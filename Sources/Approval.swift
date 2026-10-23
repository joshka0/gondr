import Foundation
import LocalAuthentication

/// Why the agent asks, from `--reason`. `main` sets it once before dispatch.
enum Request {
    static var reason: String?
}

/// Removes `--reason <text>` from the options before the `--` separator.
func takeReason(_ arguments: [String]) throws -> (arguments: [String], reason: String?) {
    let end = arguments.firstIndex(of: "--") ?? arguments.count
    guard let index = arguments[..<end].firstIndex(of: "--reason") else { return (arguments, nil) }
    guard index + 1 < end else { throw FactoryError.message("--reason takes a short sentence") }
    let reason = arguments[index + 1].trimmingCharacters(in: .whitespaces)
    guard (3...200).contains(reason.count), !reason.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) }) else {
        throw FactoryError.message("--reason takes one line of 3 to 200 characters")
    }
    var rest = arguments
    rest.removeSubrange(index...(index + 1))
    guard !rest[..<(end - 2)].contains("--reason") else { throw FactoryError.message("Duplicate option: --reason") }
    return (rest, reason)
}

/// The nearest agent process above this one, or the first few ancestors when
/// no agent is found. Ancestry comes from the kernel, not the environment.
func requestingProcess() -> (agent: String?, pid: pid_t, label: String) {
    let agents: Set<String> = ["claude", "codex", "gemini", "cursor-agent", "opencode", "droid", "amp", "pi"]
    var chain: [String] = []
    var pid = getppid()
    while pid > 1, chain.count < 12 {
        var info = kinfo_proc()
        var size = MemoryLayout<kinfo_proc>.stride
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, pid]
        guard sysctl(&mib, 4, &info, &size, nil, 0) == 0, size > 0 else { break }
        let name = withUnsafeBytes(of: info.kp_proc.p_comm) { String(decoding: $0.prefix { $0 != 0 }, as: UTF8.self) }
        // Match the executable path: Claude Code runs as `…/claude/versions/<version>`.
        var path = [CChar](repeating: 0, count: Int(MAXPATHLEN))
        let components = proc_pidpath(pid, &path, UInt32(path.count)) > 0
            ? String(cString: path).split(separator: "/").map(String.init) : [name]
        if let agent = components.last(where: agents.contains) { return (agent, pid, agent) }
        chain.append(name)
        pid = info.kp_eproc.e_ppid
    }
    return (nil, 0, "no agent found (\(chain.prefix(3).joined(separator: " < ")))")
}

/// Runs `herdr <arguments>` and returns its `result` object, or nil when
/// herdr is missing, fails, or takes longer than two seconds.
private func herdr(_ arguments: [String]) -> [String: Any]? {
    let process = Process()
    let output = Pipe()
    process.executableURL = FileManager.default.homeDirectoryForCurrentUser.appending(path: ".local/bin/herdr")
    process.arguments = arguments
    process.standardOutput = output
    process.standardError = FileHandle.nullDevice
    guard (try? process.run()) != nil else { return nil }
    // Read on another thread, so a hung herdr cannot block the prompt.
    let done = DispatchSemaphore(value: 0)
    nonisolated(unsafe) var data = Data()
    DispatchQueue.global().async {
        data = output.fileHandleForReading.readDataToEndOfFile()
        done.signal()
    }
    guard done.wait(timeout: .now() + 2) == .success else {
        process.terminate()
        return nil
    }
    process.waitUntilExit()
    guard process.terminationStatus == 0 else { return nil }
    return (try? JSONSerialization.jsonObject(with: data) as? [String: Any])?["result"] as? [String: Any]
}

/// The Herdr session of the agent: its title (the agent's session name) and
/// workspace label. The pane ID comes from `HERDR_PANE_ID`, which the caller
/// controls, so it counts only when Herdr reports the agent process in it.
func herdrSession(agentPID: pid_t) -> (title: String, workspace: String)? {
    guard agentPID > 0, let paneID = ProcessInfo.processInfo.environment["HERDR_PANE_ID"],
          matches(paneID, "^[A-Za-z0-9:_-]{1,64}$"),
          let info = herdr(["pane", "process-info", "--pane", paneID])?["process_info"] as? [String: Any] else { return nil }
    let pids = ((info["foreground_processes"] as? [[String: Any]]) ?? []).compactMap { $0["pid"] as? Int }
    guard info["foreground_process_group_id"] as? Int == Int(agentPID) || pids.contains(Int(agentPID)),
          let pane = herdr(["pane", "get", paneID])?["pane"] as? [String: Any] else { return nil }
    let title = pane["terminal_title_stripped"] as? String ?? ""
    let workspace = (pane["workspace_id"] as? String).flatMap { herdr(["workspace", "get", $0]) }
        .flatMap { ($0["workspace"] as? [String: Any])?["label"] as? String } ?? ""
    return (title.isEmpty ? "untitled" : title, workspace.isEmpty ? paneID : workspace)
}

/// Shows who asks, from where, and why, then asks for Touch ID or the login
/// password. `action` completes the system text "… is trying to <action>".
func requireUserApproval(action: String) async throws {
    let home = FileManager.default.homeDirectoryForCurrentUser.path
    let folder = FileManager.default.currentDirectoryPath
    let requester = requestingProcess()
    let session = herdrSession(agentPID: requester.pid)
    let details = [
        "Requested by: \(requester.label)\(session.map { " in \"\($0.title)\"" } ?? "")",
        "Workspace: \(session?.workspace ?? "unknown")",
        "Folder: \(folder.hasPrefix(home) ? "~" + folder.dropFirst(home.count) : folder)",
        "Reason: \(Request.reason ?? "none given")",
    ]
    for line in details { print("  \(line)") }
    print("Waiting for Touch ID…")
    fflush(stdout)

    let context = LAContext()
    var evaluationError: NSError?
    guard context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &evaluationError) else {
        throw FactoryError.message("Local user authentication is unavailable")
    }
    let approved = try await context.evaluatePolicy(
        .deviceOwnerAuthentication, localizedReason: "\(action)\n\n\(details.joined(separator: "\n"))"
    )
    guard approved else { throw FactoryError.message("User rejected the request") }
}
