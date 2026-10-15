import Foundation
import LocalAuthentication
import Security

enum FactoryError: Error, CustomStringConvertible {
    case message(String)

    var description: String {
        switch self { case let .message(message): message }
    }
}

private let usage = """
Usage (mint, revoke and exec also need --reason "<why>", before any --):
  infra-token-factory mint cloudflare <options>
  infra-token-factory revoke cloudflare --name <token-name> --account-id <id>
  infra-token-factory mint planetscale <options>
  infra-token-factory revoke planetscale --org <org> --name <token-name>
  infra-token-factory mint fly <options>
  infra-token-factory exec fly --org <org> -- <command> [args...]
  infra-token-factory mint tailscale <options>
  infra-token-factory revoke tailscale --tailnet <label> --name <key-name>
  infra-token-factory mint openrouter <options>
  infra-token-factory revoke openrouter --account <label> --name <key-name>
  infra-token-factory mint gitlab-deploy <options>
  infra-token-factory revoke gitlab-deploy --account <label> --project <group/project> --name <name>
  infra-token-factory exec gitlab --account <label> -- <command> [args...]
  infra-token-factory exec github --app <label> --owner <login> --repo <name> --permission <name>:<read|write> -- <command>
  infra-token-factory exec hetzner --project <label> -- <command> [args...]
  infra-token-factory import planetscale --org <org>
  infra-token-factory import hetzner --project <label>
  infra-token-factory import fly --org <org>
  infra-token-factory import tailscale --tailnet <label>
  infra-token-factory import openrouter --account <label>
  infra-token-factory import gitlab --account <label>
  infra-token-factory import github --app <label> --app-id <id> --key-file <path.pem>
  infra-token-factory check cloudflare
  infra-token-factory check planetscale --org <org>
  infra-token-factory check hetzner --project <label>
  infra-token-factory check fly --org <org>
  infra-token-factory check tailscale --tailnet <label>
  infra-token-factory check openrouter --account <label>
  infra-token-factory check gitlab --account <label>
  infra-token-factory check github --app <label>
"""

@main
struct InfraTokenFactory {
    static func main() async {
        let values = Array(CommandLine.arguments.dropFirst())
        do {
            guard values.count >= 2 else { throw FactoryError.message(usage) }
            let (rest, reason) = try takeReason(Array(values.dropFirst(2)))
            guard reason != nil || !["mint", "revoke", "exec"].contains(values[0]) else {
                throw FactoryError.message(#"\#(values[0]) needs --reason "<why you need it>""#)
            }
            Request.reason = reason
            switch (values[0], values[1]) {
            case ("mint", "cloudflare"): try await Cloudflare.mint(rest)
            case ("revoke", "cloudflare"): try await Cloudflare.revoke(rest)
            case ("check", "cloudflare"): try await Cloudflare.check(rest)
            case ("mint", "planetscale"): try await PlanetScale.mint(rest)
            case ("revoke", "planetscale"): try await PlanetScale.revoke(rest)
            case ("import", "planetscale"): try await PlanetScale.importParent(rest)
            case ("check", "planetscale"): try await PlanetScale.check(rest)
            case ("exec", "hetzner"): try await Hetzner.exec(rest)
            case ("import", "hetzner"): try await Hetzner.importParent(rest)
            case ("check", "hetzner"): try await Hetzner.check(rest)
            case ("mint", "fly"): try await Fly.mint(rest)
            case ("exec", "fly"): try await Fly.exec(rest)
            case ("import", "fly"): try await Fly.importParent(rest)
            case ("check", "fly"): try await Fly.check(rest)
            case ("mint", "tailscale"): try await Tailscale.mint(rest)
            case ("revoke", "tailscale"): try await Tailscale.revoke(rest)
            case ("import", "tailscale"): try await Tailscale.importParent(rest)
            case ("check", "tailscale"): try await Tailscale.check(rest)
            case ("mint", "openrouter"): try await OpenRouter.mint(rest)
            case ("revoke", "openrouter"): try await OpenRouter.revoke(rest)
            case ("import", "openrouter"): try await OpenRouter.importParent(rest)
            case ("check", "openrouter"): try await OpenRouter.check(rest)
            case ("mint", "gitlab-deploy"): try await GitLab.mintDeploy(rest)
            case ("revoke", "gitlab-deploy"): try await GitLab.revokeDeploy(rest)
            case ("exec", "gitlab"): try await GitLab.exec(rest)
            case ("import", "gitlab"): try await GitLab.importParent(rest)
            case ("check", "gitlab"): try await GitLab.check(rest)
            case ("exec", "github"): try await GitHub.exec(rest)
            case ("import", "github"): try await GitHub.importParent(rest)
            case ("check", "github"): try await GitHub.check(rest)
            default: throw FactoryError.message(usage)
            }
        } catch {
            FileHandle.standardError.write(Data("\(values.first ?? "factory")=failed reason=\(error)\n".utf8))
            exit(1)
        }
    }
}

/// `--key value` pairs. Keys in `repeatable` may appear more than once; every
/// other key at most once. Unknown keys fail closed.
struct Options {
    private var values: [String: [String]] = [:]

    init(_ arguments: [String], allowed: Set<String>, repeatable: Set<String> = []) throws {
        var index = 0
        while index < arguments.count {
            let key = arguments[index]
            guard key.hasPrefix("--"), index + 1 < arguments.count else {
                throw FactoryError.message("Expected --option value arguments")
            }
            guard allowed.contains(key) || repeatable.contains(key) else {
                throw FactoryError.message("Unknown option: \(key)")
            }
            guard repeatable.contains(key) || values[key] == nil else {
                throw FactoryError.message("Duplicate option: \(key)")
            }
            values[key, default: []].append(arguments[index + 1])
            index += 2
        }
    }

    func required(_ key: String) throws -> String {
        guard let value = optional(key) else {
            throw FactoryError.message("Missing required option: \(key)")
        }
        return value
    }

    func optional(_ key: String) -> String? {
        guard let value = values[key]?.first, !value.isEmpty else { return nil }
        return value
    }

    func all(_ key: String) -> [String] { values[key] ?? [] }
}

func matches(_ value: String, _ pattern: String) -> Bool {
    value.range(of: pattern, options: .regularExpression) != nil
}

/// `<N>h` or `<N>d` as seconds, or nil for `never`. A long-lived token is
/// always an explicit choice.
func parseExpiry(_ value: String) throws -> TimeInterval? {
    if value == "never" { return nil }
    guard matches(value, "^[1-9][0-9]{0,3}[hd]$"), let amount = Double(value.dropLast()) else {
        throw FactoryError.message("--expires-in takes <N>h, <N>d, or never")
    }
    return (value.hasSuffix("d") ? amount * 24 : amount) * 3600
}

func iso8601(_ date: Date) -> String {
    let formatter = ISO8601DateFormatter()
    formatter.formatOptions = [.withInternetDateTime]
    return formatter.string(from: date)
}

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
func requestingProcess() -> String {
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
        if let agent = components.last(where: agents.contains) { return "\(agent) (pid \(pid))" }
        chain.append(name)
        pid = info.kp_eproc.e_ppid
    }
    return "no agent found (\(chain.prefix(3).joined(separator: " < ")))"
}

/// Shows who asks, from where, and why, then asks for Touch ID or the login
/// password. `action` completes the system text "… is trying to <action>".
func requireUserApproval(action: String) async throws {
    let home = FileManager.default.homeDirectoryForCurrentUser.path
    let folder = FileManager.default.currentDirectoryPath
    let pane = ProcessInfo.processInfo.environment["HERDR_PANE_ID"]
    let details = [
        "Requested by: \(requestingProcess())\(pane.map { ", pane \($0)" } ?? "")",
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

/// A parent credential in the login keychain. The ACL trusts the binary
/// that created the item; after a rebuild macOS asks once (Always Allow).
struct KeychainItem {
    let service: String
    let account: String

    private var query: [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]
    }

    func read() throws -> Data {
        var lookup = query
        lookup[kSecReturnData as String] = true
        lookup[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: CFTypeRef?
        let status = SecItemCopyMatching(lookup as CFDictionary, &result)
        guard status == errSecSuccess, let data = result as? Data, !data.isEmpty else {
            throw FactoryError.message("Keychain parent credential \(service)/\(account) is unavailable (status \(status))")
        }
        return data
    }

    func write(_ data: Data) throws {
        let update = SecItemUpdate(query as CFDictionary, [kSecValueData as String: data] as CFDictionary)
        if update == errSecSuccess { return }
        guard update == errSecItemNotFound else {
            throw FactoryError.message("Keychain update failed (status \(update))")
        }
        var add = query
        add[kSecValueData as String] = data
        let status = SecItemAdd(add as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw FactoryError.message("Keychain add failed (status \(status))")
        }
    }

    /// Reads the item after approval and reports presence only.
    func check() async throws {
        try await requireUserApproval(action: "check whether the \(service) parent credential is available.")
        var data = try read()
        let present = !data.isEmpty
        data.resetBytes(in: 0..<data.count)
        print("keychain_service=\(service)")
        print("keychain_account=\(account)")
        print("credential_present=\(present)")
        print("credential_exposed=false")
    }
}

/// Reads one secret from the terminal with echo off. Never from stdin, so
/// a pipe or an agent cannot feed it silently.
func readSecretFromTerminal(prompt: String) throws -> Data {
    var buffer = [CChar](repeating: 0, count: 4096)
    guard readpassphrase(prompt, &buffer, buffer.count, RPP_REQUIRE_TTY) != nil else {
        throw FactoryError.message("A terminal is required to enter the secret")
    }
    defer { for index in buffer.indices { buffer[index] = 0 } }
    let length = buffer.firstIndex(of: 0) ?? 0
    guard length > 0 else { throw FactoryError.message("Empty secret") }
    return Data(buffer[0..<length].map { UInt8(bitPattern: $0) })
}

struct InfisicalDestination {
    let project: String
    let environment: String
    let path: String

    init(_ options: Options) throws {
        project = try options.required("--infisical-project")
        environment = try options.required("--infisical-env")
        path = try options.required("--infisical-path")
        guard matches(project, "^[0-9a-f-]{36}$"),
              matches(environment, "^[A-Za-z0-9_-]+$"),
              path.hasPrefix("/"), !path.contains("..") else {
            throw FactoryError.message("Infisical destination has an invalid shape")
        }
    }

    func label(_ secret: String) -> String {
        "Infisical \(path == "/" ? "" : path)/\(secret)"
    }

    /// Writes the value through stdin, so it never appears in argv.
    func store(_ value: String, as secret: String) throws {
        let process = Process()
        let input = Pipe()
        process.executableURL = URL(fileURLWithPath: "/opt/homebrew/bin/infisical")
        process.arguments = [
            "secrets", "set", "\(secret)=@/dev/stdin",
            "--projectId", project,
            "--env", environment,
            "--path", path,
            "--type", "shared",
            "--silent",
        ]
        process.standardInput = input
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        try process.run()
        input.fileHandleForWriting.write(Data(value.utf8))
        try input.fileHandleForWriting.close()
        process.waitUntilExit()
        guard process.terminationStatus == 0 else {
            throw FactoryError.message("Infisical CLI exited \(process.terminationStatus)")
        }
    }
}

func isSecretName(_ value: String) -> Bool { matches(value, "^[A-Z][A-Z0-9_]+$") }

/// Shows the command, asks for approval, puts the parent in `env`, and
/// replaces this process with the command. The command can read the secret.
func runWithSecret(_ item: KeychainItem, env: String, label: String, command: [String]) async throws -> Never {
    let shown = command.joined(separator: " ")
    print("Command request")
    print("  Credential: \(label) as \(env)")
    print("  Command: \(shown)")
    try await requireUserApproval(
        action: "run with \(label): \(shown.count > 200 ? String(shown.prefix(200)) + "…" : shown)"
    )
    var secret = try item.read()
    let value = String(decoding: secret, as: UTF8.self)
    secret.resetBytes(in: 0..<secret.count)
    try execWithEnvironment([env: value], command: command)
}

/// Sets the variables and replaces this process with the command.
func execWithEnvironment(_ variables: [String: String], command: [String]) throws -> Never {
    for (name, value) in variables { setenv(name, value, 1) }
    var argv: [UnsafeMutablePointer<CChar>?] = command.map { strdup($0) } + [nil]
    execvp(command[0], &argv)
    throw FactoryError.message("Cannot run \(command[0]): \(String(cString: strerror(errno)))")
}
