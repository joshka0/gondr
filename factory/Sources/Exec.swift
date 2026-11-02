import Foundation

/// Shows the command, asks for approval, puts the parent in `env`, and
/// replaces this process with the command. The command can read the secret.
func runWithSecret(_ item: KeychainItem, env: String, label: String, command: [String]) async throws -> Never {
    let shown = command.joined(separator: " ")
    print("Command request")
    print("  Credential: \(label) as \(env)")
    print("  Command: \(shown)")
    try await requireUserApproval(
        parent: item, action: "run with \(label): \(shown.count > 200 ? String(shown.prefix(200)) + "…" : shown)"
    )
    var secret = try item.read()
    let value = String(decoding: secret, as: UTF8.self)
    secret.resetBytes(in: 0..<secret.count)
    try execWithEnvironment([env: value], command: command)
}

/// Runs the command as a child with extra variables and returns its exit
/// status (128 + signal when killed). This process ignores SIGINT and SIGHUP
/// and forwards SIGTERM, so it lives to clean up after the child.
func runChild(_ command: [String], environment: [String: String]) throws -> Int32 {
    let process = Process()
    process.executableURL = URL(fileURLWithPath: "/usr/bin/env")
    process.arguments = command
    process.environment = ProcessInfo.processInfo.environment.merging(environment) { $1 }
    signal(SIGINT, SIG_IGN)
    signal(SIGHUP, SIG_IGN)
    signal(SIGTERM, SIG_IGN)
    let forward = DispatchSource.makeSignalSource(signal: SIGTERM)
    forward.setEventHandler { process.terminate() }
    forward.resume()
    defer { forward.cancel() }
    try process.run()
    process.waitUntilExit()
    return process.terminationReason == .uncaughtSignal ? 128 + process.terminationStatus : process.terminationStatus
}

/// Sets the variables and replaces this process with the command.
func execWithEnvironment(_ variables: [String: String], command: [String]) throws -> Never {
    for (name, value) in variables { setenv(name, value, 1) }
    var argv: [UnsafeMutablePointer<CChar>?] = command.map { strdup($0) } + [nil]
    execvp(command[0], &argv)
    throw FactoryError.message("Cannot run \(command[0]): \(String(cString: strerror(errno)))")
}
