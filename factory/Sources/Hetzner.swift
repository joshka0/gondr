import Foundation

/// Hetzner Cloud cannot mint tokens, so the factory gates use instead: a
/// project token kept in Keychain item `<prefix>.hetzner`
/// / `<project>` goes into `HCLOUD_TOKEN` for one approved command. The
/// command can read the token; approve only commands you trust.
enum Hetzner {
    private static func parent(_ project: String) -> KeychainItem {
        KeychainItem(service: "\(keychainPrefix).hetzner", account: project)
    }

    private static func validProject(_ project: String) throws -> String {
        guard matches(project, "^[A-Za-z0-9_-]{1,64}$") else {
            throw FactoryError.message("--project has an invalid shape")
        }
        return project
    }

    static func check(_ arguments: [String]) async throws {
        let options = try Options(arguments, allowed: ["--project"])
        try await parent(try validProject(try options.required("--project"))).check()
    }

    static func importParent(_ arguments: [String]) async throws {
        let options = try Options(arguments, allowed: ["--project"])
        let project = try validProject(try options.required("--project"))
        var token = try readSecretFromTerminal(prompt: "Hetzner Cloud API token for \(project): ")
        defer { token.resetBytes(in: 0..<token.count) }
        try await requireUserApproval(action: "store the Hetzner Cloud token for project \(project) in Keychain.")
        try parent(project).write(token)
        print("import=complete")
        print("keychain_service=\(keychainPrefix).hetzner")
        print("keychain_account=\(project)")
    }

    /// `--project <label> -- <command> [args...]`. Replaces this process with
    /// the command, so its exit status is the command's.
    static func exec(_ arguments: [String]) async throws {
        guard let separator = arguments.firstIndex(of: "--"), separator + 1 < arguments.count else {
            throw FactoryError.message("Usage: exec hetzner --project <label> -- <command> [args...]")
        }
        let options = try Options(Array(arguments[..<separator]), allowed: ["--project"])
        let project = try validProject(try options.required("--project"))
        try await runWithSecret(
            parent(project), env: "HCLOUD_TOKEN", label: "Hetzner project \(project)",
            command: Array(arguments[(separator + 1)...])
        )
    }
}
