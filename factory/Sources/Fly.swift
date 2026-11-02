import Foundation

/// Fly.io tokens. The parent org token lives in Keychain item
/// `<prefix>.fly` / `<org>` as the `FlyV1 fm2_…` header
/// value. Fly refuses token creation through the API for org tokens, so a
/// child is the parent attenuated offline (`fly tokens attenuate`) to one app
/// and a validity window. A child cannot be revoked alone: revoking the parent
/// revokes every child, so expiry is the bound.
enum Fly {
    private static let endpoint = URL(string: "https://api.fly.io/graphql")!

    private struct GraphQLResponse<T: Decodable>: Decodable {
        let data: T?
        let errors: [GraphQLError]?
    }

    private struct GraphQLError: Decodable {
        let message: String
    }

    private struct OrgData: Decodable {
        struct Org: Decodable { let id: String }
        let organization: Org?
    }

    private struct AppData: Decodable {
        struct App: Decodable {
            let name: String
            let internalNumericId: UInt64?
        }
        let app: App?
    }

    private static func parent(_ org: String) -> KeychainItem {
        KeychainItem(service: "\(keychainPrefix).fly", account: org)
    }

    private static func validSlug(_ value: String, _ flag: String) throws -> String {
        guard matches(value, "^[a-z0-9][a-z0-9-]{0,62}$") else {
            throw FactoryError.message("\(flag) has an invalid shape")
        }
        return value
    }

    private static func readParent(_ org: String) throws -> (Data, String) {
        let data = try parent(org).read()
        return (data, String(decoding: data, as: UTF8.self))
    }

    /// Reports presence, then whether the parent can read its org.
    static func check(_ arguments: [String]) async throws {
        let options = try Options(arguments, allowed: ["--org"])
        let org = try validSlug(try options.required("--org"), "--org")
        try await parent(org).check()
        var (data, auth) = try readParent(org)
        defer { data.resetBytes(in: 0..<data.count) }
        let result: OrgData = try await query(
            "query($slug: String!) { organization(slug: $slug) { id } }", ["slug": org], auth: auth
        )
        print("org_readable=\(result.organization != nil)")
    }

    static func importParent(_ arguments: [String]) async throws {
        let options = try Options(arguments, allowed: ["--org"])
        let org = try validSlug(try options.required("--org"), "--org")
        var token = try readSecretFromTerminal(prompt: "Fly org token (FlyV1 fm2_… or fm2_…): ")
        defer { token.resetBytes(in: 0..<token.count) }
        let header: Data
        if token.starts(with: Data("FlyV1 fm2_".utf8)) {
            header = token
        } else if token.starts(with: Data("fm2_".utf8)) {
            header = Data("FlyV1 ".utf8) + token
        } else {
            throw FactoryError.message("A Fly org token starts with FlyV1 fm2_ or fm2_")
        }
        try await requireUserApproval(parent: parent(org), action: "store the Fly org token for \(org) in Keychain.")
        try parent(org).write(header)
        print("import=complete")
        print("keychain_service=\(keychainPrefix).fly")
        print("keychain_account=\(org)")
    }

    /// The parent attenuated to one existing app (all actions on it, read-only
    /// on the rest of the org) and a validity window of at most 30 days.
    static func mint(_ arguments: [String]) async throws {
        let options = try Options(
            arguments,
            allowed: ["--org", "--app", "--expires-in",
                      "--env", "--path", "--secret"]
        )
        let org = try validSlug(try options.required("--org"), "--org")
        let app = try validSlug(try options.required("--app"), "--app")
        guard let expiresIn = try parseExpiry(try options.required("--expires-in")), expiresIn <= 30 * 86400 else {
            throw FactoryError.message("Fly children cannot be revoked alone: give --expires-in of 30d or less")
        }
        let destination = try SecretDestination(options)
        let secret = try options.required("--secret")
        guard isSecretName(secret) else {
            throw FactoryError.message("One or more arguments have an invalid shape")
        }

        let now = Int(Date().timeIntervalSince1970)
        let notAfter = now + Int(expiresIn)
        print("Fly token request")
        print("  Org: \(org)")
        print("  App: \(app) (all actions; rest of org read-only)")
        print("  Expires: \(iso8601(Date(timeIntervalSince1970: TimeInterval(notAfter)))) (cannot be revoked alone)")
        print("  Destination: \(destination.label(secret))")
        try await requireUserApproval(
            parent: parent(org), action: "create a Fly token for app \(app) in \(org), valid \(Int(expiresIn / 3600))h and not revocable alone, and store it as \(secret)."
        )
        var (data, auth) = try readParent(org)
        defer { data.resetBytes(in: 0..<data.count) }

        let found: AppData = try await query(
            "query($name: String!) { app(name: $name) { name internalNumericId } }", ["name": app], auth: auth
        )
        guard let appID = found.app?.internalNumericId.map(String.init) else {
            throw FactoryError.message("The parent cannot see app \(app)")
        }
        let caveats: [[String: Any]] = [
            ["type": "ValidityWindow", "body": ["not_before": now - 60, "not_after": notAfter]],
            // Access that names an app must name this app; other org access is read-only.
            ["type": "IfPresent", "body": [
                "ifs": [["type": "Apps", "body": ["apps": [appID: "*"]]]],
                "else": "r",
            ]],
        ]
        let child = try attenuate(parent: auth, caveats: try JSONSerialization.data(withJSONObject: caveats))

        // The child must read its own app.
        let readBack: AppData = try await query(
            "query($name: String!) { app(name: $name) { name } }", ["name": app], auth: child
        )
        guard readBack.app?.name == app else {
            throw FactoryError.message("The child cannot read app \(app); it was not stored and expires on its own")
        }
        try destination.store(child, as: secret)

        print("mint=complete")
        print("derived_token_verified=true")
        print("secret=\(secret)")
        print("parent_exposed=false")
    }

    /// Runs `fly tokens attenuate` with the parent in its environment and the
    /// caveats on stdin, and returns the child as a `FlyV1 …` header value.
    private static func attenuate(parent: String, caveats: Data) throws -> String {
        let process = Process()
        let input = Pipe()
        let output = Pipe()
        process.executableURL = URL(fileURLWithPath: "/opt/homebrew/bin/fly")
        process.arguments = ["tokens", "attenuate"]
        var environment = ProcessInfo.processInfo.environment
        environment["FLY_API_TOKEN"] = parent
        process.environment = environment
        process.standardInput = input
        process.standardOutput = output
        process.standardError = FileHandle.nullDevice
        try process.run()
        input.fileHandleForWriting.write(caveats)
        try input.fileHandleForWriting.close()
        let produced = output.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        let token = String(decoding: produced, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
        guard process.terminationStatus == 0, token.hasPrefix("FlyV1 fm2_") else {
            throw FactoryError.message("fly tokens attenuate failed (exit \(process.terminationStatus))")
        }
        return token
    }

    /// `--org <slug> -- <command> [args...]`: run one approved command with
    /// the org token in `FLY_API_TOKEN`, for work an app token cannot do
    /// (creating apps). The command can read the token.
    static func exec(_ arguments: [String]) async throws {
        guard let separator = arguments.firstIndex(of: "--"), separator + 1 < arguments.count else {
            throw FactoryError.message("Usage: exec fly --org <org> -- <command> [args...]")
        }
        let options = try Options(Array(arguments[..<separator]), allowed: ["--org"])
        let org = try validSlug(try options.required("--org"), "--org")
        try await runWithSecret(
            parent(org), env: "FLY_API_TOKEN", label: "Fly org \(org)", command: Array(arguments[(separator + 1)...])
        )
    }

    private static func query<T: Decodable>(_ text: String, _ variables: [String: Any], auth: String) async throws -> T {
        var request = URLRequest(url: endpoint)
        request.httpMethod = "POST"
        request.httpBody = try JSONSerialization.data(withJSONObject: ["query": text, "variables": variables])
        request.setValue(auth, forHTTPHeaderField: "Authorization")
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        let (data, response) = try await URLSession.shared.data(for: request)
        guard let http = response as? HTTPURLResponse else {
            throw FactoryError.message("Fly returned no HTTP response")
        }
        let operation = text.split(separator: "{").first.map { $0.trimmingCharacters(in: .whitespacesAndNewlines) } ?? "query"
        let decoded: GraphQLResponse<T>
        do {
            decoded = try JSONDecoder().decode(GraphQLResponse<T>.self, from: data)
        } catch {
            // A DecodingError names field paths, never values.
            throw FactoryError.message("Fly HTTP \(http.statusCode) for \(operation): unexpected response shape: \(error)")
        }
        guard (200..<300).contains(http.statusCode), decoded.errors?.isEmpty ?? true, let result = decoded.data else {
            let message = decoded.errors?.map(\.message).joined(separator: "; ") ?? "no data"
            throw FactoryError.message("Fly HTTP \(http.statusCode) for \(operation): \(message)")
        }
        return result
    }
}
