import Foundation
import Security

/// GitHub through a GitHub App. The parent is the app's private key, kept in
/// Keychain item `<prefix>.github` / `<app>` as
/// `<app id>\n<PKCS#1 PEM>`. Each `exec github` mints an installation token
/// limited to named repositories and permissions; it expires after one hour
/// and is never stored.
enum GitHub {
    private static let apiBase = URL(string: "https://api.github.com")!
    private static let levels: Set<String> = ["read", "write"]

    private struct Installation: Decodable {
        struct Account: Decodable { let login: String }
        let id: Int
        let account: Account
    }

    private struct InstallationToken: Decodable {
        struct Repository: Decodable { let name: String }
        let token: String
        let expires_at: String
        let permissions: [String: String]
        let repositories: [Repository]?
    }

    private struct APIError: Decodable { let message: String? }

    private static func parent(_ app: String) -> KeychainItem {
        KeychainItem(service: "\(keychainPrefix).github", account: app)
    }

    private static func validName(_ value: String, _ flag: String) throws -> String {
        guard matches(value, "^[A-Za-z0-9_.-]{1,100}$") else {
            throw FactoryError.message("\(flag) has an invalid shape")
        }
        return value
    }

    /// Reports presence, then the installations the app can see.
    static func check(_ arguments: [String]) async throws {
        let options = try Options(arguments, allowed: ["--app"])
        let app = try validName(try options.required("--app"), "--app")
        try await parent(app).check()
        let jwt = try appJWT(app)
        let installations: [Installation] = try await request("app/installations", token: jwt)
        print("installations=\(installations.map(\.account.login).sorted().joined(separator: ","))")
    }

    /// Reads the downloaded `.pem` once and stores it with the app ID.
    static func importParent(_ arguments: [String]) async throws {
        let options = try Options(arguments, allowed: ["--app", "--app-id", "--key-file"])
        let app = try validName(try options.required("--app"), "--app")
        let appID = try options.required("--app-id")
        guard matches(appID, "^[0-9]{1,12}$") else { throw FactoryError.message("--app-id takes the numeric App ID") }
        let path = try options.required("--key-file")
        var pem = try Data(contentsOf: URL(fileURLWithPath: (path as NSString).expandingTildeInPath))
        defer { pem.resetBytes(in: 0..<pem.count) }
        guard String(decoding: pem, as: UTF8.self).contains("-----BEGIN RSA PRIVATE KEY-----") else {
            throw FactoryError.message("The key file must be the GitHub App's PKCS#1 PEM (BEGIN RSA PRIVATE KEY)")
        }
        _ = try privateKey(fromPEM: pem)
        try await requireUserApproval(parent: parent(app), action: "store the GitHub App \(app) private key in Keychain.")
        try parent(app).write(Data("\(appID)\n".utf8) + pem)
        print("import=complete")
        print("keychain_service=\(keychainPrefix).github")
        print("keychain_account=\(app)")
        print("next=delete the downloaded key file: \(path)")
    }

    /// `--app <label> --owner <login> --repo <name> [--repo ...]
    /// --permission <name>:<read|write> [...] -- <command> [args...]`
    static func exec(_ arguments: [String]) async throws {
        guard let separator = arguments.firstIndex(of: "--"), separator + 1 < arguments.count else {
            throw FactoryError.message(
                "Usage: exec github --app <label> --owner <login> --repo <name> --permission <name>:<read|write> -- <command>"
            )
        }
        let options = try Options(
            Array(arguments[..<separator]), allowed: ["--app", "--owner"], repeatable: ["--repo", "--permission"]
        )
        let app = try validName(try options.required("--app"), "--app")
        let owner = try validName(try options.required("--owner"), "--owner")
        let repos = try options.all("--repo").map { try validName($0, "--repo") }
        var permissions: [String: String] = [:]
        for entry in options.all("--permission") {
            let parts = entry.split(separator: ":").map(String.init)
            guard parts.count == 2, matches(parts[0], "^[a-z_]{1,64}$"), levels.contains(parts[1]) else {
                throw FactoryError.message("--permission takes <name>:read or <name>:write, for example contents:write")
            }
            permissions[parts[0]] = parts[1]
        }
        guard !repos.isEmpty, repos.count <= 20, !permissions.isEmpty else {
            throw FactoryError.message("Give one to twenty --repo and at least one --permission")
        }
        let command = Array(arguments[(separator + 1)...])
        let shown = command.joined(separator: " ")
        let scope = permissions.sorted { $0.key < $1.key }.map { "\($0.key):\($0.value)" }.joined(separator: ", ")

        print("Command request")
        print("  Credential: GitHub App \(app) installation token as GH_TOKEN (1 hour)")
        print("  Repositories: \(repos.map { "\(owner)/\($0)" }.joined(separator: ", "))")
        print("  Permissions: \(scope)")
        print("  Command: \(shown)")
        try await requireUserApproval(
            parent: parent(app), action: "run with a GitHub token for \(owner)/\(repos.joined(separator: ",")) (\(scope)): \(shown.count > 160 ? String(shown.prefix(160)) + "…" : shown)"
        )

        let jwt = try appJWT(app)
        let installations: [Installation] = try await request("app/installations", token: jwt)
        guard let installation = installations.first(where: { $0.account.login.lowercased() == owner.lowercased() }) else {
            throw FactoryError.message("The app is not installed for \(owner)")
        }
        let minted: InstallationToken = try await request(
            "app/installations/\(installation.id)/access_tokens", method: "POST", token: jwt,
            body: try JSONSerialization.data(withJSONObject: ["repositories": repos, "permissions": permissions])
        )
        // GitHub adds `metadata: read` to every token; everything else must match the request.
        var granted = minted.permissions
        granted.removeValue(forKey: "metadata")
        var requested = permissions
        requested.removeValue(forKey: "metadata")
        guard granted == requested,
              Set((minted.repositories ?? []).map { $0.name.lowercased() }) == Set(repos.map { $0.lowercased() }) else {
            throw FactoryError.message("GitHub granted different repositories or permissions; the token was not used")
        }
        try execWithEnvironment(["GH_TOKEN": minted.token, "GITHUB_TOKEN": minted.token], command: command)
    }

    /// A 9-minute app JWT (RS256), signed with the Keychain-held private key.
    private static func appJWT(_ app: String) throws -> String {
        var stored = try parent(app).read()
        defer { stored.resetBytes(in: 0..<stored.count) }
        guard let newline = stored.firstIndex(of: UInt8(ascii: "\n")) else {
            throw FactoryError.message("Stored GitHub App key has an invalid shape; import it again")
        }
        let appID = String(decoding: stored[..<newline], as: UTF8.self)
        let key = try privateKey(fromPEM: Data(stored[stored.index(after: newline)...]))
        let now = Int(Date().timeIntervalSince1970)
        let header = base64URL(Data(#"{"alg":"RS256","typ":"JWT"}"#.utf8))
        let payload = base64URL(Data(#"{"iat":\#(now - 60),"exp":\#(now + 540),"iss":"\#(appID)"}"#.utf8))
        let signingInput = Data("\(header).\(payload)".utf8)
        var error: Unmanaged<CFError>?
        guard let signature = SecKeyCreateSignature(
            key, .rsaSignatureMessagePKCS1v15SHA256, signingInput as CFData, &error
        ) as Data? else {
            throw FactoryError.message("Cannot sign the app JWT")
        }
        return "\(header).\(payload).\(base64URL(signature))"
    }

    private static func privateKey(fromPEM pem: Data) throws -> SecKey {
        let body = String(decoding: pem, as: UTF8.self)
            .components(separatedBy: "\n")
            .filter { !$0.hasPrefix("-----") }
            .joined()
        guard let der = Data(base64Encoded: body) else {
            throw FactoryError.message("The key file is not valid PEM")
        }
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
        ]
        var error: Unmanaged<CFError>?
        guard let key = SecKeyCreateWithData(der as CFData, attributes as CFDictionary, &error) else {
            throw FactoryError.message("The key file is not an RSA private key")
        }
        return key
    }

    private static func base64URL(_ data: Data) -> String {
        data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    private static func request<T: Decodable>(
        _ path: String, method: String = "GET", token: String, body: Data? = nil
    ) async throws -> T {
        var request = URLRequest(url: apiBase.appending(path: path))
        request.httpMethod = method
        request.httpBody = body
        request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        request.setValue("application/vnd.github+json", forHTTPHeaderField: "Accept")
        request.setValue("2022-11-28", forHTTPHeaderField: "X-GitHub-Api-Version")
        let (data, response) = try await URLSession.shared.data(for: request)
        guard let http = response as? HTTPURLResponse else {
            throw FactoryError.message("GitHub returned no HTTP response")
        }
        guard (200..<300).contains(http.statusCode) else {
            let message = (try? JSONDecoder().decode(APIError.self, from: data))?.message ?? ""
            throw FactoryError.message("GitHub HTTP \(http.statusCode): \(message)")
        }
        return try JSONDecoder().decode(T.self, from: data)
    }
}
