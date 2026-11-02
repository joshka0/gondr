import Foundation

/// Tailscale auth keys, minted with a parent OAuth client kept in Keychain
/// item `<prefix>.tailscale` / `<tailnet>` as
/// `<client id>:<client secret>`. `mint` and `revoke` need the `auth_keys`
/// scope, and the client owns the tags that keys may carry. `exec` can ask
/// only for scopes the client holds.
enum Tailscale {
    private static let apiBase = URL(string: "https://api.tailscale.com/api/v2")!
    private static let keyOptions: Set<String> = ["ephemeral", "reusable", "preauthorized"]

    private struct AccessToken: Decodable {
        let access_token: String
    }

    private struct CreatedKey: Decodable {
        let id: String
        let key: String
    }

    private struct KeyInfo: Decodable {
        struct Capabilities: Decodable {
            struct Devices: Decodable {
                struct Create: Decodable { let tags: [String]? }
                let create: Create?
            }
            let devices: Devices?
        }
        let id: String
        let description: String?
        let revoked: String?
        let capabilities: Capabilities?
    }

    private struct KeyList: Decodable {
        let keys: [KeyInfo]
    }

    private struct Ignored: Decodable {}

    private struct APIError: Decodable {
        let message: String?
    }

    private static func parent(_ tailnet: String) -> KeychainItem {
        KeychainItem(service: "\(keychainPrefix).tailscale", account: tailnet)
    }

    private static func validTailnet(_ value: String) throws -> String {
        guard matches(value, "^[A-Za-z0-9_.-]{1,64}$") else {
            throw FactoryError.message("--tailnet has an invalid shape")
        }
        return value
    }

    /// Trades the parent OAuth client for a 1-hour API token limited to
    /// the given scopes and tags.
    private static func accessToken(
        _ tailnet: String, scopes: [String] = ["auth_keys"], tags: [String]
    ) async throws -> String {
        var data = try parent(tailnet).read()
        defer { data.resetBytes(in: 0..<data.count) }
        let stored = String(decoding: data, as: UTF8.self)
        guard let colon = stored.firstIndex(of: ":") else {
            throw FactoryError.message("Stored Tailscale credential has an invalid shape; import it again")
        }
        var form = URLComponents()
        form.queryItems = [
            URLQueryItem(name: "grant_type", value: "client_credentials"),
            URLQueryItem(name: "client_id", value: String(stored[..<colon])),
            URLQueryItem(name: "client_secret", value: String(stored[stored.index(after: colon)...])),
            URLQueryItem(name: "scope", value: scopes.joined(separator: " ")),
        ] + (tags.isEmpty ? [] : [URLQueryItem(name: "tags", value: tags.joined(separator: " "))])
        var request = URLRequest(url: apiBase.appending(path: "oauth/token"))
        request.httpMethod = "POST"
        request.httpBody = Data((form.percentEncodedQuery ?? "").utf8)
        request.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
        let token: AccessToken = try await send(request)
        return token.access_token
    }

    /// Reports presence, then whether the parent can get an API token.
    static func check(_ arguments: [String]) async throws {
        let options = try Options(arguments, allowed: ["--tailnet"])
        let tailnet = try validTailnet(try options.required("--tailnet"))
        try await parent(tailnet).check()
        _ = try await accessToken(tailnet, tags: [])
        print("oauth_token_granted=true")
    }

    static func importParent(_ arguments: [String]) async throws {
        let options = try Options(arguments, allowed: ["--tailnet"])
        let tailnet = try validTailnet(try options.required("--tailnet"))
        var id = try readSecretFromTerminal(prompt: "Tailscale OAuth client ID: ")
        var secret = try readSecretFromTerminal(prompt: "Tailscale OAuth client secret: ")
        defer {
            id.resetBytes(in: 0..<id.count)
            secret.resetBytes(in: 0..<secret.count)
        }
        guard !id.contains(UInt8(ascii: ":")), !id.starts(with: Data("tskey-".utf8)) else {
            throw FactoryError.message("The first value must be the client ID, not the secret")
        }
        guard secret.starts(with: Data("tskey-client-".utf8)) else {
            throw FactoryError.message("The second value must be the client secret, which starts with tskey-client-")
        }
        try await requireUserApproval(parent: parent(tailnet), action: "store the Tailscale OAuth client for \(tailnet) in Keychain.")
        try parent(tailnet).write(id + Data(":".utf8) + secret)
        print("import=complete")
        print("keychain_service=\(keychainPrefix).tailscale")
        print("keychain_account=\(tailnet)")
    }

    static func mint(_ arguments: [String]) async throws {
        let options = try Options(
            arguments,
            allowed: ["--tailnet", "--name", "--expires-in",
                      "--env", "--path", "--secret"],
            repeatable: ["--tag", "--with"]
        )
        let tailnet = try validTailnet(try options.required("--tailnet"))
        let name = try options.required("--name")
        let tags = options.all("--tag")
        let with = Set(options.all("--with"))
        guard let expiresIn = try parseExpiry(try options.required("--expires-in")), expiresIn <= 90 * 86400 else {
            throw FactoryError.message("Tailscale auth keys need --expires-in of 90d or less")
        }
        let destination = try SecretDestination(options)
        let secret = try options.required("--secret")
        guard matches(name, "^[A-Za-z0-9 -]{1,50}$"), isSecretName(secret) else {
            throw FactoryError.message("--name takes up to 50 letters, digits, hyphens, or spaces")
        }
        guard !tags.isEmpty, tags.count <= 8, tags.allSatisfy({ matches($0, "^tag:[A-Za-z0-9-]{1,64}$") }) else {
            throw FactoryError.message("Give one to eight --tag tag:<name>; OAuth-created keys must be tagged")
        }
        guard with.isSubset(of: keyOptions) else {
            throw FactoryError.message("--with takes ephemeral, reusable, or preauthorized")
        }

        print("Tailscale auth key request")
        print("  Tailnet: \(tailnet)")
        print("  Name: \(name)")
        print("  Tags: \(tags.joined(separator: ", "))")
        print("  Options: \(with.isEmpty ? "single-use" : with.sorted().joined(separator: ", "))")
        print("  Expires: \(iso8601(Date().addingTimeInterval(expiresIn)))")
        print("  Destination: \(destination.label(secret))")
        try await requireUserApproval(
            parent: parent(tailnet), action: "create Tailscale auth key \(name) (\(tags.joined(separator: ", "))) in \(tailnet) and store it as \(secret)."
        )
        let token = try await accessToken(tailnet, tags: tags)

        let body: [String: Any] = [
            "keyType": "auth",
            "description": name,
            "expirySeconds": Int(expiresIn),
            "capabilities": ["devices": ["create": [
                "reusable": with.contains("reusable"),
                "ephemeral": with.contains("ephemeral"),
                "preauthorized": with.contains("preauthorized"),
                "tags": tags,
            ]]],
        ]
        let created: CreatedKey = try await api("tailnet/-/keys", method: "POST", token: token,
                                                body: try JSONSerialization.data(withJSONObject: body))
        do {
            // Read the key back: it must exist with exactly the requested tags.
            let info: KeyInfo = try await api("tailnet/-/keys/\(created.id)", token: token)
            guard Set(info.capabilities?.devices?.create?.tags ?? []) == Set(tags) else {
                throw FactoryError.message("The key's tags differ from the request")
            }
            try destination.store(created.key, as: secret)
        } catch {
            let _: Ignored? = try? await api("tailnet/-/keys/\(created.id)", method: "DELETE", token: token)
            throw FactoryError.message("Auth key was revoked because its check or vault write failed: \(error)")
        }

        print("mint=complete")
        print("key_verified=true")
        print("secret=\(secret)")
        print("parent_exposed=false")
    }

    /// Revokes the one live key with this exact description.
    static func revoke(_ arguments: [String]) async throws {
        let options = try Options(arguments, allowed: ["--tailnet", "--name"])
        let tailnet = try validTailnet(try options.required("--tailnet"))
        let name = try options.required("--name")
        guard matches(name, "^[A-Za-z0-9 -]{1,50}$") else {
            throw FactoryError.message("--name has an invalid shape")
        }

        print("Tailscale auth key revocation")
        print("  Tailnet: \(tailnet)")
        print("  Name: \(name)")
        try await requireUserApproval(parent: parent(tailnet), action: "revoke the Tailscale auth key \(name) in \(tailnet).")
        let token = try await accessToken(tailnet, tags: [])
        let list: KeyList = try await api("tailnet/-/keys", token: token)
        var found: [KeyInfo] = []
        for key in list.keys {
            // The list may omit descriptions; read each key to compare.
            let info: KeyInfo = key.description == nil ? try await api("tailnet/-/keys/\(key.id)", token: token) : key
            if info.description == name, info.revoked == nil { found.append(info) }
        }
        guard found.count == 1 else {
            throw FactoryError.message("Expected one live key named \(name), found \(found.count)")
        }
        let _: Ignored? = try await api("tailnet/-/keys/\(found[0].id)", method: "DELETE", token: token)
        print("revoke=complete")
        print("parent_exposed=false")
    }

    /// `--tailnet <label> --scope <scope> [--scope ...] -- <command>`. Puts a
    /// 1-hour API token limited to the scopes in `TAILSCALE_API_KEY` and
    /// replaces this process with the command. The token expires by itself;
    /// the parent never reaches the command.
    static func exec(_ arguments: [String]) async throws {
        guard let separator = arguments.firstIndex(of: "--"), separator + 1 < arguments.count else {
            throw FactoryError.message("Usage: exec tailscale --tailnet <label> --scope <scope> [--scope ...] -- <command>")
        }
        let options = try Options(Array(arguments[..<separator]), allowed: ["--tailnet"], repeatable: ["--scope"])
        let tailnet = try validTailnet(try options.required("--tailnet"))
        let scopes = options.all("--scope")
        guard !scopes.isEmpty, scopes.allSatisfy({ matches($0, "^[a-z_]{1,32}(:[a-z_]{1,32}){0,2}$") }) else {
            throw FactoryError.message("Give at least one --scope, for example policy_file or devices:core:read")
        }
        let command = Array(arguments[(separator + 1)...])
        let shown = command.joined(separator: " ")

        print("Command request")
        print("  Credential: Tailscale \(tailnet) API token as TAILSCALE_API_KEY (1 hour)")
        print("  Scopes: \(scopes.joined(separator: ", "))")
        print("  Command: \(shown)")
        try await requireUserApproval(
            parent: parent(tailnet), action: "run with a Tailscale token for \(tailnet) (\(scopes.joined(separator: ", "))): \(shown.count > 160 ? String(shown.prefix(160)) + "…" : shown)"
        )
        let token = try await accessToken(tailnet, scopes: scopes, tags: [])
        try execWithEnvironment(["TAILSCALE_API_KEY": token], command: command)
    }

    private static func api<T: Decodable>(
        _ path: String, method: String = "GET", token: String, body: Data? = nil
    ) async throws -> T {
        var request = URLRequest(url: apiBase.appending(path: path))
        request.httpMethod = method
        request.httpBody = body
        request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        return try await send(request)
    }

    /// Decodes `T` from a 2xx body. An empty body decodes to nil when `T` is
    /// optional.
    private static func send<T: Decodable>(_ request: URLRequest) async throws -> T {
        let (data, response) = try await URLSession.shared.data(for: request)
        guard let http = response as? HTTPURLResponse else {
            throw FactoryError.message("Tailscale returned no HTTP response")
        }
        guard (200..<300).contains(http.statusCode) else {
            let message = (try? JSONDecoder().decode(APIError.self, from: data))?.message ?? ""
            throw FactoryError.message("Tailscale HTTP \(http.statusCode): \(message)")
        }
        return try JSONDecoder().decode(T.self, from: data.isEmpty ? Data("null".utf8) : data)
    }
}
