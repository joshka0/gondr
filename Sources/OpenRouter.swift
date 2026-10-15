import Foundation

/// OpenRouter API keys with a credit limit, minted with a management key kept
/// in Keychain item `gondr-token.openrouter` / `<account>`.
/// The limit is the budget: OpenRouter refuses requests once it is spent,
/// until the reset.
enum OpenRouter {
    private static let apiBase = URL(string: "https://openrouter.ai/api/v1")!
    private static let resets: Set<String> = ["daily", "weekly", "monthly", "never"]

    private struct CreatedKey: Decodable {
        struct Info: Decodable { let hash: String }
        let data: Info
        let key: String
    }

    private struct KeyList: Decodable {
        struct Key: Decodable {
            let hash: String
            let name: String?
            let disabled: Bool?
        }
        let data: [Key]
    }

    private struct CurrentKey: Decodable {
        struct Info: Decodable { let limit: Double? }
        let data: Info
    }

    private struct Ignored: Decodable {}

    private struct APIError: Decodable {
        struct Detail: Decodable { let message: String? }
        let error: Detail?
    }

    private static func parent(_ account: String) -> KeychainItem {
        KeychainItem(service: "gondr-token.openrouter", account: account)
    }

    private static func validAccount(_ value: String) throws -> String {
        guard matches(value, "^[A-Za-z0-9_.-]{1,64}$") else {
            throw FactoryError.message("--account has an invalid shape")
        }
        return value
    }

    private static func readParent(_ account: String) throws -> (Data, String) {
        let data = try parent(account).read()
        return (data, String(decoding: data, as: UTF8.self))
    }

    /// Reports presence, then whether the management key can list keys.
    static func check(_ arguments: [String]) async throws {
        let options = try Options(arguments, allowed: ["--account"])
        let account = try validAccount(try options.required("--account"))
        try await parent(account).check()
        var (data, management) = try readParent(account)
        defer { data.resetBytes(in: 0..<data.count) }
        let _: KeyList = try await request("keys", token: management)
        print("management_key_valid=true")
    }

    static func importParent(_ arguments: [String]) async throws {
        let options = try Options(arguments, allowed: ["--account"])
        let account = try validAccount(try options.required("--account"))
        var key = try readSecretFromTerminal(prompt: "OpenRouter management key: ")
        defer { key.resetBytes(in: 0..<key.count) }
        guard key.starts(with: Data("sk-or-".utf8)) else {
            throw FactoryError.message("An OpenRouter key starts with sk-or-")
        }
        try await requireUserApproval(action: "store the OpenRouter management key for \(account) in Keychain.")
        try parent(account).write(key)
        print("import=complete")
        print("keychain_service=gondr-token.openrouter")
        print("keychain_account=\(account)")
    }

    static func mint(_ arguments: [String]) async throws {
        let options = try Options(
            arguments,
            allowed: ["--account", "--name", "--limit-usd", "--reset", "--expires-in",
                      "--infisical-project", "--infisical-env", "--infisical-path", "--infisical-secret"]
        )
        let account = try validAccount(try options.required("--account"))
        let name = try options.required("--name")
        guard let limit = Double(try options.required("--limit-usd")), limit > 0, limit <= 100 else {
            throw FactoryError.message("--limit-usd takes a number above 0 and at most 100")
        }
        let reset = try options.required("--reset")
        guard resets.contains(reset) else {
            throw FactoryError.message("--reset takes daily, weekly, monthly, or never")
        }
        guard let expiresIn = try parseExpiry(try options.required("--expires-in")) else {
            throw FactoryError.message("OpenRouter keys need a finite --expires-in")
        }
        let destination = try InfisicalDestination(options)
        let secret = try options.required("--infisical-secret")
        guard name.count <= 120, isSecretName(secret) else {
            throw FactoryError.message("One or more arguments have an invalid shape")
        }

        let expiresAt = iso8601(Date().addingTimeInterval(expiresIn))
        let limitText = String(format: "%.2f", limit)
        print("OpenRouter key request")
        print("  Account: \(account)")
        print("  Name: \(name)")
        print("  Limit: $\(limitText) (reset: \(reset))")
        print("  Expires: \(expiresAt)")
        print("  Destination: \(destination.label(secret))")
        try await requireUserApproval(
            action: "create OpenRouter key \(name) with a $\(limitText) \(reset) limit, and store it as \(secret)."
        )
        var (data, management) = try readParent(account)
        defer { data.resetBytes(in: 0..<data.count) }

        var body: [String: Any] = ["name": name, "limit": limit, "expires_at": expiresAt, "include_byok_in_limit": true]
        if reset != "never" { body["limit_reset"] = reset }
        let created: CreatedKey = try await request(
            "keys", method: "POST", token: management, body: try JSONSerialization.data(withJSONObject: body)
        )
        do {
            // The child reads its own limit back.
            let current: CurrentKey = try await request("key", token: created.key)
            guard let granted = current.data.limit, abs(granted - limit) < 0.005 else {
                throw FactoryError.message("The key's limit differs from the request")
            }
            try destination.store(created.key, as: secret)
        } catch {
            let _: Ignored? = try? await request("keys/\(created.data.hash)", method: "DELETE", token: management)
            throw FactoryError.message("Key was deleted because its check or vault write failed: \(error)")
        }

        print("mint=complete")
        print("key_verified=true")
        print("infisical_secret=\(secret)")
        print("parent_exposed=false")
    }

    /// Deletes the one live key with this exact name.
    static func revoke(_ arguments: [String]) async throws {
        let options = try Options(arguments, allowed: ["--account", "--name"])
        let account = try validAccount(try options.required("--account"))
        let name = try options.required("--name")
        guard name.count <= 120 else { throw FactoryError.message("--name is too long") }

        print("OpenRouter key revocation")
        print("  Account: \(account)")
        print("  Name: \(name)")
        try await requireUserApproval(action: "delete the OpenRouter key \(name).")
        var (data, management) = try readParent(account)
        defer { data.resetBytes(in: 0..<data.count) }

        var found: [KeyList.Key] = []
        var offset = 0
        while true {
            let page: KeyList = try await request(
                "keys", query: [URLQueryItem(name: "offset", value: String(offset))], token: management
            )
            found += page.data.filter { $0.name == name && $0.disabled != true }
            if page.data.count < 100 { break }
            offset += page.data.count
        }
        guard found.count == 1 else {
            throw FactoryError.message("Expected one live key named \(name), found \(found.count)")
        }
        let _: Ignored? = try await request("keys/\(found[0].hash)", method: "DELETE", token: management)
        print("revoke=complete")
        print("parent_exposed=false")
    }

    /// Decodes `T` from a 2xx body. An empty body decodes to nil when `T` is
    /// optional.
    private static func request<T: Decodable>(
        _ path: String,
        method: String = "GET",
        query: [URLQueryItem] = [],
        token: String,
        body: Data? = nil
    ) async throws -> T {
        var request = URLRequest(url: apiBase.appending(path: path).appending(queryItems: query))
        request.httpMethod = method
        request.httpBody = body
        request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        let (data, response) = try await URLSession.shared.data(for: request)
        guard let http = response as? HTTPURLResponse else {
            throw FactoryError.message("OpenRouter returned no HTTP response")
        }
        guard (200..<300).contains(http.statusCode) else {
            let message = (try? JSONDecoder().decode(APIError.self, from: data))?.error?.message ?? ""
            throw FactoryError.message("OpenRouter HTTP \(http.statusCode): \(message)")
        }
        return try JSONDecoder().decode(T.self, from: data.isEmpty ? Data("null".utf8) : data)
    }
}
