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
            let label: String?
            let disabled: Bool?
            let limit: Double?
            let limit_reset: String?
            let usage: Double?
            let usage_monthly: Double?
            let expires_at: String?
            let last_used_at: String?
            let workspace_id: String?
        }
        let data: [Key]
    }

    private struct WorkspaceList: Decodable {
        struct Workspace: Decodable {
            let id: String
            let name: String
            let slug: String
        }
        let data: [Workspace]
    }

    private struct CreatedWorkspace: Decodable {
        let data: WorkspaceList.Workspace
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

    private static func workspaces(_ management: String) async throws -> [WorkspaceList.Workspace] {
        var all: [WorkspaceList.Workspace] = []
        while true {
            let page: WorkspaceList = try await request(
                "workspaces", query: [URLQueryItem(name: "offset", value: String(all.count))], token: management
            )
            all += page.data
            if page.data.isEmpty || page.data.count < 50 { return all }
        }
    }

    private static func workspace(_ slug: String, _ management: String) async throws -> WorkspaceList.Workspace {
        guard let found = try await workspaces(management).first(where: { $0.slug == slug }) else {
            throw FactoryError.message("No OpenRouter workspace with slug \(slug); create it with create openrouter-workspace")
        }
        return found
    }

    /// Every key in one workspace (nil: the default workspace), live and disabled.
    private static func keys(in workspaceID: String?, _ management: String) async throws -> [KeyList.Key] {
        var all: [KeyList.Key] = []
        while true {
            var query = [URLQueryItem(name: "offset", value: String(all.count)),
                         URLQueryItem(name: "include_disabled", value: "true")]
            if let workspaceID { query.append(URLQueryItem(name: "workspace_id", value: workspaceID)) }
            let page: KeyList = try await request("keys", query: query, token: management)
            all += page.data
            if page.data.count < 100 { return all }
        }
    }

    /// Lists every key in every workspace: names, masked labels, limits and
    /// usage. Never a key value.
    static func list(_ arguments: [String]) async throws {
        let options = try Options(arguments, allowed: ["--account"])
        let account = try validAccount(try options.required("--account"))
        print("OpenRouter key inventory")
        print("  Account: \(account)")
        try await requireUserApproval(action: "list the OpenRouter workspaces and keys of \(account) (names, limits and usage only).")
        var (data, management) = try readParent(account)
        defer { data.resetBytes(in: 0..<data.count) }
        func money(_ value: Double?) -> String { value.map { String(format: "%.2f", $0) } ?? "none" }
        var groups: [(label: String, keys: [KeyList.Key])] = []
        var seen = Set<String>()
        for space in try await workspaces(management) {
            let found = try await keys(in: space.id, management)
            seen.formUnion(found.map(\.hash))
            groups.append(("workspace=\(space.slug) name=\(space.name)", found))
        }
        let unlisted = try await keys(in: nil, management).filter { !seen.contains($0.hash) }
        if !unlisted.isEmpty { groups.append(("workspace=(default, unlisted)", unlisted)) }
        for (label, found) in groups {
            print("\(label) keys=\(found.count)")
            for key in found {
                print([
                    "  key=\(key.name ?? "?")", "hash=\(key.hash)", "label=\(key.label ?? "?")",
                    "disabled=\(key.disabled ?? false)", "limit=\(money(key.limit))", "reset=\(key.limit_reset ?? "never")",
                    "usage=\(money(key.usage))", "usage_monthly=\(money(key.usage_monthly))",
                    "last_used=\(key.last_used_at ?? "never")", "expires=\(key.expires_at ?? "never")",
                ].joined(separator: " "))
            }
        }
    }

    /// `--account --slug --name [--monthly-budget-usd N]`
    static func createWorkspace(_ arguments: [String]) async throws {
        let options = try Options(arguments, allowed: ["--account", "--slug", "--name", "--monthly-budget-usd"])
        let account = try validAccount(try options.required("--account"))
        let slug = try options.required("--slug")
        let name = try options.required("--name")
        guard matches(slug, "^[a-z0-9]+(-[a-z0-9]+)*$"), slug.count <= 64, name.count <= 100 else {
            throw FactoryError.message("--slug takes lowercase words joined by single hyphens; --name at most 100 characters")
        }
        let budget = try options.optional("--monthly-budget-usd").map { text -> Double in
            guard let value = Double(text), value > 0, value <= 500 else {
                throw FactoryError.message("--monthly-budget-usd takes a number above 0 and at most 500")
            }
            return value
        }
        print("OpenRouter workspace request")
        print("  Account: \(account)")
        print("  Workspace: \(slug) (\(name))")
        print("  Monthly budget: \(budget.map { String(format: "$%.2f", $0) } ?? "none")")
        try await requireUserApproval(
            action: "create the OpenRouter workspace \(slug)\(budget.map { String(format: " with a $%.2f monthly budget", $0) } ?? "")."
        )
        var (data, management) = try readParent(account)
        defer { data.resetBytes(in: 0..<data.count) }
        let created: CreatedWorkspace = try await request(
            "workspaces", method: "POST", token: management,
            body: try JSONSerialization.data(withJSONObject: ["name": name, "slug": slug])
        )
        if let budget {
            let _: Ignored = try await request(
                "workspaces/\(created.data.id)/budgets/monthly", method: "PUT", token: management,
                body: try JSONSerialization.data(withJSONObject: ["limit_usd": budget, "include_byok_in_budgets": true])
            )
        }
        print("workspace=created slug=\(created.data.slug) id=\(created.data.id)")
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
            allowed: ["--account", "--workspace", "--name", "--limit-usd", "--reset", "--expires-in",
                      "--infisical-project", "--infisical-env", "--infisical-path", "--infisical-secret"]
        )
        let account = try validAccount(try options.required("--account"))
        let workspaceSlug = try options.required("--workspace")
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
        print("  Workspace: \(workspaceSlug)")
        print("  Name: \(name)")
        print("  Limit: $\(limitText) (reset: \(reset))")
        print("  Expires: \(expiresAt)")
        print("  Destination: \(destination.label(secret))")
        try await requireUserApproval(
            action: "create OpenRouter key \(name) in workspace \(workspaceSlug) with a $\(limitText) \(reset) limit, and store it as \(secret)."
        )
        var (data, management) = try readParent(account)
        defer { data.resetBytes(in: 0..<data.count) }

        let space = try await workspace(workspaceSlug, management)
        var body: [String: Any] = [
            "name": name, "limit": limit, "expires_at": expiresAt, "include_byok_in_limit": true, "workspace_id": space.id,
        ]
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

    /// `--name <name>` deletes the one live key with that exact name in any
    /// workspace; `--hash <h>` (repeatable) deletes those keys. One approval.
    static func revoke(_ arguments: [String]) async throws {
        let options = try Options(arguments, allowed: ["--account", "--name"], repeatable: ["--hash"])
        let account = try validAccount(try options.required("--account"))
        let name = options.optional("--name")
        let hashes = options.all("--hash")
        guard (name == nil) != hashes.isEmpty else { throw FactoryError.message("Give --name or --hash, not both") }
        guard name.map({ $0.count <= 120 }) ?? true, hashes.count <= 50,
              hashes.allSatisfy({ matches($0, "^[A-Za-z0-9]{8,128}$") }) else {
            throw FactoryError.message("One or more arguments have an invalid shape")
        }

        print("OpenRouter key revocation")
        print("  Account: \(account)")
        if let name { print("  Name: \(name)") } else { print("  Keys: \(hashes.count) by hash") }
        try await requireUserApproval(
            action: name.map { "delete the OpenRouter key \($0)." } ?? "delete \(hashes.count) OpenRouter keys by hash."
        )
        var (data, management) = try readParent(account)
        defer { data.resetBytes(in: 0..<data.count) }

        var all = try await keys(in: nil, management)
        for space in try await workspaces(management) { all += try await keys(in: space.id, management) }
        let targets: [KeyList.Key]
        if let name {
            targets = all.filter { $0.name == name && $0.disabled != true }
            guard targets.count == 1 else {
                throw FactoryError.message("Expected one live key named \(name), found \(targets.count)")
            }
        } else {
            targets = all.filter { hashes.contains($0.hash) }
            let unknown = Set(hashes).subtracting(targets.map(\.hash))
            guard unknown.isEmpty else { throw FactoryError.message("Unknown key hashes: \(unknown.sorted().joined(separator: ", "))") }
        }
        for key in targets {
            let _: Ignored? = try await request("keys/\(key.hash)", method: "DELETE", token: management)
            print("revoked=\(key.name ?? "?") hash=\(key.hash)")
        }
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
