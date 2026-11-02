import Foundation

/// GitLab.com. The parent is a personal access token with the `api` scope,
/// kept in Keychain item `<prefix>.gitlab` / `<account>`.
/// On GitLab.com Free a PAT cannot mint scoped access tokens, so the factory
/// mints project deploy tokens and gates every other use behind `exec`.
enum GitLab {
    private static let apiBase = URL(string: "https://gitlab.com/api/v4")!
    private static let deployScopes: Set<String> = [
        "read_repository", "read_registry", "write_registry", "read_package_registry", "write_package_registry",
    ]

    private struct DeployToken: Decodable {
        let id: Int
        let name: String
        let username: String
        let token: String?
        let revoked: Bool?
        let expired: Bool?
        let scopes: [String]?
    }

    private struct CurrentUser: Decodable { let username: String }
    private struct APIError: Decodable { let message: AnyMessage?; let error: String? }

    /// GitLab returns `message` as a string or an object.
    private struct AnyMessage: Decodable {
        let text: String
        init(from decoder: Decoder) throws {
            let container = try decoder.singleValueContainer()
            if let string = try? container.decode(String.self) {
                text = string
            } else {
                text = "(structured message)"
            }
        }
    }

    private struct Ignored: Decodable {}

    private static func parent(_ account: String) -> KeychainItem {
        KeychainItem(service: "\(keychainPrefix).gitlab", account: account)
    }

    private static func validAccount(_ value: String) throws -> String {
        guard matches(value, "^[A-Za-z0-9_.-]{1,64}$") else {
            throw FactoryError.message("--account has an invalid shape")
        }
        return value
    }

    /// `group/project` or `group/sub/project`.
    private static func validProject(_ value: String) throws -> String {
        guard matches(value, "^[A-Za-z0-9_.-]+(/[A-Za-z0-9_.-]+)+$") else {
            throw FactoryError.message("--project takes a path such as group/project")
        }
        return value
    }

    private static func projectRef(_ path: String) -> String {
        path.addingPercentEncoding(withAllowedCharacters: .alphanumerics.union(CharacterSet(charactersIn: "-._~"))) ?? path
    }

    private static func readParent(_ account: String) throws -> (Data, String) {
        let data = try parent(account).read()
        return (data, String(decoding: data, as: UTF8.self))
    }

    /// Reports presence, then which user the PAT belongs to.
    static func check(_ arguments: [String]) async throws {
        let options = try Options(arguments, allowed: ["--account"])
        let account = try validAccount(try options.required("--account"))
        try await parent(account).check()
        var (data, token) = try readParent(account)
        defer { data.resetBytes(in: 0..<data.count) }
        let user: CurrentUser = try await request("user", token: token)
        print("pat_user=\(user.username)")
    }

    static func importParent(_ arguments: [String]) async throws {
        let options = try Options(arguments, allowed: ["--account"])
        let account = try validAccount(try options.required("--account"))
        var token = try readSecretFromTerminal(prompt: "GitLab personal access token (api scope): ")
        defer { token.resetBytes(in: 0..<token.count) }
        guard token.starts(with: Data("glpat-".utf8)) else {
            throw FactoryError.message("A GitLab personal access token starts with glpat-")
        }
        try await requireUserApproval(parent: parent(account), action: "store the GitLab personal access token for \(account) in Keychain.")
        try parent(account).write(token)
        print("import=complete")
        print("keychain_service=\(keychainPrefix).gitlab")
        print("keychain_account=\(account)")
    }

    /// A project deploy token: repository and registry access only.
    static func mintDeploy(_ arguments: [String]) async throws {
        let options = try Options(
            arguments,
            allowed: ["--account", "--project", "--name", "--expires-in",
                      "--env", "--path", "--secret-prefix"],
            repeatable: ["--scope"]
        )
        let account = try validAccount(try options.required("--account"))
        let project = try validProject(try options.required("--project"))
        let name = try options.required("--name")
        let scopes = options.all("--scope")
        guard let expiresIn = try parseExpiry(try options.required("--expires-in")) else {
            throw FactoryError.message("Deploy tokens need a finite --expires-in")
        }
        let destination = try SecretDestination(options)
        let prefix = try options.required("--secret-prefix")
        let userSecret = "\(prefix)_USERNAME"
        let tokenSecret = "\(prefix)_TOKEN"
        guard matches(name, "^[A-Za-z0-9 _.-]{1,100}$"), isSecretName(userSecret) else {
            throw FactoryError.message("One or more arguments have an invalid shape")
        }
        guard !scopes.isEmpty, Set(scopes).isSubset(of: deployScopes) else {
            throw FactoryError.message("--scope takes \(deployScopes.sorted().joined(separator: ", "))")
        }

        let expiresAt = iso8601(Date().addingTimeInterval(expiresIn))
        print("GitLab deploy token request")
        print("  Project: \(project)")
        print("  Name: \(name)")
        print("  Scopes: \(scopes.joined(separator: ", "))")
        print("  Expires: \(expiresAt)")
        print("  Destination: \(destination.label(userSecret)), \(destination.label(tokenSecret))")
        try await requireUserApproval(
            parent: parent(account), action: "create GitLab deploy token \(name) on \(project) (\(scopes.joined(separator: ", "))) and store it as \(tokenSecret)."
        )
        var (data, pat) = try readParent(account)
        defer { data.resetBytes(in: 0..<data.count) }

        let created: DeployToken = try await request(
            "projects/\(projectRef(project))/deploy_tokens", method: "POST", token: pat,
            body: try JSONSerialization.data(withJSONObject: ["name": name, "scopes": scopes, "expires_at": expiresAt])
        )
        do {
            guard let value = created.token, !value.isEmpty else {
                throw FactoryError.message("GitLab returned no token value")
            }
            // Read the token back from the project's list: it must be active with the requested scopes.
            let listed: [DeployToken] = try await request(
                "projects/\(projectRef(project))/deploy_tokens", query: [URLQueryItem(name: "active", value: "true")], token: pat
            )
            guard let found = listed.first(where: { $0.id == created.id }),
                  Set(found.scopes ?? []) == Set(scopes) else {
                throw FactoryError.message("The deploy token is missing or its scopes differ")
            }
            try destination.store(created.username, as: userSecret)
            try destination.store(value, as: tokenSecret)
        } catch {
            let _: Ignored? = try? await request(
                "projects/\(projectRef(project))/deploy_tokens/\(created.id)", method: "DELETE", token: pat
            )
            throw FactoryError.message("Deploy token was revoked because its check or vault write failed: \(error)")
        }

        print("mint=complete")
        print("token_verified=true")
        print("secrets=\(userSecret),\(tokenSecret)")
        print("parent_exposed=false")
    }

    /// Revokes the one active deploy token with this exact name.
    static func revokeDeploy(_ arguments: [String]) async throws {
        let options = try Options(arguments, allowed: ["--account", "--project", "--name"])
        let account = try validAccount(try options.required("--account"))
        let project = try validProject(try options.required("--project"))
        let name = try options.required("--name")

        print("GitLab deploy token revocation")
        print("  Project: \(project)")
        print("  Name: \(name)")
        try await requireUserApproval(parent: parent(account), action: "revoke the GitLab deploy token \(name) on \(project).")
        var (data, pat) = try readParent(account)
        defer { data.resetBytes(in: 0..<data.count) }

        let listed: [DeployToken] = try await request(
            "projects/\(projectRef(project))/deploy_tokens", query: [URLQueryItem(name: "active", value: "true")], token: pat
        )
        let found = listed.filter { $0.name == name }
        guard found.count == 1 else {
            throw FactoryError.message("Expected one active deploy token named \(name), found \(found.count)")
        }
        let _: Ignored? = try await request(
            "projects/\(projectRef(project))/deploy_tokens/\(found[0].id)", method: "DELETE", token: pat
        )
        print("revoke=complete")
        print("parent_exposed=false")
    }

    /// `--account <label> -- <command> [args...]`: one approved command with
    /// the PAT in `GITLAB_TOKEN` (read by `glab`). The command can read it.
    static func exec(_ arguments: [String]) async throws {
        guard let separator = arguments.firstIndex(of: "--"), separator + 1 < arguments.count else {
            throw FactoryError.message("Usage: exec gitlab --account <label> -- <command> [args...]")
        }
        let options = try Options(Array(arguments[..<separator]), allowed: ["--account"])
        let account = try validAccount(try options.required("--account"))
        try await runWithSecret(
            parent(account), env: "GITLAB_TOKEN", label: "GitLab PAT \(account)",
            command: Array(arguments[(separator + 1)...])
        )
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
        var components = URLComponents(url: apiBase, resolvingAgainstBaseURL: false)!
        // The project path is already percent-encoded; keep it as is.
        components.percentEncodedPath = apiBase.path + "/" + path
        if !query.isEmpty { components.queryItems = query }
        var request = URLRequest(url: components.url!)
        request.httpMethod = method
        request.httpBody = body
        request.setValue(token, forHTTPHeaderField: "PRIVATE-TOKEN")
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        let (data, response) = try await URLSession.shared.data(for: request)
        guard let http = response as? HTTPURLResponse else {
            throw FactoryError.message("GitLab returned no HTTP response")
        }
        guard (200..<300).contains(http.statusCode) else {
            let decoded = try? JSONDecoder().decode(APIError.self, from: data)
            throw FactoryError.message("GitLab HTTP \(http.statusCode): \(decoded?.message?.text ?? decoded?.error ?? "")")
        }
        return try JSONDecoder().decode(T.self, from: data.isEmpty ? Data("null".utf8) : data)
    }
}
