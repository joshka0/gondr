import Foundation

/// Fly.io tokens, minted through the GraphQL API with a parent org token kept
/// in Keychain item `gondr-token.fly` / `<org>` as the
/// `FlyV1 fm2_…` Authorization header value.
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
        struct Org: Decodable {
            let id: String
            let limitedAccessTokens: Tokens?
        }
        struct Tokens: Decodable { let nodes: [Token] }
        struct Token: Decodable {
            let id: String
            let name: String?
            let revokedAt: String?
        }
        let organization: Org?
    }

    private struct AppData: Decodable {
        struct App: Decodable {
            let name: String
            let limitedAccessTokens: OrgData.Tokens?
        }
        let app: App?
    }

    private struct CreateData: Decodable {
        struct Payload: Decodable { let limitedAccessToken: Token }
        struct Token: Decodable {
            let id: String
            let tokenHeader: String
        }
        let createLimitedAccessToken: Payload
    }

    private struct DeleteData: Decodable {}

    private static func parent(_ org: String) -> KeychainItem {
        KeychainItem(service: "gondr-token.fly", account: org)
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
        try await requireUserApproval(reason: "Store the Fly org token for \(org) in Keychain.")
        try parent(org).write(header)
        print("import=complete")
        print("keychain_service=gondr-token.fly")
        print("keychain_account=\(org)")
    }

    /// An app-scoped deploy token (profile `deploy`) for one existing app.
    static func mint(_ arguments: [String]) async throws {
        let options = try Options(
            arguments,
            allowed: ["--org", "--app", "--name", "--expires-in",
                      "--infisical-project", "--infisical-env", "--infisical-path", "--infisical-secret"]
        )
        let org = try validSlug(try options.required("--org"), "--org")
        let app = try validSlug(try options.required("--app"), "--app")
        let name = try options.required("--name")
        guard let expiresIn = try parseExpiry(try options.required("--expires-in")) else {
            throw FactoryError.message("Fly tokens need a finite --expires-in")
        }
        let destination = try InfisicalDestination(options)
        let secret = try options.required("--infisical-secret")
        guard name.count <= 120, isSecretName(secret) else {
            throw FactoryError.message("One or more arguments have an invalid shape")
        }

        let hours = Int(expiresIn / 3600)
        print("Fly token request")
        print("  Org: \(org)")
        print("  App: \(app) (deploy)")
        print("  Name: \(name)")
        print("  Expires: \(iso8601(Date().addingTimeInterval(expiresIn)))")
        print("  Destination: \(destination.label(secret))")
        print("Waiting for local approval…")
        fflush(stdout)
        try await requireUserApproval(
            reason: "Create Fly deploy token \(name) for app \(app) in \(org), expiring in \(hours)h, and store it as \(secret)."
        )
        var (data, auth) = try readParent(org)
        defer { data.resetBytes(in: 0..<data.count) }

        let orgData: OrgData = try await query(
            "query($slug: String!) { organization(slug: $slug) { id } }", ["slug": org], auth: auth
        )
        guard let orgID = orgData.organization?.id else {
            throw FactoryError.message("The parent cannot see org \(org)")
        }
        let created: CreateData = try await query(
            """
            mutation($name: String!, $organizationId: ID!, $profile: String!, $profileParams: JSON, $expiry: String!) {
              createLimitedAccessToken(input: {name: $name, organizationId: $organizationId, profile: $profile, profileParams: $profileParams, expiry: $expiry}) {
                limitedAccessToken { id tokenHeader }
              }
            }
            """,
            ["name": name, "organizationId": orgID, "profile": "deploy",
             "profileParams": ["app_id": app], "expiry": "\(hours)h"],
            auth: auth
        )
        let child = created.createLimitedAccessToken.limitedAccessToken
        do {
            // The child must read its own app.
            let readBack: AppData = try await query(
                "query($name: String!) { app(name: $name) { name } }", ["name": app], auth: child.tokenHeader
            )
            guard readBack.app?.name == app else {
                throw FactoryError.message("The child cannot read app \(app)")
            }
            try destination.store(child.tokenHeader, as: secret)
        } catch {
            let _: DeleteData? = try? await query(
                "mutation($input: DeleteLimitedAccessTokenInput!) { deleteLimitedAccessToken(input: $input) { token } }",
                ["input": ["id": child.id]], auth: auth
            )
            throw FactoryError.message("Derived token was revoked because its check or vault write failed: \(error)")
        }

        print("mint=complete")
        print("derived_token_verified=true")
        print("infisical_secret=\(secret)")
        print("parent_exposed=false")
    }

    /// Revokes the one live token with this exact name, among the app's
    /// tokens when `--app` is given, else among the org's.
    static func revoke(_ arguments: [String]) async throws {
        let options = try Options(arguments, allowed: ["--org", "--app", "--name"])
        let org = try validSlug(try options.required("--org"), "--org")
        let app = try options.optional("--app").map { try validSlug($0, "--app") }
        let name = try options.required("--name")
        guard name.count <= 120 else { throw FactoryError.message("--name is too long") }

        print("Fly token revocation")
        print("  Org: \(org)")
        if let app { print("  App: \(app)") }
        print("  Name: \(name)")
        print("Waiting for local approval…")
        fflush(stdout)
        try await requireUserApproval(reason: "Revoke the Fly token \(name) in \(org).")
        var (data, auth) = try readParent(org)
        defer { data.resetBytes(in: 0..<data.count) }

        let tokens: [OrgData.Token]
        if let app {
            let result: AppData = try await query(
                "query($name: String!) { app(name: $name) { name limitedAccessTokens { nodes { id name revokedAt } } } }",
                ["name": app], auth: auth
            )
            tokens = result.app?.limitedAccessTokens?.nodes ?? []
        } else {
            let result: OrgData = try await query(
                "query($slug: String!) { organization(slug: $slug) { id limitedAccessTokens { nodes { id name revokedAt } } } }",
                ["slug": org], auth: auth
            )
            tokens = result.organization?.limitedAccessTokens?.nodes ?? []
        }
        let found = tokens.filter { $0.name == name && $0.revokedAt == nil }
        guard found.count == 1 else {
            throw FactoryError.message("Expected one live token named \(name), found \(found.count)")
        }
        let _: DeleteData = try await query(
            "mutation($input: DeleteLimitedAccessTokenInput!) { deleteLimitedAccessToken(input: $input) { token } }",
            ["input": ["id": found[0].id]], auth: auth
        )
        print("revoke=complete")
        print("parent_exposed=false")
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
        let decoded = try? JSONDecoder().decode(GraphQLResponse<T>.self, from: data)
        guard (200..<300).contains(http.statusCode), let decoded, decoded.errors?.isEmpty ?? true, let result = decoded.data else {
            let message = decoded?.errors?.map(\.message).joined(separator: "; ") ?? ""
            throw FactoryError.message("Fly HTTP \(http.statusCode): \(message)")
        }
        return result
    }
}
