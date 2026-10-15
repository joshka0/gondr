import Foundation

/// PlanetScale service tokens, minted with a parent service token kept in
/// Keychain item `gondr-token.planetscale` / `<org>` as
/// `<id>:<token>` (the API's Authorization header value).
enum PlanetScale {
    private static let apiBase = URL(string: "https://api.planetscale.com/v1")!

    private struct CreatedToken: Decodable {
        let id: String
        let token: String?
    }

    private struct ListedToken: Decodable {
        let id: String
        let name: String?
    }

    private struct Access: Decodable {
        let access: String
    }

    private struct NamedOrg: Decodable {
        let name: String
    }

    private struct DataList<T: Decodable>: Decodable {
        let data: [T]
    }

    private struct APIError: Decodable {
        let message: String?
    }

    private static func parent(_ org: String) -> KeychainItem {
        KeychainItem(service: "gondr-token.planetscale", account: org)
    }

    private static func validOrg(_ org: String) throws -> String {
        guard matches(org, "^[A-Za-z0-9_-]{1,64}$") else {
            throw FactoryError.message("--org has an invalid shape")
        }
        return org
    }

    /// Reports presence, then the HTTP status of two parent reads: the
    /// org itself and its service-token list. Never prints a body.
    static func check(_ arguments: [String]) async throws {
        let options = try Options(arguments, allowed: ["--org"])
        let org = try validOrg(try options.required("--org"))
        try await parent(org).check()
        var parentData = try parent(org).read()
        defer { parentData.resetBytes(in: 0..<parentData.count) }
        let auth = String(decoding: parentData, as: UTF8.self)
        var listRequest = URLRequest(url: apiBase.appending(path: "organizations"))
        listRequest.setValue(auth, forHTTPHeaderField: "Authorization")
        listRequest.setValue("application/json", forHTTPHeaderField: "Accept")
        let (listData, listResponse) = try await URLSession.shared.data(for: listRequest)
        print("organizations_http=\((listResponse as? HTTPURLResponse)?.statusCode ?? 0)")
        if let orgs = try? JSONDecoder().decode(DataList<NamedOrg>.self, from: listData) {
            print("visible_orgs=\(orgs.data.map(\.name).joined(separator: ","))")
        }
        for (label, path) in [("org", "organizations/\(org)"), ("service_tokens", "organizations/\(org)/service-tokens")] {
            var request = URLRequest(url: apiBase.appending(path: path))
            request.setValue(auth, forHTTPHeaderField: "Authorization")
            request.setValue("application/json", forHTTPHeaderField: "Accept")
            let (_, response) = try await URLSession.shared.data(for: request)
            print("\(label)_http=\((response as? HTTPURLResponse)?.statusCode ?? 0)")
        }
    }

    static func importParent(_ arguments: [String]) async throws {
        let options = try Options(arguments, allowed: ["--org"])
        let org = try validOrg(try options.required("--org"))
        var id = try readSecretFromTerminal(prompt: "PlanetScale service token ID: ")
        var token = try readSecretFromTerminal(prompt: "PlanetScale service token: ")
        defer {
            id.resetBytes(in: 0..<id.count)
            token.resetBytes(in: 0..<token.count)
        }
        guard !id.contains(UInt8(ascii: ":")), !id.starts(with: Data("pscale_".utf8)) else {
            throw FactoryError.message("The first value must be the token ID (a short string), not the token")
        }
        guard token.starts(with: Data("pscale_tkn_".utf8)) else {
            throw FactoryError.message("The second value must be the token, which starts with pscale_tkn_")
        }
        try await requireUserApproval(action: "store the PlanetScale parent service token for \(org) in Keychain.")
        try parent(org).write(id + Data(":".utf8) + token)
        print("import=complete")
        print("keychain_service=gondr-token.planetscale")
        print("keychain_account=\(org)")
    }

    static func mint(_ arguments: [String]) async throws {
        let options = try Options(
            arguments,
            allowed: ["--org", "--name", "--expires-in", "--database",
                      "--infisical-project", "--infisical-env", "--infisical-path", "--infisical-secret-prefix"],
            repeatable: ["--org-access", "--database-access"]
        )
        let org = try validOrg(try options.required("--org"))
        let name = try options.required("--name")
        let expiresIn = try parseExpiry(try options.required("--expires-in"))
        let database = options.optional("--database")
        let orgAccess = options.all("--org-access")
        let databaseAccess = options.all("--database-access")
        let destination = try InfisicalDestination(options)
        let prefix = try options.required("--infisical-secret-prefix")
        let idSecret = "\(prefix)_SERVICE_TOKEN_ID"
        let tokenSecret = "\(prefix)_SERVICE_TOKEN"

        guard (database != nil) == !databaseAccess.isEmpty else {
            throw FactoryError.message("--database and --database-access are both-or-neither")
        }
        let accesses = orgAccess + databaseAccess
        guard name.count <= 120,
              database.map({ matches($0, "^[A-Za-z0-9_-]{1,64}$") }) ?? true,
              accesses.allSatisfy({ matches($0, "^[a-z_]+$") }),
              isSecretName(idSecret) else {
            throw FactoryError.message("One or more arguments have an invalid shape")
        }
        guard !accesses.isEmpty, accesses.count <= 24 else {
            throw FactoryError.message("Request between one and twenty-four accesses")
        }
        guard accesses.allSatisfy({ !$0.contains("service_token") }) else {
            throw FactoryError.message("Derived tokens may not manage service tokens")
        }

        let ttl = expiresIn.map { Int($0) }
        print("PlanetScale service token request")
        print("  Org: \(org)")
        print("  Name: \(name)")
        if !orgAccess.isEmpty { print("  Org access: \(orgAccess.joined(separator: ", "))") }
        if let database { print("  Database \(database): \(databaseAccess.joined(separator: ", "))") }
        print("  Expires: \(expiresIn.map { iso8601(Date().addingTimeInterval($0)) } ?? "never")")
        print("  Destination: \(destination.label(idSecret)), \(destination.label(tokenSecret))")
        try await requireUserApproval(
            action: "create PlanetScale token \(name) in \(org) (\(accesses.joined(separator: ", "))) and store it as \(prefix)_SERVICE_TOKEN."
        )
        var parentData = try parent(org).read()
        defer { parentData.resetBytes(in: 0..<parentData.count) }
        let auth = String(decoding: parentData, as: UTF8.self)

        var body: [String: Any] = ["name": name]
        if let ttl { body["ttl"] = ttl }
        let created: CreatedToken = try await request(
            "organizations/\(org)/service-tokens", method: "POST", auth: auth,
            body: try JSONSerialization.data(withJSONObject: body)
        )
        do {
            guard let token = created.token, !token.isEmpty else {
                throw FactoryError.message("PlanetScale returned no token value")
            }
            if !orgAccess.isEmpty {
                let _: DataList<Access> = try await request(
                    "organizations/\(org)/service-tokens/\(created.id)/access", method: "POST", auth: auth,
                    body: try JSONSerialization.data(withJSONObject: ["access": orgAccess])
                )
            }
            if let database {
                let _: DataList<Access> = try await request(
                    "organizations/\(org)/service-tokens/\(created.id)/access", method: "POST", auth: auth,
                    body: try JSONSerialization.data(withJSONObject: ["database": database, "access": databaseAccess])
                )
            }
            // Read the grants back: every requested access must be present.
            let granted: DataList<Access> = try await request(
                "organizations/\(org)/service-tokens/\(created.id)/access", auth: auth
            )
            let missing = Set(accesses).subtracting(granted.data.map(\.access))
            guard missing.isEmpty else {
                throw FactoryError.message("Grants missing after create: \(missing.sorted().joined(separator: ", "))")
            }
            try destination.store(created.id, as: idSecret)
            try destination.store(token, as: tokenSecret)
        } catch {
            let _: DataList<Access>? = try? await request(
                "organizations/\(org)/service-tokens/\(created.id)", method: "DELETE", auth: auth
            )
            throw FactoryError.message("Derived token was deleted because a grant, check, or vault write failed: \(error)")
        }

        print("mint=complete")
        print("grants_verified=true")
        print("infisical_secrets=\(idSecret),\(tokenSecret)")
        print("parent_exposed=false")
    }

    /// Deletes the one service token with this exact name. Fails closed on
    /// zero or several matches.
    static func revoke(_ arguments: [String]) async throws {
        let options = try Options(arguments, allowed: ["--org", "--name"])
        let org = try validOrg(try options.required("--org"))
        let name = try options.required("--name")
        guard name.count <= 120 else { throw FactoryError.message("--name is too long") }

        print("PlanetScale service token revocation")
        print("  Org: \(org)")
        print("  Name: \(name)")
        try await requireUserApproval(action: "revoke the PlanetScale service token \(name) in \(org).")
        var parentData = try parent(org).read()
        defer { parentData.resetBytes(in: 0..<parentData.count) }
        let auth = String(decoding: parentData, as: UTF8.self)

        var found: [ListedToken] = []
        var page = 1
        while true {
            let listed: DataList<ListedToken> = try await request(
                "organizations/\(org)/service-tokens",
                query: [URLQueryItem(name: "per_page", value: "100"), URLQueryItem(name: "page", value: String(page))],
                auth: auth
            )
            found += listed.data.filter { $0.name == name }
            if listed.data.count < 100 { break }
            page += 1
        }
        guard found.count == 1 else {
            throw FactoryError.message("Expected one token named \(name), found \(found.count)")
        }
        let _: DataList<Access>? = try await request(
            "organizations/\(org)/service-tokens/\(found[0].id)", method: "DELETE", auth: auth
        )
        print("revoke=complete")
        print("parent_exposed=false")
    }

    /// Decodes `T` from a 2xx body. An empty body (204) decodes to nil when
    /// `T` is optional.
    private static func request<T: Decodable>(
        _ path: String,
        method: String = "GET",
        query: [URLQueryItem] = [],
        auth: String,
        body: Data? = nil
    ) async throws -> T {
        var request = URLRequest(url: apiBase.appending(path: path).appending(queryItems: query))
        request.httpMethod = method
        request.httpBody = body
        request.setValue(auth, forHTTPHeaderField: "Authorization")
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        let (data, response) = try await URLSession.shared.data(for: request)
        guard let http = response as? HTTPURLResponse else {
            throw FactoryError.message("PlanetScale returned no HTTP response")
        }
        guard (200..<300).contains(http.statusCode) else {
            let message = (try? JSONDecoder().decode(APIError.self, from: data))?.message ?? ""
            throw FactoryError.message("PlanetScale HTTP \(http.statusCode): \(message)")
        }
        return try JSONDecoder().decode(T.self, from: data.isEmpty ? Data("null".utf8) : data)
    }
}
