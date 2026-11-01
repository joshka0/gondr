import Foundation

/// PlanetScale service tokens, minted with a parent service token kept in
/// Keychain item `<prefix>.planetscale` / `<org>` as
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
        KeychainItem(service: "\(keychainPrefix).planetscale", account: org)
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
        print("keychain_service=\(keychainPrefix).planetscale")
        print("keychain_account=\(org)")
    }

    /// The accesses a child asks for, validated once for `mint` and `exec`.
    private struct Grant {
        let orgAccess: [String]
        let database: String?
        let databaseAccess: [String]
        var all: [String] { orgAccess + databaseAccess }

        init(_ options: Options) throws {
            orgAccess = options.all("--org-access")
            database = options.optional("--database")
            databaseAccess = options.all("--database-access")
            guard (database != nil) == !databaseAccess.isEmpty else {
                throw FactoryError.message("--database and --database-access are both-or-neither")
            }
            guard database.map({ matches($0, "^[A-Za-z0-9_-]{1,64}$") }) ?? true,
                  all.allSatisfy({ matches($0, "^[a-z_]+$") }) else {
                throw FactoryError.message("One or more arguments have an invalid shape")
            }
            guard !all.isEmpty, all.count <= 24 else {
                throw FactoryError.message("Request between one and twenty-four accesses")
            }
            guard all.allSatisfy({ !$0.contains("service_token") }) else {
                throw FactoryError.message("Derived tokens may not manage service tokens")
            }
        }

        func printLines() {
            if !orgAccess.isEmpty { print("  Org access: \(orgAccess.joined(separator: ", "))") }
            if let database { print("  Database \(database): \(databaseAccess.joined(separator: ", "))") }
        }
    }

    /// Creates a child token, grants `grant`, and reads the grants back. On
    /// any failure after the create, deletes the child and throws.
    private static func createChild(
        org: String, name: String, ttl: Int?, grant: Grant, auth: String
    ) async throws -> (id: String, token: String) {
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
            if !grant.orgAccess.isEmpty {
                let _: DataList<Access> = try await request(
                    "organizations/\(org)/service-tokens/\(created.id)/access", method: "POST", auth: auth,
                    body: try JSONSerialization.data(withJSONObject: ["access": grant.orgAccess])
                )
            }
            if let database = grant.database {
                let _: DataList<Access> = try await request(
                    "organizations/\(org)/service-tokens/\(created.id)/access", method: "POST", auth: auth,
                    body: try JSONSerialization.data(withJSONObject: ["database": database, "access": grant.databaseAccess])
                )
            }
            // Read the grants back: every requested access must be present.
            let granted: DataList<Access> = try await request(
                "organizations/\(org)/service-tokens/\(created.id)/access", auth: auth
            )
            let missing = Set(grant.all).subtracting(granted.data.map(\.access))
            guard missing.isEmpty else {
                throw FactoryError.message("Grants missing after create: \(missing.sorted().joined(separator: ", "))")
            }
            return (created.id, token)
        } catch {
            try? await deleteChild(org: org, id: created.id, auth: auth)
            throw FactoryError.message("Derived token was deleted because a grant or check failed: \(error)")
        }
    }

    private static func deleteChild(org: String, id: String, auth: String) async throws {
        let _: DataList<Access>? = try await request(
            "organizations/\(org)/service-tokens/\(id)", method: "DELETE", auth: auth
        )
    }

    static func mint(_ arguments: [String]) async throws {
        let options = try Options(
            arguments,
            allowed: ["--org", "--name", "--expires-in", "--database",
                      "--env", "--path", "--secret-prefix"],
            repeatable: ["--org-access", "--database-access"]
        )
        let org = try validOrg(try options.required("--org"))
        let name = try options.required("--name")
        let expiresIn = try parseExpiry(try options.required("--expires-in"))
        let grant = try Grant(options)
        let destination = try SecretDestination(options)
        let prefix = try options.required("--secret-prefix")
        let idSecret = "\(prefix)_SERVICE_TOKEN_ID"
        let tokenSecret = "\(prefix)_SERVICE_TOKEN"
        guard name.count <= 120, isSecretName(idSecret) else {
            throw FactoryError.message("One or more arguments have an invalid shape")
        }

        print("PlanetScale service token request")
        print("  Org: \(org)")
        print("  Name: \(name)")
        grant.printLines()
        print("  Expires: \(expiresIn.map { iso8601(Date().addingTimeInterval($0)) } ?? "never")")
        print("  Destination: \(destination.label(idSecret)), \(destination.label(tokenSecret))")
        try await requireUserApproval(
            action: "create PlanetScale token \(name) in \(org) (\(grant.all.joined(separator: ", "))) and store it as \(prefix)_SERVICE_TOKEN."
        )
        var parentData = try parent(org).read()
        defer { parentData.resetBytes(in: 0..<parentData.count) }
        let auth = String(decoding: parentData, as: UTF8.self)

        let child = try await createChild(org: org, name: name, ttl: expiresIn.map { Int($0) }, grant: grant, auth: auth)
        do {
            try destination.store(child.id, as: idSecret)
            try destination.store(child.token, as: tokenSecret)
        } catch {
            try? await deleteChild(org: org, id: child.id, auth: auth)
            throw FactoryError.message("Derived token was deleted because the vault write failed: \(error)")
        }

        print("mint=complete")
        print("grants_verified=true")
        print("secrets=\(idSecret),\(tokenSecret)")
        print("parent_exposed=false")
    }

    /// `--org <org> [--org-access a ...] [--database db --database-access a ...]
    /// --expires-in <N>h -- <command>`: mints a child, runs one command with
    /// `PLANETSCALE_SERVICE_TOKEN_ID`, `PLANETSCALE_SERVICE_TOKEN` and
    /// `PLANETSCALE_ORG` set (read by `pscale`), then deletes the child. The
    /// TTL ends the child if this process dies before the delete.
    static func exec(_ arguments: [String]) async throws {
        guard let separator = arguments.firstIndex(of: "--"), separator + 1 < arguments.count else {
            throw FactoryError.message(
                "Usage: exec planetscale --org <org> [--org-access <a>] [--database <db> --database-access <a>] --expires-in <N>h -- <command>"
            )
        }
        let options = try Options(
            Array(arguments[..<separator]), allowed: ["--org", "--expires-in", "--database"],
            repeatable: ["--org-access", "--database-access"]
        )
        let org = try validOrg(try options.required("--org"))
        guard let expiresIn = try parseExpiry(try options.required("--expires-in")), expiresIn <= 24 * 3600 else {
            throw FactoryError.message("exec planetscale needs --expires-in of at most 24h")
        }
        let grant = try Grant(options)
        let command = Array(arguments[(separator + 1)...])
        let shown = command.joined(separator: " ")
        let name = "factory-exec-\(Int(Date().timeIntervalSince1970))-\(getpid())"

        print("Command request")
        print("  Credential: PlanetScale child token in \(org), deleted when the command exits (TTL \(Int(expiresIn / 3600))h)")
        grant.printLines()
        print("  Command: \(shown)")
        try await requireUserApproval(
            action: "run with a PlanetScale token for \(org) (\(grant.all.joined(separator: ", "))): \(shown.count > 160 ? String(shown.prefix(160)) + "…" : shown)"
        )
        var parentData = try parent(org).read()
        defer { parentData.resetBytes(in: 0..<parentData.count) }
        let auth = String(decoding: parentData, as: UTF8.self)

        let child = try await createChild(org: org, name: name, ttl: Int(expiresIn), grant: grant, auth: auth)
        let status: Int32
        do {
            status = try runChild(command, environment: [
                "PLANETSCALE_SERVICE_TOKEN_ID": child.id,
                "PLANETSCALE_SERVICE_TOKEN": child.token,
                "PLANETSCALE_ORG": org,
            ])
        } catch {
            try? await deleteChild(org: org, id: child.id, auth: auth)
            throw error
        }
        do {
            try await deleteChild(org: org, id: child.id, auth: auth)
            FileHandle.standardError.write(Data("planetscale_child=deleted\n".utf8))
        } catch {
            FileHandle.standardError.write(Data("planetscale_child=delete_failed name=\(name) (its TTL still ends it): \(error)\n".utf8))
        }
        exit(status)
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
