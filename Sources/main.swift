import Foundation
import LocalAuthentication
import Security

private struct CloudflareEnvelope<T: Decodable>: Decodable {
    let success: Bool
    let result: T?
    let errors: [CloudflareError]
}

private struct CloudflareError: Decodable {
    let code: Int?
    let message: String
}

private struct PermissionGroup {
    let id: String
    let name: String
    let scopes: [String]
}

private struct Zone: Decodable {
    struct Account: Decodable { let id: String }
    let id: String
    let name: String
    let account: Account
}

private struct CreatedToken: Decodable {
    let id: String
    let value: String
}

private struct VerifyResult: Decodable {
    let status: String
}

private struct ListedToken: Decodable {
    let id: String
    let name: String
}

private struct Arguments {
    let tokenName: String
    /// Absent for an account-only mint: zone flags and zone permissions are
    /// both-or-neither, enforced in `validate`.
    let zoneName: String?
    let accountID: String
    let zoneID: String?
    let accountPermissions: [String]
    let zonePermissions: [String]
    /// Nil only for an explicit `--expires-in never`.
    let expiresOn: Date?
    let allowedIPs: [String]
    let infisicalProject: String
    let infisicalEnvironment: String
    let infisicalPath: String
    let infisicalSecret: String
}

/// Shape of `GET accounts/{id}/tokens/permission_groups` rows.
private struct APIPermissionGroup: Decodable {
    let id: String
    let name: String?
    let scopes: [String]?
}

private enum MintError: Error, CustomStringConvertible {
    case message(String)

    var description: String {
        switch self { case let .message(message): message }
    }
}

@main
private struct CloudflareTokenMint {
    private static let bootstrapService = "gondr-token.cloudflare"
    private static let bootstrapAccount = "bootstrap"
    private static let apiBase = URL(string: "https://api.cloudflare.com/client/v4")!
    // Cloudflare's permission-group listing requires user-level authentication,
    // which deliberately narrow token-factory credentials do not possess.
    // Keep the approved groups pinned here, following Alchemy's typed static
    // permission catalog, and fail closed for every other permission name.
    private static let approvedPermissionGroups = [
        PermissionGroup(
            id: "e4589eb09e63436686cd64252a3aebeb",
            name: "Email Routing Addresses Write",
            scopes: ["com.cloudflare.api.account"]
        ),
        PermissionGroup(
            id: "79b3ec0d10ce4148a8f8bdc0cc5f97f2",
            name: "Email Routing Rules Write",
            scopes: ["com.cloudflare.api.account.zone"]
        ),
        PermissionGroup(
            id: "3030687196b94b638145a3953da2b699",
            name: "Zone Settings Write",
            scopes: ["com.cloudflare.api.account.zone"]
        ),
        PermissionGroup(
            id: "4755a26eedb94da69e1066d98aa820be",
            name: "DNS Write",
            scopes: ["com.cloudflare.api.account.zone"]
        ),
    ]

    static func main() async {
        do {
            let rawArguments = Array(CommandLine.arguments.dropFirst())
            if rawArguments == ["--check-keychain"] {
                try await requireUserApproval(
                    reason: "Check whether the host-wide Cloudflare token factory credential is available."
                )
                var bootstrap = try readBootstrapCredential()
                let byteCount = bootstrap.count
                bootstrap.resetBytes(in: 0..<bootstrap.count)
                print("keychain_service=\(bootstrapService)")
                print("keychain_account=\(bootstrapAccount)")
                print("credential_present=\(byteCount > 0)")
                print("credential_exposed=false")
                return
            }

            if rawArguments.first == "--revoke" {
                try await revoke(rawArguments)
                return
            }

            let arguments = try parseArguments(rawArguments)
            try validate(arguments)

            let requestedPermissions = arguments.accountPermissions + arguments.zonePermissions
            let zoneLabel = arguments.zoneName ?? "(account-only)"
            print("Cloudflare token request")
            print("  Name: \(arguments.tokenName)")
            print("  Zone: \(zoneLabel)")
            print("  Permissions: \(requestedPermissions.joined(separator: ", "))")
            print("  Expires: \(arguments.expiresOn.map(cloudflareTimestamp) ?? "never")")
            print("  Allowed IPs: \(arguments.allowedIPs.isEmpty ? "any" : arguments.allowedIPs.joined(separator: ", "))")
            print("  Destination: Infisical \(arguments.infisicalPath == "/" ? "" : arguments.infisicalPath)/\(arguments.infisicalSecret)")
            print("Waiting for local approval…")

            try await requireUserApproval(
                reason: "Create \(arguments.tokenName) for \(zoneLabel), expiring \(arguments.expiresOn.map(cloudflareTimestamp) ?? "never"), and store it as \(arguments.infisicalSecret)."
            )
            var bootstrap = try readBootstrapCredential()
            defer { bootstrap.resetBytes(in: 0..<bootstrap.count) }

            let bootstrapToken = String(decoding: bootstrap, as: UTF8.self)
            let permissionGroups = try await resolvePermissionGroups(
                arguments: arguments,
                bootstrapToken: bootstrapToken
            )
            let payload = try buildTokenPayload(
                arguments: arguments,
                permissionGroups: permissionGroups
            )
            let created = try await createToken(
                payload: payload,
                accountID: arguments.accountID,
                bootstrapToken: bootstrapToken
            )

            do {
                try await verifyToken(created.value, accountID: arguments.accountID)
                try storeInInfisical(created.value, arguments: arguments)
            } catch {
                try? await revokeToken(
                    id: created.id,
                    accountID: arguments.accountID,
                    bootstrapToken: bootstrapToken
                )
                throw MintError.message("Derived token was not retained because verification or vault storage failed: \(error)")
            }

            print("mint=complete")
            print("derived_token_verified=true")
            print("infisical_secret=\(arguments.infisicalSecret)")
            print("bootstrap_exposed=false")
        } catch {
            FileHandle.standardError.write(Data(("mint=failed reason=\(error)\n").utf8))
            exit(1)
        }
    }

    private static func parseArguments(_ values: [String]) throws -> Arguments {
        var scalars: [String: String] = [:]
        var accountPermissions: [String] = []
        var zonePermissions: [String] = []
        var allowedIPs: [String] = []
        var index = 0

        while index < values.count {
            let key = values[index]
            guard key.hasPrefix("--"), index + 1 < values.count else {
                throw MintError.message("Expected --option value arguments")
            }
            let value = values[index + 1]
            switch key {
            case "--account-permission": accountPermissions.append(value)
            case "--zone-permission": zonePermissions.append(value)
            case "--allow-ip": allowedIPs.append(value)
            default:
                guard scalars[key] == nil else {
                    throw MintError.message("Duplicate option: \(key)")
                }
                scalars[key] = value
            }
            index += 2
        }

        func required(_ key: String) throws -> String {
            guard let value = scalars[key], !value.isEmpty else {
                throw MintError.message("Missing required option: \(key)")
            }
            return value
        }

        func optional(_ key: String) -> String? {
            guard let value = scalars[key], !value.isEmpty else { return nil }
            return value
        }

        return Arguments(
            tokenName: try required("--name"),
            zoneName: optional("--zone"),
            accountID: try required("--account-id"),
            zoneID: optional("--zone-id"),
            accountPermissions: accountPermissions,
            zonePermissions: zonePermissions,
            expiresOn: try parseExpiry(try required("--expires-in")),
            allowedIPs: allowedIPs,
            infisicalProject: try required("--infisical-project"),
            infisicalEnvironment: try required("--infisical-env"),
            infisicalPath: try required("--infisical-path"),
            infisicalSecret: try required("--infisical-secret")
        )
    }

    /// `<N>h` or `<N>d` from now, or `never`. A long-lived token is always an
    /// explicit choice.
    private static func parseExpiry(_ value: String) throws -> Date? {
        if value == "never" { return nil }
        guard value.range(of: "^[1-9][0-9]{0,3}[hd]$", options: .regularExpression) != nil,
              let amount = Double(value.dropLast()) else {
            throw MintError.message("--expires-in takes <N>h, <N>d, or never")
        }
        let hours = value.hasSuffix("d") ? amount * 24 : amount
        return Date().addingTimeInterval(hours * 3600)
    }

    private static func cloudflareTimestamp(_ date: Date) -> String {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime]
        return formatter.string(from: date)
    }

    /// An IPv4 or IPv6 address with an optional prefix length.
    private static func isCIDR(_ value: String) -> Bool {
        let parts = value.split(separator: "/", omittingEmptySubsequences: false)
        guard parts.count <= 2, let address = parts.first.map(String.init) else { return false }
        var buffer = [UInt8](repeating: 0, count: 16)
        let family: Int32
        if inet_pton(AF_INET, address, &buffer) == 1 {
            family = AF_INET
        } else if inet_pton(AF_INET6, address, &buffer) == 1 {
            family = AF_INET6
        } else {
            return false
        }
        guard parts.count == 2 else { return true }
        guard let prefix = Int(parts[1]) else { return false }
        return (0...(family == AF_INET ? 32 : 128)).contains(prefix)
    }

    private static func validate(_ arguments: Arguments) throws {
        // Zone identity and zone permissions travel together: an account-only
        // mint carries neither, a zone mint carries all three. A zone name
        // without a zone permission would silently widen nothing but proves a
        // confused request; fail closed on incoherence.
        let hasZoneArguments = arguments.zoneName != nil || arguments.zoneID != nil
        let hasZonePermissions = !arguments.zonePermissions.isEmpty
        guard hasZoneArguments == hasZonePermissions,
              (arguments.zoneName != nil) == (arguments.zoneID != nil) else {
            throw MintError.message("Zone name, zone id, and zone permissions are both-or-neither")
        }

        guard arguments.tokenName.count <= 120,
              arguments.zoneName.map({ $0.range(of: "^[A-Za-z0-9.-]+$", options: .regularExpression) != nil }) ?? true,
              arguments.accountID.range(of: "^[0-9a-f]{32}$", options: .regularExpression) != nil,
              arguments.zoneID.map({ $0.range(of: "^[0-9a-f]{32}$", options: .regularExpression) != nil }) ?? true,
              arguments.infisicalProject.range(of: "^[0-9a-f-]{36}$", options: .regularExpression) != nil,
              arguments.infisicalEnvironment.range(of: "^[A-Za-z0-9_-]+$", options: .regularExpression) != nil,
              arguments.infisicalPath.hasPrefix("/"),
              !arguments.infisicalPath.contains(".."),
              arguments.infisicalSecret.range(of: "^[A-Z][A-Z0-9_]+$", options: .regularExpression) != nil else {
            throw MintError.message("One or more arguments have an invalid shape")
        }

        guard arguments.allowedIPs.count <= 16, arguments.allowedIPs.allSatisfy(isCIDR) else {
            throw MintError.message("--allow-ip takes up to sixteen IPv4 or IPv6 addresses or CIDR ranges")
        }

        let permissions = arguments.accountPermissions + arguments.zonePermissions
        guard !permissions.isEmpty, permissions.count <= 12 else {
            throw MintError.message("Request between one and twelve permissions")
        }
        guard permissions.allSatisfy({ !$0.localizedCaseInsensitiveContains("API Token") }) else {
            throw MintError.message("Derived tokens may not manage API tokens")
        }
    }

    private static func requireUserApproval(reason: String) async throws {
        let context = LAContext()
        context.localizedReason = reason
        var evaluationError: NSError?
        guard context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &evaluationError) else {
            throw MintError.message("Local user authentication is unavailable")
        }
        let approved = try await context.evaluatePolicy(
            .deviceOwnerAuthentication,
            localizedReason: context.localizedReason
        )
        guard approved else { throw MintError.message("User rejected the request") }
    }

    private static func readBootstrapCredential() throws -> Data {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: bootstrapService,
            kSecAttrAccount as String: bootstrapAccount,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status == errSecSuccess, let data = result as? Data, !data.isEmpty else {
            throw MintError.message("Keychain bootstrap credential is unavailable (status \(status))")
        }
        return data
    }

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
            throw MintError.message("Cloudflare returned no HTTP response")
        }
        let envelope = try JSONDecoder().decode(CloudflareEnvelope<T>.self, from: data)
        guard (200..<300).contains(http.statusCode), envelope.success, let result = envelope.result else {
            let message = envelope.errors.map(\.message).joined(separator: "; ")
            throw MintError.message("Cloudflare HTTP \(http.statusCode): \(message)")
        }
        return result
    }

    /**
     * Pinned catalog first; anything unpinned resolves live through the
     * ACCOUNT-scoped listing (`accounts/{id}/tokens/permission_groups`),
     * which — unlike the user-scoped listing the pinned catalog exists to
     * avoid — is reachable by a narrow token-factory bootstrap. Exact name
     * match with the expected scope, fail closed on absent or ambiguous.
     */
    private static func resolvePermissionGroups(
        arguments: Arguments,
        bootstrapToken: String
    ) async throws -> [PermissionGroup] {
        let requested = Set(arguments.accountPermissions + arguments.zonePermissions)
        let pinnedNames = Set(approvedPermissionGroups.map(\.name))
        let unpinned = requested.subtracting(pinnedNames)
        guard !unpinned.isEmpty else { return approvedPermissionGroups }

        let listed: [APIPermissionGroup] = try await request(
            "accounts/\(arguments.accountID)/tokens/permission_groups",
            token: bootstrapToken
        )
        let resolved: [PermissionGroup] = unpinned.map { name in
            let matches = listed.filter { $0.name == name }
            return PermissionGroup(
                id: matches.first?.id ?? "",
                name: name,
                scopes: matches.count == 1 ? (matches.first?.scopes ?? []) : []
            )
        }
        // A name the account listing cannot uniquely produce keeps an empty
        // scope list here and fails closed in `buildTokenPayload`'s scope
        // filter, exactly like an unpinned name did before this path existed.
        return approvedPermissionGroups + resolved
    }

    private static func buildTokenPayload(
        arguments: Arguments,
        permissionGroups: [PermissionGroup]
    ) throws -> Data {
        let byName = Dictionary(grouping: permissionGroups, by: \.name)

        func groupIDs(for names: [String], expectedScope: String) throws -> [[String: String]] {
            try names.map { name in
                let matches = (byName[name] ?? []).filter { $0.scopes.contains(expectedScope) }
                guard matches.count == 1 else {
                    throw MintError.message("Permission is unavailable or ambiguous for \(expectedScope): \(name)")
                }
                return ["id": matches[0].id, "name": matches[0].name]
            }
        }

        var policies: [[String: Any]] = []
        if !arguments.accountPermissions.isEmpty {
            policies.append([
                "effect": "allow",
                "resources": ["com.cloudflare.api.account.\(arguments.accountID)": "*"],
                "permission_groups": try groupIDs(
                    for: arguments.accountPermissions,
                    expectedScope: "com.cloudflare.api.account"
                ),
            ])
        }
        if !arguments.zonePermissions.isEmpty {
            guard let zoneID = arguments.zoneID else {
                throw MintError.message("Zone permissions require a zone id")
            }
            policies.append([
                "effect": "allow",
                "resources": ["com.cloudflare.api.account.zone.\(zoneID)": "*"],
                "permission_groups": try groupIDs(
                    for: arguments.zonePermissions,
                    expectedScope: "com.cloudflare.api.account.zone"
                ),
            ])
        }
        var payload: [String: Any] = [
            "name": arguments.tokenName,
            "policies": policies,
        ]
        if let expiresOn = arguments.expiresOn {
            payload["expires_on"] = cloudflareTimestamp(expiresOn)
        }
        if !arguments.allowedIPs.isEmpty {
            payload["condition"] = ["request_ip": ["in": arguments.allowedIPs]]
        }
        return try JSONSerialization.data(withJSONObject: payload)
    }

    private static func createToken(
        payload: Data,
        accountID: String,
        bootstrapToken: String
    ) async throws -> CreatedToken {
        try await request(
            "accounts/\(accountID)/tokens",
            method: "POST",
            token: bootstrapToken,
            body: payload
        )
    }

    private static func verifyToken(_ token: String, accountID: String) async throws {
        let result: VerifyResult = try await request(
            "accounts/\(accountID)/tokens/verify",
            token: token
        )
        guard result.status == "active" else {
            throw MintError.message("Derived Cloudflare token is not active")
        }
    }

    private static func revokeToken(
        id: String,
        accountID: String,
        bootstrapToken: String
    ) async throws {
        let _: EmptyResult = try await request(
            "accounts/\(accountID)/tokens/\(id)",
            method: "DELETE",
            token: bootstrapToken
        )
    }

    private struct EmptyResult: Decodable {}

    /// `--revoke <token-name> --account-id <id>`: delete the one account token
    /// with that exact name. Fails closed on zero or several matches.
    private static func revoke(_ values: [String]) async throws {
        guard values.count == 4, values[0] == "--revoke", values[2] == "--account-id" else {
            throw MintError.message("Usage: --revoke <token-name> --account-id <id>")
        }
        let name = values[1]
        let accountID = values[3]
        guard !name.isEmpty, name.count <= 120,
              accountID.range(of: "^[0-9a-f]{32}$", options: .regularExpression) != nil else {
            throw MintError.message("One or more arguments have an invalid shape")
        }

        print("Cloudflare token revocation")
        print("  Name: \(name)")
        print("Waiting for local approval…")
        try await requireUserApproval(reason: "Revoke the Cloudflare token \(name).")
        var bootstrap = try readBootstrapCredential()
        defer { bootstrap.resetBytes(in: 0..<bootstrap.count) }
        let bootstrapToken = String(decoding: bootstrap, as: UTF8.self)

        var matches: [ListedToken] = []
        var page = 1
        while true {
            let listed: [ListedToken] = try await request(
                "accounts/\(accountID)/tokens",
                query: [
                    URLQueryItem(name: "per_page", value: "50"),
                    URLQueryItem(name: "page", value: String(page)),
                ],
                token: bootstrapToken
            )
            matches += listed.filter { $0.name == name }
            if listed.count < 50 { break }
            page += 1
        }
        guard matches.count == 1 else {
            throw MintError.message("Expected one token named \(name), found \(matches.count)")
        }
        try await revokeToken(id: matches[0].id, accountID: accountID, bootstrapToken: bootstrapToken)
        print("revoke=complete")
        print("bootstrap_exposed=false")
    }

    private static func storeInInfisical(_ token: String, arguments: Arguments) throws {
        let process = Process()
        let input = Pipe()
        process.executableURL = URL(fileURLWithPath: "/opt/homebrew/bin/infisical")
        process.arguments = [
            "secrets", "set", "\(arguments.infisicalSecret)=@/dev/stdin",
            "--projectId", arguments.infisicalProject,
            "--env", arguments.infisicalEnvironment,
            "--path", arguments.infisicalPath,
            "--type", "shared",
            "--silent",
        ]
        process.standardInput = input
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        try process.run()
        input.fileHandleForWriting.write(Data(token.utf8))
        try input.fileHandleForWriting.close()
        process.waitUntilExit()
        guard process.terminationStatus == 0 else {
            throw MintError.message("Infisical CLI exited \(process.terminationStatus)")
        }
    }
}
