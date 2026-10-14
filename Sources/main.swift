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

private struct Arguments {
    let tokenName: String
    /// Absent for an account-only mint: zone flags and zone permissions are
    /// both-or-neither, enforced in `validate`.
    let zoneName: String?
    let accountID: String
    let zoneID: String?
    let accountPermissions: [String]
    let zonePermissions: [String]
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

            let arguments = try parseArguments(rawArguments)
            try validate(arguments)

            let requestedPermissions = arguments.accountPermissions + arguments.zonePermissions
            let zoneLabel = arguments.zoneName ?? "(account-only)"
            print("Cloudflare token request")
            print("  Name: \(arguments.tokenName)")
            print("  Zone: \(zoneLabel)")
            print("  Permissions: \(requestedPermissions.joined(separator: ", "))")
            print("  Destination: Infisical \(arguments.infisicalPath)/\(arguments.infisicalSecret)")
            print("Waiting for local approval…")

            try await requireUserApproval(
                reason: "Create \(arguments.tokenName) for \(zoneLabel) and store it as \(arguments.infisicalSecret)."
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
            infisicalProject: try required("--infisical-project"),
            infisicalEnvironment: try required("--infisical-env"),
            infisicalPath: try required("--infisical-path"),
            infisicalSecret: try required("--infisical-secret")
        )
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
        token: String,
        body: Data? = nil
    ) async throws -> T {
        var request = URLRequest(url: apiBase.appending(path: path))
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
        return try JSONSerialization.data(withJSONObject: [
            "name": arguments.tokenName,
            "policies": policies,
        ])
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
