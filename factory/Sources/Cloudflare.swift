import CryptoKit
import Foundation

/// Account-owned Cloudflare tokens, minted with the parent in Keychain item
/// `<prefix>.cloudflare` / `bootstrap`.
enum Cloudflare {
    private static let parent = KeychainItem(service: "\(keychainPrefix).cloudflare", account: "bootstrap")
    private static let apiBase = URL(string: "https://api.cloudflare.com/client/v4")!

    private struct Envelope<T: Decodable>: Decodable {
        let success: Bool
        let result: T?
        let errors: [APIError]
    }

    private struct APIError: Decodable {
        let message: String
    }

    private struct PermissionGroup: Decodable {
        let id: String
        let name: String?
        let scopes: [String]?
    }

    private struct CreatedToken: Decodable {
        let id: String
        let value: String
    }

    private struct ListedToken: Decodable {
        let id: String
        let name: String
    }

    private struct VerifyResult: Decodable {
        let status: String
    }

    private struct EmptyResult: Decodable {}

    static func check(_ arguments: [String]) async throws {
        _ = try Options(arguments, allowed: [])
        try await parent.check()
    }

    static func mint(_ arguments: [String]) async throws {
        let options = try Options(
            arguments,
            allowed: ["--name", "--zone", "--account-id", "--zone-id", "--expires-in", "--r2-jurisdiction",
                      "--env", "--path", "--secret",
                      "--r2-s3-secret-prefix"],
            repeatable: ["--account-permission", "--zone-permission", "--allow-ip", "--r2-bucket", "--bucket-permission"]
        )
        let name = try options.required("--name")
        let accountID = try options.required("--account-id")
        let zoneName = options.optional("--zone")
        let zoneID = options.optional("--zone-id")
        let accountPermissions = options.all("--account-permission")
        let zonePermissions = options.all("--zone-permission")
        let allowedIPs = options.all("--allow-ip")
        let buckets = options.all("--r2-bucket")
        let bucketPermissions = options.all("--bucket-permission")
        let jurisdiction = options.optional("--r2-jurisdiction") ?? "default"
        let s3Prefix = options.optional("--r2-s3-secret-prefix")
        let expiresIn = try parseExpiry(try options.required("--expires-in"))
        let destination = try SecretDestination(options)
        let secret = try options.required("--secret")

        // Zone identity and zone permissions travel together: an account-only
        // mint carries neither, a zone mint carries all three. `--zone '*'`
        // means every zone of the account (also needed to create a zone): it
        // takes no zone id and lives at most a day.
        let allZones = zoneName == "*"
        guard (zoneName != nil || zoneID != nil) == !zonePermissions.isEmpty,
              allZones ? zoneID == nil : (zoneName != nil) == (zoneID != nil) else {
            throw FactoryError.message("Zone name, zone id, and zone permissions are both-or-neither; --zone '*' takes no --zone-id")
        }
        guard !allZones || (expiresIn.map { $0 <= 24 * 3600 } ?? false) else {
            throw FactoryError.message("--zone '*' needs --expires-in of 24h or less")
        }
        guard buckets.isEmpty == bucketPermissions.isEmpty else {
            throw FactoryError.message("--r2-bucket and --bucket-permission are both-or-neither")
        }
        guard s3Prefix == nil || !buckets.isEmpty else {
            throw FactoryError.message("--r2-s3-secret-prefix needs --r2-bucket")
        }
        guard buckets.count <= 16,
              buckets.allSatisfy({ matches($0, "^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$") }),
              ["default", "eu", "fedramp"].contains(jurisdiction),
              s3Prefix.map({ isSecretName("\($0)_ACCESS_KEY_ID") }) ?? true else {
            throw FactoryError.message("R2 bucket, jurisdiction, or S3 secret prefix has an invalid shape")
        }
        guard name.count <= 120,
              zoneName.map({ allZones || matches($0, "^[A-Za-z0-9.-]+$") }) ?? true,
              matches(accountID, "^[0-9a-f]{32}$"),
              zoneID.map({ matches($0, "^[0-9a-f]{32}$") }) ?? true,
              isSecretName(secret) else {
            throw FactoryError.message("One or more arguments have an invalid shape")
        }
        guard allowedIPs.count <= 16, allowedIPs.allSatisfy(isCIDR) else {
            throw FactoryError.message("--allow-ip takes up to sixteen IPv4 or IPv6 addresses or CIDR ranges")
        }
        let permissions = accountPermissions + zonePermissions + bucketPermissions
        guard !permissions.isEmpty, permissions.count <= 12 else {
            throw FactoryError.message("Request between one and twelve permissions")
        }
        guard permissions.allSatisfy({ !$0.localizedCaseInsensitiveContains("API Token") }) else {
            throw FactoryError.message("Derived tokens may not manage API tokens")
        }

        let expiresOn = expiresIn.map { iso8601(Date().addingTimeInterval($0)) }
        print("Cloudflare token request")
        print("  Name: \(name)")
        print("  Zone: \(allZones ? "* (every zone of the account)" : zoneName ?? "(account-only)")")
        print("  Permissions: \(permissions.joined(separator: ", "))")
        print("  Expires: \(expiresOn ?? "never")")
        if !buckets.isEmpty { print("  R2 buckets (\(jurisdiction)): \(buckets.joined(separator: ", "))") }
        print("  Allowed IPs: \(allowedIPs.isEmpty ? "any" : allowedIPs.joined(separator: ", "))")
        print("  Destination: \(destination.label(secret))")
        if let s3Prefix {
            print("  S3 keys: \(destination.label("\(s3Prefix)_ACCESS_KEY_ID")), \(destination.label("\(s3Prefix)_SECRET_ACCESS_KEY"))")
        }
        try await requireUserApproval(
            parent: parent, action: "create Cloudflare token \(name) (\(permissions.joined(separator: ", ")))\(allZones ? " on every zone of the account" : ""), expiring \(expiresOn ?? "never"), and store it as \(secret)."
        )
        var parentData = try parent.read()
        defer { parentData.resetBytes(in: 0..<parentData.count) }
        let parentToken = String(decoding: parentData, as: UTF8.self)

        var policies: [[String: Any]] = []
        if !accountPermissions.isEmpty {
            policies.append([
                "effect": "allow",
                "resources": ["com.cloudflare.api.account.\(accountID)": "*"],
                "permission_groups": try await groupIDs(
                    accountPermissions, scope: "com.cloudflare.api.account", accountID: accountID, token: parentToken
                ),
            ])
        }
        if !zonePermissions.isEmpty {
            let resources: [String: Any] = allZones
                ? ["com.cloudflare.api.account.\(accountID)": ["com.cloudflare.api.account.zone.*": "*"]]
                : ["com.cloudflare.api.account.zone.\(zoneID!)": "*"]
            policies.append([
                "effect": "allow",
                "resources": resources,
                "permission_groups": try await groupIDs(
                    zonePermissions, scope: "com.cloudflare.api.account.zone", accountID: accountID, token: parentToken
                ),
            ])
        }
        if !buckets.isEmpty {
            var resources: [String: String] = [:]
            for bucket in buckets {
                resources["com.cloudflare.edge.r2.bucket.\(accountID)_\(jurisdiction)_\(bucket)"] = "*"
            }
            policies.append([
                "effect": "allow",
                "resources": resources,
                "permission_groups": try await groupIDs(
                    bucketPermissions, scope: "com.cloudflare.edge.r2.bucket", accountID: accountID, token: parentToken
                ),
            ])
        }
        var payload: [String: Any] = ["name": name, "policies": policies]
        if let expiresOn { payload["expires_on"] = expiresOn }
        if !allowedIPs.isEmpty { payload["condition"] = ["request_ip": ["in": allowedIPs]] }

        let created: CreatedToken = try await request(
            "accounts/\(accountID)/tokens",
            method: "POST",
            token: parentToken,
            body: try JSONSerialization.data(withJSONObject: payload)
        )
        do {
            let verified: VerifyResult = try await request("accounts/\(accountID)/tokens/verify", token: created.value)
            guard verified.status == "active" else {
                throw FactoryError.message("Derived Cloudflare token is not active")
            }
            try destination.store(created.value, as: secret)
            if let s3Prefix {
                // R2 S3 keys: the token ID, and the SHA-256 hex of the token value.
                let secretKey = SHA256.hash(data: Data(created.value.utf8)).map { String(format: "%02x", $0) }.joined()
                try destination.store(created.id, as: "\(s3Prefix)_ACCESS_KEY_ID")
                try destination.store(secretKey, as: "\(s3Prefix)_SECRET_ACCESS_KEY")
            }
        } catch {
            let _: EmptyResult? = try? await request(
                "accounts/\(accountID)/tokens/\(created.id)", method: "DELETE", token: parentToken
            )
            throw FactoryError.message("Derived token was not retained because verification or vault storage failed: \(error)")
        }

        print("mint=complete")
        print("derived_token_verified=true")
        print("secret=\(secret)")
        print("parent_exposed=false")
    }

    /// Deletes the one account token with this exact name. Fails closed on
    /// zero or several matches.
    static func revoke(_ arguments: [String]) async throws {
        let options = try Options(arguments, allowed: ["--name", "--account-id"])
        let name = try options.required("--name")
        let accountID = try options.required("--account-id")
        guard name.count <= 120, matches(accountID, "^[0-9a-f]{32}$") else {
            throw FactoryError.message("One or more arguments have an invalid shape")
        }

        print("Cloudflare token revocation")
        print("  Name: \(name)")
        try await requireUserApproval(parent: parent, action: "revoke the Cloudflare token \(name).")
        var parentData = try parent.read()
        defer { parentData.resetBytes(in: 0..<parentData.count) }
        let parentToken = String(decoding: parentData, as: UTF8.self)

        var found: [ListedToken] = []
        var page = 1
        while true {
            let listed: [ListedToken] = try await request(
                "accounts/\(accountID)/tokens",
                query: [URLQueryItem(name: "per_page", value: "50"), URLQueryItem(name: "page", value: String(page))],
                token: parentToken
            )
            found += listed.filter { $0.name == name }
            if listed.count < 50 { break }
            page += 1
        }
        guard found.count == 1 else {
            throw FactoryError.message("Expected one token named \(name), found \(found.count)")
        }
        let _: EmptyResult = try await request(
            "accounts/\(accountID)/tokens/\(found[0].id)", method: "DELETE", token: parentToken
        )
        print("revoke=complete")
        print("parent_exposed=false")
    }

    /// Resolves permission names through the account-scoped listing, which
    /// the narrow parent can reach. Exact name and scope, one match only.
    private static func groupIDs(
        _ names: [String], scope: String, accountID: String, token: String
    ) async throws -> [[String: String]] {
        let listed: [PermissionGroup] = try await request(
            "accounts/\(accountID)/tokens/permission_groups", token: token
        )
        return try names.map { name in
            let found = listed.filter { $0.name == name && ($0.scopes ?? []).contains(scope) }
            guard found.count == 1 else {
                throw FactoryError.message("Permission is unavailable or ambiguous for \(scope): \(name)")
            }
            return ["id": found[0].id, "name": name]
        }
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
            throw FactoryError.message("Cloudflare returned no HTTP response")
        }
        let envelope = try JSONDecoder().decode(Envelope<T>.self, from: data)
        guard (200..<300).contains(http.statusCode), envelope.success, let result = envelope.result else {
            throw FactoryError.message("Cloudflare HTTP \(http.statusCode): \(envelope.errors.map(\.message).joined(separator: "; "))")
        }
        return result
    }

    /// An IPv4 or IPv6 address with an optional prefix length.
    private static func isCIDR(_ value: String) -> Bool {
        let parts = value.split(separator: "/", omittingEmptySubsequences: false)
        guard parts.count <= 2, let address = parts.first.map(String.init) else { return false }
        var buffer = [UInt8](repeating: 0, count: 16)
        let maxPrefix: Int
        if inet_pton(AF_INET, address, &buffer) == 1 {
            maxPrefix = 32
        } else if inet_pton(AF_INET6, address, &buffer) == 1 {
            maxPrefix = 128
        } else {
            return false
        }
        guard parts.count == 2 else { return true }
        guard let prefix = Int(parts[1]) else { return false }
        return (0...maxPrefix).contains(prefix)
    }
}
