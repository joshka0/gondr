import CryptoKit
import Foundation

enum CloudflareTests {
    static let all: [TestCase] = [
        // MARK: - Cloudflare (REST)

        TestCase("Cloudflare: mint happy path stores token + R2 S3 credentials via seams") {
            try await withIsolatedRuntime {
                let accountID = String(repeating: "a", count: 32)
                let parentSecret = "cf-parent-secret-001"
                let mintedValue = "cf-child-secret-value-111"
                let expectedS3Secret = SHA256.hash(data: Data(mintedValue.utf8)).map { String(format: "%02x", $0) }.joined()

                let keychain = FakeKeychainStore()
                keychain.seed(service: "\(keychainPrefix).cloudflare", account: "bootstrap", value: parentSecret)
                let destFactory = FakeDestinationFactory()
                let http = FakeHTTPTransport { req in
                    let path = req.url!.path
                    if req.httpMethod == "GET", path.hasSuffix("/permission_groups") {
                        return try FakeHTTPTransport.json([
                            "success": true,
                            "errors": [],
                            "result": [
                                ["id": "pg-r2", "name": "Workers R2 Storage Bucket Item Write", "scopes": ["com.cloudflare.edge.r2.bucket"]],
                            ],
                        ])
                    }
                    if req.httpMethod == "POST", path.hasSuffix("/accounts/\(accountID)/tokens") {
                        return try FakeHTTPTransport.json([
                            "success": true, "errors": [],
                            "result": ["id": "cf-tok-100", "value": mintedValue],
                        ])
                    }
                    if req.httpMethod == "GET", path.hasSuffix("/tokens/verify") {
                        try expectEqual(req.value(forHTTPHeaderField: "Authorization"), "Bearer \(mintedValue)")
                        return try FakeHTTPTransport.json([
                            "success": true, "errors": [],
                            "result": ["status": "active"],
                        ])
                    }
                    throw FactoryError.message("Unexpected Cloudflare request: \(req.httpMethod ?? "") \(path)")
                }
                FactoryRuntime.current.keychain = keychain
                FactoryRuntime.current.http = http
                FactoryRuntime.current.destinations = destFactory

                try await Cloudflare.mint([
                    "--name", "ci-r2-token",
                    "--account-id", accountID,
                    "--expires-in", "24h",
                    "--r2-bucket", "assets-bucket",
                    "--bucket-permission", "Workers R2 Storage Bucket Item Write",
                    "--r2-s3-secret-prefix", "R2_ASSETS",
                    "--env", "dev",
                    "--path", "/repos/personal/demo",
                    "--secret", "CF_R2_TOKEN",
                ])

                let stored = destFactory.lastStore?.stored ?? []
                try expectEqual(stored.count, 3)
                try expectEqual(stored[0].secret, "CF_R2_TOKEN")
                try expectEqual(stored[0].value, mintedValue)
                try expectEqual(stored[1].secret, "R2_ASSETS_ACCESS_KEY_ID")
                try expectEqual(stored[1].value, "cf-tok-100")
                try expectEqual(stored[2].secret, "R2_ASSETS_SECRET_ACCESS_KEY")
                try expectEqual(stored[2].value, expectedS3Secret)
            }
        },

        TestCase("Cloudflare TF-01: mint store failure calls DELETE with created ID and records rollback=succeeded") {
            try await withIsolatedRuntime {
                let accountID = String(repeating: "b", count: 32)
                let mintedValue = "cf-secret-must-not-leak-222"
                let keychain = FakeKeychainStore()
                keychain.seed(service: "\(keychainPrefix).cloudflare", account: "bootstrap", value: "cf-parent-222")
                let http = FakeHTTPTransport { req in
                    let path = req.url!.path
                    if req.httpMethod == "GET", path.hasSuffix("/permission_groups") {
                        return try FakeHTTPTransport.json([
                            "success": true, "errors": [],
                            "result": [["id": "pg-1", "name": "Workers Scripts Write", "scopes": ["com.cloudflare.api.account"]]],
                        ])
                    }
                    if req.httpMethod == "POST", path.hasSuffix("/accounts/\(accountID)/tokens") {
                        return try FakeHTTPTransport.json([
                            "success": true, "errors": [],
                            "result": ["id": "cf-tok-del-1", "value": mintedValue],
                        ])
                    }
                    if req.httpMethod == "GET", path.hasSuffix("/tokens/verify") {
                        return try FakeHTTPTransport.json(["success": true, "errors": [], "result": ["status": "active"]])
                    }
                    if req.httpMethod == "DELETE", path.hasSuffix("/accounts/\(accountID)/tokens/cf-tok-del-1") {
                        return try FakeHTTPTransport.json(["success": true, "errors": [], "result": [:]])
                    }
                    throw FactoryError.message("Unexpected request: \(req.httpMethod ?? "") \(path)")
                }
                let destFactory = FakeDestinationFactory { _, secret, value in
                    throw FactoryError.message("gondr set \(secret) exited 1 (echo \(value))")
                }
                FactoryRuntime.current.keychain = keychain
                FactoryRuntime.current.http = http
                FactoryRuntime.current.destinations = destFactory

                let err = try await expectThrowsAsync {
                    try await Cloudflare.mint([
                        "--name", "deploy-token",
                        "--account-id", accountID,
                        "--expires-in", "12h",
                        "--account-permission", "Workers Scripts Write",
                        "--env", "dev",
                        "--path", "/repos/personal/demo",
                        "--secret", "CF_TOKEN",
                    ])
                }
                let text = String(describing: err)
                try expectContains(text, "gondr set CF_TOKEN exited 1")
                try expectContains(text, "rollback=succeeded id=cf-tok-del-1")
                try expectNotContains(text, mintedValue)
                try expectTrue(http.requests.contains { $0.method == "DELETE" && $0.url.path.hasSuffix("/tokens/cf-tok-del-1") })
            }
        },

        TestCase("Cloudflare TF-01: mint store failure + DELETE failure surfaces BOTH errors and orphan_id without leaking secrets") {
            try await withIsolatedRuntime {
                let accountID = String(repeating: "c", count: 32)
                let parentSecret = "cf-parent-secret-333"
                let mintedValue = "cf-minted-secret-333"
                let expectedS3Secret = SHA256.hash(data: Data(mintedValue.utf8)).map { String(format: "%02x", $0) }.joined()
                let keychain = FakeKeychainStore()
                keychain.seed(service: "\(keychainPrefix).cloudflare", account: "bootstrap", value: parentSecret)

                let http = FakeHTTPTransport { req in
                    let path = req.url!.path
                    if req.httpMethod == "GET", path.hasSuffix("/permission_groups") {
                        return try FakeHTTPTransport.json([
                            "success": true, "errors": [],
                            "result": [["id": "pg-r2", "name": "Workers R2 Storage Bucket Item Write", "scopes": ["com.cloudflare.edge.r2.bucket"]]],
                        ])
                    }
                    if req.httpMethod == "POST", path.hasSuffix("/accounts/\(accountID)/tokens") {
                        return try FakeHTTPTransport.json([
                            "success": true, "errors": [],
                            "result": ["id": "cf-orphan-333", "value": mintedValue],
                        ])
                    }
                    if req.httpMethod == "GET", path.hasSuffix("/tokens/verify") {
                        return try FakeHTTPTransport.json(["success": true, "errors": [], "result": ["status": "active"]])
                    }
                    if req.httpMethod == "DELETE", path.hasSuffix("/accounts/\(accountID)/tokens/cf-orphan-333") {
                        return try FakeHTTPTransport.json(
                            ["success": false, "errors": [["message": "backend delete timeout"]]],
                            status: 500
                        )
                    }
                    throw FactoryError.message("Unexpected request: \(req.httpMethod ?? "") \(path)")
                }
                let destFactory = FakeDestinationFactory { callIndex, secret, value in
                    if callIndex == 3 {
                        throw FactoryError.message("gondr set \(secret) exited 42 for \(value)")
                    }
                }
                FactoryRuntime.current.keychain = keychain
                FactoryRuntime.current.http = http
                FactoryRuntime.current.destinations = destFactory

                let err = try await expectThrowsAsync {
                    try await Cloudflare.mint([
                        "--name", "r2-orphan-test",
                        "--account-id", accountID,
                        "--expires-in", "12h",
                        "--r2-bucket", "media-store",
                        "--bucket-permission", "Workers R2 Storage Bucket Item Write",
                        "--r2-s3-secret-prefix", "R2_MEDIA",
                        "--env", "dev",
                        "--path", "/repos/personal/demo",
                        "--secret", "CF_R2_TOKEN",
                    ])
                }
                let text = String(describing: err)
                try expectContains(text, "gondr set R2_MEDIA_SECRET_ACCESS_KEY exited 42")
                try expectContains(text, "rollback=failed orphan_id=cf-orphan-333")
                try expectContains(text, "Cloudflare HTTP 500: backend delete timeout")
                try expectNotContains(text, mintedValue)
                try expectNotContains(text, expectedS3Secret)
                try expectNotContains(text, parentSecret)
            }
        },

        TestCase("Cloudflare TF-01: mint verify inactive triggers recorded rollback") {
            try await withIsolatedRuntime {
                let accountID = String(repeating: "d", count: 32)
                let keychain = FakeKeychainStore()
                keychain.seed(service: "\(keychainPrefix).cloudflare", account: "bootstrap", value: "cf-parent-444")
                let http = FakeHTTPTransport { req in
                    let path = req.url!.path
                    if req.httpMethod == "GET", path.hasSuffix("/permission_groups") {
                        return try FakeHTTPTransport.json([
                            "success": true, "errors": [],
                            "result": [["id": "pg-1", "name": "Workers Scripts Write", "scopes": ["com.cloudflare.api.account"]]],
                        ])
                    }
                    if req.httpMethod == "POST", path.hasSuffix("/accounts/\(accountID)/tokens") {
                        return try FakeHTTPTransport.json([
                            "success": true, "errors": [],
                            "result": ["id": "cf-inactive-1", "value": "cf-secret-inactive"],
                        ])
                    }
                    if req.httpMethod == "GET", path.hasSuffix("/tokens/verify") {
                        return try FakeHTTPTransport.json(["success": true, "errors": [], "result": ["status": "disabled"]])
                    }
                    if req.httpMethod == "DELETE", path.hasSuffix("/accounts/\(accountID)/tokens/cf-inactive-1") {
                        return try FakeHTTPTransport.json(["success": true, "errors": [], "result": [:]])
                    }
                    throw FactoryError.message("Unexpected request: \(req.httpMethod ?? "") \(path)")
                }
                FactoryRuntime.current.keychain = keychain
                FactoryRuntime.current.http = http

                let err = try await expectThrowsAsync {
                    try await Cloudflare.mint([
                        "--name", "inactive-token",
                        "--account-id", accountID,
                        "--expires-in", "12h",
                        "--account-permission", "Workers Scripts Write",
                        "--env", "dev",
                        "--path", "/repos/personal/demo",
                        "--secret", "CF_TOKEN",
                    ])
                }
                let text = String(describing: err)
                try expectContains(text, "Derived Cloudflare token is not active")
                try expectContains(text, "rollback=succeeded id=cf-inactive-1")
                try expectNotContains(text, "cf-secret-inactive")
            }
        },

        TestCase("Cloudflare: revoke deletes exact matching token") {
            try await withIsolatedRuntime {
                let accountID = String(repeating: "e", count: 32)
                let keychain = FakeKeychainStore()
                keychain.seed(service: "\(keychainPrefix).cloudflare", account: "bootstrap", value: "cf-parent-555")
                let http = FakeHTTPTransport { req in
                    let path = req.url!.path
                    if req.httpMethod == "GET", path.hasSuffix("/accounts/\(accountID)/tokens") {
                        return try FakeHTTPTransport.json([
                            "success": true, "errors": [],
                            "result": [
                                ["id": "tok-other", "name": "other"],
                                ["id": "tok-target", "name": "target-token"],
                            ],
                        ])
                    }
                    if req.httpMethod == "DELETE", path.hasSuffix("/accounts/\(accountID)/tokens/tok-target") {
                        return try FakeHTTPTransport.json(["success": true, "errors": [], "result": [:]])
                    }
                    throw FactoryError.message("Unexpected request: \(req.httpMethod ?? "") \(path)")
                }
                FactoryRuntime.current.keychain = keychain
                FactoryRuntime.current.http = http

                try await Cloudflare.revoke(["--name", "target-token", "--account-id", accountID])
                try expectTrue(http.requests.contains { $0.method == "DELETE" && $0.url.path.hasSuffix("/tokens/tok-target") })
            }
        },
    ]
}
