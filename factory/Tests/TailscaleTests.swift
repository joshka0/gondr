import Foundation

enum TailscaleTests {
    static let all: [TestCase] = [
        // MARK: - Tailscale (Derived)

        TestCase("Tailscale: mint happy path and revoke happy path via seams") {
            try await withIsolatedRuntime {
                let keychain = FakeKeychainStore()
                keychain.seed(service: "\(keychainPrefix).tailscale", account: "personal", value: "cid-1:tskey-client-secret-1")
                let destFactory = FakeDestinationFactory()
                let http = FakeHTTPTransport { req in
                    let path = req.url!.path
                    if req.httpMethod == "POST", path.hasSuffix("/oauth/token") {
                        return try FakeHTTPTransport.json(["access_token": "ts-oauth-1"])
                    }
                    if req.httpMethod == "POST", path.hasSuffix("/tailnet/-/keys") {
                        return try FakeHTTPTransport.json(["id": "ts-key-1", "key": "tskey-auth-secret-1"])
                    }
                    if req.httpMethod == "GET", path.hasSuffix("/tailnet/-/keys/ts-key-1") {
                        return try FakeHTTPTransport.json([
                            "id": "ts-key-1",
                            "description": "ci-node",
                            "capabilities": ["devices": ["create": ["tags": ["tag:ci"]]]],
                        ])
                    }
                    if req.httpMethod == "GET", path.hasSuffix("/tailnet/-/keys") {
                        return try FakeHTTPTransport.json([
                            "keys": [["id": "ts-key-1"]],
                        ])
                    }
                    if req.httpMethod == "DELETE", path.hasSuffix("/tailnet/-/keys/ts-key-1") {
                        return FakeHTTPTransport.empty(status: 204)
                    }
                    throw FactoryError.message("Unexpected Tailscale request: \(req.httpMethod ?? "") \(path)")
                }
                FactoryRuntime.current.keychain = keychain
                FactoryRuntime.current.http = http
                FactoryRuntime.current.destinations = destFactory

                try await Tailscale.mint([
                    "--tailnet", "personal",
                    "--name", "ci-node",
                    "--expires-in", "7d",
                    "--tag", "tag:ci",
                    "--with", "ephemeral",
                    "--env", "dev",
                    "--path", "/repos/personal/demo",
                    "--secret", "TS_AUTH_KEY",
                ])
                try expectEqual(destFactory.lastStore?.stored.first?.secret, "TS_AUTH_KEY")
                try expectEqual(destFactory.lastStore?.stored.first?.value, "tskey-auth-secret-1")

                try await Tailscale.revoke(["--tailnet", "personal", "--name", "ci-node"])
                try expectTrue(http.requests.contains { $0.method == "DELETE" && $0.url.path.hasSuffix("/tailnet/-/keys/ts-key-1") })
            }
        },

        TestCase("Tailscale TF-01: mint store failure + DELETE failure surfaces orphan_id and redacts secrets") {
            try await withIsolatedRuntime {
                let authKeySecret = "tskey-auth-super-secret-999"
                let oauthToken = "ts-oauth-bearer-999"
                let keychain = FakeKeychainStore()
                keychain.seed(service: "\(keychainPrefix).tailscale", account: "personal", value: "cid-2:tskey-client-secret-2")
                let http = FakeHTTPTransport { req in
                    let path = req.url!.path
                    if req.httpMethod == "POST", path.hasSuffix("/oauth/token") {
                        return try FakeHTTPTransport.json(["access_token": oauthToken])
                    }
                    if req.httpMethod == "POST", path.hasSuffix("/tailnet/-/keys") {
                        return try FakeHTTPTransport.json(["id": "ts-orphan-99", "key": authKeySecret])
                    }
                    if req.httpMethod == "GET", path.hasSuffix("/tailnet/-/keys/ts-orphan-99") {
                        return try FakeHTTPTransport.json([
                            "id": "ts-orphan-99",
                            "description": "ci-node",
                            "capabilities": ["devices": ["create": ["tags": ["tag:ci"]]]],
                        ])
                    }
                    if req.httpMethod == "DELETE", path.hasSuffix("/tailnet/-/keys/ts-orphan-99") {
                        return try FakeHTTPTransport.json(["message": "rate limited"], status: 429)
                    }
                    throw FactoryError.message("Unexpected Tailscale request: \(req.httpMethod ?? "") \(path)")
                }
                let destFactory = FakeDestinationFactory { _, secret, value in
                    throw FactoryError.message("gondr set \(secret) failed for \(value)")
                }
                FactoryRuntime.current.keychain = keychain
                FactoryRuntime.current.http = http
                FactoryRuntime.current.destinations = destFactory

                let err = try await expectThrowsAsync {
                    try await Tailscale.mint([
                        "--tailnet", "personal",
                        "--name", "ci-node",
                        "--expires-in", "7d",
                        "--tag", "tag:ci",
                        "--env", "dev",
                        "--path", "/repos/personal/demo",
                        "--secret", "TS_AUTH_KEY",
                    ])
                }
                let text = String(describing: err)
                try expectContains(text, "gondr set TS_AUTH_KEY failed")
                try expectContains(text, "rollback=failed orphan_id=ts-orphan-99")
                try expectContains(text, "Tailscale HTTP 429: rate limited")
                try expectNotContains(text, authKeySecret)
                try expectNotContains(text, oauthToken)
            }
        },

        TestCase("Tailscale TF-01: verify tag mismatch triggers recorded rollback") {
            try await withIsolatedRuntime {
                let keychain = FakeKeychainStore()
                keychain.seed(service: "\(keychainPrefix).tailscale", account: "personal", value: "cid-3:tskey-client-secret-3")
                let http = FakeHTTPTransport { req in
                    let path = req.url!.path
                    if req.httpMethod == "POST", path.hasSuffix("/oauth/token") {
                        return try FakeHTTPTransport.json(["access_token": "ts-oauth-3"])
                    }
                    if req.httpMethod == "POST", path.hasSuffix("/tailnet/-/keys") {
                        return try FakeHTTPTransport.json(["id": "ts-bad-tags", "key": "tskey-auth-bad-tags"])
                    }
                    if req.httpMethod == "GET", path.hasSuffix("/tailnet/-/keys/ts-bad-tags") {
                        return try FakeHTTPTransport.json([
                            "id": "ts-bad-tags",
                            "capabilities": ["devices": ["create": ["tags": ["tag:wrong"]]]],
                        ])
                    }
                    if req.httpMethod == "DELETE", path.hasSuffix("/tailnet/-/keys/ts-bad-tags") {
                        return FakeHTTPTransport.empty(status: 204)
                    }
                    throw FactoryError.message("Unexpected Tailscale request: \(req.httpMethod ?? "") \(path)")
                }
                FactoryRuntime.current.keychain = keychain
                FactoryRuntime.current.http = http

                let err = try await expectThrowsAsync {
                    try await Tailscale.mint([
                        "--tailnet", "personal",
                        "--name", "ci-node",
                        "--expires-in", "7d",
                        "--tag", "tag:ci",
                        "--env", "dev",
                        "--path", "/repos/personal/demo",
                        "--secret", "TS_AUTH_KEY",
                    ])
                }
                let text = String(describing: err)
                try expectContains(text, "The key's tags differ from the request")
                try expectContains(text, "rollback=succeeded id=ts-bad-tags")
                try expectNotContains(text, "tskey-auth-bad-tags")
            }
        },
    ]
}
