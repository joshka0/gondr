import Foundation

enum OpenRouterTests {
    static let all: [TestCase] = [
        // MARK: - OpenRouter (REST)

        TestCase("OpenRouter TF-01: mint store failure + DELETE failure surfaces orphan_id and redacts secrets") {
            try await withIsolatedRuntime {
                let mgmtKey = "sk-or-mgmt-secret-123"
                let childKey = "sk-or-v1-child-secret-456"
                let keychain = FakeKeychainStore()
                keychain.seed(service: "\(keychainPrefix).openrouter", account: "personal", value: mgmtKey)
                let http = FakeHTTPTransport { req in
                    let path = req.url!.path
                    if req.httpMethod == "GET", path.hasSuffix("/workspaces") {
                        return try FakeHTTPTransport.json([
                            "data": [["id": "ws-1", "name": "Demo", "slug": "demo"]],
                        ])
                    }
                    if req.httpMethod == "POST", path.hasSuffix("/keys") {
                        return try FakeHTTPTransport.json([
                            "data": ["hash": "orhash99999999"],
                            "key": childKey,
                        ])
                    }
                    if req.httpMethod == "GET", path.hasSuffix("/key") {
                        return try FakeHTTPTransport.json(["data": ["limit": 10.0]])
                    }
                    if req.httpMethod == "DELETE", path.hasSuffix("/keys/orhash99999999") {
                        return try FakeHTTPTransport.json(["error": ["message": "upstream unavailable"]], status: 502)
                    }
                    throw FactoryError.message("Unexpected OpenRouter request: \(req.httpMethod ?? "") \(path)")
                }
                let destFactory = FakeDestinationFactory { _, secret, value in
                    throw FactoryError.message("gondr set \(secret) failed (\(value))")
                }
                FactoryRuntime.current.keychain = keychain
                FactoryRuntime.current.http = http
                FactoryRuntime.current.destinations = destFactory

                let err = try await expectThrowsAsync {
                    try await OpenRouter.mint([
                        "--account", "personal",
                        "--workspace", "demo",
                        "--name", "app-key",
                        "--limit-usd", "10",
                        "--reset", "monthly",
                        "--expires-in", "30d",
                        "--env", "dev",
                        "--path", "/repos/personal/demo",
                        "--secret", "OPENROUTER_API_KEY",
                    ])
                }
                let text = String(describing: err)
                try expectContains(text, "gondr set OPENROUTER_API_KEY failed")
                try expectContains(text, "rollback=failed orphan_id=orhash99999999")
                try expectContains(text, "OpenRouter HTTP 502: upstream unavailable")
                try expectNotContains(text, childKey)
                try expectNotContains(text, mgmtKey)
            }
        },

        TestCase("OpenRouter TF-01: createWorkspace budget PUT failure rolls back newly created workspace") {
            try await withIsolatedRuntime {
                let keychain = FakeKeychainStore()
                keychain.seed(service: "\(keychainPrefix).openrouter", account: "personal", value: "sk-or-mgmt-ws")
                let http = FakeHTTPTransport { req in
                    let path = req.url!.path
                    if req.httpMethod == "POST", path.hasSuffix("/workspaces") {
                        return try FakeHTTPTransport.json([
                            "data": ["id": "ws-new-42", "name": "New WS", "slug": "new-ws"],
                        ])
                    }
                    if req.httpMethod == "PUT", path.hasSuffix("/workspaces/ws-new-42/budgets/monthly") {
                        return try FakeHTTPTransport.json(["error": ["message": "budget rejected"]], status: 400)
                    }
                    if req.httpMethod == "DELETE", path.hasSuffix("/workspaces/ws-new-42") {
                        return FakeHTTPTransport.empty(status: 204)
                    }
                    throw FactoryError.message("Unexpected OpenRouter request: \(req.httpMethod ?? "") \(path)")
                }
                FactoryRuntime.current.keychain = keychain
                FactoryRuntime.current.http = http

                let err = try await expectThrowsAsync {
                    try await OpenRouter.createWorkspace([
                        "--account", "personal",
                        "--slug", "new-ws",
                        "--name", "New WS",
                        "--monthly-budget-usd", "25",
                    ])
                }
                let text = String(describing: err)
                try expectContains(text, "OpenRouter HTTP 400: budget rejected")
                try expectContains(text, "rollback=succeeded id=ws-new-42")
                try expectTrue(http.requests.contains { $0.method == "DELETE" && $0.url.path.hasSuffix("/workspaces/ws-new-42") })
            }
        },

        TestCase("OpenRouter: mint happy path and revoke by name") {
            try await withIsolatedRuntime {
                let keychain = FakeKeychainStore()
                keychain.seed(service: "\(keychainPrefix).openrouter", account: "personal", value: "sk-or-mgmt-ok")
                let destFactory = FakeDestinationFactory()
                let http = FakeHTTPTransport { req in
                    let path = req.url!.path
                    if req.httpMethod == "GET", path.hasSuffix("/workspaces") {
                        return try FakeHTTPTransport.json(["data": [["id": "ws-1", "name": "Demo", "slug": "demo"]]])
                    }
                    if req.httpMethod == "POST", path.hasSuffix("/keys") {
                        return try FakeHTTPTransport.json(["data": ["hash": "orhash12345678"], "key": "sk-or-v1-ok"])
                    }
                    if req.httpMethod == "GET", path.hasSuffix("/key") {
                        return try FakeHTTPTransport.json(["data": ["limit": 5.0]])
                    }
                    if req.httpMethod == "GET", path.hasSuffix("/keys") {
                        return try FakeHTTPTransport.json([
                            "data": [["hash": "orhash12345678", "name": "app-key", "disabled": false]],
                        ])
                    }
                    if req.httpMethod == "DELETE", path.hasSuffix("/keys/orhash12345678") {
                        return FakeHTTPTransport.empty(status: 204)
                    }
                    throw FactoryError.message("Unexpected OpenRouter request: \(req.httpMethod ?? "") \(path)")
                }
                FactoryRuntime.current.keychain = keychain
                FactoryRuntime.current.http = http
                FactoryRuntime.current.destinations = destFactory

                try await OpenRouter.mint([
                    "--account", "personal", "--workspace", "demo", "--name", "app-key",
                    "--limit-usd", "5", "--reset", "daily", "--expires-in", "never",
                    "--env", "dev", "--path", "/repos/personal/demo", "--secret", "OPENROUTER_API_KEY",
                ])
                try expectEqual(destFactory.lastStore?.stored.first?.value, "sk-or-v1-ok")

                try await OpenRouter.revoke(["--account", "personal", "--name", "app-key"])
                try expectTrue(http.requests.contains { $0.method == "DELETE" && $0.url.path.hasSuffix("/keys/orhash12345678") })
            }
        },
    ]
}
