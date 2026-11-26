import Foundation

enum PlanetScaleTests {
    static let all: [TestCase] = [
        // MARK: - PlanetScale (REST)

        TestCase("PlanetScale TF-01: grant verify failure rolls back created token") {
            try await withIsolatedRuntime {
                let keychain = FakeKeychainStore()
                keychain.seed(service: "\(keychainPrefix).planetscale", account: "acme", value: "pid:pscale_tkn_parent")
                let http = FakeHTTPTransport { req in
                    let path = req.url!.path
                    if req.httpMethod == "POST", path.hasSuffix("/service-tokens") {
                        return try FakeHTTPTransport.json(["id": "ps-tok-verify-fail", "token": "pscale_tkn_child_1"])
                    }
                    if req.httpMethod == "POST", path.hasSuffix("/ps-tok-verify-fail/access") {
                        return try FakeHTTPTransport.json(["data": [["access": "read_branch"]]])
                    }
                    if req.httpMethod == "GET", path.hasSuffix("/ps-tok-verify-fail/access") {
                        return try FakeHTTPTransport.json(["data": []])
                    }
                    if req.httpMethod == "DELETE", path.hasSuffix("/service-tokens/ps-tok-verify-fail") {
                        return FakeHTTPTransport.empty(status: 204)
                    }
                    throw FactoryError.message("Unexpected PlanetScale request: \(req.httpMethod ?? "") \(path)")
                }
                FactoryRuntime.current.keychain = keychain
                FactoryRuntime.current.http = http

                let err = try await expectThrowsAsync {
                    try await PlanetScale.mint([
                        "--org", "acme", "--name", "ci-db", "--expires-in", "24h",
                        "--database", "appdb", "--database-access", "read_branch",
                        "--env", "dev", "--path", "/repos/personal/demo", "--secret-prefix", "PSCALE",
                    ])
                }
                let text = String(describing: err)
                try expectContains(text, "Grants missing after create: read_branch")
                try expectContains(text, "rollback=succeeded id=ps-tok-verify-fail")
                try expectNotContains(text, "pscale_tkn_child_1")
            }
        },

        TestCase("PlanetScale TF-01: mint 2nd store failure + DELETE failure surfaces orphan_id and redacts secret") {
            try await withIsolatedRuntime {
                let childSecret = "pscale_tkn_child_orphan_777"
                let parentAuth = "pid:pscale_tkn_parent_777"
                let keychain = FakeKeychainStore()
                keychain.seed(service: "\(keychainPrefix).planetscale", account: "acme", value: parentAuth)
                let http = FakeHTTPTransport { req in
                    let path = req.url!.path
                    if req.httpMethod == "POST", path.hasSuffix("/service-tokens") {
                        return try FakeHTTPTransport.json(["id": "ps-orphan-777", "token": childSecret])
                    }
                    if req.httpMethod == "POST", path.hasSuffix("/ps-orphan-777/access") {
                        return try FakeHTTPTransport.json(["data": [["access": "read_branch"]]])
                    }
                    if req.httpMethod == "GET", path.hasSuffix("/ps-orphan-777/access") {
                        return try FakeHTTPTransport.json(["data": [["access": "read_branch"]]])
                    }
                    if req.httpMethod == "DELETE", path.hasSuffix("/service-tokens/ps-orphan-777") {
                        return try FakeHTTPTransport.json(["message": "service unavailable"], status: 503)
                    }
                    throw FactoryError.message("Unexpected PlanetScale request: \(req.httpMethod ?? "") \(path)")
                }
                let destFactory = FakeDestinationFactory { callIndex, secret, value in
                    if callIndex == 2 {
                        throw FactoryError.message("gondr set \(secret) failed with \(value)")
                    }
                }
                FactoryRuntime.current.keychain = keychain
                FactoryRuntime.current.http = http
                FactoryRuntime.current.destinations = destFactory

                let err = try await expectThrowsAsync {
                    try await PlanetScale.mint([
                        "--org", "acme", "--name", "ci-db", "--expires-in", "24h",
                        "--database", "appdb", "--database-access", "read_branch",
                        "--env", "dev", "--path", "/repos/personal/demo", "--secret-prefix", "PSCALE",
                    ])
                }
                let text = String(describing: err)
                try expectContains(text, "gondr set PSCALE_SERVICE_TOKEN failed")
                try expectContains(text, "rollback=failed orphan_id=ps-orphan-777")
                try expectContains(text, "PlanetScale HTTP 503: service unavailable")
                try expectNotContains(text, childSecret)
                try expectNotContains(text, parentAuth)
            }
        },

        TestCase("PlanetScale TF-01: exec child spawn failure triggers recorded rollback") {
            try await withIsolatedRuntime {
                let childSecret = "pscale_tkn_exec_child"
                let keychain = FakeKeychainStore()
                keychain.seed(service: "\(keychainPrefix).planetscale", account: "acme", value: "pid:pscale_tkn_parent")
                let http = FakeHTTPTransport { req in
                    let path = req.url!.path
                    if req.httpMethod == "POST", path.hasSuffix("/service-tokens") {
                        return try FakeHTTPTransport.json(["id": "ps-exec-1", "token": childSecret])
                    }
                    if req.httpMethod == "POST", path.hasSuffix("/ps-exec-1/access") {
                        return try FakeHTTPTransport.json(["data": [["access": "read_branch"]]])
                    }
                    if req.httpMethod == "GET", path.hasSuffix("/ps-exec-1/access") {
                        return try FakeHTTPTransport.json(["data": [["access": "read_branch"]]])
                    }
                    if req.httpMethod == "DELETE", path.hasSuffix("/service-tokens/ps-exec-1") {
                        return try FakeHTTPTransport.json(["message": "delete denied"], status: 500)
                    }
                    throw FactoryError.message("Unexpected PlanetScale request: \(req.httpMethod ?? "") \(path)")
                }
                FactoryRuntime.current.keychain = keychain
                FactoryRuntime.current.http = http
                FactoryRuntime.current.runChildProcess = { _, _ in
                    throw FactoryError.message("spawn failed for pscale")
                }

                let err = try await expectThrowsAsync {
                    try await PlanetScale.exec([
                        "--org", "acme", "--database", "appdb", "--database-access", "read_branch",
                        "--expires-in", "1h", "--", "pscale", "branch", "list",
                    ])
                }
                let text = String(describing: err)
                try expectContains(text, "spawn failed for pscale")
                try expectContains(text, "rollback=failed orphan_id=ps-exec-1")
                try expectContains(text, "PlanetScale HTTP 500: delete denied")
                try expectNotContains(text, childSecret)
            }
        },

        TestCase("PlanetScale: mint happy path and revoke happy path") {
            try await withIsolatedRuntime {
                let keychain = FakeKeychainStore()
                keychain.seed(service: "\(keychainPrefix).planetscale", account: "acme", value: "pid:pscale_tkn_parent")
                let destFactory = FakeDestinationFactory()
                let http = FakeHTTPTransport { req in
                    let path = req.url!.path
                    if req.httpMethod == "POST", path.hasSuffix("/service-tokens") {
                        return try FakeHTTPTransport.json(["id": "ps-ok-1", "token": "pscale_tkn_ok_1"])
                    }
                    if req.httpMethod == "POST", path.hasSuffix("/ps-ok-1/access") {
                        return try FakeHTTPTransport.json(["data": [["access": "read_branch"]]])
                    }
                    if req.httpMethod == "GET", path.hasSuffix("/ps-ok-1/access") {
                        return try FakeHTTPTransport.json(["data": [["access": "read_branch"]]])
                    }
                    if req.httpMethod == "GET", path.hasSuffix("/service-tokens") {
                        return try FakeHTTPTransport.json(["data": [["id": "ps-ok-1", "name": "ci-db"]]])
                    }
                    if req.httpMethod == "DELETE", path.hasSuffix("/service-tokens/ps-ok-1") {
                        return FakeHTTPTransport.empty(status: 204)
                    }
                    throw FactoryError.message("Unexpected PlanetScale request: \(req.httpMethod ?? "") \(path)")
                }
                FactoryRuntime.current.keychain = keychain
                FactoryRuntime.current.http = http
                FactoryRuntime.current.destinations = destFactory

                try await PlanetScale.mint([
                    "--org", "acme", "--name", "ci-db", "--expires-in", "24h",
                    "--database", "appdb", "--database-access", "read_branch",
                    "--env", "dev", "--path", "/repos/personal/demo", "--secret-prefix", "PSCALE",
                ])
                try expectEqual(destFactory.lastStore?.stored.count, 2)
                try expectEqual(destFactory.lastStore?.stored[0].value, "ps-ok-1")
                try expectEqual(destFactory.lastStore?.stored[1].value, "pscale_tkn_ok_1")

                try await PlanetScale.revoke(["--org", "acme", "--name", "ci-db"])
                try expectTrue(http.requests.contains { $0.method == "DELETE" && $0.url.path.hasSuffix("/service-tokens/ps-ok-1") })
            }
        },
    ]
}
