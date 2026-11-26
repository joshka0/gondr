import Foundation

enum GitLabAndFlyTests {
    static let all: [TestCase] = [
        // MARK: - GitLab (REST)

        TestCase("GitLab TF-01: mintDeploy store failure + DELETE failure surfaces orphan_id and redacts secrets") {
            try await withIsolatedRuntime {
                let pat = "glpat-parent-secret-888"
                let deploySecret = "gldt-deploy-secret-888"
                let keychain = FakeKeychainStore()
                keychain.seed(service: "\(keychainPrefix).gitlab", account: "personal", value: pat)
                let http = FakeHTTPTransport { req in
                    let path = req.url!.path
                    if req.httpMethod == "POST", path.hasSuffix("/deploy_tokens") {
                        return try FakeHTTPTransport.json([
                            "id": 9012,
                            "name": "ci-deploy",
                            "username": "gitlab+deploy-token-9012",
                            "token": deploySecret,
                            "scopes": ["read_registry"],
                        ])
                    }
                    if req.httpMethod == "GET", path.hasSuffix("/deploy_tokens") {
                        return try FakeHTTPTransport.json([[
                            "id": 9012,
                            "name": "ci-deploy",
                            "username": "gitlab+deploy-token-9012",
                            "scopes": ["read_registry"],
                        ]])
                    }
                    if req.httpMethod == "DELETE", path.hasSuffix("/deploy_tokens/9012") {
                        return try FakeHTTPTransport.json(["message": "internal error"], status: 500)
                    }
                    throw FactoryError.message("Unexpected GitLab request: \(req.httpMethod ?? "") \(path)")
                }
                let destFactory = FakeDestinationFactory { callIndex, secret, value in
                    if callIndex == 2 {
                        throw FactoryError.message("gondr set \(secret) failed for \(value)")
                    }
                }
                FactoryRuntime.current.keychain = keychain
                FactoryRuntime.current.http = http
                FactoryRuntime.current.destinations = destFactory

                let err = try await expectThrowsAsync {
                    try await GitLab.mintDeploy([
                        "--account", "personal", "--project", "org/app",
                        "--name", "ci-deploy", "--expires-in", "7d",
                        "--scope", "read_registry",
                        "--env", "dev", "--path", "/repos/personal/demo", "--secret-prefix", "GITLAB_DEPLOY",
                    ])
                }
                let text = String(describing: err)
                try expectContains(text, "gondr set GITLAB_DEPLOY_TOKEN failed")
                try expectContains(text, "rollback=failed orphan_id=9012")
                try expectContains(text, "GitLab HTTP 500: internal error")
                try expectNotContains(text, deploySecret)
                try expectNotContains(text, pat)
            }
        },

        TestCase("GitLab TF-01: mintDeploy scope verify mismatch triggers rollback and revokeDeploy happy path") {
            try await withIsolatedRuntime {
                let keychain = FakeKeychainStore()
                keychain.seed(service: "\(keychainPrefix).gitlab", account: "personal", value: "glpat-parent-999")
                let http = FakeHTTPTransport { req in
                    let path = req.url!.path
                    if req.httpMethod == "POST", path.hasSuffix("/deploy_tokens") {
                        return try FakeHTTPTransport.json([
                            "id": 77,
                            "name": "ci-deploy",
                            "username": "gitlab+deploy-token-77",
                            "token": "gldt-secret-77",
                            "scopes": ["read_registry"],
                        ])
                    }
                    if req.httpMethod == "GET", path.hasSuffix("/deploy_tokens") {
                        return try FakeHTTPTransport.json([[
                            "id": 77,
                            "name": "ci-deploy",
                            "username": "gitlab+deploy-token-77",
                            "scopes": ["read_repository"],
                        ]])
                    }
                    if req.httpMethod == "DELETE", path.hasSuffix("/deploy_tokens/77") {
                        return FakeHTTPTransport.empty(status: 204)
                    }
                    throw FactoryError.message("Unexpected GitLab request: \(req.httpMethod ?? "") \(path)")
                }
                FactoryRuntime.current.keychain = keychain
                FactoryRuntime.current.http = http

                let err = try await expectThrowsAsync {
                    try await GitLab.mintDeploy([
                        "--account", "personal", "--project", "org/app",
                        "--name", "ci-deploy", "--expires-in", "7d",
                        "--scope", "read_registry",
                        "--env", "dev", "--path", "/repos/personal/demo", "--secret-prefix", "GITLAB_DEPLOY",
                    ])
                }
                let text = String(describing: err)
                try expectContains(text, "The deploy token is missing or its scopes differ")
                try expectContains(text, "rollback=succeeded id=77")
                try expectNotContains(text, "gldt-secret-77")

                try await GitLab.revokeDeploy(["--account", "personal", "--project", "org/app", "--name", "ci-deploy"])
                try expectEqual(http.requests.filter { $0.method == "DELETE" && $0.url.path.hasSuffix("/deploy_tokens/77") }.count, 2)
            }
        },

        // MARK: - Fly (Derived)

        TestCase("Fly: mint happy path and store failure reports rollback=unsupported without leaking token") {
            try await withIsolatedRuntime {
                let parentToken = "FlyV1 fm2_parent_secret_111"
                let childToken = "FlyV1 fm2_child_secret_222"
                let keychain = FakeKeychainStore()
                keychain.seed(service: "\(keychainPrefix).fly", account: "personal", value: parentToken)
                let http = FakeHTTPTransport { req in
                    let auth = req.value(forHTTPHeaderField: "Authorization")
                    if auth == parentToken {
                        return try FakeHTTPTransport.json(["data": ["app": ["name": "my-app", "internalNumericId": 12345]]])
                    }
                    if auth == childToken {
                        return try FakeHTTPTransport.json(["data": ["app": ["name": "my-app"]]])
                    }
                    throw FactoryError.message("Unexpected Fly auth")
                }
                let okDest = FakeDestinationFactory()
                FactoryRuntime.current.keychain = keychain
                FactoryRuntime.current.http = http
                FactoryRuntime.current.destinations = okDest
                FactoryRuntime.current.attenuateFly = { _, _ in childToken }

                try await Fly.mint([
                    "--org", "personal", "--app", "my-app", "--expires-in", "24h",
                    "--env", "dev", "--path", "/repos/personal/demo", "--secret", "FLY_APP_TOKEN",
                ])
                try expectEqual(okDest.lastStore?.stored.first?.value, childToken)

                FactoryRuntime.current.destinations = FakeDestinationFactory { _, secret, value in
                    throw FactoryError.message("gondr set \(secret) failed for \(value)")
                }
                let err = try await expectThrowsAsync {
                    try await Fly.mint([
                        "--org", "personal", "--app", "my-app", "--expires-in", "24h",
                        "--env", "dev", "--path", "/repos/personal/demo", "--secret", "FLY_APP_TOKEN",
                    ])
                }
                let text = String(describing: err)
                try expectContains(text, "gondr set FLY_APP_TOKEN failed")
                try expectContains(text, "rollback=unsupported")
                try expectNotContains(text, childToken)
                try expectNotContains(text, parentToken)
            }
        },
    ]
}
