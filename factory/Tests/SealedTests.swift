import Foundation
import Security

enum SealedTests {
    static let all: [TestCase] = [
        TestCase("TF-07: sealedState/isSealed returns sealed for YubiKey-marked payload") {
            let store = FakeKeychainStore()
            let sealer = FakeSealer()
            let sealed = try sealer.seal(Data("parent-secret".utf8))
            store.seed(service: "\(keychainPrefix).cloudflare", account: "bootstrap", data: sealed)

            let item = KeychainItem(service: "\(keychainPrefix).cloudflare", account: "bootstrap", store: store, sealer: sealer)
            try expectEqual(try item.sealedState(), .sealed)
            try expectTrue(try item.isSealed())
        },

        TestCase("TF-07: sealedState/isSealed returns unsealed for plain non-empty payload") {
            let store = FakeKeychainStore()
            let sealer = FakeSealer()
            store.seed(service: "\(keychainPrefix).cloudflare", account: "bootstrap", value: "plain-parent-token")

            let item = KeychainItem(service: "\(keychainPrefix).cloudflare", account: "bootstrap", store: store, sealer: sealer)
            try expectEqual(try item.sealedState(), .unsealed)
            try expectFalse(try item.isSealed())
        },

        TestCase("TF-07: sealedState/isSealed returns absent/false ONLY on errSecItemNotFound") {
            let store = FakeKeychainStore()
            let sealer = FakeSealer()
            let item = KeychainItem(service: "\(keychainPrefix).cloudflare", account: "bootstrap", store: store, sealer: sealer)

            try expectEqual(try item.sealedState(), .absent)
            try expectFalse(try item.isSealed())
        },

        TestCase("TF-07: isSealed fails closed on Keychain read error (auth/locked/decode)") {
            for status in [errSecAuthFailed, errSecInteractionNotAllowed, errSecDecode] {
                let store = FakeKeychainStore()
                store.readError = FactoryError.message("Keychain parent credential is unavailable (status \(status))")
                let item = KeychainItem(service: "\(keychainPrefix).cloudflare", account: "bootstrap", store: store, sealer: FakeSealer())

                let err = try expectThrows { _ = try item.isSealed() }
                try expectContains(String(describing: err), "status \(status)")
            }
        },

        TestCase("TF-07: isSealed fails closed on empty/corrupt Keychain payload") {
            let store = FakeKeychainStore()
            store.forcedReadResult = .found(Data())
            let item = KeychainItem(service: "\(keychainPrefix).cloudflare", account: "bootstrap", store: store, sealer: FakeSealer())

            let err = try expectThrows { _ = try item.isSealed() }
            try expectContains(String(describing: err), "empty or corrupt")
        },

        TestCase("TF-07: plain KeychainItem.write fails closed on Keychain read error without writing") {
            try await withIsolatedRuntime {
                let store = FakeKeychainStore()
                store.readError = FactoryError.message("Keychain parent credential is unavailable (status \(errSecInteractionNotAllowed))")
                Request.sealWithYubiKey = false

                let item = KeychainItem(service: "\(keychainPrefix).hetzner", account: "prod", store: store, sealer: FakeSealer())
                _ = try expectThrows {
                    try item.write(Data("new-plain-secret".utf8))
                }
                try expectEqual(store.writeCalls.count, 0)
            }
        },

        TestCase("TF-07 / F43: plain KeychainItem.write refuses to overwrite a sealed parent") {
            try await withIsolatedRuntime {
                let store = FakeKeychainStore()
                let sealer = FakeSealer()
                store.seed(service: "\(keychainPrefix).hetzner", account: "prod", data: try sealer.seal(Data("orig".utf8)))
                Request.sealWithYubiKey = false

                let item = KeychainItem(service: "\(keychainPrefix).hetzner", account: "prod", store: store, sealer: sealer)
                let err = try expectThrows {
                    try item.write(Data("replacement-plain".utf8))
                }
                try expectContains(String(describing: err), "sealed to a YubiKey")
                try expectEqual(store.writeCalls.count, 0)
            }
        },

        TestCase("TF-07: plain KeychainItem.write succeeds when absent or unsealed") {
            try await withIsolatedRuntime {
                let store = FakeKeychainStore()
                let sealer = FakeSealer()
                Request.sealWithYubiKey = false
                let item = KeychainItem(service: "\(keychainPrefix).hetzner", account: "prod", store: store, sealer: sealer)

                try item.write(Data("first-secret".utf8))
                try expectEqual(store.writeCalls.count, 1)
                try expectEqual(try item.read(), Data("first-secret".utf8))

                try item.write(Data("second-secret".utf8))
                try expectEqual(store.writeCalls.count, 2)
                try expectEqual(try item.read(), Data("second-secret".utf8))
            }
        },

        TestCase("TF-07: --yubikey write seals, round-trip verifies, and stores ciphertext") {
            try await withIsolatedRuntime {
                let store = FakeKeychainStore()
                let sealer = FakeSealer()
                Request.sealWithYubiKey = true
                let item = KeychainItem(service: "\(keychainPrefix).hetzner", account: "prod", store: store, sealer: sealer)

                try item.write(Data("top-secret".utf8))
                try expectEqual(sealer.sealCount, 1)
                try expectEqual(sealer.unsealCount, 1)
                try expectTrue(try item.isSealed())
                try expectEqual(try item.read(), Data("top-secret".utf8))
            }
        },

        TestCase("TF-07: liveRequireUserApproval fails closed on Keychain error without calling Touch ID") {
            try await withIsolatedRuntime {
                let store = FakeKeychainStore()
                store.readError = FactoryError.message("Keychain parent credential is unavailable (status \(errSecAuthFailed))")
                let localAuth = FakeLocalAuthEvaluator()
                FactoryRuntime.current.keychain = store
                FactoryRuntime.current.localAuth = localAuth
                Request.sealWithYubiKey = false

                let item = KeychainItem(service: "\(keychainPrefix).cloudflare", account: "bootstrap")
                let err = try await expectThrowsAsync {
                    try await liveRequireUserApproval(parent: item, action: "mint test token")
                }
                try expectContains(String(describing: err), "status \(errSecAuthFailed)")
                try expectEqual(localAuth.reasons.count, 0)
            }
        },

        TestCase("TF-07: liveRequireUserApproval skips Touch ID for sealed item and prompts for unsealed/absent") {
            try await withIsolatedRuntime {
                let store = FakeKeychainStore()
                let sealer = FakeSealer()
                let localAuth = FakeLocalAuthEvaluator()
                FactoryRuntime.current.keychain = store
                FactoryRuntime.current.sealer = sealer
                FactoryRuntime.current.localAuth = localAuth
                Request.sealWithYubiKey = false

                let sealedItem = KeychainItem(service: "\(keychainPrefix).cloudflare", account: "sealed")
                store.seed(service: sealedItem.service, account: sealedItem.account, data: try sealer.seal(Data("s".utf8)))
                try await liveRequireUserApproval(parent: sealedItem, action: "use sealed parent")
                try expectEqual(localAuth.reasons.count, 0)

                let plainItem = KeychainItem(service: "\(keychainPrefix).cloudflare", account: "plain")
                store.seed(service: plainItem.service, account: plainItem.account, value: "p")
                try await liveRequireUserApproval(parent: plainItem, action: "use plain parent")
                try expectEqual(localAuth.reasons.count, 1)

                let absentItem = KeychainItem(service: "\(keychainPrefix).cloudflare", account: "missing")
                try await liveRequireUserApproval(parent: absentItem, action: "import new parent")
                try expectEqual(localAuth.reasons.count, 2)
            }
        },
    ]
}
