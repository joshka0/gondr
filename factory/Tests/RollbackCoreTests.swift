import Foundation

enum RollbackCoreTests {
    static let all: [TestCase] = [
        // MARK: - Core Rollback Helper (TF-01 / TR-P1)

        TestCase("TF-01: withMintRollback returns work value and never calls revoke on success") {
            var revokeCalled = false
            let value = try await withMintRollback(
                resourceKind: "Test token",
                resourceID: "tok-1",
                redact: ["super-secret-value"],
                work: { "ok" },
                revoke: { revokeCalled = true }
            )
            try expectEqual(value, "ok")
            try expectFalse(revokeCalled)
        },

        TestCase("TF-01: withMintRollback records rollback=succeeded and redacts secrets") {
            var revokedID: String?
            let secret = "cf_secret_canary_9911"
            let err = try await expectThrowsAsync {
                _ = try await withMintRollback(
                    resourceKind: "Cloudflare token",
                    resourceID: "tok-42",
                    redact: [secret],
                    work: { () async throws -> Void in
                        throw FactoryError.message("store failed while writing \(secret)")
                    },
                    revoke: {
                        revokedID = "tok-42"
                    }
                )
            }
            try expectEqual(revokedID, "tok-42")
            let text = String(describing: err)
            try expectContains(text, "store failed while writing [REDACTED]")
            try expectContains(text, "rollback=succeeded id=tok-42")
            try expectNotContains(text, secret)
        },

        TestCase("TF-01: withMintRollback surfaces BOTH original and rollback errors + orphan_id and redacts secrets") {
            let secret = "tskey-auth-canary-7788"
            let parent = "tskey-client-parent-3344"
            let err = try await expectThrowsAsync {
                _ = try await withMintRollback(
                    resourceKind: "Tailscale auth key",
                    resourceID: "key-orphan-9",
                    redact: [secret, parent],
                    work: { () async throws -> Void in
                        throw FactoryError.message("gondr set exited 1 for \(secret)")
                    },
                    revoke: {
                        throw FactoryError.message("HTTP 503 with auth \(parent) and \(secret)")
                    }
                )
            }
            let text = String(describing: err)
            try expectContains(text, "gondr set exited 1 for [REDACTED]")
            try expectContains(text, "rollback=failed orphan_id=key-orphan-9")
            try expectContains(text, "reason=HTTP 503 with auth [REDACTED] and [REDACTED]")
            try expectNotContains(text, secret)
            try expectNotContains(text, parent)
            guard let rollbackErr = err as? RollbackError else {
                throw TestFailure("Expected RollbackError, got \(type(of: err))")
            }
            try expectEqual(rollbackErr.outcome, .failed(resourceID: "key-orphan-9", reason: "HTTP 503 with auth [REDACTED] and [REDACTED]"))
        },
    ]
}
