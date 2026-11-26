import Foundation

enum RollbackOutcome: Equatable {
    case succeeded(resourceID: String)
    case failed(resourceID: String, reason: String)
}

/// Structured error thrown whenever post-mint verification, vault write-back,
/// or post-create configuration fails and a compensating delete/revoke runs.
/// Always reports both the original failure and the explicit rollback outcome
/// (`rollback=succeeded` or `rollback=failed orphan_id=<id> reason=<err>`).
struct RollbackError: Error, CustomStringConvertible, Equatable {
    let resourceKind: String
    let originalReason: String
    let outcome: RollbackOutcome

    var description: String {
        switch outcome {
        case let .succeeded(resourceID):
            return "\(resourceKind) verification or vault storage failed: \(originalReason) (rollback=succeeded id=\(resourceID))"
        case let .failed(resourceID, reason):
            return "\(resourceKind) verification or vault storage failed: \(originalReason) (rollback=failed orphan_id=\(resourceID) reason=\(reason))"
        }
    }
}

/// Replaces any known secret values in error text so rollback diagnostics can
/// never leak minted or parent credentials.
func redactSecrets(_ text: String, secrets: [String]) -> String {
    var sanitized = text
    for secret in secrets where !secret.isEmpty {
        sanitized = sanitized.replacingOccurrences(of: secret, with: "[REDACTED]")
    }
    return sanitized
}

/// Runs post-create work (verification, grants, or vault write-back) for a
/// newly minted remote resource. On failure, runs `revoke` and throws a
/// `RollbackError` capturing both the original failure and whether rollback
/// succeeded or left an orphaned remote credential.
func withMintRollback<T>(
    resourceKind: String,
    resourceID: String,
    redact secrets: [String],
    work: () async throws -> T,
    revoke: () async throws -> Void
) async throws -> T {
    do {
        return try await work()
    } catch let originalError {
        let originalReason = redactSecrets(String(describing: originalError), secrets: secrets)
        do {
            try await revoke()
            throw RollbackError(
                resourceKind: resourceKind,
                originalReason: originalReason,
                outcome: .succeeded(resourceID: resourceID)
            )
        } catch let rollbackError {
            let rollbackReason = redactSecrets(String(describing: rollbackError), secrets: secrets)
            throw RollbackError(
                resourceKind: resourceKind,
                originalReason: originalReason,
                outcome: .failed(resourceID: resourceID, reason: rollbackReason)
            )
        }
    }
}
