import Foundation
import Security

/// Seals parent credentials to an EC P-256 key in the YubiKey's PIV slot 9d
/// (Key Management). macOS exposes the key through its built-in PIV token
/// driver once the slot holds a certificate whose subject contains
/// `yubiKeySubject`. The key is generated with touch policy "always", so the
/// YubiKey refuses every decryption until someone touches it: the touch is
/// the approval, enforced by the hardware.
enum YubiKey {
    static let subject = "gondr-token"
    /// Marks a sealed item. The ciphertext follows the marker.
    static let marker = Data("gondr-seal-piv-v1\n".utf8)
    private static let algorithm = SecKeyAlgorithm.eciesEncryptionStandardVariableIVX963SHA256AESGCM

    static func isSealed(_ stored: Data) -> Bool { stored.starts(with: marker) }

    /// Encrypts to the slot's public key. Needs no touch.
    static func seal(_ plain: Data) throws -> Data {
        let key = try privateKey()
        guard let publicKey = SecKeyCopyPublicKey(key) else {
            throw FactoryError.message("The YubiKey key has no public key")
        }
        var error: Unmanaged<CFError>?
        guard let sealed = SecKeyCreateEncryptedData(publicKey, algorithm, plain as CFData, &error) as Data? else {
            throw FactoryError.message("Sealing to the YubiKey failed: \(describe(error))")
        }
        return marker + sealed
    }

    /// Decrypts on the YubiKey. Blocks until the key is touched (and its PIN
    /// entered, if the slot's PIN policy asks); fails if nobody touches it.
    static func unseal(_ stored: Data) throws -> Data {
        guard isSealed(stored) else { throw FactoryError.message("Item is not sealed to a YubiKey") }
        let key = try privateKey()
        print("Touch your YubiKey…")
        fflush(stdout)
        var error: Unmanaged<CFError>?
        guard let plain = SecKeyCreateDecryptedData(key, algorithm, stored.dropFirst(marker.count) as CFData, &error) as Data?,
              !plain.isEmpty
        else {
            throw FactoryError.message("The YubiKey did not open the parent credential (no touch, wrong key, or PIN refused): \(describe(error))")
        }
        return plain
    }

    /// The one private key on a PIV smart card whose certificate subject is
    /// exactly `subject`. macOS ignores kSecMatchSubjectContains for token
    /// identities and returns every one, including keys that need no touch
    /// (an SSH key on com.apple.ctkcard), so both checks happen here.
    private static func privateKey() throws -> SecKey {
        let query: [String: Any] = [
            kSecClass as String: kSecClassIdentity,
            kSecAttrAccessGroup as String: kSecAttrAccessGroupToken,
            kSecMatchLimit as String: kSecMatchLimitAll,
            kSecReturnRef as String: true,
        ]
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        let identities = status == errSecSuccess ? (result as? [SecIdentity]) ?? [] : []
        let keys: [SecKey] = identities.compactMap { identity in
            var certificate: SecCertificate?
            var key: SecKey?
            guard SecIdentityCopyCertificate(identity, &certificate) == errSecSuccess,
                  let certificate, SecCertificateCopySubjectSummary(certificate) as String? == subject,
                  SecIdentityCopyPrivateKey(identity, &key) == errSecSuccess, let key,
                  let attributes = SecKeyCopyAttributes(key) as? [String: Any],
                  (attributes[kSecAttrTokenID as String] as? String)?.hasPrefix("com.apple.pivtoken") == true
            else { return nil }
            return key
        }
        guard !keys.isEmpty else {
            throw FactoryError.message(
                "No YubiKey with a \"\(subject)\" PIV certificate is connected. Set it up as factory/README.md says, then unplug and replug the YubiKey."
            )
        }
        guard keys.count == 1 else {
            throw FactoryError.message("\(keys.count) connected PIV certificates are named \"\(subject)\"; connect one YubiKey")
        }
        let key = keys[0]
        guard SecKeyIsAlgorithmSupported(key, .decrypt, algorithm) else {
            throw FactoryError.message("The YubiKey key cannot decrypt ECIES P-256; generate an ECCP256 key in slot 9d")
        }
        return key
    }

    private static func describe(_ error: Unmanaged<CFError>?) -> String {
        error.map { String(describing: $0.takeRetainedValue()) } ?? "unknown error"
    }
}
