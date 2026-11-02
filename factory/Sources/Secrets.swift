import Foundation
import Security

/// A parent credential in the login keychain. The ACL trusts the binary
/// that created the item; after a rebuild macOS asks once (Always Allow).
/// An item imported with `--yubikey` holds ciphertext that only the YubiKey
/// can open (`YubiKey`); `read` opens it, which needs a touch.
struct KeychainItem {
    let service: String
    let account: String

    private var query: [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]
    }

    /// The plain credential. A sealed item is opened on the YubiKey.
    func read() throws -> Data {
        let data = try stored()
        return YubiKey.isSealed(data) ? try YubiKey.unseal(data) : data
    }

    /// True when the item exists and is sealed to a YubiKey. Reads only the ciphertext.
    var isSealed: Bool { (try? stored()).map(YubiKey.isSealed) ?? false }

    /// Stores the credential, sealed when the request has `--yubikey`. A sealed
    /// item is opened once before it is stored, so a key that cannot open it
    /// stores nothing; that touch is also the approval. A sealed item is never
    /// replaced by a plain one.
    func write(_ data: Data) throws {
        guard Request.sealWithYubiKey else {
            guard !isSealed else {
                throw FactoryError.message("\(service)/\(account) is sealed to a YubiKey; import it again with --yubikey")
            }
            return try store(data)
        }
        let sealed = try YubiKey.seal(data)
        var opened = try YubiKey.unseal(sealed)
        defer { opened.resetBytes(in: 0..<opened.count) }
        guard opened == data else { throw FactoryError.message("The YubiKey opened a different value; nothing stored") }
        try store(sealed)
    }

    private func stored() throws -> Data {
        var lookup = query
        lookup[kSecReturnData as String] = true
        lookup[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: CFTypeRef?
        let status = SecItemCopyMatching(lookup as CFDictionary, &result)
        guard status == errSecSuccess, let data = result as? Data, !data.isEmpty else {
            throw FactoryError.message("Keychain parent credential \(service)/\(account) is unavailable (status \(status))")
        }
        return data
    }

    private func store(_ data: Data) throws {
        let update = SecItemUpdate(query as CFDictionary, [kSecValueData as String: data] as CFDictionary)
        if update == errSecSuccess { return }
        guard update == errSecItemNotFound else {
            throw FactoryError.message("Keychain update failed (status \(update))")
        }
        var add = query
        add[kSecValueData as String] = data
        let status = SecItemAdd(add as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw FactoryError.message("Keychain add failed (status \(status))")
        }
    }

    /// Reads the item after approval and reports presence only.
    func check() async throws {
        try await requireUserApproval(parent: self, action: "check whether the \(service) parent credential is available.")
        let sealed = isSealed
        var data = try read()
        let present = !data.isEmpty
        data.resetBytes(in: 0..<data.count)
        print("keychain_service=\(service)")
        print("keychain_account=\(account)")
        print("credential_present=\(present)")
        print("sealed=\(sealed ? "yubikey" : "none")")
        print("credential_exposed=false")
    }
}

/// Reads one secret from the terminal with echo off. Never from stdin, so
/// a pipe or an agent cannot feed it silently.
func readSecretFromTerminal(prompt: String) throws -> Data {
    var buffer = [CChar](repeating: 0, count: 4096)
    guard readpassphrase(prompt, &buffer, buffer.count, RPP_REQUIRE_TTY) != nil else {
        throw FactoryError.message("A terminal is required to enter the secret")
    }
    defer { for index in buffer.indices { buffer[index] = 0 } }
    let length = buffer.firstIndex(of: 0) ?? 0
    guard length > 0 else { throw FactoryError.message("Empty secret") }
    return Data(buffer[0..<length].map { UInt8(bitPattern: $0) })
}

/// Where a minted secret goes: the Infisical folder that `gondr token mint` resolved and checked
/// against the repo's boundary. The factory stores each value with `gondr set`, which reads it from stdin.
struct SecretDestination {
    let environment: String
    let path: String
    let gondr: String

    init(_ options: Options) throws {
        environment = try options.required("--env")
        path = try options.required("--path")
        guard let gondr = ProcessInfo.processInfo.environment["GONDR_BIN"], gondr.hasPrefix("/") else {
            throw FactoryError.message("mint stores secrets through gondr: run it as `gondr token mint ...`")
        }
        self.gondr = gondr
        guard matches(environment, "^[A-Za-z0-9_-]+$"), path.hasPrefix("/"), !path.contains("..") else {
            throw FactoryError.message("Infisical destination has an invalid shape")
        }
    }

    func label(_ secret: String) -> String {
        "Infisical \(environment):\(path)/\(secret)"
    }

    /// Writes the value through stdin, so it never appears in argv. gondr prints names only.
    func store(_ value: String, as secret: String) throws {
        let process = Process()
        let input = Pipe()
        process.executableURL = URL(fileURLWithPath: gondr)
        process.arguments = ["set", secret, "--env", environment, "--path", path]
        process.standardInput = input
        process.standardOutput = FileHandle.nullDevice
        try process.run()
        input.fileHandleForWriting.write(Data(value.utf8))
        try input.fileHandleForWriting.close()
        process.waitUntilExit()
        guard process.terminationStatus == 0 else {
            throw FactoryError.message("gondr set \(secret) exited \(process.terminationStatus)")
        }
    }
}

func isSecretName(_ value: String) -> Bool { matches(value, "^[A-Z][A-Z0-9_]+$") }
