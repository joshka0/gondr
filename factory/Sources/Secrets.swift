import Foundation
import Security

/// Explicit Keychain seal status. Any unexpected Keychain read error or
/// empty/corrupt item throws instead of producing a state.
enum SealedState: Equatable {
    case sealed
    case unsealed
    case absent
}

/// A parent credential in the login keychain. The ACL trusts the binary
/// that created the item; after a rebuild macOS asks once (Always Allow).
/// An item imported with `--yubikey` holds ciphertext that only the YubiKey
/// can open (`YubiKey`); `read` opens it, which needs a touch.
struct KeychainItem: Sendable {
    let service: String
    let account: String
    private let storeOverride: (any KeychainStore)?
    private let sealerOverride: (any CredentialSealer)?

    init(
        service: String,
        account: String,
        store: (any KeychainStore)? = nil,
        sealer: (any CredentialSealer)? = nil
    ) {
        self.service = service
        self.account = account
        self.storeOverride = store
        self.sealerOverride = sealer
    }

    private var store: any KeychainStore { storeOverride ?? FactoryRuntime.current.keychain }
    private var sealer: any CredentialSealer { sealerOverride ?? FactoryRuntime.current.sealer }

    /// The plain credential. A sealed item is opened on the YubiKey.
    func read() throws -> Data {
        let data = try stored()
        return sealer.isSealed(data) ? try sealer.unseal(data) : data
    }

    /// Distinguishes sealed, unsealed, and absent items. Any Keychain read error
    /// or empty/corrupt payload fails closed by throwing.
    func sealedState() throws -> SealedState {
        switch try store.readRaw(service: service, account: account) {
        case .itemNotFound:
            return .absent
        case let .found(data):
            guard !data.isEmpty else {
                throw FactoryError.message("Keychain parent credential \(service)/\(account) is empty or corrupt")
            }
            return sealer.isSealed(data) ? .sealed : .unsealed
        }
    }

    /// Fail-closed check: returns `true` when sealed, `false` ONLY when
    /// confirmed unsealed or absent, and throws on any Keychain/corrupt error.
    func isSealed() throws -> Bool {
        switch try sealedState() {
        case .sealed: return true
        case .unsealed, .absent: return false
        }
    }

    /// Stores the credential, sealed when the request has `--yubikey`. A sealed
    /// item is opened once before it is stored, so a key that cannot open it
    /// stores nothing; that touch is also the approval. A sealed item is never
    /// replaced by a plain one.
    func write(_ data: Data) throws {
        guard Request.sealWithYubiKey else {
            guard !(try isSealed()) else {
                throw FactoryError.message("\(service)/\(account) is sealed to a YubiKey; import it again with --yubikey")
            }
            return try store.writeRaw(data, service: service, account: account)
        }
        let sealed = try sealer.seal(data)
        var opened = try sealer.unseal(sealed)
        defer { opened.resetBytes(in: 0..<opened.count) }
        guard opened == data else { throw FactoryError.message("The YubiKey opened a different value; nothing stored") }
        try store.writeRaw(sealed, service: service, account: account)
    }

    private func stored() throws -> Data {
        switch try store.readRaw(service: service, account: account) {
        case .itemNotFound:
            throw FactoryError.message("Keychain parent credential \(service)/\(account) is unavailable (status \(errSecItemNotFound))")
        case let .found(data):
            guard !data.isEmpty else {
                throw FactoryError.message("Keychain parent credential \(service)/\(account) is empty or corrupt")
            }
            return data
        }
    }

    /// Reads the item after approval and reports presence only.
    func check() async throws {
        try await requireUserApproval(parent: self, action: "check whether the \(service) parent credential is available.")
        let sealed = try isSealed()
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
struct SecretDestination: SecretDestinationStore {
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
        let previousSigPipe = signal(SIGPIPE, SIG_IGN)
        defer { signal(SIGPIPE, previousSigPipe) }
        try process.run()
        var writeError: Error?
        do {
            try input.fileHandleForWriting.write(contentsOf: Data(value.utf8))
        } catch {
            writeError = error
        }
        try? input.fileHandleForWriting.close()
        process.waitUntilExit()
        if let writeError {
            throw FactoryError.message("gondr set \(secret) write failed (exit \(process.terminationStatus)): \(writeError)")
        }
        guard process.terminationStatus == 0 else {
            throw FactoryError.message("gondr set \(secret) exited \(process.terminationStatus)")
        }
    }
}

func isSecretName(_ value: String) -> Bool { matches(value, "^[A-Z][A-Z0-9_]+$") }
