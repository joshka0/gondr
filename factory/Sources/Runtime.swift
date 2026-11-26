import Foundation
import LocalAuthentication
import Security

/// Result of reading raw bytes from Keychain, distinguishing absence
/// (`errSecItemNotFound`) from unexpected Keychain or corruption errors.
enum KeychainReadResult: Equatable {
    case found(Data)
    case itemNotFound
}

protocol HTTPTransport: Sendable {
    func data(for request: URLRequest) async throws -> (Data, URLResponse)
}

protocol KeychainStore: Sendable {
    func readRaw(service: String, account: String) throws -> KeychainReadResult
    func writeRaw(_ data: Data, service: String, account: String) throws
}

protocol CredentialSealer: Sendable {
    func isSealed(_ stored: Data) -> Bool
    func seal(_ plain: Data) throws -> Data
    func unseal(_ stored: Data) throws -> Data
}

protocol SecretDestinationStore: Sendable {
    var environment: String { get }
    var path: String { get }
    func label(_ secret: String) -> String
    func store(_ value: String, as secret: String) throws
}

protocol SecretDestinationFactory: Sendable {
    func make(options: Options) throws -> any SecretDestinationStore
}

protocol ApprovalAuthorizer: Sendable {
    func requireApproval(parent: KeychainItem, action: String) async throws
}

protocol LocalAuthEvaluator: Sendable {
    func evaluate(localizedReason: String) async throws -> Bool
}

protocol FactoryClock: Sendable {
    func now() -> Date
}

struct LiveHTTPTransport: HTTPTransport {
    func data(for request: URLRequest) async throws -> (Data, URLResponse) {
        try await URLSession.shared.data(for: request)
    }
}

struct LiveKeychainStore: KeychainStore {
    private func baseQuery(service: String, account: String) -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]
    }

    func readRaw(service: String, account: String) throws -> KeychainReadResult {
        var lookup = baseQuery(service: service, account: account)
        lookup[kSecReturnData as String] = true
        lookup[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: CFTypeRef?
        let status = SecItemCopyMatching(lookup as CFDictionary, &result)
        if status == errSecItemNotFound {
            return .itemNotFound
        }
        guard status == errSecSuccess else {
            throw FactoryError.message("Keychain parent credential \(service)/\(account) is unavailable (status \(status))")
        }
        guard let data = result as? Data, !data.isEmpty else {
            throw FactoryError.message("Keychain parent credential \(service)/\(account) is empty or corrupt (status \(status))")
        }
        return .found(data)
    }

    func writeRaw(_ data: Data, service: String, account: String) throws {
        let query = baseQuery(service: service, account: account)
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
}

struct LiveYubiKeySealer: CredentialSealer {
    func isSealed(_ stored: Data) -> Bool { YubiKey.isSealed(stored) }
    func seal(_ plain: Data) throws -> Data { try YubiKey.seal(plain) }
    func unseal(_ stored: Data) throws -> Data { try YubiKey.unseal(stored) }
}

struct LiveSecretDestinationFactory: SecretDestinationFactory {
    func make(options: Options) throws -> any SecretDestinationStore {
        try SecretDestination(options)
    }
}

struct LiveApprovalAuthorizer: ApprovalAuthorizer {
    func requireApproval(parent: KeychainItem, action: String) async throws {
        try await liveRequireUserApproval(parent: parent, action: action)
    }
}

struct LiveLocalAuthEvaluator: LocalAuthEvaluator {
    func evaluate(localizedReason: String) async throws -> Bool {
        let context = LAContext()
        var evaluationError: NSError?
        guard context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &evaluationError) else {
            throw FactoryError.message("Local user authentication is unavailable")
        }
        return try await context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: localizedReason)
    }
}

struct LiveFactoryClock: FactoryClock {
    func now() -> Date { Date() }
}

/// Process-wide dependency seams with production defaults. Tests replace
/// `FactoryRuntime.current` with deterministic fakes without touching Keychain,
/// Touch ID, YubiKey, or the network.
struct FactoryRuntime: Sendable {
    var http: any HTTPTransport = LiveHTTPTransport()
    var keychain: any KeychainStore = LiveKeychainStore()
    var sealer: any CredentialSealer = LiveYubiKeySealer()
    var destinations: any SecretDestinationFactory = LiveSecretDestinationFactory()
    var approval: any ApprovalAuthorizer = LiveApprovalAuthorizer()
    var localAuth: any LocalAuthEvaluator = LiveLocalAuthEvaluator()
    var clock: any FactoryClock = LiveFactoryClock()
    var attenuateFly: @Sendable (String, Data) throws -> String = { try Fly.liveAttenuate(parent: $0, caveats: $1) }
    var runChildProcess: @Sendable ([String], [String: String]) throws -> Int32 = { try liveRunChild($0, environment: $1) }

    nonisolated(unsafe) static var current = FactoryRuntime()
}
