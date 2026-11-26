import Foundation
import Security

struct RecordedRequest: Sendable {
    let method: String
    let url: URL
    let headers: [String: String]
    let body: Data?
}

final class FakeHTTPTransport: HTTPTransport, @unchecked Sendable {
    private let lock = NSLock()
    private var _requests: [RecordedRequest] = []
    private let handler: @Sendable (URLRequest) throws -> (Int, Data)

    init(handler: @escaping @Sendable (URLRequest) throws -> (Int, Data)) {
        self.handler = handler
    }

    var requests: [RecordedRequest] {
        lock.lock()
        defer { lock.unlock() }
        return _requests
    }

    func data(for request: URLRequest) async throws -> (Data, URLResponse) {
        let recorded = RecordedRequest(
            method: request.httpMethod ?? "GET",
            url: request.url!,
            headers: request.allHTTPHeaderFields ?? [:],
            body: request.httpBody
        )
        lock.withLock {
            _requests.append(recorded)
        }

        let (status, body) = try handler(request)
        let response = HTTPURLResponse(
            url: request.url!,
            statusCode: status,
            httpVersion: "HTTP/1.1",
            headerFields: ["Content-Type": "application/json"]
        )!
        return (body, response)
    }

    static func json(_ object: Any, status: Int = 200) throws -> (Int, Data) {
        (status, try JSONSerialization.data(withJSONObject: object))
    }

    static func empty(status: Int = 204) -> (Int, Data) {
        (status, Data())
    }
}

final class FakeKeychainStore: KeychainStore, @unchecked Sendable {
    private let lock = NSLock()
    private var items: [String: Data] = [:]
    var readError: Error?
    var writeError: Error?
    var forcedReadResult: KeychainReadResult?
    private(set) var readCalls: [(service: String, account: String)] = []
    private(set) var writeCalls: [(service: String, account: String, data: Data)] = []

    private func key(_ service: String, _ account: String) -> String {
        "\(service)/\(account)"
    }

    func seed(service: String, account: String, value: String) {
        seed(service: service, account: account, data: Data(value.utf8))
    }

    func seed(service: String, account: String, data: Data) {
        lock.lock()
        defer { lock.unlock() }
        items[key(service, account)] = data
    }

    func storedData(service: String, account: String) -> Data? {
        lock.lock()
        defer { lock.unlock() }
        return items[key(service, account)]
    }

    func readRaw(service: String, account: String) throws -> KeychainReadResult {
        lock.lock()
        readCalls.append((service, account))
        let err = readError
        let forced = forcedReadResult
        let data = items[key(service, account)]
        lock.unlock()

        if let err { throw err }
        if let forced { return forced }
        if let data { return .found(data) }
        return .itemNotFound
    }

    func writeRaw(_ data: Data, service: String, account: String) throws {
        lock.lock()
        writeCalls.append((service, account, data))
        let err = writeError
        if err == nil {
            items[key(service, account)] = data
        }
        lock.unlock()

        if let err { throw err }
    }
}

final class FakeSealer: CredentialSealer, @unchecked Sendable {
    private let lock = NSLock()
    private(set) var sealCount = 0
    private(set) var unsealCount = 0
    var tamperUnseal = false

    func isSealed(_ stored: Data) -> Bool {
        stored.starts(with: YubiKey.marker)
    }

    func seal(_ plain: Data) throws -> Data {
        lock.lock()
        sealCount += 1
        lock.unlock()
        return YubiKey.marker + Data(plain.reversed())
    }

    func unseal(_ stored: Data) throws -> Data {
        lock.lock()
        unsealCount += 1
        let tamper = tamperUnseal
        lock.unlock()
        guard isSealed(stored) else {
            throw FactoryError.message("Item is not sealed to a YubiKey")
        }
        let body = Data(stored.dropFirst(YubiKey.marker.count).reversed())
        return tamper ? body + Data("!".utf8) : body
    }
}

final class FakeDestinationStore: SecretDestinationStore, @unchecked Sendable {
    let environment: String
    let path: String
    private let lock = NSLock()
    private(set) var stored: [(secret: String, value: String)] = []
    private let onStore: (@Sendable (Int, String, String) throws -> Void)?

    init(
        environment: String,
        path: String,
        onStore: (@Sendable (Int, String, String) throws -> Void)? = nil
    ) {
        self.environment = environment
        self.path = path
        self.onStore = onStore
    }

    func label(_ secret: String) -> String {
        "Infisical \(environment):\(path)/\(secret)"
    }

    func store(_ value: String, as secret: String) throws {
        lock.lock()
        let callNumber = stored.count + 1
        lock.unlock()

        if let onStore {
            try onStore(callNumber, secret, value)
        }

        lock.lock()
        stored.append((secret, value))
        lock.unlock()
    }
}

final class FakeDestinationFactory: SecretDestinationFactory, @unchecked Sendable {
    let onStore: (@Sendable (Int, String, String) throws -> Void)?
    private let lock = NSLock()
    private(set) var lastStore: FakeDestinationStore?

    init(onStore: (@Sendable (Int, String, String) throws -> Void)? = nil) {
        self.onStore = onStore
    }

    func make(options: Options) throws -> any SecretDestinationStore {
        let env = try options.required("--env")
        let path = try options.required("--path")
        let store = FakeDestinationStore(environment: env, path: path, onStore: onStore)
        lock.lock()
        lastStore = store
        lock.unlock()
        return store
    }
}

final class FakeApprovalAuthorizer: ApprovalAuthorizer, @unchecked Sendable {
    private let lock = NSLock()
    private(set) var requests: [(service: String, account: String, action: String)] = []
    var errorToThrow: Error?

    func requireApproval(parent: KeychainItem, action: String) async throws {
        let err: Error? = lock.withLock {
            requests.append((parent.service, parent.account, action))
            return errorToThrow
        }
        if let err { throw err }
    }
}

final class FakeLocalAuthEvaluator: LocalAuthEvaluator, @unchecked Sendable {
    private let lock = NSLock()
    private(set) var reasons: [String] = []
    var allow: Bool = true
    var errorToThrow: Error?

    func evaluate(localizedReason: String) async throws -> Bool {
        let (allowed, err): (Bool, Error?) = lock.withLock {
            reasons.append(localizedReason)
            return (allow, errorToThrow)
        }
        if let err { throw err }
        return allowed
    }
}

struct FixedClock: FactoryClock {
    let fixedDate: Date
    init(unixTimestamp: TimeInterval = 1_760_000_000) {
        self.fixedDate = Date(timeIntervalSince1970: unixTimestamp)
    }
    func now() -> Date { fixedDate }
}

func withIsolatedRuntime(_ body: () async throws -> Void) async throws {
    let savedRuntime = FactoryRuntime.current
    let savedReason = Request.reason
    let savedSeal = Request.sealWithYubiKey
    defer {
        FactoryRuntime.current = savedRuntime
        Request.reason = savedReason
        Request.sealWithYubiKey = savedSeal
    }
    Request.reason = "automated factory security test"
    Request.sealWithYubiKey = false
    FactoryRuntime.current = FactoryRuntime(
        http: FakeHTTPTransport { request in
            throw FactoryError.message("Unexpected HTTP call in test: \(request.httpMethod ?? "GET") \(request.url?.absoluteString ?? "")")
        },
        keychain: FakeKeychainStore(),
        sealer: FakeSealer(),
        destinations: FakeDestinationFactory(),
        approval: FakeApprovalAuthorizer(),
        localAuth: FakeLocalAuthEvaluator(),
        clock: FixedClock()
    )
    try await body()
}
