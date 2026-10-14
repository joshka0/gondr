import Foundation
import LocalAuthentication
import Security

enum FactoryError: Error, CustomStringConvertible {
    case message(String)

    var description: String {
        switch self { case let .message(message): message }
    }
}

private let usage = """
Usage:
  infra-token-factory mint cloudflare <options>
  infra-token-factory revoke cloudflare --name <token-name> --account-id <id>
  infra-token-factory mint planetscale <options>
  infra-token-factory revoke planetscale --org <org> --name <token-name>
  infra-token-factory exec hetzner --project <label> -- <command> [args...]
  infra-token-factory import planetscale --org <org>
  infra-token-factory import hetzner --project <label>
  infra-token-factory check cloudflare
  infra-token-factory check planetscale --org <org>
  infra-token-factory check hetzner --project <label>
"""

@main
struct InfraTokenFactory {
    static func main() async {
        let values = Array(CommandLine.arguments.dropFirst())
        do {
            guard values.count >= 2 else { throw FactoryError.message(usage) }
            let rest = Array(values.dropFirst(2))
            switch (values[0], values[1]) {
            case ("mint", "cloudflare"): try await Cloudflare.mint(rest)
            case ("revoke", "cloudflare"): try await Cloudflare.revoke(rest)
            case ("check", "cloudflare"): try await Cloudflare.check(rest)
            case ("mint", "planetscale"): try await PlanetScale.mint(rest)
            case ("revoke", "planetscale"): try await PlanetScale.revoke(rest)
            case ("import", "planetscale"): try await PlanetScale.importParent(rest)
            case ("check", "planetscale"): try await PlanetScale.check(rest)
            case ("exec", "hetzner"): try await Hetzner.exec(rest)
            case ("import", "hetzner"): try await Hetzner.importParent(rest)
            case ("check", "hetzner"): try await Hetzner.check(rest)
            default: throw FactoryError.message(usage)
            }
        } catch {
            FileHandle.standardError.write(Data("\(values.first ?? "factory")=failed reason=\(error)\n".utf8))
            exit(1)
        }
    }
}

/// `--key value` pairs. Keys in `repeatable` may appear more than once; every
/// other key at most once. Unknown keys fail closed.
struct Options {
    private var values: [String: [String]] = [:]

    init(_ arguments: [String], allowed: Set<String>, repeatable: Set<String> = []) throws {
        var index = 0
        while index < arguments.count {
            let key = arguments[index]
            guard key.hasPrefix("--"), index + 1 < arguments.count else {
                throw FactoryError.message("Expected --option value arguments")
            }
            guard allowed.contains(key) || repeatable.contains(key) else {
                throw FactoryError.message("Unknown option: \(key)")
            }
            guard repeatable.contains(key) || values[key] == nil else {
                throw FactoryError.message("Duplicate option: \(key)")
            }
            values[key, default: []].append(arguments[index + 1])
            index += 2
        }
    }

    func required(_ key: String) throws -> String {
        guard let value = optional(key) else {
            throw FactoryError.message("Missing required option: \(key)")
        }
        return value
    }

    func optional(_ key: String) -> String? {
        guard let value = values[key]?.first, !value.isEmpty else { return nil }
        return value
    }

    func all(_ key: String) -> [String] { values[key] ?? [] }
}

func matches(_ value: String, _ pattern: String) -> Bool {
    value.range(of: pattern, options: .regularExpression) != nil
}

/// `<N>h` or `<N>d` as seconds, or nil for `never`. A long-lived token is
/// always an explicit choice.
func parseExpiry(_ value: String) throws -> TimeInterval? {
    if value == "never" { return nil }
    guard matches(value, "^[1-9][0-9]{0,3}[hd]$"), let amount = Double(value.dropLast()) else {
        throw FactoryError.message("--expires-in takes <N>h, <N>d, or never")
    }
    return (value.hasSuffix("d") ? amount * 24 : amount) * 3600
}

func iso8601(_ date: Date) -> String {
    let formatter = ISO8601DateFormatter()
    formatter.formatOptions = [.withInternetDateTime]
    return formatter.string(from: date)
}

func requireUserApproval(reason: String) async throws {
    let context = LAContext()
    var evaluationError: NSError?
    guard context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &evaluationError) else {
        throw FactoryError.message("Local user authentication is unavailable")
    }
    let approved = try await context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: reason)
    guard approved else { throw FactoryError.message("User rejected the request") }
}

/// A parent credential in the login keychain. The ACL trusts the binary
/// that created the item; after a rebuild macOS asks once (Always Allow).
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

    func read() throws -> Data {
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

    func write(_ data: Data) throws {
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
        try await requireUserApproval(reason: "Check whether the \(service) parent credential is available.")
        var data = try read()
        let present = !data.isEmpty
        data.resetBytes(in: 0..<data.count)
        print("keychain_service=\(service)")
        print("keychain_account=\(account)")
        print("credential_present=\(present)")
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

struct InfisicalDestination {
    let project: String
    let environment: String
    let path: String

    init(_ options: Options) throws {
        project = try options.required("--infisical-project")
        environment = try options.required("--infisical-env")
        path = try options.required("--infisical-path")
        guard matches(project, "^[0-9a-f-]{36}$"),
              matches(environment, "^[A-Za-z0-9_-]+$"),
              path.hasPrefix("/"), !path.contains("..") else {
            throw FactoryError.message("Infisical destination has an invalid shape")
        }
    }

    func label(_ secret: String) -> String {
        "Infisical \(path == "/" ? "" : path)/\(secret)"
    }

    /// Writes the value through stdin, so it never appears in argv.
    func store(_ value: String, as secret: String) throws {
        let process = Process()
        let input = Pipe()
        process.executableURL = URL(fileURLWithPath: "/opt/homebrew/bin/infisical")
        process.arguments = [
            "secrets", "set", "\(secret)=@/dev/stdin",
            "--projectId", project,
            "--env", environment,
            "--path", path,
            "--type", "shared",
            "--silent",
        ]
        process.standardInput = input
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        try process.run()
        input.fileHandleForWriting.write(Data(value.utf8))
        try input.fileHandleForWriting.close()
        process.waitUntilExit()
        guard process.terminationStatus == 0 else {
            throw FactoryError.message("Infisical CLI exited \(process.terminationStatus)")
        }
    }
}

func isSecretName(_ value: String) -> Bool { matches(value, "^[A-Z][A-Z0-9_]+$") }
