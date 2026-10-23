import Foundation

enum FactoryError: Error, CustomStringConvertible {
    case message(String)

    var description: String {
        switch self { case let .message(message): message }
    }
}

private let usage = """
Usage (mint, revoke and exec also need --reason "<why>", before any --):
  infra-token-factory mint cloudflare <options>
  infra-token-factory revoke cloudflare --name <token-name> --account-id <id>
  infra-token-factory mint planetscale <options>
  infra-token-factory revoke planetscale --org <org> --name <token-name>
  infra-token-factory exec planetscale --org <org> [--org-access <a>] [--database <db> --database-access <a>] --expires-in <N>h -- <command>
  infra-token-factory mint fly <options>
  infra-token-factory exec fly --org <org> -- <command> [args...]
  infra-token-factory mint tailscale <options>
  infra-token-factory revoke tailscale --tailnet <label> --name <key-name>
  infra-token-factory exec tailscale --tailnet <label> --scope <scope> [--scope ...] -- <command> [args...]
  infra-token-factory mint openrouter <options>
  infra-token-factory revoke openrouter --account <label> (--name <key-name> | --hash <h> ...)
  infra-token-factory list openrouter --account <label>
  infra-token-factory revoke openrouter-workspace --account <label> --slug <slug>
  infra-token-factory create openrouter-workspace --account <label> --slug <slug> --name <name> [--monthly-budget-usd <N>]
  infra-token-factory mint gitlab-deploy <options>
  infra-token-factory revoke gitlab-deploy --account <label> --project <group/project> --name <name>
  infra-token-factory exec gitlab --account <label> -- <command> [args...]
  infra-token-factory exec github --app <label> --owner <login> --repo <name> --permission <name>:<read|write> -- <command>
  infra-token-factory exec hetzner --project <label> -- <command> [args...]
  infra-token-factory import planetscale --org <org>
  infra-token-factory import hetzner --project <label>
  infra-token-factory import fly --org <org>
  infra-token-factory import tailscale --tailnet <label>
  infra-token-factory import openrouter --account <label>
  infra-token-factory import gitlab --account <label>
  infra-token-factory import github --app <label> --app-id <id> --key-file <path.pem>
  infra-token-factory check cloudflare
  infra-token-factory check planetscale --org <org>
  infra-token-factory check hetzner --project <label>
  infra-token-factory check fly --org <org>
  infra-token-factory check tailscale --tailnet <label>
  infra-token-factory check openrouter --account <label>
  infra-token-factory check gitlab --account <label>
  infra-token-factory check github --app <label>
"""

@main
struct InfraTokenFactory {
    static func main() async {
        let values = Array(CommandLine.arguments.dropFirst())
        do {
            guard values.count >= 2 else { throw FactoryError.message(usage) }
            let (rest, reason) = try takeReason(Array(values.dropFirst(2)))
            guard reason != nil || !["mint", "revoke", "exec", "create"].contains(values[0]) else {
                throw FactoryError.message(#"\#(values[0]) needs --reason "<why you need it>""#)
            }
            Request.reason = reason
            switch (values[0], values[1]) {
            case ("mint", "cloudflare"): try await Cloudflare.mint(rest)
            case ("revoke", "cloudflare"): try await Cloudflare.revoke(rest)
            case ("check", "cloudflare"): try await Cloudflare.check(rest)
            case ("mint", "planetscale"): try await PlanetScale.mint(rest)
            case ("revoke", "planetscale"): try await PlanetScale.revoke(rest)
            case ("exec", "planetscale"): try await PlanetScale.exec(rest)
            case ("import", "planetscale"): try await PlanetScale.importParent(rest)
            case ("check", "planetscale"): try await PlanetScale.check(rest)
            case ("exec", "hetzner"): try await Hetzner.exec(rest)
            case ("import", "hetzner"): try await Hetzner.importParent(rest)
            case ("check", "hetzner"): try await Hetzner.check(rest)
            case ("mint", "fly"): try await Fly.mint(rest)
            case ("exec", "fly"): try await Fly.exec(rest)
            case ("import", "fly"): try await Fly.importParent(rest)
            case ("check", "fly"): try await Fly.check(rest)
            case ("mint", "tailscale"): try await Tailscale.mint(rest)
            case ("revoke", "tailscale"): try await Tailscale.revoke(rest)
            case ("exec", "tailscale"): try await Tailscale.exec(rest)
            case ("import", "tailscale"): try await Tailscale.importParent(rest)
            case ("check", "tailscale"): try await Tailscale.check(rest)
            case ("mint", "openrouter"): try await OpenRouter.mint(rest)
            case ("revoke", "openrouter"): try await OpenRouter.revoke(rest)
            case ("import", "openrouter"): try await OpenRouter.importParent(rest)
            case ("check", "openrouter"): try await OpenRouter.check(rest)
            case ("list", "openrouter"): try await OpenRouter.list(rest)
            case ("create", "openrouter-workspace"): try await OpenRouter.createWorkspace(rest)
            case ("revoke", "openrouter-workspace"): try await OpenRouter.revokeWorkspace(rest)
            case ("mint", "gitlab-deploy"): try await GitLab.mintDeploy(rest)
            case ("revoke", "gitlab-deploy"): try await GitLab.revokeDeploy(rest)
            case ("exec", "gitlab"): try await GitLab.exec(rest)
            case ("import", "gitlab"): try await GitLab.importParent(rest)
            case ("check", "gitlab"): try await GitLab.check(rest)
            case ("exec", "github"): try await GitHub.exec(rest)
            case ("import", "github"): try await GitHub.importParent(rest)
            case ("check", "github"): try await GitHub.check(rest)
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
