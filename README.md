# Infra token factory

`infra-token-factory` lets agents get scoped cloud credentials while you approve
each request with Touch ID. Parent credentials stay in the macOS login
Keychain. The binary never prints them.

| Provider | Mode | Keychain item (service / account) |
| --- | --- | --- |
| Cloudflare | Mint an account-owned child token into Infisical | `gondr-token.cloudflare` / `bootstrap` |
| PlanetScale | Mint a child service token into Infisical | `gondr-token.planetscale` / `<org>` |
| Hetzner Cloud | Run one approved command with `HCLOUD_TOKEN` set | `gondr-token.hetzner` / `<project>` |

Hetzner Cloud has no API to create tokens, so the factory gates each command
instead. The command can read the token. Approve only commands you trust.

## Install

Run `bin/install`. It builds the binary into
`~/.local/share/infra-token-factory/` and links it as
`~/.local/bin/infra-token-factory`.

After each install, the first use of each Keychain item makes macOS ask for
your login password. Enter it and click **Always Allow**. Later requests need
only Touch ID.

## Add a parent credential

Run these in your own terminal. Each asks for the secret with echo off, then
for Touch ID.

```sh
infra-token-factory import planetscale --org <org>
infra-token-factory import hetzner --project <label>
```

- PlanetScale parent: a service token with `write_service_tokens`,
  `read_service_tokens`, `delete_service_tokens`, and every access a child may
  get. A child can only get accesses the parent holds.
- Hetzner: a **Read & Write** API token for the project.

## Mint

```sh
infra-token-factory mint cloudflare --name <token-name> --account-id <id> \
  --account-permission <name> [--account-permission ...] \
  [--zone <zone> --zone-id <id> --zone-permission <name> ...] \
  --expires-in <N>h|<N>d|never [--allow-ip <cidr> ...] \
  --infisical-project <id> --infisical-env <env> --infisical-path <path> \
  --infisical-secret CLOUDFLARE_<CAPABILITY>_API_TOKEN

infra-token-factory mint planetscale --org <org> --name <token-name> \
  [--org-access <access> ...] [--database <db> --database-access <access> ...] \
  --expires-in <N>h|<N>d|never \
  --infisical-project <id> --infisical-env <env> --infisical-path <path> \
  --infisical-secret-prefix PLANETSCALE_<CAPABILITY>
```

- `--expires-in` is required. Use `never` only for a token that must outlive a
  rotation cycle.
- A child can never manage API tokens or service tokens.
- PlanetScale writes `<prefix>_SERVICE_TOKEN_ID` and `<prefix>_SERVICE_TOKEN`.
- If a grant, check, or vault write fails, the factory deletes the child.

## Revoke

```sh
infra-token-factory revoke cloudflare --name <token-name> --account-id <id>
infra-token-factory revoke planetscale --org <org> --name <token-name>
```

Each deletes the one token with that exact name. It fails if no token or
several tokens have that name. It does not delete the Infisical secrets.

## Run a Hetzner command

```sh
infra-token-factory exec hetzner --project <label> -- <command> [args...]
```

## Check a parent credential

```sh
infra-token-factory check cloudflare
infra-token-factory check planetscale --org <org>
infra-token-factory check hetzner --project <label>
```

Each reports presence only.
