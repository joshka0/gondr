# Infra token factory

`infra-token-factory` lets agents get scoped cloud credentials while you approve
each request with Touch ID. Parent credentials stay in the macOS login
Keychain. The binary never prints them.

| Provider | Mode | Keychain item (service / account) |
| --- | --- | --- |
| Cloudflare | Mint an account-owned child token into Infisical | `gondr-token.cloudflare` / `bootstrap` |
| PlanetScale | Mint a child service token into Infisical | `gondr-token.planetscale` / `<org>` |
| Hetzner Cloud | Run one approved command with `HCLOUD_TOKEN` set | `gondr-token.hetzner` / `<project>` |
| Fly.io | Mint an app-scoped child into Infisical, or run one approved command with `FLY_API_TOKEN` (org token) | `gondr-token.fly` / `<org>` |
| Tailscale | Mint a tagged auth key into Infisical | `gondr-token.tailscale` / `<tailnet>` |
| OpenRouter | Mint an API key with a credit limit into Infisical | `gondr-token.openrouter` / `<account>` |
| GitLab.com | Mint a project deploy token into Infisical, or run one approved command with `GITLAB_TOKEN` (the PAT) | `gondr-token.gitlab` / `<account>` |
| GitHub | Run one approved command with a 1-hour installation token (`GH_TOKEN`) limited to named repos and permissions | `gondr-token.github` / `<app>` |

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
infra-token-factory import fly --org <org>
infra-token-factory import tailscale --tailnet <label>
infra-token-factory import openrouter --account <label>
infra-token-factory import gitlab --account <label>
infra-token-factory import github --app <label> --app-id <id> --key-file <path.pem>
```

- PlanetScale parent: a service token with `write_service_tokens`,
  `read_service_tokens`, `delete_service_tokens`, and every access a child may
  get. A child can only get accesses the parent holds.
- Hetzner: a **Read & Write** API token for the project.
- Fly: an org token, `fly tokens create org --name infra-token-factory --expiry 8760h`.
  `--org` is the org slug from `fly orgs list` (for a personal org, `personal`).
- OpenRouter: a management key from https://openrouter.ai/settings/management-keys,
  with an expiry. It can manage every key in the account, so keep it here only.
- GitLab: a personal access token with the `api` scope and an expiry. On
  GitLab.com Free a PAT cannot mint scoped access tokens (those need Premium),
  so the factory mints deploy tokens and gates other use behind `exec gitlab`.
- GitHub: a GitHub App with only the permissions agents may get, installed on
  the repositories they may touch. Import reads the downloaded PKCS#1 `.pem`
  once; delete the file afterwards.
- Tailscale: an OAuth client with the `auth_keys` scope that owns the tags keys
  may carry. Import asks for the client ID, then the `tskey-client-` secret.

## Mint

```sh
infra-token-factory mint cloudflare --name <token-name> --account-id <id> \
  --account-permission <name> [--account-permission ...] \
  [--zone <zone> --zone-id <id> --zone-permission <name> ...] \
  [--r2-bucket <bucket> ... --bucket-permission <name> ... [--r2-jurisdiction default|eu|fedramp]] \
  --expires-in <N>h|<N>d|never [--allow-ip <cidr> ...] \
  --infisical-project <id> --infisical-env <env> --infisical-path <path> \
  --infisical-secret CLOUDFLARE_<CAPABILITY>_API_TOKEN [--r2-s3-secret-prefix <PREFIX>]

infra-token-factory mint planetscale --org <org> --name <token-name> \
  [--org-access <access> ...] [--database <db> --database-access <access> ...] \
  --expires-in <N>h|<N>d|never \
  --infisical-project <id> --infisical-env <env> --infisical-path <path> \
  --infisical-secret-prefix PLANETSCALE_<CAPABILITY>

infra-token-factory mint fly --org <org> --app <app> \
  --expires-in <N>h|<N>d \
  --infisical-project <id> --infisical-env <env> --infisical-path <path> \
  --infisical-secret FLY_<APP>_DEPLOY_TOKEN

infra-token-factory mint tailscale --tailnet <label> --name <key-name> \
  --tag tag:<name> [--tag ...] [--with ephemeral|reusable|preauthorized ...] \
  --expires-in <N>h|<N>d \
  --infisical-project <id> --infisical-env <env> --infisical-path <path> \
  --infisical-secret TS_AUTHKEY_<CAPABILITY>

infra-token-factory mint openrouter --account <label> --name <key-name> \
  --limit-usd <amount> --reset daily|weekly|monthly|never --expires-in <N>d \
  --infisical-project <id> --infisical-env <env> --infisical-path <path> \
  --infisical-secret OPENROUTER_<APP>_API_KEY

infra-token-factory mint gitlab-deploy --account <label> --project <group/project> \
  --name <token-name> --scope read_repository|read_registry|write_registry|... \
  --expires-in <N>d \
  --infisical-project <id> --infisical-env <env> --infisical-path <path> \
  --infisical-secret-prefix GITLAB_<PURPOSE>_DEPLOY
```

- `--expires-in` is required. Use `never` only for a token that must outlive a
  rotation cycle.
- A child can never manage API tokens or service tokens.
- `--r2-bucket` limits bucket permissions (for example
  `Workers R2 Storage Bucket Item Write`) to the named buckets.
- `--r2-s3-secret-prefix` also writes R2 S3 keys: `<PREFIX>_ACCESS_KEY_ID` (the
  token ID) and `<PREFIX>_SECRET_ACCESS_KEY` (the SHA-256 hex of the token).
- A Fly child is the org token attenuated offline (`fly tokens attenuate`): all
  actions on one existing app, read-only on the rest of the org, and a validity
  window of 30 days or less. Fly does not let an org token create tokens
  through its API. A child cannot be revoked alone; revoking the parent revokes
  every child. Creating an app needs `exec fly`.
- A Tailscale key must carry tags the OAuth client owns, and expires in 90 days
  or less.
- An OpenRouter key's limit is its budget: at most $100 per reset period.
  OpenRouter refuses requests once it is spent, until the reset.
- PlanetScale writes `<prefix>_SERVICE_TOKEN_ID` and `<prefix>_SERVICE_TOKEN`.
- If a grant, check, or vault write fails, the factory deletes the child.

## Revoke

```sh
infra-token-factory revoke cloudflare --name <token-name> --account-id <id>
infra-token-factory revoke planetscale --org <org> --name <token-name>
infra-token-factory revoke tailscale --tailnet <label> --name <key-name>
infra-token-factory revoke openrouter --account <label> --name <key-name>
infra-token-factory revoke gitlab-deploy --account <label> --project <group/project> --name <token-name>
```

Each deletes the one token with that exact name. It fails if no token or
several tokens have that name. It does not delete the Infisical secrets.

## Run a command with a parent

```sh
infra-token-factory exec hetzner --project <label> -- <command> [args...]
infra-token-factory exec fly --org <org> -- <command> [args...]
infra-token-factory exec gitlab --account <label> -- <command> [args...]
infra-token-factory exec github --app <label> --owner <login> --repo <name> \
  --permission contents:write [--permission ...] -- <command> [args...]
```

The command gets the parent in `HCLOUD_TOKEN` or `FLY_API_TOKEN`. It can read
it. Approve only commands you trust.

## Check a parent credential

```sh
infra-token-factory check cloudflare
infra-token-factory check planetscale --org <org>
infra-token-factory check hetzner --project <label>
infra-token-factory check fly --org <org>
infra-token-factory check tailscale --tailnet <label>
infra-token-factory check openrouter --account <label>
infra-token-factory check gitlab --account <label>
infra-token-factory check github --app <label>
```

Each reports presence only.
