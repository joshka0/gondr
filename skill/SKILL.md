---
name: gondr
description: "Use secrets and cloud credentials without seeing their values: gondr finds the repo's Infisical folder, runs commands with its secrets, stores values from stdin, and mints Touch ID-approved scoped tokens (gondr token). Use when a task needs a secret, an API key, or infra access."
---

# gondr

`gondr` keeps secret values out of your context. It prints key names, never values. `gondr --help` lists every command.
The repo's README explains setup. `docs/cookbook.md` explains the pattern without gondr.

## Find and use a secret

- `gondr status`: this repo's Infisical folder, keys, imports and Agent Vault vault.
- `gondr find <what>` (a key, service or host): prints the route. Follow it:
  - `proxied`: call the host directly. The proxy adds the key. Send no auth header.
  - `env`: run the command with `gondr run -- <cmd>`.
  - `import`: run `gondr need <KEY>`, then `gondr run`.
  - `repo-owned`, `not-mapped` or `missing`: stop that step. Give the operator the printed command.
- `gondr check`: which names in `.env.example` are missing.
- `gondr ls [path]`, `gondr where <KEY>`: key names, imports and owner folders.
- `gondr run -- <cmd>` injects the folder's secrets. Use `--env prod` only for a deploy or release step.

## Store a value

- Pipe it: `printf %s "$VALUE" | gondr set <KEY>`. Without `--env`, it writes `dev`.
- A new repo has no Infisical folder: `set` and `need` create it. Do not create it by hand.
- Store a shared value once under the shared root. Import it with `gondr need <KEY>`. Never copy a value.

## Get a cloud credential: `gondr token` (macOS)

`gondr token` runs the token factory (`factory/`). It holds parent credentials in the login Keychain. The operator approves each request with Touch ID. You never see a parent.

| Provider | Command | Result |
| --- | --- | --- |
| Cloudflare | `mint cloudflare` / `revoke cloudflare` | Account-owned child token in Infisical |
| PlanetScale | `exec planetscale --org <org> ... --expires-in 1h -- pscale ...`; `mint planetscale` only for a service that needs a standing token | `exec`: one command with a child token, deleted on exit. `mint`: `<prefix>_SERVICE_TOKEN_ID` and `<prefix>_SERVICE_TOKEN` |
| Hetzner Cloud | `exec hetzner --project <label> -- <command>` | One command with `HCLOUD_TOKEN` |
| Fly.io | `mint fly`; `exec fly --org <org> -- <command>` | App-scoped child (30 days or less); or one command with the org token |
| Tailscale | `mint tailscale` / `revoke tailscale`; `exec tailscale --tailnet <label> --scope <scope> -- <command>` | Tagged auth key; or one command with a 1-hour API token limited to the scopes |
| OpenRouter | `mint openrouter` / `revoke openrouter`; `list openrouter` | API key with a USD credit limit |
| GitLab.com | `mint gitlab-deploy` / `revoke gitlab-deploy`; `exec gitlab --account <label> -- <command>` | Project deploy token; or one command with the PAT |
| GitHub | `exec github --app <label> --owner <login> --repo <r> --permission contents:write -- <command>` | One command with a 1-hour installation token, never stored |

`factory/README.md` lists every flag.

### Run it

- Run on the operator's Mac, outside a sandbox that blocks Keychain or Touch ID. Use a timeout of 10 minutes or more, and tell the operator a Touch ID prompt waits.
- Give `mint`, `revoke`, `exec` and `create` a `--reason "<why, for which task>"`. The Touch ID dialog shows it.
- `mint` stores into this repo's folder (the one `gondr status` shows). Name each secret with `--secret <KEY>` (or `--secret-prefix`). Use `--env` and `--path` as in `gondr set`. gondr checks the folder and the boundary before the prompt.
- Preflight: `gondr token check <provider> [--org | --project | --tailnet <label>]`. It reports presence and reachability only.
- Missing parent: the operator runs `gondr token import <provider> ...` in their own terminal. Never pipe a secret into it.
- `--expires-in` is required. Task tokens: `7d` or less. `never` only on the operator's request.
- `revoke` leaves the stored Infisical secret. Overwrite or delete it separately.

### Self-service flow

1. Test an existing child against the exact endpoints first. Mint only when none exists, its scope is wrong, or you need isolation. Never widen an unrelated child.
2. Pick the smallest scope.
3. Mint into the repo's folder.
4. Use the child through `gondr run` or the Agent Vault proxy.
5. Declare lasting resources in the repo's infrastructure code, so they are reviewed and torn down with it.
6. Test each endpoint by status code. Never print response bodies.

### Provider notes

- Fly: a child cannot be revoked alone, so keep `--expires-in` short. `--org` is the slug, not the display name. Creating an app needs `exec fly`.
- Tailscale: a key must carry tags the OAuth client owns. Prefer `--with ephemeral --with preauthorized` for short-lived machines. Ask for `:read` scopes unless the command writes.
- GitLab.com Free cannot mint scoped access tokens from a PAT. Use deploy tokens for repo and registry access, and `exec gitlab` for API work.
- GitHub: the App's installation caps every token. `--permission` only narrows it.
- Hetzner tokens cannot be minted. `exec hetzner` and `exec fly` hand the command a parent: show the operator the exact command, and never pass one that prints or stores the token.
- Cloudflare R2 for one bucket: `--r2-bucket <bucket> --bucket-permission "Workers R2 Storage Bucket Item Write" --r2-s3-secret-prefix <PREFIX>`. The factory stores the S3 key pair. Never derive it yourself.
- Cloudflare: verify and revoke an account token through the account endpoints. `--zone '*'` is for an operator-approved one-off job only; revoke the child afterwards. Through a proxy, `--allow-ip` needs both its IPv4 and IPv6 egress addresses.
- PlanetScale: a service token cannot approve its own deploy request. Never grant `approve_deploy_request` or production deletes by default.

## Never

- Read `.env` files, print the environment, or put a value in a command line.
- Print, copy or persist a parent or child credential, or a URL that carries one.
- Read the Keychain from a shell.
- Continue past an interactive login, MFA or a credential prompt. Name the exact operator action.
