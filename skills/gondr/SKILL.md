---
name: gondr
description: "Use, store, or mint secrets and cloud credentials without seeing values via gondr (Infisical, proxy, gondr token). Use for secrets, infra access, or 401/403 tokens. Not for Infisical docs."
---

# gondr

`gondr` keeps secret values out of your context. It prints key names, never values. `gondr --help` lists every command. Every command defaults to `--env dev`; use `--env prod` only for a deploy or release step.

## Find and use a secret

- `gondr status`: this repo's Infisical folder, keys, imports, and Agent Vault vault.
- `gondr find <what>` (a key, service, or host): prints the route. Follow it:
  - `proxied`: call the host directly and send no auth header. The proxy adds the key only when `gondr status` prints `proxied here: yes`. If it prints `no`, run the call through `gondr agent <cmd>` or `agent-vault-run <vault> -- <cmd>` (`agent-vault` skill), using the vault `gondr status` names.
  - `env`: run the command with `gondr run -- <cmd>`.
  - `import`: run the printed `gondr need <KEY>` command (passing `--from <folder>` if several shared folders hold it), then `gondr run`.
  - `repo-owned`, `not-mapped`, or `missing`: stop that step. Give the operator the line `gondr` printed, word for word.
- A cloud token is missing, rejected (`401`, bad or missing key), or too narrow (`403`, missing permission): run `gondr token check <provider>` first. If the factory has the provider, mint a child ("Get a cloud credential" below). Ask only when the factory lacks the provider or the mint fails.
- `gondr check`: which names in `.env.example` are missing.
- `find` and `check` exit 1 when they report a gap. That is a result, not a failure of `gondr`.
- `gondr ls [path]`, `gondr where <KEY>`: key names, imports, and owner folders.
- `gondr run -- <cmd>` injects the folder's secrets.

## Store a value

- Pipe it: `printf %s "$VALUE" | gondr set <KEY>`.
- A new repo has no Infisical folder: `set` and `need` create it. Do not create it by hand.
- Store a shared value once: `printf %s "$VALUE" | gondr set <KEY> --path <shared folder>` (`gondr ls /shared` lists shared folders). Then run `gondr need <KEY>` in each repo. Never copy a value.

## Get a cloud credential: `gondr token` (macOS)

`gondr token` runs the macOS token factory. It holds parent credentials in the login Keychain. The operator approves each request with Touch ID (or a YubiKey touch if sealed). You never see a parent, except that `exec hetzner`, `exec fly`, and `exec gitlab` start your command with a parent in its environment.

Every `mint`, `revoke`, `exec`, and `create` requires `--reason "<why, for which task>"` (one line, 3 to 200 characters) placed before any `--`. The approval prompt shows it. The table rows below omit `--reason`.

| Provider | Command | Result |
| --- | --- | --- |
| Cloudflare | `mint cloudflare` / `revoke cloudflare` | Account-owned child token in Infisical |
| PlanetScale | `exec planetscale --org <org> ... --expires-in 1h -- pscale ...`; `mint planetscale` only for a service that needs a standing token | `exec`: one command with a child token, deleted on exit. `mint`: `<prefix>_SERVICE_TOKEN_ID` and `<prefix>_SERVICE_TOKEN` |
| Hetzner Cloud | `exec hetzner --project <label> -- <command>` | One command with `HCLOUD_TOKEN` |
| Fly.io | `mint fly`; `exec fly --org <org> -- <command>` | App-scoped child (30 days or less); or one command with the org token |
| Tailscale | `mint tailscale` / `revoke tailscale`; `exec tailscale --tailnet <label> --scope <scope> -- <command>` | Tagged auth key; or one command with a 1-hour API token limited to the scopes |
| OpenRouter | `create openrouter-workspace` / `mint openrouter` / `revoke openrouter`; `list openrouter` | Workspace or API key with a USD credit limit |
| GitLab.com | `mint gitlab-deploy` / `revoke gitlab-deploy`; `exec gitlab --account <label> -- <command>` | Project deploy token; or one command with the PAT |
| GitHub | `exec github --app <label> --owner <login> --repo <r> --permission contents:write -- <command>` | One command with a 1-hour installation token, never stored |

Run `gondr token check help` to print the factory's usage lines. The `<org>`, `<label>`, and `<account>` values are set per machine (on this machine, see `local-dev/references/secrets.md`, **Token factory on this machine**).

### Run it

- Run `gondr token` on the operator's Mac with a timeout of 10 minutes or more. If your shell is sandboxed and blocks Keychain or Touch ID, give the operator the exact command to run. Say in chat that a Touch ID prompt waits before you start. If the operator is away (AFK), do not start it: park the step.
- `mint` stores into this repo's folder (the one `gondr status` shows). Name each secret with `--secret <KEY>` (or `--secret-prefix`). Use `--env` and `--path` as in `gondr set`. `gondr` checks the folder and boundary before the prompt.
- Preflight: `gondr token check <provider> [--org | --project | --tailnet | --account | --app <label>]`. It reports presence and seal status only.
- Missing parent: the operator runs `gondr token import <provider> ...` in their own terminal. Never pipe a secret into it.
- `mint` and `exec planetscale` require `--expires-in <N>h` or `<N>d` (`exec planetscale`: 24h or less). Task tokens: `7d` or less. Use `never` only when the operator asks. The other `exec` commands take no `--expires-in`.
- `revoke` leaves the stored Infisical secret. Give the operator the key name and folder to delete, or overwrite it separately with `gondr set`.

### Self-service flow

1. Test an existing child against the exact endpoints first. Mint only when none exists, its scope is wrong, or you need isolation. Never widen an unrelated child.
2. Pick the smallest scope.
3. Mint into the repo's folder.
4. Use the child through `gondr run`. Use the proxy only when `gondr find <host>` prints `proxied`.
5. Declare lasting resources in the repo's infrastructure code so they are reviewed and torn down with it.
6. Test each endpoint by status code. Never print response bodies:
   `gondr run -- sh -c 'curl -s -o /dev/null -w "%{http_code}\n" -H "Authorization: Bearer $KEY" <url>'` (single quotes keep the value off your command line).

### Provider notes

- Fly: a child cannot be revoked alone, so keep `--expires-in` short. `--org` is the slug, not the display name. Creating an app needs `exec fly`.
- Tailscale: a key must carry tags the OAuth client owns. Prefer `--with ephemeral --with preauthorized` for short-lived machines. Ask for `:read` scopes unless the command writes.
- GitLab.com Free cannot mint scoped access tokens from a PAT. Use deploy tokens for repo and registry access, and `exec gitlab` for API work.
- GitHub: the App's installation caps every token. `--permission` only narrows it.
- Hetzner tokens cannot be minted. `exec hetzner`, `exec fly`, and `exec gitlab` hand the command a parent: show the operator the exact command, and never pass one that prints or stores the token.
- Cloudflare R2 for one bucket: `--r2-bucket <bucket> --bucket-permission "Workers R2 Storage Bucket Item Write" --r2-s3-secret-prefix <PREFIX>`. The factory stores the S3 key pair. Never derive it yourself.
- Cloudflare account tokens: verify at `/accounts/<id>/tokens/verify` (not `/user/tokens/verify`), and revoke with `gondr token revoke cloudflare`.
- Cloudflare `--zone '*'`: operator-approved one-off jobs only (24h max); revoke the child afterwards. Through a proxy, `--allow-ip` needs both its IPv4 and IPv6 egress addresses (`agent-vault` skill lists them).
- PlanetScale: a service token cannot approve its own deploy request. Never grant `approve_deploy_request` or production deletes by default.

## Never

- Read `.env` files, print the environment, or put a value in a command line.
- Print, copy, or persist a parent or child credential, or a URL that carries one.
- Read the Keychain from a shell.
- Work around a boundary refusal with another directory, another `--path`, or another vault.
- Continue past an interactive login, MFA, or credential prompt. Name the exact operator action.
