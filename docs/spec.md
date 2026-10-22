# gondr behavior contract

This file is the contract for `gondr`. The tests derive from it, not from the code.
Each `F` item names a failure that a test must catch.

## Scope

`gondr` lets coding agents use secrets without seeing their values. It has two backends:

- Infisical: the secret store. Commands `run`, `ls`, `where`, `need`, `set`.
- Infisical Agent Vault: a credential proxy. Commands `agent` and `onboard`.

`gondr` never asks Infisical for a secret value. Every secrets read sends
`viewSecretValue=false`. The one exception is `onboard`, which compares values as
SHA-256 hashes inside a child `infisical run` process and prints no value.

## Config

- File: `$GONDR_CONFIG` if set, else `$XDG_CONFIG_HOME/gondr/config.toml`, else
  `~/.config/gondr/config.toml`. TOML.
- A missing config file stops every command with exit 1 and a hint that names the path.
- `~` in a path value expands to the home directory.

```toml
[infisical]
url = "https://eu.infisical.com"        # required
project = "<project id>"                 # used when the repo has no .infisical.json
environments = ["dev", "staging", "prod"] # default ["dev", "staging", "prod"]
default_environment = "dev"               # default "dev"
warn_environments = ["prod"]              # default ["prod"]

[infisical.credentials]                   # machine identity (Universal Auth)
source = "keychain"                       # "keychain" or "env"
keychain_account = "gondr"
client_id_service = "infisical-client-id"
client_secret_service = "infisical-client-secret"

[layout]
repos_root = "~/repos"   # local folder that maps to `prefix`
prefix = "/repos"        # Infisical folder for repos
shared = "/shared"       # Infisical folder for shared owners

[agent_vault]
binary = "agent-vault"
address = "http://broker:14321"
default_vault = "shared"
grant_agents = ["my-agent"]
references_folder = "agent-vault"
token = { source = "keychain", account = "my-agent", service = "agent-vault-token" }
# token = { source = "env", name = "AGENT_VAULT_TOKEN" }

[services.github]            # extra fields fill from `agent-vault catalog --json`
hosts = ["api.github.com"]
auth = "bearer"              # "bearer" or "api-key"
header = "x-api-key"         # api-key only
key = "GITHUB_PAT"
shared = "${dev.shared.GITHUB_PAT}"
project_keys = ["GITHUB_PAT", "GITHUB_TOKEN"]

[[boundary]]
name = "Acme"
dir = "~/repos/acme"
prefix = "/repos/acme"
shared = "/repos/acme/tooling"
vault_prefix = "acme"
deny_agents = ["some-agent"]
```

- With `source = "env"`, the identity comes from `INFISICAL_UNIVERSAL_AUTH_CLIENT_ID`
  and `INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET`.
- The `[agent_vault]` table is needed only by `agent` and `onboard`.

## Repo folder

- The repo root is the parent of `git rev-parse --path-format=absolute --git-common-dir`.
  A linked worktree therefore maps to its main checkout.
- Outside Git, the repo root is the nearest folder with `.infisical.json`.
- The repo folder is `prefix` + the repo root relative to `repos_root`.
- The project is `workspaceId` from `<repo root>/.infisical.json`, else `infisical.project`.
- An explicit `--path` (or `ls <path>`) replaces the repo folder.

## Boundaries

A boundary keeps one set of secrets with one set of directories.

- "Inside B": the working directory or the repo root is under `B.dir`.
- "Path in B": the path equals `B.prefix` or starts with `B.prefix/`.
- A path in B, used from outside B, stops the command.
- A path not in B, used from inside B, stops the command.
- The error names the boundary (`B.name`).
- A boundary stop happens before any Keychain read, login, HTTP request or exec.
- `where` lists only owners that are in the current boundary (or in no boundary, outside every boundary).
- `need` looks for owners under `B.shared` inside B, else under `layout.shared`.
  It never treats `<layout.shared>/<references_folder>` as an owner.

## Commands

### `gondr ls [--env E] [path]`

- Prints `<env>:<path>`, then `  keys (N): <sorted names>`, one `  import <src> (N): <sorted names>`
  line per import, and `  folders: <sorted names>` when there are subfolders.
- One `GET /api/v4/secrets` with `projectId`, `environment`, exact `secretPath`,
  `includeImports=true`, `viewSecretValue=false`, `expandSecretReferences=false`, no `recursive=true`.
- One `GET /api/v2/folders` with `projectId`, `environment`, `path`.

### `gondr where <KEY> [--env E]`

- Prints `<env>:<folder> <KEY>` per owner, with `  imported by: <folders>` when other folders import it.
- Makes no state-changing request.
- A missing key exits 1 and prints no owner line.

### `gondr need <KEY> [--path P] [--from F] [--env E]`

- Default env is `default_environment`.
- If the key already reaches the folder (own or imported), prints `<KEY> already reaches <env>:<path>`
  and makes no write.
- Else creates one import with `POST /api/v2/secret-imports`, body
  `{projectId, environment, path, import: {environment, path}}`, and prints
  `imported <env>:<owner> into <env>:<path>`.
- No owner, or more than one owner without `--from`: exit 1.
- `--from F` passes the boundary check like a path.

### `gondr set <KEY> [--path P] [--env E]`

- Reads the value from stdin. A terminal on stdin, or an empty value: exit 1.
- The value is stored byte for byte as read (no newline trimming).
- `KEY` must match `^[A-Z][A-Z0-9_]*$`.
- The path must start with `layout.prefix/` or `layout.shared/` (or a boundary prefix) and have no
  empty, `.` or `..` segment.
- `GET /api/v4/secrets/<KEY>` with `viewSecretValue=false`: 200 → `PATCH`, 404 → `POST` with
  `secretComment`. Both send `{projectId, environment, secretPath, secretValue, skipMultilineEncoding: true, type: "shared"}`.
- Prints `created <KEY> in <env>:<path>` or `updated <KEY> in <env>:<path>`. Never the value.

### `gondr run [--env E] [--path P] -- <cmd...>`

- Execs `infisical run --domain=<url>/api --projectId=<id> --env=<E> --path=<P> --silent -- env -u INFISICAL_TOKEN <cmd...>`.
- The exec environment holds `INFISICAL_TOKEN` (the machine identity access token) and the inherited env.
- `<cmd...>` stays intact, including spaces and arguments that look like flags.

### `gondr agent [--vault V] <cmd...>`

- Vault: `--vault`, else `vault` from the nearest `agent-vault.json` between the working directory
  and the repo root, else `agent_vault.default_vault`.
- Inside boundary B, the vault must start with `B.vault_prefix`. Outside every boundary, a vault
  must not start with any boundary's `vault_prefix`. A stop exits 77.
- If the vault starts with `B.vault_prefix` and the command's basename is in `B.deny_agents`: exit 77.
- Execs `<binary> run --vault V -- /bin/sh -c '<append Infisical host to NO_PROXY and no_proxy>; exec "$@"' sh <cmd...>`
  with `AGENT_VAULT_ADDR`, `AGENT_VAULT_TOKEN`, `AGENT_VAULT_VAULT`, `AGENT_VAULT_TELEMETRY=false`,
  and `HOME` set to a gondr state folder for the broker CLI. The child gets the real `HOME` back.
- The agent token never appears in argv or output.

### `gondr onboard <folder> --admin-home DIR [--repo-dir DIR] [--vault NAME] [--services a,b] [--dry-run]`

- Default vault name: the folder below `layout.prefix`, with `/` replaced by `-`, plus `-<default_environment>`.
- A folder in any boundary: exit 1.
- For each service, the reference is the repo's own key unless its value hash equals the shared
  value's hash; then the shared reference wins. A service with neither: `skip <name>`.
- `--dry-run` prints `plan <service>: <hosts> <- <key> (<source>)` lines and writes nothing.
- Otherwise: create folder `<folder>/<references_folder>`, publish each reference as in `set`,
  create the vault on the `infisical` credential store if missing, grant `grant_agents`, add services,
  set `unmatched_host_policy=passthrough`, sync, and write `agent-vault.json` when `--repo-dir` is given.

## Errors

- Any HTTP error prints `gondr: <METHOD> <path without query> -> HTTP <code>` and exits 1.
  It never prints a response body, a token, a client secret or a value.
- A network error prints `gondr: <METHOD> <path> -> <reason>` and exits 1, with no traceback.
- Every request sends `User-Agent: gondr/<version>`.

## Failure list

- F01 A secrets read omits `viewSecretValue=false` or `expandSecretReferences=false`.
- F02 Output contains a value, token, client secret or response body, even when the API wrongly returns a value.
- F03 `ls` uses `recursive=true` or the wrong `secretPath`/`environment`.
- F04 `where` writes, or reports an owner for a missing key.
- F05 `need` creates a second import when one exists, or imports when the key is local.
- F06 A boundary violation reaches Keychain, login, HTTP or exec.
- F07 A boundary stop does not name the boundary.
- F08 A linked worktree whose main checkout is inside a boundary escapes it.
- F09 `set` prints the value, trims it, or accepts an empty value or a bad key or path.
- F10 `set` uses POST when the secret exists, or PATCH when it does not.
- F11 `run` changes the child argv or leaks `INFISICAL_TOKEN` to the child.
- F12 `.infisical.json` `workspaceId` does not replace the config project.
- F13 `env` credentials are ignored, or Keychain is read when `source = "env"`.
- F14 A missing config file gives a traceback instead of a hint.
- F15 `agent` picks the wrong vault (nearest `agent-vault.json`, stop at repo root).
- F16 `agent` runs a denied agent on a boundary vault, or a boundary directory on a non-boundary vault.
- F17 `agent` puts the agent token in argv or output.
- F18 An HTTP or network error prints a traceback or a body.
- F19 `onboard --dry-run` writes anything.
- F20 `onboard` uses the project key when its hash equals the shared hash.
- F21 A `[services.X]` entry without hosts or auth does not fill from the catalog.
- F22 An unknown `--env` passes.
