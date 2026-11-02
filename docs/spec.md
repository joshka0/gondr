# gondr behavior contract

This file is the contract for `gondr`. The tests derive from it, not from the code.
Each `F` item names a failure that a test must catch.

## Scope

`gondr` lets coding agents use secrets without seeing their values. It has two backends:

- Infisical: the secret store. Commands `run`, `ls`, `where`, `need`, `set`.
- Infisical Agent Vault: a credential proxy. Commands `agent` and `onboard`.
- Discovery for agents: `status`, `find`, `check`.

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
service_roots = []      # extra write roots for deployed services, e.g. ["/services"]; default []

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
allow_vaults = ["shared"]   # other vaults a boundary directory may use; default []
deny_agents = ["some-agent"]
```

- With `source = "env"`, the identity comes from `INFISICAL_UNIVERSAL_AUTH_CLIENT_ID`
  and `INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET`.
- The `[agent_vault]` table is needed only by `agent` and `onboard`.

## Repo folder

- The repo root is the parent of `git rev-parse --path-format=absolute --git-common-dir`.
  A linked worktree therefore maps to its main checkout.
- Outside Git, the repo root is the nearest folder with `.infisical.json`.
- A `[folders]` table maps local directories to folders (`"~/repos/acme/web-v2" = "/repos/acme/web"`).
  When the repo root is under one or more of them, the longest match is the repo folder.
- Else the repo folder is `prefix` + the repo root relative to `repos_root`.
- A mapped folder passes the boundary check like any other path.
- The project is `workspaceId` from `<repo root>/.infisical.json`, else `infisical.project`.
- An explicit `--path` (or `ls <path>`, `--from`, the `onboard` folder) replaces the repo folder.
  It must start with `/`; a relative path stops the command with exit 1.

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

- Prints `<env>:<folder> <KEY>` per owner, with `  imported by: <folders>` appended on the same line when other folders import it.
- Finds importers in every folder of the environment, also folders with no keys of their own. It lists them with
  one `GET /api/v2/folders?path=/&recursive=true`; each folder's full path is its `relativePath` field
  (Infisical returns paths relative to the queried `path`). Then one `GET /api/v2/secret-imports` per folder.
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
- The target path passes the `set` path rules before login.
- A target folder that does not exist (HTTP 404 on its list) holds no keys. `need` creates it as in
  "Missing folders" after it finds exactly one owner, and before the import. With no owner, it creates nothing.

### `gondr set <KEY> [--path P] [--env E]`

- Reads the value from stdin. A terminal on stdin, or an empty value: exit 1.
- The value is stored byte for byte as read (no newline trimming).
- `KEY` must match `^[A-Z][A-Z0-9_]*$`.
- The path must start with `layout.prefix/`, `layout.shared/`, a `layout.service_roots` entry plus `/`,
  or a boundary prefix, and have no empty, `.` or `..` segment. A service root is never a default
  folder: it is reached only with `--path`, and the boundary guard applies to it as to any path.
- `GET /api/v4/secrets/<KEY>` with `viewSecretValue=false`: 200 → `PATCH`, 404 → `POST` with
  `secretComment`. Both send `{projectId, environment, secretPath, secretValue, skipMultilineEncoding: true, type: "shared"}`.
- Prints `created <KEY> in <env>:<path>` or `updated <KEY> in <env>:<path>`. Never the value.
- Before the secret write, one `GET /api/v4/secrets` list of the folder (as in `ls`). On HTTP 404,
  `set` creates the folder as in "Missing folders", then writes the secret.

### Missing folders (used by `set` and `need`)

- Each path segment must match `^[A-Za-z0-9_-]+$` (Infisical's folder name rule). Else exit 1 before
  login, with a hint to map the repo in `[folders]` or pass `--path`.
- `gondr` walks the path from `/`. For each segment it lists the parent with `GET /api/v2/folders`
  (`projectId`, `environment`, `path`). If the segment is missing, it sends `POST /api/v2/folders` with
  body `{projectId, environment, name, path: <parent>}`. Below a created folder it sends no more lists.
- It never creates a folder that already exists, and never a folder outside the target path.
- Prints one `created folder <env>:<path>` line per created folder, parents first.

### `gondr run [--env E] [--path P] -- <cmd...>`

- Execs `infisical run --domain=<url>/api --projectId=<id> --env=<E> --path=<P> --silent -- env -u INFISICAL_TOKEN <cmd...>`.
- The exec environment holds `INFISICAL_TOKEN` (the machine identity access token) and the inherited env.
- `<cmd...>` stays intact, including spaces and arguments that look like flags.

### Vault discovery (used by `status`, `find`, `check`)

- The pane's vault is picked as in `agent` (`--vault`, nearest `agent-vault.json`, default), and must pass
  the same boundary rules; a vault that fails them is reported as `refused`, not used.
- If the process already runs behind the broker (`AGENT_VAULT_TOKEN` and `HTTPS_PROXY` are both set),
  the vault is `$AGENT_VAULT_VAULT` and discovery uses the inherited `AGENT_VAULT_ADDR` and token.
- Else discovery runs `<binary> vault discover --json` with `AGENT_VAULT_ADDR`, `AGENT_VAULT_TOKEN`,
  `AGENT_VAULT_VAULT`, `AGENT_VAULT_TELEMETRY=false` and `HOME=<gondr state folder>/agent-vault-home`.
- The reply is `{"vault": V, "services": [{"name", "host"}], "available_credentials": [names]}`.
- No `[agent_vault]` table, a missing binary, a nonzero exit or bad JSON: the vault is `unavailable`
  with a short reason. The command goes on; discovery never stops it.
- The agent token never appears in argv or output.

### `gondr status [--env E] [--json]`

- Read only. One login, one secrets list of the repo folder (the `GET /api/v4/secrets` of `ls`), and vault discovery.
- A secrets list that answers HTTP 404 means the folder does not exist. `status` then prints
  `  folder does not exist: ...` in place of the `keys` and `import` lines, and `--json` has
  `"folder_exists": false`. Exit 0. (`find` and `check` treat such a folder as empty.)
- Text output, in this order:
  - `repo: <repo root>` and `boundary: <name or ->`
  - `infisical: <env>:<folder> (project <id>)`, then the `keys` and `import` lines of `ls`
  - `vault: <V> (<source>)` where source is `--vault`, `agent-vault.json`, `default` or `this process`;
    then `  proxied here: yes|no`, then one `  host <host> (<service>)` line per service, sorted by host;
    or `vault: <V> unavailable: <reason>` / `vault: <V> refused: <reason>`
  - a `use:` block with three fixed lines:
    `  env var  -> gondr run -- <cmd>`, `  host     -> gondr agent <agent>; call https://<host> with no auth header`,
    `  other    -> gondr find <what>`
- `--json` prints one object: `repo`, `boundary`, `env`, `project`, `folder`, `keys`, `imports`
  (`[{"path", "keys"}]`), `vault` (`{"name", "source", "status": "ok"|"unavailable"|"refused", "reason",
  "proxied_here", "services": [{"name", "host"}], "credentials"}`). Exit 0 also when the vault is unavailable.

### `gondr find <words...> [--env E] [--json]`

- A candidate matches when each word (case-insensitive) is a substring of at least one of its fields
  (different words may match different fields):
  a key's name; a service's name or host. Folder paths are not matched. Words shorter than 2 characters stop the command with exit 1.
- Requests: one login, one secrets list of the repo folder, one recursive name list, and vault discovery. No import walk.
- Candidates and routes, in this order; a key appears once, under its first route:
  1. `proxied`: a vault service whose name or host matches. Route `call https://<host> in a gondr agent pane; send no auth header`.
  2. `env`: a key that reaches the folder (own or imported). Route `gondr run -- <cmd>  (reads $<KEY>)`.
  3. `import`: a key in a shared owner folder (`layout.shared`, or `B.shared` inside B; never the
     references folder) that does not reach the folder. Route `gondr need <KEY>`; with more than one owner,
     `gondr need <KEY> --from <owner>`, one line per owner.
  4. `repo-owned`: a key only in other folders under `layout.prefix` (same boundary rules as `where`).
     Route `ask the operator to move <KEY> from <folder> to a shared folder; never copy it`.
  5. `not-mapped`: a `[services.X]` entry whose name or a host matches, not in the pane's vault.
     Route `ask the operator: gondr onboard <folder> --admin-home <dir>`.
- Text output: one line per hit, `<route kind> <KEY or host>: <route>`; sorted by kind order, then name.
- No hit: print `missing: nothing matches "<words>"` and the operator command
  `ask the operator: printf %s "$VALUE" | gondr set <NAME> --path <folder>`, where `<NAME>` is the words
  joined by `_` in upper case when that is a valid key name, else `<NAME>`. Exit 1.
- `--json` prints `{"query", "folder", "vault", "hits": [{"kind", "key", "host", "service", "folders", "route"}], "missing": bool, "operator_command"}`.
- Folders outside the current boundary never appear (a boundary directory sees only its prefix).

### `gondr check [--env E] [--file F] [--json] [NAME...]`

- Names come from the arguments, else from `--file`, else from the first of `.env.example`, `.env.sample`,
  `.env.template` in the working directory, then in the checkout top (`git rev-parse --show-toplevel`).
  No names: exit 1 with a hint.
- From a file, a name is the part left of the first `=` on a line that matches
  `^\s*(export\s+)?[A-Za-z_][A-Za-z0-9_]*\s*=`. Comments and other lines are skipped.
  The text right of `=` is never printed or sent.
- Per name, one status, as `find` routes a key: `ok` (reaches the folder), `import` (`gondr need <NAME>`),
  `repo-owned`, or `missing` (the operator `gondr set` command). Text: `<status> <NAME>[: <route>]`, sorted by name.
- Exit 0 when every name is `ok`, else 1. `--json` prints `{"folder", "file", "names": [{"name", "status", "route"}]}`.

### `gondr agent [--vault V] <cmd...>`

- Vault: `--vault`, else `vault` from the nearest `agent-vault.json` between the working directory
  and the repo root, else `agent_vault.default_vault`.
- Inside boundary B, the vault must start with `B.vault_prefix` or be listed in `B.allow_vaults`.
  Outside every boundary, a vault must not start with any boundary's `vault_prefix`. A stop exits 77.
- If the command's basename is in `B.deny_agents`, and the directory is inside B or the vault starts
  with `B.vault_prefix`: exit 77. This holds also on an allowed vault such as `shared`.
- Execs `<binary> run --vault V -- /bin/sh -c '<export HOME=<real home>, append Infisical host to NO_PROXY and no_proxy>; exec "$@"' sh <cmd...>`
  with `AGENT_VAULT_ADDR`, `AGENT_VAULT_TOKEN`, `AGENT_VAULT_VAULT`, `AGENT_VAULT_TELEMETRY=false`,
  and `HOME` set to a gondr state folder for the broker CLI. The child gets the real `HOME` back.
- The agent token never appears in argv or output.

### `gondr token <verb> <provider> [options]`

- Verbs: `mint`, `revoke`, `exec`, `check`, `import`, `list`, `create`. Any other verb, or fewer than two
  arguments, prints `gondr: usage: gondr token <verbs> <provider> [options]` on stderr and exits 1,
  with no exec.
- The factory is `factory.binary` (default `~/.local/share/gondr/gondr-factory`). If it is not an
  executable file: exit 1 with a hint to run `factory/bin/install`. No login and no exec.
- Every verb execs `<binary> <verb> <provider> <options...>` with the inherited environment plus
  `GONDR_BIN`, the absolute path of the running gondr launcher (resolved `argv[0]`). If `argv[0]` is
  `__main__.py` or not executable: exit 1 before any exec.
- `mint`: gondr takes `--env <E>` and `--path <P>` (separate-argument form only, as in every gondr
  command; the last one given wins; a flag with no value exits 1) out of the options. It checks the env
  as in `set` (including the `warn_environments` notice), resolves the folder as in `set` (boundary
  guard, publish path rules and the folder-name rule), then execs
  `<binary> mint <provider> <other options...> --env <E> --path <P>`. A `--` in the options exits 1.
  Every failed check, boundary stops included, exits 1 before the exec, so no Touch ID prompt appears.
- Other verbs: gondr checks no option. It forwards them unchanged; the factory validates them.
- The exec replaces gondr, so the factory's exit status is gondr's.
- gondr does no Infisical login and sends no HTTP request for any verb.
- The factory stores each minted value by running `$GONDR_BIN set <KEY> --env <E> --path <P>` with the
  value on stdin. A nonzero exit makes it revoke the new credential and exit 1.

### `gondr onboard <folder> --admin-home DIR [--repo-dir DIR] [--vault NAME] [--services a,b] [--dry-run]`

- Default vault name: the folder below `layout.prefix`, with `/` replaced by `-`, plus `-<default_environment>`.
- A folder in any boundary: exit 1.
- For each service, the reference is the repo's own key unless its value hash equals the shared
  value's hash; then the shared reference wins. A service with neither: `skip <name>`.
- `--admin-home DIR` (or `AGENT_VAULT_ADMIN_HOME`) is the `HOME` of an `agent-vault auth login` session.
  It is valid when `DIR/.agent-vault/session.json` exists; that file holds `{"address": <broker URL>, "token": <admin token>}`.
  `--dry-run` needs no admin home.
- Every broker CLI call (`vault list|create|agent list|agent add|service add|credential-store sync`) runs with `HOME=DIR`.
- The policy is set with `PATCH <address>/v1/vaults/<vault>/settings`, body `{"unmatched_host_policy": "passthrough"}`,
  `Authorization: Bearer <admin token>`. The sync is `<binary> vault credential-store sync <vault>`.
- A `[services.X]` table may be empty; every missing field fills from the catalog template whose `id` is `X`
  (or `template = "<id>"`).
- `--dry-run` prints `plan <service>: <hosts> <- <key> (<source>)` lines and writes nothing.
- Otherwise: create folder `<folder>/<references_folder>`, publish each reference as in `set`,
  create the vault on the `infisical` credential store if missing, grant `grant_agents`, add services,
  set `unmatched_host_policy=passthrough`, sync, and write `agent-vault.json` when `--repo-dir` is given.

## Errors

- Any HTTP error prints `gondr: <METHOD> <path without query> -> HTTP <code>` and exits 1.
  It never prints a response body, a token, a client secret or a value.
- A network error prints `gondr: <METHOD> <path> -> <reason>` and exits 1, with no traceback.
- Every request sends `User-Agent: gondr/<version>`.
- HTTP 429: wait `Retry-After` seconds (else 1, 2, 4, 8; at most 30), then send the request again.
  After 5 attempts, fail as any HTTP error does.

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
- F16 `agent` runs a denied agent inside a boundary (on any vault) or on a boundary vault, runs a boundary
  directory on a vault that is neither its own nor in `allow_vaults`, or refuses an `allow_vaults` vault.
- F17 `agent` puts the agent token in argv or output.
- F18 An HTTP or network error prints a traceback or a body.
- F19 `onboard --dry-run` writes anything.
- F20 `onboard` uses the project key when its hash equals the shared hash.
- F21 A `[services.X]` entry without hosts or auth does not fill from the catalog.
- F22 An unknown `--env` passes.
- F23 `status`, `find` or `check` writes, or prints a value, token or `.env.example` value.
- F24 `status` stops when the vault is unavailable, or reports a refused vault as usable.
- F25 `status` ignores an already proxied process and starts discovery again.
- F26 `find` misses a route kind, lists a key twice, or orders routes wrong.
- F27 `find` shows folders outside the current boundary.
- F28 `find` with no hit exits 0, or prints no operator `gondr set` command.
- F29 `find` walks imports (one request per folder).
- F31 `[folders]` is ignored, or a shorter match wins over a longer one.
- F32 `status`, `find` or `check` stops on a missing repo folder (HTTP 404 on its list).
- F33 `set` or `need` stops on a missing target folder, creates an existing folder again, skips a
  missing parent, creates a folder outside the target path, or creates a folder when `need` finds no
  owner or a path rule fails.
- F34 `token` execs the factory for an unknown verb, or when the binary is missing.
- F35 `token mint` passes the user's `--env`/`--path` through unchecked, execs before the boundary,
  env and path checks, or sends a destination other than the one `set` would use.
- F36 `token` changes the options of a non-`mint` verb, adds `--env`/`--path` to them, or drops
  `GONDR_BIN` from the factory's environment.
- F37 `token` logs in to Infisical or sends an HTTP request.
- F38 `set` or `token mint` refuses a path under a `service_roots` entry, accepts the root itself or a
  path under an unlisted root, or lets a boundary directory reach a service root.
- F39 The factory accepts `--yubikey` on a verb other than `import`, accepts it twice, or passes it to a
  provider as an option. (`gondr token` forwards it unchanged, as F36 requires.)
- F40 `import --yubikey` stores a parent the connected YubiKey has not opened once, stores plain text,
  or stores anything when no YubiKey with a `gondr-token` certificate, or more than one, is connected.
  It seals to a key that is not on a PIV smart card (`com.apple.pivtoken`), or whose certificate subject
  is not exactly `gondr-token`, such as an SSH key on another token.
- F41 A sealed parent reaches a provider, a command environment or stdout without a YubiKey touch, or
  the Keychain item of a sealed parent holds anything but the `gondr-seal-piv-v1` marker and ciphertext.
- F42 A use of a sealed parent shows a Touch ID prompt, or a use of a plain parent skips Touch ID.
- F43 An `import` without `--yubikey` replaces a sealed parent with plain text.
- F44 `check` on a sealed parent omits `sealed=yubikey`, or prints the value.
- F30 `check` reads a value from the example file, exits 0 with a gap, or misreads `export NAME=` lines.
