# gondr

`gondr` lets coding agents (Claude Code, Codex, opencode and others) use secrets without seeing their values.
It drives two open-source Infisical products:

- [Infisical](https://infisical.com): the secret store. `gondr` finds the folder of the current repo,
  lists key names, shares keys by import, publishes values from stdin, and runs commands with the folder's secrets.
- [Infisical Agent Vault](https://github.com/Infisical/agent-vault): a credential proxy. `gondr` starts an
  agent behind the proxy, and the proxy adds the key to requests for a mapped host.

`gondr` is one Python file set with no dependencies besides the standard library (Python 3.11 or later).
The optional [Keeper](#keeper) store needs one extra package.

## Install

```sh
uv tool install "git+https://github.com/joshka0/gondr"
# or: pipx install "git+https://github.com/joshka0/gondr"
```

You also need the [`infisical` CLI](https://infisical.com/docs/cli/overview) for `gondr run`, and the
`agent-vault` binary for `gondr agent` and `gondr onboard`. For `gondr token` (macOS), build the token
factory with `factory/bin/install`; [`factory/README.md`](factory/README.md) lists its providers.

## Set up

1. Create an Infisical [machine identity](https://infisical.com/docs/documentation/platform/identities/universal-auth)
   with Universal Auth. Give it access to your project.
2. Store its client ID and secret in the macOS Keychain. On Linux, export them as
   `INFISICAL_UNIVERSAL_AUTH_CLIENT_ID` and `INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET`, and set
   `source = "env"` in the config.
3. Copy [`config.example.toml`](config.example.toml) to `~/.config/gondr/config.toml` and edit it.
   Set `url` to the Infisical region or self-hosted server of your project.

## Keeper

[Keeper Secrets Manager](https://docs.keeper.io/en/keeperpam/secrets-manager/overview) can hold the secrets in place of Infisical.
Your Keeper account must have Secrets Manager enabled: the **Secrets Manager** tab in the vault. A vault without it cannot work with `gondr`.

1. Install the extra: `uv tool install "gondr[keeper] @ git+https://github.com/joshka0/gondr"`, or `pip install 'gondr[keeper]'`.
2. Create a Keeper shared folder and a KSM application with access to it. Create the application's one-time token
   and redeem it to get its base64 config.
3. Put that config in the macOS Keychain, or in an environment variable.
4. In `config.toml`, set the store and the folder. See [`config.example.toml`](config.example.toml).

```toml
[store]
kind = "keeper"

[keeper]
shared_folder = "<shared folder UID>"
config = { source = "keychain", account = "gondr", service = "keeper-ksm-config" }
```

- With Keeper, `[infisical]` is not needed, `.infisical.json` is ignored, and nothing contacts Infisical.
- The folder `/repos/acme/api` in `dev` is the Keeper folder `dev/repos/acme/api` under `shared_folder`.
  A key is a `login` record titled with the key name. Its value is the record's `password`.
  `gondr set` creates missing folders and records.
- Two records with one key title in a folder stop the command. Delete one in Keeper.
- `gondr run` runs the command directly with the folder's keys in its environment. The command does not get the KSM config.
- `gondr need`, `gondr agent` and `gondr onboard` do not work with Keeper. Keeper shares records by folder access,
  and Agent Vault has no Keeper credential store. `ls`, `where`, `set`, `run`, `status`, `find`, `check` and `token mint` work.
- An SDK error prints `gondr: keeper <operation> failed: <error type>`, never the error text.

## Folder layout

`gondr` maps each local repo to one Infisical folder:

| Local | Infisical folder | Holds |
| --- | --- | --- |
| `~/repos/acme/api` | `/repos/acme/api` | keys of that repo, and imports of shared folders |
| - | `/shared/<vendor>` | one shared key, stored once |
| - | `/repos/acme/api/agent-vault` | Agent Vault references for that repo's vault |

A linked Git worktree maps to the folder of its main checkout. A `[folders]` entry in the config
maps a repo whose folder does not follow its path. A repo with `.infisical.json` uses its `workspaceId` as the project.
`gondr set` and `gondr need` create the repo folder and its missing parents, so a new repo needs no setup.

## Commands

| Command | Does |
| --- | --- |
| `gondr ls [path]` | Key names, imports and subfolders of a folder |
| `gondr where <KEY>` | Folders that hold a key, and the folders that import them |
| `gondr need <KEY>` | Import the shared folder that owns a key into this repo's folder |
| `gondr set <KEY> < value` | Create or update a key from stdin |
| `gondr run -- <cmd>` | Run a command with the folder's secrets in its environment |
| `gondr agent <cmd>` | Run an agent through the repo's Agent Vault vault |
| `gondr onboard <folder> --admin-home DIR` | Give a repo its own vault: references, grants, services |
| `gondr status` | This repo's folder, keys, imports, vault and hosts |
| `gondr find <what>` | How to use a secret: proxied host, env var, import, or the operator command |
| `gondr check` | Which names in `.env.example` reach this repo |
| `gondr token mint <provider> --secret KEY ...` | Mint a scoped cloud credential into this repo's folder, after Touch ID (macOS) |
| `gondr token exec\|revoke\|check\|import <provider> ...` | Run one command with a short-lived credential, revoke one, or manage parent credentials |

`status`, `find` and `check` take `--json`. Give your agents the block in [`docs/agents.md`](docs/agents.md), or install [`skills/gondr`](skills/gondr/SKILL.md) as a skill.
To set up the same pattern without `gondr`, follow [`docs/cookbook.md`](docs/cookbook.md).

Every command takes `--env <environment>`. The default is `dev`.

## Boundaries

A boundary keeps one set of secrets with one set of directories, for example a client's repos:

```toml
[[boundary]]
name = "Acme"
dir = "~/repos/acme"
prefix = "/repos/acme"
shared = "/repos/acme/tooling"
vault_prefix = "acme"
allow_vaults = ["shared"]
deny_agents = ["some-agent"]
```

- A command in `~/repos/acme` reaches only `/repos/acme`, and only an `acme*` vault or a vault in `allow_vaults`.
- A command elsewhere cannot reach `/repos/acme` or an `acme*` vault.
- `deny_agents` lists agent commands that never do that boundary's work: not in its directories, and not on its vaults.
- `gondr` checks the boundary before it reads a credential or sends a request.

## Threat model

`gondr` keeps secret values out of an agent's context by accident. It does not stop an agent that wants a value.

- Discovery asks Infisical for names only (`viewSecretValue=false`). Errors print the request and status, never a response body.
- `gondr set` reads the value from stdin, so it is not in argv, shell history or the transcript.
- `gondr run -- env` prints every value of the folder. Use `gondr agent` and Agent Vault when the agent must not read a key at all.
- Agent Vault keeps keys out of the agent process. A proxied process can still use a key through the proxy.
- Boundaries are a convention that `gondr` enforces. Infisical does not: the identity can read every folder it has access to.
  For a hard limit, give each boundary its own identity and project.
- Each command signs in again. Set a short access token TTL on the identity.

## Test

```sh
python3 tests/gate.py --report reports/gate.json
```

The gate runs the real CLI against a local fake Infisical server and stub `git`, `security`, `infisical` and
`agent-vault` executables. It writes a JSON report with every request and the command that reproduces it.

## License

MIT
