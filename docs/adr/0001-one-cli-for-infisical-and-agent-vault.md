# 0001: One CLI for Infisical and Agent Vault

- Status: accepted
- Date: 2026-10-22
- Topic: fleet-tooling-isec

## Context

Five private tools did this work: `isec` (Python), two publish scripts (zsh, `jq`, `curl`),
`av-agent` (sh), a broker wrapper (sh), and `av-project` (Python). Each held a project ID,
Keychain names, a broker address or a client boundary in code. Two of them were in no repo.
`av-project` signed in with the user's CLI login; the others used a machine identity.

## Options

1. Publish `isec` alone and keep the Agent Vault scripts private.
2. One CLI with a pluggable backend interface (Infisical, 1Password, others).
3. One CLI for Infisical and Infisical Agent Vault, with all site facts in a config file.

## Choice

Option 3. The operator chose a new name that covers both (`gondr`), the MIT license,
Infisical only, all three command groups in release 1, and client rules as config boundaries.

- Python standard library only; Python 3.11 for `tomllib`.
- One auth path: the Universal Auth machine identity, from Keychain or env.
- `set` publishes through the REST API in Python. The zsh publisher goes away.
- A boundary is data: directory, folder prefix, vault prefix, denied agents.
- `onboard` takes service entries from config and fills gaps from `agent-vault catalog --json`.

## Consequences

- The private setup becomes one config file (`~/.config/gondr/config.toml`).
- `isec`, `av-agent`, `agent-vault-run`, `av-project`, `services.json` and the two publish scripts
  can go after the cutover. Planned: the cutover needs the operator's go-ahead.
- `gondr agent` refuses a boundary directory on a non-boundary vault. Today `av-agent` gives
  such a directory the `shared` vault.
- Option 2 stays open as future work if a second store is ever needed.
