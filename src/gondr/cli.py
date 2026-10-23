USAGE = """gondr: let coding agents use secrets without seeing them.

Infisical (secret store):
  gondr run [--env E] [--path P] -- <cmd...>   run <cmd> with the folder's secrets and imports
  gondr ls [--env E] [path]                     key names, imports, subfolders
  gondr where <KEY> [--env E]                   folders that define KEY, and who imports them
  gondr need <KEY> [--env E] [--path P] [--from F]  import KEY's shared owner folder; creates a missing folder
  gondr set <KEY> [--env E] [--path P]          publish a value read from stdin; creates a missing folder

Discovery for agents (read only):
  gondr status [--env E] [--json]               this repo's folder, keys, imports and vault
  gondr find <words...> [--env E] [--json]      how to use a secret: env var, proxied host, import, or ask
  gondr check [NAME...] [--file F] [--json]     which needed names (.env.example) reach this repo

Infisical Agent Vault (credential proxy):
  gondr agent [--vault V] <cmd...>              run an agent through the repo's vault
  gondr onboard <folder> --admin-home DIR [--repo-dir DIR] [--vault NAME] [--services a,b] [--dry-run]

gondr prints key names, never values. Config: $GONDR_CONFIG or ~/.config/gondr/config.toml.
"""
import sys

from gondr import __version__, config, guide, infisical, vault

COMMANDS = {"run": infisical.cmd_run, "ls": infisical.cmd_ls, "where": infisical.cmd_where,
            "need": infisical.cmd_need, "set": infisical.cmd_set,
            "agent": vault.cmd_agent, "onboard": vault.cmd_onboard,
            "status": guide.cmd_status, "find": guide.cmd_find, "check": guide.cmd_check}


def main():
    argv = sys.argv[1:]
    if argv[:1] in (["--version"], ["-V"]):
        print(f"gondr {__version__}")
        return
    if not argv or argv[0] not in COMMANDS:
        print(USAGE.strip())
        sys.exit(0 if argv[:1] in (["-h"], ["--help"]) else 1)
    cfg = config.load()
    COMMANDS[argv[0]](cfg, config.Scope(cfg), argv[1:])
