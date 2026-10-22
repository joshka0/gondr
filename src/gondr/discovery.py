"""What an agent can reach from here: the pane's vault and the routes to each key."""
import json
import os
import subprocess

from gondr.common import keychain_value, state_home
from gondr.vault import pick_vault, refusal

KINDS = ["proxied", "env", "import", "repo-owned", "not-mapped"]


def agent_token_value(av):
    t = av.get("token") or {}
    if t.get("source") == "keychain":
        return keychain_value(t.get("account", ""), t.get("service", ""))
    return os.environ.get(t.get("name", "AGENT_VAULT_TOKEN"))


def vault_view(cfg, scope, explicit=None):
    """The vault this pane uses, with its hosts. Never stops the command: a failure is a status."""
    v = {"name": None, "source": None, "status": "unavailable", "reason": "", "services": [], "credentials": [],
         "proxied_here": bool(os.environ.get("AGENT_VAULT_TOKEN") and os.environ.get("HTTPS_PROXY"))}
    av = cfg.agent_vault
    if v["proxied_here"] and os.environ.get("AGENT_VAULT_VAULT"):
        v["name"], v["source"] = os.environ["AGENT_VAULT_VAULT"], "this process"
    elif av is None:
        v["reason"] = "the config has no [agent_vault] table"
        return v
    else:
        v["name"], v["source"] = pick_vault(cfg, scope, explicit)
    if reason := refusal(cfg, scope, v["name"]):
        v["status"], v["reason"] = "refused", reason
        return v
    binary = av["binary"] if av else "agent-vault"
    env = {**os.environ, "AGENT_VAULT_TELEMETRY": "false",
           "HOME": str(state_home() / "agent-vault-home")}
    if v["source"] != "this process":
        token = agent_token_value(av)
        if not token:
            v["reason"] = "no agent token"
            return v
        env.update(AGENT_VAULT_ADDR=av["address"], AGENT_VAULT_TOKEN=token, AGENT_VAULT_VAULT=v["name"])
    (state_home() / "agent-vault-home").mkdir(parents=True, exist_ok=True)
    try:
        r = subprocess.run([binary, "vault", "discover", "--json"], env=env, capture_output=True, text=True)
    except FileNotFoundError:
        v["reason"] = f"{binary} is not on PATH"
        return v
    if r.returncode != 0:
        v["reason"] = f"vault discover exited {r.returncode}"
        return v
    try:
        data = json.loads(r.stdout)
        v["services"] = sorted(({"name": s["name"], "host": s["host"]} for s in data.get("services", [])),
                               key=lambda s: s["host"])
        v["credentials"] = sorted(data.get("available_credentials", []))
    except (ValueError, KeyError, TypeError, AttributeError):
        v["reason"] = "vault discover returned no service list"
        return v
    v["status"], v["reason"] = "ok", ""
    return v


class Keys:
    """Key names that reach a folder, and where every other key of this boundary lives."""

    def __init__(self, cfg, scope, client, env, folder):
        self.cfg, self.scope, self.folder = cfg, scope, folder
        listed = client.list_folder_if_exists(env, folder)
        self.exists = listed is not None
        own, imports = listed or ([], [])
        self.reach = set(own) | {k for _, keys in imports for k in keys}
        here = scope.boundary()
        refs = cfg.agent_vault["references_folder"] if cfg.agent_vault else "agent-vault"
        self.pool = (here.shared or here.prefix) if here else cfg.shared
        self.refs = f"{cfg.shared}/{refs}"
        self.folders = {}
        for p, k in client.all_secret_paths(env):
            # A folder outside this boundary, and Agent Vault reference folders, hold no owner.
            if scope.owner_boundary(p) == here and not p.endswith("/" + refs):
                self.folders.setdefault(k, set()).add(p)

    def in_pool(self, p):
        return (p == self.pool or p.startswith(self.pool + "/")) and p != self.refs

    def route(self, key):
        """(kind, [route lines]) for one key name."""
        if key in self.reach:
            return "env", [f"gondr run -- <cmd>  (reads ${key})"]
        found = self.folders.get(key, set()) - {self.folder}
        owners = sorted(p for p in found if self.in_pool(p))
        if len(owners) == 1:
            return "import", [f"gondr need {key}"]
        if owners:
            return "import", [f"gondr need {key} --from {o}" for o in owners]
        others = sorted(p for p in found if p.startswith(self.cfg.prefix + "/"))
        if others:
            return "repo-owned", [f"ask the operator to move {key} from {o} to a shared folder; never copy it"
                                  for o in others]
        return "missing", [self.operator_set(key)]

    def operator_set(self, name):
        return f'ask the operator: printf %s "$VALUE" | gondr set {name} --path {self.folder}'
