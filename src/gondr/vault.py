"""Infisical Agent Vault: a proxy that adds a mapped key to an agent's requests."""
import json
import os
import shlex
import subprocess
import sys
import urllib.parse
from pathlib import Path

from gondr.common import die, env_secret, keychain, parse, state_home
from gondr.config import git
from gondr.infisical import Client, http

# Runs inside `infisical run`: prints {name: sha256} for the requested names.
HASHER = ("import hashlib,json,os,sys;"
          "print(json.dumps({k: hashlib.sha256(os.environ[k].encode()).hexdigest()"
          " for k in sys.argv[1:] if os.environ.get(k)}))")


def settings(cfg):
    return cfg.agent_vault or die("the config has no [agent_vault] table")


def agent_token(av):
    t = av.get("token") or die("agent_vault.token is not set")
    if t.get("source") == "keychain":
        return keychain(t["account"], t["service"])
    return env_secret(t.get("name", "AGENT_VAULT_TOKEN"))


def pick_vault(cfg, scope, explicit=None):
    """(vault, source): --vault, the nearest agent-vault.json, or the default."""
    if explicit:
        return explicit, "--vault"
    found = nearest_vault(scope)
    return (found, "agent-vault.json") if found else (settings(cfg)["default_vault"], "default")


def refusal(cfg, scope, vault):
    """Why the boundary rules refuse this vault here, or None."""
    here = scope.boundary()
    if here and not (here.holds_vault(vault) or vault in here.allow_vaults):
        return (f"a {here.name} directory needs a {here.name} vault ({here.vault_prefix}*) "
                f"or one of allow_vaults, not {vault}")
    for b in cfg.boundaries:
        if b.holds_vault(vault) and here is not b:
            return f"vault {vault} belongs to {b.name}; use it only from a directory under {b.dir}"
    return None


def nearest_vault(scope):
    """`vault` from the nearest agent-vault.json between the working directory and the checkout top."""
    top = git("rev-parse", "--show-toplevel")
    stop = top.resolve() if top else Path.home().resolve()
    for d in [scope.cwd, *scope.cwd.parents]:
        f = d / "agent-vault.json"
        if f.is_file():
            try:
                return json.loads(f.read_text())["vault"]
            except (OSError, ValueError, KeyError):
                die(f"{f} has no vault name")
        if d == stop:
            return None
    return None


def cmd_agent(cfg, scope, args):
    av = settings(cfg)
    vault = None
    # Only leading options belong to gondr; everything from the command on belongs to the agent.
    while args and args[0] in ("--vault", "--"):
        if args[0] == "--":
            args = args[1:]
            break
        if len(args) < 2:
            die("--vault needs a value")
        vault, args = args[1], args[2:]
    if not args:
        die("nothing to run", "gondr agent <command> [args...]")
    vault, _ = pick_vault(cfg, scope, vault)
    if reason := refusal(cfg, scope, vault):
        die(reason, code=77)
    here = scope.boundary()
    for b in cfg.boundaries:
        # A denied agent never does a boundary's work, whatever vault it would use.
        if (here is b or b.holds_vault(vault)) and os.path.basename(args[0]) in b.deny_agents:
            die(f"{args[0]} is denied for {b.name} work", code=77)
    token = agent_token(av)
    client_home = state_home() / "agent-vault-home"
    client_home.mkdir(parents=True, exist_ok=True)
    client_home.chmod(0o700)
    # `agent-vault run` replaces NO_PROXY. Infisical signs in with its own identity, so it
    # bypasses the broker; the shell adds its host back before the agent starts.
    host = shlex.quote(urllib.parse.urlsplit(cfg.url).hostname or "")
    # The broker CLI runs with a gondr HOME; the agent gets the real HOME back.
    script = (f'export HOME={shlex.quote(str(Path.home()))} NO_PROXY="$NO_PROXY,{host}" '
              f'no_proxy="$NO_PROXY,{host}"; exec "$@"')
    env = {**os.environ, "AGENT_VAULT_ADDR": av["address"], "AGENT_VAULT_TOKEN": token,
           "AGENT_VAULT_VAULT": vault, "AGENT_VAULT_TELEMETRY": "false", "HOME": str(client_home)}
    argv = [av["binary"], "run", "--vault", vault, "--", "/bin/sh", "-c", script, "sh", *args]
    try:
        os.execvpe(av["binary"], argv, env)
    except FileNotFoundError:
        die(f"{av['binary']} is not on PATH", "install Agent Vault: https://github.com/Infisical/agent-vault")


def run(cmd, env=None, input=None):
    try:
        r = subprocess.run(cmd, env=env, input=input, capture_output=True, text=True)
    except FileNotFoundError:
        die(f"{cmd[0]} is not on PATH")
    if r.returncode != 0:
        die(f"{os.path.basename(cmd[0])} {' '.join(cmd[1:3])} failed (exit {r.returncode})")
    return r


def services(cfg, av, wanted):
    """Service entries from the config, with missing fields filled from the broker catalog."""
    out, catalog = {}, None
    for name in wanted:
        if name not in cfg.services:
            die(f"service {name} is not in the config")
        svc = dict(cfg.services[name])
        if not all(k in svc for k in ("hosts", "auth", "key")):
            if catalog is None:
                r = run([av["binary"], "catalog", "--json", "--address", av["address"]],
                        env={**os.environ, "AGENT_VAULT_TELEMETRY": "false"})
                try:
                    catalog = {t["id"]: t for t in json.loads(r.stdout)}
                except (ValueError, KeyError, TypeError):
                    die("agent-vault catalog returned no template list")
            t = catalog.get(svc.get("template", name)) or die(f"service {name} needs hosts, auth and key")
            if t.get("auth_type") not in ("bearer", "api-key"):
                die(f"service {name}: catalog auth {t.get('auth_type')} is not supported")
            svc.setdefault("hosts", [t["host"]])
            svc.setdefault("auth", t["auth_type"])
            svc.setdefault("key", t["suggested_credential_key"])
            if t.get("header"):
                svc.setdefault("header", t["header"])
        svc.setdefault("project_keys", [svc["key"]])
        out[name] = svc
    return out


def ref_path(ref):
    """'${dev.shared.vendors.openai.KEY}' -> ('/shared/vendors/openai', 'KEY')."""
    parts = ref.strip("${}").split(".")[1:]
    return "/" + "/".join(parts[:-1]), parts[-1]


def hashes(cfg, client, env, path, names):
    """{name: sha256} for names present at an exact folder. Values stay in the child process."""
    if not names:
        return {}
    r = subprocess.run(["infisical", "run", "--silent", f"--domain={cfg.url}/api",
                        f"--projectId={client.project}", f"--env={env}", f"--path={path}", "--",
                        sys.executable, "-I", "-c", HASHER, *names],
                       env={**os.environ, "INFISICAL_TOKEN": client.token}, capture_output=True, text=True)
    for line in reversed(r.stdout.splitlines()):
        if line.startswith("{"):
            return json.loads(line)
    return {}


def cmd_onboard(cfg, scope, args):
    av = settings(cfg)
    opts, rest = parse(args, ("--admin-home", "--repo-dir", "--vault", "--services"), ("--dry-run",))
    if len(rest) != 1:
        die("usage: gondr onboard <folder> --admin-home DIR [--repo-dir DIR] [--vault NAME] "
            "[--services a,b] [--dry-run]")
    folder = scope.absolute(rest[0])
    if not folder.startswith(cfg.prefix + "/"):
        die(f"{folder} is not a repo folder under {cfg.prefix}")
    b = scope.owner_boundary(folder)
    if b:
        die(f"{folder} belongs to {b.name}; onboard does not handle boundary folders")
    env = cfg.default_environment
    vault = opts.get("vault") or folder[len(cfg.prefix) + 1:].replace("/", "-") + f"-{env}"
    admin_home = opts.get("admin-home") or os.environ.get("AGENT_VAULT_ADMIN_HOME")
    if not opts.get("dry-run") and not (admin_home and (Path(admin_home) / ".agent-vault/session.json").is_file()):
        die("--admin-home must be the HOME of an `agent-vault auth login` admin session")

    wanted = opts["services"].split(",") if opts.get("services") else list(cfg.services)
    catalog = services(cfg, av, wanted)
    client = Client(cfg, scope.project()).login()

    # A project key that equals the shared value is a copy, so the shared reference wins.
    project = hashes(cfg, client, env, folder, sorted({k for s in catalog.values() for k in s["project_keys"]}))
    plan = []
    for name, svc in catalog.items():
        own = next((k for k in svc["project_keys"] if k in project), None)
        shared_hash = None
        if svc.get("shared"):
            sp, sk = ref_path(svc["shared"])
            shared_hash = hashes(cfg, client, env, sp, [sk]).get(sk)
        if own and project[own] != shared_hash:
            plan.append((name, svc, "${%s.%s.%s}" % (env, ".".join(folder.strip("/").split("/")), own), f"project {own}"))
        elif shared_hash:
            plan.append((name, svc, svc["shared"], "shared"))
        else:
            print(f"skip {name}: no project or shared key")
    for name, svc, _, source in plan:
        print(f"plan {name}: {', '.join(svc['hosts'])} <- {svc['key']} ({source})")
    if opts.get("dry-run") or not plan:
        return

    assert admin_home
    refs = av["references_folder"]
    if refs not in client.subfolders(env, folder):
        client.call("POST", "/api/v2/folders",
                    body={"projectId": client.project, "environment": env, "name": refs, "path": folder})
    for name, svc, ref, _ in plan:
        print(f"{client.publish(env, f'{folder}/{refs}', svc['key'], ref)} {svc['key']} in {env}:{folder}/{refs}")

    admin = {**os.environ, "HOME": admin_home, "AGENT_VAULT_TELEMETRY": "false"}
    broker = lambda *a: run([av["binary"], *a], env=admin)
    if f" {vault} " not in broker("vault", "list").stdout:
        broker("vault", "create", vault, "--credential-store", "infisical", "--infisical-project-id",
               client.project, "--infisical-environment", env, "--infisical-path", f"{folder}/{refs}")
        print(f"created vault {vault}")
    granted = broker("vault", "agent", "list", "--vault", vault).stdout
    for agent in av["grant_agents"]:
        if agent not in granted:
            broker("vault", "agent", "add", agent, "--role", "proxy", "--vault", vault)
    for name, svc, _, _ in plan:
        for i, host in enumerate(svc["hosts"]):
            auth = (["--auth-type", "api-key", "--api-key-header", svc["header"], "--api-key-key", svc["key"]]
                    if svc["auth"] == "api-key" else ["--auth-type", "bearer", "--token-key", svc["key"]])
            broker("vault", "service", "add", "--vault", vault, "--name", name if i == 0 else f"{name}-{i + 1}",
                   "--host", host, *auth)
    session = json.loads((Path(admin_home) / ".agent-vault/session.json").read_text())
    status, _ = http(session["address"], "PATCH", f"/v1/vaults/{vault}/settings", session["token"],
                     body={"unmatched_host_policy": "passthrough"})
    print(f"policy passthrough: HTTP {status}")
    broker("vault", "credential-store", "sync", vault)
    print(f"synced {vault}")
    if opts.get("repo-dir"):
        f = Path(opts["repo-dir"]) / "agent-vault.json"
        f.write_text(json.dumps({"vault": vault}, indent=2) + "\n")
        print(f"wrote {f}")
