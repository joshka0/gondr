"""Discovery commands for agents: status, find, check. Read only; names, never values."""
import json
import re
from pathlib import Path

from gondr.common import die, parse
from gondr.config import git
from gondr.discovery import KINDS, Keys, vault_view
from gondr.infisical import KEY, Client, check_env

EXAMPLES = (".env.example", ".env.sample", ".env.template")
ASSIGN = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=")
USE = ["  env var  -> gondr run -- <cmd>",
       "  host     -> gondr agent <agent>; call https://<host> with no auth header",
       "  other    -> gondr find <what>"]


def start(cfg, scope, args, flags=("--env",), switches=("--json",)):
    opts, rest = parse(args, flags, switches)
    env = check_env(cfg, opts.get("env", cfg.default_environment))
    folder = scope.folder()
    return opts, rest, env, folder, Client(cfg, scope.project()).login()


def cmd_status(cfg, scope, args):
    opts, _, env, folder, client = start(cfg, scope, args)
    listed = client.list_folder_if_exists(env, folder)
    own, imports = listed or ([], [])
    v = vault_view(cfg, scope)
    here = scope.boundary()
    if opts.get("json"):
        print(json.dumps({"repo": str(scope.root), "boundary": here.name if here else None, "env": env,
                          "project": client.project, "folder": folder, "folder_exists": listed is not None,
                          "keys": own,
                          "imports": [{"path": p, "keys": k} for p, k in imports], "vault": v}, indent=2))
        return
    print(f"repo: {scope.root}")
    print(f"boundary: {here.name if here else '-'}")
    print(f"infisical: {env}:{folder} (project {client.project})")
    if listed is None:
        print("  folder does not exist: `gondr set` or `gondr need` creates it")
    else:
        print(f"  keys ({len(own)}): {' '.join(own) or '-'}")
        for src, keys in imports:
            print(f"  import {src} ({len(keys)}): {' '.join(keys)}")
    if v["status"] == "ok":
        print(f"vault: {v['name']} ({v['source']})")
        print(f"  proxied here: {'yes' if v['proxied_here'] else 'no'}")
        for s in v["services"]:
            print(f"  host {s['host']} ({s['name']})")
    else:
        print(f"vault: {v['name'] or '-'} {v['status']}: {v['reason']}")
    print("use:")
    print("\n".join(USE))


def matches(words, fields):
    return all(any(w in f.lower() for f in fields if f) for w in words)


def cmd_find(cfg, scope, args):
    opts, words, env, folder, client = start(cfg, scope, args)
    if not words:
        die("usage: gondr find <words...>")
    if any(len(w) < 2 for w in words):
        die("each word needs at least 2 characters")
    terms = [w.lower() for w in words]
    keys = Keys(cfg, scope, client, env, folder)
    v = vault_view(cfg, scope)
    hits = []
    for s in v["services"]:
        if matches(terms, [s["name"], s["host"]]):
            hits.append({"kind": "proxied", "key": None, "host": s["host"], "service": s["name"], "folders": [],
                         "route": f"call https://{s['host']} in a gondr agent pane; send no auth header"})
    for key in sorted(keys.reach | set(keys.folders)):
        where = sorted(keys.folders.get(key, set()))
        if not matches(terms, [key]):
            continue
        kind, routes = keys.route(key)
        for route in routes:
            hits.append({"kind": kind, "key": key, "host": None, "service": None, "folders": where, "route": route})
    if v["status"] == "ok":
        mapped = {s["name"] for s in v["services"]} | {s["host"] for s in v["services"]}
        for name, svc in sorted(cfg.services.items()):
            hosts = svc.get("hosts", [])
            if matches(terms, [name, *hosts]) and not ({name, *hosts} & mapped):
                hits.append({"kind": "not-mapped", "key": None, "host": ", ".join(hosts) or None, "service": name,
                             "folders": [], "route": f"ask the operator: gondr onboard {folder} --admin-home <dir>"})
    hits = [h for h in hits if h["kind"] in KINDS]
    hits.sort(key=lambda h: (KINDS.index(h["kind"]), h["key"] or h["host"] or h["service"] or ""))
    name = "_".join(words).upper()
    command = keys.operator_set(name if KEY.match(name) else "<NAME>")
    if opts.get("json"):
        print(json.dumps({"query": " ".join(words), "folder": folder, "vault": v["name"], "hits": hits,
                          "missing": not hits, "operator_command": None if hits else command}, indent=2))
    else:
        for h in hits:
            print(f"{h['kind']} {h['key'] or h['host'] or h['service']}: {h['route']}")
        if not hits:
            print(f'missing: nothing matches "{" ".join(words)}"')
            print(command)
    if not hits:
        raise SystemExit(1)


def example_file(scope, explicit):
    if explicit:
        return Path(explicit)
    top = git("rev-parse", "--show-toplevel")
    for d in [scope.cwd, *([top] if top else [])]:
        for name in EXAMPLES:
            if (d / name).is_file():
                return d / name
    return None


def cmd_check(cfg, scope, args):
    opts, names, env, folder, client = start(cfg, scope, args, ("--env", "--file"))
    source = None
    if not names:
        source = example_file(scope, opts.get("file"))
        if not source:
            die("no names to check", "pass NAME..., --file F, or add .env.example")
        try:
            lines = source.read_text().splitlines()
        except (OSError, UnicodeDecodeError):
            die(f"cannot read {source}")
        names = [m.group(1) for line in lines if (m := ASSIGN.match(line))]
        if not names:
            die(f"{source} holds no NAME= lines")
    keys = Keys(cfg, scope, client, env, folder)
    rows = []
    for name in sorted(set(names)):
        kind, routes = keys.route(name)
        rows.append({"name": name, "status": "ok" if kind == "env" else kind,
                     "route": None if kind == "env" else "; ".join(routes)})
    if opts.get("json"):
        print(json.dumps({"folder": folder, "file": str(source) if source else None, "names": rows}, indent=2))
    else:
        for r in rows:
            print(f"{r['status']} {r['name']}" + (f": {r['route']}" if r["route"] else ""))
    if any(r["status"] != "ok" for r in rows):
        raise SystemExit(1)
