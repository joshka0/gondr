"""Infisical: the secret store. Every read asks for names only."""
import json
import os
import re
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

from gondr import __version__
from gondr.common import die, env_secret, keychain, parse

# Infisical Cloud's Cloudflare rejects the default urllib agent (error 1010).
UA = f"gondr/{__version__}"
KEY = re.compile(r"^[A-Z][A-Z0-9_]*$")
RETRIES = 5

# Inside `agent-vault run`, SSL_CERT_FILE names only the broker CA, and Infisical bypasses the
# broker. Trust the system CAs as well.
TLS = ssl.create_default_context()
_defaults = ssl.get_default_verify_paths()
if _defaults.openssl_cafile and os.path.exists(_defaults.openssl_cafile):
    TLS.load_verify_locations(cafile=_defaults.openssl_cafile)


def http(base, method, path, token=None, query=None, body=None, allow=()):
    """JSON request. Returns (status, data). A status in `allow` returns (status, {}).

    Errors print the method, the path and the status only: a body can hold a value.
    """
    url = base + path + ("?" + urllib.parse.urlencode(query) if query else "")
    headers = {"User-Agent": UA, "Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, method=method, headers=headers,
                                 data=None if body is None else json.dumps(body).encode())
    for attempt in range(RETRIES):
        try:
            with urllib.request.urlopen(req, context=TLS, timeout=30) as resp:
                return resp.status, json.load(resp)
        except urllib.error.HTTPError as e:
            retry_after = e.headers.get("Retry-After", "") if e.headers else ""
            e.close()
            if e.code == 429 and attempt + 1 < RETRIES:
                # Rate limited: wait as the server asks, then send the same request again.
                time.sleep(min(int(retry_after) if retry_after.isdigit() else 2 ** attempt, 30))
                continue
            if e.code in allow:
                return e.code, {}
            die(f"{method} {path} -> HTTP {e.code}")
        except urllib.error.URLError as e:
            die(f"{method} {path} -> {e.reason}")
        except (OSError, ValueError) as e:
            die(f"{method} {path} -> {type(e).__name__}")
    die(f"{method} {path} -> HTTP 429")


class Client:
    def __init__(self, cfg, project):
        self.cfg, self.project, self.token = cfg, project, None

    def login(self):
        c = self.cfg.credentials
        if c.get("source") == "keychain":
            ident = {"clientId": keychain(c["keychain_account"], c["client_id_service"]),
                     "clientSecret": keychain(c["keychain_account"], c["client_secret_service"])}
        else:
            ident = {"clientId": env_secret("INFISICAL_UNIVERSAL_AUTH_CLIENT_ID"),
                     "clientSecret": env_secret("INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET")}
        _, data = http(self.cfg.url, "POST", "/api/v1/auth/universal-auth/login", body=ident)
        self.token = data.get("accessToken") or die("login returned no access token")
        return self

    def call(self, method, path, query=None, body=None, allow=()):
        return http(self.cfg.url, method, path, self.token, query, body, allow)

    def list_folder(self, env, path):
        _, data = self.call("GET", "/api/v4/secrets", {
            "projectId": self.project, "environment": env, "secretPath": path, "includeImports": "true",
            "viewSecretValue": "false", "expandSecretReferences": "false"})
        own = sorted(s["secretKey"] for s in data.get("secrets", []))
        imports = [(i.get("secretPath"), sorted(s["secretKey"] for s in i.get("secrets", [])))
                   for i in data.get("imports", [])]
        return own, imports

    def subfolders(self, env, path):
        _, data = self.call("GET", "/api/v2/folders", {"projectId": self.project, "environment": env, "path": path})
        return sorted(f["name"] for f in data.get("folders", []))

    def all_secret_paths(self, env):
        _, data = self.call("GET", "/api/v4/secrets", {
            "projectId": self.project, "environment": env, "secretPath": "/", "recursive": "true",
            "includeImports": "false", "viewSecretValue": "false", "expandSecretReferences": "false"})
        return [(s["secretPath"].rstrip("/") or "/", s["secretKey"]) for s in data.get("secrets", [])]

    def all_folders(self, env):
        """Every folder of the environment, also the ones that hold no keys of their own."""
        _, data = self.call("GET", "/api/v2/folders", {"projectId": self.project, "environment": env,
                                                       "path": "/", "recursive": "true"})
        return {f["relativePath"] for f in data.get("folders", []) if f.get("relativePath")}

    def importers(self, env, folders):
        out = {}
        for f in folders:
            _, data = self.call("GET", "/api/v2/secret-imports",
                                {"projectId": self.project, "environment": env, "path": f})
            for i in data.get("secretImports", []):
                out.setdefault(i["importPath"], []).append(f)
        return out

    def publish(self, env, path, key, value):
        """Create or update one secret. The value goes only into the request body."""
        name = "/api/v4/secrets/" + urllib.parse.quote(key, safe="")
        status, _ = self.call("GET", name, {"projectId": self.project, "environment": env,
                                            "secretPath": path, "viewSecretValue": "false"}, allow=(404,))
        body = {"projectId": self.project, "environment": env, "secretPath": path, "secretValue": value,
                "skipMultilineEncoding": True, "type": "shared"}
        if status == 404:
            self.call("POST", name, body={**body, "secretComment": "Published by gondr"})
            return "created"
        self.call("PATCH", name, body=body)
        return "updated"


def check_env(cfg, env):
    if env not in cfg.environments:
        die(f"unknown environment {env}", "use one of: " + " ".join(cfg.environments))
    if env in cfg.warn_environments:
        print(f"gondr: using {env} secrets; only for a deploy or release step", file=sys.stderr)
    return env


def check_publish_path(cfg, scope, path):
    roots = [cfg.prefix, cfg.shared, *(b.prefix for b in cfg.boundaries)]
    if not any(path.startswith(r + "/") for r in roots):
        die(f"{path} is outside " + ", ".join(r + "/" for r in roots))
    if any(seg in ("", ".", "..") for seg in path.split("/")[1:]):
        die(f"{path} has an empty, '.' or '..' segment")


def cmd_run(cfg, scope, args):
    opts, cmd = parse(args, ("--env", "--path"))
    if not cmd:
        die("nothing to run", "gondr run -- <command>")
    env = check_env(cfg, opts.get("env", cfg.default_environment))
    path = scope.folder(opts.get("path"))
    client = Client(cfg, scope.project()).login()
    child = {**os.environ, "INFISICAL_TOKEN": client.token}
    # The token authenticates the Infisical CLI only; `env -u` removes it before the command starts.
    argv = ["infisical", "run", f"--domain={cfg.url}/api", f"--projectId={client.project}",
            f"--env={env}", f"--path={path}", "--silent", "--", "env", "-u", "INFISICAL_TOKEN", *cmd]
    try:
        os.execvpe("infisical", argv, child)
    except FileNotFoundError:
        die("the infisical CLI is not on PATH", "install it: https://infisical.com/docs/cli/overview")


def cmd_ls(cfg, scope, args):
    opts, rest = parse(args, ("--env", "--path"))
    env = check_env(cfg, opts.get("env", cfg.default_environment))
    path = scope.folder(rest[0] if rest else opts.get("path"))
    client = Client(cfg, scope.project()).login()
    own, imports = client.list_folder(env, path)
    sub = client.subfolders(env, path)
    print(f"{env}:{path}")
    print(f"  keys ({len(own)}): {' '.join(own) or '-'}")
    for src, keys in imports:
        print(f"  import {src} ({len(keys)}): {' '.join(keys)}")
    if sub:
        print(f"  folders: {' '.join(sub)}")


def cmd_where(cfg, scope, args):
    opts, rest = parse(args, ("--env",))
    if len(rest) != 1:
        die("usage: gondr where <KEY>")
    key, env = rest[0], check_env(cfg, opts.get("env", cfg.default_environment))
    here = scope.boundary()
    client = Client(cfg, scope.project()).login()
    pairs = client.all_secret_paths(env)
    owners = sorted({p for p, k in pairs if k == key and scope.owner_boundary(p) == here})
    if not owners:
        die(f"{key} is not stored in {env}", "ask the operator to add it, or publish it with `gondr set`")
    # An importer can hold no keys of its own, so walk every folder, not only the owners.
    users = client.importers(env, sorted({p for p, _ in pairs} | {"/", cfg.prefix} | client.all_folders(env)))
    for o in owners:
        imp = users.get(o, [])
        print(f"{env}:{o} {key}" + (f"  imported by: {' '.join(sorted(imp))}" if imp else ""))


def cmd_need(cfg, scope, args):
    opts, rest = parse(args, ("--env", "--path", "--from"))
    if len(rest) != 1:
        die("usage: gondr need <KEY>")
    key = rest[0]
    env = check_env(cfg, opts.get("env", cfg.default_environment))
    path = scope.folder(opts.get("path"))
    if "from" in opts:
        scope.guard(scope.absolute(opts["from"]))
    client = Client(cfg, scope.project()).login()
    own, imports = client.list_folder(env, path)
    if key in own or any(key in keys for _, keys in imports):
        print(f"{key} already reaches {env}:{path}")
        return
    here = scope.boundary()
    pool = (here.shared or here.prefix) if here else cfg.shared
    refs = cfg.agent_vault["references_folder"] if cfg.agent_vault else "agent-vault"
    # <shared>/agent-vault is Agent Vault's input folder, not an owner to import from.
    owners = [opts["from"].rstrip("/")] if "from" in opts else sorted(
        {p for p, k in client.all_secret_paths(env)
         if k == key and (p == pool or p.startswith(pool + "/")) and p != f"{cfg.shared}/{refs}"})
    if not owners:
        die(f"no shared owner folder holds {key}", f"`gondr where {key}`; a repo-owned key is not shared by import")
    if len(owners) > 1:
        die(f"{key} is in several shared folders: {' '.join(owners)}", f"gondr need {key} --from <folder>")
    client.call("POST", "/api/v2/secret-imports",
                body={"projectId": client.project, "environment": env, "path": path,
                      "import": {"environment": env, "path": owners[0]}})
    print(f"imported {env}:{owners[0]} into {env}:{path}")


def cmd_set(cfg, scope, args):
    opts, rest = parse(args, ("--env", "--path"))
    if len(rest) != 1:
        die("usage: gondr set <KEY> < value")
    key = rest[0]
    if not KEY.match(key):
        die(f"{key} is not upper snake case")
    env = check_env(cfg, opts.get("env", cfg.default_environment))
    path = scope.folder(opts.get("path"))
    check_publish_path(cfg, scope, path)
    if sys.stdin.isatty():
        die("pipe the value through stdin")
    try:
        value = sys.stdin.buffer.read().decode("utf-8")
    except UnicodeDecodeError:
        die("the value is not UTF-8 text")
    if not value:
        die("the value is empty")
    client = Client(cfg, scope.project()).login()
    print(f"{client.publish(env, path, key, value)} {key} in {env}:{path}")
