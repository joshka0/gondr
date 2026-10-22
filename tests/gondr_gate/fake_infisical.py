"""Fake Infisical server on 127.0.0.1. Records every request."""

import http.server
import json
import re
import threading
import urllib.parse

from gondr_gate.constants import CLIENT_SECRET, LEAK_VALUE, POISON, TOKEN, VALUE_CORE


POISON_BODY = (b'{"message":"' + POISON.encode() + b" " + TOKEN.encode() + b" "
               + CLIENT_SECRET.encode() + b" " + VALUE_CORE.encode() + b' \xff\xfe\x80"}')


class Fake:
    """Fake Infisical on 127.0.0.1. Records every request. Seed with .secrets/.imports."""

    def __init__(self):
        self.reqs = []
        self.secrets = {}   # (env, path) -> [key names]
        self.imports = {}   # (env, path) -> [(src env, src path)]
        self.extra_dirs = set()  # (env, path)
        self.fail = []      # (method, path regex, status)
        self.leak = False
        outer = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, format, *args):
                pass

            def handle_any(self):
                u = urllib.parse.urlsplit(self.path)
                q = {k: (v[0] if len(v) == 1 else v)
                     for k, v in urllib.parse.parse_qs(u.query, keep_blank_values=True).items()}
                n = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(n) if n else b""
                try:
                    body = json.loads(raw) if raw else None
                except ValueError:
                    body = {"_unparsable": raw.decode("utf-8", "replace")}
                outer.reqs.append({"method": self.command, "path": u.path, "query": q, "body": body,
                                   "ua": self.headers.get("User-Agent"),
                                   "authorization": self.headers.get("Authorization")})
                status, payload = outer.route(self.command, u.path, q, body)
                data = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.send_header("X-Canary", TOKEN)
                if status == 429:
                    self.send_header("Retry-After", "0")
                self.end_headers()
                self.wfile.write(data)

            do_GET = do_POST = do_PATCH = do_PUT = do_DELETE = handle_any

        self.srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.srv.server_address[1]
        self.url = "http://127.0.0.1:%d" % self.port
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def close(self):
        self.srv.shutdown()
        self.srv.server_close()

    # ---- data helpers
    def seed(self, path, keys, env="dev"):
        self.secrets.setdefault((env, path), []).extend(keys)

    def link(self, dest, src, env="dev"):
        self.imports.setdefault((env, dest), []).append((env, src))

    def _row(self, key, path):
        row = {"secretKey": key, "secretPath": path, "type": "shared", "version": 1}
        if self.leak:
            row["secretValue"] = LEAK_VALUE
            row["secretValueHidden"] = False
        return row

    def _all_paths(self, env):
        paths = {p for (e, p) in list(self.secrets) + list(self.imports) + list(self.extra_dirs) if e == env}
        out = set()
        for p in paths:
            parts = [s for s in p.split("/") if s]
            for i in range(len(parts) + 1):
                out.add("/" + "/".join(parts[:i]))
        return out

    def _folders(self, env, path, recursive):
        """Items as Infisical Cloud returns them: relativePath is relative to the queried path, no `path` field."""
        base = path.rstrip("/")
        out = []
        for p in sorted(self._all_paths(env)):
            if p == "/" or not p.startswith(base + "/"):
                continue
            rel = p[len(base):]
            if not recursive and "/" in rel[1:]:
                continue
            out.append({"id": "d-" + p, "name": p.rsplit("/", 1)[1], "version": 1, "parentId": "d-parent",
                        "envId": "e-" + env, "description": None, "isReserved": False,
                        "lastSecretModified": "2026-10-22T00:00:00.000Z", "relativePath": rel,
                        "createdAt": "2026-10-22T00:00:00.000Z", "updatedAt": "2026-10-22T00:00:00.000Z"})
        return out

    def route(self, method, path, q, body):
        for entry in self.fail:  # (method, path regex, status[, times]); times=None means always
            m, pat, status = entry[:3]
            if m == method and re.fullmatch(pat, path):
                if len(entry) > 3 and entry[3] is not None:
                    if entry[3] <= 0:
                        continue
                    self.fail[self.fail.index(entry)] = entry[:3] + (entry[3] - 1,)
                return status, POISON_BODY
        env, spath = q.get("environment"), q.get("secretPath", "/")
        if path == "/api/v1/auth/universal-auth/login" and method == "POST":
            return 200, {"accessToken": TOKEN, "expiresIn": 7200, "accessTokenMaxTTL": 7200,
                         "tokenType": "Bearer"}
        if path == "/api/v4/secrets" and method == "GET":
            if q.get("recursive") == "true":
                base = spath.rstrip("/")
                rows = [self._row(k, p) for (e, p), keys in sorted(self.secrets.items())
                        if e == env and (p == spath or p.startswith(base + "/")) for k in keys]
            else:
                rows = [self._row(k, spath) for k in self.secrets.get((env, spath), [])]
            imps = []
            if q.get("includeImports") == "true":
                for ie, ip in self.imports.get((env, spath), []):
                    imps.append({"secretPath": ip, "environment": ie, "folderId": "f-" + ip,
                                 "secrets": [self._row(k, ip) for k in self.secrets.get((ie, ip), [])]})
            return 200, {"secrets": rows, "imports": imps}
        m = re.fullmatch(r"/api/v4/secrets/([^/]+)", path)
        if m:
            key = m.group(1)
            have = key in self.secrets.get((body.get("environment") if body else env,
                                            body.get("secretPath") if body else spath), [])
            if method == "GET":
                if have:
                    return 200, {"secret": self._row(key, spath)}
                return 404, {"statusCode": 404, "message": "Secret not found", "error": "NotFound"}
            if method in ("POST", "PATCH") and body:
                self.secrets.setdefault((body["environment"], body["secretPath"]), [])
                if key not in self.secrets[(body["environment"], body["secretPath"])]:
                    self.secrets[(body["environment"], body["secretPath"])].append(key)
                return 200, {"secret": self._row(key, body["secretPath"])}
        if path == "/api/v2/folders":
            if method == "GET":
                return 200, {"folders": self._folders(env, q.get("path", "/"), q.get("recursive") == "true")}
            if method == "POST" and body:
                full = body["path"].rstrip("/") + "/" + body["name"]
                self.extra_dirs.add((body["environment"], full))
                return 200, {"folder": {"id": "d-new", "name": body["name"], "path": full}}
        if path == "/api/v2/secret-imports":
            if method == "GET":
                return 200, {"secretImports": [
                    {"id": "i-" + ip, "importPath": ip, "importEnv": {"slug": ie, "name": ie},
                     "isReplication": False} for ie, ip in self.imports.get((env, q.get("path", "/")), [])]}
            if method == "POST" and body:
                self.imports.setdefault((body["environment"], body["path"]), []).append(
                    (body["import"]["environment"], body["import"]["path"]))
                return 200, {"message": "created", "secretImport": {"id": "i-new"}}
        if path.startswith("/v1/"):  # broker HTTP, only if gondr talks to the broker address itself
            return 200, {}
        return 404, {"message": "unknown route in fake: %s %s" % (method, path)}
