"""Per-case sandbox: temp HOME, config, stubs, the subprocess runner and the case registry."""

import hashlib
import json
import os
import pty
import re
from pathlib import Path

from gondr_gate.constants import AGENT_TOKEN, CANARIES, CLIENT_ID, CLIENT_SECRET, PROJECT, PY, SRC, UA_RE
from gondr_gate.stubs import STUB_NAMES, STUB_SRC
from gondr_gate.fake_infisical import Fake


# ---------------------------------------------------------------- sandbox + case


SERVICES_TOML = '''
[services.github]
hosts = ["api.github.com"]
auth = "bearer"
key = "GITHUB_PAT"
shared = "${dev.shared.GITHUB_PAT}"
project_keys = ["GITHUB_PAT", "GITHUB_TOKEN"]

[services.stripe]
key = "STRIPE_API_KEY"

[services.openai]
hosts = ["api.openai.com"]
auth = "bearer"
key = "OPENAI_API_KEY"
shared = "${dev.shared.OPENAI_API_KEY}"
project_keys = ["OPENAI_API_KEY"]
'''

CATALOG = [
    {"id": "github", "host": "api.github.com", "auth_type": "bearer",
     "suggested_credential_key": "GITHUB_TOKEN", "header": ""},
    {"id": "stripe", "host": "api.stripe.com", "auth_type": "bearer",
     "suggested_credential_key": "STRIPE_API_KEY", "header": ""},
    {"id": "posthog", "host": "us.posthog.com", "auth_type": "api-key",
     "suggested_credential_key": "POSTHOG_KEY", "header": "x-api-key"},
]


def config_text(url, *, creds="keychain", token="keychain", boundary=True, services=SERVICES_TOML,
                agent_vault=True, allow_vaults=(), folders=(), factory=None, service_roots=None):
    t = '[infisical]\nurl = "%s"\nproject = "%s"\n' % (url, PROJECT)
    t += 'environments = ["dev", "staging", "prod"]\ndefault_environment = "dev"\nwarn_environments = ["prod"]\n'
    t += '\n[infisical.credentials]\nsource = "%s"\n' % creds
    if creds == "keychain":
        t += ('keychain_account = "gondr"\n'
              'client_id_service = "infisical-client-id"\n'
              'client_secret_service = "infisical-client-secret"\n')
    t += '\n[layout]\nrepos_root = "~/repos"\nprefix = "/repos"\nshared = "/shared"\n'
    if service_roots is not None:
        t += 'service_roots = [%s]\n' % ", ".join('"%s"' % r for r in service_roots)
    if agent_vault:
        t += ('\n[agent_vault]\nbinary = "agent-vault"\naddress = "http://broker:14321"\n'
              'default_vault = "shared"\ngrant_agents = ["my-agent"]\nreferences_folder = "agent-vault"\n')
        if token == "keychain":
            t += 'token = { source = "keychain", account = "my-agent", service = "agent-vault-token" }\n'
        else:
            t += 'token = { source = "env", name = "AGENT_VAULT_TOKEN" }\n'
    t += services
    if folders:
        t += '\n[folders]\n' + ''.join('"%s" = "%s"\n' % kv for kv in folders)
    if boundary:
        t += ('\n[[boundary]]\nname = "Acme"\ndir = "~/repos/acme"\nprefix = "/repos/acme"\n'
              'shared = "/repos/acme/tooling"\nvault_prefix = "acme"\n'
              + ('allow_vaults = [%s]\n' % ", ".join('"%s"' % v for v in allow_vaults) if allow_vaults else "") +
              'deny_agents = ["some-agent", "other-agent", "third-agent"]\n')
    if factory:
        t += '\n[factory]\nbinary = "%s"\n' % factory
    return t


class Run:
    def __init__(self, argv, cwd, code, out, err):
        self.argv, self.cwd, self.code, self.out, self.err = argv, cwd, code, out, err
        self.text = out + err


class Case:
    def __init__(self, cid, fids, tmp):
        self.id, self.fids = cid, fids
        self.checks, self.failures, self.runs = [], [], []
        self.tmp = Path(os.path.realpath(tmp))
        self.fake = Fake()
        self.home = self.tmp / "home"
        self.bin = self.tmp / "bin"
        self.log = self.tmp / "stub.log"
        self.stub_cfg_path = self.tmp / "stub-cfg.json"
        self.config = self.tmp / "cfg" / "config.toml"
        self.canaries = list(CANARIES)
        self.git = {}
        self.stub = {"keychain": {
            "infisical-client-id": CLIENT_ID,
            "infisical-client-secret": CLIENT_SECRET,
            "agent-vault-token": AGENT_TOKEN}, "hashes": {}, "catalog": CATALOG,
            "discover": {"services": [{"name": "stripe", "host": "api.stripe.com"},
                                      {"name": "github", "host": "api.github.com"}],
                         "credentials": ["GITHUB_PAT", "STRIPE_API_KEY"]}}
        for d in (self.home, self.bin, self.config.parent):
            d.mkdir(parents=True)
        self.log.touch()
        for n in STUB_NAMES:
            p = self.bin / n
            p.write_text(STUB_SRC.replace("{py}", PY))
            p.chmod(0o755)
        self.app = self.repo("personal/app")
        self.shop = self.repo("personal/shop")
        self.acme = self.repo("acme/api")
        self.configure()

    # ---- setup helpers
    def repo(self, rel, git=True):
        p = self.home / "repos" / rel
        p.mkdir(parents=True, exist_ok=True)
        if git:
            self.git[str(p)] = str(p / ".git")
        return p

    def configure(self, url=None, **opts):
        self.config.write_text(config_text(url or self.fake.url, **opts))

    def write_stub_cfg(self):
        self.stub["git"] = self.git
        self.stub_cfg_path.write_text(json.dumps(self.stub))

    def env(self, extra=None, unset=()):
        e = {"HOME": str(self.home), "GONDR_CONFIG": str(self.config),
             "PATH": str(self.bin) + os.pathsep + os.path.dirname(PY),
             "PYTHONPATH": str(SRC), "PYTHONDONTWRITEBYTECODE": "1",
             "GONDR_STUB_LOG": str(self.log), "GONDR_STUB_CFG": str(self.stub_cfg_path),
             "KEEP_ME": "inherited-marker"}
        e.update(extra or {})
        for k in unset:
            e.pop(k, None)
        return e

    # ---- running
    def run(self, args, cwd=None, stdin=b"", env=None, unset=(), tty=False, cmd=None):
        import subprocess
        self.write_stub_cfg()
        argv = list(cmd or [PY, "-m", "gondr"]) + list(args)
        cwd = str(cwd or self.app)
        fds = None
        try:
            if tty:
                fds = pty.openpty()
                sin = fds[1]
            else:
                sin = subprocess.PIPE if stdin else subprocess.DEVNULL
            p = subprocess.run(argv, cwd=cwd, env=self.env(env, unset), input=(stdin or None) if not tty else None,
                               stdin=None if (stdin and not tty) else sin, capture_output=True, timeout=45, check=False)
            r = Run(list(args), cwd, p.returncode, p.stdout.decode("utf-8", "replace"),
                    p.stderr.decode("utf-8", "replace"))
        except subprocess.TimeoutExpired:
            r = Run(list(args), cwd, 124, "", "HARNESS: gondr timed out")
        finally:
            if fds:
                for fd in fds:
                    os.close(fd)
        self.runs.append(r)
        self.check("Traceback" not in r.text, "run %d (%s) prints no traceback" % (len(self.runs), " ".join(args[:2])))
        leaked = [c for c in self.canaries if c in r.text]
        self.check(not leaked, "F02/F17/F18 run %d (%s) prints no token, secret, value or body canary"
                   % (len(self.runs), " ".join(args[:2])))
        return r

    # ---- observation
    def check(self, ok, msg):
        self.checks.append(msg)
        if not ok:
            self.failures.append(msg)

    def stubs(self, tool=None):
        out = []
        for line in self.log.read_text().splitlines():
            try:
                e = json.loads(line)
            except ValueError:
                continue
            if tool is None or e["tool"] == tool:
                out.append(e)
        return out

    def clear_stubs(self):
        self.log.write_text("")

    def api(self):
        """Requests other than login."""
        return [r for r in self.fake.reqs if "/auth/" not in r["path"]]

    def writes(self):
        return [r for r in self.api() if r["method"] != "GET"]

    def gets(self, path):
        return [r for r in self.fake.reqs if r["method"] == "GET" and r["path"] == path]

    def posts(self, path):
        return [r for r in self.fake.reqs if r["method"] == "POST" and r["path"] == path]

    def clear_http(self):
        self.fake.reqs.clear()

    def sensitive_stubs(self):
        """Calls that mean Keychain, login-bearing exec or broker use."""
        return [e for e in self.stubs() if e["tool"] in ("security", "infisical", "agent-vault")]

    def finish(self):
        """Invariants that hold for every request of every case."""
        for r in self.fake.reqs:
            if r["path"].startswith("/api/v4/secrets") and r["method"] == "GET":
                if r["query"].get("viewSecretValue") != "false":
                    self.check(False, "F01 GET %s sends viewSecretValue=false" % r["path"])
                if r["path"] == "/api/v4/secrets" and r["query"].get("expandSecretReferences") != "false":
                    self.check(False, "F01 GET /api/v4/secrets sends expandSecretReferences=false")
        if self.fake.reqs:
            bad = [r for r in self.fake.reqs if not UA_RE.match(r["ua"] or "")]
            self.check(not bad, "every request sends User-Agent gondr/<version>")
            self.check(not any(r["query"].get("viewSecretValue") not in (None, "false")
                               for r in self.fake.reqs), "F01 no request asks for secret values")


def sha(s):
    return hashlib.sha256(s.encode()).hexdigest()


CASES = []


def case(fn):
    fids = sorted(set(re.findall(r"(?<![a-z0-9])f(\d\d)(?![0-9])", fn.__name__)))
    CASES.append((fn.__name__, ["F" + f for f in fids], fn))
    return fn


def stops(c, r, name="Acme", code=None):
    """A boundary stop: nonzero exit, boundary named, nothing external touched."""
    okcode = (r.code == code) if code is not None else (r.code != 0)
    c.check(okcode and name in r.text, "F07 %s stop exits %s and names %s (argv %s)"
            % ("boundary", code or "nonzero", name, " ".join(r.argv[:3])))
    c.check("Traceback" not in r.text, "stop prints no traceback")
