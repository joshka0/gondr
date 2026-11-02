"""Harness for the Keeper store cases: the fake SDK world, config builder and runner.

The fake SDK lives in tests/fake_ksm (a package named keeper_secrets_manager_core). Only Keeper
cases put it on the PYTHONPATH of gondr. tests/fake_ksm_absent holds a package of the same name
that fails to import, so "SDK not installed" holds also on a machine that has the real SDK.
Folders, records and values live in a JSON file in the sandbox; the fake logs every call.
"""

import json
import os
from pathlib import Path

from gondr_gate.constants import SRC
from gondr_gate.sandbox import config_text

TESTS = Path(__file__).resolve().parents[1]
FAKE_SDK = TESTS / "fake_ksm"
ABSENT_SDK = TESTS / "fake_ksm_absent"

SHARED = "SHARED-UID-0001"          # the folder in [keeper] shared_folder (parent_uid None)
OTHER_SHARED = "SHARED-UID-OTHER"   # a second shared folder the app can see (parent_uid "")
KSM_CONFIG = "Q0FOQVJZLUtTTS1DT05GSUctYTRkMQ=="
KSM_CONFIG_SERVICE = "keeper-ksm-config"
SDK_ERROR_TEXT = "SDK-ERROR-TEXT-CANARY-5c72"
WRITE_CALLS = ("create_folder", "create_secret_with_options", "save", "set_standard_field_value")


def keeper_config(url, *, infisical=False, config="keychain", extra="", **opts):
    """The default test config with `[store] kind = "keeper"`; the [infisical] table only if asked."""
    text = config_text(url, **opts)
    head, rest = text.split("\n[layout]", 1)
    kc = ('config = { source = "keychain", account = "gondr", service = "%s" }' % KSM_CONFIG_SERVICE
          if config == "keychain" else 'config = { source = "env", name = "KSM_CONFIG" }')
    store = '[store]\nkind = "keeper"\n\n[keeper]\nshared_folder = "%s"\n%s\n%s\n' % (SHARED, kc, extra)
    return store + (head + "\n" if infisical else "") + "\n[layout]" + rest


def setup(c, **opts):
    """Switch the sandbox to a Keeper config and a seeded fake SDK; returns the world."""
    c.config.write_text(keeper_config(c.fake.url, **opts))
    c.stub["keychain"][KSM_CONFIG_SERVICE] = KSM_CONFIG
    if KSM_CONFIG not in c.canaries:
        c.canaries.append(KSM_CONFIG)
    c.ksm = World(c)
    return c.ksm


class World:
    def __init__(self, c):
        self.c = c
        self.dir = c.tmp / "ksm"
        self.dir.mkdir(exist_ok=True)
        self.state_path = self.dir / "state.json"
        self.log_path = self.dir / "calls.jsonl"
        self.log_path.touch()
        self.s = {"shared": [SHARED, OTHER_SHARED], "records": [], "raise": {}, "folders": [
            {"folder_uid": SHARED, "parent_uid": None, "name": "gondr-secrets", "shared_uid": SHARED},
            {"folder_uid": OTHER_SHARED, "parent_uid": "", "name": "someone-elses", "shared_uid": OTHER_SHARED}]}
        self.n = 0
        self.flush()

    def flush(self):
        self.state_path.write_text(json.dumps(self.s))

    def uid(self, shared, chain):
        return "D-%s-%s" % (shared[-5:], "-".join(chain))

    def folder(self, chain, shared=SHARED):
        """Make the folder chain (env first), parents first; returns the leaf uid or None for the root."""
        parent = shared
        for i in range(len(chain)):
            uid = self.uid(shared, chain[:i + 1])
            if not any(f["folder_uid"] == uid for f in self.s["folders"]):
                self.s["folders"].append({"folder_uid": uid, "parent_uid": parent, "name": chain[i],
                                          "shared_uid": shared})
            parent = uid
        return parent if chain else None

    def add(self, env, path, title, password, rtype="login", shared=SHARED, extra_fields=None):
        chain = [env] + [s for s in path.split("/") if s] if env else [s for s in path.split("/") if s]
        inner = self.folder(chain, shared) if chain else None
        self.n += 1
        if password not in self.c.canaries:
            self.c.canaries.append(password)
        fields = {"password": password}
        fields.update(extra_fields or {})
        self.s["records"].append({"uid": "R-seed-%d" % self.n, "title": title, "type": rtype,
                                  "folder_uid": shared, "inner_folder_uid": inner, "fields": fields})
        self.flush()

    def keys(self, env, path, mapping, **kw):
        for k, v in mapping.items():
            self.add(env, path, k, v, **kw)

    def ksm_log(self, text):
        """Make the fake SDK warn on the `ksm` logger at import and at the start of SecretsManager()."""
        if text not in self.c.canaries:
            self.c.canaries.append(text)
        self.s["ksm_log"] = text
        self.flush()

    def fail(self, where, type_name="KsmCanaryError", message=SDK_ERROR_TEXT):
        self.s["raise"][where] = {"type": type_name, "message": message}
        self.flush()

    # ---- observation
    def state(self):
        try:
            return json.loads(self.state_path.read_text())
        except (OSError, ValueError):
            return self.s

    def calls(self, name=None):
        out = []
        for line in self.log_path.read_text().splitlines():
            try:
                e = json.loads(line)
            except ValueError:
                continue
            if name is None or e.get("call") == name:
                out.append(e)
        return out

    def writes(self):
        return [e for e in self.calls() if e["call"] in WRITE_CALLS]

    def clear(self):
        self.log_path.write_text("")

    def find_folder(self, env, path):
        """The uid of the folder dev/<segments> under the shared folder, found by name; None if absent."""
        uid = SHARED
        for name in [env] + [s for s in path.split("/") if s]:
            nxt = [f["folder_uid"] for f in self.state()["folders"] if f["parent_uid"] == uid and f["name"] == name]
            if len(nxt) != 1:
                return None
            uid = nxt[0]
        return uid

    def rows(self, env, path, title=None):
        uid = self.find_folder(env, path)
        return [r for r in self.state()["records"] if r["folder_uid"] == SHARED and r["inner_folder_uid"] == uid
                and (title is None or r["title"] == title)]

    def titles(self, env, path):
        return sorted(r["title"] for r in self.rows(env, path))

    def password(self, env, path, title):
        return [r["fields"].get("password") for r in self.rows(env, path, title)]

    def snapshot(self):
        s = self.state()
        return json.dumps([s["folders"], s["records"]], sort_keys=True)


def run(c, args, sdk="fake", env=None, **kw):
    """Run gondr with the fake SDK (sdk="fake"), a blocked SDK ("absent") or no SDK path ("none")."""
    e = {"GONDR_FAKE_KSM_STATE": str(c.ksm.state_path), "GONDR_FAKE_KSM_LOG": str(c.ksm.log_path)}
    path = {"fake": [FAKE_SDK], "absent": [ABSENT_SDK], "none": []}[sdk]
    e["PYTHONPATH"] = os.pathsep.join([str(p) for p in path] + [str(SRC)])
    e.update(env or {})
    return c.run(args, env=e, **kw)


def lines_of(r):
    return [ln.strip() for ln in r.out.splitlines()]


def untouched_infisical(c, label):
    c.check(c.fake.reqs == [], "F45 no request reaches Infisical: " + label)
    bad = [e for e in c.stubs("infisical")]
    c.check(bad == [], "F45 no infisical process: " + label)
    ids = [e for e in c.stubs("security") if "infisical" in " ".join(e["argv"])]
    c.check(ids == [], "F45 no Infisical credential read from Keychain: " + label)


def value(key, env="dev", where="app"):
    """A stored value that no command may print."""
    return "CANARY-KSM-VALUE-%s-%s-%s-8e41" % (key, env, where)


APP, VENDOR, SHOP = "/repos/personal/app", "/shared/vendor", "/repos/personal/shop"
ACME_API, ACME_LIB = "/repos/acme/api", "/repos/acme/tooling/lib"


def seed_standard(c):
    """Keys in the places a command must read, and decoys in the places it must not."""
    w = c.ksm
    for k in ("LOCAL_KEY", "STRIPE_WEBHOOK_SECRET", "DATABASE_URL"):
        w.add("dev", APP, k, value(k))
    for title in ("lowercase note", "Mixed_Case", "has space", "9_LEADING_DIGIT"):
        w.add("dev", APP, title, value("NONKEY", where=title.replace(" ", "")))
    w.add("dev", APP + "/pkg", "DEEP_KEY", value("DEEP_KEY"))
    w.folder(["dev"] + APP.split("/")[1:] + ["zdir"])
    w.add("dev", VENDOR, "VENDOR_KEY", value("VENDOR_KEY"))
    w.add("dev", VENDOR, "LOCAL_KEY", value("LOCAL_KEY", where="vendor"))
    w.add("staging", APP, "LOCAL_KEY", value("LOCAL_KEY", "staging"))
    w.add("staging", APP, "STAGING_ONLY_KEY", value("STAGING_ONLY_KEY", "staging"))
    w.add("dev", ACME_API, "ACME_KEY", value("ACME_KEY"))
    w.add("dev", ACME_API, "LOCAL_KEY", value("LOCAL_KEY", where="acme"))
    w.add("dev", ACME_LIB, "ACME_SHARED_KEY", value("ACME_SHARED_KEY"))
    w.add("prod", APP, "PROD_ONLY_KEY", value("PROD_ONLY_KEY", "prod"))
    # decoys: none of these is the folder dev:/repos/personal/app under the shared folder
    w.add("dev", APP, "FOREIGN_KEY", value("FOREIGN_KEY", where="othershared"), shared=OTHER_SHARED)
    w.add("dev", APP, "LOCAL_KEY", value("LOCAL_KEY", where="othershared"), shared=OTHER_SHARED)
    w.add(None, "app/personal/repos", "ORDER_DECOY_KEY", value("ORDER_DECOY_KEY"))
    w.add("dev", "app/personal/repos", "ORDER_DECOY2_KEY", value("ORDER_DECOY2_KEY"))
    w.add(None, "repos/dev/personal/app", "ENV_DECOY_KEY", value("ENV_DECOY_KEY"))
    w.add(None, "repos/personal/app/dev", "ENV_DECOY2_KEY", value("ENV_DECOY2_KEY"))
    w.add(None, "", "ROOT_LEVEL_KEY", value("ROOT_LEVEL_KEY"))
    w.add("dev", "/repos/personal", "PARENT_LEVEL_KEY", value("PARENT_LEVEL_KEY"))
    w.add("dev", "", "ENV_ROOT_KEY", value("ENV_ROOT_KEY"))
    return w


DECOYS = ["FOREIGN_KEY", "ORDER_DECOY_KEY", "ORDER_DECOY2_KEY", "ENV_DECOY_KEY", "ENV_DECOY2_KEY",
          "ROOT_LEVEL_KEY", "PARENT_LEVEL_KEY", "ENV_ROOT_KEY", "DEEP_KEY"]
APP_KEYS = ["DATABASE_URL", "LOCAL_KEY", "STRIPE_WEBHOOK_SECRET"]
