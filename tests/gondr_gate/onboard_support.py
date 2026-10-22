"""Fixtures and helpers shared by the onboard cases."""

import hashlib
import json
import re
from pathlib import Path

from gondr_gate.constants import SHOP
from gondr_gate.sandbox import sha


# ---------------------------------------------------------------- onboard

PLAN_RE = re.compile(r"^plan (\S+): (.+?) <- (.+?) \((.+)\)\s*$")


def onboard_setup(c, gh_equal):
    c.fake.seed(SHOP, ["GITHUB_TOKEN", "STRIPE_API_KEY"])
    c.fake.seed("/shared", ["GITHUB_PAT"])
    c.stub["hashes"] = {
        SHOP: {"GITHUB_TOKEN": sha("github-value-A"), "STRIPE_API_KEY": sha("stripe-value-1")},
        "/shared": {"GITHUB_PAT": sha("github-value-A" if gh_equal else "github-value-B")},
    }
    adm = c.tmp / "admin-home"
    # Spec: a logged-in admin HOME holds .agent-vault/session.json with the broker address and token.
    # The address points at the fake so no traffic leaves 127.0.0.1.
    (adm / ".agent-vault").mkdir(parents=True, exist_ok=True)
    (adm / ".agent-vault" / "session.json").write_text(
        json.dumps({"address": c.fake.url, "token": "synthetic-admin-token"}))
    if "synthetic-admin-token" not in c.canaries:
        c.canaries.append("synthetic-admin-token")
    return adm


def plans(r):
    out = {}
    for line in r.out.splitlines():
        m = PLAN_RE.match(line.strip())
        if m:
            out[m.group(1)] = m.groups()[1:]
    return out


def snapshot(root):
    snap = {}
    for p in sorted(Path(root).rglob("*")):
        if p.is_file():
            st = p.stat()
            snap[str(p)] = (st.st_size, st.st_mtime_ns, hashlib.sha256(p.read_bytes()).hexdigest())
        else:
            snap[str(p)] = "dir"
    return snap


def broker_mutations(c):
    read_only = {"catalog", "list", "ls", "get", "show", "version", "--version", "--help"}
    return [e for e in c.stubs("agent-vault") if not (set(e["argv"]) & read_only)]
