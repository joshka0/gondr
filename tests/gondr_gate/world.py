"""Seed data and output parsers shared by the status, find and check cases."""

import re

from gondr_gate.constants import ACME, ACMELIB, APP, OTHER, REFS, UPSTREAM, VENDOR

PERSONAL_OTHER = "/repos/personal/other"
ACME_OTHER = "/repos/acme/other"
STRIPE_NOTES = "/repos/personal/stripe-notes"
KINDS = ["proxied", "env", "import", "repo-owned", "not-mapped"]

# A [services.X] entry that the default vault does not hold: the `not-mapped` route.
CONNECT_SERVICES = '''
[services.stripe-connect]
hosts = ["connect.stripe.com"]
auth = "bearer"
key = "STRIPE_CONNECT_KEY"
'''


def seed_personal(f):
    """Secrets for the personal repo (APP) and, as noise, for a second personal repo and Acme."""
    f.seed(APP, ["LOCAL_KEY", "STRIPE_WEBHOOK_SECRET", "STRIPE_SIGNING_KEY"])
    f.link(APP, UPSTREAM)
    f.seed(UPSTREAM, ["STRIPE_IMPORTED_KEY"])
    f.seed(VENDOR, ["STRIPE_API_KEY", "STRIPE_WEBHOOK_SECRET", "STRIPE_DUAL_KEY"])
    f.seed(OTHER, ["STRIPE_DUAL_KEY"])
    f.seed(REFS, ["STRIPE_REF_KEY"])
    f.seed(PERSONAL_OTHER, ["STRIPE_TEST_KEY", "STRIPE_WEBHOOK_SECRET", "INDENTED_KEY"])
    f.seed(STRIPE_NOTES, ["NOTES_KEY"])  # the folder name matches "stripe", the key name does not
    seed_acme(f)


def seed_acme(f):
    f.seed(ACME, ["STRIPE_ACME_KEY"])
    f.seed(ACMELIB, ["STRIPE_ACME_SHARED"])
    f.seed(ACME_OTHER, ["STRIPE_ACME_OTHER"])


def hit_lines(text):
    """(kind, key or host, route) for each `find` hit line."""
    out = []
    for line in text.splitlines():
        m = re.match(r"^(proxied|env|import|repo-owned|not-mapped) (\S+): (.*)$", line.strip())
        if m:
            out.append(m.groups())
    return out
