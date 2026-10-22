"""Paths, canary strings and fixture folders shared by every case."""

import os
import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SRC = Path(os.environ.get("GONDR_SRC", ROOT / "src")).resolve()
PY = os.path.realpath(sys.executable)

# Canaries: none of these may appear in any stdout/stderr (F02, F17, F18).
TOKEN = "CANARY-ACCESS-TOKEN-4f1a"
CLIENT_ID = "CANARY-CLIENT-ID-9c2e"
CLIENT_SECRET = "CANARY-CLIENT-SECRET-71bd"
AGENT_TOKEN = "CANARY-AGENT-TOKEN-b08d"
VALUE_CORE = "CANARY-SECRET-VALUE-e5a7"
LEAK_VALUE = "CANARY-LEAKED-API-VALUE-33f0"
POISON = "CANARY-RESPONSE-BODY-6d19"
CANARIES = [TOKEN, CLIENT_ID, CLIENT_SECRET, AGENT_TOKEN, VALUE_CORE, LEAK_VALUE, POISON]
# Written byte for byte by `set`: leading space, CRLF, trailing blanks, non-ASCII.
SET_VALUE = " " + VALUE_CORE + "é\r\n  tail \n\n"

PROJECT = "proj-config-123"
APP, SHOP = "/repos/personal/app", "/repos/personal/shop"
ACME, ACMELIB = "/repos/acme/api", "/repos/acme/tooling/lib"
VENDOR, UPSTREAM, OTHER = "/shared/vendor", "/shared/upstream", "/shared/other"
REFS = "/shared/agent-vault"
UA_RE = re.compile(r"^gondr/\S+")
