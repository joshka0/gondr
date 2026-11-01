#!/usr/bin/env python3
"""Black-box gate for gondr. Derived from docs/spec.md only.

Run from the repo root:
    python3 tests/gate.py --report <new report path>

Every case runs `python3 -m gondr ...` as a subprocess with a temp HOME, a temp
config, stub executables for git/security/infisical/agent-vault, and a fake
Infisical server on 127.0.0.1. No live service, credential or Keychain is used.
Optional: GONDR_SRC overrides the PYTHONPATH entry (default <repo>/src).
The harness lives in tests/gondr_gate; each cases_*.py module holds one feature group.
"""
import importlib
import sys

sys.dont_write_bytecode = True

# Importing a cases_* module registers its cases, in this order.
CASE_MODULES = [
    "cases_ls_where_need",
    "cases_set_run",
    "cases_config_credentials",
    "cases_boundaries",
    "cases_agent",
    "cases_errors",
    "cases_onboard",
    "cases_folders",
    "cases_missing_folders",
    "cases_status",
    "cases_find",
    "cases_check",
    "cases_token",
    "cases_service_roots",
]

if __name__ == "__main__":
    for name in CASE_MODULES:
        importlib.import_module("gondr_gate." + name)
    from gondr_gate.report import main

    sys.exit(main(__doc__))
