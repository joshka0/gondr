"""Runs every registered case and writes the JSON report."""

import argparse
import hashlib
import json
import shutil
import sys
import tempfile
from pathlib import Path

from gondr_gate.constants import AGENT_TOKEN, CLIENT_SECRET, ROOT, SRC, TOKEN
from gondr_gate.sandbox import CASES, Case


# ---------------------------------------------------------------- main


def redact_http(reqs):
    out = []
    for q in reqs:
        d = {k: q[k] for k in ("method", "path", "query", "ua")}
        d["body"] = "<auth omitted>" if "/auth/" in q["path"] else q["body"]
        out.append(d)
    return out


def redact_stubs(entries):
    secret_keys = {"INFISICAL_TOKEN", "AGENT_VAULT_TOKEN"}
    out = []
    for e in entries:
        e = dict(e)
        e["env"] = {k: ("<set>" if (k in secret_keys and v) else v) for k, v in e["env"].items()}
        e["argv"] = ["<redacted>" if any(x in a for x in (TOKEN, AGENT_TOKEN, CLIENT_SECRET)) else a
                     for a in e["argv"]]
        e["stdin"] = "<%d bytes>" % len(e["stdin"])
        out.append(e)
    return out


def run_case(name, fids, fn):
    tmp = tempfile.mkdtemp(prefix="gondr-gate-")
    c = None
    try:
        c = Case(name, fids, tmp)
        status, err = "GREEN", None
        try:
            fn(c)
            if not c.checks:
                raise RuntimeError("case made no checks")
            if c.failures:
                status = "RED"
        except Exception as exc:  # noqa: BLE001 - harness fault, not a product verdict
            status, err = "HARNESS_ERROR", "%s: %s" % (type(exc).__name__, exc)
            c.failures.append(err)
        trimmed = [{"argv": r.argv, "cwd": r.cwd, "exit": r.code, "stdout": r.out[:1500], "stderr": r.err[:1500]}
                   for r in c.runs]
        return {"id": name, "fids": fids, "status": status, "checks": c.checks, "failures": c.failures,
                "runs": trimmed, "http": redact_http(c.fake.reqs),
                "stub_calls": redact_stubs(c.stubs()) if c.log.exists() else []}
    finally:
        if c is not None:
            c.fake.close()
        shutil.rmtree(tmp, ignore_errors=True)


def main(description):
    ap = argparse.ArgumentParser(description=description, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--report", type=Path, required=True)
    ap.add_argument("--only", help="run only cases whose name contains this text")
    args = ap.parse_args()
    gate_dir = Path(__file__).resolve().parents[1]
    gate_files = [gate_dir / "gate.py"] + sorted((gate_dir / "gondr_gate").glob("*.py"))
    if args.report.exists():
        ap.error("refusing to overwrite an existing report; choose a new path")
    results = []
    covered = set()
    for name, fids, fn in CASES:
        if args.only and args.only not in name:
            continue
        res = run_case(name, fids, fn)
        results.append(res)
        covered |= set(fids)
        print("%-13s %-12s %s%s" % (res["status"], ",".join(fids) or "-", name,
                                    ("  :: " + "; ".join(res["failures"][:3])) if res["failures"] else ""))
    statuses = [r["status"] for r in results]
    status = ("HARNESS_ERROR" if "HARNESS_ERROR" in statuses else "RED" if "RED" in statuses else "GREEN")
    missing = sorted({"F%02d" % i for i in range(1, 23)} - covered)
    if missing and not args.only:
        status = "HARNESS_ERROR"
        print("HARNESS_ERROR: failure-list items without a case: " + ", ".join(missing))
    report = {
        "status": status,
        "command": "python3 tests/gate.py --report " + str(args.report),
        "cwd": str(ROOT),
        "python": sys.version.split()[0],
        "src": str(SRC),
        "gate_sha256": hashlib.sha256(b"".join(f.read_bytes() for f in gate_files)).hexdigest(),
        "spec_sha256": hashlib.sha256((ROOT / "docs" / "spec.md").read_bytes()).hexdigest(),
        "counts": {s: statuses.count(s) for s in ("GREEN", "RED", "HARNESS_ERROR")},
        "failure_list_covered": sorted(covered),
        "boundary": "Synthetic black-box verification: stub executables, fake Infisical on 127.0.0.1, no live service.",
        "cases": results,
    }
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + "\n")
    print("%s %s %s" % (status, json.dumps(report["counts"]), args.report))
    return {"GREEN": 0, "RED": 1}.get(status, 2)
