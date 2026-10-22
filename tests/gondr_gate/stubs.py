"""Source of the stub executables (git, security, infisical, agent-vault and probe children)."""


STUB_NAMES = ["git", "security", "infisical", "agent-vault",
              "childprobe", "claude", "codex", "some-agent", "other-agent", "third-agent"]

STUB_SRC = r'''#!{py}
import json, os, sys
name = os.path.basename(sys.argv[0])
argv = sys.argv[1:]
cfg = {}
try:
    cfg = json.load(open(os.environ["GONDR_STUB_CFG"]))
except Exception:
    pass
stdin = ""
try:
    if name not in ("git", "security") and not sys.stdin.isatty():
        stdin = sys.stdin.buffer.read().decode("utf-8", "replace")
except Exception:
    pass
SEL = ("HOME", "INFISICAL_TOKEN", "AGENT_VAULT_ADDR", "AGENT_VAULT_TOKEN", "AGENT_VAULT_VAULT",
       "AGENT_VAULT_TELEMETRY", "NO_PROXY", "no_proxy", "KEEP_ME", "HTTPS_PROXY")
entry = {"tool": name, "argv": argv, "cwd": os.getcwd(), "stdin": stdin,
         "env": {k: os.environ.get(k) for k in SEL}}
with open(os.environ["GONDR_STUB_LOG"], "a") as f:
    f.write(json.dumps(entry) + "\n")

if name == "git":
    if "--git-common-dir" in argv or "--show-toplevel" in argv:
        cwd = os.path.realpath(os.getcwd())
        best = None
        for d, common in cfg.get("git", {}).items():
            if cwd == d or cwd.startswith(d + os.sep):
                if best is None or len(d) > len(best[0]):
                    best = (d, common)
        if best:
            print(best[1] if "--git-common-dir" in argv else best[0])
            sys.exit(0)
        sys.stderr.write("fatal: not a git repository (or any of the parent directories): .git\n")
        sys.exit(128)
    sys.exit(0)
if name == "security":
    svc = argv[argv.index("-s") + 1] if "-s" in argv else None
    val = cfg.get("keychain", {}).get(svc)
    if val is None:
        sys.stderr.write("security: The specified item could not be found in the keychain.\n")
        sys.exit(44)
    print(val)
    sys.exit(0)
if name == "infisical":
    if "--" in argv:
        i = argv.index("--")
        head, tail = argv[:i], argv[i + 1:]
        py = next((k for k, a in enumerate(tail) if os.path.basename(a).startswith("python")), None)
        if py is not None and "-c" in tail[py:]:
            path = None
            for j, a in enumerate(head):
                if a.startswith("--path="):
                    path = a[len("--path="):]
                elif a == "--path" and j + 1 < len(head):
                    path = head[j + 1]
            c = tail.index("-c", py)
            names = tail[c + 2:]
            table = cfg.get("hashes", {}).get(path, {})
            out = {n: table[n] for n in (names or list(table)) if n in table}
            print("[info] injecting secrets")
            print(json.dumps(out))
            print("done")
            sys.exit(0)
        if tail:
            if tail[0] == "env":
                tail[0] = "/usr/bin/env"
            os.execvp(tail[0], tail)
    sys.exit(0)
if name == "agent-vault":
    if argv[:1] == ["catalog"]:
        print(json.dumps(cfg.get("catalog", [])))
        sys.exit(0)
    if argv[:2] == ["vault", "discover"]:
        d = cfg.get("discover", {})
        if d.get("exit"):
            sys.stderr.write("agent-vault: discover failed\n")
            sys.exit(d["exit"])
        if d.get("bad_json"):
            print("this is { not json")
            sys.exit(0)
        print(json.dumps({"vault": os.environ.get("AGENT_VAULT_VAULT"), "services": d.get("services", []),
                          "available_credentials": d.get("credentials", [])}))
        sys.exit(0)
    if argv[:1] == ["run"] and "--" in argv:
        tail = argv[argv.index("--") + 1:]
        os.execv(tail[0], tail)
    sys.exit(0)
sys.exit(0)
'''
