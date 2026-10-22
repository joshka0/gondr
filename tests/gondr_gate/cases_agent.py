"""Cases for `agent` (F15-F17)."""

import json

from gondr_gate.constants import AGENT_TOKEN
from gondr_gate.sandbox import case


# ---------------------------------------------------------------- agent


def vault_runs(c):
    return [e for e in c.stubs("agent-vault") if e["argv"][:1] == ["run"]]


@case
def f15_agent_picks_explicit_then_nearest_json_up_to_the_repo_root_then_default(c):
    sub = c.app / "pkg" / "sub"
    sub.mkdir(parents=True)
    cmd = ["childprobe", "--flag", "a b"]

    def attempt(label, want, args=(), cwd=sub):
        c.clear_stubs()
        r = c.run(["agent"] + list(args) + cmd, cwd=cwd)
        runs = vault_runs(c)
        c.check(r.code == 0 and len(runs) == 1 and runs[0]["argv"][:3] == ["run", "--vault", want]
                and runs[0]["env"]["AGENT_VAULT_VAULT"] == want, "F15 %s -> vault %s" % (label, want))

    attempt("no json, no flag", "shared")
    (c.app.parent / "agent-vault.json").write_text(json.dumps({"vault": "above-root-v"}))
    attempt("a json above the repo root is ignored", "shared")
    (c.app / "agent-vault.json").write_text(json.dumps({"vault": "root-v"}))
    attempt("json at the repo root", "root-v")
    (c.app / "pkg" / "agent-vault.json").write_text(json.dumps({"vault": "pkg-v"}))
    attempt("the nearest json wins", "pkg-v")
    attempt("--vault beats every json", "explicit-v", args=["--vault", "explicit-v"])
    attempt("json in the working directory", "root-v", cwd=c.app)
    c.finish()


@case
def f16_agent_stops_denied_agents_and_boundary_mismatches_with_exit_77(c):
    def stop(label, args, cwd):
        c.clear_stubs()
        r = c.run(["agent"] + args, cwd=cwd)
        c.check(r.code == 77 and "Traceback" not in r.text, "F16 %s exits 77" % label)
        c.check(vault_runs(c) == [] and c.stubs("security") == [], "F16 %s: no broker run, no Keychain read" % label)
        return r

    r = stop("Acme dir on the default (non-Acme) vault", ["claude"], c.acme)
    c.check("Acme" in r.text, "F07 the stop names Acme")
    r = stop("Acme dir on an explicit non-Acme vault", ["--vault", "shared", "claude"], c.acme)
    c.check("Acme" in r.text, "F07 the stop names Acme (explicit vault)")
    r = stop("non-Acme dir on a Acme vault", ["--vault", "acme-api-dev", "claude"], c.app)
    c.check("Acme" in r.text, "F07 the stop names Acme (outside)")
    for agent in ("some-agent", "other-agent", "third-agent", "/opt/ai/bin/third-agent"):
        stop("denied agent %s on a Acme vault" % agent, ["--vault", "acme-api-dev", agent, "run"], c.acme)
    (c.acme / "agent-vault.json").write_text(json.dumps({"vault": "shared"}))
    stop("Acme dir whose agent-vault.json names a non-Acme vault", ["claude"], c.acme)
    (c.acme / "agent-vault.json").unlink()
    # controls: the allowed combinations still run
    for label, args, cwd in (("allowed agent on a Acme vault", ["--vault", "acme-api-dev", "claude"], c.acme),
                             ("denied agent name on a non-Acme vault", ["--vault", "shared", "some-agent", "x"], c.app),
                             ("Acme-prefixed vault is checked by prefix", ["--vault", "acme", "codex"], c.acme)):
        c.clear_stubs()
        r = c.run(["agent"] + args, cwd=cwd)
        c.check(r.code == 0 and len(vault_runs(c)) == 1, "control: " + label + " runs")
    c.finish()


@case
def f16_agent_allow_vaults_admit_listed_vaults_in_a_boundary_dir_but_denied_agents_stay_denied(c):
    # (d) without allow_vaults an Acme directory is refused on `shared`
    c.clear_stubs()
    r = c.run(["agent", "claude"], cwd=c.acme)
    c.check(r.code == 77 and "Acme" in r.text and vault_runs(c) == [],
            "F16 without allow_vaults the Acme dir is refused on the default vault `shared` (exit 77, Acme named, no exec)")
    c.configure(allow_vaults=["shared"])
    # (a) a listed vault runs: here through the default vault and through --vault
    for label, args in (("default vault", ["claude", "go"]), ("--vault shared", ["--vault", "shared", "claude", "go"])):
        c.clear_stubs()
        r = c.run(["agent"] + args, cwd=c.acme)
        runs = vault_runs(c)
        c.check(r.code == 0 and len(runs) == 1 and runs[0]["env"]["AGENT_VAULT_VAULT"] == "shared",
                "F16 allow_vaults: the Acme dir runs on `shared` via the %s" % label)
    c.clear_stubs()
    r = c.run(["agent", "--vault", "acme-api-dev", "claude"], cwd=c.acme)
    c.check(r.code == 0 and len(vault_runs(c)) == 1, "allow_vaults does not remove the vault_prefix rule: acme-* still runs")
    # (b) a denied agent is refused inside the boundary, also on the allowed vault
    for agent in ("some-agent", "other-agent", "third-agent", "/opt/ai/bin/third-agent"):
        c.clear_stubs()
        r = c.run(["agent", "--vault", "shared", agent, "go"], cwd=c.acme)
        c.check(r.code == 77 and vault_runs(c) == [] and c.stubs("security") == [],
                "F16 denied agent %s on the allowed vault `shared` inside Acme: exit 77, no exec, no Keychain read" % agent)
    c.clear_stubs()
    r = c.run(["agent", "some-agent", "go"], cwd=c.acme)
    c.check(r.code == 77 and vault_runs(c) == [], "F16 denied agent on the default (allowed) vault inside Acme: exit 77")
    # (c) a vault that is neither acme* nor listed is refused
    for vault in ("team-v", "shared2", "xacme"):
        c.clear_stubs()
        r = c.run(["agent", "--vault", vault, "claude"], cwd=c.acme)
        c.check(r.code == 77 and "Acme" in r.text and vault_runs(c) == [],
                "F16 vault %s is neither acme* nor in allow_vaults: exit 77, Acme named, no exec" % vault)
    # outside every boundary nothing changes
    c.clear_stubs()
    r = c.run(["agent", "--vault", "acme-api-dev", "claude"], cwd=c.app)
    c.check(r.code == 77 and "Acme" in r.text and vault_runs(c) == [], "outside Acme a vault with the acme prefix is still refused")
    c.clear_stubs()
    r = c.run(["agent", "--vault", "shared", "some-agent", "go"], cwd=c.app)
    c.check(r.code == 0 and len(vault_runs(c)) == 1, "control: outside Acme a denied agent name still runs on `shared`")
    c.finish()


@case
def f17_agent_exec_shape_env_and_token_hygiene(c):
    host = "127.0.0.1"
    cmd = ["childprobe", "--task", "two words"]
    r = c.run(["agent", "--vault", "team-v"] + cmd, env={"NO_PROXY": "localhost,.internal", "no_proxy": "localhost"})
    runs = vault_runs(c)
    c.check(r.code == 0 and len(runs) == 1, "agent execs the broker once")
    if runs:
        a = runs[0]["argv"]
        c.check(a[:4] == ["run", "--vault", "team-v", "--"] and a[4:6] == ["/bin/sh", "-c"] and a[7] == "sh"
                and a[8:] == cmd, "broker argv: run --vault V -- /bin/sh -c <script> sh <cmd...>")
        script = a[6] if len(a) > 6 else ""
        c.check("NO_PROXY" in script and "no_proxy" in script and 'exec "$@"' in script,
                "script extends NO_PROXY and no_proxy and execs the command")
        c.check("HOME=" in script and str(c.home) in script and "/usr/bin/env" not in a,
                "the script exports the real HOME itself (no /usr/bin/env)")
        e = runs[0]["env"]
        c.check(e["AGENT_VAULT_ADDR"] == "http://broker:14321" and e["AGENT_VAULT_VAULT"] == "team-v"
                and e["AGENT_VAULT_TELEMETRY"] == "false" and e["AGENT_VAULT_TOKEN"] == AGENT_TOKEN,
                "broker env has ADDR, TOKEN, VAULT and TELEMETRY=false")
        c.check(e["HOME"] not in (None, "", str(c.home)), "broker CLI runs with a gondr state HOME, not the real HOME")
        c.check(AGENT_TOKEN not in json.dumps([x["argv"] for x in c.stubs()]), "F17 the token is in no argv")
    kids = c.stubs("childprobe")
    c.check(len(kids) == 1 and kids[0]["argv"] == cmd[1:], "the command receives its own argv")
    if kids:
        e = kids[0]["env"]
        c.check(e["HOME"] == str(c.home), "the child gets the real HOME back")
        c.check(host in (e["NO_PROXY"] or "") and "localhost" in (e["NO_PROXY"] or "") and ".internal" in (e["NO_PROXY"] or ""),
                "NO_PROXY keeps its old entries and gains the Infisical host")
        c.check(host in (e["no_proxy"] or "") and "localhost" in (e["no_proxy"] or ""),
                "no_proxy keeps its old entries and gains the Infisical host")
    # token from the environment instead of Keychain
    c.clear_stubs()
    c.configure(token="env")
    c.canaries.append("CANARY-ENV-AGENT-TOKEN-02")
    r = c.run(["agent", "claude", "go"], env={"AGENT_VAULT_TOKEN": "CANARY-ENV-AGENT-TOKEN-02"})
    runs = vault_runs(c)
    c.check(r.code == 0 and runs and runs[0]["env"]["AGENT_VAULT_TOKEN"] == "CANARY-ENV-AGENT-TOKEN-02",
            "token source = env passes the env token to the broker")
    c.check(c.stubs("security") == [], "token source = env reads no Keychain")
    c.check("CANARY-ENV-AGENT-TOKEN-02" not in json.dumps([x["argv"] for x in c.stubs()]), "F17 env token is in no argv")
    c.finish()
