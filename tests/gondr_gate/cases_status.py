"""Cases for `status` and vault discovery (F23-F25)."""

import json
import re

from gondr_gate.constants import ACME, AGENT_TOKEN, APP, PROJECT, VENDOR
from gondr_gate.sandbox import case

HOST_LINE = re.compile(r"^  host \S+ \(", re.MULTILINE)
USE_BLOCK = ["  env var  -> gondr run -- <cmd>",
             "  host     -> gondr agent <agent>; call https://<host> with no auth header",
             "  other    -> gondr find <what>"]


def seed_status(c, env="dev"):
    c.fake.seed(APP, ["LOCAL_KEY", "DATABASE_URL"], env=env)
    c.fake.seed(VENDOR, ["VENDOR_KEY", "ZETA"], env=env)
    c.fake.link(APP, VENDOR, env=env)


def discovers(c):
    return [e for e in c.stubs("agent-vault") if e["argv"][:2] == ["vault", "discover"]]


def status_json(c, args, cwd=None):
    r = c.run(["status", "--json"] + args, cwd=cwd)
    try:
        doc = json.loads(r.out)
    except ValueError:
        doc = {}
    return r, doc


@case
def f23_f24_status_text_has_repo_boundary_infisical_vault_and_use_block_in_order(c):
    seed_status(c)
    r = c.run(["status"])
    lines = [ln.rstrip() for ln in r.out.splitlines()]

    def at(pred):
        return next((i for i, ln in enumerate(lines) if pred(ln)), -1)

    marks = [
        at(lambda ln: ln == "repo: %s" % c.app),
        at(lambda ln: ln.startswith("boundary: -")),
        at(lambda ln: ln == "infisical: dev:%s (project %s)" % (APP, PROJECT)),
        at(lambda ln: re.match(r"^\s+keys \(2\): DATABASE_URL LOCAL_KEY$", ln) is not None),
        at(lambda ln: re.match(r"^\s+import %s \(2\): VENDOR_KEY ZETA$" % VENDOR, ln) is not None),
        at(lambda ln: ln == "vault: shared (default)"),
        at(lambda ln: ln == "  proxied here: no"),
        at(lambda ln: ln == "  host api.github.com (github)"),
        at(lambda ln: ln == "  host api.stripe.com (stripe)"),
        at(lambda ln: ln.strip() == "use:"),
    ]
    c.check(r.code == 0 and all(m >= 0 for m in marks) and marks == sorted(marks),
            "status prints repo, boundary, infisical, keys, import, vault, proxied here, hosts sorted by host, use (positions %s)"
            % marks)
    use = marks[-1]
    c.check(use >= 0 and lines[use + 1:use + 4] == USE_BLOCK, "the use: block holds the three fixed lines")
    c.check(len(c.posts("/api/v1/auth/universal-auth/login")) == 1 and len(c.gets("/api/v2/folders")) <= 1
            and len(c.gets("/api/v4/secrets")) == 1, "status sends one login and one list of the folder (at most one folders GET)")
    c.check(c.writes() == [], "F23 status makes no state-changing request")
    d = discovers(c)
    c.check(len(d) == 1 and d[0]["argv"] == ["vault", "discover", "--json"], "discovery runs `vault discover --json` once")
    if d:
        e = d[0]["env"]
        c.check(e["AGENT_VAULT_ADDR"] == "http://broker:14321" and e["AGENT_VAULT_VAULT"] == "shared"
                and e["AGENT_VAULT_TOKEN"] == AGENT_TOKEN and e["AGENT_VAULT_TELEMETRY"] == "false",
                "discovery gets ADDR, VAULT, TOKEN and TELEMETRY=false")
        c.check((e["HOME"] or "").endswith("agent-vault-home") and e["HOME"] != str(c.home),
                "discovery runs with HOME=<gondr state folder>/agent-vault-home")
    c.check(AGENT_TOKEN not in json.dumps([x["argv"] for x in c.stubs()]), "the agent token is in no argv")
    c.clear_http()
    seed_status(c, env="staging")
    r = c.run(["status", "--env", "staging"])
    c.check(r.code == 0 and "infisical: staging:%s (project %s)" % (APP, PROJECT) in r.out, "--env selects the environment")
    c.clear_http()
    r = c.run(["status", "--env", "qa"])
    c.check(r.code != 0 and c.api() == [], "F22 an unknown environment stops status before any secret request")
    c.finish()


@case
def f24_status_json_holds_repo_folder_keys_imports_and_vault(c):
    seed_status(c)
    r, doc = status_json(c, [])
    v = doc.get("vault", {})
    c.check(r.code == 0 and doc.get("repo") == str(c.app) and doc.get("env") == "dev" and doc.get("project") == PROJECT
            and doc.get("folder") == APP and doc.get("boundary") in (None, "-", ""),
            "--json: repo, env, project, folder and an empty boundary")
    c.check(sorted(doc.get("keys", [])) == ["DATABASE_URL", "LOCAL_KEY"], "--json: keys")
    imps = doc.get("imports", [])
    c.check(len(imps) == 1 and imps[0].get("path") == VENDOR and sorted(imps[0].get("keys", [])) == ["VENDOR_KEY", "ZETA"],
            "--json: imports as [{path, keys}]")
    c.check(v.get("name") == "shared" and v.get("source") == "default" and v.get("status") == "ok"
            and v.get("proxied_here") is False, "--json: vault name, source, status and proxied_here")
    c.check({(s.get("name"), s.get("host")) for s in v.get("services", [])}
            == {("stripe", "api.stripe.com"), ("github", "api.github.com")}, "--json: vault services")
    c.check(sorted(v.get("credentials", [])) == ["GITHUB_PAT", "STRIPE_API_KEY"], "--json: vault credentials")
    c.finish()


@case
def f24_status_goes_on_with_exit_0_when_the_vault_is_unavailable(c):
    seed_status(c)
    stub = c.bin / "agent-vault"
    saved = stub.read_text()
    variants = [("a nonzero exit", {"exit": 3}), ("bad JSON", {"bad_json": True}), ("a missing binary", None)]
    for label, mode in variants:
        if mode is None:
            stub.unlink()
        else:
            c.stub["discover"] = mode
        r = c.run(["status"])
        c.check(r.code == 0 and re.search(r"^vault: shared unavailable: \S", r.out, re.MULTILINE) is not None,
                "F24 %s: `vault: shared unavailable: <reason>` and exit 0" % label)
        c.check("infisical: dev:%s" % APP in r.out and "use:" in r.out and HOST_LINE.search(r.out) is None,
                "F24 %s: the rest of the status is still printed, with no host lines" % label)
    stub.write_text(saved)
    stub.chmod(0o755)
    c.stub["discover"] = {"exit": 3}
    r, doc = status_json(c, [])
    v = doc.get("vault", {})
    c.check(r.code == 0 and v.get("status") == "unavailable" and isinstance(v.get("reason"), str) and v.get("reason")
            and v.get("services", []) == [], "--json: status unavailable with a reason and no services")
    c.configure(agent_vault=False)
    r = c.run(["status"])
    c.check(r.code == 0 and re.search(r"^vault: .*unavailable: \S", r.out, re.MULTILINE) is not None and "infisical:" in r.out,
            "F24 no [agent_vault] table: unavailable, exit 0")
    c.finish()


@case
def f24_status_reports_a_vault_that_breaks_the_boundary_rules_as_refused(c):
    c.fake.seed(ACME, ["ACME_KEY"])
    c.fake.seed(APP, ["LOCAL_KEY"])
    r = c.run(["status"], cwd=c.acme)
    c.check(r.code == 0 and re.search(r"^vault: shared refused: \S", r.out, re.MULTILINE) is not None
            and "boundary: Acme" in r.out and "infisical: dev:%s" % ACME in r.out,
            "F24 an Acme dir on the default vault: `vault: shared refused: <reason>`, exit 0, Infisical part intact")
    c.check(HOST_LINE.search(r.out) is None and "(default)" not in r.out and discovers(c) == [],
            "F24 a refused vault is not used: no hosts, no discovery")
    r, doc = status_json(c, [], cwd=c.acme)
    v = doc.get("vault", {})
    c.check(v.get("status") == "refused" and v.get("services", []) == [] and v.get("reason"), "--json: status refused")
    c.configure(allow_vaults=["shared"])
    r = c.run(["status"], cwd=c.acme)
    c.check(r.code == 0 and "vault: shared (default)" in r.out, "an allow_vaults vault is usable inside Acme")
    c.configure()
    (c.acme / "agent-vault.json").write_text(json.dumps({"vault": "team-v"}))
    r = c.run(["status"], cwd=c.acme)
    c.check(re.search(r"^vault: team-v refused: \S", r.out, re.MULTILINE) is not None,
            "a vault from agent-vault.json is refused too")
    (c.app / "agent-vault.json").write_text(json.dumps({"vault": "acme-x"}))
    c.clear_stubs()
    r = c.run(["status"], cwd=c.app)
    c.check(re.search(r"^vault: acme-x refused: \S", r.out, re.MULTILINE) is not None and discovers(c) == [],
            "outside Acme an acme-prefixed vault is refused and not asked")
    r = c.run(["status"], cwd=c.shop)
    c.check("vault: shared (default)" in r.out and "boundary: -" in r.out,
            "control: a plain repo on the default vault is usable")
    c.finish()


@case
def f25_status_uses_the_inherited_broker_vault_and_token_when_already_proxied(c):
    seed_status(c)
    inherited = "CANARY-INHERITED-AGENT-TOKEN-5c"
    c.canaries.append(inherited)
    env = {"AGENT_VAULT_TOKEN": inherited, "HTTPS_PROXY": "http://proxy.invalid:3128",
           "AGENT_VAULT_VAULT": "proxied-v", "AGENT_VAULT_ADDR": "http://inherited-broker:9"}
    r = c.run(["status"], env=env)
    c.check(r.code == 0 and "vault: proxied-v (this process)" in r.out and "  proxied here: yes" in r.out,
            "F25 an already proxied process reports its own vault and proxied here: yes")
    d = discovers(c)
    c.check(len(d) == 1 and d[0]["env"]["AGENT_VAULT_ADDR"] == "http://inherited-broker:9"
            and d[0]["env"]["AGENT_VAULT_VAULT"] == "proxied-v" and d[0]["env"]["AGENT_VAULT_TOKEN"] == inherited,
            "F25 discovery uses the inherited address, vault and token, not the config")
    c.check(not any("agent-vault-token" in " ".join(e["argv"]) for e in c.stubs("security")),
            "F25 the agent token is not read from the Keychain")
    c.clear_stubs()
    r = c.run(["status"], env={"AGENT_VAULT_TOKEN": inherited})
    d = discovers(c)
    c.check("vault: shared (default)" in r.out and "proxied here: no" in r.out and len(d) == 1
            and d[0]["env"]["AGENT_VAULT_TOKEN"] == AGENT_TOKEN and d[0]["env"]["AGENT_VAULT_ADDR"] == "http://broker:14321",
            "a token alone (no HTTPS_PROXY) does not count as proxied: normal discovery from the config")
    c.finish()


@case
def f23_status_writes_nothing_and_prints_no_value_when_the_api_returns_values(c):
    c.fake.leak = True
    seed_status(c)
    for args in (["status"], ["status", "--json"]):
        r = c.run(args)
        c.check(r.code == 0 and "LOCAL_KEY" in r.out, "status still lists key names: %s" % " ".join(args))
    c.check(c.writes() == [], "F23 status makes no state-changing request")
    c.finish()


@case
def f32_status_says_the_folder_does_not_exist_and_exits_0_on_a_404_repo_folder(c):
    c.fake.seed(VENDOR, ["VENDOR_KEY"])
    c.fake.missing.add(("dev", APP))
    r = c.run(["status"])
    lines = [ln.rstrip() for ln in r.out.splitlines()]
    gone = next((i for i, ln in enumerate(lines) if ln.startswith("  folder does not exist:")), -1)
    infisical = next((i for i, ln in enumerate(lines) if ln.startswith("infisical: dev:%s" % APP)), -1)
    vault = next((i for i, ln in enumerate(lines) if ln.startswith("vault:")), -1)
    c.check(r.code == 0 and 0 <= infisical < gone < vault,
            "F32 exit 0 and `  folder does not exist: ...` sits between the infisical and vault lines")
    c.check(re.search(r"^\s+(keys \(|import )", r.out, re.MULTILINE) is None, "F32 no keys or import lines for a missing folder")
    c.check("HTTP 404" not in r.text and "use:" in r.out and "vault: shared (default)" in r.out,
            "F32 no HTTP error text; the vault and use blocks are still printed")
    r, doc = status_json(c, [])
    c.check(r.code == 0 and doc.get("folder_exists") is False and doc.get("folder") == APP, "--json: folder_exists is false")
    c.fake.missing.clear()
    seed_status(c)
    r, doc = status_json(c, [])
    c.check(doc.get("folder_exists", True) is True, "--json: an existing folder is not reported as missing")
    c.finish()
