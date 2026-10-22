"""Cases for `onboard` (F19-F21)."""

import json

from gondr_gate.constants import PROJECT, SHOP
from gondr_gate.sandbox import case, sha
from gondr_gate.onboard_support import broker_mutations, onboard_setup, plans, snapshot


@case
def f19_f21_onboard_dry_run_prints_plan_and_writes_nothing(c):
    adm = onboard_setup(c, gh_equal=False)
    repo_dir = c.shop
    before = snapshot(c.home)
    r = c.run(["onboard", SHOP, "--admin-home", str(adm), "--repo-dir", str(repo_dir), "--dry-run"], cwd=c.shop)
    c.check(r.code == 0, "dry-run exits 0")
    p = plans(r)
    c.check(set(p) == {"github", "stripe"}, "plan lines for github and stripe only (openai has neither key)")
    c.check(any(l.strip().startswith("skip openai") for l in r.out.splitlines()) and "plan openai" not in r.out,
            "a service with neither key prints 'skip openai' and no plan line")
    g = p.get("github")
    c.check(g and "api.github.com" in g[0] and "GITHUB_TOKEN" in g[1] + g[2] and "shared" not in (g[1] + g[2]).lower(),
            "github uses the repo's own key when the hashes differ")
    s = p.get("stripe")
    c.check(s and "api.stripe.com" in s[0] and "STRIPE_API_KEY" in s[1] + s[2],
            "F21 a [services.stripe] entry without hosts or auth fills them from the catalog")
    c.check(any(e["argv"][:2] == ["catalog", "--json"] for e in c.stubs("agent-vault")), "F21 the catalog was read with `catalog --json`")
    c.check(c.writes() == [], "F19 dry-run makes no state-changing request")
    c.check(broker_mutations(c) == [], "F19 dry-run makes no broker mutation")
    r2 = c.run(["onboard", SHOP, "--dry-run"], cwd=c.shop)
    c.check(r2.code == 0 and set(plans(r2)) == {"github", "stripe"}, "dry-run needs no --admin-home")
    c.check(c.writes() == [] and broker_mutations(c) == [], "F19 the second dry-run also writes nothing")
    c.check(snapshot(c.home) == before, "F19 dry-run changes no file (no agent-vault.json, no state)")
    c.check(not (repo_dir / "agent-vault.json").exists(), "F19 no agent-vault.json is written")
    c.finish()


@case
def f20_onboard_uses_the_shared_reference_only_when_hashes_are_equal(c):
    adm = onboard_setup(c, gh_equal=True)
    r = c.run(["onboard", SHOP, "--admin-home", str(adm), "--dry-run"], cwd=c.shop)
    g = plans(r).get("github")
    c.check(r.code == 0 and g and "GITHUB_TOKEN" not in g[1] + g[2] and "shared" in (g[1] + g[2]).lower(),
            "F20 equal hashes -> the shared reference wins")
    s = plans(r).get("stripe")
    c.check(s and "STRIPE_API_KEY" in s[1] + s[2] and "shared" not in (s[1] + s[2]).lower(), "a service without a shared value keeps the repo key")
    onboard_setup(c, gh_equal=False)
    r = c.run(["onboard", SHOP, "--admin-home", str(adm), "--dry-run"], cwd=c.shop)
    g = plans(r).get("github")
    c.check(g and "GITHUB_TOKEN" in g[1] + g[2] and "shared" not in (g[1] + g[2]).lower(), "F20 different hashes -> the repo key stays")
    c.finish()


@case
def f21_onboard_fills_hosts_and_key_from_catalog_and_limits_to_services(c):
    adm = onboard_setup(c, gh_equal=False)
    r = c.run(["onboard", SHOP, "--admin-home", str(adm), "--services", "stripe", "--dry-run"], cwd=c.shop)
    p = plans(r)
    c.check(r.code == 0 and list(p) == ["stripe"], "--services limits the plan to the named service")
    c.check(p.get("stripe") and "api.stripe.com" in p["stripe"][0] and "STRIPE_API_KEY" in p["stripe"][1] + p["stripe"][2],
            "F21 stripe host and key come from the catalog")
    c.check("github" not in r.out and "openai" not in r.out, "no line for services that were not asked for")
    c.finish()


@case
def f19_f20_onboard_full_run_publishes_references_creates_vault_and_writes_repo_file(c):
    adm = onboard_setup(c, gh_equal=True)
    r = c.run(["onboard", SHOP, "--admin-home", str(adm), "--repo-dir", str(c.shop)], cwd=c.shop)
    c.check(r.code == 0, "onboard exits 0")
    folder = [q for q in c.posts("/api/v2/folders")]
    c.check(any(q["body"].get("name") == "agent-vault" and q["body"].get("path", "").rstrip("/") == SHOP
                and q["body"].get("projectId") == PROJECT and q["body"].get("environment") == "dev" for q in folder),
            "creates the folder <folder>/agent-vault")
    refs = [q for q in c.writes() if q["path"].startswith("/api/v4/secrets/") and q["body"]
            and q["body"].get("secretPath") == SHOP + "/agent-vault"]
    c.check(len(refs) >= 2, "publishes reference secrets into <folder>/agent-vault")
    vals = [q["body"]["secretValue"] for q in refs]
    c.check("${dev.shared.GITHUB_PAT}" in vals, "F20 equal hashes publish the shared reference for github")
    c.check(not any("GITHUB_TOKEN" in v for v in vals), "F20 the repo's GITHUB_TOKEN is not referenced")
    c.check(any("STRIPE_API_KEY" in v and v.startswith("${") and v.endswith("}") for v in vals),
            "the stripe reference points at the repo key")
    c.check(not any("OPENAI" in v for v in vals), "a skipped service gets no reference")
    c.check(all(q["body"].get("type") == "shared" and q["body"].get("skipMultilineEncoding") is True for q in refs),
            "references are published as in set")
    vault = "personal-shop-dev"
    calls = [e for e in c.stubs("agent-vault") if e["argv"][:1] != ["catalog"]]

    def broker(prefix):
        return [e for e in calls if e["argv"][:len(prefix)] == prefix]

    c.check(len(broker(["vault", "list"])) >= 1, "broker: vault list")
    creates = broker(["vault", "create"])
    c.check(len(creates) == 1 and creates[0]["argv"][2] == vault and "infisical" in creates[0]["argv"],
            "broker: vault create <default name> on the infisical credential store")
    c.check(any("my-agent" in e["argv"] for e in broker(["vault", "agent", "add"])), "broker: grants grant_agents")
    adds = broker(["vault", "service", "add"])
    c.check(len(adds) == 2 and any("api.github.com" in e["argv"] for e in adds)
            and any("api.stripe.com" in e["argv"] for e in adds) and all(vault in e["argv"] for e in adds),
            "broker: one service add each for github and stripe, none for the skipped openai")
    c.check([e["argv"] for e in broker(["vault", "credential-store", "sync"])]
            == [["vault", "credential-store", "sync", vault]], "broker: sync is `vault credential-store sync <vault>`")
    c.check(bool(calls) and all(e["env"]["HOME"] == str(adm) for e in calls), "every broker CLI call runs with HOME=<admin home>")
    patch = [q for q in c.fake.reqs if q["method"] == "PATCH" and q["path"] == "/v1/vaults/%s/settings" % vault]
    c.check(len(patch) == 1 and patch[0]["body"] == {"unmatched_host_policy": "passthrough"}
            and patch[0]["authorization"] == "Bearer synthetic-admin-token",
            "policy: PATCH <address>/v1/vaults/<vault>/settings with the admin bearer token")
    f = c.shop / "agent-vault.json"
    try:
        doc = json.loads(f.read_text())
    except (ValueError, OSError):
        doc = {}
    c.check(doc.get("vault") == "personal-shop-dev", "--repo-dir gets agent-vault.json with the default vault name")
    # a custom vault name wins and the file follows it
    c.clear_stubs()
    f.unlink(missing_ok=True)
    r = c.run(["onboard", SHOP, "--admin-home", str(adm), "--repo-dir", str(c.shop), "--vault", "custom-v"], cwd=c.shop)
    try:
        doc = json.loads(f.read_text())
    except (ValueError, OSError):
        doc = {}
    c.check(r.code == 0 and doc.get("vault") == "custom-v", "--vault overrides the default name")
    c.clear_stubs()
    r = c.run(["onboard", SHOP, "--vault", "env-v"], cwd=c.shop, env={"AGENT_VAULT_ADMIN_HOME": str(adm)})
    calls = [e for e in c.stubs("agent-vault") if e["argv"][:1] != ["catalog"]]
    c.check(r.code == 0 and any(e["argv"][:3] == ["vault", "create", "env-v"] for e in calls)
            and all(e["env"]["HOME"] == str(adm) for e in calls), "AGENT_VAULT_ADMIN_HOME replaces --admin-home")
    c.clear_stubs()
    c.clear_http()
    empty = c.tmp / "no-session"
    empty.mkdir()
    r = c.run(["onboard", SHOP, "--admin-home", str(empty)], cwd=c.shop)
    c.check(r.code != 0 and c.writes() == [] and broker_mutations(c) == [],
            "an admin home without .agent-vault/session.json stops onboard before any write")
    c.finish()


@case
def f21_onboard_empty_service_table_and_template_fill_everything_from_catalog(c):
    c.configure(services='\n[services.posthog]\n\n[services.billing]\ntemplate = "stripe"\n')
    adm = onboard_setup(c, gh_equal=False)
    c.fake.seed(SHOP, ["POSTHOG_KEY"])
    c.stub["hashes"] = {SHOP: {"POSTHOG_KEY": sha("ph-1"), "STRIPE_API_KEY": sha("st-1")}}
    r = c.run(["onboard", SHOP, "--dry-run"], cwd=c.shop)
    p = plans(r)
    c.check(r.code == 0 and set(p) == {"posthog", "billing"}, "an empty table and a template entry both get plan lines")
    c.check(p.get("posthog") and "us.posthog.com" in p["posthog"][0] and "POSTHOG_KEY" in p["posthog"][1] + p["posthog"][2],
            "F21 an empty [services.posthog] fills host and key from the catalog template with the same id")
    c.check(p.get("billing") and "api.stripe.com" in p["billing"][0] and "STRIPE_API_KEY" in p["billing"][1] + p["billing"][2],
            "F21 template = \"stripe\" fills host and key from that template")
    c.clear_stubs()
    r = c.run(["onboard", SHOP, "--admin-home", str(adm)], cwd=c.shop)
    adds = [e["argv"] for e in c.stubs("agent-vault") if e["argv"][:3] == ["vault", "service", "add"]]
    ph = [a for a in adds if "us.posthog.com" in a]
    c.check(r.code == 0 and len(adds) == 2 and len(ph) == 1 and "api-key" in ph[0] and "x-api-key" in ph[0],
            "F21 the api-key auth type and header come from the catalog into `vault service add`")
    c.check(any("api.stripe.com" in a and "bearer" in a for a in adds), "F21 the template service is added with bearer auth")
    c.finish()
