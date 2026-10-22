"""Cases for `find` (F23, F26-F29)."""

import json

from gondr_gate.constants import ACME, AGENT_TOKEN, APP, OTHER, VENDOR
from gondr_gate.sandbox import case
from gondr_gate.world import CONNECT_SERVICES, KINDS, PERSONAL_OTHER, hit_lines, seed_acme, seed_personal


@case
def f26_f29_find_lists_every_route_kind_once_in_order_without_walking_imports(c):
    seed_personal(c.fake)
    c.configure(services=CONNECT_SERVICES)
    r = c.run(["find", "stripe"])
    hits = hit_lines(r.out)
    c.check(r.code == 0 and hits != [], "find exits 0 when something matches")
    kinds = [h[0] for h in hits]
    c.check(kinds == sorted(kinds, key=KINDS.index), "F26 hits are ordered proxied, env, import, repo-owned, not-mapped")
    by = {}
    for kind, ident, route in hits:
        by.setdefault(kind, []).append((ident, route))
    c.check(set(by) == set(KINDS), "F26 every route kind appears: %s" % sorted(by))
    prox = by.get("proxied", [])
    c.check([i for i, _ in prox] == ["api.stripe.com"] and "https://api.stripe.com" in prox[0][1]
            and "no auth header" in prox[0][1], "proxied: the vault service host with the no-auth-header route")
    env = by.get("env", [])
    c.check([i for i, _ in env] == ["STRIPE_IMPORTED_KEY", "STRIPE_SIGNING_KEY", "STRIPE_WEBHOOK_SECRET"],
            "F26 env: own and imported keys, sorted by name")
    c.check(all("gondr run --" in rt and "$" + i in rt for i, rt in env), "env: route `gondr run -- <cmd>  (reads $<KEY>)`")
    imp = by.get("import", [])
    c.check(sorted(i for i, _ in imp) == ["STRIPE_API_KEY", "STRIPE_DUAL_KEY", "STRIPE_DUAL_KEY"],
            "F26 import: one line for a single-owner key, one line per owner for STRIPE_DUAL_KEY")
    api = [rt for i, rt in imp if i == "STRIPE_API_KEY"]
    c.check(len(api) == 1 and "gondr need STRIPE_API_KEY" in api[0] and "--from" not in api[0],
            "import: a single owner needs no --from")
    dual = [rt for i, rt in imp if i == "STRIPE_DUAL_KEY"]
    c.check(any("--from " + VENDOR in rt for rt in dual) and any("--from " + OTHER in rt for rt in dual),
            "import: more than one owner gives `gondr need <KEY> --from <owner>` per owner")
    own = by.get("repo-owned", [])
    c.check([i for i, _ in own] == ["STRIPE_TEST_KEY"] and PERSONAL_OTHER in own[0][1] and "never copy" in own[0][1],
            "repo-owned: a key only in another repo folder, with the ask-the-operator route")
    nm = by.get("not-mapped", [])
    c.check(len(nm) == 1 and nm[0][0] in ("connect.stripe.com", "stripe-connect") and "gondr onboard" in nm[0][1],
            "not-mapped: a configured service that the vault lacks, with the onboard route")
    kinds_of = {}
    for kind, ident, _ in hits:
        if kind in ("env", "import", "repo-owned"):
            kinds_of.setdefault(ident, set()).add(kind)
    c.check(all(len(v) == 1 for v in kinds_of.values()) and kinds_of.get("STRIPE_WEBHOOK_SECRET") == {"env"},
            "F26 a key appears under its first route only (STRIPE_WEBHOOK_SECRET is also elsewhere)")
    c.check("STRIPE_REF_KEY" not in r.out, "the references folder is never an owner")
    c.check("NOTES_KEY" not in r.out, "find matches key names, not folder paths (the folder is /repos/personal/stripe-notes)")
    sec = c.gets("/api/v4/secrets")
    rec = [q for q in sec if q["query"].get("recursive") == "true"]
    c.check(c.gets("/api/v2/secret-imports") == [], "F29 find sends no GET /api/v2/secret-imports")
    c.check(len(rec) == 1 and len(sec) - len(rec) <= 1 and len(c.gets("/api/v2/folders")) <= 1
            and len(c.posts("/api/v1/auth/universal-auth/login")) == 1 and len(c.api()) <= 3,
            "F29 find sends one login, at most one folder list, one recursive name list and one plain read")
    c.check(c.writes() == [], "F23 find makes no state-changing request")
    c.finish()


@case
def f26_find_words_are_case_insensitive_substrings_and_short_words_stop(c):
    seed_personal(c.fake)
    r = c.run(["find", "Stripe", "WEBHOOK"])
    c.check(r.code == 0 and [(k, i) for k, i, _ in hit_lines(r.out)] == [("env", "STRIPE_WEBHOOK_SECRET")],
            "every word must match, case-insensitively")
    r = c.run(["find", "signing"])
    c.check([(k, i) for k, i, _ in hit_lines(r.out)] == [("env", "STRIPE_SIGNING_KEY")], "a substring of a key name matches")
    r = c.run(["find", "github"])
    c.check([(k, i) for k, i, _ in hit_lines(r.out)] == [("proxied", "api.github.com")],
            "a service name or host matches; a configured service that the vault holds is not `not-mapped`")
    r = c.run(["find", "personal"])
    c.check(r.code == 1 and hit_lines(r.out) == [] and 'missing: nothing matches "personal"' in r.out,
            "a word that only occurs in folder paths is no hit")
    for words in (["s"], ["stripe", "x"], [""]):
        c.clear_http()
        r = c.run(["find"] + words)
        c.check(r.code == 1 and hit_lines(r.out) == [] and c.writes() == [],
                "a word shorter than 2 characters stops with exit 1: %r" % words)
    c.finish()


@case
def f26_find_json_hits_carry_kind_key_host_service_folders_and_route(c):
    seed_personal(c.fake)
    c.configure(services=CONNECT_SERVICES)
    r = c.run(["find", "stripe", "--json"])
    try:
        doc = json.loads(r.out)
    except ValueError:
        doc = {}
    hits = doc.get("hits", [])
    c.check(r.code == 0 and doc.get("query") == "stripe" and doc.get("folder") == APP and doc.get("missing") is False,
            "--json prints query, folder and missing=false")
    c.check(hits != [] and all({"kind", "key", "host", "service", "folders", "route"} <= set(h) for h in hits),
            "every hit has kind, key, host, service, folders and route")
    kinds = [h.get("kind") for h in hits]
    c.check(kinds == sorted(kinds, key=KINDS.index) and set(kinds) == set(KINDS), "JSON hits follow the same kind order")
    prox = [h for h in hits if h.get("kind") == "proxied"]
    c.check(len(prox) == 1 and prox[0].get("host") == "api.stripe.com" and prox[0].get("service") == "stripe",
            "a proxied hit names its host and service")
    dual = [h for h in hits if h.get("key") == "STRIPE_DUAL_KEY"]
    c.check({f for h in dual for f in h.get("folders", [])} == {VENDOR, OTHER}, "an import hit lists its owner folders")
    own = [h for h in hits if h.get("kind") == "repo-owned"]
    c.check(len(own) == 1 and own[0].get("folders") == [PERSONAL_OTHER], "a repo-owned hit lists the other folder")
    c.finish()


@case
def f27_find_shows_only_folders_of_the_current_boundary(c):
    seed_personal(c.fake)
    c.configure(services="", allow_vaults=["shared"])
    r = c.run(["find", "stripe"], cwd=c.acme)
    hits = [(k, i) for k, i, _ in hit_lines(r.out)]
    c.check(r.code == 0 and hits == [("proxied", "api.stripe.com"), ("env", "STRIPE_ACME_KEY"),
                                     ("import", "STRIPE_ACME_SHARED"), ("repo-owned", "STRIPE_ACME_OTHER")],
            "inside Acme only Acme keys and folders are hits (%s)" % hits)
    c.check(not any(w in r.out for w in ("/repos/personal", "/shared", "STRIPE_API_KEY", "STRIPE_TEST_KEY",
                                         "STRIPE_WEBHOOK_SECRET", "STRIPE_DUAL_KEY")),
            "F27 inside Acme no personal or /shared folder or key appears")
    r = c.run(["find", "stripe", "--json"], cwd=c.acme)
    try:
        doc = json.loads(r.out)
    except ValueError:
        doc = {}
    folders = [f for h in doc.get("hits", []) for f in h.get("folders", [])]
    c.check(folders != [] and all(f == ACME or f.startswith("/repos/acme/") for f in folders),
            "F27 JSON hits inside Acme name only Acme folders (%s)" % folders)
    r = c.run(["find", "stripe"], cwd=c.app)
    c.check(r.code == 0 and "acme" not in r.out.lower() and "STRIPE_API_KEY" in r.out,
            "F27 outside Acme nothing from an Acme folder appears")
    # a vault that fails the boundary rules is `refused`: not used, so no proxied hit and no discovery
    c.configure(services="")
    c.clear_stubs()
    r = c.run(["find", "stripe"], cwd=c.acme)
    kinds = [k for k, _, _ in hit_lines(r.out)]
    c.check(r.code == 0 and "proxied" not in kinds and "env" in kinds, "a refused vault gives no proxied hit and does not stop find")
    c.check([e for e in c.stubs("agent-vault") if e["argv"][:2] == ["vault", "discover"]] == [],
            "a refused vault is not asked for its services")
    c.finish()


@case
def f28_find_with_no_hit_exits_1_and_prints_the_operator_set_command(c):
    seed_personal(c.fake)
    r = c.run(["find", "zzqq"])
    c.check(r.code == 1 and 'missing: nothing matches "zzqq"' in r.out, "no hit: exit 1 and the missing line")
    c.check('ask the operator: printf %%s "$VALUE" | gondr set ZZQQ --path %s' % APP in r.out,
            "the operator command names the upper-cased key and the repo folder")
    r = c.run(["find", "no", "such", "thing"])
    c.check(r.code == 1 and 'nothing matches "no such thing"' in r.out and "gondr set NO_SUCH_THING --path" in r.out,
            "several words are joined by _ in upper case")
    r = c.run(["find", "zz-qq"])
    c.check(r.code == 1 and "gondr set <NAME> --path" in r.out, "a words string that is not a valid key name gives <NAME>")
    r = c.run(["find", "zzqq", "--json"])
    try:
        doc = json.loads(r.out)
    except ValueError:
        doc = {}
    c.check(r.code == 1 and doc.get("missing") is True and doc.get("hits") == [] and doc.get("query") == "zzqq"
            and "gondr set ZZQQ" in (doc.get("operator_command") or ""), "--json: missing, empty hits and operator_command")
    r = c.run(["find", "zzqq"], cwd=c.acme)
    c.check(r.code == 1 and "--path %s" % ACME in r.out, "inside Acme the operator command targets the Acme folder")
    c.check(c.writes() == [], "F28 no write")
    c.finish()


@case
def f23_find_writes_nothing_and_prints_no_value_when_the_api_returns_values(c):
    c.fake.leak = True
    seed_personal(c.fake)
    seed_acme(c.fake)
    r = c.run(["find", "stripe"])
    c.check(hit_lines(r.out) != [], "find still lists hits while the API leaks values")
    r = c.run(["find", "stripe", "--json"])
    try:
        hits = json.loads(r.out).get("hits", [])
    except ValueError:
        hits = []
    c.check(hits != [], "find --json still lists hits while the API leaks values")
    r = c.run(["find", "zzqq"])
    c.check("missing: nothing matches" in r.out, "find still reports a miss while the API leaks values")
    c.check(c.writes() == [], "F23 find makes no state-changing request")
    c.check(AGENT_TOKEN not in json.dumps([e["argv"] for e in c.stubs()]), "F23 the agent token is in no argv")
    c.finish()


@case
def f32_find_treats_a_404_repo_folder_as_empty(c):
    seed_personal(c.fake)
    del c.fake.secrets[("dev", APP)]
    del c.fake.imports[("dev", APP)]
    c.fake.missing.add(("dev", APP))
    r = c.run(["find", "stripe"])
    hits = [(k, i) for k, i, _ in hit_lines(r.out)]
    c.check(r.code == 0 and "404" not in r.text and hits != [], "F32 find goes on and prints hits (%s)" % hits)
    c.check("env" not in {k for k, _ in hits} and ("import", "STRIPE_WEBHOOK_SECRET") in hits
            and ("import", "STRIPE_IMPORTED_KEY") in hits,
            "F32 an empty folder reaches nothing: former env keys become import hits")
    r = c.run(["find", "zzqq"])
    c.check(r.code == 1 and 'missing: nothing matches "zzqq"' in r.out and "404" not in r.text,
            "F32 a miss in a missing folder is still the normal missing answer")
    c.finish()
