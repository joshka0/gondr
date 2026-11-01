"""Cases for `layout.service_roots` (F38): extra write roots, reached only with `--path`.

Config used: service_roots = ["/services"] unless a case says otherwise. `set` is exercised through
`python -m gondr`; `token mint` through the console-script launcher (see cases_token.py).
"""

from gondr_gate.constants import ACME, APP, SET_VALUE, VENDOR
from gondr_gate.sandbox import case, stops
from gondr_gate.cases_set_run import set_body
from gondr_gate.cases_token import MINT_OPTS, PROVIDER, mint_want, one_exec, refused, tk, untouched

ROOT = "/services"
BAD_PATHS = [
    ROOT,                      # the root itself
    "/services/",              # the root with a trailing slash: still no folder below it
    "/servicesx/a",            # lookalike: shares the text, not the `root/` prefix
    "/services-x/a",
    "/service/a",
    "/services/../etc",        # `..` segment under the root
    "/services/x/../../etc",
    "/services/x/..",
    "/services/./x",           # `.` segment
    "/services//x",            # empty segment
    "/Services/x",             # roots are case-sensitive paths
    "services/x",              # relative
]


def configure(c, roots, **kw):
    c.configure(service_roots=roots, factory=str(c.bin / "gondr-factory"), **kw)


def refuse_set(c, path, label, cwd=None, key="API_KEY"):
    c.clear_http()
    r = c.run(["set", key, "--path", path], cwd=cwd, stdin=b"v1")
    c.check(r.code != 0 and c.writes() == [] and c.gets("/api/v2/folders") == [],
            "F38 set refuses %s: nonzero exit, no write, no folder creation (exit %d)" % (label, r.code))
    return r


# ---------------------------------------------------------------- set


@case
def f38_set_writes_under_a_listed_service_root_like_any_set(c):
    configure(c, [ROOT])
    c.fake.seed(ROOT + "/api", ["API_KEY"])
    r = c.run(["set", "API_KEY", "--path", ROOT + "/api"], stdin=SET_VALUE.encode())
    c.check(r.code == 0 and r.out.strip() == "updated API_KEY in dev:%s/api" % ROOT,
            "F38 an existing key under the root prints 'updated' (exit %d, out %r)" % (r.code, r.out))
    patch = [q for q in c.fake.reqs if q["method"] == "PATCH" and q["path"] == "/api/v4/secrets/API_KEY"]
    c.check(len(patch) == 1 and patch[0]["body"] == set_body("dev", ROOT + "/api", SET_VALUE),
            "F38 PATCH body holds the value byte for byte and secretPath %s/api" % ROOT)
    c.clear_http()
    r = c.run(["set", "--env", "staging", "--path", ROOT + "/web/v2", "WEB_KEY"], stdin=SET_VALUE.encode())
    c.check(r.code == 0 and r.out.strip().splitlines()[-1] == "created WEB_KEY in staging:%s/web/v2" % ROOT,
            "F38 a new key two levels under the root prints 'created' (exit %d)" % r.code)
    post = c.posts("/api/v4/secrets/WEB_KEY")
    c.check(len(post) == 1 and post[0]["body"].get("secretPath") == ROOT + "/web/v2"
            and post[0]["body"].get("environment") == "staging" and post[0]["body"].get("secretValue") == SET_VALUE,
            "F38 POST goes to the service folder with the exact value")
    c.check([q for q in c.fake.reqs if q["method"] == "PATCH"] == [], "no PATCH for a missing key")
    c.finish()


@case
def f38_set_accepts_every_listed_root_and_only_those(c):
    configure(c, [ROOT, "/deploy/prod-apps"])
    for path in ("/deploy/prod-apps/api", ROOT + "/api"):
        c.clear_http()
        r = c.run(["set", "API_KEY", "--path", path], stdin=b"v1")
        c.check(r.code == 0 and any(q["method"] in ("POST", "PATCH") and q["body"].get("secretPath") == path
                                    for q in c.fake.reqs), "F38 set writes under listed root %s (exit %d)" % (path, r.code))
    for path in ("/deploy/api", "/deploy/prod-apps", "/deploy/prod-appsx/a"):
        refuse_set(c, path, "unlisted or partial root %s" % path)
    c.finish()


@case
def f38_set_refuses_a_service_path_when_the_list_is_empty_absent_or_names_another_root(c):
    for label, roots in (("empty list", []), ("no service_roots key", None), ("another root", ["/deploy"])):
        configure(c, roots)
        r = refuse_set(c, ROOT + "/x", "%s/x with %s" % (ROOT, label))
        c.check(r.code == 1, "F38 exit 1 with %s (got %d)" % (label, r.code))
    configure(c, ["/deploy"])
    ok = c.run(["set", "API_KEY", "--path", "/deploy/x"], stdin=b"v1")
    c.check(ok.code == 0, "control: the other root itself is a working root, so the refusal above is about the list")
    c.finish()


@case
def f38_set_refuses_the_root_itself_lookalikes_and_bad_segments(c):
    configure(c, [ROOT])
    ok = c.run(["set", "API_KEY", "--path", ROOT + "/x"], stdin=b"v1")
    c.check(ok.code == 0 and len(c.writes()) == 1, "control: %s/x is accepted with this config" % ROOT)
    for path in BAD_PATHS:
        refuse_set(c, path, "path %r" % path)
    c.finish()


@case
def f38_set_stops_a_boundary_directory_at_a_service_root_before_any_login(c):
    configure(c, [ROOT])
    for path in (ROOT + "/x", ROOT + "/x/y"):
        c.clear_http()
        c.clear_stubs()
        r = c.run(["set", "API_KEY", "--path", path], cwd=c.acme, stdin=b"v1")
        stops(c, r, code=1)
        c.check(c.fake.reqs == [] and c.sensitive_stubs() == [],
                "F38 no Keychain read, login or HTTP request for %s from the Acme repo" % path)
    sub = c.acme / "src"
    sub.mkdir()
    r = c.run(["set", "API_KEY", "--path", ROOT + "/x"], cwd=sub, stdin=b"v1")
    stops(c, r, code=1)
    c.check(c.fake.reqs == [], "F38 the stop holds from a subfolder of the Acme repo")
    # the same path works from a personal repo, so the stop above is the boundary guard
    r = c.run(["set", "API_KEY", "--path", ROOT + "/x"], cwd=c.shop, stdin=b"v1")
    c.check(r.code == 0 and len(c.writes()) == 1, "control: a personal repo may write %s/x" % ROOT)
    c.finish()


@case
def f38_a_service_root_is_never_a_default_folder(c):
    configure(c, [ROOT])
    sub = c.app / "src"
    sub.mkdir()
    for i, (cwd, want) in enumerate(((c.app, APP), (sub, APP), (c.shop, "/repos/personal/shop"), (c.acme, ACME))):
        c.clear_http()
        key = "API_KEY_%d" % i  # a fresh key per run, so each write is a 'created'
        r = c.run(["set", key], cwd=cwd, stdin=b"v1")
        writes = c.writes()
        c.check(r.code == 0 and len(writes) == 1 and writes[0]["body"].get("secretPath") == want
                and "created %s in dev:%s" % (key, want) in r.out,
                "F38 set without --path from %s writes to the repo folder %s (exit %d)" % (cwd.name, want, r.code))
        c.check(not any(ROOT in str(q["query"]) + str(q["body"]) for q in c.fake.reqs),
                "F38 no request touches %s without --path" % ROOT)
    c.clear_http()
    r = c.run(["ls"])
    sec = c.gets("/api/v4/secrets")
    c.check(r.code == 0 and sec and sec[0]["query"].get("secretPath") == APP, "ls also keeps the repo folder")
    c.finish()


@case
def f38_need_target_path_follows_the_same_service_root_rule(c):
    c.fake.seed(VENDOR, ["SHARED_KEY"])
    configure(c, [])
    c.clear_http()
    r = c.run(["need", "SHARED_KEY", "--path", ROOT + "/x", "--from", VENDOR])
    c.check(r.code != 0 and c.fake.reqs == [], "F38 need refuses a service path before login when the list is empty")
    configure(c, [ROOT])
    r = c.run(["need", "SHARED_KEY", "--path", ROOT + "/x", "--from", VENDOR])
    imp = c.posts("/api/v2/secret-imports")
    c.check(r.code == 0 and len(imp) == 1 and imp[0]["body"].get("path") == ROOT + "/x",
            "F38 need imports into a listed service folder (exit %d)" % r.code)
    c.clear_http()
    r = c.run(["need", "SHARED_KEY", "--path", ROOT, "--from", VENDOR])
    c.check(r.code != 0 and c.writes() == [], "F38 need refuses the root itself")
    c.clear_http()
    r = c.run(["need", "SHARED_KEY", "--path", ROOT + "/x", "--from", VENDOR], cwd=c.acme)
    stops(c, r, code=1)
    c.check(c.fake.reqs == [], "F38 need from the Acme repo stops before login")
    c.finish()


# ---------------------------------------------------------------- token mint


@case
def f38_mint_passes_a_listed_service_path_to_the_factory(c):
    configure(c, [ROOT])
    one_exec(c, tk(c, ["mint", PROVIDER, "--path", ROOT + "/x"] + MINT_OPTS),
             mint_want("dev", ROOT + "/x"), "service folder, default env")
    one_exec(c, tk(c, ["mint", PROVIDER, "--env", "staging"] + MINT_OPTS + ["--path", ROOT + "/api/v2"]),
             mint_want("staging", ROOT + "/api/v2"), "deeper folder, explicit env, path last")
    one_exec(c, tk(c, ["mint", PROVIDER, "--path", "/shared/other", "--path", ROOT + "/x"] + MINT_OPTS),
             mint_want("dev", ROOT + "/x"), "the last --path wins")
    untouched(c, "service-root mints")
    c.finish()


@case
def f38_mint_refuses_service_paths_that_set_would_refuse_before_exec(c):
    for label, roots in (("empty list", []), ("another root", ["/deploy"])):
        configure(c, roots)
        r = tk(c, ["mint", PROVIDER, "--path", ROOT + "/x"] + MINT_OPTS)
        refused(c, r, "%s/x with %s" % (ROOT, label))
    configure(c, [ROOT])
    one_exec(c, tk(c, ["mint", PROVIDER, "--path", ROOT + "/x"]), mint_want("dev", ROOT + "/x", opts=[]),
             "control: the listed root works")
    for path in BAD_PATHS:
        r = tk(c, ["mint", PROVIDER, "--path", path] + MINT_OPTS)
        refused(c, r, "mint path %r" % path)
    c.finish()


@case
def f38_mint_stops_a_boundary_directory_at_a_service_root_before_exec(c):
    configure(c, [ROOT])
    for path in (ROOT + "/x", ROOT + "/x/y"):
        r = tk(c, ["mint", PROVIDER, "--path", path] + MINT_OPTS, cwd=c.acme)
        stops(c, r, code=1)
        untouched(c, "Acme repo, mint --path %s" % path)
    one_exec(c, tk(c, ["mint", PROVIDER, "--path", ROOT + "/x"], cwd=c.shop), mint_want("dev", ROOT + "/x", opts=[]),
             "control: a personal repo mints into the service folder")
    c.finish()


@case
def f38_mint_without_path_keeps_the_repo_folder_when_service_roots_exist(c):
    configure(c, [ROOT])
    one_exec(c, tk(c, ["mint", PROVIDER] + MINT_OPTS), mint_want("dev", APP), "personal repo")
    one_exec(c, tk(c, ["mint", PROVIDER] + MINT_OPTS, cwd=c.acme), mint_want("dev", ACME), "Acme repo")
    c.finish()
