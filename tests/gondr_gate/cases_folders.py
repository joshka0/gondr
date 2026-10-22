"""Cases for the [folders] config table (F31)."""

from gondr_gate.constants import APP, VENDOR
from gondr_gate.sandbox import case

SHORT = ("~/repos/personal", "/repos/short-match")
LONG = ("~/repos/personal/app", "/repos/personal/mapped-app")
MAPPED = "/repos/personal/mapped-app"


@case
def f31_folders_table_maps_the_repo_root_and_the_longest_match_wins(c):
    c.fake.seed(MAPPED, ["MAPPED_KEY"])
    c.fake.seed(VENDOR, ["VENDOR_KEY"])
    for label, order in (("shorter entry first", [SHORT, LONG]), ("longer entry first", [LONG, SHORT])):
        c.configure(folders=order)
        c.clear_http()
        c.clear_stubs()
        c.fake.imports.clear()
        r = c.run(["ls"])
        sec = c.gets("/api/v4/secrets")
        c.check(r.code == 0 and sec and sec[0]["query"].get("secretPath") == MAPPED and r.out.startswith("dev:" + MAPPED),
                "F31 ls: the longest match is the repo folder (%s)" % label)
        r = c.run(["need", "VENDOR_KEY"])
        posts = c.posts("/api/v2/secret-imports")
        c.check(r.code == 0 and posts and posts[0]["body"]["path"] == MAPPED, "F31 need imports into the mapped folder (%s)" % label)
        r = c.run(["set", "NEW_KEY"], stdin=b"v1")
        sets = [q for q in c.writes() if q["path"] == "/api/v4/secrets/NEW_KEY"]
        c.check(r.code == 0 and sets and sets[-1]["body"]["secretPath"] == MAPPED and "in dev:%s" % MAPPED in r.out,
                "F31 set writes into the mapped folder (%s)" % label)
        r = c.run(["run", "--", "childprobe"])
        inf = c.stubs("infisical")
        c.check(r.code == 0 and inf and ("--path=" + MAPPED) in inf[-1]["argv"], "F31 run passes the mapped folder (%s)" % label)
    c.configure(folders=[SHORT])
    c.clear_http()
    r = c.run(["ls"])
    sec = c.gets("/api/v4/secrets")
    c.check(sec and sec[0]["query"].get("secretPath") == "/repos/short-match", "F31 a shorter entry alone still maps the repo")
    c.configure()
    c.clear_http()
    r = c.run(["ls"])
    sec = c.gets("/api/v4/secrets")
    c.check(sec and sec[0]["query"].get("secretPath") == APP, "control: without [folders] the default mapping applies")
    c.finish()


@case
def f31_a_mapped_folder_passes_the_boundary_check(c):
    c.configure(folders=[("~/repos/personal/app", "/repos/acme/api")])
    r = c.run(["ls"])
    c.check(r.code != 0 and "Acme" in r.text and c.fake.reqs == [] and c.sensitive_stubs() == [],
            "F31 a personal repo mapped into Acme stops before any Keychain read, login or request, naming Acme")
    c.configure(folders=[("~/repos/acme/api", "/shared/vendor")])
    c.clear_stubs()
    r = c.run(["ls"], cwd=c.acme)
    c.check(r.code != 0 and "Acme" in r.text and c.fake.reqs == [] and c.sensitive_stubs() == [],
            "F31 an Acme repo mapped out of Acme stops the same way")
    c.configure(folders=[("~/repos/acme/api", "/repos/acme/web")])
    r = c.run(["ls"], cwd=c.acme)
    c.check(r.code == 0 and r.out.startswith("dev:/repos/acme/web"), "control: an Acme repo mapped inside Acme works")
    c.finish()
