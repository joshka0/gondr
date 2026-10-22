"""Cases for `ls`, `where` and `need` (F01-F05)."""

import re

from gondr_gate.constants import ACME, ACMELIB, APP, OTHER, PROJECT, REFS, SET_VALUE, SHOP, UPSTREAM, VENDOR
from gondr_gate.sandbox import case


# ---------------------------------------------------------------- ls / where / need


def names_in(line):
    return [n for n in re.split(r"[,\s]+", line.strip()) if n]


@case
def f01_f03_f12_ls_sends_exact_names_only_requests_and_prints_sorted_layout(c):
    f = c.fake
    f.seed(VENDOR, ["ZETA", "ALPHA", "VENDOR_KEY"], env="staging")
    f.seed(UPSTREAM, ["IMPORTED_Z", "IMPORTED_A"], env="staging")
    f.link(VENDOR, UPSTREAM, env="staging")
    f.extra_dirs |= {("staging", VENDOR + "/z-child"), ("staging", VENDOR + "/a-child")}
    f.seed(VENDOR + "/z-child", ["DEEP_SECRET"], env="staging")
    r = c.run(["ls", "--env", "staging", VENDOR])
    c.check(r.code == 0, "ls exits 0")
    lines = r.out.splitlines()
    c.check(bool(lines) and lines[0].strip() == "staging:" + VENDOR, "header is <env>:<path>")
    keys = [l for l in lines if re.match(r"^\s+keys \(", l)]
    c.check(len(keys) == 1 and re.search(r"\(3\)", keys[0]) and names_in(keys[0].split(":", 1)[1]) == ["ALPHA", "VENDOR_KEY", "ZETA"],
            "keys line has count 3 and sorted names")
    imp = [l for l in lines if re.match(r"^\s+import ", l)]
    c.check(len(imp) == 1 and UPSTREAM in imp[0] and re.search(r"\(2\)", imp[0])
            and names_in(imp[0].rsplit(":", 1)[1]) == ["IMPORTED_A", "IMPORTED_Z"],
            "one import line shows source, count 2 and sorted names")
    fol = [l for l in lines if re.match(r"^\s+folders:", l)]
    c.check(len(fol) == 1 and names_in(fol[0].split(":", 1)[1]) == ["a-child", "z-child"],
            "folders line lists sorted subfolders")
    c.check("DEEP_SECRET" not in r.out, "F03 ls does not list keys of subfolders")
    sec, fold = c.gets("/api/v4/secrets"), c.gets("/api/v2/folders")
    c.check(len(sec) == 1 and len(fold) == 1, "exactly one secrets GET and one folders GET")
    if sec:
        q = sec[0]["query"]
        c.check(q.get("projectId") == PROJECT and q.get("environment") == "staging"
                and q.get("secretPath") == VENDOR, "F03 secrets query has projectId, environment, exact secretPath")
        c.check(q.get("includeImports") == "true" and q.get("viewSecretValue") == "false"
                and q.get("expandSecretReferences") == "false", "F01 includeImports=true, viewSecretValue=false, expandSecretReferences=false")
        c.check(q.get("recursive") != "true", "F03 ls does not use recursive=true")
    if fold:
        q = fold[0]["query"]
        c.check(q.get("projectId") == PROJECT and q.get("environment") == "staging" and q.get("path") == VENDOR,
                "folders query has projectId, environment, path")
    # default path, default environment, run from a subfolder; no subfolders means no folders line
    sub = c.app / "pkg" / "deep"
    sub.mkdir(parents=True)
    c.clear_http()
    r = c.run(["ls"], cwd=sub)
    sec = c.gets("/api/v4/secrets")
    c.check(r.code == 0 and r.out.splitlines()[0].strip() == "dev:" + APP, "bare ls prints dev:<repo folder>")
    c.check(sec and sec[0]["query"].get("secretPath") == APP and sec[0]["query"].get("environment") == "dev",
            "F03 bare ls uses the repo folder and default environment")
    c.check("folders:" not in r.out, "no folders line when there are no subfolders")
    c.finish()


@case
def f02_f01_ls_where_need_set_never_print_values_when_api_returns_them(c):
    c.fake.leak = True
    c.fake.seed(VENDOR, ["VENDOR_KEY"])
    c.fake.seed(UPSTREAM, ["IMPORTED_A"])
    c.fake.link(VENDOR, UPSTREAM)
    r = c.run(["ls", VENDOR])
    c.check(r.code == 0 and "VENDOR_KEY" in r.out and "IMPORTED_A" in r.out,
            "ls still prints key names while the API leaks values")
    r = c.run(["where", "VENDOR_KEY"])
    c.check(r.code == 0 and VENDOR in r.out, "where still finds the owner while the API leaks values")
    r = c.run(["need", "VENDOR_KEY"])
    c.check(r.code == 0 and ("imported" in r.out or "already" in r.out), "need completes while the API leaks values")
    r = c.run(["set", "NEW_KEY", "--path", "/shared/new"], stdin=SET_VALUE.encode())
    c.check(r.code == 0 and "NEW_KEY" in r.out, "set completes while the API leaks values")
    c.finish()


@case
def f04_where_prints_owner_and_importers_and_makes_no_write(c):
    f = c.fake
    f.seed(VENDOR, ["VENDOR_KEY", "ZETA"])
    f.seed(APP, ["LOCAL_KEY"])
    f.link(APP, VENDOR)
    f.link(SHOP, VENDOR)
    r = c.run(["where", "VENDOR_KEY"])
    lines = r.out.splitlines()
    c.check(r.code == 0, "where exits 0 for an existing key")
    owner = "dev:%s VENDOR_KEY" % VENDOR
    own = [ln for ln in lines if ln.strip().startswith(owner)]
    c.check(len(own) == 1, "prints '<env>:<folder> <KEY>' once for the owner")
    c.check(len(own) == 1 and "  imported by: " in own[0] and APP in own[0] and SHOP in own[0],
            "'  imported by: <folders>' is appended on the owner line and names every importing folder, also one with no keys")
    c.check(not any(ln.strip().startswith("dev:%s " % APP) for ln in lines),
            "an importing folder is not reported as an owner")
    c.check(c.writes() == [], "F04 where makes no state-changing request")
    fl = c.gets("/api/v2/folders")
    c.check(len(fl) == 1 and fl[0]["query"].get("path") == "/" and fl[0]["query"].get("recursive") == "true"
            and fl[0]["query"].get("environment") == "dev" and fl[0]["query"].get("projectId") == PROJECT,
            "one GET /api/v2/folders?path=/&recursive=true lists every folder")
    asked = [q["query"].get("path") for q in c.gets("/api/v2/secret-imports")]
    c.check(set(asked) >= f._all_paths("dev") - {"/"} and len(asked) == len(set(asked)),
            "one GET /api/v2/secret-imports per folder, with full paths built from relativePath")
    # an environment selects a different owner
    f.seed(OTHER, ["STAGE_KEY"], env="staging")
    c.clear_http()
    r = c.run(["where", "STAGE_KEY", "--env", "staging"])
    c.check(r.code == 0 and "staging:%s STAGE_KEY" % OTHER in r.out, "--env selects the environment")
    r = c.run(["where", "STAGE_KEY"])
    c.check(r.code == 1 and not re.search(r"^\s*\S+:/\S* STAGE_KEY", r.out, re.MULTILINE),
            "a key that exists only in staging is missing in dev")
    c.check(c.writes() == [], "F04 where still makes no write")
    c.finish()


@case
def f04_where_missing_key_exits_1_without_an_owner_line(c):
    c.fake.seed(VENDOR, ["VENDOR_KEY"])
    c.fake.seed(APP, ["LOCAL_KEY"])
    r = c.run(["where", "VENDOR_KEY"])
    c.check(r.code == 0 and VENDOR in r.out, "control: an existing key is found, so the miss below is a real search")
    c.clear_http()
    r = c.run(["where", "MISSING_KEY"])
    c.check(c.gets("/api/v4/secrets") != [], "the missing key was searched for in Infisical")
    c.check(r.code == 1, "missing key exits 1")
    c.check(not re.search(r"^\s*\S+:/\S* MISSING_KEY", r.out, re.MULTILINE), "no owner line for a missing key")
    c.check(c.writes() == [], "no write")
    # a name that only prefixes a real key is not a hit
    r = c.run(["where", "VENDOR"])
    c.check(r.code == 1 and not re.search(r"^\s*\S+:/\S* VENDOR\b(?!_)", r.out, re.MULTILINE),
            "a key name that is a prefix of another key is not a hit")
    c.finish()


@case
def f04_f06_where_lists_only_owners_in_the_current_boundary(c):
    f = c.fake
    f.seed(VENDOR, ["DUP_KEY"])
    f.seed(ACMELIB, ["DUP_KEY"])
    r = c.run(["where", "DUP_KEY"], cwd=c.app)
    c.check(r.code == 0 and "dev:%s DUP_KEY" % VENDOR in r.out, "outside every boundary: the shared owner is listed")
    c.check("acme" not in r.out.lower(), "outside every boundary: no Acme owner is listed")
    r = c.run(["where", "DUP_KEY"], cwd=c.acme)
    c.check(r.code == 0 and "dev:%s DUP_KEY" % ACMELIB in r.out, "inside Acme: the Acme owner is listed")
    c.check(VENDOR not in r.out, "inside Acme: the non-boundary owner is not listed")
    c.finish()


@case
def f05_need_creates_one_import_then_reports_already_reaches(c):
    c.fake.seed(VENDOR, ["VENDOR_KEY"])
    c.fake.seed(APP, ["LOCAL_KEY"])
    r = c.run(["need", "VENDOR_KEY", "--from", VENDOR])
    c.check(r.code == 0 and "imported dev:%s into dev:%s" % (VENDOR, APP) in r.out, "prints the import line")
    posts = c.posts("/api/v2/secret-imports")
    c.check(len(posts) == 1, "creates exactly one import")
    if posts:
        c.check(posts[0]["body"] == {"projectId": PROJECT, "environment": "dev", "path": APP,
                                     "import": {"environment": "dev", "path": VENDOR}},
                "import body is {projectId, environment, path, import:{environment, path}}")
    r = c.run(["need", "VENDOR_KEY"])
    c.check(r.code == 0 and "VENDOR_KEY already reaches dev:%s" % APP in r.out, "second need reports already reaches")
    r = c.run(["need", "VENDOR_KEY", "--from", VENDOR])
    c.check(r.code == 0 and "already reaches" in r.out, "second need with --from reports already reaches")
    c.check(len(c.posts("/api/v2/secret-imports")) == 1, "F05 no second import is created")
    c.finish()


@case
def f05_need_local_key_makes_no_write(c):
    c.fake.seed(APP, ["LOCAL_KEY"])
    c.fake.seed(VENDOR, ["LOCAL_KEY"])
    r = c.run(["need", "LOCAL_KEY"])
    c.check(r.code == 0 and "LOCAL_KEY already reaches dev:%s" % APP in r.out, "own key already reaches the folder")
    c.check(c.writes() == [], "F05 no import for a key the folder owns")
    r = c.run(["need", "LOCAL_KEY", "--path", VENDOR])
    c.check(r.code == 0 and "already reaches dev:%s" % VENDOR in r.out, "--path selects the folder that is checked")
    c.check(c.writes() == [], "no write for --path either")
    c.finish()


@case
def f05_need_fails_without_one_owner_and_ignores_the_reference_folder(c):
    f = c.fake
    f.seed(VENDOR, ["DUP_KEY", "BOTH_KEY"])
    f.seed(OTHER, ["DUP_KEY"])
    f.seed(REFS, ["REF_ONLY_KEY", "BOTH_KEY"])
    r = c.run(["need", "NOPE_KEY"])
    c.check(r.code == 1, "no owner exits 1")
    r = c.run(["need", "DUP_KEY"])
    c.check(r.code == 1, "two owners without --from exit 1")
    r = c.run(["need", "REF_ONLY_KEY"])
    c.check(r.code == 1, "a key in <shared>/<references_folder> is not an owner")
    c.check(c.posts("/api/v2/secret-imports") == [], "F05 none of the failures created an import")
    r = c.run(["need", "BOTH_KEY"])
    c.check(r.code == 0 and "imported dev:%s into dev:%s" % (VENDOR, APP) in r.out,
            "the reference folder does not count as a second owner")
    r = c.run(["need", "DUP_KEY", "--from", OTHER, "--path", SHOP])
    c.check(r.code == 0 and "imported dev:%s into dev:%s" % (OTHER, SHOP) in r.out, "--from picks one of two owners")
    posts = c.posts("/api/v2/secret-imports")
    c.check(len(posts) == 2 and posts[-1]["body"]["path"] == SHOP and posts[-1]["body"]["import"]["path"] == OTHER,
            "--from and --path land in the import body")
    c.finish()


@case
def f05_f06_need_inside_a_boundary_searches_the_boundary_shared_folder(c):
    f = c.fake
    f.seed(ACMELIB, ["ACME_KEY"])
    f.seed(VENDOR, ["ACME_KEY2"])
    r = c.run(["need", "ACME_KEY"], cwd=c.acme)
    c.check(r.code == 0 and "imported dev:%s into dev:%s" % (ACMELIB, ACME) in r.out,
            "inside Acme the owner under the boundary shared folder is used")
    posts = c.posts("/api/v2/secret-imports")
    c.check(len(posts) == 1 and posts[0]["body"]["path"] == ACME and posts[0]["body"]["import"]["path"] == ACMELIB,
            "import body targets the Acme folder")
    r = c.run(["need", "ACME_KEY2"], cwd=c.acme)
    c.check(r.code == 1, "inside Acme a key owned only under /shared is not found")
    c.check(len(c.posts("/api/v2/secret-imports")) == 1, "no import crosses the boundary")
    c.check(not any(q["query"].get("secretPath", "").startswith("/shared") for q in c.gets("/api/v4/secrets")),
            "inside Acme the owner search does not read /shared")
    r = c.run(["need", "ACME_KEY"], cwd=c.app)
    c.check(r.code == 1, "outside Acme a Acme-only key has no owner")
    c.check(len(c.posts("/api/v2/secret-imports")) == 1, "still one import in total")
    c.finish()
