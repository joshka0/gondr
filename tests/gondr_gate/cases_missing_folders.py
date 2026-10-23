"""Cases for missing target folders in `set` and `need` (F33)."""

from gondr_gate.constants import APP, OTHER, PROJECT, VENDOR
from gondr_gate.sandbox import case

OTHER_REPO = "/repos/personal/other"
LOGIN = "/api/v1/auth/universal-auth/login"


def seed_world(c, strict=True):
    """A server whose folders exist only where seeded: /repos/personal/other and /shared/vendor."""
    c.fake.strict = strict
    c.fake.seed(OTHER_REPO, ["OTHER_KEY"])
    c.fake.seed(VENDOR, ["VENDOR_KEY"])


def folder_posts(c):
    return c.posts("/api/v2/folders")


def folder_lists(c):
    return [q["query"].get("path") for q in c.gets("/api/v2/folders")]


def created_lines(out):
    return [l.strip() for l in out.splitlines() if l.strip().startswith("created folder ")]


def body(env, name, path):
    return {"projectId": PROJECT, "environment": env, "name": name, "path": path}


@case
def f33_set_creates_the_missing_repo_folder_then_writes_the_secret(c):
    seed_world(c)
    r = c.run(["set", "NEW_KEY"], stdin=b"v1")
    posts = folder_posts(c)
    c.check(r.code == 0 and "Traceback" not in r.text, "set exits 0 after creating the folder")
    c.check([p["body"] for p in posts] == [body("dev", "app", "/repos/personal")],
            "F33 one POST creates the missing folder, with projectId, environment, name and parent path")
    c.check(created_lines(r.out) == ["created folder dev:" + APP], "F33 prints the created folder line")
    c.check(r.out.strip().splitlines()[-1] == "created NEW_KEY in dev:" + APP, "the secret line comes last")
    idx = [i for i, q in enumerate(c.fake.reqs) if q["method"] != "GET" and q["path"] != LOGIN]
    c.check(len(idx) == 2 and c.fake.reqs[idx[0]]["path"] == "/api/v2/folders"
            and c.fake.reqs[idx[1]]["path"] == "/api/v4/secrets/NEW_KEY", "F33 the folder POST precedes the secret write")
    c.check(folder_lists(c) == ["/", "/repos", "/repos/personal"],
            "F33 the walk lists each parent from / once, down to the first missing segment")
    c.check(any(q["path"] == "/api/v4/secrets" and q["query"].get("secretPath") == APP for q in c.fake.reqs),
            "F33 set lists the target folder before the write")
    c.clear_http()
    r = c.run(["set", "NEW_KEY"], stdin=b"v2")
    c.check(r.code == 0 and r.out.strip() == "updated NEW_KEY in dev:" + APP and folder_posts(c) == [] and created_lines(r.out) == [],
            "F33 a second set finds the folder: no folder POST, no created folder line")
    c.finish()


@case
def f33_set_creates_missing_parents_first_and_lists_nothing_below_a_created_folder(c):
    seed_world(c)
    target = "/shared/new/a/b"
    r = c.run(["set", "--env", "staging", "--path", target, "NEW_KEY"], stdin=b"v1")
    c.check(r.code == 0, "set exits 0")
    # the server has no staging data at all: even /shared is missing there
    want = [("shared", "/"), ("new", "/shared"), ("a", "/shared/new"), ("b", "/shared/new/a")]
    c.check([p["body"] for p in folder_posts(c)] == [body("staging", n, p) for n, p in want],
            "F33 one POST per missing segment, parents first, each with its parent path")
    c.check(created_lines(r.out) == ["created folder staging:/shared", "created folder staging:/shared/new",
                                     "created folder staging:/shared/new/a", "created folder staging:/shared/new/a/b"],
            "F33 one created folder line per folder, parents first")
    c.check(folder_lists(c) == ["/"], "F33 below a created folder no more lists are sent")
    c.check(r.out.strip().splitlines()[-1] == "created NEW_KEY in staging:" + target, "the secret is written last")
    c.finish()


@case
def f33_set_creates_only_the_missing_tail_and_never_an_existing_folder_or_a_sibling(c):
    seed_world(c)
    target = VENDOR + "/deep/er"
    r = c.run(["set", "--path", target, "NEW_KEY"], stdin=b"v1")
    c.check(r.code == 0, "set exits 0")
    c.check([p["body"] for p in folder_posts(c)] == [body("dev", "deep", VENDOR), body("dev", "er", VENDOR + "/deep")],
            "F33 existing /shared and /shared/vendor are not POSTed; only deep and er are")
    c.check(folder_lists(c) == ["/", "/shared", VENDOR], "F33 lists stop at the first missing segment")
    c.check(created_lines(r.out) == ["created folder dev:%s/deep" % VENDOR, "created folder dev:%s/deep/er" % VENDOR],
            "F33 only the created folders are printed")
    # an existing folder: nothing created
    c.clear_http()
    r = c.run(["set", "--path", VENDOR, "VENDOR_KEY"], stdin=b"v1")
    c.check(r.code == 0 and r.out.strip() == "updated VENDOR_KEY in dev:" + VENDOR and folder_posts(c) == [],
            "F33 set into an existing folder sends no folder POST")
    c.clear_http()
    r = c.run(["set", "--path", OTHER_REPO, "OTHER_KEY"], stdin=b"v1")
    c.check(r.code == 0 and folder_posts(c) == [] and created_lines(r.out) == [],
            "F33 set into an existing repo folder sends no folder POST")
    c.finish()


@case
def f33_every_created_folder_lies_on_the_target_path(c):
    seed_world(c)
    target = "/repos/personal/fresh/leaf"
    r = c.run(["set", "--path", target, "NEW_KEY"], stdin=b"v1")
    c.check(r.code == 0, "set exits 0")
    made = [q["body"]["path"].rstrip("/") + "/" + q["body"]["name"] for q in folder_posts(c)]
    c.check(made == ["/repos/personal/fresh", target], "F33 only fresh and leaf are created")
    c.check(all(target == m or target.startswith(m + "/") for m in made), "F33 no folder outside the target path")
    c.check(c.fake.extra_dirs == {("dev", "/repos/personal/fresh"), ("dev", target)},
            "siblings of the target are untouched")
    c.finish()


@case
def f33_need_with_one_owner_creates_the_missing_folder_before_the_import(c):
    seed_world(c)
    r = c.run(["need", "VENDOR_KEY"])
    c.check(r.code == 0 and "Traceback" not in r.text, "need exits 0")
    c.check([p["body"] for p in folder_posts(c)] == [body("dev", "app", "/repos/personal")],
            "F33 need creates the missing repo folder")
    imp = c.posts("/api/v2/secret-imports")
    c.check(len(imp) == 1 and imp[0]["body"] == {"projectId": PROJECT, "environment": "dev", "path": APP,
                                                  "import": {"environment": "dev", "path": VENDOR}},
            "the import is POSTed once with the contract body")
    writes = [q["path"] for q in c.writes()]
    c.check(writes == ["/api/v2/folders", "/api/v2/secret-imports"], "F33 the folder POST comes before the import: %s" % writes)
    lines = [l.strip() for l in r.out.strip().splitlines()]
    c.check(lines == ["created folder dev:" + APP, "imported dev:%s into dev:%s" % (VENDOR, APP)],
            "F33 output: the created folder line, then the import line (got %s)" % lines)
    c.finish()


@case
def f33_need_with_from_creates_parents_first_then_imports(c):
    seed_world(c)
    c.fake.seed(OTHER, ["VENDOR_KEY"])  # two owners: --from picks one
    r = c.run(["need", "--path", "/repos/personal/x/y", "--from", VENDOR, "VENDOR_KEY"])
    c.check(r.code == 0, "need --from exits 0")
    writes = [q["path"] for q in c.writes()]
    c.check(writes == ["/api/v2/folders", "/api/v2/folders", "/api/v2/secret-imports"],
            "F33 two folder POSTs (x, y) precede the import: %s" % writes)
    c.check(created_lines(r.out) == ["created folder dev:/repos/personal/x", "created folder dev:/repos/personal/x/y"],
            "F33 created folder lines, parents first")
    c.finish()


@case
def f33_need_with_no_owner_or_several_owners_creates_nothing(c):
    seed_world(c)
    r = c.run(["need", "NOBODY_KEY"])
    c.check(r.code == 1 and "Traceback" not in r.text, "need with no owner exits 1")
    c.check(c.writes() == [], "F33 no owner: no folder POST, no import")
    c.check(created_lines(r.out) == [], "F33 no owner: no created folder line")
    c.clear_http()
    c.fake.seed(OTHER, ["VENDOR_KEY"])
    r = c.run(["need", "VENDOR_KEY"])
    c.check(r.code == 1 and c.writes() == [] and created_lines(r.out) == [],
            "F33 more than one owner without --from: exit 1 and no folder POST")
    c.finish()


@case
def f33_need_that_already_reaches_the_folder_creates_nothing(c):
    seed_world(c)
    c.fake.seed(APP, ["VENDOR_KEY"])
    r = c.run(["need", "VENDOR_KEY"])
    c.check(r.code == 0 and "already reaches" in r.out and c.writes() == [], "F33 an existing folder with the key: no write at all")
    c.finish()


@case
def f33_invalid_segment_exits_1_before_login_and_creates_nothing(c):
    seed_world(c)
    dotted = c.repo("personal/remy.food")
    for args, stdin in ((["set", "NEW_KEY"], b"v1"), (["need", "VENDOR_KEY"], b"")):
        c.clear_http()
        c.clear_stubs()
        r = c.run(args, cwd=dotted, stdin=stdin)
        c.check(r.code == 1 and "Traceback" not in r.text, "F33 %s in repo remy.food exits 1" % args[0])
        c.check(c.fake.reqs == [], "F33 %s sends no request, so no login and no folder POST" % args[0])
        c.check("remy.food" in r.text and ("[folders]" in r.text or "--path" in r.text),
                "F33 %s names the segment and hints at [folders] or --path" % args[0])
    for args, stdin in ((["set", "NEW_KEY", "--path", "/shared/ok/bad.name"], b"v1"),
                        (["set", "NEW_KEY", "--path", "/shared/new/a b"], b"v1"),
                        (["set", "NEW_KEY", "--path", "/shared/new/café"], b"v1"),
                        (["need", "VENDOR_KEY", "--path", "/repos/personal/ok/bad!"], b"")):
        c.clear_http()
        r = c.run(args, stdin=stdin)
        c.check(r.code == 1 and c.fake.reqs == [] and "Traceback" not in r.text,
                "F33 invalid segment exits 1 with no request (login included): %s" % args[-1])
    c.clear_http()
    r = c.run(["set", "A_B", "--path", "/shared/ok-1/under_score/9"], stdin=b"v1")
    c.check(r.code == 0 and len(folder_posts(c)) == 3, "control: letters, digits, - and _ are valid segments")
    c.finish()
