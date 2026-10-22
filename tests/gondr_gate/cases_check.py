"""Cases for `check` (F23, F30)."""

import json
import re

from gondr_gate.constants import ACME, APP, VENDOR
from gondr_gate.sandbox import case
from gondr_gate.world import ACME_OTHER, PERSONAL_OTHER, seed_acme

EXAMPLE_VALUES = ["CANARY-EXAMPLE-VALUE-1", "CANARY-EXAMPLE-VALUE-2", "CANARY-EXAMPLE-VALUE-3", "CANARY-EXAMPLE-VALUE-4"]
EXAMPLE = """# header comment
export LOCAL_KEY=1
VENDOR_KEY= %s
# COMMENTED_KEY=x
  INDENTED_KEY=
not a line
MISSING_KEY=%s
export   SPACED_KEY  =  %s
export WITH_EQ=a=b=%s
""" % tuple(EXAMPLE_VALUES)


def seed_check(c):
    c.fake.seed(APP, ["LOCAL_KEY", "SPACED_KEY", "WITH_EQ"])
    c.fake.seed(VENDOR, ["VENDOR_KEY"])
    c.fake.seed(PERSONAL_OTHER, ["INDENTED_KEY"])


def check_lines(text):
    """{name: (status, route)} for each `<status> <NAME>[: <route>]` line, plus the order of names."""
    got, order = {}, []
    for line in text.splitlines():
        m = re.match(r"^(ok|import|repo-owned|missing) ([A-Za-z_][A-Za-z0-9_]*)(?:: (.*))?$", line.strip())
        if m:
            got[m.group(2)] = (m.group(1), m.group(3) or "")
            order.append(m.group(2))
    return got, order


def no_value_anywhere(c):
    seen = json.dumps(c.fake.reqs) + json.dumps([(e["argv"], e["stdin"]) for e in c.stubs()])
    return not any(v in seen for v in EXAMPLE_VALUES)


@case
def f30_check_reads_names_from_the_example_file_and_never_a_value(c):
    c.canaries += EXAMPLE_VALUES
    seed_check(c)
    (c.app / ".env.example").write_text(EXAMPLE)
    r = c.run(["check"])
    got, order = check_lines(r.out)
    want = {"LOCAL_KEY": "ok", "VENDOR_KEY": "import", "INDENTED_KEY": "repo-owned", "MISSING_KEY": "missing",
            "SPACED_KEY": "ok", "WITH_EQ": "ok"}
    c.check({k: v[0] for k, v in got.items()} == want,
            "F30 names and statuses (export, spaces, indentation, a second '=' are read right; comments and junk skipped): %s"
            % {k: v[0] for k, v in got.items()})
    c.check(order == sorted(order) and len(order) == len(want), "lines are sorted by name")
    c.check(r.code == 1, "F30 a gap in the list gives exit 1")
    c.check("gondr need VENDOR_KEY" in got.get("VENDOR_KEY", ("", ""))[1], "import: route `gondr need <NAME>`")
    c.check("gondr set MISSING_KEY" in got.get("MISSING_KEY", ("", ""))[1] and APP in got.get("MISSING_KEY", ("", ""))[1],
            "missing: the operator `gondr set` command for the repo folder")
    own = got.get("INDENTED_KEY", ("", ""))[1]
    c.check("INDENTED_KEY" in own and PERSONAL_OTHER in own, "repo-owned: the ask-the-operator route names the other folder")
    c.check(no_value_anywhere(c), "F30 no example value is in any request, stub argument or stdin (and none in the output)")
    r = c.run(["check", "--json"])
    try:
        doc = json.loads(r.out)
    except ValueError:
        doc = {}
    names = {n.get("name"): n.get("status") for n in doc.get("names", [])}
    c.check(r.code == 1 and names == want and doc.get("folder") == APP and str(doc.get("file", "")).endswith(".env.example"),
            "--json: folder, file and names with statuses")
    c.check(no_value_anywhere(c), "F30 --json also carries no value")
    c.check(c.writes() == [], "F23 check makes no state-changing request")
    c.finish()


@case
def f30_check_exits_0_only_when_every_name_is_ok_and_takes_names_from_arguments(c):
    seed_check(c)
    (c.app / ".env.example").write_text(EXAMPLE)
    r = c.run(["check", "LOCAL_KEY", "SPACED_KEY"])
    got, _ = check_lines(r.out)
    c.check(r.code == 0 and {k: v[0] for k, v in got.items()} == {"LOCAL_KEY": "ok", "SPACED_KEY": "ok"},
            "names from the arguments, all ok: exit 0, and the example file is not read")
    r = c.run(["check", "LOCAL_KEY", "MISSING_KEY"])
    got, _ = check_lines(r.out)
    c.check(r.code == 1 and got.get("MISSING_KEY", ("",))[0] == "missing" and got.get("LOCAL_KEY", ("",))[0] == "ok",
            "one missing name: exit 1")
    r = c.run(["check", "--env", "qa", "LOCAL_KEY"])
    c.clear_http()
    r = c.run(["check", "--env", "qa", "LOCAL_KEY"])
    c.check(r.code != 0 and c.api() == [], "F22 an unknown environment stops check before any secret request")
    c.finish()


@case
def f30_check_finds_the_example_file_in_the_documented_order(c):
    seed_check(c)
    pkg = c.app / "pkg"
    pkg.mkdir()
    r = c.run(["check"])
    c.check(r.code == 1 and check_lines(r.out)[0] == {}, "no names and no file: exit 1 with a hint")
    for rel, name in ((".env.template", "WITH_EQ"), (".env.sample", "SPACED_KEY"), (".env.example", "LOCAL_KEY")):
        (c.app / rel).write_text("%s=\n" % name)
        r = c.run(["check"])
        c.check(list(check_lines(r.out)[0]) == [name], "%s is used (it comes before the files listed after it)" % rel)
    r = c.run(["check"], cwd=pkg)
    c.check(list(check_lines(r.out)[0]) == ["LOCAL_KEY"], "from a subfolder the file at the checkout top is found")
    (pkg / ".env.sample").write_text("WITH_EQ=\n")
    r = c.run(["check"], cwd=pkg)
    c.check(list(check_lines(r.out)[0]) == ["WITH_EQ"], "a file in the working directory beats the checkout top")
    (c.app / "other.env").write_text("export SPACED_KEY=\n")
    r = c.run(["check", "--file", "other.env"])
    c.check(list(check_lines(r.out)[0]) == ["SPACED_KEY"], "--file F overrides the search")
    c.finish()


@case
def f27_f30_check_statuses_follow_the_boundary(c):
    seed_check(c)
    seed_acme(c.fake)
    c.fake.seed(ACME, ["ACME_OWN"])
    c.fake.seed(ACME_OTHER, ["ACME_ELSEWHERE"])
    names = ["ACME_OWN", "STRIPE_ACME_SHARED", "ACME_ELSEWHERE", "VENDOR_KEY", "INDENTED_KEY"]
    r = c.run(["check"] + names, cwd=c.acme)
    got, _ = check_lines(r.out)
    c.check({k: v[0] for k, v in got.items()} == {"ACME_OWN": "ok", "STRIPE_ACME_SHARED": "import",
                                                  "ACME_ELSEWHERE": "repo-owned", "VENDOR_KEY": "missing",
                                                  "INDENTED_KEY": "missing"},
            "inside Acme: Acme keys route normally, personal and /shared keys are `missing`: %s" % {k: v[0] for k, v in got.items()})
    c.check("/repos/personal" not in r.out and VENDOR not in r.out and "--path %s" % ACME in r.out,
            "F27 inside Acme no personal or /shared folder is named; the set command targets the Acme folder")
    r = c.run(["check", "ACME_OWN", "STRIPE_ACME_SHARED", "ACME_ELSEWHERE"])
    got, _ = check_lines(r.out)
    c.check(r.code == 1 and {v[0] for v in got.values()} == {"missing"} and "/repos/acme" not in r.out,
            "F27 outside Acme every Acme key is `missing` and no Acme folder is named")
    c.finish()


@case
def f23_check_writes_nothing_and_prints_no_value_when_the_api_returns_values(c):
    c.canaries += EXAMPLE_VALUES
    c.fake.leak = True
    seed_check(c)
    (c.app / ".env.example").write_text(EXAMPLE)
    r = c.run(["check"])
    c.check(check_lines(r.out)[0] != {}, "check still lists names while the API leaks values")
    c.check(c.writes() == [] and no_value_anywhere(c), "F23 no write and no example value in any request")
    c.finish()


@case
def f32_check_treats_a_404_repo_folder_as_empty(c):
    seed_check(c)
    del c.fake.secrets[("dev", APP)]
    c.fake.missing.add(("dev", APP))
    r = c.run(["check", "VENDOR_KEY", "LOCAL_KEY"])
    got, _ = check_lines(r.out)
    c.check(r.code == 1 and "404" not in r.text and {k: v[0] for k, v in got.items()}
            == {"VENDOR_KEY": "import", "LOCAL_KEY": "missing"}, "F32 an empty folder: shared key -> import, own key -> missing (%s)"
            % {k: v[0] for k, v in got.items()})
    c.finish()
