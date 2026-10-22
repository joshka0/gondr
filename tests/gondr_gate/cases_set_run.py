"""Cases for `set`, `run` and path rules (F09-F11)."""

from gondr_gate.constants import APP, PROJECT, SET_VALUE, SHOP, TOKEN, VENDOR
from gondr_gate.sandbox import case
from gondr_gate.onboard_support import broker_mutations


# ---------------------------------------------------------------- set / run


def set_body(env, path, value):
    b = {"projectId": PROJECT, "environment": env, "secretPath": path, "secretValue": value,
         "skipMultilineEncoding": True, "type": "shared"}
    return b


@case
def f09_f10_set_patches_existing_posts_missing_and_stores_bytes_exactly(c):
    c.fake.seed(APP, ["INPUT_KEY"])
    r = c.run(["set", "INPUT_KEY"], stdin=SET_VALUE.encode())
    c.check(r.code == 0 and r.out.strip() == "updated INPUT_KEY in dev:%s" % APP, "existing key prints 'updated'")
    probe = c.gets("/api/v4/secrets/INPUT_KEY")
    c.check(len(probe) == 1 and probe[0]["query"].get("viewSecretValue") == "false"
            and probe[0]["query"].get("projectId") == PROJECT and probe[0]["query"].get("environment") == "dev"
            and probe[0]["query"].get("secretPath") == APP, "existence probe is GET with viewSecretValue=false")
    patch = [q for q in c.fake.reqs if q["method"] == "PATCH" and q["path"] == "/api/v4/secrets/INPUT_KEY"]
    c.check(len(patch) == 1 and patch[0]["body"] == set_body("dev", APP, SET_VALUE),
            "F09/F10 PATCH body holds the value byte for byte (no trimming) and the fixed fields")
    c.check(c.posts("/api/v4/secrets/INPUT_KEY") == [], "F10 no POST when the secret exists")
    c.clear_http()
    r = c.run(["set", "--env", "staging", "--path", VENDOR, "NEW_KEY"], stdin=SET_VALUE.encode())
    c.check(r.code == 0 and r.out.strip() == "created NEW_KEY in staging:%s" % VENDOR,
            "missing key prints 'created' (options may come before the key)")
    post = c.posts("/api/v4/secrets/NEW_KEY")
    c.check(len(post) == 1, "F10 POST when the secret is missing (404)")
    if post:
        b = dict(post[0]["body"])
        comment = b.pop("secretComment", None)
        c.check(isinstance(comment, str) and comment != "", "POST carries a non-empty secretComment")
        c.check(b == set_body("staging", VENDOR, SET_VALUE), "POST body holds the value byte for byte and the fixed fields")
    c.check([q for q in c.fake.reqs if q["method"] == "PATCH"] == [], "F10 no PATCH when the secret is missing")
    c.finish()


@case
def f09_set_rejects_empty_value_terminal_bad_key_and_bad_path(c):
    ok = c.run(["set", "A1_B2", "--path", "/shared/ok"], stdin=b"v1")
    c.check(ok.code == 0 and len(c.writes()) == 1, "control: a valid key, path and value succeed")
    c.clear_http()

    def refused(args, stdin=b"v1", tty=False, label=""):
        r = c.run(args, stdin=stdin, tty=tty)
        c.check(r.code != 0 and "Traceback" not in r.text and c.writes() == [],
                "F09 refused without a write: " + label)
        c.clear_http()

    refused(["set", "A1_B2", "--path", "/shared/ok"], stdin=b"", label="empty stdin")
    refused(["set", "A1_B2", "--path", "/shared/ok"], stdin=b"", tty=True, label="terminal on stdin")
    for k in ("lower", "1ABC", "A-B", "A B", "A.B", "ÄBC", "_ABC", ""):
        refused(["set", k, "--path", "/shared/ok"], label="key %r" % k)
    for p in ("/etc/passwd", "repos/personal/app", "/repos", "/shared", "/reposx/a", "/sharedx/a",
              APP + "/../shop", APP + "/./x", "/repos//personal", "/shared/../etc", "/shared/ok/.."):
        refused(["set", "A1_B2", "--path", p], label="path %r" % p)
    c.finish()


@case
def f11_run_execs_infisical_with_intact_child_argv_and_hides_token(c):
    child = ["childprobe", "argument with spaces", "--env=child", "--", "-x", "$HOME", ""]
    r = c.run(["run", "--env", "staging", "--path", VENDOR, "--"] + child)
    inf = c.stubs("infisical")
    c.check(r.code == 0 and len(inf) == 1, "run execs infisical once")
    if inf:
        want = ["run", "--domain=%s/api" % c.fake.url, "--projectId=" + PROJECT, "--env=staging",
                "--path=" + VENDOR, "--silent", "--", "env", "-u", "INFISICAL_TOKEN"] + child
        c.check(inf[0]["argv"] == want, "F11 infisical argv matches the contract and the child argv is intact")
        c.check(inf[0]["env"]["INFISICAL_TOKEN"] == TOKEN, "infisical gets the machine identity token")
        c.check(inf[0]["env"]["KEEP_ME"] == "inherited-marker", "infisical gets the inherited environment")
    probe = c.stubs("childprobe")
    c.check(len(probe) == 1 and probe[0]["argv"] == child[1:], "F11 child process receives its argv unchanged")
    c.check(len(probe) == 1 and probe[0]["env"]["INFISICAL_TOKEN"] is None, "F11 INFISICAL_TOKEN does not reach the child")
    c.check(len(probe) == 1 and probe[0]["env"]["KEEP_ME"] == "inherited-marker", "child keeps the inherited environment")
    c.check(c.writes() == [] and len(c.posts("/api/v1/auth/universal-auth/login")) == 1, "run logs in once and writes nothing")
    # defaults: repo folder, default environment, from a subfolder
    c.clear_stubs()
    sub = c.app / "src"
    sub.mkdir()
    r = c.run(["run", "--", "childprobe", "-v"], cwd=sub)
    inf = c.stubs("infisical")
    c.check(r.code == 0 and len(inf) == 1 and "--env=dev" in inf[0]["argv"] and ("--path=" + APP) in inf[0]["argv"]
            and inf[0]["argv"][-3:] == ["INFISICAL_TOKEN", "childprobe", "-v"], "defaults to dev and the repo folder")
    c.finish()


@case
def f09_relative_paths_stop_with_exit_1_and_nothing_is_written(c):
    c.fake.seed(VENDOR, ["K_ONE"])
    ok = c.run(["need", "K_ONE", "--path", SHOP, "--from", VENDOR])
    c.check(ok.code == 0 and len(c.writes()) == 1, "control: absolute --path and --from work")
    ok = c.run(["set", "K_TWO", "--path", "/shared/new"], stdin=b"v1")
    c.check(ok.code == 0, "control: set with an absolute path works")
    ok = c.run(["run", "--path", VENDOR, "--", "childprobe"])
    c.check(ok.code == 0 and len(c.stubs("infisical")) == 1, "control: run with an absolute path works")
    for args, stdin in ((["ls", "shared/vendor"], b""), (["ls", "repos/personal/app"], b""), (["ls", "./shared"], b""),
                        (["ls", "../shared"], b""), (["need", "K_ONE", "--path", "shared/vendor"], b""),
                        (["need", "K_ONE", "--from", "shared/vendor"], b""),
                        (["set", "K_TWO", "--path", "shared/new"], b"v1"),
                        (["run", "--path", "shared/vendor", "--", "childprobe"], b""),
                        (["onboard", "repos/personal/shop", "--dry-run"], b"")):
        c.clear_http()
        c.clear_stubs()
        r = c.run(args, stdin=stdin)
        c.check(r.code == 1, "a relative path exits 1: %s" % " ".join(args[:3]))
        c.check(c.writes() == [] and c.stubs("infisical") == [] and broker_mutations(c) == [],
                "a relative path writes and execs nothing: %s" % " ".join(args[:3]))
    c.finish()
