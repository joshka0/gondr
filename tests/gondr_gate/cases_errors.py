"""Cases for HTTP and network errors, 429 retry, and unknown environments (F18, F22)."""

import re
import socket
import time

from gondr_gate.constants import APP, SET_VALUE, SHOP, VENDOR
from gondr_gate.sandbox import case


# ---------------------------------------------------------------- errors, env


@case
def f18_f02_http_errors_print_method_path_and_status_only(c):
    f = c.fake
    f.seed(VENDOR, ["VENDOR_KEY"])
    f.seed(APP, ["INPUT_KEY"])
    table = [
        ("login", "POST", r"/api/v1/auth/universal-auth/login", 403, ["ls", VENDOR], b""),
        ("secrets list", "GET", r"/api/v4/secrets", 500, ["ls", VENDOR], b""),
        ("folders list", "GET", r"/api/v2/folders", 401, ["ls", VENDOR], b""),
        ("where", "GET", r"/api/v4/secrets", 503, ["where", "VENDOR_KEY"], b""),
        ("need import create", "POST", r"/api/v2/secret-imports", 422, ["need", "VENDOR_KEY", "--path", SHOP], b""),
        ("set probe", "GET", r"/api/v4/secrets/INPUT_KEY", 403, ["set", "INPUT_KEY"], SET_VALUE.encode()),
        ("set update", "PATCH", r"/api/v4/secrets/INPUT_KEY", 500, ["set", "INPUT_KEY"], SET_VALUE.encode()),
        ("set create", "POST", r"/api/v4/secrets/NEW_KEY", 400, ["set", "NEW_KEY", "--path", "/shared/new"], SET_VALUE.encode()),
    ]
    for label, method, pat, status, args, stdin in table:
        f.fail = [(method, pat, status)]
        c.clear_http()
        r = c.run(args, stdin=stdin)
        hit = [q for q in f.reqs if q["method"] == method and re.fullmatch(pat, q["path"])]
        path = hit[0]["path"] if hit else pat
        c.check(r.code == 1, "F18 %s: exit 1" % label)
        c.check(("gondr: %s %s -> HTTP %d" % (method, path, status)) in r.text,
                "F18 %s: prints 'gondr: %s %s -> HTTP %d'" % (label, method, path, status))
        c.check("Traceback" not in r.text and (path + "?") not in r.text and "projectId" not in r.text,
                "F18 %s: no traceback and no query string" % label)
    f.fail = []
    c.finish()


@case
def f18_network_error_prints_method_path_and_reason_without_traceback(c):
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    c.configure(url="http://127.0.0.1:%d" % port)
    for args in (["ls", VENDOR], ["where", "K_ONE"]):
        r = c.run(args)
        c.check(r.code == 1, "F18 network failure exits 1 (%s)" % args[0])
        c.check(re.search(r"gondr: POST /api/v1/auth/universal-auth/login -> (?!HTTP )\S", r.text) is not None,
                "F18 prints 'gondr: <METHOD> <path> -> <reason>' (%s)" % args[0])
        c.check("Traceback" not in r.text, "F18 no traceback (%s)" % args[0])
    c.finish()


@case
def f22_unknown_env_is_rejected_before_any_secret_request(c):
    c.fake.seed(VENDOR, ["VENDOR_KEY"])
    c.fake.seed(VENDOR, ["VENDOR_KEY"], env="staging")
    ok = c.run(["ls", "--env", "staging", VENDOR])
    c.check(ok.code == 0 and c.gets("/api/v4/secrets"), "control: a configured environment works")
    for args, stdin in ((["ls", "--env", "qa", VENDOR], b""), (["where", "VENDOR_KEY", "--env", "qa"], b""),
                        (["need", "VENDOR_KEY", "--env", "qa", "--from", VENDOR], b""),
                        (["set", "NEW_KEY", "--env", "qa", "--path", "/shared/new"], b"v1"),
                        (["run", "--env", "qa", "--", "childprobe"], b""), (["ls", "--env", "PROD", VENDOR], b"")):
        c.clear_http()
        c.clear_stubs()
        r = c.run(args, stdin=stdin)
        c.check(r.code != 0 and "Traceback" not in r.text, "F22 `%s --env %s` fails" % (args[0], args[args.index("--env") + 1]))
        c.check(c.api() == [] and c.stubs("infisical") == [], "F22 `%s`: no secret request or exec" % args[0])
    c.finish()


@case
def f18_http_429_waits_retry_after_resends_and_gives_up_after_five_attempts(c):
    f = c.fake
    f.seed(VENDOR, ["VENDOR_KEY"])
    f.seed(SHOP, ["OWN_KEY"])
    login = "/api/v1/auth/universal-auth/login"
    # one 429 with Retry-After: 0, then 200: the command succeeds and the request is sent twice
    for label, method, pat, args, count, expect in (
            ("secrets list", "GET", r"/api/v4/secrets", ["ls", VENDOR], lambda: len(c.gets("/api/v4/secrets")), "VENDOR_KEY"),
            ("login", "POST", login, ["ls", VENDOR], lambda: len(c.posts(login)), "VENDOR_KEY"),
            ("import create", "POST", r"/api/v2/secret-imports", ["need", "VENDOR_KEY", "--path", SHOP, "--from", VENDOR],
             lambda: len(c.posts("/api/v2/secret-imports")), "imported")):
        f.fail = [(method, pat, 429, 1)]
        c.clear_http()
        t0 = time.monotonic()
        r = c.run(args)
        c.check(r.code == 0 and expect in r.out, "429 once (%s): the command succeeds" % label)
        c.check(count() == 2, "429 once (%s): the request is sent exactly twice" % label)
        c.check(time.monotonic() - t0 < 15, "429 once (%s): Retry-After: 0 means no long wait" % label)
    posts = c.posts("/api/v2/secret-imports")
    c.check(len(posts) == 2 and posts[0]["body"] == posts[1]["body"], "the resent import has the same body")
    # 429 every time: five attempts, then the usual HTTP error
    for label, method, pat, args in (("secrets list", "GET", r"/api/v4/secrets", ["ls", VENDOR]),
                                     ("login", "POST", login, ["ls", VENDOR])):
        f.fail = [(method, pat, 429)]
        c.clear_http()
        r = c.run(args)
        path = pat.replace("\\", "")
        n = len([q for q in f.reqs if q["method"] == method and q["path"] == path])
        c.check(r.code == 1 and ("gondr: %s %s -> HTTP 429" % (method, path)) in r.text,
                "429 every time (%s): exit 1 with 'gondr: %s %s -> HTTP 429'" % (label, method, path))
        c.check(n == 5, "429 every time (%s): exactly 5 attempts (saw %d)" % (label, n))
    # other errors are not retried
    f.fail = [("GET", r"/api/v4/secrets", 403)]
    c.clear_http()
    r = c.run(["ls", VENDOR])
    c.check(r.code == 1 and len(c.gets("/api/v4/secrets")) == 1, "HTTP 403 is not retried")
    f.fail = []
    c.finish()
