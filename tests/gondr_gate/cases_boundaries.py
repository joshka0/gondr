"""Cases for boundary stops and linked worktrees (F06-F08)."""

from gondr_gate.constants import ACME, ACMELIB, APP, VENDOR
from gondr_gate.sandbox import case, stops


# ---------------------------------------------------------------- boundaries


def boundary_runs(c, cwd, stop_cmds, ok_cmds):
    """stop_cmds: (argv, stdin). Each must stop before Keychain, login, HTTP or exec."""
    for args, stdin in stop_cmds:
        c.clear_stubs()
        c.clear_http()
        r = c.run(args, cwd=cwd, stdin=stdin)
        stops(c, r)
        c.check(c.fake.reqs == [], "F06 no HTTP request or login: " + " ".join(args))
        c.check(c.sensitive_stubs() == [], "F06 no Keychain read or exec: " + " ".join(args))
    for args, stdin in ok_cmds:
        c.clear_http()
        r = c.run(args, cwd=cwd, stdin=stdin)
        c.check(r.code == 0 and c.fake.reqs != [], "control: allowed, so the stops above are boundary stops: " + " ".join(args))


@case
def f06_f07_personal_repo_cannot_use_acme_paths(c):
    v = b"value-1"
    boundary_runs(c, c.app, [
        (["ls", ACME], b""), (["ls", "/repos/acme"], b""), (["ls", ACMELIB], b""),
        (["need", "K_ONE", "--path", ACME], b""), (["need", "K_ONE", "--from", ACME], b""),
        (["need", "K_ONE", "--from", ACMELIB], b""),
        (["set", "K_ONE", "--path", ACME], v), (["run", "--path", ACME, "--", "childprobe"], b""),
    ], [
        (["ls", "/repos/acmex"], b""),  # shares the prefix text but is not under B.prefix/
        (["ls", "/repos/personal/other"], b""),
    ])
    c.finish()


@case
def f06_f07_acme_repo_cannot_use_non_acme_paths(c):
    v = b"value-1"
    boundary_runs(c, c.acme, [
        (["ls", VENDOR], b""), (["ls", APP], b""), (["ls", "/repos/acmex"], b""),
        (["need", "K_ONE", "--path", VENDOR], b""), (["need", "K_ONE", "--from", VENDOR], b""),
        (["set", "K_ONE", "--path", "/shared/x"], v), (["set", "K_ONE", "--path", APP], v),
        (["run", "--path", APP, "--", "childprobe"], b""),
    ], [
        (["ls"], b""), (["ls", ACMELIB], b""),
        (["set", "K_ONE", "--path", ACMELIB], v),
    ])
    c.finish()


@case
def f06_f07_onboard_stops_for_a_boundary_folder_with_exit_1(c):
    adm = str(c.tmp / "adm")
    for cwd in (c.app, c.acme):
        c.clear_http()
        c.clear_stubs()
        r = c.run(["onboard", ACME, "--admin-home", adm, "--dry-run"], cwd=cwd)
        c.check(r.code == 1 and "Acme" in r.text, "onboard of a Acme folder exits 1 and names Acme (cwd %s)" % cwd.name)
        c.check(c.fake.reqs == [] and c.sensitive_stubs() == [], "F06 no HTTP, Keychain or broker call before the stop")
    c.finish()


@case
def f08_linked_worktree_of_a_acme_checkout_stays_inside_the_boundary(c):
    wt = c.tmp / "work" / "api-wt"
    wt.mkdir(parents=True)
    c.git[str(wt)] = str(c.acme / ".git")  # git-common-dir of a linked worktree: the main checkout
    boundary_runs(c, wt, [
        (["ls", VENDOR], b""), (["need", "K_ONE", "--path", VENDOR], b""),
        (["set", "K_ONE", "--path", "/shared/x"], b"v"), (["run", "--path", VENDOR, "--", "childprobe"], b""),
    ], [])
    c.clear_http()
    r = c.run(["ls"], cwd=wt)
    sec = c.gets("/api/v4/secrets")
    c.check(r.code == 0 and sec and sec[0]["query"].get("secretPath") == ACME,
            "F08 the repo folder of a linked worktree is the main checkout's folder")
    c.clear_stubs()
    r = c.run(["agent", "--vault", "shared", "claude"], cwd=wt)
    stops(c, r, code=77)
    c.check([e for e in c.stubs("agent-vault") if e["argv"][:1] == ["run"]] == [], "F08 agent does not start on a non-Acme vault")
    c.finish()
