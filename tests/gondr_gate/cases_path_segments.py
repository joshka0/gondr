"""Cases for `.`, `..` and empty path segments, and the onboard boundary rules (F45, F46).

A path that a boundary check reads as text must not reach a folder the check refused. These cases
pass dotted and doubled-slash paths that point into or out of the Acme boundary, and run `onboard`
from places and with options the boundary rules forbid. Every stop must come before any Keychain
read, login, HTTP request, broker call or exec.
"""

from gondr_gate.constants import ACME, APP, PY, SHOP
from gondr_gate.onboard_support import onboard_setup
from gondr_gate.sandbox import case, stops

PROVIDER = "cloudflare"

# Paths that resolve into the Acme boundary, written so that their text does not start with /repos/acme/.
INTO_ACME = ["/repos/personal/../acme/api", "/repos//acme/api", "//repos/acme/api", "/repos/./acme/api",
             "/repos/acme/api/.."]
# Paths whose text starts with /repos/acme/ but that resolve outside the Acme boundary.
OUT_OF_ACME = ["/repos/acme/../personal/app", "/repos/acme/..", "/repos/acme/../shared/vendor"]
# Paths outside every boundary that hold an empty, `.` or `..` segment.
DOTTED = ["/repos/personal/../shop", "/repos//personal/app", "/repos/./personal/app", "/shared/./vendor",
          "/repos/personal/app//", "//"]


def launcher(c):
    """A console-script style entry point (`gondr token` refuses `python -m gondr`)."""
    d = c.tmp / "launch"
    d.mkdir(exist_ok=True)
    p = d / "gondr"
    p.write_text("#!%s\nimport sys\nfrom gondr.cli import main\nsys.exit(main())\n" % PY)
    p.chmod(0o755)
    return p


def untouched(c, label):
    c.check(c.fake.reqs == [], "F06 no HTTP request or login: " + label)
    c.check(c.sensitive_stubs() == [], "F06 no Keychain read, broker call or exec: " + label)
    c.check(c.stubs("gondr-factory") == [], "F06 no factory exec: " + label)
    c.check(c.stubs("childprobe") == [], "F06 the child command never runs: " + label)


def guarded_commands(path, adm):
    """Every command that takes an explicit folder, pointed at `path`: (argv, stdin, uses the launcher)."""
    return [
        (["ls", path], b"", False),
        (["run", "--path", path, "--", "childprobe"], b"", False),
        (["need", "K_ONE", "--from", path], b"", False),
        (["need", "K_ONE", "--path", path], b"", False),
        (["set", "K_ONE", "--path", path], b"value-1", False),
        (["token", "mint", PROVIDER, "--path", path], b"", True),
        (["onboard", path, "--admin-home", adm], b"", False),
        (["onboard", path, "--admin-home", adm, "--dry-run"], b"", False),
    ]


def run_guarded(c, args, stdin, use_launcher, cwd):
    c.clear_stubs()
    c.clear_http()
    cmd = [str(launcher(c))] if use_launcher else None
    return c.run(args, cwd=cwd, stdin=stdin, cmd=cmd)


def boundary_stops(c, cwd, paths, label):
    adm = str(onboard_setup(c, gh_equal=False))
    for path in paths:
        for args, stdin, use_launcher in guarded_commands(path, adm):
            r = run_guarded(c, args, stdin, use_launcher, cwd)
            stops(c, r)
            untouched(c, "%s: %s" % (label, " ".join(args[:4])))


def linked_worktree(c):
    wt = c.tmp / "work" / "api-wt"
    wt.mkdir(parents=True, exist_ok=True)
    c.git[str(wt)] = str(c.acme / ".git")  # git-common-dir of a linked worktree: the main checkout
    return wt


def control(c, args, cwd, label, stdin=b""):
    c.clear_stubs()
    c.clear_http()
    r = c.run(args, cwd=cwd, stdin=stdin)
    c.check(r.code == 0 and (c.fake.reqs != [] or c.stubs("agent-vault") != []),
            "control: allowed, so the stops in this case are path stops: " + label)
    return r


@case
def f06_f07_f45_dotted_paths_from_outside_cannot_reach_acme(c):
    c.configure(factory=str(c.bin / "gondr-factory"))
    control(c, ["ls", "/repos/personal/other"], c.app, "personal repo, personal path")
    boundary_stops(c, c.app, INTO_ACME, "personal repo, path into Acme")
    c.finish()


@case
def f06_f07_f45_dotted_paths_from_inside_cannot_leave_acme(c):
    c.configure(factory=str(c.bin / "gondr-factory"))
    control(c, ["ls", ACME], c.acme, "Acme repo, Acme path")
    boundary_stops(c, c.acme, OUT_OF_ACME, "Acme repo, path out of Acme")
    boundary_stops(c, linked_worktree(c), OUT_OF_ACME, "linked worktree of Acme, path out of Acme")
    c.finish()


@case
def f06_f45_dotted_or_empty_segments_stop_every_explicit_folder_before_login(c):
    c.configure(factory=str(c.bin / "gondr-factory"))
    adm = str(onboard_setup(c, gh_equal=False))
    for path in DOTTED:
        for args, stdin, use_launcher in guarded_commands(path, adm):
            r = run_guarded(c, args, stdin, use_launcher, c.app)
            c.check(r.code == 1, "F45 exits 1 on a path with an empty, . or .. segment: %s (got %d)"
                    % (" ".join(args[:4]), r.code))
            untouched(c, "personal repo, dotted path: " + " ".join(args[:4]))
    # One trailing slash and the root folder stay valid outside every boundary.
    control(c, ["ls", APP + "/"], c.app, "ls with one trailing slash")
    control(c, ["ls", "/"], c.app, "ls /")
    c.finish()


@case
def f06_f07_f46_onboard_from_inside_acme_stops_for_any_folder(c):
    adm = str(onboard_setup(c, gh_equal=False))
    control(c, ["onboard", SHOP, "--admin-home", adm, "--dry-run"], c.shop, "onboard of a personal folder from a personal repo")
    for cwd, where in ((c.acme, "Acme repo"), (linked_worktree(c), "linked worktree of Acme")):
        for extra in ([], ["--dry-run"]):
            args = ["onboard", SHOP, "--admin-home", adm] + extra
            r = run_guarded(c, args, b"", False, cwd)
            stops(c, r, code=1)
            untouched(c, "%s: %s" % (where, " ".join(args[:1] + extra)))
    c.finish()


@case
def f06_f07_f46_onboard_from_outside_stops_on_an_acme_vault_or_repo_dir(c):
    adm = str(onboard_setup(c, gh_equal=False))
    control(c, ["onboard", SHOP, "--admin-home", adm, "--vault", "personal-shop-dev", "--dry-run"], c.shop,
            "onboard with a non-boundary --vault")
    other = c.repo("acme-extra/shop")
    c.fake.seed("/repos/acme-extra/shop", ["GITHUB_TOKEN"])
    runs = [
        (["onboard", SHOP, "--admin-home", adm, "--vault", "acme-prod"], c.shop, "explicit --vault acme-prod"),
        (["onboard", SHOP, "--admin-home", adm, "--vault", "acme"], c.shop, "explicit --vault acme"),
        (["onboard", "/repos/acme-extra/shop", "--admin-home", adm], other,
         "default vault acme-extra-shop-dev starts with the Acme vault prefix"),
        (["onboard", SHOP, "--admin-home", adm, "--repo-dir", str(c.acme)], c.shop, "--repo-dir inside Acme"),
    ]
    for args, cwd, label in runs:
        for extra in ([], ["--dry-run"]):
            r = run_guarded(c, args + extra, b"", False, cwd)
            stops(c, r, code=1)
            untouched(c, label + (" (dry run)" if extra else ""))
    c.finish()
