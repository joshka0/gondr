"""Cases for `gondr token` (F34-F37).

The factory is an external executable, stubbed as `gondr-factory` (it logs argv and GONDR_BIN).
`gondr token` needs a real launcher as argv[0]; the rest of the gate runs `python -m gondr`, whose
argv[0] is `__main__.py` and which the spec refuses. So these cases run an installed-console-script
style launcher (`launcher()`), except where they test that refusal.
"""

import os
import shutil

from gondr_gate.constants import ACME, ACMELIB, APP, PY, SHOP, VENDOR
from gondr_gate.sandbox import case, stops

PROVIDER = "cloudflare"
MINT_OPTS = ["--name", "ci-deploy", "--limit", "5"]
VERBS = ["mint", "revoke", "exec", "check", "import", "list", "create"]
NON_MINT = [v for v in VERBS if v != "mint"]


def launcher(c, name="gondr", mode=0o755):
    """A console-script style entry point, the way pip installs `gondr`."""
    d = c.tmp / "launch"
    d.mkdir(exist_ok=True)
    p = d / name
    p.write_text("#!%s\nimport sys\nfrom gondr.cli import main\nsys.exit(main())\n" % PY)
    p.chmod(mode)
    return p


def setup(c, factory=None):
    """Point [factory] binary at the stub (default: the stub in the sandbox bin folder)."""
    c.configure(factory=str(factory or c.bin / "gondr-factory"))


def tk(c, args, cwd=None, **kw):
    """Run `gondr token ...` through the launcher."""
    return c.run(["token"] + list(args), cwd=cwd, cmd=[str(launcher(c))], **kw)


def fac(c):
    return c.stubs("gondr-factory")


def mint_want(env, path, opts=MINT_OPTS, provider=PROVIDER):
    return ["mint", provider] + list(opts) + ["--env", env, "--path", path]


def untouched(c, label):
    c.check(fac(c) == [], "no factory exec: " + label)
    c.check(c.fake.reqs == [] and c.sensitive_stubs() == [], "no login, Keychain read or HTTP request: " + label)


def refused(c, r, label, code=1):
    c.check(r.code == code, "exits %d: %s (got %d)" % (code, label, r.code))
    untouched(c, label)


def one_exec(c, r, want, label):
    calls = fac(c)
    c.check(r.code == 0 and len(calls) == 1, "%s: factory runs once and gondr exits 0 (exit %d)" % (label, r.code))
    c.check(bool(calls) and calls[0]["argv"] == want,
            "%s: factory argv is %s (got %s)" % (label, want, calls[0]["argv"] if calls else None))
    c.clear_stubs()
    return calls


# ---------------------------------------------------------------- F34


@case
def f34_unknown_verb_or_too_few_arguments_print_usage_and_never_exec(c):
    setup(c)
    ok = tk(c, ["list", PROVIDER])
    one_exec(c, ok, ["list", PROVIDER], "control: a valid verb and provider")
    for args in (["token"], ["token", "mint"], ["token", "list"], ["token", "revoke"],
                 ["token", "bogus", PROVIDER], ["token", "Mint", PROVIDER], ["token", PROVIDER, "mint"],
                 ["token", "rotate", PROVIDER, "--env", "dev"]):
        c.clear_stubs()
        r = c.run(args, cmd=[str(launcher(c))])
        refused(c, r, "`%s`" % " ".join(args))
        c.check("usage" in r.text.lower(), "usage is printed for `%s`" % " ".join(args))
    c.finish()


@case
def f34_missing_or_non_executable_factory_binary_exits_1_with_install_hint(c):
    missing = c.tmp / "nowhere" / "gondr-factory"
    plain = c.tmp / "plain" / "gondr-factory"
    plain.parent.mkdir()
    shutil.copy(c.bin / "gondr-factory", plain)
    plain.chmod(0o644)
    for label, path in (("missing file", missing), ("file without execute bit", plain)):
        setup(c, path)
        for args in (["list", PROVIDER], ["mint", PROVIDER, "--name", "ci-deploy"]):
            c.clear_stubs()
            r = tk(c, args)
            refused(c, r, "%s, verb %s" % (label, args[0]))
            c.check("factory/bin/install" in r.text, "the hint names factory/bin/install (%s, %s)" % (label, args[0]))
    # the default location is ~/.local/share/gondr/gondr-factory when the config has no [factory] table
    c.configure()
    r = tk(c, ["list", PROVIDER])
    refused(c, r, "default binary path absent")
    c.check("factory/bin/install" in r.text, "the hint names factory/bin/install (default path)")
    c.finish()


@case
def f34_factory_binary_that_is_a_folder_exits_1_with_install_hint(c):
    folder = c.tmp / "folder" / "gondr-factory"
    folder.mkdir(parents=True)
    setup(c, folder)
    for args in (["list", PROVIDER], ["mint", PROVIDER, "--name", "ci-deploy"]):
        r = tk(c, args)
        refused(c, r, "folder as binary, verb %s" % args[0])
        c.check("factory/bin/install" in r.text, "the hint names factory/bin/install (folder, %s)" % args[0])
    c.finish()


@case
def f34_factory_binary_comes_from_config_or_the_home_default(c):
    default = c.home / ".local" / "share" / "gondr" / "gondr-factory"
    default.parent.mkdir(parents=True)
    shutil.copy(c.bin / "gondr-factory", default)
    default.chmod(0o755)
    c.configure()
    r = tk(c, ["check", PROVIDER, "--json"])
    one_exec(c, r, ["check", PROVIDER, "--json"], "default path under HOME")
    other = c.home / "tools" / "gondr-factory"
    other.parent.mkdir()
    shutil.copy(c.bin / "gondr-factory", other)
    other.chmod(0o755)
    c.configure(factory="~/tools/gondr-factory")
    r = tk(c, ["check", PROVIDER, "--json"])
    c.check(r.code == 0 and len(fac(c)) == 1, "a `~` in [factory] binary expands to HOME")
    c.finish()


# ---------------------------------------------------------------- F35


@case
def f35_mint_defaults_to_default_env_and_repo_folder_like_set(c):
    setup(c)
    one_exec(c, tk(c, ["mint", PROVIDER] + MINT_OPTS), mint_want("dev", APP), "personal repo root")
    sub = c.app / "src" / "lib"
    sub.mkdir(parents=True)
    one_exec(c, tk(c, ["mint", PROVIDER] + MINT_OPTS, cwd=sub), mint_want("dev", APP), "subfolder of the repo")
    one_exec(c, tk(c, ["mint", PROVIDER] + MINT_OPTS, cwd=c.shop), mint_want("dev", SHOP), "second personal repo")
    one_exec(c, tk(c, ["mint", PROVIDER] + MINT_OPTS, cwd=c.acme), mint_want("dev", ACME), "repo inside the Acme boundary")
    one_exec(c, tk(c, ["mint", PROVIDER]), mint_want("dev", APP, opts=[]), "no other options")
    wt = c.tmp / "work" / "api-wt"
    wt.mkdir(parents=True)
    c.git[str(wt)] = str(c.acme / ".git")
    one_exec(c, tk(c, ["mint", PROVIDER] + MINT_OPTS, cwd=wt), mint_want("dev", ACME), "linked worktree maps to its main checkout")
    c.configure(factory=str(c.bin / "gondr-factory"), folders=[("~/repos/personal/app", "/repos/personal/mapped-app")])
    one_exec(c, tk(c, ["mint", PROVIDER] + MINT_OPTS), mint_want("dev", "/repos/personal/mapped-app"), "[folders] mapping")
    untouched(c, "default mints")
    c.finish()


@case
def f35_mint_sends_the_users_env_and_path_once_at_the_end_and_keeps_other_options_in_order(c):
    setup(c)
    one_exec(c, tk(c, ["mint", PROVIDER, "--env", "staging", "--path", VENDOR] + MINT_OPTS),
             mint_want("staging", VENDOR), "env and path first")
    one_exec(c, tk(c, ["mint", PROVIDER, "--name", "ci-deploy", "--path", VENDOR, "--limit", "5", "--env", "staging"]),
             mint_want("staging", VENDOR), "env and path between other options")
    one_exec(c, tk(c, ["mint", PROVIDER] + MINT_OPTS + ["--path", "/shared/new/team"]),
             mint_want("dev", "/shared/new/team"), "explicit --path alone keeps the default env and a not yet existing folder")
    one_exec(c, tk(c, ["mint", PROVIDER, "--env", "staging"] + MINT_OPTS), mint_want("staging", APP),
             "explicit --env alone keeps the repo folder")
    one_exec(c, tk(c, ["mint", PROVIDER, "--path", ACMELIB, "--name", "ci-deploy"], cwd=c.acme),
             mint_want("dev", ACMELIB, opts=["--name", "ci-deploy"]), "explicit path inside the boundary")
    r = tk(c, ["mint", "openrouter", "--limit", "5", "--env", "staging", "--env", "prod", "--path", VENDOR])
    calls = fac(c)
    c.check(len(calls) == 1 and calls[0]["argv"].count("--env") == 1 and calls[0]["argv"].count("--path") == 1,
            "the factory sees exactly one --env and one --path, never the user's own copy")
    c.check(c.fake.reqs == [] and c.sensitive_stubs() == [], "no login or HTTP request for explicit mints")
    c.finish()


@case
def f35_mint_refuses_unknown_env_before_exec(c):
    setup(c)
    one_exec(c, tk(c, ["mint", PROVIDER, "--env", "staging"] + MINT_OPTS), mint_want("staging", APP), "control: a configured env")
    for env in ("qa", "Dev", "dev ", "production", ""):
        r = tk(c, ["mint", PROVIDER, "--env", env] + MINT_OPTS)
        refused(c, r, "unknown env %r" % env)
        r = tk(c, ["mint", PROVIDER, "--path", VENDOR, "--env", env])
        refused(c, r, "unknown env %r with an explicit path" % env)
    c.finish()


@case
def f35_mint_refuses_boundary_violations_before_exec(c):
    setup(c)
    one_exec(c, tk(c, ["mint", PROVIDER, "--path", "/repos/personal/other"]),
             mint_want("dev", "/repos/personal/other", opts=[]), "control: personal repo, personal path")
    for path in (ACME, "/repos/acme", ACMELIB, ACME + "/web"):
        r = tk(c, ["mint", PROVIDER, "--path", path])
        stops(c, r, code=1)
        untouched(c, "personal repo, --path %s" % path)
    for path in (VENDOR, APP, "/repos/acmex", "/shared/x"):
        r = tk(c, ["mint", PROVIDER, "--path", path], cwd=c.acme)
        stops(c, r, code=1)
        untouched(c, "Acme repo, --path %s" % path)
    one_exec(c, tk(c, ["mint", PROVIDER, "--path", ACMELIB], cwd=c.acme), mint_want("dev", ACMELIB, opts=[]),
             "control: Acme repo, Acme shared path")
    wt = c.tmp / "work" / "api-wt"
    wt.mkdir(parents=True)
    c.git[str(wt)] = str(c.acme / ".git")
    r = tk(c, ["mint", PROVIDER, "--path", VENDOR], cwd=wt)
    stops(c, r, code=1)
    untouched(c, "linked worktree of an Acme checkout, --path outside Acme")
    # a [folders] mapping is a default path too: it passes the boundary check
    c.configure(factory=str(c.bin / "gondr-factory"), folders=[("~/repos/personal/app", "/repos/acme/api")])
    r = tk(c, ["mint", PROVIDER])
    stops(c, r, code=1)
    untouched(c, "personal repo mapped into Acme")
    c.configure(factory=str(c.bin / "gondr-factory"), folders=[("~/repos/acme/api", "/shared/vendor")])
    r = tk(c, ["mint", PROVIDER], cwd=c.acme)
    stops(c, r, code=1)
    untouched(c, "Acme repo mapped out of Acme")
    c.finish()


@case
def f35_mint_refuses_paths_that_set_would_refuse_before_exec(c):
    setup(c)
    one_exec(c, tk(c, ["mint", PROVIDER, "--path", "/shared/ok"]), mint_want("dev", "/shared/ok", opts=[]), "control: valid path")
    for p in ("/etc/passwd", "repos/personal/app", "shared/ok", "/repos", "/shared", "/reposx/a", "/sharedx/a",
              APP + "/../shop", APP + "/./x", "/repos//personal", "/shared/../etc", "/shared/ok/.."):
        r = tk(c, ["mint", PROVIDER, "--path", p])
        refused(c, r, "path %r" % p)
    c.finish()


@case
def f35_mint_with_double_dash_in_options_exits_1_before_exec(c):
    setup(c)
    for args in (["mint", PROVIDER, "--name", "ci-deploy", "--", "--env", "staging"],
                 ["mint", PROVIDER, "--"],
                 ["mint", PROVIDER, "--env", "staging", "--", "--limit", "5"],
                 ["mint", PROVIDER, "--path", VENDOR, "--", "echo", "hello"]):
        r = tk(c, args)
        refused(c, r, "`%s`" % " ".join(args))
    c.finish()


# ---------------------------------------------------------------- F36


@case
def f36_non_mint_verbs_pass_options_unchanged_and_add_no_env_or_path(c):
    setup(c)
    odd = ["--env", "qa", "--path", "/somewhere/else", "--json", "-x", "arg with spaces", "", "--", "$HOME", "--env=prod"]
    for verb in NON_MINT:
        prov = "github" if verb == "exec" else PROVIDER
        for opts in ([], ["--org", "acme-eu", "--tailnet", "main"], odd):
            r = tk(c, [verb, prov] + opts)
            one_exec(c, r, [verb, prov] + opts, "%s with %d option(s)" % (verb, len(opts)))
    r = tk(c, ["exec", "github", "--repos", "api", "--", "gh", "pr", "list", "--env", "x"])
    one_exec(c, r, ["exec", "github", "--repos", "api", "--", "gh", "pr", "list", "--env", "x"],
             "exec keeps a command after `--`")
    untouched(c, "non-mint verbs")
    c.finish()


@case
def f36_factory_gets_an_absolute_executable_gondr_bin_the_inherited_environment_and_its_exit_code_returns(c):
    setup(c)
    me = launcher(c)
    stale = {"GONDR_BIN": "/bin/false"}
    for args in (["list", PROVIDER], ["mint", PROVIDER, "--name", "ci-deploy"]):
        r = tk(c, args, env=stale)
        calls = fac(c)
        c.check(r.code == 0 and len(calls) == 1, "%s: factory runs once" % args[0])
        if calls:
            gb = calls[0]["env"]["GONDR_BIN"]
            c.check(bool(gb) and os.path.isabs(gb) and os.path.isfile(gb) and os.access(gb, os.X_OK),
                    "%s: GONDR_BIN is an absolute path to an executable file (got %r)" % (args[0], gb))
            c.check(bool(gb) and os.path.realpath(gb) == os.path.realpath(me),
                    "%s: GONDR_BIN is the running launcher, not a stale inherited value (got %r)" % (args[0], gb))
            c.check(calls[0]["env"]["KEEP_ME"] == "inherited-marker" and calls[0]["env"]["HOME"] == str(c.home),
                    "%s: the factory keeps the inherited environment" % args[0])
        c.clear_stubs()
    # started by a relative path or through a symlink: GONDR_BIN is still absolute and points at the launcher
    link = c.tmp / "link" / "gondr"
    link.parent.mkdir()
    link.symlink_to(me)
    for label, cmd in (("relative path", [os.path.relpath(me, c.app)]), ("symlink", [str(link)])):
        r = c.run(["token", "mint", PROVIDER, "--name", "ci-deploy"], cmd=cmd)
        calls = fac(c)
        gb = calls[0]["env"]["GONDR_BIN"] if calls else None
        c.check(r.code == 0 and bool(gb) and os.path.isabs(gb) and os.path.realpath(gb) == os.path.realpath(me),
                "GONDR_BIN is absolute and names the launcher when started by %s (got %r)" % (label, gb))
        c.clear_stubs()
    # exec replaces gondr: the factory's exit status is gondr's
    c.stub["factory_exit"] = 3
    r = tk(c, ["list", PROVIDER])
    c.check(r.code == 3 and len(fac(c)) == 1, "the factory's exit status 3 is gondr's exit status (got %d)" % r.code)
    c.finish()


@case
def f36_python_dash_m_or_a_non_executable_launcher_is_refused_before_exec(c):
    setup(c)
    ok = tk(c, ["list", PROVIDER])
    one_exec(c, ok, ["list", PROVIDER], "control: an executable launcher")
    for args in (["token", "list", PROVIDER], ["token", "mint", PROVIDER, "--name", "ci-deploy"]):
        r = c.run(args)  # python -m gondr: argv[0] is __main__.py
        refused(c, r, "`python -m gondr %s`" % " ".join(args[:2]))
        plain = launcher(c, "gondr-plain", mode=0o644)
        r = c.run(args, cmd=[PY, str(plain)])  # argv[0] is a file without the execute bit
        c.check(not os.access(plain, os.X_OK), "harness: the launcher copy is not executable")
        refused(c, r, "non-executable launcher, verb %s" % args[1])
    c.finish()


# ---------------------------------------------------------------- F37


@case
def f37_no_token_verb_logs_in_to_infisical_or_sends_an_http_request(c):
    setup(c)
    for verb in VERBS:
        argv = [verb, PROVIDER] + (["--name", "ci-deploy"] if verb == "mint" else ["--json"])
        r = tk(c, argv)
        one_exec(c, r, argv + (["--env", "dev", "--path", APP] if verb == "mint" else []), "verb %s" % verb)
        untouched(c, "verb %s" % verb)
    r = tk(c, ["mint", PROVIDER, "--env", "staging", "--path", "/shared/new/team"])
    one_exec(c, r, mint_want("staging", "/shared/new/team", opts=[]), "mint into a folder that does not exist yet")
    c.check(c.fake.reqs == [] and c.sensitive_stubs() == [],
            "mint into a missing folder creates no folder: gondr sends no request, the later `set` does")
    c.finish()
