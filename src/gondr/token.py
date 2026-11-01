"""`gondr token`: scoped cloud credentials from the Touch ID factory (factory/, macOS).

The factory holds the parent credentials in the Keychain and asks for Touch ID. For `mint`, gondr
first resolves and checks the Infisical folder, then the factory stores each minted value with
`gondr set` on stdin. A failed store makes the factory revoke what it minted.
"""
import os
import sys
from pathlib import Path

from gondr.common import die
from gondr.infisical import check_env, check_publish_path

VERBS = ("mint", "revoke", "exec", "check", "import", "list", "create")


def gondr_bin():
    """This gondr's own launcher, so the factory calls `gondr set` on the same install."""
    path = Path(sys.argv[0]).resolve()
    if path.name == "__main__.py" or not os.access(path, os.X_OK):
        die("the factory calls gondr back, so run the installed `gondr` command, not `python -m gondr`")
    return str(path)


def cmd_token(cfg, scope, args):
    if len(args) < 2 or args[0] not in VERBS:
        die("usage: gondr token <" + "|".join(VERBS) + "> <provider> [options]",
            "run `gondr token check cloudflare` to see the factory's full usage")
    binary = cfg.factory["binary"]
    if not os.access(binary, os.X_OK):
        die(f"no token factory at {binary}", "build it with factory/bin/install (macOS only)")
    argv = [binary, *args]
    if args[0] == "mint":
        # gondr owns the destination: --env and --path come from gondr's own flags and the repo folder.
        rest, env, path = [], None, None
        it = iter(args[2:])
        for a in it:
            if a == "--":
                die("mint takes no command")
            if a in ("--env", "--path"):
                value = next(it, None) or die(f"{a} needs a value")
                env, path = (value, path) if a == "--env" else (env, value)
            else:
                rest.append(a)
        env = check_env(cfg, env or cfg.default_environment)
        path = scope.folder(path)
        check_publish_path(cfg, scope, path)
        argv = [binary, args[0], args[1], *rest, "--env", env, "--path", path]
    os.execve(binary, argv, {**os.environ, "GONDR_BIN": gondr_bin()})
