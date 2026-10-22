import os
import subprocess
import sys
from pathlib import Path
from typing import NoReturn


def die(msg, hint=None, code=1) -> NoReturn:
    print(f"gondr: {msg}", file=sys.stderr)
    if hint:
        print(f"  next: {hint}", file=sys.stderr)
    sys.exit(code)


def keychain(account, service):
    """A generic password from the macOS Keychain. The value never reaches output."""
    try:
        r = subprocess.run(["security", "find-generic-password", "-a", account, "-s", service, "-w"],
                           capture_output=True, text=True)
    except FileNotFoundError:
        die("the `security` tool is missing; Keychain works only on macOS",
            'set source = "env" in the config')
    if r.returncode != 0 or not r.stdout.strip():
        die(f"Keychain item {service} for account {account} is missing", "store it with `security add-generic-password`")
    return r.stdout.strip()


def env_secret(name):
    value = os.environ.get(name)
    if not value:
        die(f"{name} is not set")
    return value


def state_home():
    base = os.environ.get("XDG_STATE_HOME") or str(Path.home() / ".local/state")
    return Path(base) / "gondr"


def parse(args, flags=(), switches=()):
    """Split args into {flag: value} options and the rest. Everything after `--` is rest."""
    opts, rest = {}, []
    it = iter(args)
    for a in it:
        if a == "--":
            rest.extend(it)
            break
        if a in flags:
            opts[a[2:]] = next(it, None) or die(f"{a} needs a value")
        elif a in switches:
            opts[a[2:]] = True
        else:
            rest.append(a)
    return opts, rest
