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


def keychain_value(account, service):
    """A generic password from the macOS Keychain, or None. The value never reaches output."""
    try:
        r = subprocess.run(["security", "find-generic-password", "-a", account, "-s", service, "-w"],
                           capture_output=True, text=True)
    except FileNotFoundError:
        return None
    return r.stdout.strip() if r.returncode == 0 and r.stdout.strip() else None


def keychain(account, service):
    return keychain_value(account, service) or die(
        f"Keychain item {service} for account {account} is missing (Keychain works only on macOS)",
        'store it with `security add-generic-password`, or set source = "env" in the config')


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
