"""The config file, the repo folder, and boundaries."""
import json
import os
import posixpath
import subprocess
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

from gondr.common import die


def expand(p):
    return Path(os.path.expanduser(str(p))).resolve()


def normalize_path(path):
    """Canonical POSIX form of an Infisical path (collapsing leading `//`, `.` and `..`)."""
    norm = posixpath.normpath("/" + path.lstrip("/"))
    return norm if norm.startswith("/") else "/" + norm


def check_segments(path):
    if path != "/" and any(seg in ("", ".", "..") for seg in path.split("/")[1:]):
        die(f"{path} has an empty, '.' or '..' segment")
    return path


def config_path():
    if os.environ.get("GONDR_CONFIG"):
        return Path(os.environ["GONDR_CONFIG"])
    base = os.environ.get("XDG_CONFIG_HOME") or str(Path.home() / ".config")
    return Path(base) / "gondr" / "config.toml"


@dataclass
class Boundary:
    """One set of secrets that stays with one set of directories."""
    name: str
    dir: Path
    prefix: str
    shared: str | None = None
    vault_prefix: str | None = None
    allow_vaults: list = field(default_factory=list)
    deny_agents: list = field(default_factory=list)

    def holds(self, path):
        norm = normalize_path(path)
        return norm == self.prefix or norm.startswith(self.prefix + "/")

    def holds_vault(self, vault):
        return bool(self.vault_prefix) and vault.startswith(self.vault_prefix)


@dataclass
class Config:
    url: str
    project: str | None
    environments: list
    default_environment: str
    warn_environments: list
    credentials: dict
    repos_root: Path
    prefix: str
    shared: str
    service_roots: list
    agent_vault: dict | None
    services: dict
    boundaries: list
    folders: dict
    factory: dict


def load():
    path = config_path()
    try:
        raw = tomllib.loads(path.read_text())
    except FileNotFoundError:
        die(f"no config file at {path}", "copy config.example.toml there, or set GONDR_CONFIG")
    except (OSError, tomllib.TOMLDecodeError) as e:
        die(f"cannot read {path}: {e}")
    inf = raw.get("infisical") or {}
    if not inf.get("url"):
        die(f"{path} has no infisical.url")
    layout = raw.get("layout") or {}
    av = raw.get("agent_vault")
    if av is not None:
        av = {"binary": "agent-vault", "default_vault": "shared", "grant_agents": [],
              "references_folder": "agent-vault", **av}
        av["binary"] = os.path.expanduser(av["binary"])
    return Config(
        url=inf["url"].rstrip("/"),
        project=inf.get("project"),
        environments=inf.get("environments", ["dev", "staging", "prod"]),
        default_environment=inf.get("default_environment", "dev"),
        warn_environments=inf.get("warn_environments", ["prod"]),
        credentials=inf.get("credentials") or {"source": "env"},
        repos_root=expand(layout.get("repos_root", "~/repos")),
        prefix=normalize_path("/" + layout.get("prefix", "/repos").strip("/")),
        shared=normalize_path("/" + layout.get("shared", "/shared").strip("/")),
        service_roots=[normalize_path("/" + r.strip("/")) for r in layout.get("service_roots", [])],
        agent_vault=av,
        services=raw.get("services") or {},
        boundaries=[Boundary(name=b["name"], dir=expand(b["dir"]),
                             prefix=normalize_path("/" + b["prefix"].strip("/")),
                             shared=normalize_path("/" + b["shared"].strip("/")) if b.get("shared") else None,
                             vault_prefix=b.get("vault_prefix"),
                             allow_vaults=b.get("allow_vaults", []), deny_agents=b.get("deny_agents", []))
                    for b in raw.get("boundary", [])],
        folders={expand(d): normalize_path("/" + f.strip("/")) for d, f in (raw.get("folders") or {}).items()},
        factory={"binary": os.path.expanduser((raw.get("factory") or {}).get(
            "binary", "~/.local/share/gondr/gondr-factory"))},
    )


def git(*args):
    try:
        r = subprocess.run(["git", *args], capture_output=True, text=True)
    except FileNotFoundError:
        return None
    return Path(r.stdout.strip()) if r.returncode == 0 and r.stdout.strip() else None


class Scope:
    """Where the command runs: working directory, repo root, and the boundary they are in."""

    def __init__(self, cfg):
        self.cfg = cfg
        self.cwd = Path.cwd().resolve()
        common = git("rev-parse", "--path-format=absolute", "--git-common-dir")
        # The main checkout, also from a linked worktree. Outside Git: the nearest .infisical.json.
        self.root = common.resolve().parent if common else next(
            (d for d in [self.cwd, *self.cwd.parents] if (d / ".infisical.json").exists()), None)

    def inside(self, b):
        return self.cwd.is_relative_to(b.dir) or bool(self.root and self.root.is_relative_to(b.dir))

    def boundary(self):
        return next((b for b in self.cfg.boundaries if self.inside(b)), None)

    def owner_boundary(self, path):
        return next((b for b in self.cfg.boundaries if b.holds(path)), None)

    def guard(self, path):
        """A boundary's secrets stay with its directories, and its directories with its secrets."""
        norm = normalize_path(path)
        for b in self.cfg.boundaries:
            if b.holds(norm) and not self.inside(b):
                die(f"{path} belongs to {b.name}; use it only from a directory under {b.dir}")
            if self.inside(b) and not b.holds(norm):
                die(f"a {b.name} directory reaches only {b.prefix}, not {path}")
        check_segments(path)
        return norm

    @staticmethod
    def absolute(path):
        if not path.startswith("/"):
            die(f"{path} is not an absolute Infisical folder", f"pass /{path}")
        if path == "/":
            return "/"
        # Strip at most one trailing slash so trailing `//` is still caught as an empty segment.
        return path[:-1] if path.endswith("/") and not path.endswith("//") else path

    def folder(self, explicit=None):
        if explicit:
            return self.guard(self.absolute(explicit))
        # A [folders] entry maps a repo whose folder does not follow its path; the longest match wins.
        mapped = [d for d in self.cfg.folders if self.root and self.root.is_relative_to(d)]
        if mapped:
            return self.guard(self.cfg.folders[max(mapped, key=lambda d: len(d.parts))])
        if not self.root or not self.root.is_relative_to(self.cfg.repos_root):
            die(f"not inside a repo under {self.cfg.repos_root}", "pass --path <infisical folder>")
        rel = self.root.relative_to(self.cfg.repos_root).as_posix()
        return self.guard(self.cfg.prefix + ("/" + rel if rel != "." else ""))

    def project(self):
        binding = self.root / ".infisical.json" if self.root else None
        if binding and binding.exists():
            try:
                pid = json.loads(binding.read_text()).get("workspaceId")
            except (OSError, ValueError):
                die(f"cannot read {binding}")
            if pid:
                return pid
        return self.cfg.project or die("no Infisical project", "set infisical.project or add .infisical.json")
