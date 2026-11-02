"""Keeper Secrets Manager: the secret store when `[store] kind = "keeper"`.

Folder `P` in environment `E` is the Keeper folder chain `E/<segments of P>` under `keeper.shared_folder`.
A key is a `login` record titled with the key name; its value is the record's `password` field.
The SDK is the optional package `keeper-secrets-manager-core`: it loads only when a command opens the store.
The KSM config and every value stay in memory. An SDK error prints its type, never its text.
"""
import logging
import os
from contextlib import contextmanager
from types import SimpleNamespace

from gondr.common import die, env_secret, keychain
from gondr.infisical import KEY


@contextmanager
def sdk_call(operation):
    """Turn any SDK error into one line: the exception text can hold a record or a value."""
    try:
        yield
    except Exception as e:
        die(f"keeper {operation} failed: {type(e).__name__}")


def segments(path):
    return [] if path == "/" else path.strip("/").split("/")


class Keeper:
    """The commands' view of the store, like infisical.Client. A folder is `(env, path)`."""

    imports = False

    def __init__(self, cfg):
        self.cfg = cfg
        self.project = cfg.keeper["shared_folder"]
        self.sm = None
        self.sdk = None
        self._folders = None
        self._records = None

    def login(self):
        # The SDK logs to its "ksm" logger, and before SecretsManager disables it, Python's fallback
        # handler prints those records on stderr. A record can quote config or server text: silence it.
        ksm_log = logging.getLogger("ksm")
        ksm_log.disabled, ksm_log.propagate = True, False
        ksm_log.addHandler(logging.NullHandler())
        try:
            from keeper_secrets_manager_core import SecretsManager
            from keeper_secrets_manager_core.dto.dtos import RecordCreate, RecordField
            from keeper_secrets_manager_core.dto.payload import CreateOptions
            from keeper_secrets_manager_core.storage import InMemoryKeyValueStorage
        except ImportError:
            die("the Keeper SDK is not installed", "pip install 'gondr[keeper]'")
        self.sdk = SimpleNamespace(RecordCreate=RecordCreate, RecordField=RecordField, CreateOptions=CreateOptions)
        c = self.cfg.keeper["config"]
        ksm_config = (keychain(c["account"], c["service"]) if c["source"] == "keychain"
                      else env_secret(c["name"])).strip()
        with sdk_call("connect"):
            self.sm = SecretsManager(config=InMemoryKeyValueStorage(ksm_config))
        return self

    # Folders

    def _all_folders(self):
        if self._folders is None:
            with sdk_call("list folders"):
                self._folders = list(self.sm.get_folders())
        return self._folders

    def _child(self, parent_uid, name, where):
        found = [f.folder_uid for f in self._all_folders() if f.parent_uid == parent_uid and f.name == name]
        if len(found) > 1:
            die(f"Keeper holds {len(found)} folders named {name} in one folder ({where})",
                "keep one folder per name in Keeper")
        return found[0] if found else None

    def _resolve(self, env, path):
        """The Keeper folder UID of `env:path`, or None when the folder does not exist."""
        uid = self.project
        for name in [env, *segments(path)]:
            uid = self._child(uid, name, f"{env}:{path}")
            if uid is None:
                return None
        return uid

    def subfolders(self, env, path):
        uid = self._resolve(env, path)
        return sorted(f.name for f in self._all_folders() if uid and f.parent_uid == uid)

    def make_folder(self, env, path):
        """Create the folder and each missing parent, the environment folder first. Returns the paths created."""
        made, parent, here = [], self.project, None
        for name in [env, *segments(path)]:
            here = "/" if here is None else here.rstrip("/") + "/" + name
            uid = self._child(parent, name, f"{env}:{here}")
            if uid is None:
                with sdk_call("create folder"):
                    uid = self.sm.create_folder(
                        self.sdk.CreateOptions(self.project, None if parent == self.project else parent), name)
                self._all_folders().append(SimpleNamespace(folder_uid=uid, parent_uid=parent, name=name))
                made.append(here)
            parent = uid
        return made

    # Records

    def _login_records(self):
        if self._records is None:
            with sdk_call("list records"):
                self._records = [r for r in self.sm.get_secrets()
                                 if r.type == "login" and r.folder_uid == self.project
                                 and isinstance(r.title, str) and KEY.match(r.title)]
        return self._records

    def _keyed(self, uid, label):
        """{key: record} for one folder. Two records with one title stop the command."""
        keyed = {}
        for r in self._login_records():
            if r.inner_folder_uid != uid:
                continue
            if r.title in keyed:
                die(f"{label} holds two Keeper records titled {r.title}", "delete one of them in Keeper")
            keyed[r.title] = r
        return keyed

    def _existing(self, env, path):
        uid = self._resolve(env, path)
        return uid, None if uid is None else self._keyed(uid, f"{env}:{path}")

    def list_folder_if_exists(self, env, path):
        """(own names, no imports), or None when the folder does not exist."""
        uid, keyed = self._existing(env, path)
        return None if uid is None else (sorted(keyed), [])

    def list_folder(self, env, path):
        listed = self.list_folder_if_exists(env, path)
        return listed or die(f"{env}:{path} does not exist in Keeper")

    def all_secret_paths(self, env):
        """(folder path, key) for every key under the environment. A repeated pair is a duplicate record."""
        env_uid = self._child(self.project, env, env)
        if env_uid is None:
            return []
        paths, queue = {env_uid: "/"}, [env_uid]
        while queue:
            parent = queue.pop()
            for f in self._all_folders():
                if f.parent_uid == parent and f.folder_uid not in paths:
                    paths[f.folder_uid] = paths[parent].rstrip("/") + "/" + f.name
                    queue.append(f.folder_uid)
        return [(paths[r.inner_folder_uid], r.title) for r in self._login_records() if r.inner_folder_uid in paths]

    def read_values(self, env, path):
        """{key: password} of one folder, for `run`."""
        uid, keyed = self._existing(env, path)
        if uid is None:
            die(f"{env}:{path} does not exist in Keeper")
        values = {}
        for key, record in keyed.items():
            with sdk_call("read record"):
                value = record.field("password", single=True)
            if not isinstance(value, str) or not value:
                die(f"the Keeper record {key} in {env}:{path} has no password")
            values[key] = value
        return values

    def publish(self, env, path, key, value):
        """Create or update one key. The value goes only to the SDK."""
        uid, keyed = self._existing(env, path)
        if uid is None:
            die(f"{env}:{path} does not exist in Keeper")
        if key in keyed:
            with sdk_call("update record"):
                keyed[key].set_standard_field_value("password", value)
                self.sm.save(keyed[key])
            return "updated"
        record = self.sdk.RecordCreate("login", key)
        record.fields = [self.sdk.RecordField(field_type="password", value=[value])]
        with sdk_call("create record"):
            self.sm.create_secret_with_options(self.sdk.CreateOptions(self.project, uid), record)
        return "created"

    def run(self, env, path, cmd):
        """Replace gondr with `cmd`, which gets the folder's keys over the inherited environment."""
        c = self.cfg.keeper["config"]
        values = self.read_values(env, path)
        # The KSM config is the store's credential, so the command never inherits it.
        child = {k: v for k, v in os.environ.items() if not (c["source"] == "env" and k == c["name"])}
        child.update(values)
        try:
            os.execvpe(cmd[0], cmd, child)
        except (OSError, ValueError) as e:
            die(f"cannot run {cmd[0]}: {type(e).__name__}")
