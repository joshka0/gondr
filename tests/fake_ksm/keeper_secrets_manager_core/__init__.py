"""Fake keeper-secrets-manager-core for the gondr gate.

Only the API surface that docs/spec.md "Keeper store" allows gondr to use exists here.
Misuse (a wrong argument, a missing parent folder) raises TypeError or ValueError, so the
gate sees a product failure and never a silent pass.
"""
import uuid

from . import _fake
from ._fake import KsmCanaryError  # noqa: F401  (the gate raises it from inside SDK calls)

_fake.log(call="import")
_fake.emit_ksm_log()


class Record:
    def __init__(self, row):
        self.uid = row["uid"]
        self.title = row["title"]
        self.type = row["type"]
        self.folder_uid = row["folder_uid"]
        self.inner_folder_uid = row["inner_folder_uid"]
        self._fields = {k: v for k, v in row["fields"].items()}

    def field(self, name, single=False):
        value = self._fields.get(name)
        if single:
            return value
        return [] if value is None else [value]

    def set_standard_field_value(self, name, value):
        _fake.log(call="set_standard_field_value", uid=self.uid, field=name, value=value)
        self._fields[name] = value


class Folder:
    def __init__(self, row):
        self.folder_uid = row["folder_uid"]
        self.parent_uid = row["parent_uid"]
        self.name = row["name"]


class SecretsManager:
    def __init__(self, config=None):
        _fake.emit_ksm_log()
        from .storage import InMemoryKeyValueStorage
        if not isinstance(config, InMemoryKeyValueStorage):
            raise TypeError("config must be an InMemoryKeyValueStorage")
        _fake.log(call="init", config=config.config)
        self._s = _fake.load()
        _fake.maybe_raise(self._s, "init")

    def get_folders(self):
        _fake.log(call="get_folders")
        _fake.maybe_raise(self._s, "get_folders")
        return [Folder(r) for r in self._s["folders"]]

    def get_secrets(self, uids=None):
        _fake.log(call="get_secrets", uids=uids)
        _fake.maybe_raise(self._s, "get_secrets")
        return [Record(r) for r in self._s["records"] if uids is None or r["uid"] in uids]

    def _folder(self, uid):
        return next((f for f in self._s["folders"] if f["folder_uid"] == uid), None)

    def create_folder(self, create_options, folder_name):
        from .dto.payload import CreateOptions
        if not isinstance(create_options, CreateOptions) or not isinstance(folder_name, str):
            raise TypeError("create_folder(CreateOptions, name)")
        shared, parent = create_options.folder_uid, create_options.subfolder_uid
        _fake.log(call="create_folder", shared_uid=shared, parent_uid=parent, name=folder_name)
        _fake.maybe_raise(self._s, "create_folder")
        top = self._folder(shared)
        if top is None or top["parent_uid"]:
            raise ValueError("folder_uid %r is not a shared folder" % shared)
        if parent in ("", None):
            parent = shared  # a folder at the shared folder root
        elif parent != shared:
            p = self._folder(parent)
            if p is None or p.get("shared_uid") != shared:
                raise ValueError("parent %r is not a folder inside shared folder %r" % (parent, shared))
        if any(f["parent_uid"] == parent and f["name"] == folder_name for f in self._s["folders"]):
            raise ValueError("folder %r exists in %r" % (folder_name, parent))
        uid = "N-" + uuid.uuid4().hex[:10]
        self._s["folders"].append({"folder_uid": uid, "parent_uid": parent, "name": folder_name,
                                   "shared_uid": shared})
        _fake.save(self._s)
        return uid

    def create_secret_with_options(self, create_options, record):
        from .dto.dtos import RecordCreate
        from .dto.payload import CreateOptions
        if not isinstance(create_options, CreateOptions) or not isinstance(record, RecordCreate):
            raise TypeError("create_secret_with_options(CreateOptions, RecordCreate)")
        fields = [{"type": f.field_type, "value": f.value} for f in (record.fields or [])]
        _fake.log(call="create_secret_with_options", shared_uid=create_options.folder_uid,
                  subfolder_uid=create_options.subfolder_uid, record_type=record.record_type,
                  title=record.title, fields=fields)
        _fake.maybe_raise(self._s, "create_secret_with_options")
        shared, inner = create_options.folder_uid, create_options.subfolder_uid
        if shared not in self._s["shared"]:
            raise ValueError("folder_uid %r is not a shared folder" % shared)
        if inner in ("", shared):
            inner = None
        if inner is not None and (self._folder(inner) or {}).get("shared_uid") != shared:
            raise ValueError("subfolder %r is not inside shared folder %r" % (inner, shared))
        flat = {}
        for f in fields:
            if not isinstance(f["value"], list):
                raise TypeError("RecordField.value must be a list")
            flat[f["type"]] = f["value"][0] if f["value"] else None
        uid = "R-" + uuid.uuid4().hex[:10]
        self._s["records"].append({"uid": uid, "title": record.title, "type": record.record_type,
                                   "folder_uid": shared, "inner_folder_uid": inner, "fields": flat})
        _fake.save(self._s)
        return uid

    def save(self, record):
        _fake.log(call="save", uid=record.uid, fields=sorted(record._fields))
        _fake.maybe_raise(self._s, "save")
        for r in self._s["records"]:
            if r["uid"] == record.uid:
                r["fields"] = dict(record._fields)
                _fake.save(self._s)
                return
        raise ValueError("unknown record %r" % record.uid)
