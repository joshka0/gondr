"""Cases for the Keeper store: set, run, duplicates, refused commands and SDK errors (F48-F51, F53, F54)."""

import re

from gondr_gate.cases_keeper import tree_text
from gondr_gate.constants import SET_VALUE, VALUE_CORE
from gondr_gate.keeper_support import (APP, APP_KEYS, KSM_CONFIG, SDK_ERROR_TEXT, SHARED, VENDOR, run,
                                       seed_standard, setup, value)
from gondr_gate.onboard_support import broker_mutations, onboard_setup
from gondr_gate.sandbox import case


def env_dump(path):
    out = {}
    if path.exists():
        for line in path.read_text().splitlines():
            if "=" in line:
                k, v = line.split("=", 1)
                out[k] = v
    return out


def value_nowhere(c, secret=VALUE_CORE):
    """The value is in no argv, env or stdin of a child process, and in no file outside the fake SDK's."""
    seen = " ".join(str((e["argv"], e["env"], e["stdin"])) for e in c.stubs())
    return secret not in seen and not [p for p, b in tree_text(c).items() if secret.encode() in b]


# ---------------------------------------------------------------- F49 set


@case
def f49_f48_keeper_set_updates_only_the_password_of_the_one_record_in_the_folder(c):
    setup(c)
    seed_standard(c)
    before = c.ksm.titles("dev", APP)
    r = run(c, ["set", "LOCAL_KEY"], stdin=SET_VALUE.encode())
    c.check(r.code == 0 and r.out.strip() == "updated LOCAL_KEY in dev:" + APP, "F49 set prints `updated <KEY> in <env>:<path>` only")
    sets = c.ksm.calls("set_standard_field_value")
    c.check(len(sets) == 1 and sets[0]["field"] == "password" and sets[0]["value"] == SET_VALUE,
            "F49 set writes the password field, byte for byte as read (got %s)" % [(e["field"], e["value"]) for e in sets])
    c.check(len(c.ksm.calls("save")) == 1 and c.ksm.calls("create_secret_with_options") == [] and c.ksm.calls("create_folder") == [],
            "F49 set saves the existing record; it creates no record and no folder")
    c.check(c.ksm.password("dev", APP, "LOCAL_KEY") == [SET_VALUE], "F49 exactly one record titled LOCAL_KEY holds the new value")
    c.check(c.ksm.titles("dev", APP) == before, "F49 the folder holds the same titles as before")
    c.check(c.ksm.password("staging", APP, "LOCAL_KEY") == [value("LOCAL_KEY", "staging")]
            and c.ksm.password("dev", VENDOR, "LOCAL_KEY") == [value("LOCAL_KEY", where="vendor")],
            "F48 the same title in another env or folder is not touched")
    c.check(value_nowhere(c), "F49 the value is in no argv, env or file")
    c.finish()


@case
def f49_f48_keeper_set_creates_a_login_record_with_a_password_field_in_the_folder(c):
    setup(c)
    seed_standard(c)
    r = run(c, ["set", "FRESH_KEY"], stdin=SET_VALUE.encode())
    c.check(r.code == 0 and r.out.strip() == "created FRESH_KEY in dev:" + APP, "F49 set prints `created <KEY> in <env>:<path>` only")
    made = c.ksm.calls("create_secret_with_options")
    app_uid = c.ksm.uid(SHARED, ["dev"] + APP.split("/")[1:])
    c.check(len(made) == 1 and made[0]["record_type"] == "login" and made[0]["title"] == "FRESH_KEY"
            and made[0]["shared_uid"] == SHARED and made[0]["subfolder_uid"] == app_uid,
            "F48/F49 the record is login-typed, titled FRESH_KEY, in the shared folder and the dev/repos/personal/app subfolder (got %s)"
            % [{k: e[k] for k in ("record_type", "title", "shared_uid", "subfolder_uid")} for e in made])
    filled = [f for e in made for f in e["fields"] if f["value"]]
    c.check(filled == [{"type": "password", "value": [SET_VALUE]}], "F49 the only field with a value is password, byte for byte (got %s)" % filled)
    c.check(c.ksm.calls("create_folder") == [], "F49 no folder is created when the folder exists")
    c.check(c.ksm.password("dev", APP, "FRESH_KEY") == [SET_VALUE], "F49 one FRESH_KEY record exists")
    r = run(c, ["set", "FOREIGN_KEY"], stdin=b"v1")
    c.check(r.code == 0 and r.out.strip() == "created FOREIGN_KEY in dev:" + APP and c.ksm.password("dev", APP, "FOREIGN_KEY") == ["v1"],
            "F48 a record of that title in another shared folder is not the key (it creates, not updates)")
    c.check(value_nowhere(c), "F49 the value is in no argv, env or file")
    c.finish()


@case
def f49_keeper_set_creates_missing_folders_parents_first_and_only_on_the_target_path(c):
    setup(c)
    seed_standard(c)
    before = c.ksm.state()["folders"]
    path = "/shared/new/deeper/leaf"
    r = run(c, ["set", "NEW_KEY", "--path", path], stdin=b"v1")
    created = [(e["shared_uid"], e["parent_uid"], e["name"]) for e in c.ksm.calls("create_folder")]
    folders = c.ksm.state()["folders"]
    uid = {f["name"]: f["folder_uid"] for f in folders if f not in before}
    dev_shared = c.ksm.uid(SHARED, ["dev", "shared"])
    c.check(created == [(SHARED, dev_shared, "new"), (SHARED, uid.get("new"), "deeper"), (SHARED, uid.get("deeper"), "leaf")],
            "F49 three folders are created, parents first, each under its parent in the shared folder (got %s)" % created)
    c.check(len(folders) == len(before) + 3, "F49 no folder outside the target path is created")
    c.check([ln.strip() for ln in r.out.splitlines()] == [
        "created folder dev:/shared/new", "created folder dev:/shared/new/deeper",
        "created folder dev:" + path, "created NEW_KEY in dev:" + path], "F49 output is the folder lines, then the key line (got %r)" % r.out)
    made = c.ksm.calls("create_secret_with_options")
    c.check(r.code == 0 and len(made) == 1 and made[0]["subfolder_uid"] == uid.get("leaf"), "F49 the record lands in the new leaf folder")
    c.ksm.clear()
    r = run(c, ["set", "NEW_KEY", "--path", path], stdin=b"v2")
    c.check(r.code == 0 and r.out.strip() == "updated NEW_KEY in dev:" + path and c.ksm.calls("create_folder") == []
            and c.ksm.calls("create_secret_with_options") == [], "F49 a second set updates; it creates no folder and no second record")
    c.check(c.ksm.password("dev", path, "NEW_KEY") == ["v2"], "F49 still one record titled NEW_KEY, with the new value")
    c.finish()


@case
def f49_keeper_set_refuses_a_bad_value_key_or_path_without_a_write(c):
    setup(c)
    seed_standard(c)
    ok = run(c, ["set", "A1_B2", "--path", "/shared/ok"], stdin=b"v1")
    c.check(ok.code == 0 and c.ksm.writes() != [], "control: a valid set writes through the SDK")
    before = c.ksm.snapshot()
    c.ksm.clear()
    for args, stdin in ((["set", "A1_B2", "--path", "/shared/ok"], b""), (["set", "lower", "--path", "/shared/ok"], b"v1"),
                        (["set", "A-B", "--path", "/shared/ok"], b"v1"), (["set", "A1_B2", "--path", "/etc/passwd"], b"v1"),
                        (["set", "A1_B2", "--path", "/shared/../etc"], b"v1"), (["set", "A1_B2", "--path", "repos/personal/app"], b"v1"),
                        (["set", "A1_B2", "--path", "/shared/new folder"], b"v1"), (["set", "A1_B2", "--path", "/repos"], b"v1")):
        r = run(c, args, stdin=stdin)
        c.check(r.code != 0 and c.ksm.writes() == [] and c.ksm.snapshot() == before,
                "F49 refused with no write: %s" % " ".join(args[1:]))
    c.finish()


# ---------------------------------------------------------------- F50 duplicates


@case
def f50_keeper_duplicate_key_titles_stop_every_command_that_reads_the_folder(c):
    setup(c)
    seed_standard(c)
    c.ksm.add("dev", APP, "DUP_KEY", value("DUP_KEY", where="first"))
    c.ksm.add("dev", APP, "DUP_KEY", value("DUP_KEY", where="second"))
    before = c.ksm.snapshot()
    for args, stdin in ((["ls"], b""), (["set", "DUP_KEY"], b"v1"), (["set", "OTHER_KEY"], b"v1"), (["run", "--", "childprobe"], b""),
                        (["status"], b""), (["find", "dup"], b""), (["check", "DUP_KEY"], b"")):
        r = run(c, args, stdin=stdin)
        c.check(r.code == 1 and APP in r.text, "F50 `%s` exits 1 and names the folder %s (exit %s)" % (" ".join(args[:2]), APP, r.code))
        c.check(c.ksm.writes() == [] and c.ksm.snapshot() == before, "F50 `%s` writes nothing" % " ".join(args[:2]))
    c.check(c.stubs("childprobe") == [], "F50 run does not exec the command")
    r = run(c, ["ls", "--env", "staging"])
    c.check(r.code == 0, "control: the same title in one other folder is no duplicate")
    c.finish()


# ---------------------------------------------------------------- F51 run


@case
def f51_keeper_run_adds_one_variable_per_key_and_lets_the_folder_win_and_hides_the_config(c):
    setup(c)
    seed_standard(c)
    special = 'pa ss=wo"rd $HOME `x` \\n ' + value("SPECIAL_KEY")
    c.ksm.add("dev", APP, "SPECIAL_KEY", special)
    dump = c.tmp / "env.txt"
    sh = ["/bin/sh", "-c", '/usr/bin/env > "$0"', str(dump)]
    r = run(c, ["run", "--"] + sh, env={"LOCAL_KEY": "stale-inherited-value", "INHERIT_ME": "kept-1", "INFISICAL_TOKEN": "x"})
    got = env_dump(dump)
    c.check(r.code == 0 and all(got.get(k) == value(k) for k in APP_KEYS if k != "LOCAL_KEY") and got.get("LOCAL_KEY") == value("LOCAL_KEY"),
            "F51 each key of the folder is a variable with its password; the folder value replaces the inherited LOCAL_KEY")
    c.check(got.get("SPECIAL_KEY") == special, "F51 a value with spaces, quotes, $ and backticks arrives intact")
    c.check(got.get("INHERIT_ME") == "kept-1" and got.get("KEEP_ME") == "inherited-marker", "F51 other inherited variables stay")
    c.check(not [k for k in got if k in ("DEEP_KEY", "FOREIGN_KEY", "PROD_ONLY_KEY", "STAGING_ONLY_KEY", "ENV_ROOT_KEY", "VENDOR_KEY")],
            "F48/F51 no key of another folder, env or shared folder is exported")
    c.check(KSM_CONFIG not in "".join(got.values()) and not [k for k in got if "KSM" in k.upper() and k != "GONDR_FAKE_KSM_STATE"
                                                          and k != "GONDR_FAKE_KSM_LOG"], "F51 the KSM config is not in the command's environment")
    c.check(c.stubs("infisical") == [] and c.fake.reqs == [], "F51 no infisical child and no Infisical request")
    c.clear_stubs()
    child = ["childprobe", "argument with spaces", "--env=child", "--", "-x", "$HOME", ""]
    r = run(c, ["run", "--env", "staging", "--"] + child)
    probe = c.stubs("childprobe")
    c.check(r.code == 0 and len(probe) == 1 and probe[0]["argv"] == child[1:], "F51 the command's argv is unchanged, with no value appended")
    c.check(len(probe) == 1 and probe[0]["env"]["KEEP_ME"] == "inherited-marker", "F51 the command keeps the inherited environment")
    run(c, ["run", "--env", "staging", "--"] + sh)
    got = env_dump(dump)
    c.check(got.get("LOCAL_KEY") == value("LOCAL_KEY", "staging") and got.get("STAGING_ONLY_KEY") and "DATABASE_URL" not in got,
            "F51 --env staging exports the staging folder's keys only")
    run(c, ["run", "--path", VENDOR, "--"] + sh)
    got = env_dump(dump)
    c.check(got.get("VENDOR_KEY") == value("VENDOR_KEY") and "DATABASE_URL" not in got, "F51 --path selects the folder")
    r = run(c, ["run", "--", "/bin/sh", "-c", "exit 7"])
    c.check(r.code == 7, "F51 the command's exit status is gondr's (got %s)" % r.code)
    c.check(value_nowhere(c, value("LOCAL_KEY")), "F51 no value in any child's argv or any file")
    c.finish()


# ---------------------------------------------------------------- F53


@case
def f53_keeper_need_agent_and_onboard_exit_1_and_change_nothing(c):
    setup(c)
    seed_standard(c)
    adm = onboard_setup(c, True)
    c.clear_http()
    before = c.ksm.snapshot()
    repo_dir = c.tmp / "repo-dir"
    repo_dir.mkdir()
    cmds = [["need", "VENDOR_KEY"], ["need", "VENDOR_KEY", "--from", VENDOR], ["agent", "claude"],
            ["agent", "--vault", "shared", "claude", "chat"],
            ["onboard", "/repos/personal/shop", "--admin-home", str(adm), "--dry-run"],
            ["onboard", "/repos/personal/shop", "--admin-home", str(adm), "--repo-dir", str(repo_dir)]]
    for args in cmds:
        r = run(c, args)
        c.check(r.code == 1 and r.text.strip() != "", "F53 `%s` exits 1 with a hint (exit %s)" % (" ".join(args[:2]), r.code))
        if args[0] == "agent":
            c.check("keeper" in r.text.lower(), "F53 agent's hint says Agent Vault has no Keeper credential store (got %r)" % r.text.strip())
    c.check(c.ksm.writes() == [] and c.ksm.snapshot() == before, "F53 no folder or record changes")
    c.check(c.fake.reqs == [] and c.stubs("infisical") == [], "F53 no Infisical request")
    c.check(broker_mutations(c) == [] and c.stubs("claude") == [] and list(repo_dir.iterdir()) == [],
            "F53 no broker change, no agent exec, no agent-vault.json written")
    c.finish()


# ---------------------------------------------------------------- F54


@case
def f54_keeper_sdk_errors_print_the_error_type_only_and_exit_1(c):
    message = "%s value=%s config=%s" % (SDK_ERROR_TEXT, value("LOCAL_KEY"), KSM_CONFIG)
    c.canaries.append(SDK_ERROR_TEXT)
    table = [("init", "KsmCanaryError", ["ls"]), ("get_folders", "KsmCanaryError", ["ls"]),
             ("get_secrets", "ValueError", ["ls"]), ("get_secrets", "RuntimeError", ["where", "LOCAL_KEY"]),
             ("get_secrets", "KeyError", ["run", "--", "childprobe"]), ("get_secrets", "KsmCanaryError", ["status"]),
             ("get_secrets", "ValueError", ["find", "local"]), ("get_secrets", "RuntimeError", ["check", "LOCAL_KEY"]),
             ("get_secrets", "KsmCanaryError", ["set", "FRESH_KEY"]),
             ("create_folder", "RuntimeError", ["set", "FRESH_KEY", "--path", "/shared/new/leaf"]),
             ("create_secret_with_options", "ValueError", ["set", "FRESH_KEY"]),
             ("save", "KsmCanaryError", ["set", "LOCAL_KEY"])]
    for where, kind, args in table:
        setup(c)
        seed_standard(c)
        c.ksm.fail(where, kind, message)
        c.clear_stubs()
        before = c.ksm.snapshot()
        r = run(c, args, stdin=b"v1" if args[0] == "set" else b"")
        label = "%s failing in %s (%s)" % (args[0], where, kind)
        c.check(r.code == 1 and re.search(r"gondr: keeper .+ failed: .*%s" % kind, r.text), "F54 %s: exit 1 and `gondr: keeper <operation> failed: %s` (got %r)"
                % (label, kind, r.text.strip()[:160]))
        c.check(SDK_ERROR_TEXT not in r.text and value("LOCAL_KEY") not in r.text and KSM_CONFIG not in r.text,
                "F54 %s: the error text, a value and the config stay out of the output" % label)
        if where == "get_secrets" and args[0] == "run":
            c.check(c.stubs("childprobe") == [], "F54 a failed run does not exec the command")
        if where in ("init", "get_folders", "get_secrets"):
            c.check(c.ksm.snapshot() == before and c.ksm.writes() == [], "F54 %s: nothing is written" % label)
    c.finish()


@case
def f54_keeper_sdk_logger_records_never_reach_the_output(c):
    setup(c)
    seed_standard(c)
    noise = "KSM-LOGGER-CANARY-2b9e value=%s config=%s" % (value("LOCAL_KEY"), KSM_CONFIG)
    cmds = [(["ls"], b""), (["where", "LOCAL_KEY"], b""), (["status"], b""), (["find", "local"], b""),
            (["check", "LOCAL_KEY"], b""), (["set", "LOCAL_KEY"], b"v1"), (["set", "FRESH_KEY"], b"v2"),
            (["run", "--", "/bin/sh", "-c", "exit 3"], b"")]
    quiet = []
    for args, stdin in cmds:
        r = run(c, args, stdin=stdin)
        quiet.append((r.code, r.out))
    c.ksm.ksm_log(noise)
    c.ksm.clear()
    for (args, stdin), (code, out) in zip(cmds, quiet):
        r = run(c, args, stdin=stdin)
        c.check(r.code == code and r.out == out, "F54 `%s` behaves as without logger output (exit %s, same stdout)" % (" ".join(args[:2]), code))
        c.check("KSM-LOGGER-CANARY" not in r.text, "F54 `%s`: no SDK logger record reaches stdout or stderr" % " ".join(args[:2]))
    c.check(len(c.ksm.calls("ksm_log")) >= 2 * len(cmds), "control: the fake SDK logged at import and in SecretsManager() on every run")
    c.ksm.fail("get_secrets", "ValueError", SDK_ERROR_TEXT)
    r = run(c, ["ls"])
    c.check(r.code == 1 and "failed: " in r.text and "KSM-LOGGER-CANARY" not in r.text and SDK_ERROR_TEXT not in r.text,
            "F54 an SDK error with logger output prints only the error line")
    c.finish()
