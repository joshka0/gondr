"""Cases for the Keeper store: selection, config, SDK and read mapping (F45-F48, F52).

Docs/spec.md "Keeper store" is the contract. The fake SDK is described in keeper_support.py.
"""

import json
import re

from gondr_gate.cases_check import check_lines
from gondr_gate.cases_token import launcher
from gondr_gate.keeper_support import (ACME_API, ACME_LIB, APP, APP_KEYS, DECOYS, KSM_CONFIG, KSM_CONFIG_SERVICE,
                                       VENDOR, World, run, seed_standard, setup, untouched_infisical, value)
from gondr_gate.sandbox import case, stops
from gondr_gate.world import hit_lines, seed_personal

HINT = "pip install 'gondr[keeper]'"
READ_CMDS = [["ls"], ["where", "LOCAL_KEY"], ["status"], ["find", "local"], ["check", "LOCAL_KEY"]]


def names_in(line):
    return [n for n in re.split(r"[,\s]+", line.strip()) if n]


def tree_text(c):
    """Every sandbox file the gondr process could have written, except the harness's own."""
    out = {}
    for p in sorted(c.tmp.rglob("*")):
        if p.is_file() and p != c.stub_cfg_path and c.ksm.dir not in p.parents:
            out[str(p)] = p.read_bytes()
    return out


# ---------------------------------------------------------------- F45


@case
def f45_default_store_never_imports_the_keeper_sdk(c):
    seed_personal(c.fake)
    c.ksm = World(c)
    cmds = [["ls"], ["where", "LOCAL_KEY"], ["need", "STRIPE_API_KEY"], ["status"], ["find", "stripe"],
            ["check", "LOCAL_KEY"], ["set", "NEW_KEY"], ["run", "--", "childprobe"]]
    base = c.config.read_text()
    for label, text in (("no [store] table", base),
                        ("kind = infisical", '[store]\nkind = "infisical"\n\n' + base)):
        c.config.write_text(text)
        for args in cmds:
            r = run(c, args, stdin=b"v1" if args[0] == "set" else b"")
            c.check(r.code in (0, 1) and "keeper" not in r.text.lower(), "%s: %s runs as an Infisical command"
                    % (label, args[0]))
        r = run(c, ["ls"])
        c.check(r.code == 0 and c.gets("/api/v4/secrets"), "control: %s serves ls from Infisical" % label)
        c.check(c.ksm.calls() == [], "F45 %s: no command imports the Keeper SDK (calls %s)"
                % (label, [e["call"] for e in c.ksm.calls()][:3]))
    c.finish()


@case
def f45_keeper_store_needs_no_infisical_table_and_never_contacts_infisical(c):
    for label, infisical in (("no [infisical] table", False), ("[infisical] table present", True)):
        setup(c, infisical=infisical)
        seed_standard(c)
        (c.app / ".infisical.json").write_text("{not json")
        for args in READ_CMDS + [["set", "FRESH_KEY"], ["run", "--", "childprobe"]]:
            r = run(c, args, stdin=b"v1" if args[0] == "set" else b"")
            c.check(r.code == 0, "%s: %s succeeds on Keeper (exit %s)" % (label, args[0], r.code))
        c.check(len(c.ksm.calls("get_secrets")) >= 5, "control: %s reads through the SDK" % label)
        untouched_infisical(c, label)
        c.check(c.stubs("infisical") == [], "F45 %s: run starts no infisical child" % label)
        c.clear_stubs()
    c.finish()


# ---------------------------------------------------------------- F46


@case
def f46_keeper_config_from_keychain_reaches_the_sdk_but_no_file_argv_env_or_output(c):
    setup(c)
    seed_standard(c)
    dump = c.tmp / "child-env.txt"
    runs = [(["ls"], b""), (["where", "LOCAL_KEY"], b""), (["set", "FRESH_KEY"], b"v1"),
            (["run", "--", "/bin/sh", "-c", '/usr/bin/env > "$0"', str(dump)], b"")]
    for args, stdin in runs:
        r = run(c, args, stdin=stdin)
        c.check(r.code == 0, "control: %s succeeds" % args[0])
    sec = c.stubs("security")
    want = ["find-generic-password", "-a", "gondr", "-s", KSM_CONFIG_SERVICE, "-w"]
    c.check(bool(sec) and all(e["argv"][:1] == want[:1] and sorted(e["argv"][1:]) == sorted(want[1:]) and
                              e["argv"][e["argv"].index("-a") + 1] == "gondr" and
                              e["argv"][e["argv"].index("-s") + 1] == KSM_CONFIG_SERVICE for e in sec
                              if "-a" in e["argv"] and "-s" in e["argv"]) and
            all("-a" in e["argv"] and "-s" in e["argv"] for e in sec),
            "F46 the config is read with security find-generic-password -a gondr -s %s -w and nothing else is read"
            % KSM_CONFIG_SERVICE)
    inits = c.ksm.calls("init")
    c.check(len(inits) >= len(runs) and all(e["config"] == KSM_CONFIG for e in inits),
            "the SDK receives the config string exactly (got %s)" % [e.get("config") for e in inits])
    files = {p: b for p, b in tree_text(c).items() if KSM_CONFIG.encode() in b}
    c.check(not files, "F46 the config is written to no file: %s" % sorted(files))
    c.check(KSM_CONFIG not in json.dumps([(e["argv"], e["env"], e["stdin"]) for e in c.stubs()]),
            "F46 the config is in no argv or env of any child process")
    child_env = dump.read_text() if dump.exists() else ""
    c.check(bool(child_env) and KSM_CONFIG not in child_env, "F46 the config is not in the command's environment")
    c.finish()


@case
def f46_keeper_config_from_env_var_does_not_read_keychain_and_is_not_passed_on(c):
    setup(c, config="env")
    seed_standard(c)
    dump = c.tmp / "child-env.txt"
    env = {"KSM_CONFIG": KSM_CONFIG}
    for args in (["ls"], ["run", "--", "/bin/sh", "-c", '/usr/bin/env > "$0"', str(dump)]):
        r = run(c, args, env=env)
        c.check(r.code == 0, "control: %s succeeds with source = env" % args[0])
    c.check(c.stubs("security") == [], "F46 Keychain is not read when source = env")
    inits = c.ksm.calls("init")
    c.check(len(inits) >= 2 and all(e["config"] == KSM_CONFIG for e in inits), "the SDK receives the env var's value exactly")
    child_env = dump.read_text() if dump.exists() else ""
    c.check(bool(child_env) and "KSM_CONFIG" not in child_env and KSM_CONFIG not in child_env,
            "F46/F51 neither the variable nor its value reaches the command")
    c.check(not [p for p, b in tree_text(c).items() if KSM_CONFIG.encode() in b], "F46 the config is written to no file")
    c.clear_stubs()
    c.ksm.clear()
    r = run(c, ["ls"])
    c.check(r.code == 1 and c.ksm.calls("get_secrets") == [] and c.stubs("security") == [],
            "F46 an unset config variable exits 1, with no SDK read and no Keychain fallback")
    c.finish()


@case
def f46_keeper_config_missing_from_keychain_stops_with_exit_1(c):
    setup(c)
    seed_standard(c)
    del c.stub["keychain"][KSM_CONFIG_SERVICE]
    r = run(c, ["ls"])
    c.check(r.code == 1 and "Traceback" not in r.text and c.ksm.calls("get_secrets") == [] and c.fake.reqs == [],
            "F46 a missing Keychain item exits 1 with no traceback and no SDK read")
    c.finish()


# ---------------------------------------------------------------- F47


@case
def f47_missing_keeper_sdk_exits_1_with_the_install_hint_and_help_needs_no_sdk(c):
    setup(c, factory=str(c.bin / "gondr-factory"))
    seed_standard(c)
    for args, stdin in ((["ls"], b""), (["where", "LOCAL_KEY"], b""), (["set", "NEW_KEY"], b"v1"),
                        (["run", "--", "childprobe"], b""), (["status"], b""), (["find", "local"], b""),
                        (["check", "LOCAL_KEY"], b"")):
        r = run(c, args, sdk="absent", stdin=stdin)
        c.check(r.code == 1 and HINT in r.text and "Traceback" not in r.text,
                "F47 %s without the SDK exits 1 with the hint %r" % (args[0], HINT))
    c.check(c.stubs("childprobe") == [] and c.fake.reqs == [], "F47 a stopped command execs and requests nothing")
    for args, cmd in ((["--help"], None), (["token", "list", "cloudflare"], [str(launcher(c))])):
        gone = run(c, args, sdk="absent", cmd=cmd)
        there = run(c, args, sdk="fake", cmd=cmd)
        c.check(gone.code == 0 and gone.out == there.out and gone.err == there.err,
                "F47 `gondr %s` needs no store: same result without the SDK as with it" % " ".join(args))
    c.check(len(c.stubs("gondr-factory")) == 2, "control: token list reached the factory in both runs")
    c.check(c.ksm.calls() == [], "F47 `--help` and `token list` do not import the SDK even when it is present")
    c.finish()


# ---------------------------------------------------------------- F48


@case
def f48_keeper_ls_maps_env_and_path_to_the_folder_chain_under_the_shared_folder(c):
    setup(c)
    seed_standard(c)
    r = run(c, ["ls"])
    lines = [ln.rstrip() for ln in r.out.splitlines()]
    keys = [ln for ln in lines if re.match(r"^\s+keys \(", ln)]
    folders = [ln for ln in lines if re.match(r"^\s+folders:", ln)]
    c.check(r.code == 0 and lines[:1] == ["dev:" + APP], "F48 ls prints dev:<repo folder>")
    c.check(len(keys) == 1 and "(3)" in keys[0] and names_in(keys[0].split(":", 1)[1]) == APP_KEYS,
            "F48 keys are exactly the key-titled records of dev/repos/personal/app (got %s)" % keys)
    c.check(len(folders) == 1 and names_in(folders[0].split(":", 1)[1]) == ["pkg", "zdir"],
            "F48 folders lists the sorted subfolders, empty ones included (got %s)" % folders)
    c.check(not [ln for ln in lines if ln.lstrip().startswith("import")], "F52 ls prints no import line")
    gone = [d for d in DECOYS + ["lowercase", "Mixed_Case", "LEADING"] if d in r.out]
    c.check(not gone, "F48 no decoy (other shared folder, wrong order, env not on top, other level, non-key title) is used: %s" % gone)
    r = run(c, ["ls", "--env", "staging"])
    keys = [ln for ln in r.out.splitlines() if re.match(r"^\s+keys \(", ln)]
    c.check(r.code == 0 and r.out.startswith("staging:" + APP) and keys
            and names_in(keys[0].split(":", 1)[1]) == ["LOCAL_KEY", "STAGING_ONLY_KEY"],
            "F48 --env staging reads staging/repos/personal/app")
    r = run(c, ["ls", VENDOR])
    keys = [ln for ln in r.out.splitlines() if re.match(r"^\s+keys \(", ln)]
    c.check(r.code == 0 and keys and names_in(keys[0].split(":", 1)[1]) == ["LOCAL_KEY", "VENDOR_KEY"],
            "F48 an explicit path maps to the same chain")
    sub = c.app / "pkg" / "deep"
    sub.mkdir(parents=True)
    r = run(c, ["ls"], cwd=sub)
    c.check(r.code == 0 and r.out.startswith("dev:" + APP), "F48 a subdirectory still maps to the repo folder")
    c.check(c.ksm.writes() == [], "ls writes nothing")
    c.finish()


@case
def f48_keeper_only_login_records_are_keys(c):
    setup(c)
    w = c.ksm
    w.add("dev", APP, "REAL_KEY", value("REAL_KEY"))
    w.add("dev", APP, "NOTE_TYPED_KEY", value("NOTE_TYPED_KEY"), rtype="note")
    w.add("dev", APP, "CARD_TYPED_KEY", value("CARD_TYPED_KEY"), rtype="bankCard")
    r = run(c, ["ls"])
    keys = [ln for ln in r.out.splitlines() if re.match(r"^\s+keys \(", ln)]
    c.check(r.code == 0 and keys and "(1)" in keys[0] and names_in(keys[0].split(":", 1)[1]) == ["REAL_KEY"],
            "F48 a record that is not of type login is not a key (got %s)" % keys)
    r = run(c, ["where", "NOTE_TYPED_KEY"])
    c.check(r.code == 1 and "dev:" not in r.out, "F48 where finds no owner for a non-login record")
    dump = c.tmp / "env.txt"
    run(c, ["run", "--", "/bin/sh", "-c", '/usr/bin/env > "$0"', str(dump)])
    text = dump.read_text() if dump.exists() else ""
    c.check("REAL_KEY=" in text and "NOTE_TYPED_KEY" not in text and "CARD_TYPED_KEY" not in text,
            "F48 run exports only login records")
    c.finish()


# ---------------------------------------------------------------- F52


@case
def f52_keeper_read_commands_print_no_value_and_no_import_line(c):
    setup(c)
    seed_standard(c)
    r = run(c, ["status"])
    c.check(r.code == 0 and "LOCAL_KEY" in r.out and "import" not in r.out.lower().replace("important", ""),
            "F52 status lists the keys and no import line")
    r = run(c, ["status", "--json"])
    try:
        doc = json.loads(r.out)
    except ValueError:
        doc = {}
    c.check(doc.get("keys") == APP_KEYS and doc.get("imports", []) == [] and doc.get("folder") == APP,
            "F52 status --json holds the keys, the folder and no imports (got %s)" % {k: doc.get(k) for k in ("keys", "imports", "folder")})
    r = run(c, ["find", "local"])
    hits = hit_lines(r.out)
    c.check(r.code == 0 and ("env", "LOCAL_KEY") == hits[0][:2] if hits else False,
            "F52 find reports the key under `env` (got %s)" % hits)
    c.check(not [h for h in hits if h[0] == "import"], "F52 find reports no import hit")
    r = run(c, ["find", "zzqq-nothing"])
    c.check(r.code == 1 and 'missing: nothing matches "zzqq-nothing"' in r.out, "find with no hit exits 1 with the missing line")
    r = run(c, ["check", "LOCAL_KEY", "NOT_THERE_KEY"])
    got, _ = check_lines(r.out)
    c.check(r.code == 1 and got.get("LOCAL_KEY", ("",))[0] == "ok" and got.get("NOT_THERE_KEY", ("",))[0] == "missing",
            "F52 check reports ok and missing, exit 1 (got %s)" % got)
    r = run(c, ["check", "LOCAL_KEY"])
    c.check(r.code == 0 and check_lines(r.out)[0].get("LOCAL_KEY", ("",))[0] == "ok", "F52 check exits 0 when every name is ok")
    c.check(c.ksm.writes() == [] and c.fake.reqs == [], "F52 read commands write nothing")
    c.finish()


@case
def f52_keeper_where_lists_each_folder_with_the_key_without_imports_or_decoys(c):
    setup(c)
    seed_standard(c)
    r = run(c, ["where", "LOCAL_KEY"])
    lines = sorted(ln for ln in r.out.splitlines() if ln.strip())
    c.check(r.code == 0 and lines == sorted(["dev:%s LOCAL_KEY" % APP, "dev:%s LOCAL_KEY" % VENDOR]),
            "F52 where lists dev:<folder> <KEY> for each folder under dev that holds the key, and no other (got %s)" % lines)
    c.check("imported" not in r.out, "F52 where has no `imported by` part")
    r = run(c, ["where", "LOCAL_KEY", "--env", "staging"])
    c.check(r.code == 0 and r.out.split() == ["staging:" + APP, "LOCAL_KEY"], "where --env staging reads staging only")
    r = run(c, ["where", "NO_SUCH_KEY"])
    c.check(r.code == 1 and "dev:" not in r.out, "A missing key exits 1 and prints no owner line")
    r = run(c, ["where", "FOREIGN_KEY"])
    c.check(r.code == 1, "F48 a key in another shared folder is not an owner")
    c.check(c.ksm.writes() == [], "where writes nothing")
    c.finish()


@case
def f52_keeper_where_and_ls_follow_the_boundary_rules(c):
    setup(c)
    seed_standard(c)
    r = run(c, ["where", "LOCAL_KEY"], cwd=c.acme)
    c.check(r.code == 0 and r.out.split() == ["dev:" + ACME_API, "LOCAL_KEY"],
            "F52 inside Acme, where lists only Acme folders (got %r)" % r.out)
    r = run(c, ["where", "LOCAL_KEY"])
    c.check(r.code == 0 and ACME_API not in r.out and APP in r.out, "F52 outside Acme, where lists no Acme folder (got %r)" % r.out)
    r = run(c, ["ls", ACME_LIB], cwd=c.acme)
    c.check(r.code == 0 and "ACME_SHARED_KEY" in r.out, "control: Acme reads its own shared folder")
    for args, cwd in ((["ls", ACME_API], c.app), (["ls", VENDOR], c.acme), (["ls", APP], c.acme)):
        c.clear_stubs()
        c.ksm.clear()
        r = run(c, args, cwd=cwd)
        stops(c, r)
        c.check(c.sensitive_stubs() == [] and [e for e in c.ksm.calls() if e["call"] != "import"] == [],
                "F06/F52 the boundary stop comes before any Keychain read or SDK call: %s" % " ".join(args))
    c.finish()
