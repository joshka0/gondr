"""Cases for project selection, credentials and config lookup (F12-F14)."""

import json

from gondr_gate.constants import CLIENT_ID, CLIENT_SECRET, PROJECT, SHOP, VENDOR
from gondr_gate.sandbox import case, config_text


@case
def f12_infisical_json_workspace_replaces_config_project(c):
    (c.app / ".infisical.json").write_text(json.dumps(
        {"workspaceId": "proj-file-999", "defaultEnvironment": "", "gitBranchToEnvironmentMapping": None}))
    sub = c.app / "pkg" / "src"
    sub.mkdir(parents=True)
    r = c.run(["ls"], cwd=sub)
    sec = c.gets("/api/v4/secrets")
    c.check(r.code == 0 and sec and sec[0]["query"].get("projectId") == "proj-file-999",
            "F12 ls uses the workspaceId of the repo root .infisical.json")
    c.check(all(q["query"].get("projectId") == "proj-file-999" for q in c.gets("/api/v2/folders")) and c.gets("/api/v2/folders"),
            "F12 folders request uses the same project")
    r = c.run(["run", "--", "childprobe"], cwd=sub)
    inf = c.stubs("infisical")
    c.check(inf and "--projectId=proj-file-999" in inf[-1]["argv"], "F12 run passes the file project to infisical")
    c.clear_http()
    r = c.run(["ls"], cwd=c.shop)
    sec = c.gets("/api/v4/secrets")
    c.check(sec and sec[0]["query"].get("projectId") == PROJECT, "a repo without .infisical.json uses infisical.project")
    # outside Git: the nearest folder with .infisical.json is the repo root
    nogit = c.repo("personal/nogit", git=False)
    (nogit / ".infisical.json").write_text(json.dumps({"workspaceId": "proj-nogit-777"}))
    deep = nogit / "pkg" / "deep"
    deep.mkdir(parents=True)
    c.clear_http()
    r = c.run(["ls"], cwd=deep)
    sec = c.gets("/api/v4/secrets")
    c.check(r.code == 0 and sec and sec[0]["query"].get("secretPath") == "/repos/personal/nogit"
            and sec[0]["query"].get("projectId") == "proj-nogit-777",
            "outside Git the nearest .infisical.json folder maps to the repo folder and project")
    c.finish()


@case
def f13_env_credentials_are_used_and_keychain_is_not_read(c):
    c.configure(creds="env")
    env = {"INFISICAL_UNIVERSAL_AUTH_CLIENT_ID": "env-id-CANARY-5521",
           "INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET": "env-secret-CANARY-8830"}
    c.canaries += list(env.values())
    c.stub["keychain"]["infisical-client-id"] = CLIENT_ID
    r = c.run(["ls", VENDOR], env=env)
    login = c.posts("/api/v1/auth/universal-auth/login")
    c.check(r.code == 0 and len(login) == 1, "ls succeeds with env credentials")
    c.check(login and login[0]["body"] == {"clientId": env["INFISICAL_UNIVERSAL_AUTH_CLIENT_ID"],
                                          "clientSecret": env["INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET"]},
            "F13 login uses the env client id and secret")
    c.check(c.stubs("security") == [], "F13 Keychain is not read when source = env")
    c.finish()


@case
def f13_keychain_credentials_are_used_when_source_is_keychain(c):
    decoys = {"INFISICAL_UNIVERSAL_AUTH_CLIENT_ID": "decoy-id-CANARY-1", "INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET": "decoy-secret-CANARY-2"}
    c.canaries += list(decoys.values())
    r = c.run(["ls", VENDOR], env=decoys)
    login = c.posts("/api/v1/auth/universal-auth/login")
    c.check(r.code == 0 and login and login[0]["body"] == {"clientId": CLIENT_ID, "clientSecret": CLIENT_SECRET},
            "login uses the Keychain identity, not the env decoys")
    argvs = [" ".join(e["argv"]) for e in c.stubs("security")]
    for svc in ("infisical-client-id", "infisical-client-secret"):
        c.check(any(svc in a and "gondr" in a for a in argvs), "Keychain read for service " + svc)
    c.finish()


@case
def f14_missing_config_gives_a_hint_with_the_path_and_no_traceback(c):
    missing = c.tmp / "nowhere" / "config.toml"
    for args, stdin in ((["ls"], b""), (["where", "K"], b""), (["need", "K"], b""), (["set", "K"], b"v"),
                        (["run", "--", "childprobe"], b""), (["agent", "claude"], b""),
                        (["onboard", SHOP, "--admin-home", str(c.tmp / "adm")], b"")):
        r = c.run(args, stdin=stdin, env={"GONDR_CONFIG": str(missing)})
        c.check(r.code == 1 and "Traceback" not in r.text and str(missing) in r.text,
                "F14 %s: exit 1 and a hint that names the config path" % args[0])
    c.check(c.fake.reqs == [] and c.stubs("infisical") == [] and c.stubs("agent-vault") == [],
            "nothing external ran without a config")
    # default location when GONDR_CONFIG and XDG_CONFIG_HOME are unset
    r = c.run(["ls"], unset=("GONDR_CONFIG", "XDG_CONFIG_HOME"))
    c.check(r.code == 1 and str(c.home / ".config" / "gondr" / "config.toml") in r.text and "Traceback" not in r.text,
            "F14 the hint names ~/.config/gondr/config.toml by default")
    c.finish()


@case
def f14_config_search_order_is_gondr_config_then_xdg_then_home(c):
    dead = "http://127.0.0.1:1"
    good = config_text(c.fake.url)
    bad = config_text(dead)
    xdg = c.tmp / "xdg"
    (xdg / "gondr").mkdir(parents=True)
    (c.home / ".config" / "gondr").mkdir(parents=True)
    unset = ("GONDR_CONFIG", "XDG_CONFIG_HOME")
    (c.home / ".config" / "gondr" / "config.toml").write_text(good)
    r = c.run(["ls", VENDOR], unset=unset)
    c.check(r.code == 0 and c.fake.reqs, "~/.config/gondr/config.toml is used by default")
    c.clear_http()
    (c.home / ".config" / "gondr" / "config.toml").write_text(bad)
    (xdg / "gondr" / "config.toml").write_text(good)
    r = c.run(["ls", VENDOR], env={"XDG_CONFIG_HOME": str(xdg)}, unset=("GONDR_CONFIG",))
    c.check(r.code == 0 and c.fake.reqs, "$XDG_CONFIG_HOME/gondr/config.toml beats ~/.config")
    c.clear_http()
    (xdg / "gondr" / "config.toml").write_text(bad)
    c.config.write_text(good)
    r = c.run(["ls", VENDOR], env={"XDG_CONFIG_HOME": str(xdg)})
    c.check(r.code == 0 and c.fake.reqs, "$GONDR_CONFIG beats XDG_CONFIG_HOME")
    c.finish()
