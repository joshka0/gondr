"""State file and call log of the fake Keeper SDK.

The gate points GONDR_FAKE_KSM_STATE (JSON state) and GONDR_FAKE_KSM_LOG (JSON lines) at
files in the sandbox. Each case seeds the state before it runs gondr and reads both afterwards.
Every log write opens, appends and closes, so a call is on disk before gondr execs a child.
"""
import json
import os


class KsmCanaryError(Exception):
    """An SDK failure whose message carries text that gondr must never print."""


def log(**entry):
    path = os.environ.get("GONDR_FAKE_KSM_LOG")
    if path:
        with open(path, "a") as f:
            f.write(json.dumps(entry) + "\n")


def load():
    with open(os.environ["GONDR_FAKE_KSM_STATE"]) as f:
        return json.load(f)


def save(state):
    with open(os.environ["GONDR_FAKE_KSM_STATE"], "w") as f:
        json.dump(state, f)


def maybe_raise(state, where):
    spec = state.get("raise", {}).get(where)
    if spec:
        kind = {"KsmCanaryError": KsmCanaryError, "ValueError": ValueError,
                "RuntimeError": RuntimeError, "KeyError": KeyError}[spec["type"]]
        log(call="raise", where=where, type=spec["type"])
        raise kind(spec["message"])


def emit_ksm_log(state=None):
    """Log the state file's `ksm_log` text through the SDK's own logger, as the real SDK does."""
    import logging
    try:
        text = (state if state is not None else load()).get("ksm_log")
    except (OSError, ValueError, KeyError):
        return
    if text:
        log(call="ksm_log")
        logging.getLogger("ksm").warning(text)
