"""
Sweep - persistent preferences.

Small, human-readable JSON in the Sweep state directory. Deliberately tiny:
everything that matters is either a rule selection (which belongs to the user's
own task) or a behavioural preference (which belongs here).
"""

from __future__ import annotations

import json
import os

from . import base

DEFAULTS = {
    # Re-launch through UAC on startup so system-scope features work.
    "auto_elevate": False,
    # Send deletions to the Recycle Bin instead of unlinking.
    "recycle_bin": False,
}


def path() -> str:
    return os.path.join(base.state_dir(), "config.json")


def load(p: str | None = None) -> dict:
    data = dict(DEFAULTS)
    try:
        with open(p or path(), encoding="utf-8") as fh:
            blob = json.load(fh)
        if isinstance(blob, dict):
            for k, v in blob.items():
                if k in DEFAULTS and isinstance(v, type(DEFAULTS[k])):
                    data[k] = v
    except (OSError, ValueError):
        pass
    return data


def save(values: dict, p: str | None = None) -> str:
    """Merge *values* over what is already stored, then write atomically.

    Merging rather than replacing means writing one preference never resets
    another one the caller did not mention.
    """
    target = p or path()
    os.makedirs(os.path.dirname(target) or ".", exist_ok=True)
    data = load(target)
    data.update({k: v for k, v in values.items() if k in DEFAULTS})
    tmp = target + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)
    os.replace(tmp, target)
    return target


def get(key: str, default=None):
    return load().get(key, DEFAULTS.get(key, default))


def set_value(key: str, value) -> str:      # noqa: A001 - mirrors dict.set
    data = load()
    data[key] = value
    return save(data)
