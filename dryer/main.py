"""Dryer A/B launcher v1. Install once; Wi-Fi updates replace an app slot only."""
import os
import json
import time
import machine
import sys
import hashlib
import binascii

STATE = "boot_state.json"


def read_json(path, default):
    try:
        with open(path) as stream:
            return json.load(stream)
    except (OSError, ValueError):
        return default


def write_json(path, value):
    # Pico's normal LittleFS provides atomic rename. Never delete old first.
    with open(path + ".tmp", "w") as stream:
        json.dump(value, stream)
    if hasattr(os, "sync"):
        os.sync()
    os.rename(path + ".tmp", path)
    if hasattr(os, "sync"):
        os.sync()


def load_state():
    state = read_json(STATE, {})
    if not isinstance(state, dict) or state.get("active") not in ("a", "b"):
        state = {"active": "a", "previous": "b", "pending": None, "failures": 0}
    return state


class BootContext:
    def __init__(self, state, slot, trial, watchdog):
        self.state, self.slot, self.trial = state, slot, trial
        self.watchdog = watchdog
        self.started = time.ticks_ms()
        self.last_tick = self.started
        self.elapsed_ms = 0
        self.confirmed = False
        digest = hashlib.sha256()
        with open("dryer_" + slot + ".py", "rb") as stream:
            while True:
                chunk = stream.read(1024)
                if not chunk:
                    break
                digest.update(chunk)
                watchdog.feed()
        self.sha256 = binascii.hexlify(digest.digest()).decode()

    def age_ms(self):
        return self.elapsed_ms + max(0, time.ticks_diff(time.ticks_ms(), self.last_tick))

    def feed(self):
        now = time.ticks_ms()
        self.elapsed_ms += max(0, time.ticks_diff(now, self.last_tick))
        self.last_tick = now
        self.watchdog.feed()
        # An unconfirmed Wi-Fi update must not strand the device indefinitely.
        if self.trial and self.age_ms() >= 180000:
            machine.reset()

    def confirm(self):
        if self.age_ms() < 60000:
            return False
        if not self.confirmed:
            previous = self.state["active"] if self.trial else self.state.get("previous")
            self.state.update(active=self.slot, previous=previous, pending=None, failures=0)
            write_json(STATE, self.state)
            self.confirmed = True
            self.trial = False
        return True

    def stage(self, slot):
        if self.trial or slot not in ("a", "b") or slot == self.slot:
            raise ValueError("Invalid update target or unconfirmed trial")
        self.state.update(active=self.slot, pending=slot, failures=0)
        write_json(STATE, self.state)


def launch():
    # USB repair escape hatch, checked before enabling the watchdog.
    try:
        with open("maintenance.flag", "r"):
            pass
        print("Dryer maintenance mode: remove maintenance.flag and hardware-reset to run")
        return
    except OSError:
        pass
    state = load_state()
    pending = state.get("pending")
    trial = pending in ("a", "b") and pending != state["active"]
    slot = pending if trial else state["active"]
    if trial:
        # Consume BEFORE importing. Any reset before confirmation goes back.
        state["pending"] = None
    else:
        failures = int(state.get("failures", 0))
        previous = state.get("previous")
        if failures >= 3 and previous in ("a", "b") and previous != slot:
            slot = previous
            state.update(active=slot, previous=None, failures=0)
        state["failures"] = int(state.get("failures", 0)) + 1
    write_json(STATE, state)
    watchdog = machine.WDT(timeout=8000)
    context = BootContext(state, slot, trial, watchdog)
    try:
        application = __import__("dryer_" + slot)
        watchdog.feed()
        application.run(context)
        raise RuntimeError("Dryer application returned unexpectedly")
    except Exception as exc:
        sys.print_exception(exc)
        try:
            write_json("last_crash.json", {"slot": slot, "trial": trial,
                                          "error": str(exc)[:180]})
        except Exception:
            pass
        time.sleep_ms(200)
        machine.reset()


if __name__ == "__main__":
    launch()
