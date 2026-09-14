"""Windows PowerShell -> real loopback TCP -> actual washer HttpClient.

Only local temporary fixtures and 127.0.0.1 are used. Hardware/Shelly are fake;
boot selection is simulated, BootContext is real, and trial time is accelerated.
Never install or run this desktop test on the Pico.
"""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import select
import socket
import subprocess
import threading
import time
import types

ROOT = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("washer_test_support", ROOT / "test_firmware.py")
tests = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tests)
POWERSHELL = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32/WindowsPowerShell/v1.0/powershell.exe"


def run_case(mode):
    case = tests.FirmwareTests()
    case.setUp()
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(4)
    listener.setblocking(False)
    port = listener.getsockname()[1]
    app = case.app
    payload = (ROOT / "washer_a.py").read_bytes()
    expected_digest = hashlib.sha256(payload).hexdigest()
    laptop = Path("laptop package with spaces")
    laptop.mkdir()
    private = dict(app.config)
    if mode == "wrong_config":
        private["DEVICE_ID"] = "washer-different-unit"
    if mode == "wrong_token":
        private["UPDATE_TOKEN"] = "b" * 64
    (laptop / "pico_config.json").write_text(json.dumps(private))
    (laptop / "Update-Washer.ps1").write_bytes((ROOT / "Update-Washer.ps1").read_bytes())
    selected_payload = payload.replace(b'DEVICE_TYPE = "washer"', b'DEVICE_TYPE = "dryer"') if mode == "wrong_firmware" else payload
    (laptop / "washer_a.py").write_bytes(selected_payload)
    Path("washer_a.py").write_bytes(b"previous confirmed application")
    Path("washer_b.py").write_bytes(payload if mode.startswith("confirm") else b"previous backup")
    state = {"active": "a", "previous": "b", "pending": None, "failures": 0}
    case.boot.write_json("boot_state.json", state)
    slot = "b" if mode.startswith("confirm") else "a"
    if mode == "confirm_wrong_hash":
        Path("washer_b.py").write_bytes(payload + b"\n# not the selected file\n")
    app.ctx = case.boot.BootContext(state, slot, mode.startswith("confirm"), types.SimpleNamespace(feed=lambda: None))
    app.ctx.confirmed = not mode.startswith("confirm")
    case.healthy_idle()
    app.http_server = types.SimpleNamespace(sock=listener)
    if mode == "wrong_device":
        app.DEVICE_TYPE = "dryer"
    app.ready = lambda sock, mask: ready(sock, mask)
    clients = []
    stopped = threading.Event()
    errors = []
    observations = {"staged": False, "trial": False, "confirmed": False, "requests": []}
    start = time.monotonic()
    last_sample = start - 1
    original_route = app.HttpClient.route

    def route(client, head, remaining):
        observations["requests"].append(head.split(b"\r\n", 1)[0].decode())
        return original_route(client, head, remaining)
    app.HttpClient.route = route

    def serve():
        nonlocal last_sample
        try:
            while not stopped.is_set():
                wall_now = time.monotonic()
                case.clock.now = 70000 + int((wall_now - start) * 30000)
                if wall_now - last_sample > 0.02:
                    # Fake a fresh read initiated now, not an old cached value.
                    app.last_shelly_request_ms = case.clock.ticks_ms()
                    app.receive_watts(0.0, case.clock.ticks_ms())
                    last_sample = wall_now
                try:
                    client, address = listener.accept()
                    clients.append(app.HttpClient(client))
                except BlockingIOError:
                    pass
                for client in clients[:]:
                    client.step()
                    if client.sock is None:
                        clients.remove(client)
                if app.reset_at_ms is not None and app.due(app.reset_at_ms):
                    observations["staged"] = True
                    app.reset_at_ms = None
                    staged = case.boot.load_state()
                    target = staged["pending"]
                    if target not in ("a", "b"):
                        raise AssertionError("No pending trial at simulated reboot")
                    assert Path("washer_" + target + ".py").read_bytes() == payload
                    staged["pending"] = None
                    case.boot.write_json("boot_state.json", staged)
                    app.ctx = case.boot.BootContext(staged, target, True, types.SimpleNamespace(feed=lambda: None))
                    app.healthy_since_ms = case.clock.ticks_ms()
                    observations["trial"] = True
                app.ctx.feed()
                if app.ctx.confirmed and app.ctx.slot == "b":
                    observations["confirmed"] = True
                time.sleep(0.002)
        except BaseException as exc:
            errors.append(type(exc).__name__ + ": " + str(exc))
            stopped.set()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    args = [str(POWERSHELL), "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
            "-File", str((laptop / "Update-Washer.ps1").resolve()),
            "-PicoAddress", "127.0.0.1", "-Port", str(port)]
    if mode == "explicit_paths":
        args += ["-Firmware", str((laptop / "washer_a.py").resolve()),
                 "-ConfigFile", str((laptop / "pico_config.json").resolve())]
    if mode.startswith("confirm"):
        args.append("-ConfirmOnly")
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=25)
        success = mode in ("default_paths", "explicit_paths", "confirm_only")
        if success:
            assert result.returncode == 0, result.stderr + result.stdout
            assert "SUCCESS" in result.stdout, result.stdout
            assert app.ctx.slot == "b" and not app.ctx.trial and app.ctx.confirmed
            assert app.ctx.sha256 == expected_digest
            if not mode.startswith("confirm"):
                assert observations["staged"] and observations["trial"]
                assert Path("washer_a.py").read_bytes() == b"previous confirmed application"
        else:
            assert result.returncode != 0, "Unsafe updater unexpectedly succeeded"
            assert not observations["staged"]
            if mode != "wrong_token":
                assert not any(line.startswith("PUT ") for line in observations["requests"])
            assert not any(line.startswith("POST /update/confirm ") for line in observations["requests"])
        assert not errors, errors
        assert "a" * 64 not in result.stdout + result.stderr
        assert "test-password" not in result.stdout + result.stderr
        return {"case": mode, "result": "PASS", "powerShellExit": result.returncode,
                "staged": observations["staged"], "trialObserved": observations["trial"],
                "confirmed": app.ctx.confirmed and app.ctx.slot == "b"}
    finally:
        stopped.set()
        thread.join(timeout=3)
        for client in clients:
            client.close()
        listener.close()
        case.tearDown()


def ready(sock, mask):
    readable, writable, errors = select.select([sock] if mask & 1 else [], [sock] if mask & 4 else [], [sock], 0)
    return mask if readable or writable or errors else 0


if __name__ == "__main__":
    for mode in ("default_paths", "explicit_paths", "wrong_device", "wrong_config", "wrong_token",
                 "wrong_firmware", "confirm_wrong_hash", "confirm_only"):
        print(json.dumps(run_case(mode)), flush=True)
    print("8 real-loopback Windows updater cases passed; hardware and time were simulated.")
