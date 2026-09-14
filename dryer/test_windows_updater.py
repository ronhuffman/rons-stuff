"""Real Windows PowerShell client -> real loopback TCP -> actual firmware HTTP parser.
Uses fake Pico hardware and accelerated boot timing. Never contacts the real Pico.
"""
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
import hashlib

OUT = Path(__file__).resolve().parent
POWERSHELL = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32/WindowsPowerShell/v1.0/powershell.exe"
spec = importlib.util.spec_from_file_location("firmware_tests", OUT / "test_firmware.py")
tests = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tests)
case = tests.FirmwareTests()
case.setUp()
case.healthy_idle()
app = case.app
app.safe_debug = lambda message: None
listener = socket.socket()
listener.bind(("127.0.0.1", 0))
listener.listen(4)
listener.setblocking(False)
port = listener.getsockname()[1]
laptop_dir = Path("laptop").resolve()
laptop_dir.mkdir()
(laptop_dir / "pico_config.json").write_text(json.dumps(app.config))
(laptop_dir / "Update-Dryer.ps1").write_bytes((OUT / "Update-Dryer.ps1").read_bytes())
(laptop_dir / "dryer_a.py").write_bytes((OUT / "dryer_a.py").read_bytes())
Path("dryer_a.py").write_text("original test slot")
Path("dryer_b.py").write_text("old backup test slot")
started = time.monotonic()
trial_start = None
staged_slot = None
confirmed = False
clients = []
errors = []
stop = threading.Event()


def ready(sock, mask):
    readers, writers, failures = select.select([sock] if mask == 1 else [],
                                               [sock] if mask == 4 else [], [sock], 0)
    return mask if readers or writers or failures else 0


def stage(slot):
    global staged_slot
    staged_slot = slot


def confirm():
    global confirmed
    if app.ctx.age_ms() < 60000:
        return False
    app.ctx.trial = False
    confirmed = True
    return True


app.ready = ready
app.ctx.stage = stage
app.ctx.confirm = confirm
app.ctx.age_ms = lambda: 70000 if trial_start is None else case.clock.now - trial_start


def serve():
    global trial_start
    try:
        while not stop.is_set():
            case.clock.now = 70000 + int((time.monotonic() - started) * 8000)
            app.last_accel_ms = case.clock.now
            app.idle_since_ms = case.clock.now - 40000
            try:
                client, _ = listener.accept()
                clients.append(app.HttpClient(client))
            except BlockingIOError:
                pass
            for client in clients[:]:
                client.step()
                if client.sock is None:
                    clients.remove(client)
            if staged_slot and trial_start is None and app.reset_at_ms is not None and app.due(app.reset_at_ms):
                trial_start = case.clock.now
                app.ctx.slot = staged_slot
                app.ctx.sha256 = hashlib.sha256(Path("dryer_" + staged_slot + ".py").read_bytes()).hexdigest()
                app.ctx.trial = True
            time.sleep(0.003)
    except BaseException as error:
        errors.append(repr(error))


worker = threading.Thread(target=serve, daemon=True)
worker.start()
try:
    command = [str(POWERSHELL),
               "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(laptop_dir / "Update-Dryer.ps1"),
               "-PicoAddress", "127.0.0.1", "-Port", str(port)]
    completed = subprocess.run(command, capture_output=True, text=True, timeout=45)
    print(completed.stdout)
    if completed.returncode:
        print(completed.stderr)
    assert completed.returncode == 0, "Windows updater failed"
    assert not errors, errors
    assert confirmed, "New app was not confirmed"
    assert app.ctx.slot == "b"
    assert Path("dryer_a.py").read_text() == "original test slot", "Active file was overwritten"
    assert Path("dryer_b.py").read_bytes() == (OUT / "dryer_a.py").read_bytes()
    print("PASS: real Windows updater uploaded, SHA-verified and confirmed through the firmware HTTP parser.")
finally:
    stop.set()
    worker.join(timeout=3)
    for client in clients:
        client.close()
    listener.close()
    case.tearDown()
