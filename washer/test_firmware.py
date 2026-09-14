"""Host-side regression/fault-injection tests. Does not contact any appliance.
Run with desktop Python 3: python test_firmware.py -v
Hardware, CYW43 driver, RF conditions, and flash power-loss behavior are not emulated.
"""
import ast
import gc
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import select
import socket
import struct
import sys
import tempfile
import time
import types
import unittest

ROOT = Path(__file__).resolve().parent


class Reset(BaseException):
    pass


class Clock:
    PERIOD = 1 << 30

    def __init__(self):
        self.now = 0

    def ticks_ms(self):
        return self.now % self.PERIOD

    def ticks_diff(self, a, b):
        return (a - b + self.PERIOD // 2) % self.PERIOD - self.PERIOD // 2

    def ticks_add(self, a, b):
        return (a + b) % self.PERIOD

    def sleep_ms(self, ms):
        self.now += ms

    def gmtime(self, value=None):
        return time.gmtime(1789344000 if value is None else value)

    def time(self):
        return 1789344000 + self.now // 1000


class FakeSocket:
    def __init__(self, incoming=b"", send_limit=999999, error=None):
        self.incoming = incoming
        self.output = b""
        self.closed = False
        self.send_limit = send_limit
        self.error = error
        self.timeout = None
        self.eof = False

    def settimeout(self, value):
        self.timeout = value

    def recv(self, count):
        if self.error:
            raise self.error
        if not self.incoming:
            if self.eof:
                return b""
            raise OSError(11)
        chunk, self.incoming = self.incoming[:count], self.incoming[count:]
        return chunk

    def send(self, data):
        if self.error:
            raise self.error
        count = min(len(data), self.send_limit)
        self.output += data[:count]
        return count

    def close(self):
        self.closed = True

    def shutdown(self, mode):
        pass

    def connect(self, address):
        self.address = address

    def setsockopt(self, *args):
        pass

    def bind(self, address):
        self.bound = address

    def listen(self, backlog):
        self.backlog = backlog

    def accept(self):
        raise self.error or OSError(11)


class FakeWlan:
    PM_NONE = 0

    def __init__(self):
        self.connected = False
        self.calls = []

    def active(self, value):
        self.calls.append(("active", value))

    def config(self, **values):
        pass

    def isconnected(self):
        return self.connected

    def ifconfig(self):
        return ("192.0.2.20", "255.255.255.0", "192.0.2.1", "192.0.2.1")

    def connect(self, *args):
        self.calls.append(("connect",))

    def disconnect(self):
        self.calls.append(("disconnect",))

    def status(self, *args):
        return -55 if args else 1


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


class FirmwareTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="washer-test-")
        self.previous = os.getcwd()
        os.chdir(self.temp.name)
        self.clock = Clock()
        self.wlan = FakeWlan()
        self.feeds = []
        watchdog = types.SimpleNamespace(feed=lambda: self.feeds.append(self.clock.now))
        self.machine = types.SimpleNamespace(
            Pin=lambda *a, **k: None, I2C=lambda *a, **k: None,
            WDT=lambda **k: watchdog, reset=self.reset, reset_cause=lambda: 1,
            RTC=lambda: types.SimpleNamespace(datetime=lambda value: setattr(self, "rtc", value)))
        sys.modules["machine"] = self.machine
        constructor = lambda *args: self.wlan
        constructor.PM_NONE = 0
        sys.modules["network"] = types.SimpleNamespace(STA_IF=0, WLAN=constructor)
        time.ticks_ms = self.clock.ticks_ms
        self.boot = load_module("main", ROOT / "main.py")
        self.boot.time = self.clock
        self.boot.os = types.SimpleNamespace(rename=os.replace, sync=lambda: None)
        sys.print_exception = lambda exc: None
        self.app = load_module("washer_test_app", ROOT / "washer_a.py")
        a = self.app
        a.time = self.clock
        a.safe_debug = lambda message: None
        a.os = types.SimpleNamespace(rename=os.replace, sync=lambda: None, remove=os.remove, urandom=os.urandom,
                                    uname=lambda: types.SimpleNamespace(release="fake", machine="fake Pico"))
        a.gc = types.SimpleNamespace(mem_free=lambda: 100000, collect=gc.collect)
        a.select = types.SimpleNamespace(POLLIN=1, POLLOUT=4)
        a.ready = lambda sock, mask: mask if mask == 4 or sock.incoming or sock.error or sock.eof else 0
        a.config = {"WIFI_SSID": "test-network", "WIFI_PASSWORD": "test-password",
                    "UPDATE_TOKEN": "a" * 64, "DEVICE_TYPE": "washer", "DEVICE_ID": "washer-test-unit"}
        a.ctx = types.SimpleNamespace(slot="a", trial=False, sha256="old", confirmed=True,
                                     age_ms=lambda: 70000, stage=lambda slot: setattr(self, "staged", slot),
                                     confirm=lambda: True, cancel_stage=lambda: setattr(self, "cancelled", True))
        a.wifi = types.SimpleNamespace(ip="192.0.2.20", wlan=self.wlan, power_save_disabled=True)
        a.http_server = types.SimpleNamespace(sock=object(), step=lambda: None, close=lambda: None)
        a.socket = types.SimpleNamespace(socket=lambda: FakeSocket(), SOL_SOCKET=1, SO_REUSEADDR=2)
        a.ntp = types.SimpleNamespace(last_sync_ms=None)

    def tearDown(self):
        os.chdir(self.previous)
        self.temp.cleanup()

    @staticmethod
    def reset():
        raise Reset()

    def drain(self, client, count=100):
        for _ in range(count):
            if client.sock is None:
                return
            client.step()
            self.clock.now += 5

    def test_full_headers_and_partial_sends(self):
        sock = FakeSocket(b"GET /status HTTP/1.1\r\nHost: pico\r\n", send_limit=37)
        client = self.app.HttpClient(sock)
        client.step()
        self.assertEqual(sock.output, b"")
        sock.incoming += b"X-Test: " + b"x" * 2500 + b"\r\n\r\n"
        self.drain(client, 250)
        self.assertTrue(sock.closed)
        self.assertEqual(sock.incoming, b"")
        head, body = sock.output.split(b"\r\n\r\n", 1)
        self.assertIn(b"200 OK", head)
        self.assertEqual(json.loads(body)["version"], "6.0.0")
        length = int(head.split(b"Content-Length: ")[1].split(b"\r\n")[0])
        self.assertEqual(length, len(body))

    def test_slow_client_deadline(self):
        sock = FakeSocket()
        client = self.app.HttpClient(sock)
        self.clock.now = 8001
        client.step()
        self.assertTrue(sock.closed)

    def test_fatal_receive_is_not_silenced(self):
        sock = FakeSocket(error=OSError(104))
        self.app.HttpClient(sock).step()
        self.assertTrue(sock.closed)
        self.assertEqual(self.app.diag["http_errors"], 1)

    def test_oversized_headers_rejected(self):
        sock = FakeSocket(b"GET /status HTTP/1.1\r\nX: " + b"x" * 5000)
        self.drain(self.app.HttpClient(sock))
        self.assertIn(b"400 Bad Request", sock.output)

    def test_listener_restarts_after_fatal_accept(self):
        a = self.app
        listener = a.Listener(80)
        sock = FakeSocket(error=OSError(9))
        listener.sock = sock
        listener.step()
        self.assertTrue(sock.closed)
        self.assertIsNone(listener.sock)
        self.clock.now += 1001
        new = FakeSocket()
        a.socket = types.SimpleNamespace(socket=lambda: new, SOL_SOCKET=1, SO_REUSEADDR=2)
        listener.step()
        self.assertIs(listener.sock, new)
        self.assertEqual(new.timeout, 0)

    def test_missing_listener_retries_bind_failure(self):
        a = self.app
        listener = a.Listener(80)
        bad = FakeSocket()
        bad.bind = lambda addr: (_ for _ in ()).throw(OSError(98))
        a.socket = types.SimpleNamespace(socket=lambda: bad, SOL_SOCKET=1, SO_REUSEADDR=2)
        listener.step()
        self.assertIsNone(listener.sock)
        self.clock.now += 3001
        new = FakeSocket()
        a.socket.socket = lambda: new
        listener.step()
        self.assertIs(listener.sock, new)

    def test_eagain_does_not_destroy_listener(self):
        listener = self.app.Listener(80)
        sock = FakeSocket()
        listener.sock = sock
        listener.step()
        self.assertIs(listener.sock, sock)

    def test_wifi_rebuilds_on_reconnect_and_address_change(self):
        a = self.app
        restarts = []
        a.restart_listeners = lambda: restarts.append(1)
        manager = a.Wifi()
        manager.step()
        self.assertEqual(self.clock.now, 0)
        self.assertTrue(manager.connecting)
        self.wlan.connected = True
        manager.step()
        self.wlan.connected = False
        manager.step()
        self.wlan.connected = True
        manager.step()
        self.assertEqual(len(restarts), 3)

    def test_wifi_timeout_is_polled_not_slept(self):
        manager = self.app.Wifi()
        manager.step()
        self.clock.now = 20001
        manager.step()
        self.assertFalse(manager.connecting)
        self.assertEqual(self.clock.now, 20001)
        self.assertIn(("disconnect",), self.wlan.calls)

    def test_chunked_bulb_response(self):
        packet = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n"
        self.assertEqual(self.app.parse_response(packet), b"hello")
        self.assertIsNone(self.app.parse_response(packet[:-3]))
        with self.assertRaises(ValueError):
            self.app.parse_response(packet[:-3], eof=True)

    def test_truncated_bulb_content_length_rejected(self):
        with self.assertRaises(ValueError):
            self.app.parse_response(b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\n\r\nshort", eof=True)

    def test_fetch_absolute_deadline_closes_socket(self):
        a = self.app
        sock = FakeSocket()
        a.socket = types.SimpleNamespace(socket=lambda: sock)
        fetch = a.Fetch("192.0.2.30", "GET", "/sensor/Uptime")
        self.clock.now = 3000
        fetch.step()
        self.assertEqual(fetch.result, (None, "HTTP deadline"))
        self.assertTrue(sock.closed)

    def test_hostnames_rejected_to_avoid_blocking_dns(self):
        with self.assertRaises(ValueError):
            self.app.Fetch("bulb.local", "GET", "/")

    def test_update_auth_required(self):
        self.healthy_idle()
        sock = FakeSocket(self.request("PUT", "/update", b"#" * 2000, authorized=False))
        self.drain(self.app.HttpClient(sock))
        self.assertIn(b"401 Unauthorized", sock.output)
        self.assertFalse(list(Path(".").glob("*.upload")))

    def test_bad_checksum_preserves_both_slots(self):
        self.healthy_idle()
        Path("washer_a.py").write_bytes(b"current")
        Path("washer_b.py").write_bytes(b"previous")
        sock = FakeSocket(self.request("PUT", "/update", b"#" * 2000, extra="X-SHA256: " + "0" * 64 + "\r\n"))
        self.drain(self.app.HttpClient(sock))
        self.assertIn(b"SHA-256 mismatch", sock.output)
        self.assertEqual(Path("washer_b.py").read_bytes(), b"previous")
        self.assertFalse(hasattr(self, "staged"))

    def test_interrupted_upload_not_staged(self):
        self.healthy_idle()
        full = self.request("PUT", "/update", b"#" * 2000, extra="X-SHA256: " + "0" * 64 + "\r\n")
        sock = FakeSocket(full[:-1000])
        client = self.app.HttpClient(sock)
        client.step()
        sock.eof = True
        self.drain(client)
        self.assertFalse(hasattr(self, "staged"))
        self.assertIsNone(self.app.upload_owner)

    def test_concurrent_upload_and_trial_upload_rejected(self):
        self.healthy_idle()
        self.app.upload_owner = object()
        self.assertFalse(self.app.update_allowed())
        self.app.upload_owner = None
        self.app.ctx.trial = True
        self.assertFalse(self.app.update_allowed())

    def test_initial_boot_must_be_confirmed_before_staging(self):
        self.healthy_idle()
        self.app.ctx.confirmed = False
        self.assertFalse(self.app.update_allowed())

    def new_context(self, trial=True):
        Path("washer_a.py").write_bytes(b"previous")
        Path("washer_b.py").write_bytes(b"new")
        state = {"active": "a", "previous": "b", "pending": None, "failures": 0}
        return self.boot.BootContext(state, "b" if trial else "a", trial,
                                     types.SimpleNamespace(feed=lambda: None))

    def test_trial_requires_sixty_seconds_before_confirmation(self):
        context = self.new_context()
        self.assertFalse(context.confirm())
        self.clock.now = 60000
        self.assertTrue(context.confirm())
        self.assertFalse(context.trial)
        state = json.loads(Path("boot_state.json").read_text())
        self.assertEqual(state["active"], "b")
        self.assertEqual(state["previous"], "a")

    def test_unconfirmed_trial_resets_after_three_minutes(self):
        context = self.new_context()
        self.clock.now = 180000
        with self.assertRaises(Reset):
            context.feed()

    def test_boot_age_survives_tick_wrap(self):
        self.clock.now = Clock.PERIOD - 100
        context = self.new_context(trial=False)
        self.clock.now += 200
        context.feed()
        self.assertEqual(context.age_ms(), 200)

    def test_boot_consumes_trial_before_import_and_falls_back_on_next_reset(self):
        self.new_context()
        self.boot.write_json("boot_state.json", {"active": "a", "previous": "b", "pending": "b", "failures": 0})
        launched = []

        def run(context):
            launched.append((context.slot, context.trial))
            raise Reset()

        sys.modules["washer_a"] = types.SimpleNamespace(run=run)
        sys.modules["washer_b"] = types.SimpleNamespace(run=run)
        with self.assertRaises(Reset):
            self.boot.launch()
        with self.assertRaises(Reset):
            self.boot.launch()
        self.assertEqual(launched, [("b", True), ("a", False)])

    def test_stable_repeated_early_crashes_try_previous_slot(self):
        self.new_context()
        self.boot.write_json("boot_state.json", {"active": "a", "previous": "b", "pending": None, "failures": 3})
        launched = []
        def run(context):
            launched.append(context.slot)
            raise Reset()
        sys.modules["washer_b"] = types.SimpleNamespace(run=run)
        with self.assertRaises(Reset):
            self.boot.launch()
        self.assertEqual(launched, ["b"])

    def test_usb_maintenance_flag_skips_application_and_watchdog(self):
        Path("maintenance.flag").touch()
        self.machine.WDT = lambda **kw: self.fail("Watchdog must not start in maintenance mode")
        self.boot.launch()
        self.assertFalse(Path("boot_state.json").exists())

    def test_confirm_route_requires_auth_and_healthy_sensors(self):
        sock = FakeSocket(self.request("POST", "/update/confirm", authorized=False))
        self.drain(self.app.HttpClient(sock))
        self.assertIn(b"401 Unauthorized", sock.output)
        sock = FakeSocket(self.request("POST", "/update/confirm"))
        self.drain(self.app.HttpClient(sock))
        self.assertIn(b"409 Conflict", sock.output)

    def test_no_blocking_requests_library_or_ntptime(self):
        source = (ROOT / "washer_a.py").read_text()
        tree = ast.parse(source)
        imports = [alias.name for n in ast.walk(tree) if isinstance(n, ast.Import) for alias in n.names]
        self.assertNotIn("urequests", imports)
        self.assertNotIn("ntptime", imports)
        self.assertNotIn("setdefaulttimeout", source)

    def healthy_idle(self):
        a = self.app
        self.clock.now = 70000
        a.state = "READY"
        a.last_watts = 0.0
        a.last_shelly_ok = True
        a.last_shelly_ok_ms = a.last_shelly_request_ms = self.clock.ticks_ms()
        a.input_gap = False
        a.idle_since_ms = 10000
        a.healthy_since_ms = 0

    def request(self, method="GET", path="/status", body=b"", authorized=True, extra=""):
        token = "Authorization: Bearer " + "a" * 64 + "\r\n" if authorized else ""
        identity = "X-Device-Type: washer\r\nX-Device-ID: washer-test-unit\r\nX-Confirm-SHA256: old\r\n"
        return (method + " " + path + " HTTP/1.1\r\nHost: pico\r\n" + token + identity + extra +
                "Content-Length: " + str(len(body)) + "\r\n\r\n").encode() + body

    def payload(self, device="washer"):
        return ('DEVICE_TYPE = "' + device + '"\nBOOT_API = 1\nVERSION = "6.0.0"\n' +
                "# simulated application\n" * 90 + "def run(context):\n    pass\n").encode()

    def upload(self, body=None):
        self.healthy_idle()
        body = self.payload() if body is None else body
        digest = hashlib.sha256(body).hexdigest()
        sock = FakeSocket(self.request("PUT", "/update", body, extra="X-SHA256: " + digest + "\r\n"))
        client = self.app.HttpClient(sock)
        self.drain(client, 10)
        return client, sock, body

    def power_after_upload(self):
        self.clock.now += 10
        self.app.last_shelly_request_ms = self.clock.ticks_ms()
        self.app.receive_watts(0.0, self.clock.ticks_ms())

    def job(self, body=b"{}", error=None, started=None):
        return types.SimpleNamespace(result=(body, error), step=lambda: None,
                                     started=self.clock.ticks_ms() if started is None else started,
                                     finish=lambda **kwargs: None)

    def active_alert(self):
        a = self.app
        a.state = "COMPLETE_CLOSED"
        a.start_bulb_alert("test")
        a.bulb_previous_uptime = 1000

    def bulb_result(self, kind="uptime", body=b'{"value":1001}', error=None, generation=None):
        a = self.app
        a.bulb_job = self.job(body, error)
        a.bulb_job_kind = kind
        a.bulb_job_generation = a.bulb_generation if generation is None else generation
        a.service_bulb_alert()

    def test_status_schema_and_no_secrets(self):
        self.healthy_idle()
        data = self.app.status_dict()
        for key in ("state", "internal_state", "alert_active", "watts", "shelly_online", "cycle_number"):
            self.assertIn(key, data)
        self.assertEqual(data["device_type"], "washer")
        self.assertEqual(data["device_id"], "washer-test-unit")
        encoded = json.dumps(data, allow_nan=False)
        self.assertNotIn("test-password", encoded)
        self.assertNotIn("a" * 64, encoded)

    def test_update_rejected_while_running_or_ambiguous(self):
        self.healthy_idle()
        for state in ("RUNNING", "FINISH_WATCH", "POSSIBLE_START", "COMPLETE_CLOSED", "ACKNOWLEDGED_WAIT"):
            with self.subTest(state=state):
                self.app.state = state
                self.assertFalse(self.app.update_allowed())
        self.app.state = "RUNNING"
        sock = FakeSocket(self.request("PUT", "/update", self.payload()))
        self.drain(self.app.HttpClient(sock))
        self.assertIn(b"409 Conflict", sock.output)

    def test_good_update_writes_only_inactive_slot_after_fresh_power_check(self):
        Path("washer_a.py").write_bytes(b"current")
        Path("washer_b.py").write_bytes(b"previous")
        client, sock, body = self.upload()
        self.assertEqual(client.phase, "verify")
        self.assertEqual(Path("washer_b.py").read_bytes(), b"previous")
        self.assertFalse(hasattr(self, "staged"))
        self.power_after_upload()
        self.drain(client)
        self.assertIn(b"202 Accepted", sock.output)
        self.assertEqual(Path("washer_a.py").read_bytes(), b"current")
        self.assertEqual(Path("washer_b.py").read_bytes(), body)
        self.assertEqual(self.staged, "b")
        self.assertFalse(Path("washer_b.upload").exists())

    def test_activity_during_upload_cancels(self):
        client, sock, body = self.upload()
        self.app.receive_watts(100, self.clock.ticks_ms())
        self.drain(client)
        self.assertIn(b"update cancelled", sock.output)
        self.assertFalse(hasattr(self, "staged"))
        self.assertFalse(Path("washer_b.upload").exists())

    def test_stale_input_cancels_upload_even_without_next_chunk(self):
        client, sock, body = self.upload()
        self.clock.now += 18000
        self.drain(client)
        self.assertIn(b"update cancelled", sock.output)
        self.assertFalse(hasattr(self, "staged"))
        self.assertFalse(Path("washer_b.upload").exists())

    def test_wrong_application_identity_rejected(self):
        client, sock, body = self.upload(self.payload("dryer"))
        self.drain(client)
        self.assertIn(b"Not a washer application", sock.output)
        self.assertFalse(hasattr(self, "staged"))

    def test_wrong_device_identity_rejected(self):
        self.healthy_idle()
        for wrong in (b"X-Device-Type: dryer", b"X-Device-ID: washer-another-unit"):
            request = self.request("PUT", "/update", self.payload())
            original = b"X-Device-Type: washer" if b"Type" in wrong else b"X-Device-ID: washer-test-unit"
            sock = FakeSocket(request.replace(original, wrong))
            self.drain(self.app.HttpClient(sock))
            self.assertIn(b"Wrong washer device identity", sock.output)
        self.assertFalse(hasattr(self, "staged"))

    def test_wrong_token_rejected(self):
        self.healthy_idle()
        sock = FakeSocket(self.request("PUT", "/update", self.payload()).replace(b"a" * 64, b"b" * 64))
        self.drain(self.app.HttpClient(sock))
        self.assertIn(b"401 Unauthorized", sock.output)

    def test_confirm_hash_must_match_and_health_must_be_sustained(self):
        self.healthy_idle()
        sock = FakeSocket(self.request("POST", "/update/confirm").replace(b"X-Confirm-SHA256: old", b"X-Confirm-SHA256: wrong"))
        self.drain(self.app.HttpClient(sock))
        self.assertIn(b"hash does not match", sock.output)
        self.app.healthy_since_ms = self.clock.ticks_ms()
        sock = FakeSocket(self.request("POST", "/update/confirm"))
        self.drain(self.app.HttpClient(sock))
        self.assertIn(b"409 Conflict", sock.output)
        self.app.healthy_since_ms = 0
        sock = FakeSocket(self.request("POST", "/update/confirm"))
        self.drain(self.app.HttpClient(sock))
        self.assertIn(b'"confirmed": true', sock.output)

    def test_ack_requires_complete_headers_and_body(self):
        self.active_alert()
        sock = FakeSocket(b"POST /ack HTTP/1.1\r\nContent-Length: 2\r\n")
        client = self.app.HttpClient(sock)
        client.step()
        self.assertEqual(self.app.state, "COMPLETE_CLOSED")
        sock.incoming = b"\r\n{"
        client.step()
        self.assertEqual(self.app.state, "COMPLETE_CLOSED")
        sock.incoming = b"}"
        self.drain(client)
        self.assertEqual(self.app.state, "ACKNOWLEDGED_WAIT")
        self.assertEqual(self.app.bulb_reset_stage, "WHITE")
        self.assertIn(b'"accepted": true', sock.output)

    def test_ack_legacy_no_token_and_no_bulb_network_inside_handler(self):
        self.active_alert()
        self.app.Fetch = lambda *args: self.fail("Synchronous bulb operation during acknowledgment")
        sock = FakeSocket(self.request("POST", "/ack", authorized=False))
        self.drain(self.app.HttpClient(sock))
        self.assertIn(b'"accepted": true', sock.output)

    def test_ack_in_ready_is_not_accepted(self):
        sock = FakeSocket(self.request("POST", "/ack", authorized=False))
        self.drain(self.app.HttpClient(sock))
        self.assertIn(b'"accepted": false', sock.output)

    def test_write_none_makes_no_progress_but_recovers(self):
        sock = FakeSocket(self.request())
        client = self.app.HttpClient(sock)
        client.step()
        send = sock.send
        sock.send = lambda data: None
        client.step()
        self.assertFalse(sock.closed)
        self.assertEqual(sock.output, b"")
        sock.send = send
        self.drain(client)
        self.assertIn(b"200 OK", sock.output)

    def test_four_silent_clients_do_not_advance_fake_clock(self):
        listener = self.app.Listener(80)
        listener.sock = FakeSocket()
        listener.clients = [self.app.HttpClient(FakeSocket()) for _ in range(4)]
        listener.step()
        self.assertEqual(self.clock.now, 0)

    def test_slow_trickle_cannot_extend_absolute_deadline(self):
        sock = FakeSocket()
        client = self.app.HttpClient(sock)
        for _ in range(15):
            if client.sock is None:
                break
            sock.incoming += b"G"
            self.clock.now += 700
            client.step()
        self.assertTrue(sock.closed)
        self.assertLess(self.clock.now, 10000)

    def test_duplicate_framing_and_chunked_requests_rejected(self):
        for extra in ("Content-Length: 0\r\n", "Transfer-Encoding: chunked\r\n"):
            sock = FakeSocket(self.request(extra=extra))
            self.drain(self.app.HttpClient(sock))
            self.assertIn(b"400 Bad Request", sock.output)

    def test_client_settimeout_failure_closes_socket(self):
        sock = FakeSocket()
        sock.settimeout = lambda value: (_ for _ in ()).throw(OSError(5))
        with self.assertRaises(OSError):
            self.app.HttpClient(sock)
        self.assertTrue(sock.closed)

    def test_bind_failure_closes_allocated_socket(self):
        sock = FakeSocket()
        sock.bind = lambda address: (_ for _ in ()).throw(OSError(98))
        self.app.socket.socket = lambda: sock
        self.app.Listener(80).step()
        self.assertTrue(sock.closed)

    def test_wifi_driver_errors_are_contained_and_backed_off(self):
        for operation in ("connect", "isconnected", "active", "status", "ifconfig"):
            with self.subTest(operation=operation):
                self.set_driver_failure(operation)

    def set_driver_failure(self, operation):
        self.wlan = FakeWlan()
        constructor = lambda *args: self.wlan
        constructor.PM_NONE = 0
        self.app.network = types.SimpleNamespace(WLAN=constructor, STA_IF=0)
        manager = self.app.Wifi()
        self.app.wifi = manager
        if operation == "ifconfig":
            self.wlan.connected = True
        if operation == "status":
            manager.connecting, manager.started = True, self.clock.ticks_ms()
        setattr(self.wlan, operation, lambda *args: (_ for _ in ()).throw(OSError(5)))
        before = self.app.diag["wifi_errors"]
        manager.step()
        self.assertEqual(self.app.diag["wifi_errors"], before + 1)
        self.assertFalse(manager.connecting)
        self.assertGreater(self.clock.ticks_diff(manager.next_ms, self.clock.ticks_ms()), 0)

    def test_unsupported_wifi_power_save_setting_does_not_block_connect(self):
        self.wlan.config = lambda **kwargs: (_ for _ in ()).throw(ValueError("unsupported"))
        manager = self.app.Wifi()
        manager.step()
        self.assertTrue(manager.connecting)
        self.assertFalse(manager.power_save_disabled)

    def test_wifi_radio_reset_is_split_across_service_passes(self):
        manager = self.app.Wifi()
        manager.attempts = 2
        manager.step()
        self.assertTrue(manager.radio_off)
        self.assertEqual(self.clock.now, 0)
        self.clock.now = 501
        manager.step()
        self.assertTrue(manager.connecting)
        self.assertFalse(manager.radio_off)

    def test_shelly_invalid_values_contained_and_marked_unavailable(self):
        self.healthy_idle()
        for data in ({}, {"apower": "nan"}, {"apower": "inf"}, {"apower": -1},
                     {"apower": True}, {"apower": 0, "id": 7}, []):
            with self.subTest(data=data):
                self.app.shelly_job = self.job(json.dumps(data).encode())
                self.app.service_shelly()
                self.assertFalse(self.app.last_shelly_ok)
                self.assertIsNone(self.app.last_watts)
                self.assertFalse(self.app.update_allowed())

    def test_shelly_failure_and_recovery_with_receipt_timestamp(self):
        self.healthy_idle()
        self.app.shelly_job = self.job(error="timeout")
        self.app.service_shelly()
        self.assertFalse(self.app.last_shelly_ok)
        self.assertGreater(self.app.shelly_next_ms, self.clock.ticks_ms())
        self.clock.now += 3000
        self.app.shelly_job = self.job(b'{"id":0,"apower":0}', started=self.clock.ticks_ms() - 500)
        self.app.service_shelly()
        self.assertTrue(self.app.last_shelly_ok)
        self.assertEqual(self.app.last_shelly_ok_ms, self.clock.ticks_ms())
        self.assertEqual(self.app.shelly_failures, 0)

    def test_stale_status_does_not_report_old_watts_online(self):
        self.healthy_idle()
        self.clock.now += 18000
        data = self.app.status_dict()
        self.assertIsNone(data["watts"])
        self.assertFalse(data["shelly_online"])
        self.assertFalse(data["update_allowed"])

    def test_network_gap_resets_continuity_not_cycle_history(self):
        self.healthy_idle()
        a = self.app
        a.state, a.cycle_start_ms = "FINISH_WATCH", 0
        a.final_spin_seen = a.final_pump_seen = True
        a.spin_start_ms = a.final_low_start_ms = a.fallback_low_start_ms = 1000
        a.start_hits_ms = [1000]
        a.invalidate_input("simulated missing readings")
        self.assertIsNone(a.spin_start_ms)
        self.assertIsNone(a.final_low_start_ms)
        self.assertIsNone(a.fallback_low_start_ms)
        self.assertEqual(a.start_hits_ms, [])
        self.assertTrue(a.final_pump_seen)
        self.clock.now += 500000
        a.receive_watts(1.7, self.clock.ticks_ms())
        self.assertEqual(a.state, "FINISH_WATCH")
        self.assertEqual(a.final_low_start_ms, self.clock.ticks_ms())
        self.assertEqual(a.last_activity_ms, self.clock.ticks_ms())

    def test_no_wifi_still_completes_service_pass_and_preserves_state(self):
        self.healthy_idle()
        a = self.app
        a.state = "COMPLETE_CLOSED"
        a.bulb_alert_active = True
        a.wifi.ip = None
        a.Fetch = lambda *args: self.fail("No requests may start without Wi-Fi")
        a.service_once()
        self.assertEqual(a.state, "COMPLETE_CLOSED")
        self.assertTrue(a.bulb_alert_active)
        self.assertFalse(a.last_shelly_ok)
        self.assertIsNone(a.healthy_since_ms)

    def test_temporary_bulb_failure_retains_alert(self):
        self.active_alert()
        self.bulb_result(error="timeout")
        self.assertTrue(self.app.bulb_alert_active)
        self.assertEqual(self.app.state, "COMPLETE_CLOSED")
        self.assertGreater(self.app.bulb_next_ms, self.clock.ticks_ms())

    def test_bulb_recovery_without_reboot_preserves_alert(self):
        self.active_alert()
        self.app.bulb_was_unreachable = True
        self.bulb_result()
        self.assertTrue(self.app.bulb_alert_active)
        self.assertEqual(self.app.bulb_job_kind, "color")

    def test_confirmed_bulb_uptime_drop_acknowledges_with_off_pending(self):
        self.active_alert()
        self.bulb_result(body=b'{"value":10}')
        self.assertFalse(self.app.bulb_alert_active)
        self.assertEqual(self.app.state, "ACKNOWLEDGED_WAIT")
        self.assertEqual(self.app.bulb_reset_stage, "OFF")

    def test_invalid_uptime_never_acknowledges(self):
        for value in (None, -1, "nan", "inf", True, "invalid"):
            self.active_alert()
            self.bulb_result(body=json.dumps({"value": value}).encode())
            self.assertTrue(self.app.bulb_alert_active)
            self.assertEqual(self.app.state, "COMPLETE_CLOSED")

    def test_stale_bulb_reply_cannot_relight_cleared_alert(self):
        self.active_alert()
        generation = self.app.bulb_generation
        self.app.acknowledge_alert("HA test")
        self.app.Fetch = lambda *args: self.fail("Old reply must not send a color")
        self.bulb_result(generation=generation)
        self.assertFalse(self.app.bulb_alert_active)

    def test_failed_color_preserves_alert(self):
        self.active_alert()
        self.bulb_result(kind="color", error="timeout")
        self.assertTrue(self.app.bulb_alert_active)

    def test_failed_white_retains_off_work(self):
        self.app.reset_bulb_to_white_then_off("test")
        self.bulb_result(kind="white", error="timeout")
        self.assertEqual(self.app.bulb_reset_stage, "OFF")

    def test_failed_off_retains_retry_until_success(self):
        self.app.reset_bulb_to_white_then_off("test")
        self.app.bulb_reset_stage = "OFF"
        self.bulb_result(kind="off", error="timeout")
        self.assertEqual(self.app.bulb_reset_stage, "OFF")
        self.bulb_result(kind="off")
        self.assertIsNone(self.app.bulb_reset_stage)

    def test_new_alert_cancels_obsolete_off_job(self):
        self.app.reset_bulb_to_white_then_off("test")
        generation = self.app.bulb_generation
        self.app.start_bulb_alert("new load")
        self.bulb_result(kind="off", generation=generation)
        self.assertTrue(self.app.bulb_alert_active)
        self.assertIsNone(self.app.bulb_reset_stage)

    def test_white_wait_measured_after_response_and_no_sleep(self):
        self.app.reset_bulb_to_white_then_off("test")
        self.clock.now = 700
        self.bulb_result(kind="white")
        self.assertEqual(self.clock.now, 700)
        self.assertEqual(self.app.bulb_next_ms, 2700)

    def test_delayed_reset_skips_cosmetic_white(self):
        self.app.reset_bulb_to_white_then_off("test")
        self.clock.now = 6000
        self.app.service_bulb_alert()
        self.assertEqual(self.app.bulb_job_kind, "off")

    def test_fetch_none_send_and_receive_do_not_crash(self):
        sock = FakeSocket()
        self.app.socket.socket = lambda: sock
        fetch = self.app.Fetch("192.0.2.1", "GET", "/")
        sock.send = lambda data: None
        fetch.step()
        self.assertIsNone(fetch.result)
        fetch.sent = len(fetch.tx)
        sock.incoming = b"x"
        sock.recv = lambda count: None
        fetch.step()
        self.assertIsNone(fetch.result)

    def test_shelly_chunked_and_malformed_http_framing(self):
        a = self.app
        self.assertEqual(a.parse_response(b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nC\r\n{"apower":0}\r\n0\r\n\r\n'), b'{"apower":0}')
        for frame in (b"Transfer-Encoding: chunked\r\nContent-Length: 0", b"Content-Length: -1",
                      b"Content-Length: 0\r\nContent-Length: 1"):
            with self.assertRaises(ValueError):
                a.parse_response(b"HTTP/1.1 200 OK\r\n" + frame + b"\r\n\r\n", eof=True)

    def test_original_detection_functions_and_constants_preserved(self):
        original = ast.parse((ROOT / "original_logic.py").read_text())
        upgraded = ast.parse((ROOT / "washer_a.py").read_text())
        funcs = lambda tree: {n.name: ast.dump(n, include_attributes=False) for n in tree.body if isinstance(n, ast.FunctionDef)}
        for name in ("begin_cycle", "complete_cycle", "process_watts", "acknowledge_alert", "display_state", "elapsed_seconds"):
            self.assertEqual(funcs(original)[name], funcs(upgraded)[name], name)
        constants = lambda tree: {n.targets[0].id: ast.dump(n.value, include_attributes=False)
            for n in tree.body if isinstance(n, ast.Assign) and isinstance(n.targets[0], ast.Name) and n.targets[0].id.isupper()}
        expected, actual = constants(original), constants(upgraded)
        for key, value in expected.items():
            self.assertEqual(actual[key], value, key)

    def compare_trajectory(self, fallback=False):
        a = self.app
        ref = load_module("washer_reference", ROOT / "original_logic.py")
        ref.time = self.clock
        fields = ("state", "poll_seconds", "cycle_number", "cycle_start_ms", "cycle_end_ms", "start_hits_ms",
                  "last_activity_ms", "spin_start_ms", "final_spin_seen", "final_pump_seen", "final_low_start_ms",
                  "fallback_low_start_ms", "alert_sent")
        def observe(watts, seconds):
            until = self.clock.now + int(seconds * 1000)
            while self.clock.now <= until:
                stamp = self.clock.ticks_ms()
                ref.process_watts(watts, stamp)
                a.receive_watts(watts, stamp)
                for field in fields:
                    self.assertEqual(getattr(a, field), getattr(ref, field), (field, self.clock.now, watts))
                self.clock.now += int(ref.poll_seconds * 1000)
        observe(0, 30)
        observe(2, 30)
        observe(0, 20)
        observe(20, 10)
        observe(100, 2100)
        observe(300, 70)
        if not fallback:
            observe(40, 6)
        observe(1.7, 340 if fallback else 130)
        self.assertEqual(a.state, "COMPLETE_CLOSED")
        observe(0, 20)
        self.assertEqual(a.state, "READY")

    def test_golden_original_primary_cycle_and_lid_ack(self):
        self.compare_trajectory()

    def test_golden_original_fallback_cycle(self):
        self.compare_trajectory(fallback=True)

    def test_acknowledged_wait_does_not_repeat_load(self):
        self.active_alert()
        self.app.acknowledge_alert("HA")
        for i in range(5):
            self.app.receive_watts(1.7, i * 1000)
            self.assertEqual(self.app.state, "ACKNOWLEDGED_WAIT")
        self.app.receive_watts(0, 6000)
        self.assertEqual(self.app.state, "READY")

    def test_runtime_completed_alert_survives_restart(self):
        a = self.app
        self.active_alert()
        a.cycle_number, a.bulb_previous_uptime = 7, 1000
        a.persist_runtime()
        a.state, a.bulb_alert_active = "READY", False
        a.load_runtime()
        self.assertEqual(a.state, "COMPLETE_CLOSED")
        self.assertTrue(a.bulb_alert_active)
        self.assertEqual(a.cycle_number, 7)
        self.assertEqual(a.bulb_previous_uptime, 1000)

    def test_runtime_running_restores_evidence_not_continuity_timers(self):
        self.healthy_idle()
        a = self.app
        a.state, a.cycle_start_ms = "FINISH_WATCH", 0
        a.final_spin_seen = a.final_pump_seen = True
        a.persist_runtime()
        self.clock.now += 100000
        a.load_runtime()
        self.assertEqual(a.state, "FINISH_WATCH")
        self.assertTrue(a.final_pump_seen)
        self.assertAlmostEqual(a.elapsed_seconds(a.cycle_start_ms), 70)
        self.assertIsNone(a.final_low_start_ms)
        self.assertTrue(a.recovery_uncertain)

    def test_pending_off_survives_restart_without_late_white(self):
        a = self.app
        a.reset_bulb_to_white_then_off("test")
        a.persist_runtime()
        a.bulb_reset_stage = None
        a.load_runtime()
        self.assertEqual(a.bulb_reset_stage, "OFF")

    def test_corrupt_runtime_is_conservative_until_zero(self):
        for text in ("broken", "[]", '{"format":1,"device_type":"washer","state":"evil"}'):
            Path("washer_state.json").write_text(text)
            self.app.load_runtime()
            self.assertEqual(self.app.state, "ACKNOWLEDGED_WAIT")
            self.assertTrue(self.app.recovery_uncertain)
            self.app.receive_watts(0, self.clock.ticks_ms())
            self.assertEqual(self.app.state, "READY")
            self.assertFalse(self.app.recovery_uncertain)

    def test_persistence_is_rate_limited_and_checkpoints_running_age(self):
        a = self.app
        writes = []
        a.write_json = lambda *args: writes.append(args)
        a.persist_runtime()
        a.state, a.cycle_start_ms = "RUNNING", 0
        a.persist_runtime()
        self.assertEqual(len(writes), 1)
        self.clock.now = 5001
        a.persist_runtime()
        self.assertEqual(len(writes), 2)
        self.clock.now += 60001
        a.persist_runtime()
        self.assertEqual(len(writes), 3)

    def test_reboot_after_staging_cancelled_if_activity_appears(self):
        self.healthy_idle()
        a = self.app
        a.reset_at_ms = self.clock.ticks_ms()
        a.receive_watts(100, self.clock.ticks_ms())
        a.service_shelly = lambda: None
        a.service_bulb_alert = lambda: None
        a.service_once()
        self.assertTrue(self.cancelled)
        self.assertIsNone(a.reset_at_ms)

    def test_boot_cancel_stage_clears_pending(self):
        context = self.new_context(trial=False)
        context.stage("b")
        context.cancel_stage()
        self.assertIsNone(json.loads(Path("boot_state.json").read_text())["pending"])

    def test_corrupt_boot_failure_count_is_sanitized(self):
        self.boot.write_json("boot_state.json", {"active": "a", "failures": "bad", "pending": "bad", "previous": "bad"})
        state = self.boot.load_state()
        self.assertEqual(state["failures"], 0)
        self.assertIsNone(state["pending"])
        self.assertIsNone(state["previous"])

    def test_scheduling_wrap_preserves_freshness_and_deadline(self):
        self.healthy_idle()
        self.clock.now = Clock.PERIOD - 100
        a = self.app
        a.last_shelly_ok_ms = self.clock.ticks_ms()
        deadline = a.later(300)
        self.clock.now += 200
        self.assertTrue(a.sample_fresh())
        self.assertFalse(a.due(deadline))
        self.clock.now += 200
        self.assertTrue(a.due(deadline))

    def test_no_shelly_power_control_routes(self):
        source = (ROOT / "washer_a.py").read_text()
        self.assertNotIn("Switch.Set", source)
        self.assertNotIn("Switch.Toggle", source)
        self.assertIn("/rpc/Switch.GetStatus?id=", source)

    def test_color_job_creation_failure_is_contained(self):
        self.active_alert()
        self.app.Fetch = lambda *args: (_ for _ in ()).throw(OSError(12))
        self.bulb_result()
        self.assertTrue(self.app.bulb_alert_active)
        self.assertGreater(self.app.bulb_next_ms, self.clock.ticks_ms())
        self.assertEqual(self.app.diag["bulb_errors"], 1)

    def test_wifi_already_connected_configures_power_save(self):
        self.wlan.connected = True
        manager = self.app.Wifi()
        manager.step()
        self.assertTrue(manager.power_save_disabled)

    def test_live_address_change_rebuilds_listener_and_invalidates_sample(self):
        self.healthy_idle()
        manager = self.app.Wifi()
        self.wlan.connected = True
        manager.step()
        old = manager.ip
        self.wlan.ifconfig = lambda: ("192.0.2.99", "", "", "")
        self.app.last_shelly_ok = True
        manager.step()
        self.assertNotEqual(manager.ip, old)
        self.assertEqual(manager.ip, "192.0.2.99")
        self.assertFalse(self.app.last_shelly_ok)

    def prepare_run(self, duration):
        a = self.app
        Path("pico_config.json").write_text(json.dumps(a.config))
        class Led:
            OUT = 1
            def __init__(self, *args):
                pass
            def value(self, value):
                pass
        a.Pin = Led
        self.context = self.new_context(trial=False)
        original_feed = self.context.feed
        def feed():
            original_feed()
            if self.clock.now >= duration:
                raise Reset()
        self.context.feed = feed
        return self.context

    def test_full_run_without_wifi_keeps_watchdog_service_alive(self):
        context = self.prepare_run(25000)
        self.app.Fetch = lambda *args: self.fail("Offline run cannot issue HTTP")
        with self.assertRaises(Reset):
            self.app.run(context)
        self.assertGreaterEqual(self.clock.now, 25000)
        self.assertEqual(self.app.state, "READY")
        self.assertFalse(context.confirmed)
        self.assertFalse(self.app.last_shelly_ok)
        self.assertLess(self.app.diag["max_loop_ms"], 10)

    def test_full_run_connected_parses_fresh_shelly_and_confirms_boot(self):
        context = self.prepare_run(65000)
        self.wlan.connected = True
        created = []
        class SocketWithShelly(FakeSocket):
            def connect(self, address):
                super().connect(address)
                self.incoming = b'HTTP/1.1 200 OK\r\nContent-Length: 19\r\n\r\n{"id":0,"apower":0}'
        # Calculate the header rather than rely on the deliberately explicit fixture length.
        def factory():
            sock = SocketWithShelly()
            original_connect = sock.connect
            def connect(address):
                original_connect(address)
                body = b'{"id":0,"apower":0}'
                sock.incoming = b"HTTP/1.1 200 OK\r\nContent-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body
            sock.connect = connect
            created.append(sock)
            return sock
        self.app.socket.socket = factory
        with self.assertRaises(Reset):
            self.app.run(context)
        self.assertTrue(context.confirmed)
        self.assertTrue(self.app.sample_fresh())
        self.assertEqual(self.app.last_watts, 0)
        self.assertEqual(self.app.state, "READY")
        self.assertGreater(sum(b"/rpc/Switch.GetStatus?id=0" in sock.output for sock in created), 3)
        self.assertEqual(self.app.diag["shelly_errors"], 0)


if __name__ == "__main__":
    unittest.main()
