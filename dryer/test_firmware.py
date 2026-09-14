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
        self.temp = tempfile.TemporaryDirectory(prefix="dryer-test-")
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
        self.app = load_module("dryer_test_app", ROOT / "dryer_a.py")
        a = self.app
        a.time = self.clock
        a.safe_debug = lambda message: None
        a.os = types.SimpleNamespace(rename=os.replace, sync=lambda: None, urandom=os.urandom,
                                    uname=lambda: types.SimpleNamespace(release="fake", machine="fake Pico"))
        a.gc = types.SimpleNamespace(mem_free=lambda: 100000, collect=gc.collect)
        a.select = types.SimpleNamespace(POLLIN=1, POLLOUT=4)
        a.ready = lambda sock, mask: mask
        a.config = {"WIFI_SSID": "test-network", "WIFI_PASSWORD": "test-password",
                    "UPDATE_TOKEN": "a" * 64, "NTP_SERVER_IP": "162.159.200.1"}
        a.ctx = types.SimpleNamespace(slot="a", trial=False, sha256="old", confirmed=True,
                                     age_ms=lambda: 70000, stage=lambda slot: setattr(self, "staged", slot),
                                     confirm=lambda: True)
        a.wifi = types.SimpleNamespace(ip="192.0.2.20", wlan=self.wlan, power_save_disabled=True)
        a.http_server = types.SimpleNamespace(sock=object())
        a.ntp = types.SimpleNamespace(last_sync_ms=None)

    def tearDown(self):
        os.chdir(self.previous)
        self.temp.cleanup()

    @staticmethod
    def reset():
        raise Reset()

    def healthy_idle(self):
        a = self.app
        self.clock.now = 70000
        a.accel_ok = a.lux_ok = a.baseline_ready = True
        a.last_accel_ms = self.clock.now
        a.idle_since_ms = 10000

    def request(self, method="GET", path="/status", body=b"", authorized=True, extra=""):
        token = "Authorization: Bearer " + "a" * 64 + "\r\n" if authorized else ""
        return (method + " " + path + " HTTP/1.1\r\nHost: pico\r\n" + token + extra +
                "Content-Length: " + str(len(body)) + "\r\n\r\n").encode() + body

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
        self.assertEqual(json.loads(body)["version"], "5.0.0")
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

    def test_laptop_partial_send_preserves_csv_record(self):
        sock = FakeSocket(send_limit=3)
        client = self.app.MonitorClient(sock)
        expected = "1,2,3,4,5.00,6.00,WAITING,DAY\n"
        for _ in range(30):
            client.step(expected.strip() if not sock.output else "ignored record")
            if sock.output.endswith(b"\n"):
                break
        self.assertEqual(sock.output.decode(), expected)

    def test_bulb_failure_retains_all_alert_reasons(self):
        a = self.app
        a.start_bulb_alert("dryer complete")
        a.start_bulb_alert("utility light left on")
        a.bulb_job = types.SimpleNamespace(step=lambda: None, result=(None, "timeout"))
        a.bulb_job_generation = a.bulb_generation
        a.service_bulb_alert()
        self.assertEqual(len(a.bulb_alert_reasons), 2)
        self.assertTrue(a.bulb_alert_active)

    def test_confirmed_bulb_uptime_drop_acknowledges(self):
        a = self.app
        a.start_bulb_alert("dryer complete")
        a.bulb_previous_uptime = 5000
        a.bulb_job_kind = "uptime"
        a.bulb_job_generation = a.bulb_generation
        a.bulb_job = types.SimpleNamespace(step=lambda: None, result=(b'{"value": 5}', None))
        jobs = []
        a.begin_bulb_job = jobs.append
        a.service_bulb_alert()
        self.assertFalse(a.bulb_alert_active)
        self.assertTrue(a.bulb_off_pending)
        self.assertEqual(jobs, ["off"])

    def test_invalid_bulb_uptime_does_not_acknowledge(self):
        a = self.app
        a.start_bulb_alert("dryer complete")
        a.bulb_job_kind = "uptime"
        a.bulb_job_generation = a.bulb_generation
        a.bulb_job = types.SimpleNamespace(step=lambda: None, result=(b'{"value":"NaN"}', None))
        a.service_bulb_alert()
        self.assertTrue(a.bulb_alert_active)

    def test_stale_bulb_response_cannot_relight_cleared_alert(self):
        a = self.app
        a.start_bulb_alert("dryer complete")
        a.bulb_job_generation = a.bulb_generation
        a.bulb_job = types.SimpleNamespace(step=lambda: None, result=(b'{"value":5}', None))
        a.stop_bulb_alert("dryer complete")
        a.service_bulb_alert()
        self.assertIsNone(a.bulb_job)
        self.assertTrue(a.bulb_off_pending)

    def test_light_off_after_dawn_preserves_dryer_reason(self):
        a = self.app
        a.darkness_monitoring_active = lambda: (False, "DAY")
        a.light_alert_latched = True
        a.start_bulb_alert("dryer complete")
        a.start_bulb_alert("utility light left on")
        a.process_light(0)
        self.assertFalse(a.light_alert_latched)
        self.assertEqual(list(a.bulb_alert_reasons), ["dryer complete"])
        self.assertFalse(a.bulb_off_pending)

    def test_light_ten_minute_hysteresis_unchanged(self):
        a = self.app
        a.darkness_monitoring_active = lambda: (True, "CIVIL_TWILIGHT")
        a.process_light(4)
        self.clock.now = 599999
        a.process_light(2)
        self.assertFalse(a.light_alert_latched)
        self.clock.now = 600000
        a.process_light(2)
        self.assertTrue(a.light_alert_latched)

    def test_dryer_threshold_timing_unchanged(self):
        a = self.app
        a.process_dryer_rms(500)
        self.clock.now = 29999
        a.process_dryer_rms(500)
        self.assertEqual(a.dryer_state, "WAITING")
        self.clock.now = 30000
        a.process_dryer_rms(500)
        self.assertEqual(a.dryer_state, "RUNNING")
        a.process_dryer_rms(250)
        self.clock.now += 89999
        a.process_dryer_rms(250)
        self.assertEqual(a.dryer_state, "RUNNING")
        self.clock.now += 1
        a.process_dryer_rms(250)
        self.assertEqual(a.dryer_state, "COMPLETE")

    def test_sample_gap_cancels_both_continuity_timers(self):
        a = self.app
        a.baseline_ready = True
        a.read_accel = lambda: (0, 0, 0)
        a.start_candidate_ms = a.quiet_start_ms = 0
        a.last_sample_ms = 0
        sensors = a.Sensors()
        sensors.accel_started = True
        self.clock.now = 31000
        sensors.sample()
        self.assertIsNone(a.start_candidate_ms)
        self.assertIsNone(a.quiet_start_ms)
        self.assertEqual(a.diag["sample_gaps"], 1)

    def test_sensor_failure_keeps_process_alive_and_invalidates_values(self):
        a = self.app
        a.baseline_ready = True
        a.read_accel = lambda: (_ for _ in ()).throw(OSError(5))
        sensors = a.Sensors()
        sensors.accel_started = True
        self.assertIsNone(sensors.sample())
        self.assertFalse(a.accel_ok)
        self.assertIsNone(a.last_vibration)
        self.assertEqual(a.diag["sensor_errors"], 1)

    def test_saved_baseline_is_reused(self):
        self.boot.write_json("baseline.json", {"format": 1, "xyz": [10, 20, 8000]})
        self.app.load_runtime()
        self.assertTrue(self.app.baseline_ready)
        self.assertEqual(self.app.base_z, 8000)

    def test_initial_calibration_samples_without_sleeping(self):
        a = self.app
        a.read_accel = lambda: (10, 20, 8000)
        sensors = a.Sensors()
        sensors.accel_started = True
        for _ in range(100):
            sensors.sample()
            self.clock.now += 20
        self.assertTrue(a.baseline_ready)
        self.assertEqual(self.clock.now, 2000)
        self.assertEqual(json.loads(Path("baseline.json").read_text())["xyz"], [10, 20, 8000])

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

    def test_ntp_validates_server_nonce_and_sets_utc(self):
        a = self.app
        client = a.Ntp()
        client.sock = FakeSocket()
        client.sent_ms = 0
        client.nonce = b"12345678"
        packet = bytearray(48)
        packet[0], packet[1] = 0x24, 2
        packet[24:32] = client.nonce
        packet[40:44] = struct.pack("!I", 1789344000 + 2208988800)
        client.sock.recvfrom = lambda count: (packet, (a.config["NTP_SERVER_IP"], 123))
        client.step()
        self.assertEqual(self.rtc[:3], (2026, 9, 14))
        self.assertIsNone(client.sock)

    def test_ntp_rejects_wrong_nonce(self):
        a = self.app
        client = a.Ntp()
        client.sock = FakeSocket()
        client.sent_ms = 0
        client.nonce = b"12345678"
        packet = bytes([0x24, 2]) + bytes(46)
        client.sock.recvfrom = lambda count: (packet, (a.config["NTP_SERVER_IP"], 123))
        client.step()
        self.assertFalse(hasattr(self, "rtc"))

    def test_status_schema_and_no_secrets(self):
        encoded = json.dumps(self.app.status_dict())
        for field in ("dryer_state", "dryer_running", "dryer_complete", "vibration", "rms", "lux",
                      "light_state", "civil_dark", "dark_reason", "clock_valid", "light_timer_active",
                      "light_timer_elapsed", "light_timer_remaining", "light_alert_active", "bulb_alert_active"):
            self.assertIn(field, json.loads(encoded))
        self.assertNotIn("test-password", encoded)
        self.assertNotIn("a" * 64, encoded)

    def test_update_auth_required(self):
        self.healthy_idle()
        sock = FakeSocket(self.request("PUT", "/update", b"#" * 2000, authorized=False))
        self.drain(self.app.HttpClient(sock))
        self.assertIn(b"401 Unauthorized", sock.output)
        self.assertFalse(list(Path(".").glob("*.upload")))

    def test_update_rejected_while_dryer_running(self):
        self.healthy_idle()
        self.app.dryer_state = "RUNNING"
        sock = FakeSocket(self.request("PUT", "/update", b"#" * 2000))
        self.drain(self.app.HttpClient(sock))
        self.assertIn(b"409 Conflict", sock.output)

    def test_good_update_writes_only_inactive_slot(self):
        self.healthy_idle()
        Path("dryer_a.py").write_bytes(b"current")
        Path("dryer_b.py").write_bytes(b"previous")
        body = b"# application\n" * 100
        digest = hashlib.sha256(body).hexdigest()
        sock = FakeSocket(self.request("PUT", "/update", body, extra="X-SHA256: " + digest + "\r\n"))
        self.drain(self.app.HttpClient(sock))
        self.assertIn(b"202 Accepted", sock.output)
        self.assertEqual(Path("dryer_a.py").read_bytes(), b"current")
        self.assertEqual(Path("dryer_b.py").read_bytes(), body)
        self.assertEqual(self.staged, "b")

    def test_bad_checksum_preserves_both_slots(self):
        self.healthy_idle()
        Path("dryer_a.py").write_bytes(b"current")
        Path("dryer_b.py").write_bytes(b"previous")
        sock = FakeSocket(self.request("PUT", "/update", b"#" * 2000, extra="X-SHA256: " + "0" * 64 + "\r\n"))
        self.drain(self.app.HttpClient(sock))
        self.assertIn(b"SHA-256 mismatch", sock.output)
        self.assertEqual(Path("dryer_b.py").read_bytes(), b"previous")
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

    def test_motion_during_upload_cancels(self):
        self.healthy_idle()
        full = self.request("PUT", "/update", b"#" * 2000, extra="X-SHA256: " + "0" * 64 + "\r\n")
        sock = FakeSocket(full)
        client = self.app.HttpClient(sock)
        client.step()
        self.app.idle_since_ms = None
        self.drain(client)
        self.assertIn(b"update cancelled", sock.output)
        self.assertFalse(hasattr(self, "staged"))

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

    def test_local_detection_keeps_running_without_wifi(self):
        a = self.app
        self.boot.write_json("pico_config.json", a.config)
        self.boot.write_json("baseline.json", {"format": 1, "xyz": [0, 0, 8000]})

        class Pin:
            OUT = 1
            def __init__(self, *args):
                pass
            def value(self, value):
                pass

        class I2C:
            def __init__(self, *args, **kwargs):
                pass
            def writeto_mem(self, *args):
                pass
            def writeto(self, *args):
                pass
            def readfrom_mem(self, *args):
                return struct.pack('>hhh', 800, 0, 8000)
            def readfrom(self, *args):
                return b'\x00\x00'

        a.Pin, a.I2C = Pin, I2C
        feeds = []
        def feed():
            feeds.append(self.clock.now)
            if self.clock.now >= 35000:
                raise Reset()
        context = types.SimpleNamespace(slot='a', trial=False, confirmed=False,
                    feed=feed, age_ms=lambda: self.clock.now, confirm=lambda: True)
        with self.assertRaises(Reset):
            a.run(context)
        self.assertEqual(a.dryer_state, 'RUNNING')
        self.assertTrue(a.accel_ok)
        self.assertTrue(a.lux_ok)
        self.assertGreater(len(feeds), 10000)
        self.assertIsNone(a.wifi.ip)

    def test_sensor_recovers_after_backoff(self):
        a = self.app
        sensors = a.Sensors()
        sensors.accel_started = True
        a.baseline_ready = True
        a.i2c = types.SimpleNamespace(writeto_mem=lambda *args: None)
        a.read_accel = lambda: (_ for _ in ()).throw(OSError(5))
        sensors.sample()
        self.assertFalse(a.accel_ok)
        a.read_accel = lambda: (0, 0, 8000)
        self.clock.now = 5001
        sensors.sample()
        self.clock.now += 20
        sensors.sample()
        self.assertTrue(a.accel_ok)

    def test_light_sensor_failure_does_not_use_old_lux(self):
        a = self.app
        a.i2c = object()
        a.last_lux = 5.0
        a.lux_ok = True
        a.light_timer_start_ms = 0
        a.read_lux = lambda: (_ for _ in ()).throw(OSError(5))
        sensors = a.Sensors()
        sensors.lux_started = True
        sensors.light()
        self.assertFalse(a.lux_ok)
        self.assertIsNone(a.last_lux)
        self.assertIsNone(a.light_timer_start_ms)

    def test_short_restart_tumble_does_not_start_new_cycle(self):
        a = self.app
        a.dryer_state = 'COMPLETE'
        a.process_dryer_rms(600)
        self.clock.now = 10000
        a.process_dryer_rms(0)
        self.assertEqual(a.dryer_state, 'COMPLETE')
        self.assertIsNone(a.start_candidate_ms)

    def new_context(self, trial=True):
        Path("dryer_a.py").write_bytes(b"previous")
        Path("dryer_b.py").write_bytes(b"new")
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

        sys.modules["dryer_a"] = types.SimpleNamespace(run=run)
        sys.modules["dryer_b"] = types.SimpleNamespace(run=run)
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
        sys.modules["dryer_b"] = types.SimpleNamespace(run=run)
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
        source = (ROOT / "dryer_a.py").read_text()
        tree = ast.parse(source)
        imports = [alias.name for n in ast.walk(tree) if isinstance(n, ast.Import) for alias in n.names]
        self.assertNotIn("urequests", imports)
        self.assertNotIn("ntptime", imports)
        self.assertNotIn("setdefaulttimeout", source)


if __name__ == "__main__":
    unittest.main()
