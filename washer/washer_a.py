"""Washer 6.0.0: preserved v5 detection, cooperative networking and A/B OTA.
Install with the washer launcher and private configuration; not the dryer app.
"""
DEVICE_TYPE = "washer"
BOOT_API = 1
VERSION = "6.0.0"
BUILD = "2026-09-13-washer-network-ota-public-example"

import machine
from machine import Pin
import network
import time
import math
import socket
import select
import json
import os
import gc
import hashlib
import binascii
from main import read_json, write_json


# PUBLIC EXAMPLES: customize these addresses and the URL-encoded bulb entity.
# Keep both initial application slots identical. Do not flash example settings.
SHELLY_IP = "192.0.2.40"
SWITCH_ID = 0

BULB_IP = "192.0.2.30"
BULB_LIGHT_ENTITY = "Laundry%20Indicator"

# Keep outbound calls shorter than Home Assistant's local REST timeout.  The
# Pico serves /status from this same single-threaded loop, so a long Shelly or
# bulb request must not monopolize the loop for several seconds.
HTTP_TIMEOUT_SECONDS = 1.5
BULB_HTTP_TIMEOUT_SECONDS = 1.0

# Local Home Assistant interface.
# Home Assistant reads http://PICO_IP/status and acknowledges with
# POST to http://PICO_IP/ack.
LOCAL_HTTP_PORT = 80
LOCAL_HTTP_CLIENT_TIMEOUT_SECONDS = 0.75
LOCAL_HTTP_MAX_REQUEST_BYTES = 768
LOCAL_HTTP_MAX_REQUESTS_PER_PASS = 4

# Verified v5 adaptive polling rates.
POLL_STANDBY_SECONDS = 15.0
POLL_RUNNING_SECONDS = 5.0
POLL_TRANSITION_SECONDS = 2.0
POLL_COMPLETE_CLOSED_SECONDS = 5.0

# Verified v5 power bands.
SLEEP_MAX_WATTS = 0.8
CLOSED_LID_IDLE_MIN_WATTS = 1.2
CLOSED_LID_IDLE_MAX_WATTS = 2.2
ACTIVITY_WATTS = 5.0
FINAL_PUMP_MIN_WATTS = 25.0
FINAL_PUMP_MAX_WATTS = 60.0
FINAL_SPIN_MIN_WATTS = 250.0

# Verified v5 start and finish confirmation.
START_HITS_REQUIRED = 2
START_HIT_WINDOW_SECONDS = 60.0
MINIMUM_CYCLE_SECONDS = 35 * 60
FINAL_SPIN_CONFIRM_SECONDS = 60.0
FINAL_LOW_CONFIRM_SECONDS = 120.0
FALLBACK_NO_ACTIVITY_SECONDS = 4 * 60
FALLBACK_LOW_CONFIRM_SECONDS = 60.0

# KAUF alert behavior.
BULB_COLOR_SECONDS = 2.0
BULB_RESET_WHITE_SECONDS = 2.0
BULB_START_RETRY_SECONDS = 10.0

BULB_COLOR_SEQUENCE = (
    ("RED", "brightness=255&r=255&g=0&b=0&transition=0"),
    ("GREEN", "brightness=255&r=0&g=255&b=0&transition=0"),
    ("BLUE", "brightness=255&r=0&g=0&b=255&transition=0"),
    ("WHITE", "brightness=255&color_temp=357&transition=0"),
)


state = "READY"
poll_seconds = POLL_STANDBY_SECONDS

cycle_number = 0
cycle_start_ms = None
cycle_end_ms = None
start_hits_ms = []
last_activity_ms = None

spin_start_ms = None
final_spin_seen = False
final_pump_seen = False
final_low_start_ms = None
fallback_low_start_ms = None
alert_sent = False

bulb_alert_active = False
bulb_color_index = 0
bulb_next_color_ms = 0
bulb_previous_uptime = None
bulb_was_unreachable = False
bulb_retry_after_ms = 0
bulb_reset_stage = None
bulb_reset_reason = ""
bulb_reset_due_ms = 0

last_shelly_error = ""
last_watts = None
last_shelly_ok = False

http_server = None

MAX_HEADERS = 4096
MAX_UPLOAD = 120000
TRANSIENT = (11, 35, 10035, 115, 114, 119)
config = {}
ctx = wifi = led = None
diag = {"wifi_errors": 0, "wifi_reconnects": 0, "listener_restarts": 0,
        "http_errors": 0, "shelly_errors": 0, "bulb_errors": 0,
        "storage_errors": 0, "sample_gaps": 0, "max_loop_ms": 0,
        "last_fault": None}
uptime_ms = 0
upload_owner = reset_at_ms = None
idle_since_ms = healthy_since_ms = None
shelly_job = None
shelly_next_ms = 0
shelly_failures = 0
last_shelly_ok_ms = last_shelly_request_ms = None
last_sample_interval_ms = 15000
input_gap = True
recovery_uncertain = False
bulb_job = None
bulb_job_kind = None
bulb_generation = bulb_job_generation = 0
bulb_next_ms = bulb_failures = 0
bulb_reset_started_ms = None
saved_snapshot = last_persist_ms = None


def safe_debug(message):
    try:
        print(message)
    except Exception:
        pass


def fault(kind, error):
    diag[kind] = diag.get(kind, 0) + 1
    message = kind + ": " + str(error)[:140]
    if message != diag["last_fault"]:
        safe_debug(message)
    diag["last_fault"] = message


def due(stamp, now=None):
    return time.ticks_diff(time.ticks_ms() if now is None else now, stamp) >= 0


def later(ms):
    return time.ticks_add(time.ticks_ms(), ms)


def temporary(exc):
    return isinstance(exc, OSError) and bool(exc.args) and exc.args[0] in TRANSIENT


def close_socket(sock):
    if sock is not None:
        try:
            sock.close()
        except OSError:
            pass


def ready(sock, mask):
    poll = select.poll()
    poll.register(sock, mask)
    events = poll.poll(0)
    return events[0][1] if events else 0


def numeric_ip(value):
    try:
        fields = value.split(".")
        return len(fields) == 4 and all(part.isdigit() and 0 <= int(part) <= 255 for part in fields)
    except (AttributeError, ValueError):
        return False


def authorized(headers):
    token = config.get("UPDATE_TOKEN", "")
    supplied = headers.get(b"authorization", b"")
    expected = ("Bearer " + token).encode()
    if len(token) < 32 or len(supplied) != len(expected):
        return False
    difference = 0
    for left, right in zip(supplied, expected):
        difference |= left ^ right
    return difference == 0

def elapsed_seconds(start_ms, now_ms=None):
    if start_ms is None:
        return 0.0
    if now_ms is None:
        now_ms = time.ticks_ms()
    return time.ticks_diff(now_ms, start_ms) / 1000.0


def display_state():
    """Simple user-facing state for the Home Assistant tile."""
    if state == "RUNNING":
        return "Running"
    if state == "FINISH_WATCH":
        return "Finishing"
    if state == "COMPLETE_CLOSED":
        return "Complete"

    # POSSIBLE_START is not a confirmed cycle yet.
    # ACKNOWLEDGED_WAIT is intentionally shown as Ready while the Pico waits
    # for the old completed load to reach true 0 W before re-arming.
    return "Ready"


def acknowledge_alert(reason, command_bulb=True, washer_is_sleeping=False):
    """
    Clear the current completed-cycle alert.

    If acknowledgement happens while the washer is still sitting in its
    closed-lid finished power state, use ACKNOWLEDGED_WAIT internally. HA still
    displays Ready, but the old load cannot re-trigger. True READY/re-arm occurs
    after the Shelly reports 0 W.
    """
    global state
    global poll_seconds
    global bulb_alert_active
    global bulb_was_unreachable

    if state != "COMPLETE_CLOSED":
        return False

    if command_bulb:
        reset_bulb_to_white_then_off(reason)
    else:
        bulb_alert_active = False
        safe_debug("Bulb alert stopped without command: {}".format(reason))

    bulb_was_unreachable = False

    if washer_is_sleeping:
        state = "READY"
        poll_seconds = POLL_STANDBY_SECONDS
    else:
        state = "ACKNOWLEDGED_WAIT"
        poll_seconds = POLL_COMPLETE_CLOSED_SECONDS

    safe_debug("Washer alert acknowledged: {}".format(reason))
    return True


def begin_cycle(start_ms):
    global cycle_number
    global cycle_start_ms
    global cycle_end_ms
    global last_activity_ms
    global spin_start_ms
    global final_spin_seen
    global final_pump_seen
    global final_low_start_ms
    global fallback_low_start_ms
    global alert_sent
    global start_hits_ms
    global state
    global poll_seconds

    cycle_number += 1
    cycle_start_ms = start_ms
    cycle_end_ms = None
    last_activity_ms = start_ms
    spin_start_ms = None
    final_spin_seen = False
    final_pump_seen = False
    final_low_start_ms = None
    fallback_low_start_ms = None
    alert_sent = False
    start_hits_ms = []
    state = "RUNNING"
    poll_seconds = POLL_RUNNING_SECONDS


def complete_cycle(now_ms, reason):
    global state
    global cycle_end_ms
    global poll_seconds
    global alert_sent

    if state == "COMPLETE_CLOSED":
        return ""

    state = "COMPLETE_CLOSED"
    cycle_end_ms = now_ms
    poll_seconds = POLL_COMPLETE_CLOSED_SECONDS

    event = "Cycle {} complete ({})".format(cycle_number, reason)
    safe_debug(event)

    if not alert_sent:
        alert_sent = True
        start_bulb_alert("washer cycle complete")

    return event


def process_watts(watts, now_ms):
    global state
    global poll_seconds
    global start_hits_ms
    global last_activity_ms
    global spin_start_ms
    global final_spin_seen
    global final_pump_seen
    global final_low_start_ms
    global fallback_low_start_ms

    event = ""

    # READY: true sleep/standby after lid opening.
    if state == "READY":
        poll_seconds = POLL_STANDBY_SECONDS

        if watts > SLEEP_MAX_WATTS:
            state = "POSSIBLE_START"
            poll_seconds = POLL_TRANSITION_SECONDS
            start_hits_ms = []
            event = "Washer woke at {:.1f} W; checking for a new cycle".format(watts)

    # ACKNOWLEDGED_WAIT: alert was manually acknowledged while the old
    # completed load is still sitting at its closed-lid idle power. Ignore that
    # old load until the washer reaches true 0 W, then re-arm.
    if state == "ACKNOWLEDGED_WAIT":
        poll_seconds = POLL_COMPLETE_CLOSED_SECONDS

        if watts <= SLEEP_MAX_WATTS:
            state = "READY"
            poll_seconds = POLL_STANDBY_SECONDS
            event = "Acknowledged completed load reached 0 W; washer re-armed"

    # POSSIBLE_START: two meaningful activity hits within one minute.
    if state == "POSSIBLE_START":
        poll_seconds = POLL_TRANSITION_SECONDS

        start_hits_ms = [
            hit for hit in start_hits_ms
            if elapsed_seconds(hit, now_ms) <= START_HIT_WINDOW_SECONDS
        ]

        if watts > ACTIVITY_WATTS:
            start_hits_ms.append(now_ms)

        if len(start_hits_ms) >= START_HITS_REQUIRED:
            begin_cycle(start_hits_ms[0])
            event = "Cycle {} confirmed running".format(cycle_number)

        elif watts <= SLEEP_MAX_WATTS and not start_hits_ms:
            state = "READY"
            poll_seconds = POLL_STANDBY_SECONDS
            event = "Wake-up ended without a confirmed cycle"

    if state in ("RUNNING", "FINISH_WATCH"):
        cycle_elapsed = elapsed_seconds(cycle_start_ms, now_ms)

        if state == "FINISH_WATCH":
            poll_seconds = POLL_TRANSITION_SECONDS
        else:
            poll_seconds = POLL_RUNNING_SECONDS

        if watts > ACTIVITY_WATTS:
            last_activity_ms = now_ms
            final_low_start_ms = None
            fallback_low_start_ms = None

        # Confirm a sustained high-power final spin.
        if watts >= FINAL_SPIN_MIN_WATTS and cycle_elapsed >= MINIMUM_CYCLE_SECONDS:
            if spin_start_ms is None:
                spin_start_ms = now_ms
            elif elapsed_seconds(spin_start_ms, now_ms) >= FINAL_SPIN_CONFIRM_SECONDS:
                if not final_spin_seen:
                    final_spin_seen = True
                    state = "FINISH_WATCH"
                    poll_seconds = POLL_TRANSITION_SECONDS
                    event = "Sustained final spin detected; watching for final pump"
        else:
            spin_start_ms = None

        # The repeated 37-45 W event following final spin.
        if (
            final_spin_seen
            and FINAL_PUMP_MIN_WATTS <= watts <= FINAL_PUMP_MAX_WATTS
        ):
            if not final_pump_seen:
                final_pump_seen = True
                state = "FINISH_WATCH"
                poll_seconds = POLL_TRANSITION_SECONDS
                event = "Final pump/event detected at {:.1f} W".format(watts)

        in_finished_band = (
            CLOSED_LID_IDLE_MIN_WATTS
            <= watts
            <= CLOSED_LID_IDLE_MAX_WATTS
        )

        # Primary completion path.
        if final_pump_seen and in_finished_band:
            if final_low_start_ms is None:
                final_low_start_ms = now_ms
            elif elapsed_seconds(final_low_start_ms, now_ms) >= FINAL_LOW_CONFIRM_SECONDS:
                return complete_cycle(
                    now_ms,
                    "final pump followed by stable closed-lid idle",
                )
        else:
            final_low_start_ms = None

        # Conservative fallback if the short final pump sample is missed.
        no_activity_for = elapsed_seconds(last_activity_ms, now_ms)

        if (
            final_spin_seen
            and not final_pump_seen
            and in_finished_band
            and no_activity_for >= FALLBACK_NO_ACTIVITY_SECONDS
        ):
            if fallback_low_start_ms is None:
                fallback_low_start_ms = now_ms
            elif elapsed_seconds(fallback_low_start_ms, now_ms) >= FALLBACK_LOW_CONFIRM_SECONDS:
                return complete_cycle(
                    now_ms,
                    "fallback: long quiet closed-lid idle",
                )
        else:
            fallback_low_start_ms = None

    if state == "COMPLETE_CLOSED":
        poll_seconds = POLL_COMPLETE_CLOSED_SECONDS

        if watts <= SLEEP_MAX_WATTS:
            acknowledge_alert(
                "lid opened / washer entered 0 W sleep",
                command_bulb=True,
                washer_is_sleeping=True,
            )
            event = "Lid opened / washer entered 0 W sleep; alert reset; READY"

        elif watts > ACTIVITY_WATTS:
            reset_bulb_to_white_then_off("new washer activity")
            state = "POSSIBLE_START"
            poll_seconds = POLL_TRANSITION_SECONDS
            start_hits_ms = [now_ms]
            event = "New washer activity detected after completed cycle"

    if event:
        safe_debug(event)

    return event


def safe_float(value):
    try:
        number = float(value) if value is not None and not isinstance(value, bool) else None
        return number if number is not None and math.isfinite(number) else None
    except (ValueError, TypeError, OverflowError):
        return None


def invalidate_input(reason):
    global last_shelly_ok, last_shelly_error, last_watts, input_gap, idle_since_ms
    global start_hits_ms, spin_start_ms, final_low_start_ms, fallback_low_start_ms
    if not input_gap:
        diag["sample_gaps"] += 1
    input_gap = True
    last_shelly_ok = False
    last_watts = None
    idle_since_ms = None
    last_shelly_error = str(reason)[:140]
    start_hits_ms = []
    spin_start_ms = final_low_start_ms = fallback_low_start_ms = None


def abort_network_jobs():
    global shelly_job, shelly_next_ms
    if shelly_job is not None:
        shelly_job.finish(error="Wi-Fi changed")
        shelly_job = None
    shelly_next_ms = time.ticks_ms()
    abort_bulb_job()
    invalidate_input("Wi-Fi unavailable or address changed")


def restart_listeners():
    if http_server is not None:
        http_server.close()
        http_server.next_ms = time.ticks_ms()


class Wifi:
    def __init__(self):
        self.wlan = network.WLAN(network.STA_IF)
        self.ip = None
        self.connecting = False
        self.next_ms = time.ticks_ms()
        self.started = None
        self.attempts = 0
        self.radio_off = False
        self.power_save_disabled = False
        self.pm_attempted = False

    def configure_pm(self):
        if self.pm_attempted:
            return
        self.pm_attempted = True
        self.power_save_disabled = False
        try:
            self.wlan.config(pm=network.WLAN.PM_NONE)
            self.power_save_disabled = True
        except (AttributeError, ValueError, OSError, TypeError):
            pass

    def lost(self):
        if self.ip is not None:
            self.ip = None
            restart_listeners()
            abort_network_jobs()

    def step(self):
        now = time.ticks_ms()
        try:
            if self.wlan.isconnected():
                self.configure_pm()
                address = self.wlan.ifconfig()[0]
                if not numeric_ip(address) or address == "0.0.0.0":
                    raise ValueError("Wi-Fi has no usable IPv4 address")
                if address != self.ip:
                    self.ip = address
                    diag["wifi_reconnects"] += 1
                    restart_listeners()
                    abort_network_jobs()
                self.connecting = False
                self.attempts = 0
                return
            self.lost()
            if self.connecting:
                if self.wlan.status() < 0 or elapsed_seconds(self.started, now) >= 20:
                    self.connecting = False
                    self.next_ms = later(min(60000, 2000 * (2 ** min(self.attempts, 5))))
                    self.wlan.disconnect()
                return
            if not due(self.next_ms, now):
                return
            if not self.radio_off:
                self.attempts += 1
                if self.attempts % 3 == 0:
                    self.radio_off = True
                    self.next_ms = later(500)
                    self.wlan.active(False)
                    return
            self.wlan.active(True)
            self.radio_off = False
            self.pm_attempted = False
            self.configure_pm()
            self.wlan.connect(config["WIFI_SSID"], config["WIFI_PASSWORD"])
            self.started = now
            self.connecting = True
        except (OSError, ValueError, RuntimeError, TypeError) as exc:
            self.lost()
            fault("wifi_errors", exc)
            self.connecting = False
            self.next_ms = later(5000)


class Fetch:
    """Incremental HTTP to an existing numeric LAN address, with a total deadline."""
    def __init__(self, ip, method, path, timeout=BULB_HTTP_TIMEOUT_SECONDS):
        if not numeric_ip(ip):
            raise ValueError("HTTP target must be a numeric IPv4 address")
        self.sock = None
        self.started = time.ticks_ms()
        self.timeout = timeout
        self.rx = b""
        self.tx = (method + " " + path + " HTTP/1.0\r\nHost: " + ip +
                   "\r\nConnection: close\r\nContent-Length: 0\r\n\r\n").encode()
        self.sent = 0
        self.result = None
        try:
            self.sock = socket.socket()
            self.sock.settimeout(0)
            try:
                self.sock.connect((ip, 80))
            except OSError as exc:
                if not temporary(exc):
                    raise
        except Exception:
            close_socket(self.sock)
            raise

    def finish(self, body=None, error=None):
        close_socket(self.sock)
        self.sock = None
        self.result = (body, error)

    def step(self):
        if self.result is not None:
            return
        if elapsed_seconds(self.started) >= self.timeout:
            self.finish(error="HTTP deadline")
            return
        try:
            if self.sent < len(self.tx):
                if ready(self.sock, select.POLLOUT):
                    count = self.sock.send(self.tx[self.sent:self.sent + 512])
                    if count is None:
                        return
                    if count <= 0:
                        raise OSError("HTTP write closed")
                    self.sent += count
                return
            if not ready(self.sock, select.POLLIN):
                return
            chunk = self.sock.recv(1024)
            if chunk is None:
                return
            self.rx += chunk
            if len(self.rx) > 16384:
                raise ValueError("HTTP response too large")
            body = parse_response(self.rx, eof=not chunk)
            if body is not None:
                self.finish(body=body)
        except OSError as exc:
            if not temporary(exc):
                self.finish(error=str(exc))
        except (ValueError, IndexError, TypeError) as exc:
            self.finish(error=str(exc))


def parse_response(data, eof=False):
    end = data.find(b"\r\n\r\n")
    if end < 0:
        if eof or len(data) > MAX_HEADERS:
            raise ValueError("Incomplete or oversized HTTP headers")
        return None
    if end > MAX_HEADERS:
        raise ValueError("HTTP headers too large")
    head, body = data[:end], data[end + 4:]
    lines = head.split(b"\r\n")
    status = lines[0].split()
    if len(status) < 2 or not status[0].startswith(b"HTTP/1."):
        raise ValueError("Invalid HTTP status")
    code = int(status[1])
    if not 200 <= code < 300:
        raise ValueError("HTTP " + str(code))
    headers = {}
    for line in lines[1:]:
        key, value = line.split(b":", 1)
        key = key.strip().lower()
        if key in (b"content-length", b"transfer-encoding") and key in headers:
            raise ValueError("Duplicate HTTP framing header")
        headers[key] = value.strip().lower()
    encoding = headers.get(b"transfer-encoding")
    if encoding is not None:
        if encoding != b"chunked" or b"content-length" in headers:
            raise ValueError("Unsupported or conflicting HTTP framing")
        output = b""
        pos = 0
        while True:
            end = body.find(b"\r\n", pos)
            if end < 0:
                break
            size = int(body[pos:end].split(b";", 1)[0], 16)
            if size < 0 or size > 16384:
                raise ValueError("Invalid chunk length")
            pos = end + 2
            if size == 0:
                if body[pos:pos + 2] == b"\r\n" or b"\r\n\r\n" in body[pos:]:
                    return output
                break
            if len(body) < pos + size + 2:
                break
            if body[pos + size:pos + size + 2] != b"\r\n":
                raise ValueError("Malformed chunk")
            output += body[pos:pos + size]
            pos += size + 2
        if eof:
            raise ValueError("Truncated chunked body")
        return None
    if b"content-length" in headers:
        length = int(headers[b"content-length"])
        if length < 0 or length > 16384:
            raise ValueError("Invalid HTTP Content-Length")
        if len(body) >= length:
            return body[:length]
        if eof:
            raise ValueError("Truncated HTTP body")
        return None
    return body if eof or code == 204 else None


def sample_fresh():
    return (last_shelly_ok and wifi is not None and wifi.ip is not None
            and last_shelly_ok_ms is not None
            and elapsed_seconds(last_shelly_ok_ms) <= (last_sample_interval_ms / 1000.0 + HTTP_TIMEOUT_SECONDS + 1))


def receive_watts(watts, stamp):
    """Fresh-input wrapper; the three original decision functions above are unchanged."""
    global input_gap, last_activity_ms, last_watts, last_shelly_ok, last_shelly_ok_ms
    global last_shelly_error, last_sample_interval_ms, idle_since_ms, recovery_uncertain
    if last_shelly_ok_ms is not None and not sample_fresh():
        invalidate_input("Shelly sampling gap")
    if input_gap and state in ("RUNNING", "FINISH_WATCH"):
        # Downtime is not evidence of continuously observed inactivity.
        last_activity_ms = stamp
    input_gap = False
    last_watts, last_shelly_ok, last_shelly_ok_ms = watts, True, stamp
    last_shelly_error = ""
    process_watts(watts, stamp)
    last_sample_interval_ms = int(poll_seconds * 1000)
    if state == "READY" and watts <= SLEEP_MAX_WATTS:
        recovery_uncertain = False
        if idle_since_ms is None:
            idle_since_ms = stamp
    else:
        idle_since_ms = None


def service_shelly():
    global shelly_job, shelly_next_ms, shelly_failures, last_shelly_request_ms
    if last_shelly_ok and not sample_fresh():
        invalidate_input("Shelly sample stale")
    if wifi is None or wifi.ip is None:
        if last_shelly_ok:
            invalidate_input("Wi-Fi unavailable")
        return
    if shelly_job is not None:
        shelly_job.step()
        if shelly_job.result is None:
            return
        job, shelly_job = shelly_job, None
        body, error = job.result
        if error is None:
            try:
                data = json.loads(body)
                if not isinstance(data, dict) or data.get("id", SWITCH_ID) != SWITCH_ID:
                    raise ValueError("Unexpected Shelly switch response")
                watts = safe_float(data.get("apower"))
                if watts is None or watts < 0:
                    raise ValueError("Shelly apower is missing or invalid")
                last_shelly_request_ms = job.started
                receive_watts(watts, time.ticks_ms())
                shelly_failures = 0
            except (ValueError, TypeError, KeyError) as exc:
                error = str(exc)
        if error is not None:
            fault("shelly_errors", error)
            invalidate_input(error)
            shelly_failures += 1
            delay = min(30000, 2000 * (2 ** min(shelly_failures - 1, 4)))
        else:
            delay = 1000 if upload_owner is not None else int(poll_seconds * 1000)
        shelly_next_ms = later(delay)
        return
    if due(shelly_next_ms):
        try:
            shelly_job = Fetch(SHELLY_IP, "GET", "/rpc/Switch.GetStatus?id=" + str(SWITCH_ID), HTTP_TIMEOUT_SECONDS)
        except (OSError, ValueError) as exc:
            fault("shelly_errors", exc)
            invalidate_input(exc)
            shelly_next_ms = later(5000)


def abort_bulb_job():
    global bulb_job
    if bulb_job is not None:
        bulb_job.finish(error="Superseded")
        bulb_job = None


def start_bulb_alert(reason):
    global bulb_alert_active, bulb_generation, bulb_color_index, bulb_reset_stage
    global bulb_next_ms, bulb_reset_started_ms, bulb_failures, bulb_previous_uptime
    if bulb_alert_active:
        return True
    abort_bulb_job()
    bulb_generation += 1
    bulb_alert_active = True
    bulb_reset_stage = None
    bulb_reset_started_ms = None
    bulb_color_index = 0
    bulb_failures = 0
    bulb_previous_uptime = None
    bulb_next_ms = time.ticks_ms()
    safe_debug("Bulb alert scheduled: " + reason)
    return True


def reset_bulb_to_white_then_off(reason):
    global bulb_alert_active, bulb_generation, bulb_reset_stage, bulb_reset_reason
    global bulb_next_ms, bulb_reset_started_ms, bulb_failures
    abort_bulb_job()
    bulb_generation += 1
    bulb_alert_active = False
    bulb_reset_stage = "WHITE"
    bulb_reset_reason = reason
    bulb_reset_started_ms = time.ticks_ms()
    bulb_failures = 0
    bulb_next_ms = time.ticks_ms()
    safe_debug("Bulb reset scheduled: " + reason)


def begin_bulb_job(kind):
    global bulb_job, bulb_job_kind, bulb_job_generation
    path = "/light/" + BULB_LIGHT_ENTITY
    method = "POST"
    if kind == "uptime":
        path, method = "/sensor/Uptime", "GET"
    elif kind == "color":
        path += "/turn_on?" + BULB_COLOR_SEQUENCE[bulb_color_index][1]
    elif kind == "white":
        path += "/turn_on?brightness=255&color_temp=357&transition=0"
    else:
        path += "/turn_off?transition=0"
    bulb_job = Fetch(BULB_IP, method, path)
    bulb_job_kind, bulb_job_generation = kind, bulb_generation


def service_bulb_alert():
    global bulb_job, bulb_next_ms, bulb_failures, bulb_previous_uptime
    global bulb_was_unreachable, bulb_color_index, bulb_generation
    global bulb_reset_stage, bulb_reset_started_ms
    if wifi is None or wifi.ip is None:
        return
    if bulb_job is not None:
        bulb_job.step()
        if bulb_job.result is None:
            return
        body, error = bulb_job.result
        kind, generation = bulb_job_kind, bulb_job_generation
        bulb_job = None
        if generation != bulb_generation:
            return
        value = None
        if kind == "uptime" and error is None:
            try:
                data = json.loads(body)
                value = safe_float(data.get("value")) if isinstance(data, dict) else None
                if value is None or value < 0:
                    raise ValueError("Invalid Kauf uptime")
            except (ValueError, TypeError) as exc:
                error = str(exc)
        if error is not None:
            fault("bulb_errors", error)
            bulb_failures += 1
            bulb_was_unreachable = True
            # WHITE is cosmetic: after a bounded attempt, retain OFF work.
            # Repeated late WHITE commands must not relight a shared lamp.
            if kind == "white":
                bulb_reset_stage = "OFF"
            delay = min(30000, 2000 * (2 ** min(bulb_failures - 1, 4)))
            if kind == "uptime" and bulb_previous_uptime is None:
                delay = max(delay, int(BULB_START_RETRY_SECONDS * 1000))
            bulb_next_ms = later(delay)
            return
        bulb_failures = 0
        bulb_was_unreachable = False
        if kind == "uptime" and bulb_alert_active:
            if bulb_previous_uptime is not None and value + 1.0 < bulb_previous_uptime:
                acknowledge_alert("Kauf power cycle confirmed by uptime", command_bulb=False)
                bulb_generation += 1
                bulb_reset_stage = "OFF"
                bulb_reset_started_ms = time.ticks_ms()
                bulb_next_ms = time.ticks_ms()
            else:
                bulb_previous_uptime = value
                # Acknowledgments run before this service pass. Generation checks
                # discard old replies; starting a command never services HA inside it.
                try:
                    begin_bulb_job("color")
                except (OSError, ValueError) as exc:
                    fault("bulb_errors", exc)
                    bulb_next_ms = later(5000)
        elif kind == "color" and bulb_alert_active:
            bulb_color_index = (bulb_color_index + 1) % len(BULB_COLOR_SEQUENCE)
            bulb_next_ms = later(int(BULB_COLOR_SECONDS * 1000))
        elif kind == "white" and not bulb_alert_active:
            bulb_reset_stage = "OFF"
            bulb_next_ms = later(int(BULB_RESET_WHITE_SECONDS * 1000))
        elif kind == "off" and not bulb_alert_active:
            bulb_reset_stage = None
            bulb_reset_started_ms = None
        return
    if not due(bulb_next_ms):
        return
    kind = None
    if bulb_alert_active:
        kind = "uptime"
    elif bulb_reset_stage:
        # Avoid a delayed cosmetic white flash when Wi-Fi returns much later.
        if bulb_reset_stage == "WHITE" and elapsed_seconds(bulb_reset_started_ms) > 5:
            bulb_reset_stage = "OFF"
        kind = "white" if bulb_reset_stage == "WHITE" else "off"
    if kind:
        try:
            begin_bulb_job(kind)
        except (OSError, ValueError) as exc:
            fault("bulb_errors", exc)
            bulb_next_ms = later(5000)


def healthy():
    return sample_fresh() and http_server is not None and http_server.sock is not None


def safe_idle():
    return (healthy() and state == "READY" and not recovery_uncertain
            and last_watts is not None and last_watts <= SLEEP_MAX_WATTS
            and not bulb_alert_active and bulb_reset_stage is None and bulb_job is None
            and idle_since_ms is not None and elapsed_seconds(idle_since_ms) >= 30)


def confirmation_allowed():
    return (healthy() and healthy_since_ms is not None
            and elapsed_seconds(healthy_since_ms) >= 60 and ctx.age_ms() >= 60000)


def update_allowed():
    return (ctx is not None and ctx.confirmed and not ctx.trial and safe_idle()
            and upload_owner is None and reset_at_ms is None and ctx.age_ms() >= 60000)


def status_dict():
    fresh = sample_fresh()
    data = {"state": display_state(), "internal_state": state,
            "alert_active": state == "COMPLETE_CLOSED", "watts": last_watts if fresh else None,
            "shelly_online": bool(fresh), "cycle_number": cycle_number,
            "version": VERSION, "build": BUILD, "device_type": DEVICE_TYPE,
            "device_id": config.get("DEVICE_ID"), "boot_api": BOOT_API,
            "uptime_seconds": uptime_ms // 1000, "reset_cause": machine.reset_cause(),
            "firmware": os.uname().release, "hardware": os.uname().machine,
            "memory_free": gc.mem_free(), "wifi_connected": wifi.ip is not None,
            "wifi_power_save_disabled": wifi.power_save_disabled, "ip": wifi.ip,
            "shelly_age_seconds": elapsed_seconds(last_shelly_ok_ms) if last_shelly_ok_ms is not None else None,
            "last_shelly_error": last_shelly_error, "sample_valid": bool(fresh),
            "recovery_uncertain": recovery_uncertain, "bulb_alert_active": bulb_alert_active,
            "bulb_off_pending": bulb_reset_stage is not None, "bulb_reset_stage": bulb_reset_stage,
            "slot": ctx.slot, "trial": ctx.trial, "boot_age_seconds": ctx.age_ms() // 1000,
            "running_sha256": ctx.sha256, "update_allowed": bool(update_allowed()),
            "confirmation_allowed": bool(confirmation_allowed()),
            "last_crash": read_json("last_crash.json", None)}
    data.update(diag)
    try:
        data["wifi_rssi"] = wifi.wlan.status("rssi") if wifi.ip else None
    except (OSError, ValueError, TypeError):
        data["wifi_rssi"] = None
    return data


class HttpClient:
    def __init__(self, sock):
        self.sock = sock
        try:
            sock.settimeout(0)
        except Exception:
            close_socket(sock)
            raise
        self.started = time.ticks_ms()
        self.rx = self.tx = self.prefix = b""
        self.sent = self.count = self.length = 0
        self.phase = "headers"
        self.file = self.upload_path = None
        self.deadline = 8000
        self.close_at = None

    def discard_upload(self):
        global upload_owner
        if self.file is not None:
            try:
                self.file.close()
            finally:
                self.file = None
        if self.upload_path is not None:
            # Only our own fixed inactive-slot temporary path, never a user path.
            try:
                os.remove(self.upload_path)
            except OSError:
                pass
            self.upload_path = None
        if upload_owner is self:
            upload_owner = None

    def close(self):
        try:
            self.discard_upload()
        finally:
            close_socket(self.sock)
            self.sock = None

    def respond(self, code, body):
        payload = (body if isinstance(body, str) else json.dumps(body)).encode()
        self.tx = ("HTTP/1.1 " + code + "\r\nContent-Type: application/json\r\n"
                   "Connection: close\r\nCache-Control: no-store\r\nContent-Length: " +
                   str(len(payload)) + "\r\n\r\n").encode() + payload
        self.sent = 0
        self.phase = "response"

    def acknowledge(self):
        accepted = acknowledge_alert("Home Assistant / Echo acknowledgement")
        self.respond("200 OK", {"accepted": accepted, "state": display_state(), "internal_state": state})

    def route(self, head, remaining):
        global upload_owner, shelly_next_ms
        lines = head.split(b"\r\n")
        first = lines[0].split()
        if len(first) != 3 or first[2] not in (b"HTTP/1.0", b"HTTP/1.1"):
            raise ValueError("Invalid request line")
        method, path = first[:2]
        path = path.split(b"?", 1)[0].rstrip(b"/") or b"/"
        headers = {}
        for line in lines[1:]:
            key, value = line.split(b":", 1)
            key = key.strip().lower()
            if not key or key in headers:
                raise ValueError("Missing or duplicate header")
            headers[key] = value.strip()
        if b"transfer-encoding" in headers:
            raise ValueError("Use fixed Content-Length, not chunked requests")
        self.length = int(headers.get(b"content-length", b"0"))
        if self.length < 0 or len(remaining) > self.length:
            raise ValueError("Invalid body length or pipelining")
        if method == b"GET" and path in (b"/", b"/status"):
            if self.length:
                raise ValueError("GET must have an empty body")
            self.respond("200 OK", status_dict())
            return
        if path == b"/ack" and method == b"POST":
            if self.length > 2048:
                raise ValueError("Acknowledgment body too large")
            self.count = len(remaining)
            if self.count == self.length:
                self.acknowledge()
            else:
                self.phase = "ack_body"
            return
        if path not in (b"/update", b"/update/confirm"):
            self.respond("404 Not Found", {"error": "Not found"})
            return
        if not authorized(headers):
            self.respond("401 Unauthorized", {"error": "Update token required"})
            return
        if headers.get(b"x-device-type") != b"washer" or headers.get(b"x-device-id") != config["DEVICE_ID"].encode():
            self.respond("409 Conflict", {"error": "Wrong washer device identity"})
            return
        if path == b"/update/confirm" and method == b"POST":
            if self.length:
                raise ValueError("Confirmation must have an empty body")
            if headers.get(b"x-confirm-sha256", b"").decode() != ctx.sha256:
                self.respond("409 Conflict", {"error": "Running application hash does not match confirmation"})
            elif not confirmation_allowed() or not ctx.confirm():
                self.respond("409 Conflict", {"error": "Need 60 healthy seconds with fresh Shelly readings"})
            else:
                self.respond("200 OK", {"confirmed": True, "slot": ctx.slot,
                                        "device_type": DEVICE_TYPE, "device_id": config["DEVICE_ID"], "sha256": ctx.sha256})
            return
        if path != b"/update" or method != b"PUT":
            self.respond("405 Method Not Allowed", {"error": "Use PUT /update"})
            return
        if not update_allowed():
            self.respond("409 Conflict", {"error": "Need confirmed firmware, fresh readings and idle washer for 30 seconds"})
            return
        if not 1000 <= self.length <= MAX_UPLOAD:
            self.respond("413 Content Too Large", {"error": "Application size outside allowed range"})
            return
        self.expected = headers.get(b"x-sha256", b"").decode().lower()
        if len(self.expected) != 64 or any(c not in "0123456789abcdef" for c in self.expected):
            raise ValueError("SHA-256 header required")
        self.slot = "b" if ctx.slot == "a" else "a"
        self.upload_path = "washer_" + self.slot + ".upload"
        self.file = open(self.upload_path, "wb")
        self.digest = hashlib.sha256()
        self.deadline = 60000
        self.phase = "upload"
        upload_owner = self
        shelly_next_ms = time.ticks_ms()
        if headers.get(b"expect", b"").lower() == b"100-continue":
            self.tx = b"HTTP/1.1 100 Continue\r\n\r\n"
            self.sent = 0
        self.consume(remaining)

    def consume(self, chunk):
        global shelly_next_ms
        if not safe_idle():
            raise ValueError("Washer activity or stale input; update cancelled")
        if self.count + len(chunk) > self.length:
            raise ValueError("Upload exceeds declared size")
        if len(self.prefix) < 2048:
            self.prefix += chunk[:2048 - len(self.prefix)]
        written = self.file.write(chunk)
        if written != len(chunk):
            raise OSError("Short flash write")
        self.digest.update(chunk)
        self.count += len(chunk)
        if self.count != self.length:
            return
        self.file.close()
        self.file = None
        actual = binascii.hexlify(self.digest.digest()).decode()
        if actual != self.expected:
            raise ValueError("SHA-256 mismatch; confirmed application untouched")
        prefix = b"\n" + self.prefix.replace(b"\r\n", b"\n")
        if b'\nDEVICE_TYPE = "washer"\n' not in prefix or b"\nBOOT_API = 1\n" not in prefix:
            raise ValueError("Not a washer application for this boot API")
        self.verify_started = time.ticks_ms()
        self.phase = "verify"
        # Require a power request begun AFTER receiving the complete upload.
        shelly_next_ms = time.ticks_ms()

    def finish_upload(self):
        global reset_at_ms, upload_owner
        if not safe_idle():
            raise ValueError("Washer activity or stale input; update cancelled")
        if (last_shelly_request_ms is None or last_shelly_ok_ms is None
                or time.ticks_diff(last_shelly_request_ms, self.verify_started) < 0
                or elapsed_seconds(last_shelly_ok_ms) > 3):
            return
        if hasattr(os, "sync"):
            os.sync()
        os.rename(self.upload_path, "washer_" + self.slot + ".py")
        self.upload_path = None
        if hasattr(os, "sync"):
            os.sync()
        ctx.stage(self.slot)
        upload_owner = None
        reset_at_ms = later(2500)
        self.respond("202 Accepted", {"staged": self.slot, "sha256": self.expected,
                                      "confirmation_required": True,
                                      "device_type": DEVICE_TYPE, "device_id": config["DEVICE_ID"]})

    def step(self):
        if self.sock is None:
            return
        if time.ticks_diff(time.ticks_ms(), self.started) > self.deadline:
            self.close()
            return
        try:
            if self.phase in ("upload", "verify") and not safe_idle():
                raise ValueError("Washer activity or stale input; update cancelled")
            if self.tx:
                if ready(self.sock, select.POLLOUT):
                    count = self.sock.send(self.tx[self.sent:self.sent + 1024])
                    if count is None:
                        return
                    if count <= 0:
                        self.close()
                        return
                    self.sent += count
                if self.sent >= len(self.tx):
                    self.tx, self.sent = b"", 0
                    if self.phase == "response":
                        self.phase = "closing"
                        self.close_at = later(250)
                        try:
                            self.sock.shutdown(1)
                        except (AttributeError, OSError):
                            pass
                return
            if self.phase == "closing":
                if due(self.close_at):
                    self.close()
                elif ready(self.sock, select.POLLIN) and self.sock.recv(1024) == b"":
                    self.close()
                return
            if self.phase == "verify":
                if ready(self.sock, select.POLLIN):
                    extra = self.sock.recv(1024)
                    if extra == b"":
                        self.close()
                        return
                    if extra:
                        raise ValueError("Unexpected data after upload")
                self.finish_upload()
                return
            if not ready(self.sock, select.POLLIN):
                return
            chunk = self.sock.recv(1024)
            if chunk is None:
                return
            if not chunk:
                self.close()
                return
            if self.phase == "upload":
                self.consume(chunk)
            elif self.phase == "ack_body":
                self.count += len(chunk)
                if self.count > self.length:
                    raise ValueError("Acknowledgment body length exceeded")
                if self.count == self.length:
                    self.acknowledge()
            else:
                self.rx += chunk
                end = self.rx.find(b"\r\n\r\n")
                if end >= 0:
                    if end > MAX_HEADERS:
                        raise ValueError("HTTP headers too large")
                    self.route(self.rx[:end], self.rx[end + 4:])
                    self.rx = b""
                elif len(self.rx) > MAX_HEADERS:
                    raise ValueError("HTTP headers too large")
        except OSError as exc:
            if not temporary(exc):
                fault("http_errors", exc)
                self.close()
        except (ValueError, IndexError, UnicodeError, TypeError) as exc:
            fault("http_errors", exc)
            self.discard_upload()
            self.respond("400 Bad Request", {"error": str(exc)[:140]})


class Listener:
    def __init__(self, port):
        self.port = port
        self.sock = None
        self.clients = []
        self.next_ms = time.ticks_ms()

    def close(self):
        for client in self.clients:
            client.close()
        self.clients = []
        close_socket(self.sock)
        self.sock = None

    def step(self):
        if wifi.ip is None:
            self.close()
            return
        if self.sock is None:
            if not due(self.next_ms):
                return
            try:
                self.sock = socket.socket()
                try:
                    self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                except (OSError, AttributeError):
                    pass
                self.sock.settimeout(0)
                self.sock.bind(("0.0.0.0", self.port))
                self.sock.listen(4)
                diag["listener_restarts"] += 1
            except (OSError, ValueError) as exc:
                fault("http_errors", exc)
                self.close()
                self.next_ms = later(3000)
                return
        if len(self.clients) < LOCAL_HTTP_MAX_REQUESTS_PER_PASS:
            try:
                sock, address = self.sock.accept()
                self.clients.append(HttpClient(sock))
            except OSError as exc:
                if not temporary(exc):
                    fault("http_errors", exc)
                    self.close()
                    self.next_ms = later(1000)
                    return
        for client in self.clients[:]:
            client.step()
            if client.sock is None:
                self.clients.remove(client)


def load_runtime():
    global state, poll_seconds, cycle_number, cycle_start_ms, last_activity_ms
    global final_spin_seen, final_pump_seen, alert_sent, bulb_alert_active
    global bulb_previous_uptime, bulb_reset_stage, bulb_reset_started_ms, recovery_uncertain
    try:
        with open("washer_state.json") as stream:
            saved = json.load(stream)
    except OSError as exc:
        if exc.args and exc.args[0] == 2:
            return  # New installation, not a claim about any previous load.
        saved = None
    except ValueError:
        saved = None
    try:
        if not isinstance(saved, dict) or saved.get("format") != 1 or saved.get("device_type") != DEVICE_TYPE:
            raise ValueError("Unusable washer recovery state")
        restored = saved["state"]
        if restored not in ("READY", "POSSIBLE_START", "RUNNING", "FINISH_WATCH", "COMPLETE_CLOSED", "ACKNOWLEDGED_WAIT"):
            raise ValueError("Invalid saved washer state")
        number = saved["cycle_number"]
        age = safe_float(saved.get("cycle_elapsed", 0))
        if not isinstance(number, int) or isinstance(number, bool) or number < 0 or age is None or not 0 <= age <= 86400:
            raise ValueError("Invalid saved cycle metadata")
        state, cycle_number = restored, number
        now = time.ticks_ms()
        if state in ("RUNNING", "FINISH_WATCH"):
            cycle_start_ms = time.ticks_add(now, -int(age * 1000))
            last_activity_ms = now
            final_spin_seen = saved.get("final_spin") is True
            final_pump_seen = final_spin_seen and saved.get("final_pump") is True
            recovery_uncertain = True
        poll_seconds = POLL_STANDBY_SECONDS if state == "READY" else POLL_TRANSITION_SECONDS
        bulb_alert_active = state == "COMPLETE_CLOSED"
        alert_sent = bulb_alert_active
        value = safe_float(saved.get("bulb_uptime"))
        bulb_previous_uptime = value if value is not None and value >= 0 else None
        if saved.get("off_pending") is True and not bulb_alert_active:
            bulb_reset_stage = "OFF"
            bulb_reset_started_ms = now
    except (ValueError, KeyError, TypeError) as exc:
        fault("storage_errors", exc)
        # Do not turn corrupted prior-cycle state into a newly observed cycle.
        state = "ACKNOWLEDGED_WAIT"
        poll_seconds = POLL_COMPLETE_CLOSED_SECONDS
        recovery_uncertain = True


def persist_runtime():
    global saved_snapshot, last_persist_ms
    snapshot = (state, cycle_number, final_spin_seen, final_pump_seen,
                bulb_alert_active, bulb_reset_stage is not None)
    elapsed = elapsed_seconds(last_persist_ms) if last_persist_ms is not None else 86400
    checkpoint = state in ("RUNNING", "FINISH_WATCH") and elapsed >= 60
    if (snapshot == saved_snapshot and not checkpoint) or elapsed < 5:
        return
    last_persist_ms = time.ticks_ms()
    try:
        write_json("washer_state.json", {"format": 1, "device_type": DEVICE_TYPE,
                   "state": state, "cycle_number": cycle_number,
                   "cycle_elapsed": min(86400, max(0, elapsed_seconds(cycle_start_ms))),
                   "final_spin": final_spin_seen, "final_pump": final_pump_seen,
                   "bulb_uptime": bulb_previous_uptime, "off_pending": bulb_reset_stage is not None})
        saved_snapshot = snapshot
    except OSError as exc:
        fault("storage_errors", exc)


def service_once():
    global healthy_since_ms, reset_at_ms
    # Polling precedes incoming requests, so new activity can cancel an upload.
    service_shelly()
    http_server.step()
    service_bulb_alert()
    persist_runtime()
    if healthy():
        if healthy_since_ms is None:
            healthy_since_ms = time.ticks_ms()
    else:
        healthy_since_ms = None
    if not ctx.trial and not ctx.confirmed and confirmation_allowed():
        ctx.confirm()
    if reset_at_ms is not None and due(reset_at_ms):
        # Staging was safe at its last check. Avoid rebooting into an update if
        # activity appears in the brief response-drain window.
        if safe_idle():
            machine.reset()
        ctx.cancel_stage()
        reset_at_ms = None
        fault("http_errors", "Staged reboot cancelled: washer no longer safely idle")


def run(context):
    global ctx, config, wifi, http_server, led, uptime_ms
    ctx = context
    config = read_json("pico_config.json", {})
    if (not isinstance(config, dict) or not config.get("WIFI_SSID") or not config.get("WIFI_PASSWORD")
            or len(config.get("UPDATE_TOKEN", "")) < 32 or config.get("DEVICE_TYPE") != DEVICE_TYPE
            or not isinstance(config.get("DEVICE_ID"), str) or not config["DEVICE_ID"].startswith("washer-")):
        raise ValueError("Missing washer identity, Wi-Fi settings or secure update token")
    load_runtime()
    led = Pin("LED", Pin.OUT)
    http_server = Listener(LOCAL_HTTP_PORT)
    wifi = Wifi()
    next_wifi = next_gc = last_loop = time.ticks_ms()
    safe_debug("Washer " + VERSION + " slot " + ctx.slot + (" TRIAL" if ctx.trial else ""))
    while True:
        now = time.ticks_ms()
        delta = max(0, time.ticks_diff(now, last_loop))
        last_loop = now
        uptime_ms += delta
        diag["max_loop_ms"] = max(diag["max_loop_ms"], delta)
        if due(next_wifi, now):
            next_wifi = later(250)
            wifi.step()
        service_once()
        if due(next_gc):
            gc.collect()
            next_gc = later(30000)
        # Only after a complete service pass. AP/Shelly outages retry without
        # reboot loops; a genuinely stuck interpreter/driver stops feeding.
        ctx.feed()
        led.value(1 if wifi.ip else (time.ticks_ms() // 500) % 2)
        time.sleep_ms(2)
