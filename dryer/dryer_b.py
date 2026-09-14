"""Dryer Monitor 5.0.0 - MicroPython Pico 2 W, cooperative networking + A/B OTA.
Generated using unchanged V4.1 thresholds, civil calculations and dryer decisions.
Install with the supplied main.py launcher and private pico_config.json.
"""
import machine
from machine import Pin, I2C
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
import struct
from main import read_json, write_json

VERSION = "5.0.0"
BUILD = "2026-09-13-network-ota-public-example"
BOOT_API = 1
# PUBLIC EXAMPLES: set your bulb address/entity and actual latitude/longitude.
# Zero coordinates are placeholders, not the installation location.
BULB_IP = "192.0.2.30"
BULB_LIGHT_ENTITY = "Laundry%20Indicator"
PORT = 5000
HA_HTTP_PORT = 80
LOCATION_LATITUDE = 0.0
LOCATION_LONGITUDE = 0.0
NTP_RESYNC_SECONDS = 6 * 60 * 60
NTP_RETRY_SECONDS = 15 * 60
START_RMS_THRESHOLD = 500.0
START_CONFIRM_SECONDS = 30.0
STOP_RMS_THRESHOLD = 250.0
STOP_CONFIRM_SECONDS = 90.0
RMS_WINDOW_SECONDS = 1.0
LIGHT_ON_THRESHOLD = 3.0
LIGHT_OFF_THRESHOLD = 1.5
LIGHT_ALERT_SECONDS = 10 * 60
CIVIL_TWILIGHT_ZENITH_DEGREES = 96.0
BULB_HTTP_TIMEOUT_SECONDS = 3
BULB_COLOR_SECONDS = 2.0
BULB_COLOR_SEQUENCE = (
    ("RED", "brightness=255&r=255&g=0&b=0&transition=0"),
    ("GREEN", "brightness=255&r=0&g=255&b=0&transition=0"),
    ("BLUE", "brightness=255&r=0&g=0&b=255&transition=0"),
    ("WHITE", "brightness=255&color_temp=357&transition=0"),
)
MPU6050 = 0x68
BH1750 = 0x23

SAMPLE_MS = 20
MAX_SAMPLE_GAP_MS = 200
MAX_UPLOAD = 120000
MAX_HEADERS = 4096
TRANSIENT = (11, 35, 10035, 115, 114, 119)
config = {}
ctx = None
i2c = None
led = None
diag = {"wifi_reconnects": 0, "listener_restarts": 0, "http_errors": 0,
        "bulb_errors": 0, "ntp_errors": 0, "sensor_errors": 0,
        "sample_gaps": 0, "max_loop_ms": 0, "last_fault": None}
twilight_cache_date = None
twilight_dawn_utc = None
twilight_dusk_utc = None
last_time_dark_state = None
base_x = base_y = base_z = 0.0
baseline_ready = False
rms_window_start_ms = time.ticks_ms()
rms_sum_squares = 0.0
rms_sample_count = 0
last_rms = 0.0
dryer_state = "WAITING"
start_candidate_ms = quiet_start_ms = None
light_state = "DAY"
light_timer_start_ms = None
light_alert_latched = False
last_dark_reason = None
bulb_alert_reasons = {}
bulb_alert_active = False
bulb_previous_uptime = None
bulb_off_pending = False
bulb_color_index = 0
bulb_generation = 0
bulb_job = None
bulb_job_kind = None
bulb_job_generation = 0
bulb_next_ms = time.ticks_ms()
bulb_failures = 0
last_accel_ms = last_lux_ok_ms = last_sample_ms = None
last_vibration = last_lux = None
accel_ok = lux_ok = False
idle_since_ms = None
uptime_ms = 0
http_server = monitor_server = wifi = ntp = None
saved_snapshot = None
last_persist_ms = None
reset_at_ms = None
upload_owner = None


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


def elapsed_seconds(start_ms, now_ms=None):
    if start_ms is None:
        return 0.0
    return time.ticks_diff(time.ticks_ms() if now_ms is None else now_ms, start_ms) / 1000.0


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


def signed16(value):
    if value > 32767:
        value -= 65536
    return value

def read_accel():
    data = i2c.readfrom_mem(MPU6050, 0x3B, 6)

    x = signed16((data[0] << 8) | data[1])
    y = signed16((data[2] << 8) | data[3])
    z = signed16((data[4] << 8) | data[5])

    return x, y, z

def read_lux():
    data = i2c.readfrom(BH1750, 2)
    return ((data[0] << 8) | data[1]) / 1.2

def clock_is_valid():
    """
    MicroPython may start with an old/default RTC date after a full power loss.
    We consider the clock usable only when the year is at least 2025.
    """
    try:
        return time.gmtime()[0] >= 2025
    except Exception:
        return False

def is_leap_year(year):
    return (
        (year % 4 == 0 and year % 100 != 0)
        or (year % 400 == 0)
    )

def day_of_year(year, month, day):
    month_days = (
        31,
        28 + (1 if is_leap_year(year) else 0),
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    )

    total = day
    for index in range(month - 1):
        total += month_days[index]

    return total

def normalize_degrees(value):
    while value < 0:
        value += 360.0
    while value >= 360.0:
        value -= 360.0
    return value

def normalize_hours(value):
    while value < 0:
        value += 24.0
    while value >= 24.0:
        value -= 24.0
    return value

def deg_to_rad(value):
    return value * math.pi / 180.0

def rad_to_deg(value):
    return value * 180.0 / math.pi

def solar_event_utc_hour(year, month, day, sunrise):
    """
    NOAA-style sunrise/sunset approximation.
    Uses civil twilight zenith = 96 degrees.
    Returns decimal UTC hour.
    """

    n = day_of_year(year, month, day)
    longitude_hour = LOCATION_LONGITUDE / 15.0

    if sunrise:
        t = n + ((6.0 - longitude_hour) / 24.0)
    else:
        t = n + ((18.0 - longitude_hour) / 24.0)

    mean_anomaly = (0.9856 * t) - 3.289

    true_longitude = (
        mean_anomaly
        + 1.916 * math.sin(deg_to_rad(mean_anomaly))
        + 0.020 * math.sin(deg_to_rad(2.0 * mean_anomaly))
        + 282.634
    )
    true_longitude = normalize_degrees(true_longitude)

    right_ascension = rad_to_deg(
        math.atan(
            0.91764 * math.tan(deg_to_rad(true_longitude))
        )
    )
    right_ascension = normalize_degrees(right_ascension)

    longitude_quadrant = math.floor(true_longitude / 90.0) * 90.0
    ra_quadrant = math.floor(right_ascension / 90.0) * 90.0

    right_ascension += longitude_quadrant - ra_quadrant
    right_ascension /= 15.0

    sin_declination = (
        0.39782 * math.sin(deg_to_rad(true_longitude))
    )
    cos_declination = math.cos(math.asin(sin_declination))

    cos_hour_angle = (
        math.cos(deg_to_rad(CIVIL_TWILIGHT_ZENITH_DEGREES))
        - (
            sin_declination
            * math.sin(deg_to_rad(LOCATION_LATITUDE))
        )
    ) / (
        cos_declination
        * math.cos(deg_to_rad(LOCATION_LATITUDE))
    )

    # Not expected at this latitude, but avoid acos domain errors.
    if cos_hour_angle > 1.0:
        cos_hour_angle = 1.0
    elif cos_hour_angle < -1.0:
        cos_hour_angle = -1.0

    if sunrise:
        hour_angle = 360.0 - rad_to_deg(math.acos(cos_hour_angle))
    else:
        hour_angle = rad_to_deg(math.acos(cos_hour_angle))

    hour_angle /= 15.0

    local_mean_time = (
        hour_angle
        + right_ascension
        - (0.06571 * t)
        - 6.622
    )

    utc_hour = local_mean_time - longitude_hour
    return normalize_hours(utc_hour)

def refresh_twilight_cache():
    global twilight_cache_date
    global twilight_dawn_utc
    global twilight_dusk_utc

    if not clock_is_valid():
        return False

    utc = time.gmtime()
    date_key = (utc[0], utc[1], utc[2])

    if date_key == twilight_cache_date:
        return True

    twilight_dawn_utc = solar_event_utc_hour(
        utc[0], utc[1], utc[2], True
    )
    twilight_dusk_utc = solar_event_utc_hour(
        utc[0], utc[1], utc[2], False
    )
    twilight_cache_date = date_key

    safe_debug(
        "Civil twilight UTC: dawn {:.2f}, dusk {:.2f}".format(
            twilight_dawn_utc,
            twilight_dusk_utc,
        )
    )

    return True

def civil_twilight_is_dark():
    global last_time_dark_state

    if not refresh_twilight_cache():
        return False

    utc = time.gmtime()
    now_hour = (
        utc[3]
        + utc[4] / 60.0
        + utc[5] / 3600.0
    )

    dawn = twilight_dawn_utc
    dusk = twilight_dusk_utc

    # Depending on season, the UTC night interval may or may not cross midnight.
    if dusk < dawn:
        dark = dusk <= now_hour < dawn
    else:
        dark = now_hour >= dusk or now_hour < dawn

    if dark != last_time_dark_state:
        last_time_dark_state = dark
        safe_debug(
            "Civil-twilight darkness gate: {}".format(
                "ON" if dark else "OFF"
            )
        )

    return dark

def darkness_monitoring_active():
    """
    Civil twilight is the ONLY day/night authority.

    If the UTC clock is invalid, fail safe: do not arm the utility-light
    alert, and report TIME_UNSYNCED to the laptop monitor.
    """
    if not clock_is_valid():
        return False, "TIME_UNSYNCED"

    if civil_twilight_is_dark():
        return True, "CIVIL_TWILIGHT"

    return False, "DAY"

def calculate_vibration(x, y, z):
    dx = x - base_x
    dy = y - base_y
    dz = z - base_z

    return math.sqrt(
        dx * dx
        + dy * dy
        + dz * dz
    )

def update_rms(vibration):
    global rms_window_start_ms
    global rms_sum_squares
    global rms_sample_count
    global last_rms

    rms_sum_squares += vibration * vibration
    rms_sample_count += 1

    now_ms = time.ticks_ms()

    if (
        elapsed_seconds(rms_window_start_ms, now_ms)
        < RMS_WINDOW_SECONDS
    ):
        return None

    if rms_sample_count > 0:
        last_rms = math.sqrt(
            rms_sum_squares / rms_sample_count
        )
    else:
        last_rms = 0.0

    rms_window_start_ms = now_ms
    rms_sum_squares = 0.0
    rms_sample_count = 0

    return last_rms

def process_dryer_rms(rms):
    global dryer_state
    global start_candidate_ms
    global quiet_start_ms

    now_ms = time.ticks_ms()

    # --------------------------------------------------------
    # WAITING
    # Real dryer must sustain high 1-second RMS.
    # Washer vibration in our test exceeded the threshold for
    # only about 7 seconds, not the required 30 seconds.
    # --------------------------------------------------------
    if dryer_state == "WAITING":
        if rms >= START_RMS_THRESHOLD:
            if start_candidate_ms is None:
                start_candidate_ms = now_ms
                safe_debug(
                    "Dryer start candidate: RMS {:.1f}".format(
                        rms
                    )
                )

            elif (
                elapsed_seconds(
                    start_candidate_ms,
                    now_ms,
                )
                >= START_CONFIRM_SECONDS
            ):
                dryer_state = "RUNNING"
                start_candidate_ms = None
                quiet_start_ms = None
                safe_debug(
                    "Dryer RUNNING detected "
                    "(RMS {:.1f})".format(rms)
                )

        else:
            if start_candidate_ms is not None:
                safe_debug(
                    "Dryer start candidate cancelled "
                    "(RMS {:.1f})".format(rms)
                )
            start_candidate_ms = None

    # --------------------------------------------------------
    # RUNNING
    # Completion has its OWN quiet timer.
    # It is never shared with startup logic.
    # --------------------------------------------------------
    elif dryer_state == "RUNNING":
        if rms <= STOP_RMS_THRESHOLD:
            if quiet_start_ms is None:
                quiet_start_ms = now_ms
                safe_debug(
                    "Dryer quiet candidate: RMS {:.1f}".format(
                        rms
                    )
                )

            elif (
                elapsed_seconds(
                    quiet_start_ms,
                    now_ms,
                )
                >= STOP_CONFIRM_SECONDS
            ):
                dryer_state = "COMPLETE"
                quiet_start_ms = None
                start_candidate_ms = None

                safe_debug(
                    "Dryer COMPLETE "
                    "(quiet {:.0f}s, RMS {:.1f})".format(
                        STOP_CONFIRM_SECONDS,
                        rms,
                    )
                )

                start_bulb_alert(
                    "dryer complete"
                )

        else:
            if quiet_start_ms is not None:
                safe_debug(
                    "Dryer quiet candidate cancelled "
                    "(RMS {:.1f})".format(rms)
                )
            quiet_start_ms = None

    # --------------------------------------------------------
    # COMPLETE
    # Ignore short Wrinkle Prevent tumbles.
    # A genuinely new cycle must again sustain START RMS for
    # the full START_CONFIRM_SECONDS.
    # --------------------------------------------------------
    elif dryer_state == "COMPLETE":
        if rms >= START_RMS_THRESHOLD:
            if start_candidate_ms is None:
                start_candidate_ms = now_ms
                safe_debug(
                    "Possible new dryer cycle: "
                    "RMS {:.1f}".format(rms)
                )

            elif (
                elapsed_seconds(
                    start_candidate_ms,
                    now_ms,
                )
                >= START_CONFIRM_SECONDS
            ):
                dryer_state = "RUNNING"
                start_candidate_ms = None
                quiet_start_ms = None

                safe_debug(
                    "New dryer cycle RUNNING "
                    "(RMS {:.1f})".format(rms)
                )

        else:
            start_candidate_ms = None


def invalidate_samples():
    global rms_window_start_ms, rms_sum_squares, rms_sample_count
    global start_candidate_ms, quiet_start_ms, idle_since_ms
    rms_window_start_ms = time.ticks_ms()
    rms_sum_squares = 0.0
    rms_sample_count = 0
    start_candidate_ms = quiet_start_ms = idle_since_ms = None


class Wifi:
    def __init__(self):
        self.wlan = network.WLAN(network.STA_IF)
        self.ip = None
        self.connecting = False
        self.next_ms = time.ticks_ms()
        self.started = None
        self.attempts = 0
        self.power_save_disabled = False
        self.wlan.active(True)
        try:
            self.wlan.config(pm=network.WLAN.PM_NONE)
            self.power_save_disabled = True
        except (AttributeError, ValueError, OSError):
            pass  # Do not assume an undocumented PM bitfield on older firmware.

    def step(self):
        now = time.ticks_ms()
        try:
            if self.wlan.isconnected():
                address = self.wlan.ifconfig()[0]
                if address != self.ip:
                    self.ip = address
                    diag["wifi_reconnects"] += 1
                    restart_listeners()
                self.connecting = False
                self.attempts = 0
                return
            if self.ip is not None:
                self.ip = None
                self.next_ms = now
                self.connecting = False
                restart_listeners()
                abort_bulb_job()
            if self.connecting:
                status = self.wlan.status()
                if status < 0 or elapsed_seconds(self.started, now) >= 20:
                    self.wlan.disconnect()
                    self.connecting = False
                    self.next_ms = later(min(60000, 2000 * (2 ** min(self.attempts, 5))))
                return
            if due(self.next_ms, now):
                self.attempts += 1
                if self.attempts % 3 == 0:
                    self.wlan.active(False)
                    self.next_ms = later(500)
                    return
                self.wlan.active(True)
                self.wlan.connect(config["WIFI_SSID"], config["WIFI_PASSWORD"])
                self.started = now
                self.connecting = True
        except OSError as exc:
            fault("wifi_errors", exc)
            self.connecting = False
            self.next_ms = later(5000)


class Fetch:
    """One bounded numeric-IP HTTP operation, progressed without deliberate waits."""
    def __init__(self, ip, method, path):
        if not numeric_ip(ip):
            raise ValueError("HTTP target must be a numeric IPv4 address")
        self.sock = None
        self.started = time.ticks_ms()
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
        if elapsed_seconds(self.started) >= BULB_HTTP_TIMEOUT_SECONDS:
            self.finish(error="HTTP deadline")
            return
        try:
            if self.sent < len(self.tx):
                if ready(self.sock, select.POLLOUT):
                    sent = self.sock.send(self.tx[self.sent:self.sent + 512])
                    if sent == 0:
                        raise OSError("HTTP write closed")
                    self.sent += sent
                return
            if not ready(self.sock, select.POLLIN):
                return
            chunk = self.sock.recv(1024)
            self.rx += chunk
            if len(self.rx) > 16384:
                raise ValueError("Bulb response too large")
            body = parse_response(self.rx, eof=not chunk)
            if body is not None:
                self.finish(body=body)
        except OSError as exc:
            if not temporary(exc):
                self.finish(error=str(exc))
        except (ValueError, IndexError) as exc:
            self.finish(error=str(exc))


def parse_response(data, eof=False):
    if b"\r\n\r\n" not in data:
        if eof:
            raise ValueError("Incomplete HTTP headers")
        return None
    head, body = data.split(b"\r\n\r\n", 1)
    lines = head.split(b"\r\n")
    code = int(lines[0].split()[1])
    if not 200 <= code < 300:
        raise ValueError("Bulb HTTP " + str(code))
    headers = {}
    for line in lines[1:]:
        key, value = line.split(b":", 1)
        headers[key.lower()] = value.strip().lower()
    if headers.get(b"transfer-encoding") == b"chunked":
        output = b""
        pos = 0
        while True:
            end = body.find(b"\r\n", pos)
            if end < 0:
                break
            size = int(body[pos:end].split(b";", 1)[0], 16)
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
            raise ValueError("Invalid bulb Content-Length")
        if len(body) >= length:
            return body[:length]
        if eof:
            raise ValueError("Truncated bulb body")
        return None
    return body if eof or code == 204 else None


def abort_bulb_job():
    global bulb_job
    if bulb_job is not None:
        bulb_job.finish(error="Wi-Fi disconnected")


def start_bulb_alert(reason):
    global bulb_alert_active, bulb_generation, bulb_next_ms, bulb_off_pending
    bulb_alert_reasons[reason] = True
    bulb_alert_active = True
    bulb_off_pending = False
    bulb_generation += 1
    bulb_next_ms = time.ticks_ms()


def stop_bulb_alert(reason, turn_off=True):
    global bulb_alert_active, bulb_off_pending, bulb_generation, bulb_next_ms
    bulb_alert_reasons.pop(reason, None)
    bulb_alert_active = bool(bulb_alert_reasons)
    bulb_generation += 1
    if not bulb_alert_active and turn_off:
        bulb_off_pending = True
        bulb_next_ms = time.ticks_ms()


def service_bulb_alert():
    global bulb_job, bulb_job_kind, bulb_job_generation, bulb_failures
    global bulb_previous_uptime, bulb_next_ms, bulb_color_index
    global bulb_alert_active, bulb_off_pending, bulb_generation
    if bulb_job is not None:
        bulb_job.step()
        if bulb_job.result is None:
            return
        body, error = bulb_job.result
        bulb_job = None
        if bulb_job_generation != bulb_generation:
            return  # Discard an old reply after a reason was added/removed.
        if not error and bulb_job_kind == "uptime":
            try:
                uptime = float(json.loads(body)["value"])
                if not math.isfinite(uptime) or uptime < 0:
                    raise ValueError("Invalid bulb uptime")
            except (ValueError, KeyError, TypeError):
                error = "Invalid bulb uptime response"
        if error:
            fault("bulb_errors", error)
            bulb_failures += 1
            bulb_next_ms = later(min(30000, 2000 * (2 ** min(bulb_failures, 4))))
            return  # A timeout is NOT evidence of a physical power cycle.
        bulb_failures = 0
        if bulb_job_kind == "off":
            bulb_off_pending = False
            bulb_previous_uptime = None
        elif bulb_job_kind == "uptime":
            if bulb_previous_uptime is not None and uptime + 2 < bulb_previous_uptime:
                bulb_alert_reasons.clear()
                bulb_alert_active = False
                bulb_off_pending = True
                bulb_generation += 1
                bulb_next_ms = time.ticks_ms()
            else:
                bulb_previous_uptime = uptime
                bulb_job_kind = "color"
                begin_bulb_job("color")
                return
        elif bulb_job_kind == "color":
            bulb_color_index = (bulb_color_index + 1) % len(BULB_COLOR_SEQUENCE)
            bulb_next_ms = later(int(BULB_COLOR_SECONDS * 1000))
    if wifi.ip is None or not due(bulb_next_ms):
        return
    if bulb_off_pending:
        begin_bulb_job("off")
    elif bulb_alert_active:
        begin_bulb_job("uptime")


def begin_bulb_job(kind):
    global bulb_job, bulb_job_kind, bulb_job_generation, bulb_next_ms
    try:
        path = "/light/" + BULB_LIGHT_ENTITY
        if kind == "uptime":
            path, method = "/sensor/Uptime", "GET"
        elif kind == "off":
            path, method = path + "/turn_off", "POST"
        else:
            path, method = path + "/turn_on?" + BULB_COLOR_SEQUENCE[bulb_color_index][1], "POST"
        bulb_job = Fetch(BULB_IP, method, path)
        bulb_job_kind = kind
        bulb_job_generation = bulb_generation
    except (OSError, ValueError) as exc:
        fault("bulb_errors", exc)
        bulb_next_ms = later(5000)


def process_light(lux):
    global light_state, light_timer_start_ms, light_alert_latched, last_dark_reason
    dark, reason = darkness_monitoring_active()
    last_dark_reason = reason
    # Physical OFF must clear its OWN reason even after dawn/time loss.
    if lux <= LIGHT_OFF_THRESHOLD:
        if light_alert_latched or "utility light left on" in bulb_alert_reasons:
            stop_bulb_alert("utility light left on", turn_off=True)
        light_alert_latched = False
        light_timer_start_ms = None
        light_state = "DARK" if dark else reason
        return
    if not dark:
        if not light_alert_latched:
            light_state = reason
        light_timer_start_ms = None
        return
    if light_alert_latched:
        light_state = "LIGHT_ALERT"
        return
    if lux >= LIGHT_ON_THRESHOLD and light_timer_start_ms is None:
        light_timer_start_ms = time.ticks_ms()
    if light_timer_start_ms is not None:
        light_state = "LIGHT_TIMER"
        if elapsed_seconds(light_timer_start_ms) >= LIGHT_ALERT_SECONDS:
            light_state = "LIGHT_ALERT"
            light_alert_latched = True
            start_bulb_alert("utility light left on")


class Ntp:
    def __init__(self):
        self.sock = None
        self.next_ms = time.ticks_ms()
        self.sent_ms = None
        self.last_sync_ms = None

    def step(self):
        global twilight_cache_date, light_timer_start_ms
        try:
            if self.sock is not None:
                if elapsed_seconds(self.sent_ms) >= 3 or wifi.ip is None:
                    raise OSError("NTP deadline or Wi-Fi lost")
                if not ready(self.sock, select.POLLIN):
                    return
                packet, address = self.sock.recvfrom(512)
                if (address[0] != config["NTP_SERVER_IP"] or address[1] != 123 or
                        len(packet) < 48 or packet[0] & 7 != 4 or packet[0] >> 6 == 3 or
                        not 1 <= packet[1] <= 15 or packet[24:32] != self.nonce):
                    return
                seconds = struct.unpack("!I", packet[40:44])[0]
                # NTP era rollover 2036. MicroPython ports use 1970 or 2000 epoch.
                if seconds < 2208988800:
                    seconds += 4294967296
                epoch = 3155673600 if time.gmtime(0)[0] == 2000 else 2208988800
                utc = time.gmtime(seconds - epoch)
                if not 2025 <= utc[0] <= 2100:
                    raise ValueError("NTP time outside supported range")
                machine.RTC().datetime((utc[0], utc[1], utc[2], utc[6], utc[3], utc[4], utc[5], 0))
                twilight_cache_date = None
                light_timer_start_ms = None  # Do not carry a darkness timer across a clock step.
                self.last_sync_ms = time.ticks_ms()
                self.next_ms = later(NTP_RESYNC_SECONDS * 1000)
                close_socket(self.sock)
                self.sock = None
            elif wifi.ip is not None and due(self.next_ms):
                ip = config["NTP_SERVER_IP"]
                if not numeric_ip(ip):
                    raise ValueError("NTP must use numeric IPv4 to avoid blocking DNS")
                self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                self.sock.settimeout(0)
                self.nonce = os.urandom(8)
                packet = bytearray(48)
                packet[0] = 0x23
                packet[40:48] = self.nonce
                self.sent_ms = time.ticks_ms()
                self.sock.sendto(packet, (ip, 123))
        except OSError as exc:
            if not temporary(exc):
                self.failed(exc)
        except ValueError as exc:
            self.failed(exc)

    def failed(self, exc):
        fault("ntp_errors", exc)
        close_socket(self.sock)
        self.sock = None
        self.next_ms = later(NTP_RETRY_SECONDS * 1000)


def status_dict():
    now = time.ticks_ms()
    timer = light_timer_start_ms is not None and light_state == "LIGHT_TIMER" and lux_ok
    timer_elapsed = elapsed_seconds(light_timer_start_ms, now) if timer else 0.0
    data = {"dryer_state": dryer_state, "dryer_running": dryer_state == "RUNNING",
            "dryer_complete": dryer_state == "COMPLETE", "vibration": last_vibration,
            "rms": last_rms if accel_ok and baseline_ready else None, "lux": last_lux,
            "light_state": light_state, "civil_dark": last_dark_reason == "CIVIL_TWILIGHT",
            "dark_reason": last_dark_reason or "UNKNOWN", "clock_valid": clock_is_valid(),
            "light_timer_active": timer, "light_timer_elapsed": round(timer_elapsed, 1),
            "light_timer_remaining": round(max(0, LIGHT_ALERT_SECONDS - timer_elapsed), 1) if timer else 0,
            "light_alert_active": light_alert_latched, "bulb_alert_active": bulb_alert_active,
            "version": VERSION, "build": BUILD, "uptime_seconds": uptime_ms // 1000,
            "reset_cause": machine.reset_cause(), "firmware": os.uname().release,
            "hardware": os.uname().machine, "memory_free": gc.mem_free(),
            "accel_ok": accel_ok, "lux_ok": lux_ok, "baseline_ready": baseline_ready,
            "sample_age_ms": time.ticks_diff(now, last_accel_ms) if last_accel_ms is not None else None,
            "lux_age_ms": time.ticks_diff(now, last_lux_ok_ms) if last_lux_ok_ms is not None else None,
            "alert_reasons": list(bulb_alert_reasons), "bulb_off_pending": bulb_off_pending,
            "wifi_connected": wifi.ip is not None, "ip": wifi.ip,
            "wifi_power_save_disabled": wifi.power_save_disabled,
            "ntp_age_seconds": elapsed_seconds(ntp.last_sync_ms) if ntp.last_sync_ms is not None else None,
            "slot": ctx.slot, "trial": ctx.trial, "boot_age_seconds": ctx.age_ms() // 1000,
            "running_sha256": ctx.sha256, "update_allowed": update_allowed(),
            "boot_api": BOOT_API, "last_crash": read_json("last_crash.json", None)}
    data.update(diag)
    try:
        data["wifi_rssi"] = wifi.wlan.status("rssi") if wifi.ip else None
    except (OSError, ValueError):
        data["wifi_rssi"] = None
    return data


def healthy():
    return (baseline_ready and accel_ok and lux_ok and wifi.ip is not None
            and http_server.sock is not None and last_accel_ms is not None
            and elapsed_seconds(last_accel_ms) < 0.5)


def update_allowed():
    return (ctx.confirmed and not ctx.trial and healthy() and dryer_state != "RUNNING"
            and start_candidate_ms is None and idle_since_ms is not None
            and elapsed_seconds(idle_since_ms) >= 30 and upload_owner is None
            and reset_at_ms is None and ctx.age_ms() >= 60000)


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


class HttpClient:
    def __init__(self, sock):
        self.sock = sock
        sock.settimeout(0)
        self.started = time.ticks_ms()
        self.rx = b""
        self.tx = b""
        self.sent = 0
        self.phase = "headers"
        self.file = None
        self.count = 0
        self.length = 0
        self.update = False
        self.deadline = 8000
        self.close_at = None

    def close(self):
        global upload_owner
        if self.file is not None:
            self.file.close()
            self.file = None
        if upload_owner is self:
            upload_owner = None
        close_socket(self.sock)
        self.sock = None

    def respond(self, code, body):
        if not isinstance(body, str):
            body = json.dumps(body)
        payload = body.encode()
        self.tx = ("HTTP/1.1 " + code + "\r\nContent-Type: application/json\r\n"
                   "Connection: close\r\nCache-Control: no-store\r\nContent-Length: " +
                   str(len(payload)) + "\r\n\r\n").encode() + payload
        self.sent = 0
        self.phase = "response"

    def route(self, head, remaining):
        global upload_owner
        lines = head.split(b"\r\n")
        first = lines[0].split()
        if len(first) != 3:
            raise ValueError("Invalid request line")
        method, path = first[0], first[1]
        if path.startswith(b"http://"):
            parts = path.split(b"/", 3)
            path = b"/" + parts[3] if len(parts) == 4 else b"/"
        path = path.split(b"?", 1)[0].rstrip(b"/") or b"/"
        headers = {}
        for line in lines[1:]:
            key, value = line.split(b":", 1)
            key = key.strip().lower()
            if key in headers:
                raise ValueError("Duplicate header")
            headers[key] = value.strip()
        if b"transfer-encoding" in headers:
            self.respond("400 Bad Request", {"error": "Use fixed Content-Length, not chunked upload"})
            return
        self.length = int(headers.get(b"content-length", b"0"))
        if self.length < 0:
            raise ValueError("Negative Content-Length")
        if method == b"GET" and path in (b"/", b"/status"):
            if self.length or remaining:
                raise ValueError("GET bodies/pipelining are not supported")
            self.respond("200 OK", status_dict())
            return
        if path not in (b"/update", b"/update/confirm"):
            self.respond("404 Not Found", {"error": "Not found"})
            return
        if not authorized(headers):
            self.respond("401 Unauthorized", {"error": "Update token required"})
            return
        if path == b"/update/confirm" and method == b"POST":
            if self.length or remaining:
                raise ValueError("Confirmation must have an empty body")
            if not healthy() or not ctx.confirm():
                self.respond("409 Conflict", {"error": "Need 60 seconds and healthy sensors/network"})
            else:
                self.respond("200 OK", {"confirmed": True, "slot": ctx.slot})
            return
        if path != b"/update" or method != b"PUT":
            self.respond("405 Method Not Allowed", {"error": "Use PUT /update"})
            return
        if not update_allowed():
            self.respond("409 Conflict", {"error": "Need confirmed firmware, healthy sensors and idle dryer for 30 seconds"})
            return
        if not 1000 <= self.length <= MAX_UPLOAD:
            self.respond("413 Content Too Large", {"error": "Application size outside allowed range"})
            return
        self.expected = headers.get(b"x-sha256", b"").decode().lower()
        if len(self.expected) != 64 or any(c not in "0123456789abcdef" for c in self.expected):
            raise ValueError("SHA-256 header required")
        self.slot = "b" if ctx.slot == "a" else "a"
        self.file = open("dryer_" + self.slot + ".upload", "wb")
        self.digest = hashlib.sha256()
        self.deadline = 60000
        self.phase = "upload"
        self.update = True
        upload_owner = self
        if headers.get(b"expect", b"").lower() == b"100-continue":
            self.tx = b"HTTP/1.1 100 Continue\r\n\r\n"
            self.sent = 0
        self.consume(remaining)

    def consume(self, chunk):
        global reset_at_ms, upload_owner
        if not accel_ok or dryer_state == "RUNNING" or start_candidate_ms is not None or idle_since_ms is None:
            raise ValueError("Dryer moved or accelerometer became unavailable; update cancelled")
        if self.count + len(chunk) > self.length:
            raise ValueError("Upload exceeds declared size")
        self.file.write(chunk)
        self.digest.update(chunk)
        self.count += len(chunk)
        if self.count != self.length:
            return
        self.file.close()
        self.file = None
        actual = binascii.hexlify(self.digest.digest()).decode()
        if actual != self.expected:
            raise ValueError("SHA-256 mismatch; current application untouched")
        if hasattr(os, "sync"):
            os.sync()
        os.rename("dryer_" + self.slot + ".upload", "dryer_" + self.slot + ".py")
        if hasattr(os, "sync"):
            os.sync()
        ctx.stage(self.slot)
        upload_owner = None
        # Let the complete success response leave before rebooting.
        reset_at_ms = later(2500)
        self.respond("202 Accepted", {"staged": self.slot, "sha256": actual,
                                      "confirmation_required": True})

    def step(self):
        if time.ticks_diff(time.ticks_ms(), self.started) > self.deadline:
            self.close()
            return
        try:
            if self.tx:
                if ready(self.sock, select.POLLOUT):
                    count = self.sock.send(self.tx[self.sent:self.sent + 1024])
                    if not count:
                        self.close()
                        return
                    self.sent += count
                if self.sent >= len(self.tx):
                    self.tx = b""
                    self.sent = 0
                    if self.phase == "response":
                        self.phase = "closing"
                        self.close_at = later(250)
                        # RP2 versions may not implement shutdown; complete headers
                        # have already been consumed, and close still queues FIN.
                        try:
                            self.sock.shutdown(1)
                        except (AttributeError, OSError):
                            pass
                return
            if self.phase == "closing":
                if due(self.close_at):
                    self.close()
                elif ready(self.sock, select.POLLIN):
                    if not self.sock.recv(1024):
                        self.close()
                return
            if not ready(self.sock, select.POLLIN):
                return
            chunk = self.sock.recv(1024)
            if not chunk:
                self.close()
                return
            if self.phase == "upload":
                self.consume(chunk)
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
        except (ValueError, IndexError, UnicodeError) as exc:
            fault("http_errors", exc)
            if self.file is not None:
                self.file.close()
                self.file = None
            global upload_owner
            if upload_owner is self:
                upload_owner = None
            self.respond("400 Bad Request", {"error": str(exc)})


class Listener:
    def __init__(self, port, monitor=False):
        self.port, self.monitor = port, monitor
        self.sock = None
        self.clients = []
        self.next_ms = time.ticks_ms()

    def close(self):
        for client in self.clients:
            client.close()
        self.clients = []
        close_socket(self.sock)
        self.sock = None

    def step(self, message=None):
        if wifi.ip is None:
            return
        if self.sock is None:
            if not due(self.next_ms):
                return
            try:
                self.sock = socket.socket()
                self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                self.sock.settimeout(0)
                self.sock.bind(("0.0.0.0", self.port))
                self.sock.listen(4)
                diag["listener_restarts"] += 1
            except OSError as exc:
                fault("http_errors", exc)
                self.close()
                self.next_ms = later(3000)
                return
        # At most one accept per pass, and at most four HTTP clients.
        if len(self.clients) < (1 if self.monitor else 4):
            try:
                sock, address = self.sock.accept()
                self.clients.append(MonitorClient(sock) if self.monitor else HttpClient(sock))
            except OSError as exc:
                if not temporary(exc):
                    fault("http_errors", exc)
                    self.close()
                    self.next_ms = later(1000)
                    return
        for client in self.clients[:]:
            if self.monitor:
                client.step(message)
            else:
                client.step()
            if client.sock is None:
                self.clients.remove(client)


class MonitorClient:
    def __init__(self, sock):
        self.sock = sock
        sock.settimeout(0)
        self.buffer = b""
        self.sent = 0
        self.started = time.ticks_ms()

    def close(self):
        close_socket(self.sock)
        self.sock = None

    def step(self, message):
        try:
            if not self.buffer and message is not None:
                self.buffer = (message + "\n").encode()
                self.sent = 0
                self.started = time.ticks_ms()
            if not self.buffer:
                return
            if elapsed_seconds(self.started) > 2:
                self.close()
                return
            if ready(self.sock, select.POLLOUT):
                count = self.sock.send(self.buffer[self.sent:])
                if not count:
                    self.close()
                    return
                self.sent += count
                if self.sent >= len(self.buffer):
                    self.buffer = b""
        except OSError as exc:
            if not temporary(exc):
                self.close()


def restart_listeners():
    for listener in (http_server, monitor_server):
        if listener is not None:
            listener.close()
            listener.next_ms = time.ticks_ms()


def load_runtime():
    global base_x, base_y, base_z, baseline_ready, dryer_state
    global bulb_alert_active, bulb_previous_uptime, light_alert_latched, bulb_off_pending
    baseline = read_json("baseline.json", {})
    try:
        values = baseline["xyz"]
        if baseline.get("format") != 1 or len(values) != 3:
            raise ValueError("Baseline format")
        if not all(math.isfinite(v) and abs(v) <= 32768 for v in values):
            raise ValueError("Baseline values")
        base_x, base_y, base_z = values
        baseline_ready = True
    except (ValueError, KeyError, TypeError):
        safe_debug("No valid saved baseline: keep BOTH appliances still for initial calibration")
    state = read_json("runtime_state.json", {})
    if not isinstance(state, dict):
        state = {}
    if baseline_ready and state.get("dryer_state") in ("WAITING", "RUNNING", "COMPLETE"):
        dryer_state = state["dryer_state"]
    for reason in state.get("reasons", []):
        if reason in ("dryer complete", "utility light left on"):
            bulb_alert_reasons[reason] = True
    bulb_alert_active = bool(bulb_alert_reasons)
    light_alert_latched = state.get("light_latched") is True
    bulb_off_pending = state.get("off_pending") is True and not bulb_alert_active
    value = state.get("bulb_uptime")
    if isinstance(value, (int, float)) and math.isfinite(value) and value >= 0:
        bulb_previous_uptime = value


def persist_runtime():
    global saved_snapshot, last_persist_ms
    snapshot = (dryer_state, tuple(sorted(bulb_alert_reasons)), light_alert_latched, bulb_off_pending)
    if snapshot == saved_snapshot:
        if last_persist_ms is not None and elapsed_seconds(last_persist_ms) >= 5:
            last_persist_ms = None
        return
    if last_persist_ms is not None and elapsed_seconds(last_persist_ms) < 5:
        return
    last_persist_ms = time.ticks_ms()
    try:
        write_json("runtime_state.json", {"dryer_state": dryer_state,
                   "reasons": list(snapshot[1]), "light_latched": light_alert_latched,
                   "off_pending": bulb_off_pending, "bulb_uptime": bulb_previous_uptime})
        saved_snapshot = snapshot
    except OSError as exc:
        fault("storage_errors", exc)


class Sensors:
    def __init__(self):
        self.accel_started = False
        self.lux_started = False
        self.accel_retry = self.lux_retry = time.ticks_ms()
        self.lux_due = time.ticks_ms()
        self.cal_sum = [0, 0, 0]
        self.cal_square = 0
        self.cal_count = 0

    def clear_calibration(self):
        self.cal_sum = [0, 0, 0]
        self.cal_square = 0
        self.cal_count = 0

    def sample(self):
        global i2c, last_accel_ms, last_sample_ms, last_vibration, accel_ok
        global base_x, base_y, base_z, baseline_ready, idle_since_ms
        global rms_window_start_ms, rms_sum_squares, rms_sample_count
        now = time.ticks_ms()
        if last_sample_ms is not None and time.ticks_diff(now, last_sample_ms) > MAX_SAMPLE_GAP_MS:
            diag["sample_gaps"] += 1
            invalidate_samples()
            self.clear_calibration()
        last_sample_ms = now
        if not self.accel_started and not due(self.accel_retry):
            return None
        try:
            if i2c is None:
                i2c = I2C(0, scl=Pin(1), sda=Pin(0), freq=400000, timeout=50000)
            if not self.accel_started:
                i2c.writeto_mem(MPU6050, 0x6B, b"\x00")
                i2c.writeto_mem(MPU6050, 0x1C, b"\x08")
                self.accel_started = True
                invalidate_samples()
                return None
            x, y, z = read_accel()
            accel_ok = True
            last_accel_ms = time.ticks_ms()
            if not baseline_ready:
                for index, value in enumerate((x, y, z)):
                    self.cal_sum[index] += value
                self.cal_square += x*x + y*y + z*z
                self.cal_count += 1
                if self.cal_count >= 100:
                    means = [v / self.cal_count for v in self.cal_sum]
                    noise = math.sqrt(max(0, self.cal_square / self.cal_count - sum(v*v for v in means)))
                    if noise <= STOP_RMS_THRESHOLD:
                        write_json("baseline.json", {"format": 1, "xyz": means})
                        base_x, base_y, base_z = means
                        baseline_ready = True
                        invalidate_samples()
                        safe_debug("Still baseline saved; future resets reuse it")
                    self.clear_calibration()
                return None
            vibration = calculate_vibration(x, y, z)
            last_vibration = round(vibration, 2)
            # Don't count sparse/invalid data as continuous threshold evidence.
            count = rms_sample_count + 1
            window_done = elapsed_seconds(rms_window_start_ms) >= RMS_WINDOW_SECONDS
            if window_done and count < 25:
                invalidate_samples()
                return None
            rms = update_rms(vibration)
            if rms is not None:
                process_dryer_rms(rms)
                if rms <= STOP_RMS_THRESHOLD and dryer_state != "RUNNING":
                    if idle_since_ms is None:
                        idle_since_ms = time.ticks_ms()
                    elif elapsed_seconds(idle_since_ms) >= 30:
                        idle_since_ms = time.ticks_add(time.ticks_ms(), -30000)
                else:
                    idle_since_ms = None
            # Block an upload immediately on significant motion, not 30s later.
            if vibration > START_RMS_THRESHOLD:
                idle_since_ms = None
            return "{},{},{},{},{:.2f},{:.2f},{},{}".format(
                time.time(), x, y, z, vibration,
                last_lux if last_lux is not None else float("nan"), dryer_state, light_state)
        except (OSError, ValueError) as exc:
            fault("sensor_errors", exc)
            accel_ok = False
            last_vibration = None
            self.accel_started = False
            self.accel_retry = later(5000)
            self.clear_calibration()
            invalidate_samples()
            return None

    def light(self):
        global lux_ok, last_lux, last_lux_ok_ms, light_state, light_timer_start_ms
        if i2c is None or not due(self.lux_due):
            return
        self.lux_due = later(1000)
        try:
            if not self.lux_started:
                if not due(self.lux_retry):
                    return
                i2c.writeto(BH1750, b"\x10")
                self.lux_started = True
                return  # Conversion completes before the next 1-second poll.
            value = read_lux()
            if not math.isfinite(value) or value < 0:
                raise ValueError("Invalid light sample")
            if last_lux_ok_ms is not None and elapsed_seconds(last_lux_ok_ms) > 2.5:
                light_timer_start_ms = None
            last_lux = round(value, 2)
            last_lux_ok_ms = time.ticks_ms()
            lux_ok = True
            process_light(value)
        except (OSError, ValueError) as exc:
            fault("sensor_errors", exc)
            lux_ok = False
            last_lux = None
            light_state = "SENSOR_ERROR"
            light_timer_start_ms = None
            self.lux_started = False
            self.lux_retry = later(5000)


def run(context):
    global ctx, config, wifi, ntp, http_server, monitor_server, led, uptime_ms
    ctx = context
    config = read_json("pico_config.json", {})
    if not config.get("WIFI_SSID") or not config.get("WIFI_PASSWORD") or len(config.get("UPDATE_TOKEN", "")) < 32:
        raise ValueError("Missing Wi-Fi settings or secure update token in pico_config.json")
    load_runtime()
    led = Pin("LED", Pin.OUT)
    http_server = Listener(HA_HTTP_PORT)
    monitor_server = Listener(PORT, monitor=True)
    wifi = Wifi()
    ntp = Ntp()
    sensors = Sensors()
    next_sample = next_gc = next_wifi = time.ticks_ms()
    last_loop = time.ticks_ms()
    safe_debug("Dryer " + VERSION + " slot " + ctx.slot + (" TRIAL" if ctx.trial else ""))
    while True:
        now = time.ticks_ms()
        delta = time.ticks_diff(now, last_loop)
        last_loop = now
        uptime_ms += max(0, delta)
        diag["max_loop_ms"] = max(diag["max_loop_ms"], delta)
        message = None
        if due(next_sample, now):
            next_sample = time.ticks_add(now, SAMPLE_MS)
            message = sensors.sample()
        sensors.light()
        if due(next_wifi, now):
            next_wifi = later(250)
            wifi.step()
        http_server.step()
        monitor_server.step(message)
        service_bulb_alert()
        ntp.step()
        persist_runtime()
        if not ctx.trial and healthy() and not ctx.confirmed and ctx.age_ms() >= 60000:
            ctx.confirm()
        if reset_at_ms is not None and due(reset_at_ms):
            machine.reset()
        if due(next_gc):
            gc.collect()
            next_gc = later(30000)
        # Feed after the whole service pass, not inside a timer/IRQ.
        # A disconnected AP or failed sensor is recoverable and does not itself
        # trigger reboot; a stuck interpreter/driver stops reaching this feed.
        ctx.feed()
        led.value(1 if wifi.ip else (time.ticks_ms() // 500) % 2)
        time.sleep_ms(2)
