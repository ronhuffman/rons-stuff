"""Independent original washer decision reference, no hardware/network or credentials."""
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

def safe_debug(message):
    pass

def start_bulb_alert(reason):
    global bulb_alert_active
    bulb_alert_active = True
    return True

def reset_bulb_to_white_then_off(reason):
    global bulb_alert_active, bulb_reset_stage
    bulb_alert_active = False
    bulb_reset_stage = "WHITE"
