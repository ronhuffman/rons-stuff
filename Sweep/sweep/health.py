"""
Sweep - laptop health.

A cleaner reclaims space. This module tries to answer the question that actually
matters for a laptop: *is anything degrading?*

Design constraint, learned the hard way: much of Windows' own health surface
needs elevation or a working WMI/CIM stack. Every check here therefore has a
path that works for a standard user, and reports ``unknown`` honestly when it
cannot read something rather than inventing a green tick.

Checks that need administrator are labelled in their advice, not hidden.
"""

from __future__ import annotations

import ctypes
import ctypes.wintypes as wintypes
import json
import os
import re
import subprocess
import time
import winreg
from dataclasses import dataclass, field

from . import base

CREATE_NO_WINDOW = 0x08000000

OK, WARN, BAD, UNKNOWN = "ok", "warn", "bad", "unknown"

_RANK = {OK: 0, UNKNOWN: 1, WARN: 2, BAD: 3}


@dataclass
class Check:
    key: str
    title: str
    status: str
    value: str = ""
    advice: str = ""
    weight: int = 1
    detail: list[str] = field(default_factory=list)


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------

def _run(cmd: list[str], timeout: int = 60) -> tuple[int, str]:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                           creationflags=CREATE_NO_WINDOW)
        return r.returncode, (r.stdout or "") + (r.stderr or "")
    except (OSError, subprocess.SubprocessError) as exc:
        return 1, str(exc)


def _ps(script: str, timeout: int = 120) -> tuple[int, str]:
    return _run(["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
                timeout=timeout)


def _reg(hive: int, path: str, name: str):
    try:
        with winreg.OpenKey(hive, path, 0, winreg.KEY_READ) as k:
            return winreg.QueryValueEx(k, name)[0]
    except OSError:
        return None


HKLM = winreg.HKEY_LOCAL_MACHINE
HKCU = winreg.HKEY_CURRENT_USER


# --------------------------------------------------------------------------
# individual checks
# --------------------------------------------------------------------------

def check_uptime() -> Check:
    try:
        k32 = ctypes.windll.kernel32
        k32.GetTickCount64.restype = ctypes.c_ulonglong
        ms = k32.GetTickCount64()
    except Exception:
        return Check("uptime", "Uptime", UNKNOWN, "unavailable")
    hours = ms / 3_600_000.0
    days = hours / 24.0
    if days >= 14:
        return Check("uptime", "Uptime", WARN, f"{days:.1f} days",
                     "Long uptimes hide pending-update reboots and slowly leak "
                     "memory. Restart when convenient.", weight=2)
    if days >= 7:
        return Check("uptime", "Uptime", WARN, f"{days:.1f} days",
                     "Consider restarting to let updates finish.")
    return Check("uptime", "Uptime", OK, f"{days:.1f} days")


def check_pending_reboot() -> Check:
    markers = []
    if _reg(HKLM, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing",
            "RebootPending") is not None:
        markers.append("servicing")
    if _reg(HKLM, r"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update",
            "RebootRequired") is not None:
        markers.append("Windows Update")
    if _reg(HKLM, r"SYSTEM\CurrentControlSet\Control\Session Manager",
            "PendingFileRenameOperations"):
        markers.append("file-rename")
    if markers:
        return Check("reboot", "Pending reboot", BAD, ", ".join(markers),
                     "A reboot is queued and being deferred. Until it happens, "
                     "updates are half-applied.", weight=2)
    return Check("reboot", "Pending reboot", OK, "none")


def check_disk_space() -> Check:
    drives = []
    for letter in "CDEFGH":
        root = f"{letter}:\\"
        if os.path.exists(root):
            try:
                total, used, free = __import__("shutil").disk_usage(root)
            except OSError:
                continue
            if total == 0:
                continue
            pct = free / total * 100.0
            drives.append((letter, free, pct))
    if not drives:
        return Check("disk", "Free space", UNKNOWN, "no fixed drives found")

    worst = min(drives, key=lambda d: d[2])
    letter, free, pct = worst
    detail = [f"{d[0]}: {base.human(d[1])} free ({d[2]:.0f}%)" for d in drives]
    if pct < 8:
        return Check("disk", "Free space", BAD, f"{letter}: {pct:.0f}%",
                     "Below 8% free: Windows Update and the page file start "
                     "failing, and SSDs write-amplify badly. Free space now.",
                     weight=2, detail=detail)
    if pct < 15:
        return Check("disk", "Free space", WARN, f"{letter}: {pct:.0f}%",
                     "Under 15% free. Aim for at least 15-20% on a system drive.",
                     detail=detail)
    return Check("disk", "Free space", OK, f"{letter}: {pct:.0f}%", detail=detail)


def check_trim() -> Check:
    rc, out = _run(["fsutil", "behavior", "query", "DisableDeleteNotify"])
    if rc != 0:
        return Check("trim", "TRIM enabled", UNKNOWN, "fsutil unavailable")
    m = re.search(r"NTFS DisableDeleteNotify\s*=\s*(\d)", out)
    if not m:
        return Check("trim", "TRIM enabled", UNKNOWN, "could not parse")
    if m.group(1) == "0":
        return Check("trim", "TRIM enabled", OK, "yes",
                     "TRIM is what keeps SSD write performance from decaying.")
    return Check("trim", "TRIM enabled", BAD, "disabled",
                 "TRIM is off. On an SSD this accelerates wear and slows writes. "
                 "Re-enable with: fsutil behavior set DisableDeleteNotify 0",
                 weight=2)


def check_battery() -> Check:
    class POWER_STATUS(ctypes.Structure):
        _fields_ = [
            ("ACLineStatus", wintypes.BYTE),
            ("BatteryFlag", wintypes.BYTE),
            ("BatteryLifePercent", wintypes.BYTE),
            ("Reserved1", wintypes.BYTE),
            ("BatteryLifeTime", wintypes.DWORD),
            ("BatteryFullLifeTime", wintypes.DWORD),
        ]

    try:
        ps = POWER_STATUS()
        if not ctypes.windll.kernel32.GetSystemPowerStatus(ctypes.byref(ps)):
            raise OSError("GetSystemPowerStatus failed")
    except Exception:
        return Check("battery", "Battery", UNKNOWN, "unavailable")

    if ps.BatteryFlag == 128:
        return Check("battery", "Battery", UNKNOWN, "no battery (desktop)")
    on_ac = ps.ACLineStatus == 1
    pct = ps.BatteryLifePercent
    pct_txt = "unknown" if pct == 255 else f"{pct:.0f}%"
    value = f"{pct_txt} ({'AC' if on_ac else 'on battery'})"

    advice = ("Battery wear (design capacity vs current full charge) needs one "
              "elevated run: powercfg /batteryreport")
    if pct != 255 and pct <= 15 and not on_ac:
        return Check("battery", "Battery", WARN, value,
                     "Running very low. Plug in to avoid a deep discharge. " + advice)
    return Check("battery", "Battery", OK, value, advice)


def check_power_scheme() -> Check:
    rc, out = _run(["powercfg", "/getactivescheme"])
    if rc != 0:
        return Check("power", "Power plan", UNKNOWN, "unavailable")
    m = re.search(r"\(([^)]+)\)", out)
    name = m.group(1) if m else "unknown"
    low = name.lower()
    if "power saver" in low:
        return Check("power", "Power plan", WARN, name,
                     "Power saver caps performance. Use Balanced unless you need "
                     "the runtime.")
    if any(k in low for k in ("turbo", "performance", "ultimate", "high")):
        return Check("power", "Power plan", WARN, name,
                     "A maximum-performance plan raises heat and fan noise and "
                     "shortens battery life on a laptop. Balanced is the "
                     "healthier default for daily use.")
    return Check("power", "Power plan", OK, name)


def check_fast_startup() -> Check:
    hib = _reg(HKLM, r"SYSTEM\CurrentControlSet\Control\Power", "HibernateEnabled")
    fast = _reg(HKLM,
                r"SYSTEM\CurrentControlSet\Control\Session Manager\Power",
                "HiberbootEnabled")
    parts = []
    if hib is not None:
        parts.append(f"hibernation={'on' if hib else 'off'}")
    if fast is not None:
        parts.append(f"fast startup={'on' if fast else 'off'}")
    if not parts:
        return Check("power.sleep", "Sleep/hibernate config", UNKNOWN, "unavailable")
    value = ", ".join(parts)
    advice = ""
    if fast:
        advice = ("Fast startup makes 'shutdown' a partial hibernate. If you see "
                  "odd driver or update behaviour, a full restart "
                  "(shutdown /s /full) clears it.")
    return Check("power.sleep", "Sleep/hibernate config", OK, value, advice)


def check_secure_boot() -> Check:
    val = _reg(HKLM, r"SYSTEM\CurrentControlSet\Control\SecureBoot\State",
               "UEFISecureBootEnabled")
    if val is None:
        return Check("secureboot", "Secure Boot", UNKNOWN,
                     "not exposed (legacy BIOS or no UEFI state key)")
    if val:
        return Check("secureboot", "Secure Boot", OK, "enabled")
    return Check("secureboot", "Secure Boot", WARN, "disabled",
                 "Secure Boot blocks bootkits. Re-enable it in firmware settings "
                 "unless you dual-boot something that requires it.", weight=2)


def check_defender() -> Check:
    """Defender's own status is served by WMI, which is often unavailable to a
    standard user. Fall back to the policy registry keys, and say unknown rather
    than guessing."""
    disabled = _reg(HKLM, r"SOFTWARE\Microsoft\Windows Defender", "DisableAntiSpyware")
    if disabled == 1:
        return Check("defender", "Defender", BAD, "disabled by policy",
                     "Real-time protection is switched off by policy.", weight=3)

    rc, out = _ps("(Get-MpComputerStatus).RealTimeProtectionEnabled", timeout=60)
    text = out.strip().lower()
    if "true" in text:
        return Check("defender", "Defender", OK, "real-time on")
    if "false" in text:
        return Check("defender", "Defender", BAD, "real-time off",
                     "Real-time protection is disabled.", weight=3)
    return Check("defender", "Defender", UNKNOWN,
                 "status needs elevation (Get-MpComputerStatus)")


_EVENT_PS = r"""
$ErrorActionPreference = 'SilentlyContinue'
$since = (Get-Date).AddDays(-__DAYS__)
$ids = @(41, 6008, 1001, 7, 51, 153, 55)
$out = @()
foreach ($id in $ids) {
  $ev = Get-WinEvent -FilterHashtable @{LogName='System'; Id=$id; StartTime=$since} -MaxEvents 60
  foreach ($e in $ev) {
    $out += [pscustomobject]@{
      Id       = $id
      Time     = $e.TimeCreated.ToString('yyyy-MM-dd HH:mm')
      Provider = $e.ProviderName
      Message  = (($e.Message -split "`r?`n")[0])
    }
  }
}
ConvertTo-Json -InputObject @($out) -Compress -Depth 3
"""

_SHUTDOWN_IDS = {41, 6008, 1001}
_DISK_IDS = {7, 51, 153, 55}


def _parse_time(text: str):
    try:
        return time.strptime(str(text), "%Y-%m-%d %H:%M")
    except (ValueError, TypeError):
        return None


def _distinct_incidents(events: list[dict], ids: set[int],
                        window_min: int = 10) -> list[list[dict]]:
    """Group events into incidents.

    Windows records one unexpected shutdown in several places: Kernel-Power 41,
    EventLog 6008 and often BugCheck 1001 all fire within seconds of each other.
    Counting rows would triple the apparent problem, so events closer together
    than *window_min* are treated as one incident.
    """
    rows = [e for e in events if int(e.get("Id", 0)) in ids]
    rows.sort(key=lambda e: str(e.get("Time")))

    incidents: list[list[dict]] = []
    last_stamp = None
    for e in rows:
        stamp = _parse_time(e.get("Time"))
        same = False
        if last_stamp is not None and stamp is not None:
            gap = abs(time.mktime(stamp) - time.mktime(last_stamp))
            same = gap <= window_min * 60
        if same and incidents:
            incidents[-1].append(e)
        else:
            incidents.append([e])
        if stamp is not None:
            last_stamp = stamp
    return incidents


def check_reliability(events: list[dict], days: int = 30) -> Check:
    if events is None:
        return Check("reliability", f"Stability ({days}d)", UNKNOWN,
                     "event log unavailable")

    incidents = _distinct_incidents(events, _SHUTDOWN_IDS)
    disk_rows = [e for e in events if int(e.get("Id", 0)) in _DISK_IDS]

    detail = []
    for inc in sorted(incidents, key=lambda g: str(g[0].get("Time")), reverse=True)[:5]:
        ids = sorted({int(e.get("Id", 0)) for e in inc})
        detail.append(f"unexpected shutdown {inc[0].get('Time')} (id {ids})")
    for e in sorted(disk_rows, key=lambda x: str(x.get("Time")), reverse=True)[:5]:
        detail.append(f"storage warning id={e.get('Id')} {e.get('Time')}")

    n = len(incidents)
    if n >= 3:
        return Check("reliability", f"Stability ({days}d)", BAD,
                     f"{n} unexpected shutdown(s)",
                     "Repeated unexpected shutdowns usually mean power delivery, "
                     "overheating, or a driver crash. Check for a minidump in "
                     r"%WINDIR%\Minidump.", weight=2, detail=detail)
    if n:
        return Check("reliability", f"Stability ({days}d)", WARN,
                     f"{n} unexpected shutdown(s)",
                     "One or two can be a battery pull, a hard reset, or a crash "
                     "during sleep.", detail=detail)
    if disk_rows:
        return Check("reliability", f"Stability ({days}d)", WARN,
                     f"{len(disk_rows)} storage warning(s)",
                     "Storage retries or paging errors can precede a failing "
                     "drive. Back up, then check the drive's SMART status.",
                     weight=2, detail=detail)
    return Check("reliability", f"Stability ({days}d)", OK, "no critical events",
                 detail=detail)


def fetch_events(days: int = 30) -> list[dict]:
    rc, out = _ps(_EVENT_PS.replace("__DAYS__", str(int(days))), timeout=180)
    text = out.strip()
    if not text or text.lower().startswith("convertto-json"):
        return []
    try:
        blob = json.loads(text)
    except ValueError:
        return []
    if isinstance(blob, dict):
        blob = [blob]
    return [e for e in (blob or []) if isinstance(e, dict)]


def check_startup_load() -> Check:
    count = 0
    for hive, path in ((HKCU, r"Software\Microsoft\Windows\CurrentVersion\Run"),
                       (HKLM, r"Software\Microsoft\Windows\CurrentVersion\Run"),
                       (HKLM, r"Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run")):
        try:
            with winreg.OpenKey(hive, path, 0, winreg.KEY_READ) as k:
                i = 0
                while True:
                    try:
                        winreg.EnumValue(k, i)
                        count += 1
                        i += 1
                    except OSError:
                        break
        except OSError:
            continue
    if count >= 15:
        return Check("startup", "Startup programs", WARN, f"{count} entries",
                     "A heavy startup set slows every login. Review them on the "
                     "Startup page, or with 'sweep startup'.")
    return Check("startup", "Startup programs", OK, f"{count} entries")


def check_sweep_state() -> Check:
    """Is Sweep itself configured to help on a schedule?"""
    from . import schedule
    try:
        st = schedule.status()
    except Exception:
        return Check("watchdog", "Automatic cleaning", UNKNOWN, "unavailable")
    if getattr(st, "error", ""):
        # unreadable is not the same as "not scheduled"
        return Check("watchdog", "Automatic cleaning", UNKNOWN,
                     "Task Scheduler could not be read", detail=[st.error[:200]])
    if st.installed:
        return Check("watchdog", "Automatic cleaning", OK,
                     f"scheduled, next {st.next_run or 'unknown'}")
    return Check("watchdog", "Automatic cleaning", WARN, "not scheduled",
                 "A weekly clean keeps caches from ballooning. Turn it on from "
                 "the Automatic cleaning page, or with 'sweep schedule'.")


# --------------------------------------------------------------------------
# run / score / history
# --------------------------------------------------------------------------

def run_checks(days: int = 30, include_events: bool = True) -> list[Check]:
    events = fetch_events(days) if include_events else None
    checks = [
        check_disk_space(),
        check_uptime(),
        check_pending_reboot(),
        check_battery(),
        check_trim(),
        check_reliability(events, days),
        check_power_scheme(),
        check_fast_startup(),
        check_secure_boot(),
        check_defender(),
        check_startup_load(),
        check_sweep_state(),
    ]
    return checks


def score(checks: list[Check]) -> int:
    total = 100
    for c in checks:
        if c.status == BAD:
            total -= 12 * c.weight
        elif c.status == WARN:
            total -= 5 * c.weight
    return max(0, min(100, total))


def verdict(score_value: int) -> str:
    if score_value >= 90:
        return "healthy"
    if score_value >= 75:
        return "needs attention"
    if score_value >= 55:
        return "degraded"
    return "act now"


def history_path() -> str:
    return os.path.join(base.state_dir(), "health-history.jsonl")


def save_snapshot(checks: list[Check], path: str | None = None) -> str:
    p = path or history_path()
    os.makedirs(os.path.dirname(p) or ".", exist_ok=True)
    rec = {
        "ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "score": score(checks),
        "statuses": {c.key: c.status for c in checks},
        "values": {c.key: c.value for c in checks},
    }
    with open(p, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(rec) + "\n")
    return p


def load_history(path: str | None = None) -> list[dict]:
    p = path or history_path()
    out = []
    try:
        with open(p, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    out.append(json.loads(line))
                except ValueError:
                    continue
    except OSError:
        pass
    return out


def to_dict(checks: list[Check]) -> dict:
    return {
        "score": score(checks),
        "verdict": verdict(score(checks)),
        "generated": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "admin": base.is_admin(),
        "checks": [
            {"key": c.key, "title": c.title, "status": c.status,
             "value": c.value, "advice": c.advice, "detail": c.detail}
            for c in checks
        ],
    }
