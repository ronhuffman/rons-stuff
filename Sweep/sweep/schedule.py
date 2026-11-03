"""
Sweep - scheduled cleaning.

Registers one Windows Task Scheduler job that runs Sweep's clean non-interactively.
Uses the Schedule.Service COM API through PowerShell, so it does not depend on
``schtasks.exe`` being on PATH (it is absent or blocked on some systems).

The task runs ``pythonw.exe -m sweep clean --apply --quiet`` so no console window
ever appears. Removing the task is a single call and leaves no residue.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from dataclasses import dataclass

CREATE_NO_WINDOW = 0x08000000
TASK_NAME = "Sweep - Automatic Clean"

TRIGGERS = {
    "daily": 2,      # TASK_TRIGGER_DAILY
    "weekly": 3,     # TASK_TRIGGER_WEEKLY
    "logon": 9,      # TASK_TRIGGER_LOGON
    "idle": 6,       # TASK_TRIGGER_IDLE
}


@dataclass
class ScheduleState:
    installed: bool = False
    enabled: bool = False
    next_run: str = ""
    last_run: str = ""
    last_result: str = ""
    command: str = ""
    error: str = ""


def _run_ps(script: str, timeout: int = 120) -> tuple[int, str]:
    try:
        r = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
            capture_output=True, text=True, timeout=timeout,
            creationflags=CREATE_NO_WINDOW,
        )
        return r.returncode, (r.stdout or "") + (r.stderr or "")
    except (OSError, subprocess.SubprocessError) as exc:
        return 1, str(exc)


def _launcher() -> tuple[str, str, str]:
    """(executable, arguments, working directory) for the scheduled run."""
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if getattr(sys, "frozen", False):
        exe = sys.executable
        args = "clean --apply --quiet"
        work = os.path.dirname(exe)
    else:
        exe = sys.executable
        # prefer pythonw so no console flashes
        pyw = os.path.join(os.path.dirname(exe), "pythonw.exe")
        if os.path.isfile(pyw):
            exe = pyw
        args = "-m sweep clean --apply --quiet"
        work = here
    return exe, args, work


_CREATE_PS = r"""
$ErrorActionPreference = 'Stop'
try {
  $svc = New-Object -ComObject Schedule.Service
  $svc.Connect()
  $folder = $svc.GetFolder('\')
  $def = $svc.NewTask(0)
  $def.RegistrationInfo.Description = 'Sweep automatic cleaning'
  $def.Settings.Enabled = $true
  $def.Settings.StartWhenAvailable = $true
  $def.Settings.DisallowStartIfOnBatteries = $false
  $def.Settings.StopIfGoingOnBatteries = $false
  $def.Settings.ExecutionTimeLimit = 'PT1H'
  $def.Settings.MultipleInstances = 2
  $act = $def.Actions.Create(0)
  $act.Path = '__EXE__'
  $act.Arguments = '__ARGS__'
  $act.WorkingDirectory = '__WORK__'
  __TRIGGER__
  $null = $folder.RegisterTaskDefinition('__NAME__', $def, 6, $null, $null, 3)
  Write-Output 'OK'
} catch {
  Write-Output ('ERR:' + $_.Exception.Message)
}
"""

_TRIGGER_DAILY = """
  $t = $def.Triggers.Create(2)
  $t.StartBoundary = '__WHEN__'
  $t.DaysInterval = 1
"""

_TRIGGER_WEEKLY = """
  $t = $def.Triggers.Create(3)
  $t.StartBoundary = '__WHEN__'
  $t.DaysOfWeek = __DAYS__
  $t.WeeksInterval = 1
"""

_TRIGGER_LOGON = """
  $t = $def.Triggers.Create(9)
  $t.Delay = 'PT5M'
"""

_TRIGGER_IDLE = """
  $t = $def.Triggers.Create(6)
  $t.IdleDuration = 'PT10M'
  $t.WaitTimeout = 'PT1H'
"""


def create(frequency: str = "weekly", time_of_day: str = "12:00",
           weekdays: str = "MON,WED,FRI") -> tuple[bool, str]:
    """Register the scheduled clean. frequency: daily|weekly|logon|idle."""
    freq = frequency.lower()
    if freq not in TRIGGERS:
        return False, f"unknown frequency {frequency!r}"

    exe, args, work = _launcher()
    when = f"{_today()}T{time_of_day}:00"
    if freq == "daily":
        trigger = _TRIGGER_DAILY.replace("__WHEN__", when)
    elif freq == "weekly":
        trigger = _TRIGGER_WEEKLY.replace("__WHEN__", when).replace(
            "__DAYS__", _weekday_mask(weekdays))
    elif freq == "logon":
        trigger = _TRIGGER_LOGON
    else:
        trigger = _TRIGGER_IDLE

    script = (_CREATE_PS
              .replace("__EXE__", _esc(exe))
              .replace("__ARGS__", _esc(args))
              .replace("__WORK__", _esc(work))
              .replace("__NAME__", _esc(TASK_NAME))
              .replace("__TRIGGER__", trigger))
    rc, out = _run_ps(script)
    if "OK" in out:
        return True, f"scheduled: {freq} at {time_of_day}" if freq in ("daily", "weekly") else f"scheduled: {freq}"
    msg = out.strip()
    if msg.startswith("ERR:"):
        msg = msg[4:].strip()
    return False, msg or f"Task Scheduler returned {rc}"


def _esc(s: str) -> str:
    return s.replace("'", "''")


def _today() -> str:
    import datetime
    return datetime.date.today().isoformat()


def _weekday_mask(days: str) -> str:
    bits = {"SUN": 1, "MON": 2, "TUE": 4, "WED": 8, "THU": 16, "FRI": 32, "SAT": 64}
    mask = 0
    for part in days.replace(" ", "").split(","):
        mask |= bits.get(part.upper()[:3], 0)
    return str(mask or 62)      # Mon-Fri default


_REMOVE_PS = r"""
$ErrorActionPreference = 'Stop'
try {
  $svc = New-Object -ComObject Schedule.Service
  $svc.Connect()
  $folder = $svc.GetFolder('\')
  $folder.DeleteTask('__NAME__', 0)
  Write-Output 'OK'
} catch {
  Write-Output ('ERR:' + $_.Exception.Message)
}
"""


def remove() -> tuple[bool, str]:
    rc, out = _run_ps(_REMOVE_PS.replace("__NAME__", _esc(TASK_NAME)))
    if "OK" in out:
        return True, "scheduled task removed"
    msg = out.strip()
    if msg.startswith("ERR:"):
        return False, msg[4:].strip()
    return False, msg or "could not remove task"


_STATUS_PS = r"""
$ErrorActionPreference = 'Stop'
try {
  $svc = New-Object -ComObject Schedule.Service
  $svc.Connect()
  $folder = $svc.GetFolder('\')
  $t = $folder.GetTask('__NAME__')
  $d = [pscustomobject]@{
    Name      = $t.Name
    Enabled   = $t.Enabled
    State     = $t.State
    NextRun   = "$($t.NextRunTime)"
    LastRun   = "$($t.LastRunTime)"
    LastCode  = "$($t.LastTaskResult)"
  }
  ConvertTo-Json -InputObject $d -Compress
} catch {
  Write-Output ('MISSING')
}
"""


def status() -> ScheduleState:
    rc, out = _run_ps(_STATUS_PS.replace("__NAME__", _esc(TASK_NAME)))
    text = out.strip()
    if text.startswith("MISSING"):
        return ScheduleState(installed=False)
    if not text:
        # no answer at all means the query failed, not that nothing is scheduled
        return ScheduleState(installed=False,
                             error=f"no response from Task Scheduler (exit code {rc})")
    try:
        blob = json.loads(text.splitlines()[-1])
    except (ValueError, IndexError):
        return ScheduleState(installed=False, error=text[:200])
    return ScheduleState(
        installed=True,
        enabled=bool(blob.get("Enabled")),
        next_run=str(blob.get("NextRun") or ""),
        last_run=str(blob.get("LastRun") or ""),
        last_result=str(blob.get("LastCode") or ""),
        command=str(blob.get("Name") or ""),
    )
