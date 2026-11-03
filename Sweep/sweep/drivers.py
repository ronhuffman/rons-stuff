"""
Sweep - driver inventory and updates.

Sweep does not ship a driver catalogue and does not download drivers from a
vendor-unknown mirror. Driver updates come from **Windows Update**, which is
where Microsoft publishes signed, hardware-ID-matched driver packages. That is
slower to appear than a commercial driver service, but it is signed, matched to
your hardware, and reversible through Windows' own rollback.

Inventory uses ``driverquery``, updates use the Windows Update COM API through
PowerShell (no pywin32 dependency).
"""

from __future__ import annotations

import csv
import io
import json
import subprocess
import winreg
from dataclasses import dataclass

CREATE_NO_WINDOW = 0x08000000


@dataclass
class Driver:
    module_name: str
    display_name: str
    driver_type: str
    start_mode: str
    state: str
    path: str = ""
    date: str = ""


@dataclass
class DriverUpdate:
    title: str
    update_id: str
    driver_class: str = ""
    manufacturer: str = ""
    model: str = ""
    version_date: str = ""


def friendly_name(display: str, module: str, image: str = "") -> str:
    """Driver DisplayName is often an indirect resource reference such as
    ``@%SystemRoot%\\system32\\drivers\\afd.sys,-1000``. Showing that raw is
    useless, so fall back to the service key (the canonical driver name) or the
    image file name."""
    text = (display or "").strip()
    if text and not text.startswith("@"):
        return text
    if module:
        return module
    base = os.path.basename((image or "").strip('"').strip())
    return base or text or "(unknown)"


def _run_ps(script: str, timeout: int = 300) -> tuple[int, str]:
    try:
        r = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
            capture_output=True, text=True, timeout=timeout,
            creationflags=CREATE_NO_WINDOW,
        )
        return r.returncode, (r.stdout or "") + (r.stderr or "")
    except (OSError, subprocess.SubprocessError) as exc:
        return 1, str(exc)


START_MODES = {0: "Boot", 1: "System", 2: "Automatic", 3: "Manual", 4: "Disabled"}


#: ``driverquery`` reports "Kernel" / "User" / "File System", while the registry
#: path reports "Kernel Driver" / "File System Driver". Normalise to the longer
#: form so the UI reads the same whichever path produced the row.
_DRIVERQUERY_TYPES = {
    "kernel": "Kernel Driver",
    "file system": "File System Driver",
    "user": "User Mode Driver",
}


def normalize_type(value: str) -> str:
    """Unify the driver-type vocabulary across both inventory paths."""
    text = (value or "").strip()
    return _DRIVERQUERY_TYPES.get(text.lower(), text)


def _inventory_registry() -> list[Driver]:
    """Enumerate kernel drivers from the Services registry hive.

    ``driverquery`` is unavailable or broken on some builds ("version mismatch"),
    so this is the reliable path: every kernel driver registers here with a Type
    bit, a Start mode and an ImagePath.
    """
    out: list[Driver] = []
    root = r"SYSTEM\CurrentControlSet\Services"
    try:
        hive = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, root)
    except OSError:
        return out
    i = 0
    while True:
        try:
            name = winreg.EnumKey(hive, i)
        except OSError:
            break
        i += 1
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, f"{root}\\{name}") as sk:
                def q(n, default=None):
                    try:
                        return winreg.QueryValueEx(sk, n)[0]
                    except OSError:
                        return default
                typ = int(q("Type", 0) or 0)
                if not (typ & 1):                 # 1 = kernel driver
                    continue
                start = q("Start", None)
                image = str(q("ImagePath", "") or "")
                out.append(Driver(
                    module_name=name,
                    display_name=friendly_name(str(q("DisplayName", "") or ""),
                                               name, image),
                    driver_type="File System Driver" if typ & 2 else "Kernel Driver",
                    start_mode=START_MODES.get(int(start), "") if start is not None else "",
                    state="",
                    path=image,
                    date="",
                ))
        except OSError:
            continue
    out.sort(key=lambda d: d.display_name.lower())
    return out


def inventory() -> list[Driver]:
    """Installed kernel drivers, preferring driverquery and falling back to the
    registry when it is unavailable or errors out."""
    drivers = _inventory_driverquery()
    if drivers:
        return drivers
    return _inventory_registry()


def _inventory_driverquery() -> list[Driver]:
    try:
        r = subprocess.run(["driverquery", "/FO", "CSV", "/V"],
                           capture_output=True, text=True, timeout=120,
                           creationflags=CREATE_NO_WINDOW)
        if r.returncode != 0:
            r = subprocess.run(["driverquery", "/FO", "CSV"],
                               capture_output=True, text=True, timeout=120,
                               creationflags=CREATE_NO_WINDOW)
    except (OSError, subprocess.SubprocessError):
        return []

    text = r.stdout or ""
    if not text.strip():
        return []
    out: list[Driver] = []
    try:
        reader = csv.DictReader(io.StringIO(text))
        for row in reader:
            low = {k.strip().lower(): (v or "").strip() for k, v in row.items() if k}
            out.append(Driver(
                module_name=low.get("module name", ""),
                display_name=low.get("display name", ""),
                driver_type=normalize_type(low.get("driver type", "")),
                start_mode=low.get("start mode", ""),
                state=low.get("state", ""),
                path=low.get("path", ""),
                date=low.get("date", ""),
            ))
    except (csv.Error, UnicodeError):
        return []
    return [d for d in out if d.module_name]


_UPDATES_PS = r"""
$ErrorActionPreference = 'Stop'
try {
  $session  = New-Object -ComObject Microsoft.Update.Session
  $searcher = $session.CreateUpdateSearcher()
  $result   = $searcher.Search("IsInstalled=0 and Type='Driver'")
  $items = @()
  foreach ($u in $result.Updates) {
    $items += [pscustomobject]@{
      Title        = $u.Title
      UpdateID     = $u.Identity.UpdateID
      DriverClass  = "$($u.DriverClass)"
      Manufacturer = "$($u.DriverManufacturer)"
      Model        = "$($u.DriverModel)"
      VersionDate  = "$($u.DriverVerDate)"
    }
  }
  ConvertTo-Json -InputObject @($items) -Compress -Depth 4
} catch {
  Write-Output ("ERR:" + $_.Exception.Message)
}
"""


def search_updates(timeout: int = 300) -> tuple[list[DriverUpdate], str]:
    """Ask Windows Update for driver-class updates. Returns (updates, error)."""
    rc, out = _run_ps(_UPDATES_PS, timeout=timeout)
    text = out.strip()
    if not text:
        return [], "no response from Windows Update"
    if text.startswith("ERR:"):
        msg = text[4:].strip()
        if "access" in msg.lower() or "denied" in msg.lower():
            return [], "Windows Update refused access - run Sweep as administrator"
        return [], msg
    try:
        blob = json.loads(text)
    except ValueError:
        return [], "could not parse Windows Update response"
    if isinstance(blob, dict):
        blob = [blob]
    updates = []
    for item in blob or []:
        if not isinstance(item, dict):
            continue
        title = str(item.get("Title") or "").strip()
        uid = str(item.get("UpdateID") or "").strip()
        if not title or not uid:
            continue
        updates.append(DriverUpdate(
            title=title,
            update_id=uid,
            driver_class=str(item.get("DriverClass") or ""),
            manufacturer=str(item.get("Manufacturer") or ""),
            model=str(item.get("Model") or ""),
            version_date=str(item.get("VersionDate") or ""),
        ))
    return updates, ""


_INSTALL_PS = r"""
$ErrorActionPreference = 'Stop'
$ids = @({IDS})
try {
  $session  = New-Object -ComObject Microsoft.Update.Session
  $searcher = $session.CreateUpdateSearcher()
  $result   = $searcher.Search("IsInstalled=0 and Type='Driver'")
  $chosen = New-Object -ComObject Microsoft.Update.UpdateColl
  foreach ($u in $result.Updates) {
    if ($ids -contains $u.Identity.UpdateID) {
      if (-not $u.EulaAccepted) { $u.AcceptEula() }
      $chosen.Add($u) | Out-Null
    }
  }
  if ($chosen.Count -eq 0) { Write-Output "NOTFOUND"; exit 1 }
  $dl = $session.CreateUpdateDownloader(); $dl.Updates = $chosen; $dl.Download() | Out-Null
  $inst = $session.CreateUpdateInstaller(); $inst.Updates = $chosen
  $res = $inst.Install()
  Write-Output ("RESULT:" + $res.ResultCode)
} catch {
  Write-Output ("ERR:" + $_.Exception.Message)
}
"""


def install_updates(update_ids: list[str], timeout: int = 3600) -> tuple[bool, str]:
    if not update_ids:
        return False, "no updates selected"
    ids = ",".join("'" + i.replace("'", "") + "'" for i in update_ids)
    rc, out = _run_ps(_INSTALL_PS.replace("{IDS}", ids), timeout=timeout)
    text = out.strip()
    if "RESULT:2" in text:
        return True, "installed successfully"
    if "RESULT:" in text:
        code = text.split("RESULT:")[-1].strip().split()[0]
        return False, f"install returned result code {code} (see Windows Update history)"
    if text.startswith("NOTFOUND"):
        return False, "the selected updates are no longer offered"
    if text.startswith("ERR:"):
        return False, text[4:].strip()
    return False, text.splitlines()[-1] if text else "no output"
