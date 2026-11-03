"""
Sweep - Windows Update orchestration.

The Windows Update COM API is the only supported way to enumerate and install
Windows and driver updates. It requires elevation: a standard-user
``Search()`` returns *Access denied*, which Sweep reports rather than hiding.

Everything is previewed before it is applied. Nothing installs silently, nothing
is hidden from the list, and the result code of each install is surfaced so a
half-applied update is visible rather than assumed successful.
"""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass

from . import base

CREATE_NO_WINDOW = 0x08000000


@dataclass
class WinUpdate:
    title: str
    update_id: str
    kb: str = ""
    size_mb: float = 0.0
    severity: str = ""
    categories: str = ""
    is_driver: bool = False
    downloaded: bool = False
    reboot_required: bool = False

    @property
    def kind(self) -> str:
        return "driver" if self.is_driver else "windows"


def _ps(script: str, timeout: int = 900) -> tuple[int, str]:
    try:
        r = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
            capture_output=True, text=True, timeout=timeout,
            creationflags=CREATE_NO_WINDOW,
        )
        return r.returncode, (r.stdout or "") + (r.stderr or "")
    except (OSError, subprocess.SubprocessError) as exc:
        return 1, str(exc)


_SEARCH_PS = r"""
$ErrorActionPreference = 'Stop'
try {
  $session  = New-Object -ComObject Microsoft.Update.Session
  $searcher = $session.CreateUpdateSearcher()
  $result   = $searcher.Search("IsInstalled=0 and IsHidden=0")
  $items = @()
  foreach ($u in $result.Updates) {
    $items += [pscustomobject]@{
      Title          = $u.Title
      UpdateID       = $u.Identity.UpdateID
      KB             = ($u.KBArticleIDs -join ',')
      SizeMB         = [math]::Round($u.MaxDownloadSize / 1MB, 1)
      Severity       = "$($u.MsrSeverity)"
      Categories     = (($u.Categories | ForEach-Object { $_.Name }) -join '; ')
      IsDriver       = ("$($u.Type)" -match '2')
      Downloaded     = [bool]$u.IsDownloaded
      RebootRequired = [bool]$u.RebootRequired
    }
  }
  ConvertTo-Json -InputObject @($items) -Compress -Depth 4
} catch {
  Write-Output ("ERR:" + $_.Exception.Message)
}
"""


def _explain(msg: str) -> str:
    low = msg.lower()
    if "access" in low and "denied" in low:
        return ("Windows Update refused access. This needs administrator rights - "
                "run 'sweep update --elevate' or start Sweep as admin.")
    if "0x8024402c" in low or "0x8024002e" in low:
        return "Windows Update service is disabled or unreachable: " + msg
    return msg


def search(timeout: int = 900) -> tuple[list[WinUpdate], str]:
    """List pending Windows and driver updates. Returns (updates, error)."""
    rc, out = _ps(_SEARCH_PS, timeout=timeout)
    text = out.strip()
    if not text:
        return [], "no response from Windows Update"
    if text.startswith("ERR:"):
        return [], _explain(text[4:].strip())
    # PowerShell may emit warnings before the JSON payload
    brace = text.find("[")
    if brace > 0:
        text = text[brace:]
    elif brace < 0:
        brace = text.find("{")
        if brace > 0:
            text = text[brace:]
    try:
        blob = json.loads(text)
    except ValueError:
        return [], "could not parse the Windows Update response"
    if isinstance(blob, dict):
        blob = [blob]
    items: list[WinUpdate] = []
    for raw in blob or []:
        if not isinstance(raw, dict):
            continue
        title = str(raw.get("Title") or "").strip()
        uid = str(raw.get("UpdateID") or "").strip()
        if not title or not uid:
            continue
        try:
            size = float(raw.get("SizeMB") or 0)
        except (TypeError, ValueError):
            size = 0.0
        items.append(WinUpdate(
            title=title,
            update_id=uid,
            kb=str(raw.get("KB") or ""),
            size_mb=size,
            severity=str(raw.get("Severity") or ""),
            categories=str(raw.get("Categories") or ""),
            is_driver=bool(raw.get("IsDriver")),
            downloaded=bool(raw.get("Downloaded")),
            reboot_required=bool(raw.get("RebootRequired")),
        ))
    items.sort(key=lambda u: (u.is_driver, u.title.lower()))
    return items, ""


_INSTALL_PS = r"""
$ErrorActionPreference = 'Stop'
$ids = @({IDS})
try {
  $session  = New-Object -ComObject Microsoft.Update.Session
  $searcher = $session.CreateUpdateSearcher()
  $result   = $searcher.Search("IsInstalled=0 and IsHidden=0")
  $chosen = New-Object -ComObject Microsoft.Update.UpdateColl
  $found = @()
  foreach ($u in $result.Updates) {
    if ($ids -contains $u.Identity.UpdateID) {
      if (-not $u.EulaAccepted) { $u.AcceptEula() }
      $chosen.Add($u) | Out-Null
      $found += $u.Title
    }
  }
  if ($chosen.Count -eq 0) { Write-Output "NOTFOUND"; exit 1 }

  $dl = $session.CreateUpdateDownloader()
  $dl.Updates = $chosen
  $dlResult = $dl.Download()

  $inst = $session.CreateUpdateInstaller()
  $inst.Updates = $chosen
  $res = $inst.Install()

  $lines = @()
  for ($i = 0; $i -lt $chosen.Count; $i++) {
    $code = $res.GetUpdateResult($i).ResultCode
    $lines += "$code|$($chosen.Item($i).Title)"
  }
  Write-Output ("OK:" + ($lines -join "`n"))
  Write-Output ("REBOOT:" + [bool]$res.RebootRequired)
} catch {
  Write-Output ("ERR:" + $_.Exception.Message)
}
"""

#: IInstallationResult result codes.
_RESULT_TEXT = {
    0: "not started",
    1: "in progress",
    2: "succeeded",
    3: "succeeded with errors",
    4: "failed",
    5: "aborted",
}


@dataclass
class InstallOutcome:
    title: str
    code: int
    ok: bool

    @property
    def text(self) -> str:
        return _RESULT_TEXT.get(self.code, f"code {self.code}")


def install(update_ids: list[str], timeout: int = 3600) -> tuple[bool, str, list[InstallOutcome], bool]:
    """Download and install the selected updates.

    Returns (ok, message, per-update outcomes, reboot_required).
    """
    if not update_ids:
        return False, "no updates selected", [], False
    ids = ",".join("'" + i.replace("'", "") + "'" for i in update_ids)
    rc, out = _ps(_INSTALL_PS.replace("{IDS}", ids), timeout=timeout)
    text = out.strip()
    if not text:
        return False, "no response from Windows Update", [], False
    if "ERR:" in text:
        return False, _explain(text.split("ERR:", 1)[1].strip()), [], False
    if text.startswith("NOTFOUND"):
        return False, "the selected updates are no longer offered", [], False

    outcomes: list[InstallOutcome] = []
    reboot = False
    payload = text.split("OK:", 1)[1] if "OK:" in text else ""
    for line in payload.splitlines():
        line = line.strip()
        if not line or line.startswith("REBOOT:"):
            continue
        if "|" not in line:
            continue
        code_txt, title = line.split("|", 1)
        try:
            code = int(code_txt)
        except ValueError:
            continue
        outcomes.append(InstallOutcome(title=title, code=code, ok=code in (2, 3)))
    if "REBOOT:True" in text:
        reboot = True

    ok = bool(outcomes) and all(o.ok for o in outcomes)
    succeeded = sum(1 for o in outcomes if o.ok)
    msg = f"{succeeded}/{len(outcomes)} installed" if outcomes else "no per-update result"
    if reboot:
        msg += " - a restart is required to finish"
    return ok, msg, outcomes, reboot
