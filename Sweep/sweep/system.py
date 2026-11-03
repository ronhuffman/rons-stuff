"""
Sweep - privileged system operations and startup management.

Everything here is reversible except the DISM component cleanup, which is
explicitly opt-in and labelled as permanent. Startup items are *moved* to a
quarantine store owned by Sweep, not deleted, so "disable" can always be undone
with "enable".
"""

from __future__ import annotations

import ctypes
import ctypes.wintypes as wintypes
import json
import os
import subprocess
import winreg
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from . import base

CREATE_NO_WINDOW = 0x08000000


def _run(args: list[str], timeout: int = 120) -> tuple[int, str]:
    try:
        p = subprocess.run(
            args, capture_output=True, text=True, timeout=timeout,
            creationflags=CREATE_NO_WINDOW if base.IS_WINDOWS else 0,
        )
        return p.returncode, (p.stdout or "") + (p.stderr or "")
    except FileNotFoundError:
        return 127, f"not found: {args[0]}"
    except subprocess.TimeoutExpired:
        return 124, f"timed out after {timeout}s"
    except OSError as exc:
        return 1, str(exc)


# --------------------------------------------------------------------------
# clean actions
# --------------------------------------------------------------------------

def empty_recycle_bin() -> str:
    ok = base.empty_recycle_bin()
    return "recycle bin emptied" if ok else "could not empty recycle bin"


def flush_dns() -> str:
    rc, out = _run(["ipconfig", "/flushdns"], timeout=30)
    return "DNS cache flushed" if rc == 0 else f"flushdns failed ({rc})"


def dism_component_cleanup() -> str:
    if not base.is_admin():
        return "needs administrator privileges - skipped"
    rc, out = _run(
        ["dism.exe", "/Online", "/Cleanup-Image", "/StartComponentCleanup"],
        timeout=3600,
    )
    if rc == 0:
        return "component store cleanup completed"
    return f"dism failed ({rc}): {out.strip().splitlines()[-1] if out.strip() else 'no output'}"


# --------------------------------------------------------------------------
# informational system facts
# --------------------------------------------------------------------------

def system_facts() -> dict:
    """Read-only snapshot of big-ticket system files/dirs. Reported, never
    modified - these are configuration, not junk."""
    facts: dict[str, object] = {}
    for name, path in (
        ("hiberfil.sys", os.path.join(os.environ.get("SystemDrive", "C:") + "\\", "hiberfil.sys")),
        ("pagefile.sys", os.path.join(os.environ.get("SystemDrive", "C:") + "\\", "pagefile.sys")),
        ("swapfile.sys", os.path.join(os.environ.get("SystemDrive", "C:") + "\\", "swapfile.sys")),
        ("MEMORY.DMP", os.path.join(os.environ.get("WINDIR", r"C:\Windows"), "MEMORY.DMP")),
    ):
        try:
            facts[name] = os.path.getsize(path)
        except OSError:
            facts[name] = None

    win_dir = os.environ.get("WINDIR", r"C:\Windows")
    facts["_hints"] = {
        "hibernation": "Disable with: powercfg /hibernate off  (frees hiberfil.sys; also disables Fast Startup)",
        "winsxs": "Component store size: dism /Online /Cleanup-Image /AnalyzeComponentStore",
        "restore": "Shadow storage: vssadmin list shadowstorage",
    }
    return facts


# --------------------------------------------------------------------------
# startup items
# --------------------------------------------------------------------------

@dataclass
class StartupItem:
    name: str
    command: str
    location: str          # human readable source
    kind: str              # "registry" | "folder" | "task" | "service"
    hive: str = ""         # for registry
    key: str = ""
    value: str = ""
    enabled: bool = True
    path: str = ""         # for folder items
    extra: dict = field(default_factory=dict)

    @property
    def key_id(self) -> str:
        return f"{self.kind}|{self.location}|{self.name}"


_RUN_LOCATIONS = [
    ("HKCU", r"Software\Microsoft\Windows\CurrentVersion\Run"),
    ("HKCU", r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
    ("HKLM", r"Software\Microsoft\Windows\CurrentVersion\Run"),
    ("HKLM", r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
    ("HKLM", r"Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run"),
]

_HIVES = {"HKCU": winreg.HKEY_CURRENT_USER, "HKLM": winreg.HKEY_LOCAL_MACHINE}

_STARTUP_FOLDERS = [
    ("User", os.path.join(os.environ.get("APPDATA", ""), r"Microsoft\Windows\Start Menu\Programs\Startup")),
    ("Common", os.path.join(os.environ.get("ProgramData", ""), r"Microsoft\Windows\Start Menu\Programs\Startup")),
]

QUARANTINE_DIR = os.path.join(
    base.state_dir(), "disabled-startup"
)
QUARANTINE_DB = os.path.join(QUARANTINE_DIR, "registry.json")

#: Set when the last schedule enumeration failed, so callers can surface it
#: instead of implying there are no scheduled tasks.
TASK_ERROR: str | None = None


def _load_quarantine() -> list[dict]:
    """Quarantined registry entries, for display. Unreadable reads as empty;
    anything that writes the store must use :func:`_read_quarantine`."""
    recs, _err = _read_quarantine()
    return recs


def _read_quarantine() -> tuple[list[dict], str]:
    """(records, error). A store that exists but cannot be read must not be
    saved over: it holds the only copy of every entry disabled so far."""
    try:
        with open(QUARANTINE_DB, encoding="utf-8") as fh:
            recs = json.load(fh)
    except FileNotFoundError:
        return [], ""
    except (OSError, ValueError) as exc:
        return [], str(exc)
    if not isinstance(recs, list):
        return [], "unexpected format"
    return recs, ""


def _save_quarantine(items: list[dict]) -> None:
    os.makedirs(QUARANTINE_DIR, exist_ok=True)
    tmp = QUARANTINE_DB + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(items, fh, indent=2)
    os.replace(tmp, QUARANTINE_DB)


def list_startup(include_tasks: bool = True, include_services: bool = False) -> list[StartupItem]:
    items: list[StartupItem] = []

    # registry Run keys
    for hive_name, key_path in _RUN_LOCATIONS:
        try:
            with winreg.OpenKey(_HIVES[hive_name], key_path) as key:
                i = 0
                while True:
                    try:
                        name, val, _typ = winreg.EnumValue(key, i)
                    except OSError:
                        break
                    i += 1
                    if not name:
                        continue
                    items.append(StartupItem(
                        name=name, command=str(val),
                        location=f"{hive_name}\\...\\{key_path.split('\\')[-1]}",
                        kind="registry", hive=hive_name, key=key_path, value=name,
                    ))
        except OSError:
            continue
        # values disabled by Sweep
        for rec in _load_quarantine():
            if rec.get("hive") == hive_name and rec.get("key") == key_path:
                items.append(StartupItem(
                    name=rec.get("name", "?"), command=rec.get("command", ""),
                    location=f"{hive_name}\\...\\{key_path.split('\\')[-1]}",
                    kind="registry", hive=hive_name, key=key_path,
                    value=rec.get("name", ""), enabled=False,
                ))

    # startup folders
    for label, folder in _STARTUP_FOLDERS:
        if not folder or not os.path.isdir(folder):
            continue
        try:
            for entry in os.scandir(folder):
                if entry.name.lower() == "desktop.ini":
                    continue
                if not entry.is_file(follow_symlinks=False):
                    continue
                items.append(StartupItem(
                    name=entry.name, command=entry.path,
                    location=f"{label} Startup folder", kind="folder", path=entry.path,
                ))
        except OSError:
            pass
    if os.path.isdir(QUARANTINE_DIR):
        try:
            for entry in os.scandir(QUARANTINE_DIR):
                if entry.is_file() and entry.name.lower().endswith((".lnk", ".url", ".exe", ".bat", ".cmd")):
                    items.append(StartupItem(
                        name=entry.name, command=entry.path,
                        location="Disabled by Sweep", kind="folder",
                        path=entry.path, enabled=False,
                        extra={"quarantined": True},
                    ))
        except OSError:
            pass

    if include_tasks:
        items.extend(_list_tasks())
    if include_services:
        items.extend(_list_services())
    return items


def _list_tasks() -> list[StartupItem]:
    global TASK_ERROR
    TASK_ERROR = None
    rc, out = _run(["schtasks", "/Query", "/FO", "CSV", "/NH"], timeout=60)
    if rc != 0:
        # Say so rather than reporting "no scheduled tasks exist".
        TASK_ERROR = ("scheduled tasks could not be listed "
                      f"(schtasks exit {rc}); they are not shown")
        return []
    import csv
    import io
    items: list[StartupItem] = []
    for row in csv.reader(io.StringIO(out)):
        if len(row) < 3:
            continue
        name, status = row[0], row[2] if len(row) > 2 else ""
        if not name or name.lower().startswith("taskname"):
            continue
        low = name.lower()
        # skip the OS's own plumbing - it is noise, not user startup
        if low.startswith("\\microsoft\\") or low.startswith("microsoft\\"):
            continue
        items.append(StartupItem(
            name=name, command="", location="Task Scheduler", kind="task",
            enabled=("disabled" not in status.lower()), extra={"status": status},
        ))
    return items


def _list_services() -> list[StartupItem]:
    """Non-Microsoft automatic services - the honest part of a 'startup
    optimizer'. Read-only here; toggling is offered separately."""
    items: list[StartupItem] = []
    key = r"SYSTEM\CurrentControlSet\Services"
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key) as root:
            i = 0
            while True:
                try:
                    name = winreg.EnumKey(root, i)
                except OSError:
                    break
                i += 1
                try:
                    with winreg.OpenKey(root, name) as sk:
                        try:
                            start, _ = winreg.QueryValueEx(sk, "Start")
                        except OSError:
                            continue
                        if start != 2:      # only auto-start
                            continue
                        try:
                            img, _ = winreg.QueryValueEx(sk, "ImagePath")
                            img = str(img)
                        except OSError:
                            img = ""
                        items.append(StartupItem(
                            name=name, command=img, location="Service (auto)",
                            kind="service", enabled=True,
                            extra={"start": start},
                        ))
                except OSError:
                    continue
    except OSError:
        pass
    return items


# ---- toggling ------------------------------------------------------------

def disable_startup(item: StartupItem) -> str:
    if item.kind == "registry":
        recs, err = _read_quarantine()
        if err:
            return f"failed: Sweep's record of disabled entries is unreadable ({err}); nothing changed"
        try:
            with winreg.OpenKey(_HIVES[item.hive], item.key, 0,
                                winreg.KEY_READ | winreg.KEY_WRITE) as key:
                try:
                    val, typ = winreg.QueryValueEx(key, item.value)
                except FileNotFoundError:
                    return "entry no longer present"
                # Record the entry before removing it: if the record cannot be
                # saved, the entry stays where it is.
                rec = {"hive": item.hive, "key": item.key, "name": item.value,
                       "command": val, "type": int(typ)}
                recs.append(rec)
                try:
                    _save_quarantine(recs)
                except (OSError, TypeError, ValueError) as exc:
                    return f"failed: could not record the entry ({exc}); nothing changed"
                try:
                    winreg.DeleteValue(key, item.value)
                except OSError as exc:
                    recs.remove(rec)
                    try:
                        _save_quarantine(recs)
                    except OSError:
                        pass
                    return f"failed: {exc}"
        except OSError as exc:
            return f"failed: {exc}"
        return "disabled (moved to Sweep quarantine)"

    if item.kind == "folder":
        if item.extra.get("quarantined"):
            return "already disabled"
        os.makedirs(QUARANTINE_DIR, exist_ok=True)
        dest = os.path.join(QUARANTINE_DIR, item.name)
        if os.path.lexists(dest):
            # Never overwrite an item that is already in quarantine.
            return f"failed: {item.name} is already in Sweep's quarantine"
        try:
            import shutil
            shutil.move(item.path, dest)
            return "disabled (moved to Sweep quarantine)"
        except OSError as exc:
            return f"failed: {exc}"

    if item.kind == "task":
        rc, out = _run(["schtasks", "/Change", "/TN", item.name, "/DISABLE"], timeout=60)
        return "disabled" if rc == 0 else f"failed ({rc}): {out.strip()[:120]}"

    if item.kind == "service":
        rc, out = _run(["sc", "config", item.name, "start=", "demand"], timeout=60)
        return "set to manual" if rc == 0 else f"failed ({rc}): {out.strip()[:120]} (needs admin)"

    return "unsupported"


def enable_startup(item: StartupItem) -> str:
    if item.kind == "registry":
        recs, err = _read_quarantine()
        if err:
            return f"failed: Sweep's record of disabled entries is unreadable ({err})"
        match = [r for r in recs if r.get("hive") == item.hive
                 and r.get("key") == item.key and r.get("name") == item.value]
        if not match:
            return "no backup found"
        rec = match[0]
        try:
            with winreg.OpenKey(_HIVES[item.hive], item.key, 0, winreg.KEY_WRITE) as key:
                winreg.SetValueEx(key, rec["name"], 0, rec.get("type", winreg.REG_SZ), rec.get("command", ""))
        except OSError as exc:
            return f"failed: {exc}"
        recs.remove(rec)
        _save_quarantine(recs)
        return "re-enabled"

    if item.kind == "folder":
        if not item.extra.get("quarantined"):
            return "already enabled"
        target_dir = _STARTUP_FOLDERS[0][1]
        try:
            import shutil
            os.makedirs(target_dir, exist_ok=True)
            shutil.move(item.path, os.path.join(target_dir, item.name))
            return "re-enabled (moved to user Startup folder)"
        except OSError as exc:
            return f"failed: {exc}"

    if item.kind == "task":
        rc, out = _run(["schtasks", "/Change", "/TN", item.name, "/ENABLE"], timeout=60)
        return "enabled" if rc == 0 else f"failed ({rc}): {out.strip()[:120]}"

    if item.kind == "service":
        rc, out = _run(["sc", "config", item.name, "start=", "auto"], timeout=60)
        return "set to automatic" if rc == 0 else f"failed ({rc}): {out.strip()[:120]} (needs admin)"

    return "unsupported"


# =========================================================================
# additional clean actions (used by both built-in and imported rules)
# =========================================================================

def clean_volumecache(name: str) -> str:
    """Drive one Windows VolumeCaches handler the way Disk Cleanup does.

    Only this handler's StateFlags0064 bit is set, then cleanmgr runs in
    "sagerun" mode. Any handler that was already flagged by the user keeps
    running - we never clear their selection.
    """
    if not base.is_admin():
        return "needs administrator - skipped"
    root_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches"
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, root_path, 0, winreg.KEY_READ) as root:
            names = []
            i = 0
            while True:
                try:
                    names.append(winreg.EnumKey(root, i))
                except OSError:
                    break
                i += 1
    except OSError:
        return "cannot read VolumeCaches"
    match = next((n for n in names if n.lower() == name.lower()), None)
    if match is None:
        return f"handler not present: {name}"
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                            f"{root_path}\\{match}", 0,
                            winreg.KEY_READ | winreg.KEY_WRITE) as hk:
            winreg.SetValueEx(hk, "StateFlags0064", 0, winreg.REG_DWORD, 2)
    except OSError as exc:
        return f"cannot flag {match}: {exc}"
    rc, out = _run(["cleanmgr.exe", "/sagerun:64"], timeout=3600)
    if rc == 0:
        return f"ran volume cache: {match}"
    tail = out.strip().splitlines()[-1] if out.strip() else ""
    return f"cleanmgr exit {rc} for {match} {tail}".strip()


def clear_clipboard() -> str:
    u = ctypes.windll.user32
    if u.OpenClipboard(None):
        try:
            u.EmptyClipboard()
            return "clipboard emptied"
        finally:
            u.CloseClipboard()
    return "clipboard is busy - skipped"


def clear_recent_docs() -> str:
    """SHAddToRecentDocs with a NULL payload clears the Recent list."""
    for flag in (1, 3):          # SHARD_PIDL, SHARD_PATHW
        try:
            ctypes.windll.shell32.SHAddToRecentDocs(flag, None)
            return "recent documents list cleared"
        except Exception:
            continue
    return "could not clear recent documents"


def clear_jump_lists() -> str:
    recent = os.path.join(os.environ.get("APPDATA", ""),
                          r"Microsoft\Windows\Recent")
    removed = 0
    for sub in ("AutomaticDestinations", "CustomDestinations"):
        folder = os.path.join(recent, sub)
        if not os.path.isdir(folder):
            continue
        for entry in os.scandir(folder):
            try:
                if entry.is_file(follow_symlinks=False):
                    os.unlink(entry.path)
                    removed += 1
            except OSError:
                continue
    return f"removed {removed} jump list file(s)"


def clear_event_logs() -> str:
    if not base.is_admin():
        return "needs administrator - skipped"
    rc, out = _run(["wevtutil", "el"], timeout=120)
    if rc != 0:
        return "could not enumerate event logs"
    logs = [ln.strip() for ln in out.splitlines() if ln.strip()]
    cleared = failed = 0
    for name in logs:
        rc2, _ = _run(["wevtutil", "cl", name], timeout=60)
        if rc2 == 0:
            cleared += 1
        else:
            failed += 1
    return f"cleared {cleared} event log(s)" + (f", {failed} failed" if failed else "")


def clean_environment_path() -> str:
    """Drop PATH entries that point at directories which no longer exist.

    The previous value is always saved first; this edits a configuration value,
    not a cache, so it must stay recoverable.
    """
    key = r"Environment"
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key, 0,
                            winreg.KEY_READ | winreg.KEY_WRITE) as hk:
            try:
                current, typ = winreg.QueryValueEx(hk, "Path")
            except OSError:
                return "no user PATH to clean"
            entries = [e for e in str(current).split(";") if e.strip()]
            keep, dropped = [], []
            for e in entries:
                probe = os.path.expandvars(e.strip())
                if "%" in probe or os.path.isdir(probe):
                    keep.append(e)
                else:
                    dropped.append(e)
            if not dropped:
                return "user PATH has no dead entries"
            backup_dir = os.path.join(
                base.state_dir(), "backups")
            try:
                os.makedirs(backup_dir, exist_ok=True)
                import json as _json
                import time as _time
                with open(os.path.join(backup_dir, "environment-path.json"), "w",
                          encoding="utf-8") as fh:
                    _json.dump({"saved": _time.strftime("%Y-%m-%dT%H:%M:%S"),
                                "path": str(current)}, fh, indent=2)
            except OSError:
                return "could not back up PATH - skipped"
            winreg.SetValueEx(hk, "Path", 0, typ, ";".join(keep))
            return f"removed {len(dropped)} dead PATH entr" + ("y" if len(dropped) == 1 else "ies")
    except OSError as exc:
        return f"could not edit PATH: {exc}"


def clear_office_mru(version: str = "16.0") -> str:
    """Remove the file/place MRU lists for one Office version."""
    root = rf"Software\Microsoft\Office\{version}"
    removed = 0
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, root, 0, winreg.KEY_READ) as h:
            apps = []
            i = 0
            while True:
                try:
                    apps.append(winreg.EnumKey(h, i))
                except OSError:
                    break
                i += 1
    except OSError:
        return f"Office {version} not present"
    for app in apps:
        for path in (rf"{root}\{app}\File MRU", rf"{root}\{app}\Place MRU"):
            try:
                with winreg.OpenKey(winreg.HKEY_CURRENT_USER, path, 0,
                                    winreg.KEY_READ | winreg.KEY_WRITE) as hk:
                    names = []
                    j = 0
                    while True:
                        try:
                            names.append(winreg.EnumValue(hk, j)[0])
                        except OSError:
                            break
                        j += 1
                    for n in names:
                        try:
                            winreg.DeleteValue(hk, n)
                            removed += 1
                        except OSError:
                            pass
            except OSError:
                continue
    return f"removed {removed} Office {version} MRU entr" + ("y" if removed == 1 else "ies")


def clear_last_visited() -> str:
    """Clear the common-dialog LastVisited MRU lists."""
    removed = 0
    base_key = r"Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32"
    for sub in ("LastVisitedPidlMRU", "LastVisitedPidlMRULegacy",
                "OpenSavePidlMRU", "CIDSizeMRU", "FirstFolder"):
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, f"{base_key}\\{sub}", 0,
                                winreg.KEY_READ | winreg.KEY_WRITE) as hk:
                names = []
                i = 0
                while True:
                    try:
                        names.append(winreg.EnumValue(hk, i)[0])
                    except OSError:
                        break
                    i += 1
                for n in names:
                    try:
                        winreg.DeleteValue(hk, n)
                        removed += 1
                    except OSError:
                        pass
        except OSError:
            continue
    return f"removed {removed} last-visited entr" + ("y" if removed == 1 else "ies")


# ---- credential store ---------------------------------------------------

class _CREDENTIALW(ctypes.Structure):
    _fields_ = [
        ("Flags", wintypes.DWORD),
        ("Type", wintypes.DWORD),
        ("TargetName", wintypes.LPWSTR),
        ("Comment", wintypes.LPWSTR),
        ("LastWritten", wintypes.FILETIME),
        ("CredentialBlobSize", wintypes.DWORD),
        ("CredentialBlob", ctypes.POINTER(ctypes.c_byte)),
        ("Persist", wintypes.DWORD),
        ("AttributeCount", wintypes.DWORD),
        ("Attributes", ctypes.c_void_p),
        ("TargetAlias", wintypes.LPWSTR),
        ("UserName", wintypes.LPWSTR),
    ]


def clear_credentials(types: tuple[int, ...] = (1, 2, 3)) -> str:
    """Delete stored credentials via the WinCred API.

    types: 1=generic, 2=domain password, 3=domain certificate. Persistent
    credentials only - session credentials are owned by the logon session.
    """
    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    count = ctypes.c_uint32(0)
    creds = ctypes.POINTER(ctypes.POINTER(_CREDENTIALW))()
    ok = advapi.CredEnumerateW(None, 0, ctypes.byref(count), ctypes.byref(creds))
    if not ok:
        return "no credential store access"
    targets = []
    try:
        for i in range(count.value):
            c = creds[i].contents
            if c.Type in types and c.Persist == 2:      # LOCAL_MACHINE persistence
                targets.append((c.TargetName, c.Type))
    finally:
        try:
            advapi.CredFree(creds)
        except Exception:
            pass
    removed = failed = 0
    for name, typ in targets:
        if not name:
            continue
        if advapi.CredDeleteW(name, typ, 0):
            removed += 1
        else:
            failed += 1
    return (f"removed {removed} stored credential(s)"
            + (f", {failed} failed" if failed else ""))


def clear_network_passwords() -> str:
    return clear_credentials(types=(2,))


def remove_empty_directories() -> str:
    return "handled per-rule; nothing global to do"


#: Registry of callable action names. `_run_action` only ever dispatches
#: through this table, never through arbitrary attribute lookup.
ACTIONS = {
    "empty_recycle_bin": empty_recycle_bin,
    "flush_dns": flush_dns,
    "dism_component_cleanup": dism_component_cleanup,
    "clear_clipboard": clear_clipboard,
    "clear_recent_docs": clear_recent_docs,
    "clear_jump_lists": clear_jump_lists,
    "clear_event_logs": clear_event_logs,
    "clean_environment_path": clean_environment_path,
    "clear_office_mru": clear_office_mru,
    "clear_last_visited": clear_last_visited,
    "clear_credentials": clear_credentials,
    "clear_network_passwords": clear_network_passwords,
    "remove_empty_directories": remove_empty_directories,
    "clean_volumecache": clean_volumecache,
}


def run_action(action: str) -> str:
    """Dispatch `name` or `name:arg` to an entry in ACTIONS."""
    name, _, arg = action.partition(":")
    fn = ACTIONS.get(name)
    if fn is None:
        return f"unsupported action {action!r}"
    return fn(arg) if arg and name in ("clear_office_mru", "clean_volumecache") else fn()


# =========================================================================
# System Restore
# =========================================================================

class _RESTOREPOINTINFO(ctypes.Structure):
    _fields_ = [
        ("dwEventType", wintypes.DWORD),
        ("dwRestorePtType", wintypes.DWORD),
        ("llSequenceNumber", ctypes.c_int64),
        ("szDescription", wintypes.WCHAR * 256),
    ]


class _STATEMGRSTATUS(ctypes.Structure):
    _fields_ = [
        ("nStatus", wintypes.DWORD),
        ("llSequenceNumber", ctypes.c_int64),
    ]


_BEGIN_SYSTEM_CHANGE = 100
_END_SYSTEM_CHANGE = 101
_MODIFY_SETTINGS = 12

#: Win32 codes SRSetRestorePointW can report (STATEMGRSTATUS.nStatus), in plain
#: language. Everything except 0 (ERROR_SUCCESS) is a failure.
_RESTORE_ERRORS = {
    5: "access denied - run as administrator",
    10: "Windows is in safe mode, where restore points cannot be made",
    13: "System Restore rejected the request (invalid sequence number)",
    112: "System Restore is paused because the drive is low on space",
    1058: ("System Protection is turned off for this drive. Enable it in System "
           "Properties > System Protection, then try again"),
    1060: "the System Restore service is not running",
    1359: "System Restore reported an internal error",
    1460: "System Restore was busy with another restore point and timed out",
    0x8007045D: "the drive returned an I/O error",
}

#: What a restore point is for, said wherever one is reported. System Restore
#: does not bring back personal files, so it must never read as an undo for a
#: clean. The Recycle Bin option is the undo for deleted files.
RESTORE_SCOPE = ("A restore point can roll back Windows settings, the registry and "
                 "installed programs. It does not bring back deleted files - "
                 "use “Send to Recycle Bin” for that.")


@dataclass
class RestorePoint:
    sequence: int
    created: "datetime | None"
    description: str

    def when(self) -> str:
        if self.created is None:
            return "earlier"
        return "at " + self.created.astimezone().strftime("%Y-%m-%d %H:%M")


def parse_restore_point(line: str) -> RestorePoint | None:
    """Parse one ``sequence|creation time|description`` line written by
    :func:`newest_restore_point`'s PowerShell. The creation time is WMI's DMTF
    form, ``yyyymmddHHMMSS.ffffff+UUU`` (offset in minutes). None if malformed."""
    parts = (line or "").strip().split("|", 2)
    if len(parts) < 2:
        return None
    try:
        seq = int(parts[0])
    except ValueError:
        return None
    return RestorePoint(sequence=seq, created=_parse_dmtf(parts[1]),
                        description=parts[2].strip() if len(parts) > 2 else "")


def _parse_dmtf(text: str) -> "datetime | None":
    text = (text or "").strip()
    try:
        stamp = datetime.strptime(text[:14], "%Y%m%d%H%M%S")
    except ValueError:
        return None
    offset = 0
    tail = text[21:] if len(text) > 21 and text[14:15] == "." else ""
    if tail[:1] in ("+", "-") and tail[1:].isdigit():
        offset = int(tail[1:]) * (1 if tail[0] == "+" else -1)
    return stamp.replace(tzinfo=timezone(timedelta(minutes=offset)))


def newest_restore_point() -> tuple[RestorePoint | None, bool]:
    """The newest restore point on this PC, and whether the list could be read.

    (None, True) means the list was read and is empty; (None, False) means
    Sweep could not look - the two must not be confused.
    """
    if not base.IS_WINDOWS:
        return None, False
    ps = ("$p = Get-ComputerRestorePoint -ErrorAction Stop | "
          "Sort-Object SequenceNumber | Select-Object -Last 1; "
          "if ($p) { '{0}|{1}|{2}' -f $p.SequenceNumber, $p.CreationTime, $p.Description }; "
          "'ok'")
    rc, out = _run(["powershell", "-NoProfile", "-NonInteractive", "-Command", ps],
                   timeout=60)
    lines = [ln for ln in out.splitlines() if ln.strip()]
    if rc != 0 or not lines or lines[-1].strip() != "ok":
        return None, False
    point = parse_restore_point(lines[0]) if len(lines) > 1 else None
    return point, True


def _skipped_message(existing: RestorePoint) -> str:
    return ("skipped - Windows lets programs make only one restore point per 24 "
            f"hours, and one was already made {existing.when()} "
            f"(\u201c{existing.description or 'no description'}\u201d); "
            "that one is still available")


def restore_outcome(api_ok: bool, status: int, sequence: int,
                    before: RestorePoint | None, before_known: bool,
                    after: RestorePoint | None = None, after_known: bool = False,
                    started: "datetime | None" = None) -> tuple[str, str]:
    """Decide what SRSetRestorePointW actually did. Pure, so it can be tested.

    Returns (kind, message) with kind one of "created", "skipped", "unconfirmed"
    or "failed". The trap it guards against: since Windows 8 the API skips the
    restore point when one was made in the last 24 hours, yet still returns
    TRUE with ERROR_SUCCESS and the *previous* point's sequence number. Only a
    sequence number newer than the newest point before the call is a new point.
    """
    if status != 0:
        return "failed", _RESTORE_ERRORS.get(
            int(status), f"System Restore returned code {int(status)}")
    if not api_ok:
        return "failed", "System Restore did not accept the request"
    if before_known and sequence:
        if before is None or sequence > before.sequence:
            return "created", f"sequence {sequence}"
        return "skipped", _skipped_message(before)
    # No usable comparison beforehand: judge by what exists now.
    if after_known and after is not None and after.sequence == sequence and sequence:
        if started is not None and after.created is not None:
            if after.created >= started - timedelta(minutes=2):
                return "created", f"sequence {sequence}"
            return "skipped", _skipped_message(after)
    return "unconfirmed", (
        "unconfirmed - System Restore accepted the request"
        + (f" (sequence {sequence})" if sequence else "")
        + " but Sweep could not read the list of restore points to check that a new one exists")


def create_restore_point(description: str = "Sweep: before cleaning") -> tuple[bool, str]:
    """Create a System Restore point and say exactly what happened.

    Calls SRSetRestorePointW. Like ``Checkpoint-Computer``, it is subject to
    Windows' one-restore-point-per-24-hours limit, and inside that window it
    reports success without making anything - so the newest restore point is
    read before the call and compared afterwards (see :func:`restore_outcome`).
    A new point is closed with END_SYSTEM_CHANGE, as the API documents.

    Returns (ok, message): ok is True only for a restore point that was really
    made by this call. A skipped or unconfirmed attempt returns False with a
    message that starts with "skipped -" or "unconfirmed -". Never raises.
    """
    if not base.IS_WINDOWS:
        return False, "System Restore is Windows-only"
    if not base.is_admin():
        return False, "needs administrator - nothing was created"
    try:
        srclient = ctypes.WinDLL("srclient.dll", use_last_error=True)
    except OSError as exc:
        return False, f"System Restore API unavailable ({exc})"

    before, before_known = newest_restore_point()
    started = datetime.now(timezone.utc)

    info = _RESTOREPOINTINFO()
    info.dwEventType = _BEGIN_SYSTEM_CHANGE
    info.dwRestorePtType = _MODIFY_SETTINGS
    info.llSequenceNumber = 0
    info.szDescription = description[:255]
    status = _STATEMGRSTATUS()

    try:
        api_ok = bool(srclient.SRSetRestorePointW(ctypes.byref(info), ctypes.byref(status)))
    except (AttributeError, OSError) as exc:
        return False, f"could not call System Restore ({exc})"

    # The documented place for the sequence number is the status struct.
    seq = int(status.llSequenceNumber or 0) or int(info.llSequenceNumber or 0)
    after, after_known = (None, False)
    if api_ok and int(status.nStatus) == 0 and not (before_known and seq):
        after, after_known = newest_restore_point()
    kind, msg = restore_outcome(api_ok, int(status.nStatus), seq, before, before_known,
                                after, after_known, started)
    if kind == "created" and seq:
        _end_restore_point(srclient, seq, description)
        msg = f"“{description}”, {msg}"
    return kind == "created", msg


def _end_restore_point(srclient, sequence: int, description: str) -> None:
    """Close a BEGIN_SYSTEM_CHANGE restore point. Best effort: the point already
    exists once BEGIN succeeds, so a failure here is not reported as a failure
    to create it."""
    info = _RESTOREPOINTINFO()
    info.dwEventType = _END_SYSTEM_CHANGE
    info.dwRestorePtType = _MODIFY_SETTINGS
    info.llSequenceNumber = sequence
    info.szDescription = description[:255]
    status = _STATEMGRSTATUS()
    try:
        srclient.SRSetRestorePointW(ctypes.byref(info), ctypes.byref(status))
    except (AttributeError, OSError):
        pass


def restore_point_supported() -> tuple[bool, str]:
    """Whether a restore point can be made right now, without making one."""
    if not base.IS_WINDOWS:
        return False, "Windows-only"
    if not base.is_admin():
        return False, "needs administrator"
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore") as k:
            try:
                disabled = winreg.QueryValueEx(k, "DisableSR")[0]
            except OSError:
                disabled = 0
            if disabled:
                return False, "System Protection is turned off"
        return True, "available"
    except OSError:
        return True, "available (service state unknown)"
