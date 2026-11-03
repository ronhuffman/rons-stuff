"""
Sweep - registry cleaning.

Registry cleaning is the most discredited part of every cleaner, for a good
reason: most of it deletes entries that are merely *unused*, which reclaims no
space and occasionally breaks something.

Sweep takes a narrower and more defensible position. It only removes an entry
when it can **prove** the entry is dangling - the file it names no longer
exists, or the program it names is no longer installed. Every removal is written
to a JSON backup that `sweep restore-registry` replays exactly, types included.

Categories that cannot be verified this way (firewall rules, "Interface",
"Windows Services", shared-DLL reference counting) are deliberately not
implemented. `implemented()` reports what exists so the UI never implies more.
"""

from __future__ import annotations

import json
import os
import winreg
from dataclasses import dataclass, field

HIVES = {"HKCU": winreg.HKEY_CURRENT_USER, "HKLM": winreg.HKEY_LOCAL_MACHINE}

# Access rights that work for both 32- and 64-bit views on a 64-bit OS.
KEY_READ = winreg.KEY_READ
KEY_WRITE = winreg.KEY_WRITE

_TYPE_NAMES = {
    winreg.REG_SZ: "REG_SZ",
    winreg.REG_EXPAND_SZ: "REG_EXPAND_SZ",
    winreg.REG_DWORD: "REG_DWORD",
    winreg.REG_QWORD: "REG_QWORD",
    winreg.REG_BINARY: "REG_BINARY",
    winreg.REG_MULTI_SZ: "REG_MULTI_SZ",
}


@dataclass
class RegEntry:
    """One removable registry element."""
    hive: str
    key: str                       # full subkey path under the hive
    kind: str = "value"            # "value" | "subkey"
    value: str | None = None
    reason: str = ""
    _type: int | None = None
    _data: object = None
    _exists: bool = True

    @property
    def display(self) -> str:
        base = f"{self.hive}\\{self.key}"
        if self.kind == "value" and self.value:
            return f"{base}\\{self.value}"
        return base

    def backup_record(self) -> dict:
        """What is needed to put this entry back. A subkey is recorded with
        everything under it - removal deletes the whole tree, so a backup of
        just the key name would restore an empty shell."""
        rec = {"hive": self.hive, "key": self.key, "kind": self.kind,
               "value": self.value, "reason": self.reason}
        if self.kind == "value":
            rec.update(_encode_value(self._type, self._data))
        else:
            rec["tree"] = _read_tree(HIVES[self.hive], self.key)
        return rec


def _encode_value(typ, data) -> dict:
    rec = {"type": typ, "type_name": _TYPE_NAMES.get(typ, str(typ))}
    if isinstance(data, bytes):
        rec["data"] = data.hex()
        rec["data_encoding"] = "hex"
    elif isinstance(data, list):
        rec["data"] = [str(x) for x in data]
    else:
        rec["data"] = data
    return rec


def _decode_value(rec: dict):
    typ = rec.get("type")
    if typ is None:
        typ = winreg.REG_SZ
    data = rec.get("data")
    if rec.get("data_encoding") == "hex" and isinstance(data, str):
        data = bytes.fromhex(data)
    return typ, data


def _read_tree(root, path: str, depth: int = 0) -> dict:
    """Every value and subkey under *path*. Raises OSError if any part cannot
    be read: an incomplete backup must stop the deletion, not excuse it."""
    if depth > 64:
        raise OSError(f"registry tree too deep to back up: {path}")
    with winreg.OpenKey(root, path, 0, KEY_READ) as h:
        values = []
        i = 0
        while True:
            try:
                name, data, typ = winreg.EnumValue(h, i)
            except OSError:
                break
            values.append(dict(name=name, **_encode_value(typ, data)))
            i += 1
        names = []
        i = 0
        while True:
            try:
                names.append(winreg.EnumKey(h, i))
            except OSError:
                break
            i += 1
    return {"values": values,
            "subkeys": {n: _read_tree(root, f"{path}\\{n}", depth + 1) for n in names}}


def _write_tree(root, path: str, tree: dict) -> None:
    with winreg.CreateKeyEx(root, path, 0, KEY_WRITE) as h:
        for v in tree.get("values", []):
            typ, data = _decode_value(v)
            winreg.SetValueEx(h, v.get("name") or "", 0, typ, data)
    for name, sub in (tree.get("subkeys") or {}).items():
        _write_tree(root, f"{path}\\{name}", sub)


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------

def _open(hive: str, key: str, write: bool = False):
    return winreg.OpenKey(HIVES[hive], key, 0, KEY_WRITE if write else KEY_READ)


def _try_open(hive: str, key: str):
    try:
        return _open(hive, key)
    except OSError:
        return None


def _enum_values(hive: str, key: str):
    h = _try_open(hive, key)
    if h is None:
        return
    i = 0
    while True:
        try:
            name, data, typ = winreg.EnumValue(h, i)
        except OSError:
            break
        i += 1
        yield name, data, typ


def _exists(path: str) -> bool:
    """False only when *path* is provably missing. Anything that cannot be
    resolved - an unexpanded variable, or a bare name such as ``MsiExec.exe``
    that Windows finds on its search path - counts as present, because a
    relative lookup from Sweep's own folder proves nothing."""
    if not path:
        return False
    p = os.path.expandvars(path.strip().strip('"'))
    if not p or "%" in p:
        return True                     # cannot resolve -> do not judge it dead
    if not os.path.isabs(p):
        return True
    try:
        return os.path.exists(p)
    except (OSError, ValueError):
        return True


def _exe_from_command(cmd: str) -> str:
    """Pull a filesystem path out of a Run/Uninstall command line."""
    if not cmd:
        return ""
    c = os.path.expandvars(cmd.strip())
    if c.startswith('"'):
        end = c.find('"', 1)
        return c[1:end] if end > 0 else c[1:]
    # unquoted: take up to the first " -" or " /" switch that follows a .exe
    low = c.lower()
    for token in (" -", " /", " --"):
        idx = low.find(token)
        if idx > 0:
            c = c[:idx]
            break
    return c.strip()


# --------------------------------------------------------------------------
# scanners - each yields RegEntry candidates
# --------------------------------------------------------------------------

def _scan_muicache() -> list[RegEntry]:
    """MuiCache holds display names for programs Explorer has run. Entries whose
    target is gone are pure residue."""
    key = r"Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache"
    out = []
    for name, data, typ in _enum_values("HKCU", key):
        if not name or not isinstance(data, str):
            continue
        if _exists(_muicache_target(name)):
            continue
        out.append(RegEntry("HKCU", key, "value", name,
                            "cached display name for a program that no longer exists",
                            typ, data))
    return out


def _muicache_target(name: str) -> str:
    """The program a MuiCache value name refers to. Modern names carry a
    suffix (``C:\\x\\app.exe.FriendlyAppName``) and resource names look like
    ``@C:\\x\\shell32.dll,-1234``; checking either as a path would call every
    entry dangling."""
    target = name
    if target.startswith("@"):
        target = target[1:].split(",", 1)[0]
    for suffix in (".FriendlyAppName", ".ApplicationCompany"):
        if target.endswith(suffix):
            target = target[: -len(suffix)]
            break
    return target


def _scan_app_paths() -> list[RegEntry]:
    """App Paths entries whose executable is missing."""
    out = []
    for hive in ("HKLM", "HKCU"):
        root = r"Software\Microsoft\Windows\CurrentVersion\App Paths"
        h = _try_open(hive, root)
        if h is None:
            continue
        i = 0
        while True:
            try:
                sub = winreg.EnumKey(h, i)
            except OSError:
                break
            i += 1
            full = f"{root}\\{sub}"
            try:
                with winreg.OpenKey(HIVES[hive], full) as sk:
                    default, typ = winreg.QueryValueEx(sk, "")
            except OSError:
                continue
            if isinstance(default, str) and not _exists(default):
                out.append(RegEntry(hive, full, "subkey", None,
                                    f"registered executable is missing: {default}"))
    return out


def _scan_shared_dlls() -> list[RegEntry]:
    """SharedDLLs maps full DLL paths to a reference count. Only entries whose
    file is absent are removed - we never touch reference counting."""
    key = r"Software\Microsoft\Windows\CurrentVersion\SharedDLLs"
    out = []
    for hive in ("HKLM", "HKCU"):
        for name, data, typ in _enum_values(hive, key):
            if name and not _exists(name):
                out.append(RegEntry(hive, key, "value", name,
                                    f"shared DLL no longer present: {name}", typ, data))
    return out


def _scan_open_with() -> list[RegEntry]:
    """FileExts\\<ext>\\OpenWithList entries naming missing executables."""
    root = r"Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts"
    out = []
    h = _try_open("HKCU", root)
    if h is None:
        return out
    i = 0
    while True:
        try:
            ext = winreg.EnumKey(h, i)
        except OSError:
            break
        i += 1
        owl = f"{root}\\{ext}\\OpenWithList"
        for name, data, typ in _enum_values("HKCU", owl):
            if name.lower() == "mrulist":
                continue
            if isinstance(data, str) and data.strip():
                # a bare image name is resolved against System32
                probe = data if os.path.sep in data else os.path.join(
                    os.environ.get("WINDIR", r"C:\Windows"), "System32", data)
                if not _exists(probe):
                    out.append(RegEntry("HKCU", owl, "value", name,
                                        f"open-with handler missing for {ext}: {data}",
                                        typ, data))
    return out


def obsolete_reason(install_location: str, uninstall_string: str) -> str:
    """Why an Uninstall entry is provably dead, or "" if it is not.

    Both the install folder and the uninstaller must be recorded and both must
    be gone. One missing pointer is not proof - plenty of installed programs
    have a stale InstallLocation, and an uninstaller run through ``MsiExec.exe``
    cannot be checked as a file at all.
    """
    loc = (install_location or "").strip()
    exe = _exe_from_command(uninstall_string or "")
    if not loc or not exe:
        return ""
    if _exists(loc) or _exists(exe):
        return ""
    return f"install location and uninstaller both gone: {loc}; {exe}"


def _scan_obsolete_software() -> list[RegEntry]:
    """Uninstall entries where the install location and uninstaller are both
    gone. The entry is removed, never the program."""
    roots = [
        ("HKLM", r"Software\Microsoft\Windows\CurrentVersion\Uninstall"),
        ("HKLM", r"Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
        ("HKCU", r"Software\Microsoft\Windows\CurrentVersion\Uninstall"),
    ]
    out = []
    for hive, root in roots:
        h = _try_open(hive, root)
        if h is None:
            continue
        i = 0
        while True:
            try:
                sub = winreg.EnumKey(h, i)
            except OSError:
                break
            i += 1
            full = f"{root}\\{sub}"
            try:
                with winreg.OpenKey(HIVES[hive], full) as sk:
                    def get(n):
                        try:
                            return str(winreg.QueryValueEx(sk, n)[0])
                        except OSError:
                            return ""
                    loc = get("InstallLocation")
                    unins = get("UninstallString")
                    disp = get("DisplayName")
                if not disp:
                    continue                     # updates/hidden entries
                # only judge when every concrete pointer is provably gone
                why = obsolete_reason(loc, unins)
                if why:
                    out.append(RegEntry(hive, full, "subkey", None, why))
            except OSError:
                continue
    return out


def _scan_run_at_startup() -> list[RegEntry]:
    """Run entries whose executable no longer exists. This is *not* a startup
    manager - it never removes a working entry."""
    locations = [
        ("HKCU", r"Software\Microsoft\Windows\CurrentVersion\Run"),
        ("HKLM", r"Software\Microsoft\Windows\CurrentVersion\Run"),
        ("HKLM", r"Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run"),
    ]
    out = []
    for hive, key in locations:
        for name, data, typ in _enum_values(hive, key):
            if not name or not isinstance(data, str):
                continue
            exe = _exe_from_command(data)
            if exe and os.path.sep in exe and not _exists(exe):
                out.append(RegEntry(hive, key, "value", name,
                                    f"startup target missing: {exe}", typ, data))
    return out


def _scan_sound_events() -> list[RegEntry]:
    """Scheme\\.Current values pointing at a missing .wav."""
    root = r"AppEvents\Schemes\Apps"
    out = []

    def walk(hive: str, path: str, depth: int) -> None:
        if depth > 5:
            return
        h = _try_open(hive, path)
        if h is None:
            return
        i = 0
        while True:
            try:
                sub = winreg.EnumKey(h, i)
            except OSError:
                break
            i += 1
            child = f"{path}\\{sub}"
            if sub.lower() == ".current":
                try:
                    with winreg.OpenKey(HIVES[hive], child) as sk:
                        val, typ = winreg.QueryValueEx(sk, "")
                except OSError:
                    continue
                if isinstance(val, str) and val and not _exists(val):
                    out.append(RegEntry(hive, child, "value", "",
                                        f"sound file missing: {val}", typ, val))
            else:
                walk(hive, child, depth + 1)

    walk("HKCU", root, 0)
    return out


def _scan_fonts() -> list[RegEntry]:
    """Installed-font entries whose font file is gone."""
    key = r"Software\Microsoft\Windows NT\CurrentVersion\Fonts"
    out = []
    win = os.environ.get("WINDIR", r"C:\Windows")
    for name, data, typ in _enum_values("HKLM", key):
        if not isinstance(data, str) or not data:
            continue
        p = data if os.path.isabs(data) else os.path.join(win, "Fonts", data)
        if not _exists(p):
            out.append(RegEntry("HKLM", key, "value", name,
                                f"font file missing: {data}", typ, data))
    return out


SCANNERS = {
    "muicache": _scan_muicache,
    "app_paths": _scan_app_paths,
    "shared_dlls": _scan_shared_dlls,
    "open_with": _scan_open_with,
    "obsolete_software": _scan_obsolete_software,
    "run_at_startup": _scan_run_at_startup,
    "sound_events": _scan_sound_events,
    "fonts": _scan_fonts,
}

#: categories Sweep intentionally does not implement, with the reason shown to
#: the user instead of a silent empty result.
NOT_IMPLEMENTED = {
    "firewall_rules": "requires the Windows Firewall COM API; not a file check",
    "interface": "no verifiable definition of a dangling entry",
    "windows_services": "removing service records can prevent a driver from loading",
    "installers": "removing MSI product records breaks repair/uninstall",
    "help_files": "help MRU entries reclaim no space and may be live",
    "invalid_file_extensions": "extension records are shared and easy to misjudge",
    "browser_helper": "a registered BHO may be disabled rather than dead",
}


def implemented() -> list[str]:
    return sorted(SCANNERS)


def scan_category(category: str, errors: list[str] | None = None) -> list[RegEntry]:
    fn = SCANNERS.get(category)
    if fn is None:
        return []
    try:
        return fn()
    except OSError as exc:
        # Returning [] here made an unreadable key look like a clean one.
        if errors is not None:
            errors.append(f"{category}: {exc.strerror or exc}")
        return []


def scan_direct(spec: dict) -> list[RegEntry]:
    """Enumerate a rule-supplied registry location.

    spec = {"hive": "HKCU", "key": "Software\\...", "value": "Name" | "*" | None}

    ``value=None`` removes the whole subkey; ``"*"`` removes every value in the
    key but keeps the key; a concrete name removes just that value.
    """
    hive = spec.get("hive", "HKCU")
    key = spec.get("key", "")
    value = spec.get("value")
    if hive not in HIVES or not key:
        return []
    note = spec.get("why", "rule-specified registry entry")

    if value == "*":
        return [RegEntry(hive, key, "value", name, note, typ, data)
                for name, data, typ in _enum_values(hive, key)]

    if value:
        for name, data, typ in _enum_values(hive, key):
            if name.lower() == value.lower():
                return [RegEntry(hive, key, "value", name, note, typ, data)]
        return []

    # whole subkey
    if _try_open(hive, key) is None:
        return []
    return [RegEntry(hive, key, "subkey", None, note)]


# --------------------------------------------------------------------------
# removal + backup
# --------------------------------------------------------------------------

def backup(entries: list[RegEntry], path: str) -> str:
    """Write a JSON backup that `restore()` can replay exactly, whole subkey
    trees included. Raises OSError if anything cannot be read - the caller
    must then not delete."""
    recs = [e.backup_record() for e in entries]        # read before writing
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump({"version": 2, "entries": recs}, fh, indent=2)
    os.replace(tmp, path)
    return path


def remove(entries: list[RegEntry]) -> tuple[int, int]:
    """Delete the recorded values/subkeys. Returns (removed, failed).

    Only an entry that was actually deleted counts as removed: a key that
    could not be opened or deleted is a failure, not a success."""
    ok = fail = 0
    for e in entries:
        try:
            if e.kind == "subkey":
                _delete_tree(HIVES[e.hive], e.key)
            else:
                with _open(e.hive, e.key, write=True) as h:
                    winreg.DeleteValue(h, e.value or "")
            ok += 1
        except OSError:
            fail += 1
    return ok, fail


def _delete_tree(root, path: str) -> None:
    """Recursively delete a subkey. Raises OSError if any part of it cannot
    be deleted."""
    with winreg.OpenKey(root, path, 0, KEY_READ | KEY_WRITE) as h:
        children = []
        i = 0
        while True:
            try:
                children.append(winreg.EnumKey(h, i))
            except OSError:
                break
            i += 1
    for child in children:
        _delete_tree(root, f"{path}\\{child}")
    winreg.DeleteKey(root, path)


def restore(path: str) -> tuple[int, int]:
    """Replay a backup. Returns (restored, failed)."""
    with open(path, encoding="utf-8") as fh:
        blob = json.load(fh)
    ok = fail = 0
    for rec in blob.get("entries", []):
        try:
            hive = HIVES[rec["hive"]]
            if rec["kind"] == "subkey":
                if "tree" in rec:
                    _write_tree(hive, rec["key"], rec["tree"])
                else:
                    # A version-1 backup recorded only the key's name; its
                    # contents were never saved and cannot be brought back.
                    with winreg.CreateKeyEx(hive, rec["key"], 0, KEY_WRITE):
                        pass
            else:
                typ, data = _decode_value(rec)
                with winreg.CreateKeyEx(hive, rec["key"], 0, KEY_WRITE) as h:
                    winreg.SetValueEx(h, rec["value"] or "", 0, typ, data)
            ok += 1
        except (OSError, KeyError, ValueError, TypeError):
            fail += 1
    return ok, fail
