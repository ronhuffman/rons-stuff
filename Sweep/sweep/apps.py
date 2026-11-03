"""
Sweep - installed applications: inventory, uninstall, leftovers, updates.

Leftover detection is deliberately *advisory*. It reports folders and registry
keys that look like they belong to an uninstalled program; it does not delete
them on its own, because a name match is evidence, not proof.
"""

from __future__ import annotations

import os
import re
import subprocess
import winreg
from dataclasses import dataclass, field

from . import base

CREATE_NO_WINDOW = 0x08000000

UNINSTALL_ROOTS = [
    # note: these must be real registry access flags. Passing the literal 64/32
    # makes OpenKey fail with Access denied and silently hides every machine-wide
    # application.
    ("HKLM", r"Software\Microsoft\Windows\CurrentVersion\Uninstall",
     winreg.KEY_WOW64_64KEY),
    ("HKLM", r"Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall", 0),
    ("HKCU", r"Software\Microsoft\Windows\CurrentVersion\Uninstall", 0),
]

_HIVES = {"HKLM": winreg.HKEY_LOCAL_MACHINE, "HKCU": winreg.HKEY_CURRENT_USER}


@dataclass
class App:
    name: str
    version: str = ""
    publisher: str = ""
    install_location: str = ""
    uninstall_string: str = ""
    quiet_uninstall: str = ""
    install_date: str = ""
    hive: str = ""
    key: str = ""
    size_bytes: int | None = None
    source: str = "registry"

    @property
    def uninstallable(self) -> bool:
        return bool(self.uninstall_string)

    @property
    def key_id(self) -> str:
        return f"{self.hive}|{self.key}" if self.hive else self.name


def _read(hive_const: int, path: str, name: str) -> str:
    try:
        with winreg.OpenKey(hive_const, path, 0, winreg.KEY_READ) as hk:
            return str(winreg.QueryValueEx(hk, name)[0])
    except OSError:
        return ""


def list_apps(errors: list[str] | None = None) -> list[App]:
    """Every registered application, deduplicated by name+version.

    Pass a list as *errors* to collect the Uninstall views that could not be
    opened. Without that, a failed view is indistinguishable from a machine
    with fewer programs installed.
    """
    apps: list[App] = []
    seen: set[tuple[str, str]] = set()
    for hive, root, view in UNINSTALL_ROOTS:
        hconst = _HIVES[hive]
        try:
            access = winreg.KEY_READ | (view if view else 0)
            with winreg.OpenKey(hconst, root, 0, access) as h:
                i = 0
                subs = []
                while True:
                    try:
                        subs.append(winreg.EnumKey(h, i))
                    except OSError:
                        break
                    i += 1
        except FileNotFoundError:
            continue              # this view does not exist on this machine
        except OSError as exc:
            if errors is not None:
                errors.append(f"{root}: {exc.strerror or exc}")
            continue
        for sub in subs:
            path = f"{root}\\{sub}"
            try:
                access = winreg.KEY_READ | (view if view else 0)
                with winreg.OpenKey(hconst, path, 0, access) as hk:
                    def get(n):
                        try:
                            return str(winreg.QueryValueEx(hk, n)[0])
                        except OSError:
                            return ""
                    name = get("DisplayName").strip()
                    if not name:
                        continue
                    if get("SystemComponent") == "1":
                        continue
                    if get("ParentKeyName"):
                        continue            # patch/update entry, not an app
                    app = App(
                        name=name,
                        version=get("DisplayVersion"),
                        publisher=get("Publisher"),
                        install_location=get("InstallLocation"),
                        uninstall_string=get("UninstallString"),
                        quiet_uninstall=get("QuietUninstallString"),
                        install_date=get("InstallDate"),
                        hive=hive,
                        key=path,
                    )
                    sig = (app.name.lower(), app.version.lower())
                    if sig in seen:
                        continue
                    seen.add(sig)
                    apps.append(app)
            except OSError:
                continue
    apps.sort(key=lambda a: a.name.lower())
    return apps


def app_size(app: App) -> int | None:
    if not app.install_location or not os.path.isdir(app.install_location):
        return None
    try:
        return base.dir_size(app.install_location)
    except OSError:
        return None


def launch_uninstall(app: App, quiet: bool = False) -> tuple[bool, str]:
    """Start the application's own uninstaller. This is the only way Sweep
    removes an app - it never deletes an install directory by itself."""
    cmd = app.quiet_uninstall if (quiet and app.quiet_uninstall) else app.uninstall_string
    if not cmd:
        return False, "no uninstall command registered"
    try:
        subprocess.Popen(cmd, shell=True, creationflags=CREATE_NO_WINDOW)
        return True, cmd
    except OSError as exc:
        return False, str(exc)


# --------------------------------------------------------------------------
# leftovers (advisory)
# --------------------------------------------------------------------------

_STOPWORDS = {"the", "pro", "free", "version", "edition", "setup", "installer",
              "app", "application", "for", "and", "with", "microsoft", "windows"}


def _tokens(name: str) -> list[str]:
    raw = re.split(r"[^A-Za-z0-9]+", name.lower())
    out = [t for t in raw if len(t) >= 4 and t not in _STOPWORDS]
    return out[:4]


@dataclass
class Leftover:
    kind: str            # "folder" | "registry"
    path: str
    size: int = 0
    matched: str = ""


def _search_roots() -> list[str]:
    roots = []
    for env in ("ProgramFiles", "ProgramFiles(x86)", "ProgramData", "LOCALAPPDATA", "APPDATA"):
        p = os.environ.get(env)
        if p and os.path.isdir(p):
            roots.append(p)
    return roots


def find_leftovers(app: App) -> list[Leftover]:
    """Folders/registry keys whose name looks like this application.

    Only used for an app that is already uninstalled (or being removed); the
    result is a review list.
    """
    toks = _tokens(app.name)
    if not toks:
        return []
    out: list[Leftover] = []

    skip_install = base.norm(app.install_location) if app.install_location else ""

    for root in _search_roots():
        try:
            with os.scandir(root) as it:
                for entry in it:
                    if not entry.is_dir(follow_symlinks=False):
                        continue
                    low = entry.name.lower()
                    hit = next((t for t in toks if t in low), None)
                    if not hit:
                        continue
                    if skip_install and base.norm(entry.path) == skip_install:
                        continue
                    size = 0
                    try:
                        size = base.dir_size(entry.path)
                    except OSError:
                        pass
                    out.append(Leftover("folder", entry.path, size, hit))
        except OSError:
            continue

    for hive, root in (("HKCU", r"Software"), ("HKLM", r"Software"), ("HKLM", r"Software\Wow6432Node")):
        hconst = _HIVES[hive]
        try:
            with winreg.OpenKey(hconst, root, 0, winreg.KEY_READ) as h:
                i = 0
                subs = []
                while True:
                    try:
                        subs.append(winreg.EnumKey(h, i))
                    except OSError:
                        break
                    i += 1
        except OSError:
            continue
        for sub in subs:
            low = sub.lower()
            hit = next((t for t in toks if t in low), None)
            if hit:
                out.append(Leftover("registry", f"{hive}\\{root}\\{sub}", 0, hit))

    out.sort(key=lambda x: (x.kind, -x.size))
    return out


# --------------------------------------------------------------------------
# software updates (winget)
# --------------------------------------------------------------------------

@dataclass
class Upgrade:
    name: str
    package_id: str
    current: str
    available: str
    source: str = ""


def winget_available() -> bool:
    return winget_diagnose()[0]


def winget_diagnose() -> tuple[bool, str]:
    """Is winget usable, and if not, why not.

    ``winget.exe`` under WindowsApps is normally a 0-byte *App Execution Alias*
    stub. It can exist and still fail to activate - in a non-interactive or
    sandboxed session it returns 0x8A150001 (APPINSTALLER_CLI_ERROR_INTERNAL_ERROR)
    even though App Installer is installed. Reporting that code is far more
    useful than "not available".
    """
    alias = os.path.join(os.environ.get("LOCALAPPDATA", ""),
                         r"Microsoft\WindowsApps\winget.exe")
    try:
        r = subprocess.run(["winget", "--version"], capture_output=True, text=True,
                           timeout=25, creationflags=CREATE_NO_WINDOW)
    except FileNotFoundError:
        return False, "winget is not installed (no App Installer)"
    except (OSError, subprocess.SubprocessError) as exc:
        return False, f"winget could not be started: {exc}"

    if r.returncode == 0:
        ver = (r.stdout or "").strip().splitlines()
        return True, ver[0] if ver else "winget ready"

    code = r.returncode & 0xFFFFFFFF
    if code == 0x8A150001:
        return False, ("winget is installed but could not activate in this session "
                       "(0x8A150001). Run Sweep from a normal desktop session, or "
                       "run 'winget upgrade' once by hand to confirm.")
    if os.path.isfile(alias) and os.path.getsize(alias) == 0:
        return False, (f"winget alias exists but returned 0x{code:08X}; "
                       "repair App Installer from the Microsoft Store")
    return False, f"winget returned 0x{code:08X}"


_UPGRADE_ROW = re.compile(r"^(?P<name>.+?)\s{2,}(?P<id>\S+)\s+(?P<cur>\S+)\s+(?P<avail>\S+)\s+(?P<src>\S+)\s*$")


def _winget_table_recognised(text: str) -> bool:
    """Whether winget printed an upgrade table we understand.

    Empty output counts as recognised (nothing to upgrade). Output we cannot
    parse does not: treating it as an empty list is what lets a format change
    read as "every package is current".
    """
    low = (text or "").strip().lower()
    if not low:
        return True
    return "name" in low and "id" in low and "version" in low


def parse_winget_upgrade(text: str) -> list[Upgrade]:
    """Parse `winget upgrade` table output.

    The table is column-aligned with runs of two or more spaces between fields,
    and is preceded by header lines and dashed separators that must be skipped.
    """
    out: list[Upgrade] = []
    for line in text.splitlines():
        s = line.rstrip()
        if not s.strip():
            continue
        low = s.lower()
        if "-----" in s or low.startswith("name ") or "available" in low and "source" in low:
            continue
        if "upgrades available" in low or "package(s)" in low:
            continue
        m = _UPGRADE_ROW.match(s)
        if not m:
            continue
        name = m.group("name").strip()
        pid = m.group("id").strip()
        if not pid or pid.lower() == "id":
            continue
        out.append(Upgrade(
            name=name,
            package_id=pid,
            current=m.group("cur").strip(),
            available=m.group("avail").strip(),
            source=m.group("src").strip(),
        ))
    return out


def list_upgrades() -> tuple[list[Upgrade], str]:
    """Return (upgrades, error). Never raises."""
    ok, detail = winget_diagnose()
    if not ok:
        return [], detail
    try:
        r = subprocess.run(
            ["winget", "upgrade", "--include-unknown",
             "--accept-source-agreements", "--disable-interactivity"],
            capture_output=True, text=True, timeout=180,
            creationflags=CREATE_NO_WINDOW,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return [], f"winget failed: {exc}"
    text = (r.stdout or "") + "\n" + (r.stderr or "")
    items = parse_winget_upgrade(text)
    if not items and r.returncode != 0:
        return [], "winget returned an error (code %d)" % r.returncode
    if not items and not _winget_table_recognised(text):
        return [], ("winget output could not be read (no upgrade table found) - "
                    "the installed packages are not known to be current")
    return items, ""


def upgrade_package(package_id: str) -> tuple[bool, str]:
    if not package_id:
        return False, "no package id"
    try:
        r = subprocess.run(
            ["winget", "upgrade", "--id", package_id, "--exact",
             "--silent", "--accept-package-agreements", "--accept-source-agreements",
             "--disable-interactivity"],
            capture_output=True, text=True, timeout=1800,
            creationflags=CREATE_NO_WINDOW,
        )
        ok = r.returncode == 0
        tail = (r.stdout or r.stderr or "").strip().splitlines()
        return ok, (tail[-1] if tail else f"exit {r.returncode}")
    except (OSError, subprocess.SubprocessError) as exc:
        return False, str(exc)


#: winget failures that mean something specific. Matched case-insensitively.
_WINGET_EXPLAIN = [
    ("0x80072ee7", "network: could not reach the download source (DNS or "
                   "connection failed). Retry later, or use the vendor's own "
                   "updater for this one."),
    ("0x80072ee4", "network: the source returned no usable response."),
    ("install technology is different",
     "in-place upgrade not supported: this app was installed by a different "
     "installer type, so winget will not replace it. Download the vendor's "
     "own installer instead."),
    ("0x80073d02", "the app is running - close it, then retry."),
    ("being used by another", "the app is running - close it, then retry."),
    ("no applicable upgrade", "winget found no applicable newer version."),
    ("no newer version", "already current according to winget."),
    ("0x8a15002b", "no applicable installer for this system architecture."),
    ("hash does not match", "the downloaded installer failed its hash check; "
                            "the publisher's manifest is stale."),
    ("0x80070005", "access denied - run Sweep as administrator."),
]


def explain_winget_error(message: str) -> str:
    """Turn a winget failure into a sentence that says what to do.

    Returns "" when the message is not recognised, so callers fall back to the
    raw text rather than inventing a cause.
    """
    low = (message or "").lower()
    for needle, explanation in _WINGET_EXPLAIN:
        if needle.lower() in low:
            return explanation
    return ""


def short_status(ok: bool, message: str, width: int = 34) -> str:
    """A compact result label for a table cell."""
    if ok:
        return "ok"
    low = (message or "").lower()
    if "0x80072ee7" in low or "0x80072ee4" in low:
        return "failed: network"
    if "install technology" in low:
        return "failed: wrong installer type"
    if "0x80073d02" in low or "running" in low:
        return "failed: app running"
    if "0x80070005" in low or "access denied" in low:
        return "failed: needs admin"
    if "hash does not match" in low:
        return "failed: bad installer hash"
    return "failed" if not message else "failed: " + message[:width]
