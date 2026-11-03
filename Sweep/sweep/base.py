"""
Sweep - core primitives: sizing, safe path walking, Windows API bindings.

Design rule for this module: nothing in here may delete anything it was not
explicitly handed, and every path handed in must survive `assert_contained`.
"""

from __future__ import annotations

import ctypes
import ctypes.wintypes as wintypes
import fnmatch
import os
import re
import stat
import sys
import threading

IS_WINDOWS = sys.platform == "win32"

# --------------------------------------------------------------------------
# formatting
# --------------------------------------------------------------------------

_UNITS = ("B", "KB", "MB", "GB", "TB", "PB")


def human(n: int | float | None) -> str:
    """1536 -> '1.5 KB'. Never negative, never noisy."""
    if n is None:
        return "-"
    n = float(n)
    if n < 0:
        n = 0.0
    i = 0
    while n >= 1024 and i < len(_UNITS) - 1:
        n /= 1024.0
        i += 1
    if i == 0:
        return f"{int(n)} {_UNITS[i]}"
    return f"{n:.1f} {_UNITS[i]}"


def count(n: int) -> str:
    return f"{n:,}"


def files_per_sec(n: int, secs: float) -> str:
    if secs <= 0:
        return "-"
    return f"{int(n / secs):,}/s"


# --------------------------------------------------------------------------
# environment / path expansion
# --------------------------------------------------------------------------

_VAR_RE = re.compile(r"%([A-Za-z0-9_()]+)%")


def expand(text: str) -> str:
    """Expand %VARS% and ~. Unknown vars are left verbatim so the caller can
    treat the rule as absent instead of matching a literal '%FOO%' path."""
    if not text:
        return text

    def repl(m: re.Match) -> str:
        name = m.group(1)
        val = os.environ.get(name)
        if val is None:
            # a few aliases CCleaner-style rule sets commonly use
            aliases = {
                "LOCALAPPDATA": os.environ.get("LOCALAPPDATA"),
                "APPDATA": os.environ.get("APPDATA"),
                "USERPROFILE": os.environ.get("USERPROFILE"),
                "WINDIR": os.environ.get("WINDIR") or os.environ.get("SystemRoot"),
                "SYSTEMROOT": os.environ.get("SystemRoot"),
                "PROGRAMDATA": os.environ.get("ProgramData"),
                "PROGRAMFILES": os.environ.get("ProgramFiles"),
                "PROGRAMFILES(X86)": os.environ.get("ProgramFiles(x86)"),
                "TEMP": os.environ.get("TEMP"),
                "TMP": os.environ.get("TMP"),
                "PUBLIC": os.environ.get("PUBLIC"),
                "ALLUSERSPROFILE": os.environ.get("ALLUSERSPROFILE"),
                "COMMONPROGRAMFILES": os.environ.get("CommonProgramFiles"),
            }
            val = aliases.get(name.upper())
        return val if val is not None else m.group(0)

    out = _VAR_RE.sub(repl, text)
    if out.startswith("~"):
        home = os.path.expanduser("~")
        out = home + out[1:]
    return os.path.expandvars(out)


def norm(path: str) -> str:
    """Normalise for comparison only - never for the path we hand to the OS."""
    try:
        return os.path.normcase(os.path.abspath(path))
    except (OSError, ValueError):
        return os.path.normcase(path)


# --------------------------------------------------------------------------
# path safety
# --------------------------------------------------------------------------

class UnsafePath(Exception):
    """Raised when a deletion target escapes its declared root."""


class PathGuard:
    """Confines every deletion to an explicit allow-list of roots.

    The guard is built from the *scannable* roots of the rule set that the
    user actually selected. A path that is not under one of those roots is
    refused, even if some other code path produced it. This is the backstop
    against a bad pattern (``*`` in the wrong place, a wildcard in a path
    segment, a junction loop) turning into a system-wide wipe.
    """

    def __init__(self) -> None:
        self._roots: list[str] = []

    def add(self, root: str) -> None:
        r = norm(root).rstrip("\\/")
        if r and r not in self._roots:
            self._roots.append(r)

    @property
    def roots(self) -> list[str]:
        return list(self._roots)

    def __bool__(self) -> bool:
        return bool(self._roots)

    def contains(self, path: str) -> bool:
        p = norm(path)
        for r in self._roots:
            if p == r or p.startswith(r + os.sep):
                return True
        return False

    def require(self, path: str) -> None:
        if not self.contains(path):
            raise UnsafePath(f"refusing target outside allow-list: {path!r}")


# Names that are never deleted regardless of rule, because losing them breaks
# the machine or the user's actual data rather than reclaiming junk. Rule
# authors cannot opt out of this list.
PROTECTED_NAMES = {
    "desktop.ini", "thumbs.db", ".ds_store",
    "boot.ini", "bcd", "ntldr", "ntdetect.com", "bootmgr",
    "pagefile.sys", "hiberfil.sys", "swapfile.sys", "dumpstack.log.tmp",
    "sam", "security", "software", "system", "default", "ntuser.dat",
    "ntuser.ini", "usrclass.dat",
}

# Extensions whose loss is data, not junk - a cleaner must never remove these
# by wildcard accident.
DATA_EXTENSIONS = {
    ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".pdf", ".rtf", ".odt",
    ".txt", ".md", ".csv", ".json", ".xml", ".yaml", ".yml", ".ini", ".cfg",
    ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tif", ".tiff", ".heic", ".raw",
    ".cr2", ".nef", ".arw", ".dng", ".psd", ".ai", ".indd", ".svg", ".webp",
    ".mp3", ".wav", ".flac", ".aac", ".m4a", ".ogg", ".wma",
    ".mp4", ".mkv", ".avi", ".mov", ".wmv", ".flv", ".webm", ".m4v",
    ".zip", ".7z", ".rar", ".tar", ".gz", ".bz2", ".xz", ".iso", ".img",
    ".py", ".js", ".ts", ".c", ".h", ".cpp", ".cs", ".java", ".go", ".rs",
    ".sql", ".db", ".sqlite", ".mdb", ".pst", ".ost", ".eml", ".msg",
    ".key", ".pem", ".pfx", ".p12", ".kdbx", ".gpg", ".asc",
}


def is_protected(name: str) -> bool:
    return name.lower() in PROTECTED_NAMES


def looks_like_data(name: str) -> bool:
    return os.path.splitext(name)[1].lower() in DATA_EXTENSIONS


def is_reparse(path: str) -> bool:
    """True for symlinks / junctions / mount points. We never descend these:
    a junction inside a scannable root can point anywhere, and following it
    would let a temp-file rule reach C:\\Windows\\System32."""
    try:
        st = os.lstat(path)
    except (OSError, ValueError):
        return False
    if stat.S_ISLNK(st.st_mode):
        return True
    if IS_WINDOWS:
        FILE_ATTRIBUTE_REPARSE_POINT = 0x400
        return bool(getattr(st, "st_file_attributes", 0) & FILE_ATTRIBUTE_REPARSE_POINT)
    return False


def walk(
    root: str,
    pattern: str = "*",
    recurse: bool = False,
    min_age_hours: float = 0.0,
    skip_dirs: set[str] | None = None,
    now: float | None = None,
):
    """Yield (path, size) for regular files under *root* matching *pattern*.

    - never follows reparse points
    - never yields directories
    - ignores unreadable subdirectories instead of aborting the scan
    - ``min_age_hours`` skips files modified more recently than the cut-off,
      which is how we avoid pulling a temp file out from under a running
      installer.
    """
    import time

    if now is None:
        now = time.time()
    cutoff = now - (min_age_hours * 3600.0) if min_age_hours > 0 else None
    pats = [p.strip().lower() for p in pattern.split(";") if p.strip()] or ["*"]
    skip = {s.lower() for s in (skip_dirs or ())}

    def match(name: str) -> bool:
        n = name.lower()
        return any(fnmatch.fnmatchcase(n, p) for p in pats)

    def onerror(_e):
        return

    if not recurse:
        try:
            with os.scandir(root) as it:
                for de in it:
                    try:
                        if de.is_dir(follow_symlinks=False):
                            continue
                        if not de.is_file(follow_symlinks=False):
                            continue
                    except OSError:
                        continue
                    if not match(de.name):
                        continue
                    try:
                        st = de.stat(follow_symlinks=False)
                    except OSError:
                        continue
                    if cutoff is not None and st.st_mtime > cutoff:
                        continue
                    yield de.path, st.st_size
        except (OSError, ValueError):
            return
        return

    for dirpath, dirnames, filenames in os.walk(root, topdown=True, onerror=onerror, followlinks=False):
        # prune junctions and explicitly-skipped dirs before descending
        keep = []
        for d in dirnames:
            if d.lower() in skip:
                continue
            full = os.path.join(dirpath, d)
            if is_reparse(full):
                continue
            keep.append(d)
        dirnames[:] = keep

        for fname in filenames:
            full = os.path.join(dirpath, fname)
            if not match(fname):
                continue
            try:
                st = os.stat(full, follow_symlinks=False)
            except OSError:
                continue
            if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
                continue
            if cutoff is not None and st.st_mtime > cutoff:
                continue
            yield full, st.st_size


def dir_size(path: str) -> int:
    total = 0
    for _p, size in walk(path, "*", recurse=True):
        total += size
    return total


# --------------------------------------------------------------------------
# Windows API
# --------------------------------------------------------------------------

_advapi = ctypes.WinDLL("advapi32", use_last_error=True) if IS_WINDOWS else None
_shell32 = ctypes.WinDLL("shell32", use_last_error=True) if IS_WINDOWS else None
_kernel32 = ctypes.WinDLL("kernel32", use_last_error=True) if IS_WINDOWS else None


def is_admin() -> bool:
    if not IS_WINDOWS:
        return os.geteuid() == 0
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def relaunch_as_admin(argv: list[str] | None = None) -> bool:
    """Re-launch the current interpreter elevated. Returns True if the new
    process was started (caller should then exit)."""
    if not IS_WINDOWS:
        return False
    argv = list(argv if argv is not None else sys.argv)
    if getattr(sys, "frozen", False):
        exe, params = sys.executable, " ".join(f'"{a}"' for a in argv[1:])
    else:
        exe = sys.executable
        params = " ".join(f'"{a}"' for a in argv)
    try:
        rc = ctypes.windll.shell32.ShellExecuteW(None, "runas", exe, params, os.getcwd(), 1)
        return rc > 32
    except Exception:
        return False


# --- process enumeration (no psutil dependency) ---------------------------

_TH32CS_SNAPPROCESS = 0x00000002


class PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("cntUsage", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("th32DefaultHeapID", ctypes.POINTER(ctypes.c_ulong)),
        ("th32ModuleID", wintypes.DWORD),
        ("cntThreads", wintypes.DWORD),
        ("th32ParentProcessID", wintypes.DWORD),
        ("pcPriClassBase", ctypes.c_long),
        ("dwFlags", wintypes.DWORD),
        ("szExeFile", wintypes.WCHAR * 260),
    ]


def running_process_names() -> set[str]:
    """Lower-case image names of currently running processes."""
    names: set[str] = set()
    if not IS_WINDOWS:
        return names
    snap = _kernel32.CreateToolhelp32Snapshot(_TH32CS_SNAPPROCESS, 0)
    if snap in (0, -1):
        return names
    try:
        entry = PROCESSENTRY32W()
        entry.dwSize = ctypes.sizeof(PROCESSENTRY32W)
        ok = _kernel32.Process32FirstW(snap, ctypes.byref(entry))
        while ok:
            names.add(entry.szExeFile.lower())
            ok = _kernel32.Process32NextW(snap, ctypes.byref(entry))
    finally:
        _kernel32.CloseHandle(snap)
    return names


# --- recycle bin ----------------------------------------------------------

class SHFILEOPSTRUCTW(ctypes.Structure):
    _fields_ = [
        ("hwnd", wintypes.HWND),
        ("wFunc", wintypes.UINT),
        ("pFrom", ctypes.c_wchar_p),
        ("pTo", ctypes.c_wchar_p),
        ("fFlags", ctypes.c_ushort),
        ("fAnyOperationsAborted", wintypes.BOOL),
        ("hNameMappings", ctypes.c_void_p),
        ("lpszProgressTitle", ctypes.c_wchar_p),
    ]


FO_DELETE = 0x0003
FOF_SILENT = 0x0004
FOF_NOCONFIRMATION = 0x0010
FOF_ALLOWUNDO = 0x0040
FOF_NOERRORUI = 0x0400
FOF_NOCONFIRMMKDIR = 0x0200


def recycle(paths: list[str]) -> tuple[int, int]:
    """Move *paths* to the Recycle Bin. Returns (ok_count, fail_count).

    This is the safe default for anything with a non-trivial risk level: a
    mistaken clean stays recoverable.
    """
    if not IS_WINDOWS or not paths:
        return 0, len(paths)
    ok = fail = 0
    # SHFileOperationW wants a double-NUL-terminated list; batch in chunks so
    # one bad path does not fail the whole operation.
    CHUNK = 64
    for i in range(0, len(paths), CHUNK):
        batch = paths[i:i + CHUNK]
        joined = "\0".join(batch) + "\0\0"
        op = SHFILEOPSTRUCTW()
        op.hwnd = None
        op.wFunc = FO_DELETE
        op.pFrom = joined
        op.pTo = None
        op.fFlags = FOF_ALLOWUNDO | FOF_NOCONFIRMATION | FOF_SILENT | FOF_NOERRORUI | FOF_NOCONFIRMMKDIR
        op.fAnyOperationsAborted = False
        op.hNameMappings = None
        op.lpszProgressTitle = None
        res = _shell32.SHFileOperationW(ctypes.byref(op))
        if res == 0 and not op.fAnyOperationsAborted:
            ok += len(batch)
        else:
            # fall back to per-item so partial failures are counted honestly
            for p in batch:
                single = SHFILEOPSTRUCTW()
                single.hwnd = None
                single.wFunc = FO_DELETE
                single.pFrom = p + "\0\0"
                single.pTo = None
                single.fFlags = op.fFlags
                single.fAnyOperationsAborted = False
                single.hNameMappings = None
                single.lpszProgressTitle = None
                r = _shell32.SHFileOperationW(ctypes.byref(single))
                if r == 0 and not single.fAnyOperationsAborted:
                    ok += 1
                else:
                    fail += 1
    return ok, fail


def empty_recycle_bin() -> bool:
    if not IS_WINDOWS:
        return False
    flags = 0x00000001 | 0x00000002 | 0x00000004  # NOCONFIRMATION|NOPROGRESSUI|NOSOUND
    try:
        return _shell32.SHEmptyRecycleBinW(None, None, flags) == 0
    except Exception:
        return False


# --- misc ----------------------------------------------------------------

def long_path(p: str) -> str:
    """Prefix for paths beyond MAX_PATH."""
    if IS_WINDOWS and not p.startswith("\\\\?\\") and len(p) > 240:
        if p.startswith("\\\\"):
            return "\\\\?\\UNC\\" + p[2:]
        return "\\\\?\\" + p
    return p


def delete_file(path: str) -> None:
    """Unlink a single file, tolerating read-only and long paths."""
    try:
        os.unlink(long_path(path))
    except PermissionError:
        try:
            os.chmod(long_path(path), stat.S_IWRITE)
            os.unlink(long_path(path))
        except OSError:
            raise


def remove_empty_dirs(root: str, guard: PathGuard | None = None) -> int:
    """Remove empty directories beneath *root* (deepest first). The root
    itself is never removed - callers may remove it explicitly."""
    removed = 0
    for dirpath, dirnames, filenames in os.walk(root, topdown=False, onerror=lambda e: None):
        if norm(dirpath) == norm(root):
            continue
        if guard is not None and not guard.contains(dirpath):
            continue
        if is_reparse(dirpath):
            continue
        try:
            os.rmdir(dirpath)  # only succeeds when empty - that is the point
            removed += 1
        except OSError:
            pass
    return removed


class Cancel:
    """Cooperative cancellation shared between GUI/CLI and the scanner."""

    def __init__(self) -> None:
        self._ev = threading.Event()

    def set(self) -> None:
        self._ev.set()

    def is_set(self) -> bool:
        return self._ev.is_set()

def state_dir() -> str:
    """Where Sweep keeps logs, backups, the keep-list and imported rules.

    ``SWEEP_HOME`` overrides it, which keeps the tool testable and lets a user
    relocate its state (e.g. onto the same volume as the data).
    """
    override = os.environ.get("SWEEP_HOME")
    if override:
        return override
    root = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
    return os.path.join(root, "Sweep")


def relaunch_elevated(params: str, cwd: str | None = None,
                      exe: str | None = None) -> bool:
    """Start an elevated instance of the current interpreter.

    *params* is the argument string only (no executable). *exe* overrides the
    interpreter, which lets the GUI relaunch through ``pythonw.exe`` so no
    console window flashes. Returns True when the shell accepted the request;
    the caller should then exit.
    """
    if not IS_WINDOWS:
        return False
    try:
        rc = ctypes.windll.shell32.ShellExecuteW(
            None, "runas", exe or sys.executable, params, cwd or os.getcwd(), 1)
        return rc > 32
    except Exception:
        return False
