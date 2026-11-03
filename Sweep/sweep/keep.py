"""
Sweep - cookie keep-list.

Deleting cookies logs you out of everything. A keep-list makes that a choice:
domains listed here survive a cookie clean.

Chromium-family browsers store cookies in a SQLite file with a ``cookies`` table
keyed by ``host_key``; Firefox uses ``moz_cookies`` keyed by ``host``. Both are
handled, and the database is copied to a backup before any row is removed.
"""

from __future__ import annotations

import json
import os
import shutil
import sqlite3
import time
from dataclasses import dataclass, field

from . import base

def default_path() -> str:
    return os.path.join(base.state_dir(), "keep.json")


@dataclass
class KeepList:
    domains: list[str] = field(default_factory=list)
    path: str = field(default_factory=default_path)
    #: Set when the file existed but could not be read. Saving over it would
    #: destroy a list the user believes is intact.
    load_error: str = ""

    # ---- persistence ---------------------------------------------------
    @classmethod
    def load(cls, path: str | None = None) -> "KeepList":
        p = path or default_path()
        try:
            with open(p, encoding="utf-8") as fh:
                blob = json.load(fh)
            doms = [str(d).strip().lower() for d in blob.get("domains", []) if str(d).strip()]
            return cls(domains=sorted(set(doms)), path=p)
        except FileNotFoundError:
            return cls(domains=[], path=p)      # genuinely no list yet
        except (OSError, ValueError) as exc:
            return cls(domains=[], path=p, load_error=str(exc))

    def save(self, path: str | None = None) -> str:
        p = path or self.path
        os.makedirs(os.path.dirname(p) or ".", exist_ok=True)
        if self.load_error and os.path.exists(p):
            # Keep a copy of what could not be parsed before replacing it.
            try:
                with open(p, "rb") as src, open(p + ".corrupt", "wb") as dst:
                    dst.write(src.read())
            except OSError:
                pass
        tmp = p + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump({"domains": self.domains}, fh, indent=2)
        os.replace(tmp, p)
        self.path = p
        return p

    # ---- membership ----------------------------------------------------
    def add(self, domain: str) -> None:
        d = _normalise(domain)
        if d and d not in self.domains:
            self.domains.append(d)
            self.domains.sort()

    def remove(self, domain: str) -> None:
        d = _normalise(domain)
        if d in self.domains:
            self.domains.remove(d)

    def keeps(self, host: str) -> bool:
        return matches(host, self.domains)


def _normalise(domain: str) -> str:
    d = domain.strip().lower()
    for prefix in ("https://", "http://"):
        if d.startswith(prefix):
            d = d[len(prefix):]
    d = d.split("/")[0]
    if d.startswith("www."):
        d = d[4:]
    return d


def matches(host: str, domains: list[str]) -> bool:
    """True when *host* is, or is a subdomain of, a kept domain."""
    if not host:
        return False
    h = host.lower().lstrip(".")
    for d in domains:
        if h == d or h.endswith("." + d):
            return True
    return False


@dataclass
class FilterResult:
    kept: int = 0
    removed: int = 0
    db: str = ""
    backup: str = ""
    error: str = ""
    table: str = ""


def filter_cookies(db_path: str, domains: list[str],
                   make_backup: bool = True) -> FilterResult:
    """Delete cookies whose host is not kept. Preserves every kept cookie."""
    res = FilterResult(db=db_path)
    if not os.path.isfile(db_path):
        res.error = "no cookie database"
        return res
    if not domains:
        res.error = "keep-list is empty; refuse to delete every cookie silently"
        return res

    if make_backup:
        try:
            stamp = time.strftime("%Y%m%d-%H%M%S")
            backup = f"{db_path}.sweep-{stamp}.bak"
            shutil.copy2(db_path, backup)
            res.backup = backup
        except OSError as exc:
            res.error = f"could not back up cookie db: {exc}"
            return res

    try:
        conn = sqlite3.connect(f"file:{db_path}?mode=rw", uri=True, timeout=5)
    except sqlite3.Error as exc:
        res.error = f"cannot open cookie db: {exc}"
        return res

    try:
        tables = {row[0].lower() for row in
                  conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if "cookies" in tables:
            table, col = "cookies", "host_key"
        elif "moz_cookies" in tables:
            table, col = "moz_cookies", "host"
        else:
            res.error = "unrecognised cookie database layout"
            return res
        res.table = table

        rows = list(conn.execute(f"SELECT rowid, {col} FROM {table}"))
        res.kept = sum(1 for _rid, h in rows if matches(h or "", domains))
        doomed = [rid for rid, h in rows if not matches(h or "", domains)]
        res.removed = len(doomed)
        if doomed:
            conn.executemany(f"DELETE FROM {table} WHERE rowid = ?",
                             ((r,) for r in doomed))
        conn.commit()
        try:
            conn.execute("VACUUM")
        except sqlite3.Error:
            pass
        return res
    except sqlite3.Error as exc:
        res.error = f"cookie cleanup failed: {exc}"
        return res
    finally:
        conn.close()


#: Cookie databases Sweep knows how to filter, relative to a profile root.
def candidate_dbs(localappdata: str | None = None,
                  appdata: str | None = None) -> list[tuple[str, str]]:
    """Return (label, path) pairs for cookie stores that exist."""
    la = localappdata or os.environ.get("LOCALAPPDATA", "")
    ap = appdata or os.environ.get("APPDATA", "")
    out: list[tuple[str, str]] = []

    chromium = {
        "Chrome": os.path.join(la, "Google", "Chrome", "User Data"),
        "Edge": os.path.join(la, "Microsoft", "Edge", "User Data"),
        "Brave": os.path.join(la, "BraveSoftware", "Brave-Browser", "User Data"),
        "Vivaldi": os.path.join(la, "Vivaldi", "User Data"),
        "Chromium": os.path.join(la, "Chromium", "User Data"),
    }
    for label, root in chromium.items():
        if not os.path.isdir(root):
            continue
        for profile in _profiles(root):
            for rel in (os.path.join("Network", "Cookies"), "Cookies"):
                p = os.path.join(profile, rel)
                if os.path.isfile(p):
                    out.append((f"{label} - {os.path.basename(profile)}", p))

    for label, folder in (("Firefox", os.path.join(ap, "Mozilla", "Firefox", "Profiles")),
                          ("Thunderbird", os.path.join(ap, "Thunderbird", "Profiles"))):
        if not os.path.isdir(folder):
            continue
        try:
            for entry in os.scandir(folder):
                if not entry.is_dir(follow_symlinks=False):
                    continue
                p = os.path.join(entry.path, "cookies.sqlite")
                if os.path.isfile(p):
                    out.append((f"{label} - {entry.name}", p))
        except OSError:
            continue
    return out


def _profiles(user_data: str) -> list[str]:
    out = []
    try:
        for entry in os.scandir(user_data):
            if not entry.is_dir(follow_symlinks=False):
                continue
            n = entry.name.lower()
            if n in ("default", "guest profile", "system profile") or n.startswith("profile"):
                out.append(entry.path)
    except OSError:
        pass
    return out
