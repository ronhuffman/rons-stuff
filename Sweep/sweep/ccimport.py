"""
Sweep - import an existing CCleaner ruleset.

CCleaner ships its cleaning rules as a plain-text ``ccleaner.ini`` inside its own
install directory. Rather than re-authoring 769 categories by hand (and getting
them subtly wrong), Sweep can read *your local copy* at runtime and execute those
rules through Sweep's engine - allow-listing, junction-safety, protected names,
caution-never-default.

Nothing is copied into this project or redistributed: the file stays on the
machine that already has a licence to it, and the import produces a local rule
file in Sweep's own format.

Why this is not just a wrapper
------------------------------
The imported rules go through a validator first. A rule is dropped when its
target is structurally dangerous - a drive root, a profile root, or a system
directory matched with an executable/binary pattern. CCleaner's own engine will
happily run some of those; Sweep will not.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field

from . import base

SECTION_RE = re.compile(r"^\[(.+)\]$")
KEY_RE = re.compile(r"^(FileKey|RegKey|ExcludeKey|Action|OnFile|DetectFile|DetectOS"
                    r"|Detect|Default|Tags|Author|ID|WarningRef|Risk|ActiveProcesses"
                    r"|ActiveServices|MaxProcessStopTimeout|AdditionalUsers)\d*$",
                    re.IGNORECASE)

#: Extensions that must never be matched by a wildcard inside a system directory.
FORBIDDEN_IN_SYSTEM = {
    ".exe", ".dll", ".sys", ".drv", ".ocx", ".cpl", ".mui", ".ax", ".efi",
    ".msi", ".msp", ".cat", ".inf", ".manifest",
}

SYSTEM_ROOTS = ("%windir%", "%systemroot%", "%programfiles%", "%programfiles(x86)%",
                "%systemdrive%", "c:\\windows")

#: Action names Sweep can execute. Anything else is reported, not silently lost.
SUPPORTED_ACTIONS = {
    "EmptyRecycleBin": "empty_recycle_bin",
    "CleanDNSCache": "flush_dns",
    "CleanClipboard": "clear_clipboard",
    "CleanWindowsEventLogs": "clear_event_logs",
    "TaskbarJumpLists": "clear_jump_lists",
    "ShellAddToRecentDocs": "clear_recent_docs",
    "CleanEnvironmentPath": "clean_environment_path",
    "CleanNetworkPasswords": "clear_network_passwords",
    "CleanOfficeMRU": "clear_office_mru",
    "RemoveEmptyDirectories": "remove_empty_directories",
}

RISK_SAFE_HINTS = ("cache", "temp", "tmp", "log", "crash", "dump", "trace",
                   "thumb", "shader", "fetch", "update")
RISK_PRIVATE_HINTS = ("cookie", "history", "password", "login", "session",
                      "form", "autofill", "credential", "recent", "mru",
                      "typed", "account")

#: `Registry|<Name>` categories that Sweep can verify. Everything else is
#: reported as unimplemented instead of silently doing nothing.
REGISTRY_ACTIONS = {
    "MissingSharedDlls": "shared_dlls",
    "MUICache": "muicache",
    "ApplicationPaths": "app_paths",
    "OpenWithApplication": "open_with",
    "ObsoleteSoftware": "obsolete_software",
    "RunAtStartup": "run_at_startup",
    "SoundEvents": "sound_events",
    "Fonts": "fonts",
}


@dataclass
class ImportReport:
    rules: list[dict] = field(default_factory=list)
    sections_seen: int = 0
    sections_kept: int = 0
    file_rules: int = 0
    reg_rules: int = 0
    actions: int = 0
    dropped_unsafe: list[tuple[str, str]] = field(default_factory=list)
    unknown_actions: dict[str, int] = field(default_factory=dict)
    source: str = ""

    def summary(self) -> str:
        return (f"{self.sections_kept}/{self.sections_seen} sections, "
                f"{self.file_rules} file rules, {self.reg_rules} registry rules, "
                f"{self.actions} actions, "
                f"{len(self.dropped_unsafe)} unsafe targets dropped")


# --------------------------------------------------------------------------
# discovery
# --------------------------------------------------------------------------

def find_installations() -> list[str]:
    """Locate any local CCleaner ruleset.

    The ruleset lives at ``<install dir>\\ccleaner.ini``, where the install dir
    is usually ``Program Files\\Piriform\\CCleaner 7`` - so the vendor level has
    to be searched too, not just the top of Program Files.
    """
    found: list[str] = []
    roots = [os.environ.get("ProgramFiles", r"C:\Program Files"),
             os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")]
    seen: set[str] = set()

    def consider(directory: str) -> None:
        ini = os.path.join(directory, "ccleaner.ini")
        if os.path.isfile(ini):
            key = os.path.normcase(ini)
            if key not in seen:
                seen.add(key)
                found.append(ini)

    for root in roots:
        if not root or not os.path.isdir(root):
            continue
        consider(root)
        try:
            level1 = [e for e in os.scandir(root) if e.is_dir(follow_symlinks=False)]
        except OSError:
            continue
        for vendor in level1:
            consider(vendor.path)
            if "ccleaner" not in vendor.name.lower() and "piriform" not in vendor.name.lower():
                continue
            try:
                for sub in os.scandir(vendor.path):
                    if sub.is_dir(follow_symlinks=False):
                        consider(sub.path)
            except OSError:
                continue
    return found


# --------------------------------------------------------------------------
# parsing
# --------------------------------------------------------------------------

def _parse_sections(path: str) -> dict[str, list[tuple[str, str]]]:
    sections: dict[str, list[tuple[str, str]]] = {}
    cur: str | None = None
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            s = line.strip()
            if not s or s.startswith(";"):
                continue
            m = SECTION_RE.match(s)
            if m:
                cur = m.group(1).strip()
                sections.setdefault(cur, [])
                continue
            if cur is None or "=" not in s:
                continue
            k, v = s.split("=", 1)
            k = k.strip()
            k = re.sub(r"\d+$", "", k)          # FileKey12 -> FileKey
            sections[cur].append((k, v.strip()))
    return sections


def _parse_rule_vars(entries: list[tuple[str, str]]) -> dict[str, str]:
    return {k: v for k, v in entries}


def _expand_vars(path: str, varz: dict[str, str], depth: int = 0) -> list[str]:
    """Expand %VAR% references, including vars that expand to a comma list of
    directory patterns (CCleaner uses this heavily for browser profiles)."""
    if depth > 4:
        return [path]

    def one(p: str) -> list[str]:
        m = re.search(r"%([A-Za-z0-9_()]+)%", p)
        if not m:
            return [p]
        name = m.group(1)
        if name in varz:
            repl_raw = varz[name]
        else:
            env = os.environ.get(name)
            if env is None:
                return [p]                      # unresolvable -> leave for env expand
            repl_raw = env
        out: list[str] = []
        for piece in repl_raw.split(","):
            piece = piece.strip()
            if not piece:
                continue
            out.extend(one(p[:m.start()] + piece + p[m.end():]))
        return out

    return one(path)


def _looks_system(path: str) -> bool:
    low = path.lower()
    return any(low.startswith(r) for r in SYSTEM_ROOTS)


def validate_target(path: str, pattern: str, recurse: bool = False) -> str | None:
    """Return a reason to drop this (path, pattern), or None if it is safe.

    The checks are structural and deliberately narrow. Rejecting everything
    under ``C:\\Windows`` would also reject ``C:\\Windows|*.log``, which is
    legitimate junk cleanup, so the rule is:

      * a drive root, a profile root, or the Windows root matched with an
        unbounded pattern is refused;
      * a system directory matched with an executable/binary pattern is refused;
      * otherwise the target is allowed and the engine's own guards apply.
    """
    norm = base.norm(base.expand(path))
    if not norm:
        return "empty path"

    _drive, rest = os.path.splitdrive(norm)
    if rest.strip("\\/") == "":
        return "targets a drive root"

    unbounded = pattern.strip().lower() in ("*", "*.*", "?*", "*.?")

    # roots that must never be *swept*. A literal filename inside one of them
    # (e.g. %USERPROFILE%|QTPlayerSession.xml) is a normal targeted cleanup.
    win = base.norm(base.expand("%windir%")).rstrip("\\")
    wild = any(ch in pattern for ch in "*?")
    user = base.norm(base.expand("%userprofile%")).rstrip("\\")
    if norm.rstrip("\\") == user and (wild or recurse):
        return "targets the user profile root"
    for bad in ("%appdata%", "%localappdata%", "%programdata%"):
        if norm.rstrip("\\") == base.norm(base.expand(bad)).rstrip("\\") and (wild or recurse):
            return "targets a profile root"
    if norm.rstrip("\\") == win and (unbounded or recurse):
        return "sweeps the Windows directory"

    # system directories must not be matched against binaries
    if _looks_system(path):
        for p in (x.strip().lower() for x in pattern.split(";") if x.strip()):
            # note: os.path.splitext("*.dll") gives (".dll", "") because a
            # leading dot reads as a dotfile, so split on the last dot instead
            ext = ("." + p.rsplit(".", 1)[-1]) if "." in p else ""
            if ext in FORBIDDEN_IN_SYSTEM:
                return f"would match system binaries ({p})"
            if p == "*" and recurse and norm.rstrip("\\") in (
                    win, base.norm(base.expand("%programfiles%")).rstrip("\\")):
                return "recursive unbounded sweep of a system root"
    return None


def _risk_for(name: str) -> str:
    low = name.lower()
    if any(h in low for h in RISK_PRIVATE_HINTS):
        return "caution"
    if any(h in low for h in RISK_SAFE_HINTS):
        return "safe"
    return "moderate"


def _group_for(name: str, tags: list[str]) -> str:
    if " - " in name:
        return name.split(" - ", 1)[0].strip()
    tagset = {t.strip().lower() for t in tags}
    if tagset & {"system", "microsoft", "ccsystem", "ccwindows", "ccregistry", "registry"}:
        return "Windows (imported)"
    if tagset & {"browser", "edge", "firefox", "chrome", "opera"}:
        return "Browsers (imported)"
    return "Applications (imported)"


def parse(path: str) -> ImportReport:
    """Turn a ccleaner.ini into Sweep rules."""
    sections = _parse_sections(path)
    varz = _parse_rule_vars(sections.get("Rule Vars", []))
    report = ImportReport(source=path)

    for raw_name, entries in sections.items():
        if raw_name.lower() == "rule vars":
            continue
        report.sections_seen += 1

        meta: dict[str, list[str]] = {}
        for k, v in entries:
            meta.setdefault(k.lower(), []).append(v)

        default = (meta.get("default", ["false"])[0].strip().lower() in ("true", "1", "yes"))
        tags = [t.strip() for t in ",".join(meta.get("tags", [])).split(",") if t.strip()]
        risk = _risk_for(raw_name)
        procs = [p.strip() for p in ",".join(meta.get("activeprocesses", [])).split(",")
                 if p.strip() and p.strip().lower() != "explorer.exe"]

        files: list[dict] = []
        for spec in meta.get("filekey", []):
            parts = spec.split("|")
            raw_path = parts[0].strip()
            pattern = parts[1].strip() if len(parts) > 1 and parts[1].strip() else "*"
            flags = ",".join(parts[2:]).upper() if len(parts) > 2 else ""
            recurse = "RECURSE" in flags
            remove_self = "REMOVESELF" in flags

            # `path\*` means "everything directly in path"
            trimmed = raw_path
            if trimmed.endswith("\\*") or trimmed.endswith("/*"):
                trimmed = trimmed[:-2]
                if pattern == "*":
                    pattern = "*"
                    recurse = False

            for expanded in _expand_vars(trimmed, varz):
                reason = validate_target(expanded, pattern, recurse)
                if reason:
                    report.dropped_unsafe.append((raw_name, f"{expanded}|{pattern} ({reason})"))
                    continue
                files.append({"path": expanded, "pattern": pattern,
                              "recurse": recurse, "remove_empty": remove_self})
                report.file_rules += 1

        regs: list[dict] = []
        for spec in meta.get("regkey", []):
            parts = spec.split("|")
            key = parts[0].strip()
            if not key:
                continue
            value = parts[1].strip() if len(parts) > 1 and parts[1].strip() else None
            hive, _, sub = key.partition("\\")
            if hive.upper() not in ("HKCU", "HKLM"):
                continue
            regs.append({"hive": hive.upper(), "key": sub,
                         "value": value, "kind": "value" if value else "subkey"})
            report.reg_rules += 1

        actions: list[str] = []
        reg_scan: str | None = None
        for spec in meta.get("action", []):
            aname, _, arg = spec.partition("|")
            aname = aname.strip()
            arg = arg.strip()

            if aname == "DiskCleanup":
                if arg:
                    actions.append("clean_volumecache:" + arg)
                    report.actions += 1
                continue
            if aname == "Registry":
                cat = REGISTRY_ACTIONS.get(arg)
                if cat:
                    reg_scan = cat
                    report.actions += 1
                else:
                    key = f"Registry|{arg}"
                    report.unknown_actions[key] = report.unknown_actions.get(key, 0) + 1
                continue
            if aname == "CleanOfficeMRU":
                actions.append("clear_office_mru:" + (arg or "16.0"))
                report.actions += 1
                continue
            if aname == "CleanCredentials":
                actions.append("clear_credentials")
                report.actions += 1
                continue
            if aname == "CommonLastVisited":
                actions.append("clear_last_visited")
                report.actions += 1
                continue
            if aname in SUPPORTED_ACTIONS:
                actions.append(SUPPORTED_ACTIONS[aname])
                report.actions += 1
            else:
                report.unknown_actions[aname] = report.unknown_actions.get(aname, 0) + 1

        if not files and not regs and not actions and not reg_scan:
            continue

        rule: dict = {
            "id": "cc." + re.sub(r"[^a-z0-9]+", "-", raw_name.lower()).strip("-")[:60],
            "name": raw_name,
            "group": _group_for(raw_name, tags),
            "risk": risk,
            "default": default and risk != "caution",
            "why": "Imported from the local CCleaner ruleset.",
            "needs_admin": any(p.strip().lower().startswith(("%windir%", "%programdata%"))
                               for p in [f["path"] for f in files] + [""]) or
                           any(r["hive"] == "HKLM" for r in regs),
            "imported": True,
            "files": files,
            "reg": regs,
        }
        if procs:
            rule["procs"] = procs
        if reg_scan:
            rule["reg_scan"] = reg_scan
        if actions:
            # one action per rule; extras are folded into the first
            rule["action"] = actions[0]
            if len(actions) > 1:
                rule["extra_actions"] = actions[1:]
        report.rules.append(rule)
        report.sections_kept += 1

    return report


# --------------------------------------------------------------------------
# persistence
# --------------------------------------------------------------------------

def default_output() -> str:
    """Where an import is written when the caller does not choose a path."""
    return os.path.join(base.state_dir(), "imported-rules.json")


def save(report: ImportReport, out_path: str) -> str:
    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
    blob = {
        "version": 1,
        "source": report.source,
        "summary": report.summary(),
        "dropped_unsafe": report.dropped_unsafe,
        "unknown_actions": report.unknown_actions,
        "rules": report.rules,
    }
    tmp = out_path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(blob, fh, indent=1)
    os.replace(tmp, out_path)
    return out_path


def load(path: str) -> tuple[list[dict], dict]:
    with open(path, encoding="utf-8") as fh:
        blob = json.load(fh)
    rules = blob.get("rules", [])
    for r in rules:
        r.setdefault("imported", True)
        r.setdefault("files", [])
        r.setdefault("reg", [])
        r.setdefault("needs_admin", False)
        r.setdefault("risk", "moderate")
        r.setdefault("group", "Imported")
        r.setdefault("default", False)
        r.setdefault("why", "Imported from a local CCleaner ruleset.")
    return rules, blob
