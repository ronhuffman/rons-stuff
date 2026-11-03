"""
Sweep - scan engine.

The scanner is the only component allowed to decide *what* is cleanable. It
produces an explicit, deduplicated list of (path, size) pairs plus the totals
shown in the UI. The cleaner is then constrained to that list, so a pattern
bug can never expand into a delete the user did not see previewed.
"""

from __future__ import annotations

import glob
import os
import re
import time
from dataclasses import dataclass, field

from . import base, rules


# --------------------------------------------------------------------------
# results
# --------------------------------------------------------------------------

@dataclass
class RuleResult:
    rule_id: str
    name: str
    group: str
    risk: str
    needs_admin: bool
    action: str | None = None
    extra_actions: list[str] = field(default_factory=list)
    handler: str | None = None
    long_running: bool = False
    size: int = 0
    count: int = 0
    files: list[tuple[str, int]] = field(default_factory=list)
    reg_items: list = field(default_factory=list)
    absent: bool = False        # every target path was missing
    denied: int = 0             # directories/files we could not read
    skipped: int = 0            # matched but excluded (age, protection, dedupe)
    error: str | None = None

    @property
    def empty(self) -> bool:
        return self.count == 0 and self.action is None


@dataclass
class ScanResult:
    results: list[RuleResult] = field(default_factory=list)
    duration: float = 0.0
    files_seen: int = 0
    allowlist: set[str] = field(default_factory=set)
    #: True when the scan stopped early, so totals are a lower bound.
    cancelled: bool = False

    @property
    def total_size(self) -> int:
        return sum(r.size for r in self.results)

    @property
    def total_count(self) -> int:
        return sum(r.count for r in self.results)

    def actionable(self) -> list[RuleResult]:
        return [r for r in self.results if not r.empty and r.error is None]


# --------------------------------------------------------------------------
# path templates
# --------------------------------------------------------------------------

def _escape_segments(template: str) -> str:
    """Escape glob metacharacters in literal path segments so that a folder
    name containing '[' cannot change the meaning of the pattern."""
    parts = template.split("\\")
    out = []
    for seg in parts:
        out.append(seg if "*" in seg else glob.escape(seg))
    return "\\".join(out)


def expand_targets(template: str, refused: list[str] | None = None) -> list[str]:
    """Expand %VARS% and wildcard directory segments into concrete paths.

    A folder that is, or sits beneath, a symlink, junction or mount point is
    dropped (and listed in *refused*): the walk never follows links inside a
    root, and the root itself must not be one either.
    """
    p = base.expand(template)
    if not p:
        return []
    if "%" in p and re.search(r"%[A-Za-z0-9_()]+%", p):
        return []           # unresolved variable -> rule does not apply here
    if "*" in p:
        try:
            found = glob.glob(_escape_segments(p))
        except (OSError, re.error):
            return []
        roots = sorted({f for f in found if os.path.isdir(f)})
    else:
        roots = [p] if os.path.isdir(p) else []
    safe = []
    for r in roots:
        if base.through_link(r):
            if refused is not None:
                refused.append(r)
            continue
        safe.append(r)
    return safe


# --------------------------------------------------------------------------
# walking
# --------------------------------------------------------------------------

def _match(name: str, pats: list[str]) -> bool:
    import fnmatch
    n = name.lower()
    for p in pats:
        if fnmatch.fnmatchcase(n, p):
            return True
    return False


def _walk(root: str, pats: list[str], recurse: bool, min_age_hours: float,
          now: float, out: list[tuple[str, int]], cancel: base.Cancel | None,
          stats: dict, deadline_check=None) -> None:
    """Depth-first walk that never follows reparse points and never aborts on
    a single unreadable directory."""
    cutoff = now - min_age_hours * 3600.0 if min_age_hours > 0 else None
    stack = [root]
    visited = 0

    while stack:
        if cancel is not None and cancel.is_set():
            return
        cur = stack.pop()
        try:
            with os.scandir(cur) as it:
                for de in it:
                    visited += 1
                    if deadline_check is not None and (visited & 0x3FF) == 0:
                        deadline_check()
                    try:
                        is_dir = de.is_dir(follow_symlinks=False)
                    except TimeoutError:
                        raise            # deadline, not a denial
                    except OSError:
                        stats["denied"] += 1
                        continue
                    if is_dir:
                        if not recurse:
                            continue
                        try:
                            if de.is_symlink():
                                continue
                        except OSError:
                            continue
                        if base.is_reparse(de.path):
                            stats["skipped"] += 1
                            continue
                        stack.append(de.path)
                        continue
                    try:
                        if not de.is_file(follow_symlinks=False):
                            continue
                    except OSError:
                        stats["denied"] += 1
                        continue
                    if pats and not _match(de.name, pats):
                        continue
                    if base.is_protected(de.name):
                        stats["skipped"] += 1
                        continue
                    try:
                        st = de.stat(follow_symlinks=False)
                    except OSError:
                        stats["denied"] += 1
                        continue
                    if cutoff is not None and st.st_mtime > cutoff:
                        stats["skipped"] += 1
                        continue
                    out.append((de.path, st.st_size))
                    stats["files"] += 1
        except PermissionError:
            stats["denied"] += 1
        except OSError:
            stats["denied"] += 1


# --------------------------------------------------------------------------
# scan
# --------------------------------------------------------------------------

def _scan_rule(rule: dict, cancel: "base.Cancel | None", now: float,
               min_age_hours: float, check_deadline) -> tuple[RuleResult, dict]:
    """Scan a single rule. Pure with respect to other rules: it never touches
    shared state, so rules can run concurrently."""
    rr = RuleResult(
        rule_id=rule["id"], name=rule["name"], group=rule["group"],
        risk=rule["risk"], needs_admin=bool(rule.get("needs_admin")),
        action=rule.get("action"), long_running=bool(rule.get("long_running")),
        extra_actions=list(rule.get("extra_actions") or []),
        handler=rule.get("handler"),
    )
    stats = {"files": 0, "denied": 0, "skipped": 0}
    targets_present = 0

    if rule.get("action") and not rule.get("files"):
        return rr, stats           # pure system action, no enumeration

    try:
        for ent in rule.get("files", []):
            refused: list[str] = []
            expanded = expand_targets(ent["path"], refused)
            if refused:
                # Present, but reached through a link: report, never clean.
                stats["skipped"] += len(refused)
                targets_present += len(refused)
            if not expanded:
                continue
            targets_present += len(expanded)
            pats = [p.strip().lower() for p in ent["pattern"].split(";") if p.strip()] or ["*"]
            for root in expanded:
                bucket: list[tuple[str, int]] = []
                _walk(root, pats, bool(ent.get("recurse", True)), min_age_hours,
                      now, bucket, cancel, stats, check_deadline)
                if cancel is not None and cancel.is_set():
                    break
                rr.files.extend(bucket)
            if cancel is not None and cancel.is_set():
                break
    except TimeoutError as exc:
        rr.error = str(exc)
    except Exception as exc:                      # never let one rule kill the run
        rr.error = f"{type(exc).__name__}: {exc}"

    # ---- registry: explicit locations declared by the rule --------------
    reg_specs = rule.get("reg") or []
    if reg_specs:
        from . import registry as regmod
        for spec in reg_specs:
            try:
                rr.reg_items.extend(regmod.scan_direct(spec))
            except OSError:
                stats["denied"] += 1        # unreadable, not clean
        targets_present += max(1, len(rr.reg_items))

    # ---- registry: orphan-detection category ----------------------------
    cat = rule.get("reg_scan")
    if cat:
        from . import registry as regmod
        reg_errors: list[str] = []
        rr.reg_items.extend(regmod.scan_category(cat, reg_errors))
        if reg_errors and not rr.reg_items:
            stats["denied"] += len(reg_errors)
        targets_present += max(1, len(rr.reg_items))

    rr.denied = stats["denied"]
    rr.skipped += stats["skipped"]
    rr.absent = targets_present == 0
    return rr, stats


def default_workers() -> int:
    """Rules are independent I/O jobs; a small pool hides disk latency without
    thrashing the spindle."""
    cpus = os.cpu_count() or 4
    return max(1, min(8, cpus))


def scan(rule_ids: list[str] | None = None,
         cancel: base.Cancel | None = None,
         progress=None,
         min_age_hours: float = 0.0,
         deadline_s: float | None = None,
         workers: int | None = None) -> ScanResult:
    """Scan the selected rules.

    Rules run concurrently on a bounded thread pool (``workers``); the results
    are merged in rule order so output is deterministic regardless of scheduling.
    ``progress(done, total, label, bytes_so_far)`` is called as rules finish.
    """
    selected = [r for r in rules.RULES if rule_ids is None or r["id"] in rule_ids]
    result = ScanResult()
    t0 = time.time()
    now = t0
    seen: set[str] = set()
    deadline = t0 + deadline_s if deadline_s else None
    total_rules = len(selected)
    if workers is None:
        workers = default_workers()
    workers = max(1, min(int(workers), total_rules or 1))

    def check_deadline():
        if deadline is not None and time.time() > deadline:
            raise TimeoutError("scan deadline exceeded")

    def merge(rr: RuleResult, stats: dict) -> None:
        """Apply cross-rule de-duplication and recompute totals."""
        kept: list[tuple[str, int]] = []
        size = 0
        for path, fsize in rr.files:
            key = base.norm(path)
            if key in seen:
                rr.skipped += 1
                continue
            seen.add(key)
            kept.append((path, fsize))
            size += fsize
        rr.files = kept
        rr.size = size
        rr.count = len(rr.files) + len(rr.reg_items)
        result.files_seen += stats["files"]
        result.results.append(rr)

    if workers <= 1 or total_rules <= 2:
        for idx, rule in enumerate(selected):
            if cancel is not None and cancel.is_set():
                result.cancelled = True
                break
            if progress:
                progress(idx, total_rules, rule["name"], result.total_size)
            rr, stats = _scan_rule(rule, cancel, now, min_age_hours, check_deadline)
            merge(rr, stats)
    else:
        from concurrent.futures import ThreadPoolExecutor, as_completed

        done = 0
        slots: dict[int, tuple[RuleResult, dict]] = {}
        with ThreadPoolExecutor(max_workers=workers,
                                thread_name_prefix="sweep-scan") as pool:
            futures = {
                pool.submit(_scan_rule, rule, cancel, now, min_age_hours,
                            check_deadline): (i, rule)
                for i, rule in enumerate(selected)
            }
            for fut in as_completed(futures):
                i, rule = futures[fut]
                try:
                    slots[i] = fut.result()
                except Exception as exc:          # defensive: pool should not raise
                    rr = RuleResult(rule_id=rule["id"], name=rule["name"],
                                    group=rule["group"], risk=rule["risk"],
                                    needs_admin=bool(rule.get("needs_admin")))
                    rr.error = f"{type(exc).__name__}: {exc}"
                    slots[i] = (rr, {"files": 0, "denied": 0, "skipped": 0})
                done += 1
                if progress:
                    progress(done, total_rules, rule["name"], result.total_size)

        for i in range(total_rules):
            if i in slots:
                rr, stats = slots[i]
                merge(rr, stats)

    result.duration = time.time() - t0
    result.allowlist = seen
    if progress:
        progress(total_rules, total_rules, "done", result.total_size)
    return result


# --------------------------------------------------------------------------
# reporting helpers
# --------------------------------------------------------------------------

def group_totals(res: ScanResult) -> dict[str, tuple[int, int]]:
    """group -> (bytes, files) for rules that actually found something."""
    out: dict[str, list[int]] = {}
    for r in res.results:
        if r.empty or r.error:
            continue
        cur = out.setdefault(r.group, [0, 0])
        cur[0] += r.size
        cur[1] += r.count
    return {g: (v[0], v[1]) for g, v in out.items()}
