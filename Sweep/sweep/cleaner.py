"""
Sweep - deletion executor.

Safety contract:
  * only paths present in the ScanResult allow-list may be deleted;
  * nothing is deleted unless *confirm* is set (the CLI requires --apply, the
    GUI requires a click);
  * every attempt is appended to a JSONL session log before it is retried or
    reported, so a clean can always be reconstructed after the fact;
  * failures are counted, never raised, so one locked file cannot abort a run.
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass, field

from . import base, scanner


@dataclass
class RuleOutcome:
    rule_id: str
    name: str
    risk: str
    deleted: int = 0
    bytes: int = 0
    locked: int = 0          # sharing/lock violation - close the app
    denied: int = 0          # permission denied - needs administrator
    registry: int = 0        # registry entries removed (reclaims no disk space)
    kept: int = 0            # items deliberately preserved (cookie keep-list)
    failed: int = 0
    errors: list[str] = field(default_factory=list)
    action_result: str | None = None


@dataclass
class CleanReport:
    outcomes: list[RuleOutcome] = field(default_factory=list)
    duration: float = 0.0
    simulated: bool = True
    mode: str = "dry-run"
    log_path: str | None = None
    #: Outcome of the pre-clean System Restore point, in plain language.
    #: Empty when no attempt was made (dry run, or nothing to delete).
    restore_point: str = ""

    @property
    def deleted(self) -> int:
        return sum(o.deleted for o in self.outcomes)

    @property
    def bytes(self) -> int:
        return sum(o.bytes for o in self.outcomes)

    @property
    def locked(self) -> int:
        return sum(o.locked for o in self.outcomes)

    @property
    def denied(self) -> int:
        return sum(o.denied for o in self.outcomes)

    @property
    def failed(self) -> int:
        return sum(o.failed for o in self.outcomes)


class SessionLog:
    """Append-only JSONL record of every delete attempt."""

    def __init__(self, path: str | None) -> None:
        self.path = path
        self._fh = None
        if not path:
            return
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            self._fh = open(path, "a", encoding="utf-8")
        except OSError:
            # A clean must not be blocked by a log that cannot be written.
            # Degrade to "no log" and say so through .path is None.
            self._fh = None
            self.path = None

    def write(self, **rec) -> None:
        if not self._fh:
            return
        rec.setdefault("ts", time.strftime("%Y-%m-%dT%H:%M:%S"))
        try:
            self._fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
        except OSError:
            pass

    def close(self) -> None:
        if self._fh:
            try:
                self._fh.flush()
                self._fh.close()
            except OSError:
                pass
            self._fh = None


# WinError codes that mean "someone has it open", not "we did something wrong"
_LOCKED = {32, 33}             # sharing violation, lock violation
_DENIED = {5}                  # access denied -> privileges, not contention


def _is_locked(exc: OSError) -> bool:
    if getattr(exc, "winerror", None) in _LOCKED:
        return True
    return exc.errno in (26,)          # ETXTBSY


def _is_denied(exc: OSError) -> bool:
    """Access denied must not be reported as 'file in use': the fix is to run
    elevated, not to close an application."""
    if getattr(exc, "winerror", None) in _DENIED:
        return True
    return exc.errno in (13,)          # EACCES


def default_backup_dir() -> str:
    """Where registry backups go when the caller does not choose a folder."""
    return os.path.join(base.state_dir(), "logs", "registry-backups")


def _resolve_keep(keep_domains: list[str] | None) -> tuple[list[str], str]:
    """The cookie keep-list to honour, and why it could not be read ("" if ok).

    ``None`` means "use the saved keep-list" - the safe default, so a caller
    that forgets to pass it (the GUI once did) still protects kept sites. An
    explicit list, even an empty one, is used as given.
    """
    if keep_domains is not None:
        return list(keep_domains), ""
    from . import keep as keepmod
    kl = keepmod.KeepList.load()
    return kl.domains, kl.load_error


def restore_point_note(ok: bool, msg: str) -> str:
    """The one-line restore-point outcome for a clean report.

    "created" only when a restore point was really made by this run. A skipped
    point (Windows allows one per 24 hours) and an unconfirmed one keep their
    own wording, so neither can be read as "created".
    """
    if ok:
        return "created - " + msg
    if msg.startswith(("skipped -", "unconfirmed -")):
        return msg
    return "not created - " + msg


def clean(scan_result: scanner.ScanResult,
          rule_ids: list[str] | None = None,
          confirm: bool = False,
          mode: str = "delete",
          progress=None,
          log: SessionLog | None = None,
          cancel: base.Cancel | None = None,
          backup_dir: str | None = None,
          passes: int = 1,
          keep_domains: list[str] | None = None,
          backup_cookies: bool = True,
          restore_point: bool = True) -> CleanReport:
    """Delete (or simulate deleting) the scanned files.

    mode: "dry-run" | "delete" | "recycle"

    When *restore_point* is set and anything is actually about to be deleted,
    a System Restore point is attempted first. Its outcome is reported on
    ``CleanReport.restore_point`` - never assumed, and never allowed to block a
    clean that the user asked for.

    Two protections do not depend on the caller remembering them: registry
    entries are always backed up before removal (to *backup_dir*, or
    :func:`default_backup_dir`), and cookie stores honour the saved keep-list
    unless *keep_domains* is passed explicitly.
    """
    simulated = mode == "dry-run" or not confirm
    report = CleanReport(simulated=simulated,
                         mode="dry-run" if simulated else mode,
                         log_path=log.path if log else None)
    t0 = time.time()

    if not confirm and mode != "dry-run":
        # Refuse rather than silently downgrade - the caller must be explicit.
        raise PermissionError("clean() requires confirm=True to modify anything")

    allow = scan_result.allowlist

    targets = [r for r in scan_result.results if not r.empty and r.error is None]
    if rule_ids is not None:
        targets = [r for r in targets if r.rule_id in rule_ids]

    # An allow-list is only meaningful when there are files to remove. A run
    # that consists solely of system actions (recycle bin, DISM) legitimately
    # has no file allow-list.
    if not allow and mode != "dry-run" and any(t.count for t in targets):
        raise PermissionError("allow-list is empty; refusing to run any deletion")

    keep_error = ""
    if any(t.handler == "cookie_dbs" for t in targets):
        keep_domains, keep_error = _resolve_keep(keep_domains)
    if backup_dir is None:
        backup_dir = default_backup_dir()

    # ---- undo point before anything is destroyed -----------------------
    # Only when something will genuinely be deleted. A dry run creates nothing,
    # and a run of pure system actions (DISM, recycle bin) has no files to undo.
    if restore_point and not simulated and any(t.count for t in targets):
        from . import system
        try:
            rp_ok, rp_msg = system.create_restore_point("Sweep: before cleaning")
        except Exception as exc:                       # never block the clean
            rp_ok, rp_msg = False, f"restore point failed: {exc}"
        report.restore_point = restore_point_note(rp_ok, rp_msg)
        if log:
            log.write(result="restore-point", ok=rp_ok, detail=rp_msg)

    total = len(targets)
    for idx, rr in enumerate(targets):
        if cancel is not None and cancel.is_set():
            break
        out = RuleOutcome(rule_id=rr.rule_id, name=rr.name, risk=rr.risk)
        if progress:
            progress(idx, total, rr.name, report.bytes)

        # ---- system actions ------------------------------------------
        if rr.action:
            acts = [rr.action] + list(getattr(rr, "extra_actions", []) or [])
            results = []
            for act in acts:
                if simulated:
                    results.append(f"would run {act}")
                else:
                    results.append(_run_action(act, log))
            out.action_result = "; ".join(results)
            if not rr.files and not rr.reg_items:
                report.outcomes.append(out)
                continue

        # ---- registry entries ------------------------------------------
        if rr.reg_items:
            if simulated:
                out.deleted += len(rr.reg_items)
                out.registry += len(rr.reg_items)
                if log:
                    log.write(rule=rr.rule_id, result="would-remove-registry",
                              count=len(rr.reg_items))
            else:
                from . import registry as regmod
                stamp = time.strftime("%Y%m%d-%H%M%S")
                backup_path = os.path.join(
                    backup_dir, f"registry-{rr.rule_id.replace('.', '-')}-{stamp}.json")
                try:
                    regmod.backup(rr.reg_items, backup_path)
                except (OSError, ValueError, TypeError) as exc:
                    # No backup, no deletion. Registry edits are the one
                    # thing that must never be irreversible.
                    out.failed += len(rr.reg_items)
                    out.errors.append(f"{rr.rule_id}: backup failed ({exc}), skipped")
                    if log:
                        log.write(rule=rr.rule_id, result="registry-skipped",
                                  error=f"backup failed: {exc}")
                    report.outcomes.append(out)
                    continue
                ok, bad = regmod.remove(rr.reg_items)
                out.deleted += ok
                out.registry += ok
                out.failed += bad
                if log:
                    log.write(rule=rr.rule_id, result="registry-removed",
                              count=ok, failed=bad, backup=backup_path)

        # ---- file deletion -------------------------------------------
        to_recycle: list[tuple[str, int]] = []

        # A keep-list that exists but cannot be read must not be treated as
        # "keep nothing": deleting the stores would destroy the cookies it
        # protects. Leave them alone and say why.
        if rr.handler == "cookie_dbs" and keep_error and rr.files:
            out.failed += len(rr.files)
            out.errors.append(f"cookie keep-list unreadable ({keep_error}); "
                              "cookies left alone")
            if log:
                log.write(rule=rr.rule_id, result="cookies-skipped", error=keep_error)
            report.outcomes.append(out)
            continue

        # A rule may nominate a handler instead of a plain unlink. The cookie
        # handler rewrites the SQLite store so kept domains survive.
        if (rr.handler == "cookie_dbs" and keep_domains
                and not simulated and rr.files):
            from . import keep as keepmod
            for path, size in rr.files:
                res = keepmod.filter_cookies(path, keep_domains,
                                             make_backup=backup_cookies)
                if res.error:
                    out.failed += 1
                    if len(out.errors) < 20:
                        out.errors.append(f"{path}: {res.error}")
                    if log:
                        log.write(rule=rr.rule_id, path=path, result="cookie-filter-failed",
                                  error=res.error)
                    continue
                out.kept += res.kept
                out.deleted += res.removed
                out.bytes += size
                if log:
                    log.write(rule=rr.rule_id, path=path, result="cookies-filtered",
                              kept=res.kept, removed=res.removed, backup=res.backup)
            report.outcomes.append(out)
            continue
        elif rr.handler == "cookie_dbs" and keep_domains and simulated:
            for path, size in rr.files:
                out.deleted += 1
                out.bytes += size
            out.kept = -1                      # unknown before the real filter
            if log:
                log.write(rule=rr.rule_id, result="would-filter-cookies")
            report.outcomes.append(out)
            continue
        for path, size in rr.files:
            if cancel is not None and cancel.is_set():
                break
            key = base.norm(path)
            if key not in allow:
                # A path the scanner did not preview. Never delete it.
                out.failed += 1
                out.errors.append(f"not in allow-list: {path}")
                if log:
                    log.write(rule=rr.rule_id, path=path, size=size, result="refused")
                continue

            if simulated:
                out.deleted += 1
                out.bytes += size
                if log:
                    log.write(rule=rr.rule_id, path=path, size=size, result="would-delete")
                continue

            if mode == "recycle":
                to_recycle.append((path, size))
                continue

            try:
                if mode == "secure":
                    from . import secure
                    w = secure.wipe_file(path, passes=passes)
                    if not w.ok:
                        raise OSError(w.error or "wipe failed")
                else:
                    base.delete_file(path)
                out.deleted += 1
                out.bytes += size
                if log:
                    log.write(rule=rr.rule_id, path=path, size=size,
                              result="wiped" if mode == "secure" else "deleted")
            except OSError as exc:
                if _is_locked(exc):
                    out.locked += 1
                    result = "locked"
                elif _is_denied(exc):
                    out.denied += 1
                    result = "denied"
                else:
                    out.failed += 1
                    result = "failed"
                if len(out.errors) < 20:
                    out.errors.append(f"{path}: {exc}")
                if log:
                    log.write(rule=rr.rule_id, path=path, size=size,
                              result=result, error=str(exc))

        if mode == "recycle" and to_recycle:
            ok, bad = base.recycle([p for p, _ in to_recycle])
            if ok:
                # Attribute the recyled bytes; which ones succeeded is not
                # reported per item by SHFileOperation, so be conservative:
                # count bytes only when the whole batch succeeded.
                if bad == 0:
                    out.deleted += ok
                    out.bytes += sum(s for _, s in to_recycle)
                else:
                    out.deleted += ok
                if log:
                    log.write(rule=rr.rule_id, result="recycled", count=ok, failed=bad)
            if bad:
                out.failed += bad
                if log:
                    log.write(rule=rr.rule_id, result="recycle-failed", count=bad)

        # ---- optional empty-directory cleanup ------------------------
        # Only rules that explicitly ask for it, and never a drive root.
        for ent in (rules_files(rr.rule_id) if out.deleted else []):
            if simulated or not ent.get("remove_empty"):
                continue
            for root in scanner.expand_targets(ent["path"]):
                if os.path.splitdrive(root)[1] in ("\\", "/", ""):
                    continue
                base.remove_empty_dirs(root)

        report.outcomes.append(out)

    report.duration = time.time() - t0
    if progress:
        progress(total, total, "done", report.bytes)
    return report


def rules_files(rule_id: str) -> list[dict]:
    from .rules import get
    r = get(rule_id)
    return list(r.get("files", [])) if r else []


# --------------------------------------------------------------------------
# system actions
# --------------------------------------------------------------------------

def _run_action(action: str, log: SessionLog | None) -> str:
    from . import system
    try:
        msg = system.run_action(action)
        if log:
            log.write(action=action, result="ok", detail=str(msg))
        return str(msg)
    except Exception as exc:
        if log:
            log.write(action=action, result="error", error=str(exc))
        return f"error: {exc}"
