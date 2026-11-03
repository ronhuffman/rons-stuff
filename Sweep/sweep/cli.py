"""
Sweep - command line interface.

The default for every destructive command is a dry run. `clean` will not touch
a single byte until `--apply` is present, and it prints a per-rule plan first.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time

from . import __version__, analyzer, base, cleaner, rules, scanner, system

# --------------------------------------------------------------------------
# tiny table renderer (no third-party deps)
# --------------------------------------------------------------------------

def table(headers: list[str], rows: list[list[str]], aligns: str | None = None) -> str:
    if not rows:
        return "  (nothing found)"
    aligns = aligns or ("<" + "<" * (len(headers) - 2) + ">")
    widths = [len(h) for h in headers]
    for r in rows:
        for i, cell in enumerate(r):
            widths[i] = max(widths[i], len(str(cell)))
    out = []
    out.append("  " + "  ".join(h.ljust(widths[i]) for i, h in enumerate(headers)))
    out.append("  " + "  ".join("-" * widths[i] for i in range(len(headers))))
    for r in rows:
        cells = []
        for i, cell in enumerate(r):
            s = str(cell)
            a = aligns[i] if i < len(aligns) else "<"
            cells.append(s.rjust(widths[i]) if a == ">" else s.ljust(widths[i]))
        out.append("  " + "  ".join(cells))
    return "\n".join(out)


RISK_MARK = {"safe": "", "moderate": "~", "caution": "!"}


def banner(admin: bool) -> str:
    build = sys.getwindowsversion().build if base.IS_WINDOWS else 0
    return (f"Sweep {__version__}  |  build {build}  |  "
            f"{'administrator' if admin else 'standard user'}")


# --------------------------------------------------------------------------
# commands
# --------------------------------------------------------------------------

def cmd_rules(args) -> int:
    groups = rules.by_group()
    for group, rs in groups.items():
        print(f"\n{group}")
        rows = []
        for r in rs:
            rows.append([
                RISK_MARK.get(r["risk"], "") + r["id"],
                r["name"],
                "on" if r.get("default") else "off",
                "admin" if r.get("needs_admin") else "",
            ])
        print(table(["id", "name", "default", "needs"], rows))
    print("\n  ~ = moderate risk   ! = caution (never on by default)")
    return 0


def cmd_import(args) -> int:
    from . import ccimport

    src = args.source
    if not src:
        found = ccimport.find_installations()
        if not found:
            print("no CCleaner ruleset found. Pass --from <path to ccleaner.ini>.",
                  file=sys.stderr)
            return 2
        src = found[0]
        print(f"  found {len(found)} ruleset(s); using {found[0]}")
    if not os.path.isfile(src):
        print(f"not a file: {src}", file=sys.stderr)
        return 2

    rep = ccimport.parse(src)
    out = args.out or os.path.join(
        base.state_dir(), "imported-rules.json")
    ccimport.save(rep, out)

    print(banner(base.is_admin()))
    print(f"  source            {src}")
    print(f"  output            {out}")
    print()
    print(f"  categories        {rep.sections_seen} found, {rep.sections_kept} imported")
    print(f"  file rules        {rep.file_rules:,}")
    print(f"  registry rules    {rep.reg_rules:,}")
    print(f"  system actions    {rep.actions:,}")
    if rep.dropped_unsafe:
        print(f"  unsafe dropped    {len(rep.dropped_unsafe):,}")
        for name, detail in rep.dropped_unsafe[:8]:
            print(f"      {name}: {detail}")
        if len(rep.dropped_unsafe) > 8:
            print(f"      ... {len(rep.dropped_unsafe) - 8} more")
    if rep.unknown_actions:
        print("  actions not run   " + ", ".join(
            f"{k} x{v}" for k, v in sorted(rep.unknown_actions.items())))
    print()
    print("  Use them with:  sweep scan --rules-file <output>")
    print("                  sweep clean --rules-file <output> --apply")
    return 0


def cmd_restore_registry(args) -> int:
    from . import registry
    path = args.path[0]
    if not os.path.isfile(path):
        print(f"not a file: {path}", file=sys.stderr)
        return 2
    try:
        ok, fail = registry.restore(path)
    except (OSError, ValueError) as exc:
        print(f"could not read backup: {exc}", file=sys.stderr)
        return 1
    print(f"  restored {ok} entr{'y' if ok == 1 else 'ies'}"
          + (f", {fail} failed" if fail else ""))
    return 0


def _load_rules_file(args) -> None:
    for path in (getattr(args, "rules_file", None) or []):
        if not os.path.isfile(path):
            print(f"rules file not found: {path}", file=sys.stderr)
            raise SystemExit(2)
        n = rules.load_external(path)
        print(f"  loaded {n} imported rule(s) from {path}")
    auto = os.path.join(base.state_dir(), "imported-rules.json")
    if not (getattr(args, "rules_file", None)) and os.path.isfile(auto):
        n = rules.load_external(auto)
        print(f"  loaded {n} imported rule(s) from {auto} (automatic)")


def _select(args) -> list[str]:
    if getattr(args, "imported", False) and not getattr(args, "rules", None):
        return [r["id"] for r in rules.RULES if r.get("imported")]
    if getattr(args, "rules", None):
        ids = []
        for chunk in args.rules:
            ids.extend(x.strip() for x in chunk.split(",") if x.strip())
        unknown = [i for i in ids if rules.get(i) is None]
        if unknown:
            print(f"unknown rule id(s): {', '.join(unknown)}", file=sys.stderr)
            print("run `sweep rules` to list ids", file=sys.stderr)
            raise SystemExit(2)
        return ids
    if getattr(args, "all", False):
        return rules.ids()
    if getattr(args, "defaults", False):
        return [r["id"] for r in rules.defaults()]
    # default selection: safe + moderate by default flag
    return [r["id"] for r in rules.defaults()]


def _print_scan(res: scanner.ScanResult, verbose: bool, admin: bool) -> None:
    by_group = scanner.group_totals(res)
    rows = []
    last_group = None
    for r in sorted(res.results, key=lambda x: (x.group, -x.size)):
        # A denied rule has count 0 but is not "empty": it was never measured.
        # Keep it in the table so the totals cannot look cleaner than reality.
        if r.empty and not (r.denied or r.error):
            continue
        if r.group != last_group:
            rows.append([r.group, "", "", ""])
            last_group = r.group
        mark = RISK_MARK.get(r.risk, "")
        badge = ""
        if r.error:
            badge = "could not run"
        elif r.needs_admin and not admin:
            badge = "needs admin"
        elif r.denied:
            badge = f"{r.denied:,} not readable"
        elif r.skipped:
            badge = f"{r.skipped:,} skipped"
        size_txt = base.human(r.size) if r.size else "\u2013"
        rows.append([f"  {mark}{r.name}", size_txt, f"{r.count:,}" if r.count else "", badge])
    print(table(["category", "reclaimable", "files", "note"], rows,
                aligns=["<", ">", ">", "<"]))
    print()
    print(f"  total reclaimable   {base.human(res.total_size)}")
    print(f"  total files         {res.total_count:,}")
    print(f"  scanned in          {res.duration:.1f}s")
    if getattr(res, "cancelled", False):
        print("  stopped early       scan cancelled - totals above are partial")
    blocked = sum(r.denied for r in res.results)
    if blocked:
        print(f"  not readable        {blocked:,} path(s)"
              + ("" if admin else "  - re-run as administrator to measure them"))
    if verbose:
        print()
        for r in res.results:
            # Denial and error first: an all-denied rule is r.empty too, and
            # calling that "nothing present" was the whole problem.
            if r.error:
                print(f"  ! {r.rule_id}: {r.error}")
            elif r.denied:
                print(f"  ~ {r.rule_id}: {r.denied} path(s) not readable "
                      f"({'elevate for full coverage' if not admin else 'locked'})")
            elif r.empty:
                print(f"  - {r.rule_id}: nothing present")


def cmd_scan(args) -> int:
    admin = base.is_admin()
    print(banner(admin))
    _load_rules_file(args)
    ids = _select(args)

    def progress(done, total, label, size):
        if args.quiet:
            return
        bar = f"[{done:>2}/{total}]"
        sys.stderr.write(f"\r{bar} {label[:44]:<44} {base.human(size):>10}")
        sys.stderr.flush()

    res = scanner.scan(ids, progress=None if args.quiet else progress,
                       min_age_hours=args.min_age)
    if not args.quiet:
        sys.stderr.write("\r" + " " * 70 + "\r")
    _print_scan(res, args.verbose, admin)
    if args.json:
        payload = {
            "version": __version__,
            "scanned": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "total_size": res.total_size,
            "total_files": res.total_count,
            "rules": [
                {"id": r.rule_id, "name": r.name, "group": r.group, "risk": r.risk,
                 "size": r.size, "files": r.count, "denied": r.denied,
                 "error": r.error, "needs_admin": r.needs_admin}
                for r in res.results
            ],
        }
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2)
        print(f"\n  wrote {args.json}")
    return 0


def cmd_clean(args) -> int:
    admin = base.is_admin()
    print(banner(admin))
    _load_rules_file(args)
    ids = _select(args)
    print(f"  selecting {len(ids)} rule(s)\n")

    def progress(done, total, label, size):
        if args.quiet:
            return
        sys.stderr.write(f"\r[{done:>2}/{total}] {label[:44]:<44} {base.human(size):>10}")
        sys.stderr.flush()

    res = scanner.scan(ids, min_age_hours=args.min_age)
    if not args.apply:
        print(table(
            ["rule", "would free", "files"],
            [[r.name, base.human(r.size), f"{r.count:,}"]
             for r in res.results if not r.empty],
            aligns=["<", ">", ">"],
        ))
        print(f"\n  dry run - would free {base.human(res.total_size)} "
              f"across {res.total_count:,} files")
        from . import keep as keepmod
        kept_domains = keepmod.KeepList.load().domains
        if kept_domains and any(r.rule_id == "privacy.cookies" and not r.empty
                                for r in res.results):
            print(f"  keep-list will preserve cookies for {len(kept_domains)} "
                  "domain(s); the cookie figure above is an upper bound")
        print("  nothing was deleted. re-run with --apply to proceed.")
        return 0

    log_path = args.log or os.path.join(
        base.state_dir(), "logs", f"clean-{time.strftime('%Y%m%d-%H%M%S')}.jsonl")
    if getattr(args, "secure", None):
        mode = "secure"
    else:
        mode = "recycle" if args.recycle else "delete"
    passes = max(1, args.secure or 1)
    # None = the saved keep-list, which the cleaner loads itself and refuses to
    # treat as empty when it exists but cannot be read. --no-keep is explicit.
    keep_domains: list[str] | None = [] if getattr(args, "no_keep", False) else None
    if keep_domains is None:
        from . import keep as keepmod
        kl = keepmod.KeepList.load()
        if kl.load_error:
            print(f"  keep-list unreadable ({kl.load_error}): cookies will be left alone")
        elif kl.domains:
            print(f"  keep-list active: {len(kl.domains)} domain(s) preserved")
    backup_dir = args.backup_dir or os.path.join(os.path.dirname(log_path), "registry-backups")
    log = cleaner.SessionLog(log_path)
    try:
        rep = cleaner.clean(res, confirm=True, mode=mode, log=log,
                            backup_dir=backup_dir, passes=passes,
                            keep_domains=keep_domains,
                            restore_point=not getattr(args, "no_restore_point", False),
                            progress=None if args.quiet else progress)
    finally:
        log.close()

    if not args.quiet:
        sys.stderr.write("\r" + " " * 70 + "\r")
    rows = []
    for o in rep.outcomes:
        if o.deleted or o.locked or o.denied or o.failed or o.action_result:
            note = []
            if o.locked:
                note.append(f"{o.locked} in use")
            if o.denied:
                note.append(f"{o.denied} need admin")
            if o.failed:
                note.append(f"{o.failed} failed")
            if o.action_result:
                note.append(o.action_result)
            rows.append([o.name, base.human(o.bytes), f"{o.deleted:,}", "; ".join(note)])
    print(table(["rule", "freed", "files", "note"], rows, aligns=["<", ">", ">", "<"]))
    print()
    print(f"  freed               {base.human(rep.bytes)}")
    print(f"  files removed       {rep.deleted:,}")
    if rep.locked:
        print(f"  skipped (in use)    {rep.locked:,}  - close the owning app and re-run")
    if rep.denied:
        print(f"  denied              {rep.denied:,}  - re-run as administrator")
    if rep.failed:
        print(f"  failed              {rep.failed:,}")
    if rep.restore_point:
        print(f"  restore point       {rep.restore_point}")
    print(f"  mode                {mode}")
    print(f"  log                 {log_path}")
    return 0


def cmd_analyze(args) -> int:
    root = os.path.abspath(args.path)
    if not os.path.isdir(root):
        print(f"not a directory: {root}", file=sys.stderr)
        return 2
    usage = analyzer.disk_usage(root)
    print(banner(base.is_admin()))
    if usage is None:
        print("  volume   could not measure this volume\n")
    else:
        total, used, free = usage
        print(f"  volume   {total - free:,} used / {base.human(total)}  "
              f"({base.human(free)} free)\n")

    if args.duplicates:
        print("  scanning for duplicates (this reads file contents)...")
        sys.stderr.write("")
        groups = analyzer.find_duplicates(root, min_size=args.min_size)
        if not groups:
            print("  no duplicate files found above the size floor")
            return 0
        wasted = sum(g[0][1] * (len(g) - 1) for g in groups)
        rows = []
        for g in groups[:args.limit]:
            for p, s in g:
                rows.append([base.human(s), os.path.relpath(p, root)])
            rows.append(["", ""])
        print(table(["size", "path"], rows, aligns=[">", "<"]))
        print(f"\n  {len(groups)} duplicate group(s), {base.human(wasted)} reclaimable")
        return 0

    print("  scanning tree...")
    tree = analyzer.build_tree(root, max_depth=args.depth)
    rows = []
    for child in tree.children[:args.limit]:
        pct = (child.size / tree.size * 100) if tree.size else 0
        rows.append([base.human(child.size), f"{pct:5.1f}%",
                     f"{child.file_count:,}", child.name, child.path])
    print(table(["size", "share", "files", "name", "path"], rows,
                aligns=[">", ">", ">", "<", "<"]))

    print("\n  largest files")
    big = analyzer.largest_files(root, limit=args.limit, min_size=args.min_size)
    print(table(["size", "path"], [[base.human(s), p] for p, s in big], aligns=[">", "<"]))
    return 0


def cmd_startup(args) -> int:
    print(banner(base.is_admin()))
    items = system.list_startup(include_tasks=not args.no_tasks,
                                include_services=args.services)
    if args.disable or args.enable:
        target = (args.disable or args.enable)[0]
        matches = [i for i in items if i.key_id == target or i.name == target]
        if not matches:
            print(f"no startup item matching {target!r}", file=sys.stderr)
            return 2
        if len(matches) > 1:
            print("ambiguous; matches:", file=sys.stderr)
            for m in matches:
                print(f"  {m.key_id}", file=sys.stderr)
            return 2
        msg = (system.disable_startup if args.disable else system.enable_startup)(matches[0])
        print(f"  {msg}")
        return 0

    rows = []
    for i in items:
        state = "on " if i.enabled else "off"
        rows.append([state, i.kind, i.name[:64], i.location])
    print(table(["state", "kind", "name", "source"], rows, aligns=["<", "<", "<", "<"]))
    print(f"\n  {len(items)} item(s). "
          f"Use --disable <key_id> / --enable <key_id> to toggle (reversible).")
    if system.TASK_ERROR:
        print(f"  note: {system.TASK_ERROR}")
    print("  key_id  =  kind|source|name  - copy it from the table's first three columns.")
    if args.show_ids:
        for i in items:
            print(f"    {i.key_id}")
    return 0


def cmd_gui(args) -> int:
    try:
        from . import gui
    except ImportError as exc:
        print(f"GUI unavailable: {exc}", file=sys.stderr)
        return 1
    gui.main()
    return 0


# --------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="sweep",
        description="Sweep - a Windows cleaner that shows its work and never nags.",
    )
    p.add_argument("--version", action="version", version=f"Sweep {__version__}")
    sub = p.add_subparsers(dest="cmd")

    def add_sel(sp):
        sp.add_argument("--rules", action="append", metavar="ID[,ID]",
                        help="explicit rule ids (comma separated)")
        sp.add_argument("--all", action="store_true", help="every rule, including caution")
        sp.add_argument("--defaults", action="store_true", help="default rules only")
        sp.add_argument("--rules-file", action="append", metavar="PATH",
                        help="load imported rules from a Sweep rule file")
        sp.add_argument("--imported", action="store_true",
                        help="select only rules imported from CCleaner")
        sp.add_argument("--min-age", type=float, default=0.0, metavar="HOURS",
                        help="ignore files modified in the last N hours (default 0)")
        sp.add_argument("--quiet", action="store_true")

    s = sub.add_parser("scan", help="measure what can be freed (never deletes)")
    add_sel(s)
    s.add_argument("--json", metavar="PATH", help="write machine-readable results")
    s.add_argument("--verbose", "-v", action="store_true")
    s.set_defaults(func=cmd_scan)

    c = sub.add_parser("clean", help="delete the scanned junk (dry run unless --apply)")
    add_sel(c)
    c.add_argument("--apply", action="store_true", help="actually delete")
    c.add_argument("--recycle", action="store_true",
                   help="send to Recycle Bin instead of deleting permanently")
    c.add_argument("--log", metavar="PATH", help="JSONL audit log path")
    c.add_argument("--backup-dir", metavar="PATH",
                   help="where registry backups are written (default: beside the log)")
    c.add_argument("--secure", type=int, metavar="PASSES",
                   help="overwrite each file N times before deleting it")
    c.add_argument("--no-keep", action="store_true",
                   help="ignore the cookie keep-list and remove every cookie")
    c.add_argument("--no-restore-point", action="store_true",
                   help="skip the System Restore point normally created before cleaning")
    c.set_defaults(func=cmd_clean)

    a = sub.add_parser("analyze", help="show what is using space (treemap data, big files)")
    a.add_argument("path", nargs="?", default="C:\\")
    a.add_argument("--depth", type=int, default=3)
    a.add_argument("--limit", type=int, default=25)
    a.add_argument("--min-size", type=int, default=1 << 20, help="bytes")
    a.add_argument("--duplicates", action="store_true")
    a.set_defaults(func=cmd_analyze)

    st = sub.add_parser("startup", help="list / toggle startup programs and tasks")
    st.add_argument("--services", action="store_true", help="include auto-start services")
    st.add_argument("--no-tasks", action="store_true")
    st.add_argument("--disable", nargs=1, metavar="KEY")
    st.add_argument("--enable", nargs=1, metavar="KEY")
    st.add_argument("--show-ids", action="store_true")
    st.set_defaults(func=cmd_startup)

    r = sub.add_parser("rules", help="list every built-in rule")
    r.set_defaults(func=cmd_rules)

    im = sub.add_parser("import", help="import a local CCleaner ruleset")
    im.add_argument("--from", dest="source", metavar="INI",
                    help="path to ccleaner.ini (auto-detected if omitted)")
    im.add_argument("--out", metavar="PATH", help="where to write the Sweep rule file")
    im.set_defaults(func=cmd_import)

    rr = sub.add_parser("restore-registry", help="replay a registry backup")
    rr.add_argument("path", nargs=1, metavar="BACKUP.json")
    rr.set_defaults(func=cmd_restore_registry)

    g = sub.add_parser("gui", help="open the graphical interface")
    g.set_defaults(func=cmd_gui)

    sec = sub.add_parser("secure", help="overwrite files or free space before removing")
    sec.add_argument("path", nargs="*")
    sec.add_argument("--passes", type=int, default=1)
    sec.add_argument("--free-space", action="store_true")
    sec.add_argument("--apply", action="store_true")
    sec.set_defaults(func=cmd_secure)

    ap = sub.add_parser("apps", help="list, uninstall, or inspect applications")
    ap.add_argument("--uninstall", nargs=1, metavar="NAME")
    ap.add_argument("--leftovers", nargs=1, metavar="NAME")
    ap.add_argument("--quiet-uninstall", action="store_true")
    ap.set_defaults(func=cmd_apps)

    dv = sub.add_parser("drivers", help="driver inventory and Windows Update drivers")
    dv.add_argument("--check", action="store_true")
    dv.add_argument("--install", action="store_true")
    dv.add_argument("--only", action="append")
    dv.add_argument("--elevate", action="store_true",
                    help="relaunch elevated (Windows Update needs admin)")
    dv.set_defaults(func=cmd_drivers)

    up = sub.add_parser("updates", help="software updates via winget")
    up.add_argument("--apply", nargs=1, metavar="all|ID")
    up.set_defaults(func=cmd_updates)

    ua = sub.add_parser("update",
                        help="everything: software, Windows and drivers, in one preview")
    ua.add_argument("--apply", action="store_true")
    ua.add_argument("--elevate", action="store_true",
                    help="relaunch elevated (needed for Windows/driver updates)")
    ua.add_argument("--no-software", action="store_true")
    ua.add_argument("--no-windows", action="store_true")
    ua.add_argument("--no-drivers", action="store_true")
    ua.add_argument("--json", metavar="PATH")
    ua.set_defaults(func=cmd_update)

    wu = sub.add_parser("windows-update", help="Windows Update only")
    wu.add_argument("--apply", action="store_true")
    wu.add_argument("--elevate", action="store_true")
    wu.set_defaults(func=cmd_windows_update)

    kp = sub.add_parser("keep", help="manage the cookie keep-list")
    kp.add_argument("--add", action="append")
    kp.add_argument("--remove", action="append")
    kp.add_argument("--list", action="store_true")
    kp.set_defaults(func=cmd_keep)

    sc = sub.add_parser("schedule", help="install or remove automatic cleaning")
    sc.add_argument("--frequency", default="weekly",
                    choices=["daily", "weekly", "logon", "idle"])
    sc.add_argument("--at", default="12:00")
    sc.add_argument("--days", default="MON,WED,FRI")
    sc.add_argument("--remove", action="store_true")
    sc.add_argument("--status", action="store_true")
    sc.set_defaults(func=cmd_schedule)

    hl = sub.add_parser("health", help="laptop health: disk, battery, stability")
    hl.add_argument("--days", type=int, default=30, help="event-log window")
    hl.add_argument("--json", metavar="PATH", help="write a machine-readable report")
    hl.add_argument("--history", action="store_true", help="show past scores")
    hl.add_argument("--no-save", action="store_true", help="do not record a snapshot")
    hl.set_defaults(func=cmd_health)

    return p


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "cmd", None):
        return cmd_gui(args)
    try:
        return args.func(args)
    except KeyboardInterrupt:
        print("\n  interrupted", file=sys.stderr)
        return 130
    except PermissionError as exc:
        print(f"  refused: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())


# =========================================================================
# remaining commands: secure, apps, drivers, updates, keep, schedule
# =========================================================================

def cmd_secure(args) -> int:
    from . import secure

    print(banner(base.is_admin()))
    passes = max(1, args.passes)

    if args.free_space:
        root = (args.path or ["C:\\"])[0]
        print(f"  overwriting free space on {root} with {passes} pass(es)")
        print("  this writes random data until the volume is nearly full")
        if not args.apply:
            print("\n  dry run - nothing written. re-run with --apply.")
            return 0
        cancel = base.Cancel()

        def prog(done, total):
            sys.stderr.write(f"\r  {base.human(done)} / {base.human(total)}   ")
            sys.stderr.flush()

        written, files, note = secure.wipe_free_space(root, cancel=cancel, progress=prog)
        sys.stderr.write("\r" + " " * 60 + "\r")
        print(f"  {note}")
        return 0

    targets: list[str] = []
    for raw in (args.path or []):
        p = os.path.abspath(os.path.expandvars(raw))
        if os.path.isdir(p):
            for f, _s in base.walk(p, "*", recurse=True):
                targets.append(f)
        elif os.path.isfile(p):
            targets.append(p)
        else:
            print(f"  not found: {p}", file=sys.stderr)

    if not targets:
        print("  nothing to wipe", file=sys.stderr)
        return 2
    total = sum(os.path.getsize(t) for t in targets if os.path.exists(t))
    print(f"  {len(targets)} file(s), {base.human(total)}, {passes} pass(es)")
    if not args.apply:
        print("\n  dry run - nothing overwritten. re-run with --apply.")
        return 0
    ok = fail = 0
    wiped = 0
    for t in targets:
        r = secure.wipe_file(t, passes=passes)
        if r.ok:
            ok += 1
            wiped += r.size
        else:
            fail += 1
    print(f"  wiped {ok} file(s), {base.human(wiped)}" + (f", {fail} failed" if fail else ""))
    if secure.is_ssd(os.path.abspath(targets[0])) is True:
        print("  note: this is an SSD - overwriting logical blocks does not guarantee")
        print("        the original cells are erased. Use BitLocker + key destruction")
        print("        or the drive vendor's Secure Erase for that guarantee.")
    return 0


def cmd_apps(args) -> int:
    from . import apps as appmod

    print(banner(base.is_admin()))
    all_apps = appmod.list_apps()

    if args.uninstall:
        needle = args.uninstall[0].lower()
        match = [a for a in all_apps if needle in a.name.lower()]
        if not match:
            print(f"  no application matching {needle!r}", file=sys.stderr)
            return 2
        if len(match) > 1:
            print("  ambiguous; matches:", file=sys.stderr)
            for a in match[:20]:
                print(f"    {a.name}  {a.version}", file=sys.stderr)
            return 2
        a = match[0]
        print(f"  {a.name}  {a.version}")
        if not a.uninstallable:
            print("  no uninstall command registered", file=sys.stderr)
            return 1
        if not messageboxless_confirm(f"Run the uninstaller for {a.name}?"):
            print("  cancelled")
            return 0
        ok, info = appmod.launch_uninstall(a, quiet=args.quiet_uninstall)
        print(f"  {'started' if ok else 'failed'}: {info}")
        return 0 if ok else 1

    if args.leftovers:
        needle = args.leftovers[0].lower()
        for a in all_apps:
            if needle in a.name.lower():
                print(f"\n  {a.name} {a.version}")
                left = appmod.find_leftovers(a)
                if not left:
                    print("    no obvious leftovers")
                for lo in left:
                    size = base.human(lo.size) if lo.size else ""
                    print(f"    [{lo.kind}] {lo.path} {size}")
                return 0
        print(f"  no application matching {needle!r}", file=sys.stderr)
        return 2

    rows = []
    for a in all_apps:
        size = appmod.app_size(a)
        rows.append([a.name[:58], a.version[:16], (a.publisher or "")[:26],
                     base.human(size) if size else ""])
    print(table(["name", "version", "publisher", "size"], rows))
    print(f"\n  {len(all_apps)} application(s).")
    print("  --uninstall NAME   run its uninstaller")
    print("  --leftovers NAME   show folders/keys that look orphaned")
    return 0


def cmd_drivers(args) -> int:
    from . import drivers

    print(banner(base.is_admin()))
    if args.check or args.install:
        print("  asking Windows Update for driver-class updates...")
        ups, err = drivers.search_updates()
        if err:
            print(f"  {err}", file=sys.stderr)
            return 1
        if not ups:
            print("  no driver updates are offered for this machine")
            return 0
        rows = [[u.title[:64], u.driver_class, u.manufacturer[:20], u.version_date]
                for u in ups]
        print(table(["update", "class", "provider", "date"], rows))
        if args.install:
            ids = [u.update_id for u in ups if not args.only or
                   any(o.lower() in u.title.lower() for o in args.only)]
            if not ids:
                print("  nothing selected", file=sys.stderr)
                return 2
            print(f"\n  installing {len(ids)} update(s) via Windows Update...")
            ok, msg = drivers.install_updates(ids)
            print(f"  {'ok' if ok else 'failed'}: {msg}")
            return 0 if ok else 1
        print("\n  dry run - nothing installed. re-run with --install.")
        return 0

    inv = drivers.inventory()
    rows = [[d.module_name[:26], d.display_name[:44], d.driver_type, d.state, d.date]
            for d in inv[:120]]
    print(table(["module", "display name", "type", "state", "date"], rows))
    print(f"\n  {len(inv)} driver(s) installed.")
    print("  --check   list driver updates offered by Windows Update")
    print("  --install install them (needs administrator)")
    return 0


def cmd_updates(args) -> int:
    from . import apps as appmod

    print(banner(base.is_admin()))
    ok, detail = appmod.winget_diagnose()
    if not ok:
        print(f"  {detail}", file=sys.stderr)
        print("  Install/repair 'App Installer' from the Microsoft Store.",
              file=sys.stderr)
        return 1
    items, err = appmod.list_upgrades()
    if err:
        print(f"  {err}", file=sys.stderr)
        return 1
    if not items:
        print("  every winget-managed package is current")
        return 0
    rows = [[u.name[:46], u.package_id[:34], u.current, u.available] for u in items]
    print(table(["package", "id", "current", "available"], rows, aligns=["<", "<", ">", ">"]))
    print(f"\n  {len(items)} upgrade(s) available")
    if args.apply:
        target = args.apply[0]
        chosen = items if target == "all" else [
            u for u in items if target.lower() in u.package_id.lower()
            or target.lower() in u.name.lower()]
        if not chosen:
            print(f"  nothing matching {target!r}", file=sys.stderr)
            return 2
        for u in chosen:
            print(f"  upgrading {u.package_id} ...")
            ok, msg = appmod.upgrade_package(u.package_id)
            print(f"    {'ok' if ok else 'failed'}: {msg}")
        return 0
    print("  --apply all        upgrade everything")
    print("  --apply <id>       upgrade one package")
    return 0


def cmd_keep(args) -> int:
    from . import keep

    kl = keep.KeepList.load()
    if args.add:
        for d in args.add:
            kl.add(d)
        path = kl.save()
        print(f"  added; {len(kl.domains)} domain(s) kept -> {path}")
    if args.remove:
        for d in args.remove:
            kl.remove(d)
        path = kl.save()
        print(f"  removed; {len(kl.domains)} domain(s) kept -> {path}")
    if args.list or not (args.add or args.remove):
        if not kl.domains:
            print("  keep-list is empty. cookies for every site are removed.")
        else:
            print(f"  {len(kl.domains)} domain(s) will survive a cookie clean:")
            for d in kl.domains:
                print(f"    {d}")
        dbs = keep.candidate_dbs()
        if dbs:
            print(f"\n  {len(dbs)} cookie store(s) found:")
            for label, p in dbs:
                print(f"    {label}")
    return 0


def cmd_schedule(args) -> int:
    from . import schedule

    print(banner(base.is_admin()))
    if args.remove:
        ok, msg = schedule.remove()
        print(f"  {'ok' if ok else 'failed'}: {msg}")
        return 0 if ok else 1
    if args.status:
        st = schedule.status()
        if not st.installed:
            print("  no scheduled clean is registered")
            return 0
        print(f"  installed   {st.installed}")
        print(f"  enabled     {st.enabled}")
        print(f"  next run    {st.next_run}")
        print(f"  last run    {st.last_run} (code {st.last_result})")
        return 0
    ok, msg = schedule.create(frequency=args.frequency, time_of_day=args.at,
                              weekdays=args.days)
    print(f"  {'scheduled' if ok else 'failed'}: {msg}")
    if ok:
        print("  manage it in Task Scheduler as 'Sweep - Automatic Clean'")
    return 0 if ok else 1


def messageboxless_confirm(prompt: str) -> bool:
    try:
        return input(f"  {prompt} [y/N] ").strip().lower().startswith("y")
    except EOFError:
        return False


# =========================================================================
# health
# =========================================================================

_HEALTH_MARK = {"ok": "ok  ", "warn": "WARN", "bad": "BAD ", "unknown": "?   "}


def cmd_health(args) -> int:
    from . import health

    print(banner(base.is_admin()))
    checks = health.run_checks(days=args.days)
    sc = health.score(checks)

    if args.json:
        import json as _json
        with open(args.json, "w", encoding="utf-8") as fh:
            _json.dump(health.to_dict(checks), fh, indent=2)
        print(f"  wrote {args.json}")

    print()
    print(f"  health score   {sc}/100   ({health.verdict(sc)})")
    print()

    rows = []
    for c in checks:
        rows.append([_HEALTH_MARK.get(c.status, c.status), c.title, c.value])
    print(table(["", "check", "value"], rows, aligns=["<", "<", "<"]))

    bad = [c for c in checks if c.status in (health.BAD, health.WARN)]
    if bad:
        print()
        for c in bad:
            print(f"  [{_HEALTH_MARK[c.status].strip()}] {c.title}: {c.value}")
            if c.advice:
                for line in _wrap(c.advice, 74):
                    print(f"         {line}")
            for d in c.detail[:4]:
                print(f"         - {d}")

    unknown = [c for c in checks if c.status == health.UNKNOWN]
    if unknown:
        print()
        print("  could not read: " + ", ".join(c.title for c in unknown))
        if not base.is_admin():
            print("  (some checks need administrator - try 'Restart as admin')")

    if not args.no_save:
        p = health.save_snapshot(checks)
        hist = health.load_history()
        if len(hist) >= 2:
            prev = hist[-2]
            delta = sc - int(prev.get("score", sc))
            trend = "no change" if delta == 0 else f"{delta:+d} vs last run"
            print(f"\n  trend          {trend}   ({len(hist)} snapshot(s))")
        print(f"  history        {p}")

    if args.history:
        hist = health.load_history()
        if not hist:
            print("\n  no history yet")
        else:
            print()
            for rec in hist[-10:]:
                print(f"    {rec.get('ts','?')}   {rec.get('score','?')}/100")
    return 0


def _wrap(text: str, width: int) -> list[str]:
    words = text.split()
    lines, cur = [], ""
    for w in words:
        if len(cur) + len(w) + 1 > width:
            lines.append(cur)
            cur = w
        else:
            cur = (cur + " " + w).strip()
    if cur:
        lines.append(cur)
    return lines


# =========================================================================
# unified updates
# =========================================================================

def _maybe_elevate(args) -> int | None:
    """Re-launch elevated when --elevate was asked for. Returns an exit code
    when the caller should stop, or None to continue."""
    if not getattr(args, "elevate", False):
        return None
    if base.is_admin():
        return None
    rest = [a for a in sys.argv[1:] if a != "--elevate"]
    params = " ".join(["-m", "sweep"] + [f'"{a}"' if " " in a else a for a in rest])
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    print("  requesting elevation...")
    if base.relaunch_elevated(params, cwd=root):
        print("  an elevated window is opening; this one can be closed.")
        return 0
    print("  elevation was refused.", file=sys.stderr)
    return 1


def _gather_updates(args) -> tuple[list, list, list, list]:
    from . import apps as appmod, winupdate

    software: list = []
    if not getattr(args, "no_software", False):
        ok, detail = appmod.winget_diagnose()
        if ok:
            software, err = appmod.list_upgrades()
            if err:
                print(f"  winget: {err}", file=sys.stderr)
        else:
            print(f"  winget: {detail}", file=sys.stderr)

    wu_items: list = []
    wu_err = ""
    if not (getattr(args, "no_windows", False) and getattr(args, "no_drivers", False)):
        wu_items, wu_err = winupdate.search()
        if wu_err:
            print(f"  Windows Update: {wu_err}", file=sys.stderr)

    windows = [] if getattr(args, "no_windows", False) else [
        u for u in wu_items if not u.is_driver]
    drivers = [] if getattr(args, "no_drivers", False) else [
        u for u in wu_items if u.is_driver]
    return software, windows, drivers, wu_items


def cmd_update(args) -> int:
    from . import apps as appmod, winupdate

    stop = _maybe_elevate(args)
    if stop is not None:
        return stop

    print(banner(base.is_admin()))
    software, windows, drivers, _wu = _gather_updates(args)

    print()
    if software:
        print("  software (winget)")
        print(table(["package", "current", "available"],
                    [[u.name[:44], u.current, u.available] for u in software],
                    aligns=["<", ">", ">"]))
    if windows:
        print("\n  Windows updates")
        print(table(["update", "KB", "size", "severity"],
                    [[u.title[:56], u.kb, f"{u.size_mb:.0f} MB", u.severity]
                     for u in windows], aligns=["<", "<", ">", "<"]))
    if drivers:
        print("\n  driver updates (Windows Update)")
        print(table(["driver", "size", "category"],
                    [[u.title[:56], f"{u.size_mb:.0f} MB", u.categories[:34]]
                     for u in drivers], aligns=["<", ">", "<"]))

    total = len(software) + len(windows) + len(drivers)
    if total == 0:
        print("  nothing outstanding - everything visible to Sweep is current")
        return 0
    print(f"\n  {total} item(s) available")

    if args.json:
        import json as _json
        with open(args.json, "w", encoding="utf-8") as fh:
            _json.dump({
                "software": [{"name": u.name, "id": u.package_id,
                              "current": u.current, "available": u.available}
                             for u in software],
                "windows": [{"title": u.title, "kb": u.kb, "id": u.update_id,
                             "size_mb": u.size_mb, "severity": u.severity}
                            for u in windows],
                "drivers": [{"title": u.title, "id": u.update_id,
                             "size_mb": u.size_mb} for u in drivers],
            }, fh, indent=2)
        print(f"  wrote {args.json}")

    if not args.apply:
        print("  nothing was changed. re-run with --apply to install.")
        if not base.is_admin() and (windows or drivers):
            print("  Windows and driver updates need admin: add --elevate")
        return 0

    failures = 0
    if software:
        print("\n  installing software...")
        for u in software:
            ok, msg = appmod.upgrade_package(u.package_id)
            print(f"    {'ok  ' if ok else 'FAIL'} {u.package_id}: {msg}")
            failures += 0 if ok else 1

    wu_ids = [u.update_id for u in windows + drivers]
    if wu_ids:
        print(f"\n  installing {len(wu_ids)} Windows/driver update(s)...")
        ok, msg, outcomes, reboot = winupdate.install(wu_ids)
        for o in outcomes:
            print(f"    {'ok  ' if o.ok else 'FAIL'} {o.title[:60]} - {o.text}")
        print(f"  {msg}")
        failures += sum(1 for o in outcomes if not o.ok)

    return 0 if failures == 0 else 1


def cmd_windows_update(args) -> int:
    from . import winupdate

    stop = _maybe_elevate(args)
    if stop is not None:
        return stop

    print(banner(base.is_admin()))
    items, err = winupdate.search()
    if err:
        print(f"  {err}", file=sys.stderr)
        return 1
    if not items:
        print("  Windows Update reports nothing pending")
        return 0

    rows = [[u.kind, u.title[:56], u.kb, f"{u.size_mb:.0f} MB", u.severity]
            for u in items]
    print(table(["kind", "update", "KB", "size", "severity"], rows,
                aligns=["<", "<", "<", ">", "<"]))
    print(f"\n  {len(items)} update(s) pending")
    if not args.apply:
        print("  nothing installed. re-run with --apply.")
        return 0

    ok, msg, outcomes, reboot = winupdate.install([u.update_id for u in items])
    for o in outcomes:
        print(f"    {'ok  ' if o.ok else 'FAIL'} {o.title[:60]} - {o.text}")
    print(f"  {msg}")
    return 0 if ok else 1
