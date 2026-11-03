"""Sweep test suite - focuses on the safety properties, not coverage numbers."""

from __future__ import annotations

import os
import shutil
import sys
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sweep import analyzer, base, cleaner, rules, scanner, system  # noqa: E402


class Sandbox:
    """A throwaway tree that mimics a cache directory next to real data.

    Note: this deliberately does not use tempfile.mkdtemp. On this host a
    mkdtemp-created directory is left in a state where creating children is
    denied (even icacls cannot read its ACL), while a makedirs-created
    directory inherits the workspace ACL normally.
    """

    ROOT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                        ".test-tmp")
    _counter = 0

    def __init__(self) -> None:
        os.makedirs(self.ROOT, exist_ok=True)
        Sandbox._counter += 1
        name = f"sweep-{os.getpid()}-{Sandbox._counter}-{int(time.time() * 1000) % 100000}"
        self.root = os.path.join(self.ROOT, name)
        os.makedirs(self.root, exist_ok=True)
        self.cache = os.path.join(self.root, "cache", "deep")
        self.keep = os.path.join(self.root, "keep")
        os.makedirs(self.cache)
        os.makedirs(self.keep)
        self.junk = []
        for i in range(5):
            p = os.path.join(self.cache, f"junk{i}.tmp")
            with open(p, "wb") as fh:
                fh.write(b"x" * 1024)
            self.junk.append(p)
        self.precious = os.path.join(self.keep, "thesis.docx")
        with open(self.precious, "wb") as fh:
            fh.write(b"important" * 100)

    def cleanup(self) -> None:
        shutil.rmtree(self.root, ignore_errors=True)


class TestScanAndClean(unittest.TestCase):
    TEST_RULE = "test.cache"

    def setUp(self) -> None:
        self.sb = Sandbox()
        rules.RULES.append({
            "id": self.TEST_RULE,
            "name": "Test cache",
            "group": "Test",
            "risk": "safe",
            "default": False,
            "files": [{"path": self.sb.cache, "pattern": "*", "recurse": True,
                       "remove_empty": False}],
        })

    def tearDown(self) -> None:
        rules.RULES[:] = [r for r in rules.RULES if r["id"] != self.TEST_RULE]
        self.sb.cleanup()

    def test_scan_finds_only_the_cache(self):
        res = scanner.scan([self.TEST_RULE])
        self.assertEqual(res.total_count, 5)
        self.assertEqual(res.total_size, 5 * 1024)
        self.assertNotIn(base.norm(self.sb.precious), res.allowlist)

    def test_clean_deletes_cache_and_spares_data(self):
        res = scanner.scan([self.TEST_RULE])
        rep = cleaner.clean(res, confirm=True, mode="delete")
        self.assertEqual(rep.deleted, 5)
        self.assertEqual(rep.bytes, 5 * 1024)
        self.assertTrue(os.path.exists(self.sb.precious),
                        "user data outside the rule must never be touched")
        for p in self.sb.junk:
            self.assertFalse(os.path.exists(p))

    def test_restore_point_is_skipped_on_a_dry_run(self):
        res = scanner.scan([self.TEST_RULE])
        called = []
        orig = system.create_restore_point
        system.create_restore_point = lambda *a, **k: (called.append(1) or (True, "stub"))
        try:
            rep = cleaner.clean(res, confirm=True, mode="dry-run")
        finally:
            system.create_restore_point = orig
        self.assertEqual(called, [], "a dry run must not create a restore point")
        self.assertEqual(rep.restore_point, "")

    def test_restore_point_failure_is_reported_and_does_not_block(self):
        res = scanner.scan([self.TEST_RULE])
        orig = system.create_restore_point
        system.create_restore_point = lambda *a, **k: (False, "System Protection is off")
        try:
            rep = cleaner.clean(res, confirm=True, mode="delete")
        finally:
            system.create_restore_point = orig
        self.assertIn("not created", rep.restore_point)
        self.assertIn("System Protection is off", rep.restore_point)
        self.assertEqual(rep.deleted, 5,
                         "a missing undo point must not block a requested clean")

    def test_restore_point_success_is_reported(self):
        res = scanner.scan([self.TEST_RULE])
        orig = system.create_restore_point
        system.create_restore_point = lambda *a, **k: (True, "sequence 42")
        try:
            rep = cleaner.clean(res, confirm=True, mode="delete")
        finally:
            system.create_restore_point = orig
        self.assertIn("created", rep.restore_point)
        self.assertIn("sequence 42", rep.restore_point)

    def test_restore_point_can_be_disabled(self):
        res = scanner.scan([self.TEST_RULE])
        called = []
        orig = system.create_restore_point
        system.create_restore_point = lambda *a, **k: (called.append(1) or (True, "stub"))
        try:
            rep = cleaner.clean(res, confirm=True, mode="delete", restore_point=False)
        finally:
            system.create_restore_point = orig
        self.assertEqual(called, [], "--no-restore-point must skip the attempt")
        self.assertEqual(rep.restore_point, "")

    def test_restore_point_answers_instead_of_raising(self):
        """It must always return (bool, reason), never raise, when it cannot run."""
        supported_ok, supported_msg = system.restore_point_supported()
        self.assertIsInstance(supported_ok, bool)
        self.assertIsInstance(supported_msg, str)
        if not base.is_admin():
            ok, msg = system.create_restore_point("sweep test")
            self.assertFalse(ok)
            self.assertIn("administrator", msg.lower())

    def test_dry_run_deletes_nothing(self):
        res = scanner.scan([self.TEST_RULE])
        rep = cleaner.clean(res, confirm=True, mode="dry-run")
        self.assertEqual(rep.deleted, 5)
        self.assertTrue(rep.simulated)
        for p in self.sb.junk:
            self.assertTrue(os.path.exists(p), "dry run must not delete")

    def test_clean_without_confirm_is_refused(self):
        res = scanner.scan([self.TEST_RULE])
        with self.assertRaises(PermissionError):
            cleaner.clean(res, confirm=False, mode="delete")
        for p in self.sb.junk:
            self.assertTrue(os.path.exists(p))

    def test_path_outside_allowlist_is_refused(self):
        """A tampered result must not be able to delete an arbitrary file."""
        res = scanner.scan([self.TEST_RULE])
        # Inject a path the scanner never produced.
        res.results[0].files.append((self.sb.precious, 900))
        rep = cleaner.clean(res, confirm=True, mode="delete")
        self.assertTrue(os.path.exists(self.sb.precious),
                        "path escaping the allow-list must be refused")
        self.assertGreaterEqual(rep.failed, 1)

    def test_recycle_mode_keeps_files_recoverable(self):
        res = scanner.scan([self.TEST_RULE])
        rep = cleaner.clean(res, confirm=True, mode="recycle")
        self.assertEqual(rep.deleted, 5)
        for p in self.sb.junk:
            self.assertFalse(os.path.exists(p))

    def test_junction_is_not_followed(self):
        """A junction inside a cache dir must not widen the scan."""
        if not base.IS_WINDOWS:
            self.skipTest("junction test is Windows-only")
        link = os.path.join(self.sb.cache, "escape")
        try:
            os.system(f'mklink /J "{link}" "{self.sb.keep}" >nul 2>&1')
        except OSError:
            self.skipTest("mklink unavailable")
        if not os.path.exists(link):
            self.skipTest("mklink unavailable")
        res = scanner.scan([self.TEST_RULE])
        self.assertNotIn(base.norm(self.sb.precious), res.allowlist,
                         "scan must not descend a junction")

    def test_min_age_protects_fresh_files(self):
        res = scanner.scan([self.TEST_RULE], min_age_hours=24)
        self.assertEqual(res.total_count, 0,
                         "files touched seconds ago must be skipped by --min-age")


class TestPathGuard(unittest.TestCase):
    def test_containment(self):
        g = base.PathGuard()
        g.add(r"C:\Temp\foo")
        self.assertTrue(g.contains(r"C:\Temp\foo\bar.txt"))
        self.assertTrue(g.contains(r"C:\temp\FOO\bar.txt"))       # case-insensitive
        self.assertFalse(g.contains(r"C:\Temp\foobar\x.txt"))     # prefix, not child
        self.assertFalse(g.contains(r"C:\Windows\System32"))

    def test_require_raises(self):
        g = base.PathGuard()
        g.add(r"C:\a")
        with self.assertRaises(base.UnsafePath):
            g.require(r"C:\b\c")


class TestProtected(unittest.TestCase):
    def test_system_hives_protected(self):
        for n in ("ntuser.dat", "pagefile.sys", "hiberfil.sys", "SAM"):
            self.assertTrue(base.is_protected(n), n)

    def test_data_extensions(self):
        self.assertTrue(base.looks_like_data("thesis.docx"))
        self.assertTrue(base.looks_like_data("photo.JPG"))
        self.assertFalse(base.looks_like_data("cache.tmp"))


class TestTreemap(unittest.TestCase):
    def test_areas_sum_to_box(self):
        items = [("a", 10), ("b", 30), ("c", 60), ("d", 5)]
        rects = analyzer.squarify(items, 0, 0, 400, 300)
        self.assertEqual(len(rects), 4)
        area = sum(w * h for _l, _x, _y, w, h in rects)
        self.assertAlmostEqual(area, 400 * 300, delta=400 * 300 * 0.02)

    def test_degenerate_inputs(self):
        self.assertEqual(analyzer.squarify([], 0, 0, 10, 10), [])
        self.assertEqual(analyzer.squarify([("a", 0)], 0, 0, 10, 10), [])
        self.assertEqual(analyzer.squarify([("a", 1)], 0, 0, 0, 10), [])


class TestRulesIntegrity(unittest.TestCase):
    def test_ids_unique(self):
        ids = rules.ids()
        self.assertEqual(len(ids), len(set(ids)))

    def test_every_rule_well_formed(self):
        for r in rules.RULES:
            self.assertIn(r["risk"], rules.RISK_ORDER, r["id"])
            self.assertIn("group", r)
            self.assertIn("name", r)
            self.assertTrue(r.get("files") or r.get("action") or r.get("reg")
                            or r.get("reg_scan"), r["id"])

    def test_caution_is_never_default(self):
        for r in rules.RULES:
            if r["risk"] == "caution":
                self.assertFalse(r.get("default"),
                                 f"{r['id']} is caution but on by default")

    def test_no_rule_targets_whole_profile(self):
        """Guard against a rule that would sweep an entire user profile."""
        bad = ("%USERPROFILE%", "%APPDATA%", "%LOCALAPPDATA%", "C:\\Users")
        for r in rules.RULES:
            for ent in r.get("files", []):
                p = ent["path"].rstrip("\\")
                self.assertNotIn(p.upper(), [b.upper() for b in bad],
                                 f"{r['id']} scans an entire profile root")

    def test_expand_handles_unknown_var(self):
        self.assertEqual(scanner.expand_targets("%NOPE_NOT_A_VAR%\\x"), [])


class TestCleanerAccounting(unittest.TestCase):
    def test_locked_file_is_counted_not_raised(self):
        sb = Sandbox()
        try:
            rules.RULES.append({
                "id": "test.locked", "name": "Locked", "group": "Test",
                "risk": "safe", "default": False,
                "files": [{"path": sb.cache, "pattern": "*", "recurse": True,
                           "remove_empty": False}],
            })
            res = scanner.scan(["test.locked"])
            # Make one target permanently undeletable by pointing it at a dir.
            d = os.path.join(sb.cache, "subdir")
            os.makedirs(d, exist_ok=True)
            res.results[0].files.append((d, 0))
            rep = cleaner.clean(res, confirm=True, mode="delete")
            self.assertGreaterEqual(rep.failed + rep.locked, 1)
        finally:
            rules.RULES[:] = [r for r in rules.RULES if r["id"] != "test.locked"]
            sb.cleanup()


class TestErrorClassification(unittest.TestCase):
    """'Close the app' and 'run as administrator' are different instructions;
    conflating them sends the user chasing the wrong fix."""

    def test_access_denied_is_not_locked(self):
        exc = PermissionError(5, "Access is denied")
        exc.winerror = 5
        self.assertTrue(cleaner._is_denied(exc))
        self.assertFalse(cleaner._is_locked(exc))

    def test_sharing_violation_is_locked(self):
        exc = PermissionError(32, "being used by another process")
        exc.winerror = 32
        self.assertTrue(cleaner._is_locked(exc))
        self.assertFalse(cleaner._is_denied(exc))

    def test_lock_violation(self):
        exc = OSError(33, "lock violation")
        exc.winerror = 33
        self.assertTrue(cleaner._is_locked(exc))

    def test_denied_and_locked_counts_are_separate(self):
        rep = cleaner.CleanReport(outcomes=[
            cleaner.RuleOutcome("a", "A", "safe", locked=3),
            cleaner.RuleOutcome("b", "B", "safe", denied=5),
        ])
        self.assertEqual(rep.locked, 3)
        self.assertEqual(rep.denied, 5)
        self.assertEqual(rep.failed, 0)


class TestSessionLog(unittest.TestCase):
    def test_log_records_each_attempt(self):
        sb = Sandbox()
        try:
            rules.RULES.append({
                "id": "test.log", "name": "Log", "group": "Test",
                "risk": "safe", "default": False,
                "files": [{"path": sb.cache, "pattern": "*", "recurse": True,
                           "remove_empty": False}],
            })
            res = scanner.scan(["test.log"])
            logfile = os.path.join(sb.root, "audit.jsonl")
            log = cleaner.SessionLog(logfile)
            cleaner.clean(res, confirm=True, mode="delete", log=log)
            log.close()
            with open(logfile, encoding="utf-8") as fh:
                lines = [ln for ln in fh if ln.strip()]
            # The log carries one pre-run record (the undo point) plus one
            # record per file attempt. Count the attempts, not the lines.
            records = [ln for ln in lines if '"result": "restore-point"' not in ln]
            self.assertEqual(len(records), 5, "one record per file attempt")
            self.assertIn('"result": "deleted"', records[0])
            self.assertTrue(any('"result": "restore-point"' in ln for ln in lines),
                            "the restore-point outcome must be recorded too")
        finally:
            rules.RULES[:] = [r for r in rules.RULES if r["id"] != "test.log"]
            sb.cleanup()


if __name__ == "__main__":
    unittest.main(verbosity=2)
