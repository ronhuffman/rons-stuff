"""Gaps found when the safety fixes were reviewed a second time.

* "Open with" cleanup judged a bare program name by looking only in System32,
  so ordinary third-party programs were called missing.
* A registry enumeration that failed part-way was treated as finished, so a
  backup could silently miss keys that the deletion then removed.
* A clean made only of registry entries was refused: the allow-list check
  counted registry items as files.
* Cookie filtering skipped the allow-list check that every other file gets.
* Links were only refused at scan time; a folder swapped for a link before
  the clean was followed.
"""

from __future__ import annotations

import os
import shutil
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
sys.path.insert(0, HERE)

from sweep import base, cleaner, keep, registry, scanner  # noqa: E402
from test_safety import (HKCU, TEST_KEY, _cookie_db, _FakeRegistry,  # noqa: E402
                         _hosts, _make_dir_link, _scan_with, _StateDir)

FILE_EXTS = r"Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts"


# --------------------------------------------------------------------------
# "Open with": a bare name is only missing if its registration is
# --------------------------------------------------------------------------

class TestOpenWith(_FakeRegistry):
    def setUp(self):
        super().setUp()
        self._win = os.environ.get("WINDIR")
        self.win = os.path.join(self.tmp, "Windows")
        os.makedirs(os.path.join(self.win, "System32"))
        open(os.path.join(self.win, "System32", "notepad.exe"), "wb").close()
        os.environ["WINDIR"] = self.win
        self.alive = os.path.join(self.tmp, "Apps", "Code.exe")
        os.makedirs(os.path.dirname(self.alive))
        open(self.alive, "wb").close()
        self.gone = os.path.join(self.tmp, "Removed", "Old.exe")

    def tearDown(self):
        if self._win is None:
            os.environ.pop("WINDIR", None)
        else:
            os.environ["WINDIR"] = self._win
        super().tearDown()

    def register(self, name, exe, hive=None):
        key = rf"Software\Classes\Applications\{name}\shell\open\command"
        root = registry.HIVES[hive or "HKCU"]
        with self.reg.CreateKeyEx(root, key) as h:
            self.reg.SetValueEx(h, "", 0, self.reg.REG_SZ, f'"{exe}" "%1"')

    def test_unregistered_third_party_name_is_not_missing(self):
        self.assertEqual(registry.open_with_reason("ThirdParty.exe"), "")

    def test_windows_program_is_not_missing(self):
        self.assertEqual(registry.open_with_reason("notepad.exe"), "")

    def test_registered_program_that_exists_is_not_missing(self):
        self.register("Code.exe", self.alive)
        self.assertEqual(registry.open_with_reason("Code.exe"), "")

    def test_registered_program_that_is_gone_is_missing(self):
        self.register("Old.exe", self.gone)
        self.assertIn("missing program", registry.open_with_reason("Old.exe"))

    def test_one_live_registration_is_enough(self):
        self.register("Old.exe", self.gone, "HKCU")
        with self.reg.CreateKeyEx(registry.HIVES["HKLM"],
                                  r"Software\Microsoft\Windows\CurrentVersion\App Paths\Old.exe") as h:
            self.reg.SetValueEx(h, "", 0, self.reg.REG_SZ, self.alive)
        self.assertEqual(registry.open_with_reason("Old.exe"), "")

    def test_full_paths_are_judged_directly(self):
        self.assertEqual(registry.open_with_reason(self.alive), "")
        self.assertIn("missing", registry.open_with_reason(self.gone))

    def test_scan_flags_only_the_proven_entry(self):
        self.register("Old.exe", self.gone)
        owl = FILE_EXTS + r"\.txt\OpenWithList"
        self.put(owl, "a", "ThirdParty.exe")
        self.put(owl, "b", "Old.exe")
        self.put(owl, "c", "notepad.exe")
        self.put(owl, "MRUList", "abc")
        flagged = {e.value for e in registry._scan_open_with()}
        self.assertEqual(flagged, {"b"})


# --------------------------------------------------------------------------
# a registry enumeration that fails part-way stops the backup and the deletion
# --------------------------------------------------------------------------

class TestEnumerationErrors(_FakeRegistry):
    def test_only_no_more_items_ends_an_enumeration(self):
        def gen(stop_error):
            def fn(_h, i):
                if i < 2:
                    return i
                raise stop_error
            return fn
        self.assertEqual(registry._enum_all(gen(OSError(259, "No more data")), None), [0, 1])
        with self.assertRaises(PermissionError):
            registry._enum_all(gen(PermissionError(5, "Access is denied")), None)

    def test_partial_enumeration_blocks_backup_and_deletion(self):
        self.put(TEST_KEY + r"\One", "v", "1")
        self.put(TEST_KEY + r"\Two", "v", "2")
        self.reg.enum_errors[TEST_KEY.lower()] = OSError(5, "Access is denied")
        junk = os.path.join(self.tmp, "junk.tmp")
        open(junk, "wb").close()
        entry = registry.RegEntry("HKCU", TEST_KEY, "subkey", None, "test")
        rule = scanner.RuleResult(rule_id="t.partial", name="P", group="T", risk="safe",
                                  needs_admin=False, files=[(junk, 0)], reg_items=[entry],
                                  count=2)
        rep = cleaner.clean(_scan_with(rule, [junk]), confirm=True, mode="delete",
                            restore_point=False)
        self.assertTrue(self.reg.exists(HKCU, TEST_KEY + r"\Two"),
                        "a backup that missed a key must not license deleting it")
        self.assertTrue(any("backup failed" in e for e in rep.outcomes[0].errors))


# --------------------------------------------------------------------------
# registry-only cleaning is allowed (it has its own backup gate)
# --------------------------------------------------------------------------

class TestRegistryOnlyClean(_FakeRegistry):
    def test_registry_only_selection_is_cleaned_and_backed_up(self):
        self.put(TEST_KEY, "Stale", "x")
        entry = registry.RegEntry("HKCU", TEST_KEY, "subkey", None, "test")
        rule = scanner.RuleResult(rule_id="t.reg", name="R", group="T", risk="safe",
                                  needs_admin=False, reg_items=[entry], count=1)
        rep = cleaner.clean(scanner.ScanResult(results=[rule]), confirm=True,
                            mode="delete", restore_point=False)
        self.assertFalse(self.reg.exists(HKCU, TEST_KEY))
        self.assertEqual(rep.outcomes[0].registry, 1)
        self.assertEqual(len(os.listdir(cleaner.default_backup_dir())), 1)

    def test_files_without_an_allow_list_are_still_refused(self):
        junk = os.path.join(self.tmp, "junk.tmp")
        open(junk, "wb").close()
        rule = scanner.RuleResult(rule_id="t.f", name="F", group="T", risk="safe",
                                  needs_admin=False, files=[(junk, 0)], count=1)
        with self.assertRaises(PermissionError):
            cleaner.clean(scanner.ScanResult(results=[rule]), confirm=True, mode="delete",
                          restore_point=False)
        self.assertTrue(os.path.exists(junk))


# --------------------------------------------------------------------------
# cookie databases go through the same allow-list as every other file
# --------------------------------------------------------------------------

class TestCookieAllowList(_StateDir):
    def test_unpreviewed_cookie_store_is_not_touched(self):
        db = os.path.join(self.tmp, "Cookies")
        _cookie_db(db)
        other = os.path.join(self.tmp, "previewed.tmp")
        open(other, "wb").close()
        keep.KeepList(domains=["example.com"]).save()
        rule = scanner.RuleResult(rule_id="privacy.cookies", name="Cookies", group="T",
                                  risk="moderate", needs_admin=False, handler="cookie_dbs",
                                  files=[(db, 1)], count=1)
        rep = cleaner.clean(_scan_with(rule, [other]), confirm=True, mode="delete",
                            restore_point=False, backup_cookies=False)
        self.assertEqual(_hosts(db), [".example.com", ".tracker.net"])
        self.assertTrue(any("not in allow-list" in e for e in rep.outcomes[0].errors))


# --------------------------------------------------------------------------
# a folder swapped for a link after the scan is still not followed
# --------------------------------------------------------------------------

class TestLinkSwappedAfterScan(_StateDir):
    def test_clean_refuses_a_path_that_became_a_link(self):
        cache = os.path.join(self.tmp, "cache")
        os.makedirs(cache)
        junk = os.path.join(cache, "junk.tmp")
        with open(junk, "wb") as fh:
            fh.write(b"cache")
        rule = scanner.RuleResult(rule_id="t.swap", name="S", group="T", risk="safe",
                                  needs_admin=False, files=[(junk, 5)], count=1)
        res = _scan_with(rule, [junk])

        # After the scan, the cache folder is replaced by a link elsewhere.
        outside = os.path.join(self.tmp, "outside")
        os.makedirs(outside)
        with open(os.path.join(outside, "junk.tmp"), "wb") as fh:
            fh.write(b"precious")
        shutil.rmtree(cache)
        if not _make_dir_link(outside, cache):
            self.skipTest("cannot create a directory link here")
        try:
            rep = cleaner.clean(res, confirm=True, mode="delete", restore_point=False)
            with open(os.path.join(outside, "junk.tmp"), "rb") as fh:
                self.assertEqual(fh.read(), b"precious")
            self.assertTrue(any("through a link" in e for e in rep.outcomes[0].errors))
        finally:
            try:
                os.rmdir(cache) if base.IS_WINDOWS else os.unlink(cache)
            except OSError:
                pass

    def test_file_that_became_a_link_is_not_wiped_through(self):
        cache = os.path.join(self.tmp, "cache2")
        os.makedirs(cache)
        junk = os.path.join(cache, "junk.tmp")
        target = os.path.join(self.tmp, "target.dat")
        with open(target, "wb") as fh:
            fh.write(b"precious")
        try:
            os.symlink(target, junk)
        except (OSError, NotImplementedError):
            self.skipTest("cannot create a file symlink here")
        rule = scanner.RuleResult(rule_id="t.flink", name="L", group="T", risk="safe",
                                  needs_admin=False, files=[(junk, 8)], count=1)
        cleaner.clean(_scan_with(rule, [junk]), confirm=True, mode="secure",
                      restore_point=False)
        with open(target, "rb") as fh:
            self.assertEqual(fh.read(), b"precious", "a wipe must never write through a link")


if __name__ == "__main__":
    unittest.main()
