"""Tests for the CCleaner ruleset importer and the registry engine."""

from __future__ import annotations

import json
import os
import shutil
import sys
import time
import unittest
import winreg

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sweep import ccimport, registry  # noqa: E402

TMP_ROOT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                        ".test-tmp")
TEST_KEY = r"Software\SweepSelfTest"


class TestValidation(unittest.TestCase):
    def test_drive_root_refused(self):
        self.assertIsNotNone(ccimport.validate_target("C:\\", "*"))

    def test_profile_root_with_wildcard_refused(self):
        self.assertIsNotNone(
            ccimport.validate_target("%USERPROFILE%", "*", recurse=True))

    def test_profile_root_literal_file_allowed(self):
        # CCleaner has a legitimate rule for one named file here
        self.assertIsNone(
            ccimport.validate_target("%USERPROFILE%", "QTPlayerSession.xml"))

    def test_windows_root_narrow_pattern_allowed(self):
        self.assertIsNone(ccimport.validate_target("%WINDIR%", "*.old;*.tmp"))

    def test_windows_root_unbounded_refused(self):
        self.assertIsNotNone(ccimport.validate_target("%WINDIR%", "*"))

    def test_system_binary_pattern_refused(self):
        self.assertIsNotNone(
            ccimport.validate_target("%WINDIR%\\System32", "*.dll"))
        self.assertIsNotNone(
            ccimport.validate_target("%WINDIR%\\System32", "*.exe"))

    def test_normal_cache_allowed(self):
        self.assertIsNone(
            ccimport.validate_target("%LOCALAPPDATA%\\Google\\Chrome\\User Data\\*\\Cache",
                                     "*", recurse=True))


class TestImporter(unittest.TestCase):
    INI = """\
[Rule Vars]
PROFILE_FOLDERS=%LOCALAPPDATA%\\Vendor\\User Data\\*,%LOCALAPPDATA%\\Vendor\\User Data\\Default

[Vendor Browser - Internet Cache]
Author=Test
Default=True
Tags=Browser
FileKey1=%PROFILE_FOLDERS%|Cache|RECURSE
FileKey2=%WINDIR%|*.old;*.tmp

[Vendor Browser - Cookies]
Default=True
Tags=Browser
FileKey1=%LOCALAPPDATA%\\Vendor\\User Data\\*\\Network|Cookies

[Dangerous]
Default=False
FileKey1=%USERPROFILE%|*|RECURSE
FileKey2=C:\\|*|RECURSE

[Recycle]
Default=False
Action1=EmptyRecycleBin

[Reg Cleanup]
Default=False
Action1=Registry|MUICache
"""

    @classmethod
    def setUpClass(cls):
        os.makedirs(TMP_ROOT, exist_ok=True)
        cls.path = os.path.join(TMP_ROOT, f"test-{os.getpid()}.ini")
        with open(cls.path, "w", encoding="utf-8") as fh:
            fh.write(cls.INI)
        cls.report = ccimport.parse(cls.path)

    @classmethod
    def tearDownClass(cls):
        try:
            os.unlink(cls.path)
        except OSError:
            pass

    def test_rule_vars_expand_to_multiple_paths(self):
        rule = next(r for r in self.report.rules if r["name"].endswith("Internet Cache"))
        paths = [f["path"] for f in rule["files"]]
        self.assertEqual(len(paths), 3, paths)      # 2 from the var + the windir rule
        self.assertTrue(any("Default" in p for p in paths))

    def test_recursive_flag_parsed(self):
        rule = next(r for r in self.report.rules if r["name"].endswith("Internet Cache"))
        self.assertTrue(rule["files"][0]["recurse"])

    def test_dangerous_targets_dropped(self):
        self.assertTrue(any("Dangerous" in n for n, _ in self.report.dropped_unsafe))
        names = [r["name"] for r in self.report.rules]
        self.assertNotIn("Dangerous", names)

    def test_cookies_marked_caution_and_off(self):
        rule = next(r for r in self.report.rules if r["name"].endswith("Cookies"))
        self.assertEqual(rule["risk"], "caution")
        self.assertFalse(rule["default"],
                         "a caution rule must never be a default even if the ini says so")

    def test_action_mapped(self):
        rule = next(r for r in self.report.rules if r["name"] == "Recycle")
        self.assertEqual(rule["action"], "empty_recycle_bin")

    def test_registry_action_becomes_scan_category(self):
        rule = next(r for r in self.report.rules if r["name"] == "Reg Cleanup")
        self.assertEqual(rule.get("reg_scan"), "muicache")

    def test_save_and_load_roundtrip(self):
        out = os.path.join(TMP_ROOT, f"rules-{os.getpid()}.json")
        try:
            ccimport.save(self.report, out)
            loaded, blob = ccimport.load(out)
            self.assertEqual(len(loaded), len(self.report.rules))
            self.assertIn("summary", blob)
        finally:
            try:
                os.unlink(out)
            except OSError:
                pass


class TestRegistryEngine(unittest.TestCase):
    def setUp(self):
        self._clear()
        try:
            with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, TEST_KEY, 0,
                                    winreg.KEY_WRITE) as hk:
                winreg.SetValueEx(hk, "Alpha", 0, winreg.REG_SZ, "one")
                winreg.SetValueEx(hk, "Beta", 0, winreg.REG_DWORD, 42)
        except PermissionError:
            # A confined sandbox can deny HKCU writes; the engine is still
            # exercised by the non-mutating tests in that case.
            self.skipTest("registry writes not permitted in this environment")

    def tearDown(self):
        self._clear()

    @staticmethod
    def _clear():
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, TEST_KEY, 0,
                                winreg.KEY_READ | winreg.KEY_WRITE) as hk:
                names = []
                i = 0
                while True:
                    try:
                        names.append(winreg.EnumValue(hk, i)[0])
                    except OSError:
                        break
                    i += 1
                for n in names:
                    winreg.DeleteValue(hk, n)
        except OSError:
            pass
        try:
            winreg.DeleteKey(winreg.HKEY_CURRENT_USER, TEST_KEY)
        except OSError:
            pass

    def test_scan_direct_finds_named_value(self):
        items = registry.scan_direct({"hive": "HKCU", "key": TEST_KEY, "value": "Alpha"})
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0].value, "Alpha")

    def test_scan_direct_wildcard_finds_all(self):
        items = registry.scan_direct({"hive": "HKCU", "key": TEST_KEY, "value": "*"})
        self.assertEqual({i.value for i in items}, {"Alpha", "Beta"})

    def test_backup_remove_restore_roundtrip(self):
        items = registry.scan_direct({"hive": "HKCU", "key": TEST_KEY, "value": "*"})
        self.assertEqual(len(items), 2)

        os.makedirs(TMP_ROOT, exist_ok=True)
        backup = os.path.join(TMP_ROOT, f"reg-{os.getpid()}.json")
        try:
            registry.backup(items, backup)
            self.assertTrue(os.path.isfile(backup))

            ok, fail = registry.remove(items)
            self.assertEqual((ok, fail), (2, 0))

            left = registry.scan_direct({"hive": "HKCU", "key": TEST_KEY, "value": "*"})
            self.assertEqual(left, [], "values should be gone")

            ok, fail = registry.restore(backup)
            self.assertEqual((ok, fail), (2, 0))

            back = {i.value: i._data for i in
                    registry.scan_direct({"hive": "HKCU", "key": TEST_KEY, "value": "*"})}
            self.assertEqual(back.get("Alpha"), "one")
            self.assertEqual(back.get("Beta"), 42, "DWORD type and value must survive")
        finally:
            try:
                os.unlink(backup)
            except OSError:
                pass

    def test_backup_is_json_with_types(self):
        items = registry.scan_direct({"hive": "HKCU", "key": TEST_KEY, "value": "Beta"})
        os.makedirs(TMP_ROOT, exist_ok=True)
        backup = os.path.join(TMP_ROOT, f"reg2-{os.getpid()}.json")
        try:
            registry.backup(items, backup)
            with open(backup, encoding="utf-8") as fh:
                blob = json.load(fh)
            rec = blob["entries"][0]
            self.assertEqual(rec["type_name"], "REG_DWORD")
            self.assertEqual(rec["data"], 42)
        finally:
            try:
                os.unlink(backup)
            except OSError:
                pass


class TestUnimplementedIsHonest(unittest.TestCase):
    def test_not_implemented_list_is_documented(self):
        self.assertTrue(registry.NOT_IMPLEMENTED)
        for cat, reason in registry.NOT_IMPLEMENTED.items():
            self.assertTrue(reason, f"{cat} needs a stated reason")

    def test_no_overlap_between_implemented_and_not(self):
        self.assertFalse(set(registry.implemented()) & set(registry.NOT_IMPLEMENTED))

    def test_unknown_category_returns_empty(self):
        self.assertEqual(registry.scan_category("no_such_category"), [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
