"""Safeguards that must hold on every path, not just the command line.

Each test pins a defect found in review:

* the GUI cleaned without the saved cookie keep-list or registry backups;
* a whole-key registry backup saved only the key's name, so restoring it
  brought back an empty key; and an install was called "obsolete" when only
  one of its install folder and uninstaller was missing;
* a cleaning root that was itself a junction (or sat beneath one) was walked;
* the free-space wipe reused a fixed folder and then deleted everything in it;
* the packaged exe opened the window for the scheduled "clean" command;
* disabling a registry startup entry used an already-closed registry handle.
"""

from __future__ import annotations

import importlib.util
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
sys.path.insert(0, HERE)

from fakereg import FakeWinreg  # noqa: E402
from sweep import base, cleaner, keep, registry, scanner, secure, system  # noqa: E402

HKCU = registry.HIVES["HKCU"]
TEST_KEY = r"Software\SweepSafetyTest"


class _StateDir(unittest.TestCase):
    """Point Sweep's state folder (keep-list, logs, backups) at a temp dir."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="sweep-safety-")
        self._old_home = os.environ.get("SWEEP_HOME")
        os.environ["SWEEP_HOME"] = self.tmp

    def tearDown(self):
        if self._old_home is None:
            os.environ.pop("SWEEP_HOME", None)
        else:
            os.environ["SWEEP_HOME"] = self._old_home
        shutil.rmtree(self.tmp, ignore_errors=True)


class _FakeRegistry(_StateDir):
    def setUp(self):
        super().setUp()
        self.reg = FakeWinreg(registry.winreg)
        self._orig = (registry.winreg, system.winreg)
        registry.winreg = self.reg
        system.winreg = self.reg

    def tearDown(self):
        registry.winreg, system.winreg = self._orig
        super().tearDown()

    def put(self, sub, name, data, typ=None):
        with self.reg.CreateKeyEx(HKCU, sub) as h:
            self.reg.SetValueEx(h, name, 0, typ if typ is not None else self.reg.REG_SZ, data)


# --------------------------------------------------------------------------
# 1. cleaner safeguards no longer depend on the caller
# --------------------------------------------------------------------------

def _scan_with(rule: scanner.RuleResult, files: list[str]) -> scanner.ScanResult:
    res = scanner.ScanResult(results=[rule])
    res.allowlist = {base.norm(p) for p in files}
    return res


class TestCleanerDefaults(_FakeRegistry):
    def _mixed_rule(self):
        junk = os.path.join(self.tmp, "junk.tmp")
        with open(junk, "wb") as fh:
            fh.write(b"x" * 10)
        self.put(TEST_KEY + r"\Child", "Path", r"C:\gone\app.exe")
        self.put(TEST_KEY, "Count", 7, self.reg.REG_DWORD)
        entry = registry.RegEntry("HKCU", TEST_KEY, "subkey", None, "test")
        rule = scanner.RuleResult(rule_id="t.mixed", name="Mixed", group="T", risk="safe",
                                  needs_admin=False, files=[(junk, 10)], reg_items=[entry],
                                  count=2, size=10)
        return rule, junk

    def test_registry_is_backed_up_when_no_folder_is_given(self):
        rule, junk = self._mixed_rule()
        rep = cleaner.clean(_scan_with(rule, [junk]), confirm=True, mode="delete",
                            restore_point=False)
        self.assertFalse(self.reg.exists(HKCU, TEST_KEY), "key should be removed")
        backups = os.listdir(cleaner.default_backup_dir())
        self.assertEqual(len(backups), 1, "a registry backup must always be written")
        self.assertEqual(rep.outcomes[0].registry, 1)
        ok, bad = registry.restore(os.path.join(cleaner.default_backup_dir(), backups[0]))
        self.assertEqual((ok, bad), (1, 0))
        self.assertEqual(self.reg.dump(HKCU, TEST_KEY)["values"]["Count"],
                         (7, self.reg.REG_DWORD))
        self.assertEqual(self.reg.dump(HKCU, TEST_KEY + r"\Child")["values"]["Path"][0],
                         r"C:\gone\app.exe")

    def test_unreadable_tree_blocks_the_deletion(self):
        rule, junk = self._mixed_rule()
        self.reg.denied.add((TEST_KEY + r"\Child").lower())
        rep = cleaner.clean(_scan_with(rule, [junk]), confirm=True, mode="delete",
                            restore_point=False)
        self.assertTrue(self.reg.exists(HKCU, TEST_KEY + r"\Child"),
                        "no complete backup, no deletion")
        self.assertEqual(rep.outcomes[0].registry, 0)
        self.assertTrue(any("backup failed" in e for e in rep.outcomes[0].errors))


def _cookie_db(path: str) -> None:
    conn = sqlite3.connect(path)
    conn.execute("CREATE TABLE cookies (host_key TEXT, name TEXT)")
    conn.executemany("INSERT INTO cookies VALUES (?, ?)",
                     [(".example.com", "keep"), (".tracker.net", "drop")])
    conn.commit()
    conn.close()


def _hosts(path: str) -> list[str]:
    conn = sqlite3.connect(path)
    try:
        return sorted(h for (h,) in conn.execute("SELECT host_key FROM cookies"))
    finally:
        conn.close()


class TestCookieKeepList(_StateDir):
    def _rule(self):
        db = os.path.join(self.tmp, "Cookies")
        _cookie_db(db)
        rule = scanner.RuleResult(rule_id="privacy.cookies", name="Cookies", group="T",
                                  risk="moderate", needs_admin=False, handler="cookie_dbs",
                                  files=[(db, os.path.getsize(db))], count=1, size=1)
        return rule, db

    def test_saved_keep_list_is_honoured_without_being_passed(self):
        rule, db = self._rule()
        keep.KeepList(domains=["example.com"]).save()
        cleaner.clean(_scan_with(rule, [db]), confirm=True, mode="delete",
                      restore_point=False, backup_cookies=False)
        self.assertEqual(_hosts(db), [".example.com"])

    def test_unreadable_keep_list_leaves_cookies_alone(self):
        rule, db = self._rule()
        with open(keep.default_path(), "w", encoding="utf-8") as fh:
            fh.write("{not json")
        rep = cleaner.clean(_scan_with(rule, [db]), confirm=True, mode="delete",
                            restore_point=False, backup_cookies=False)
        self.assertTrue(os.path.exists(db))
        self.assertEqual(_hosts(db), [".example.com", ".tracker.net"])
        self.assertTrue(any("keep-list unreadable" in e for e in rep.outcomes[0].errors))

    def test_explicit_empty_list_still_means_keep_nothing(self):
        rule, db = self._rule()
        keep.KeepList(domains=["example.com"]).save()
        cleaner.clean(_scan_with(rule, [db]), confirm=True, mode="delete",
                      restore_point=False, keep_domains=[])
        self.assertFalse(os.path.exists(db), "--no-keep deletes the store as before")


class TestGuiPassesSafeguards(_StateDir):
    def test_gui_clean_uses_backups_and_the_saved_keep_list(self):
        try:
            from tkinter import messagebox
            from sweep import gui
            app = gui.SweepApp()
        except Exception as exc:
            self.skipTest(f"GUI unavailable: {exc}")
        captured = {}
        orig = (cleaner.clean, messagebox.askyesno, messagebox.showinfo)

        def fake_clean(res, **kw):
            captured.update(kw)
            return cleaner.CleanReport(simulated=False, mode=kw.get("mode", "delete"))

        cleaner.clean = fake_clean
        messagebox.askyesno = lambda *a, **k: True
        messagebox.showinfo = lambda *a, **k: None
        try:
            junk = os.path.join(self.tmp, "junk.tmp")
            open(junk, "wb").close()
            rule = scanner.RuleResult(rule_id="t.one", name="One", group="T", risk="safe",
                                      needs_admin=False, files=[(junk, 1)], count=1, size=1)
            tab = app.clean_tab
            tab.last_scan = _scan_with(rule, [junk])
            tab.selected = {"t.one"}
            tab.do_clean()
            end = time.time() + 10
            while tab.worker.busy and time.time() < end:
                app.update()
                time.sleep(0.02)
            app.update()
        finally:
            cleaner.clean, messagebox.askyesno, messagebox.showinfo = orig
            app.destroy()
        self.assertTrue(captured, "the clean never ran")
        self.assertTrue(captured.get("backup_dir", "").endswith("registry-backups"))
        self.assertIn("keep_domains", captured)
        self.assertIsNone(captured["keep_domains"], "None = the saved keep-list")


# --------------------------------------------------------------------------
# 2. registry backups are complete, and "dangling" means proven
# --------------------------------------------------------------------------

class TestRegistryRoundTrip(_FakeRegistry):
    def test_subkey_backup_restores_the_whole_tree_with_types(self):
        self.put(TEST_KEY, "", "default text")
        self.put(TEST_KEY, "Bin", b"\x00\x01\xff", self.reg.REG_BINARY)
        self.put(TEST_KEY, "Multi", ["a", "b"], self.reg.REG_MULTI_SZ)
        self.put(TEST_KEY + r"\A\B", "Deep", 5, self.reg.REG_DWORD)
        before = self.reg.dump(HKCU, TEST_KEY)
        entry = registry.RegEntry("HKCU", TEST_KEY, "subkey", None, "test")
        path = registry.backup([entry], os.path.join(self.tmp, "b.json"))
        self.assertEqual(registry.remove([entry]), (1, 0))
        self.assertFalse(self.reg.exists(HKCU, TEST_KEY))
        self.assertEqual(registry.restore(path), (1, 0))
        self.assertEqual(self.reg.dump(HKCU, TEST_KEY), before)

    def test_missing_key_is_a_failure_not_a_removal(self):
        entry = registry.RegEntry("HKCU", TEST_KEY + r"\Nope", "subkey", None, "test")
        self.assertEqual(registry.remove([entry]), (0, 1))


class TestObsoleteSoftware(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="sweep-obsolete-")
        self.gone = os.path.join(self.tmp, "gone")
        self.exe = os.path.join(self.tmp, "unins000.exe")
        open(self.exe, "wb").close()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_both_gone_is_obsolete(self):
        why = registry.obsolete_reason(self.gone, f'"{os.path.join(self.gone, "u.exe")}"')
        self.assertIn("both gone", why)

    def test_one_missing_pointer_is_not_proof(self):
        self.assertEqual(registry.obsolete_reason(self.gone, f'"{self.exe}"'), "")
        self.assertEqual(registry.obsolete_reason(self.tmp, f'"{self.gone}\\u.exe"'), "")

    def test_only_one_pointer_recorded_is_not_proof(self):
        self.assertEqual(registry.obsolete_reason(self.gone, ""), "")
        self.assertEqual(registry.obsolete_reason("", f'"{self.gone}\\u.exe"'), "")

    def test_msiexec_uninstaller_cannot_be_judged(self):
        self.assertEqual(registry.obsolete_reason(
            self.gone, "MsiExec.exe /X{12345678-1234-1234-1234-123456789012}"), "")

    def test_bare_names_are_never_called_missing(self):
        self.assertTrue(registry._exists("MsiExec.exe"))
        self.assertTrue(registry._exists("ding.wav"))
        self.assertFalse(registry._exists(self.gone))

    def test_muicache_names_are_checked_as_programs(self):
        self.assertEqual(registry._muicache_target(r"C:\x\app.exe.FriendlyAppName"),
                         r"C:\x\app.exe")
        self.assertEqual(registry._muicache_target(r"C:\x\app.exe.ApplicationCompany"),
                         r"C:\x\app.exe")
        self.assertEqual(registry._muicache_target(r"@C:\x\shell32.dll,-22067"),
                         r"C:\x\shell32.dll")


# --------------------------------------------------------------------------
# 3. a cleaning root reached through a link is never walked
# --------------------------------------------------------------------------

def _make_dir_link(target: str, link: str) -> bool:
    try:
        os.symlink(target, link, target_is_directory=True)
        return True
    except (OSError, NotImplementedError):
        pass
    if base.IS_WINDOWS:                    # junctions need no special privilege
        r = subprocess.run(["cmd", "/c", "mklink", "/J", link, target],
                           capture_output=True, text=True)
        return r.returncode == 0 and os.path.isdir(link)
    return False


class TestLinkedRoots(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="sweep-links-")
        self.outside = os.path.join(self.tmp, "outside")
        os.makedirs(os.path.join(self.outside, "sub"))
        for p in ("precious.dat", os.path.join("sub", "precious.dat")):
            with open(os.path.join(self.outside, p), "wb") as fh:
                fh.write(b"x")
        self.cache = os.path.join(self.tmp, "cache")
        if not _make_dir_link(self.outside, self.cache):
            self.skipTest("cannot create a directory link here")

    def tearDown(self):
        try:
            os.rmdir(self.cache) if base.IS_WINDOWS else os.unlink(self.cache)
        except OSError:
            pass
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_link_itself_is_refused(self):
        refused = []
        self.assertEqual(scanner.expand_targets(self.cache, refused), [])
        self.assertEqual(refused, [self.cache])

    def test_folder_beneath_a_link_is_refused(self):
        under = os.path.join(self.cache, "sub")
        self.assertEqual(scanner.expand_targets(under), [])
        self.assertEqual(scanner.expand_targets(os.path.join(self.cache, "*")), [])

    def test_scan_offers_nothing_and_reports_it_skipped(self):
        rule = {"id": "t.link", "name": "Linked", "group": "T", "risk": "safe",
                "files": [{"path": self.cache, "pattern": "*", "recurse": True}]}
        rr, _stats = scanner._scan_rule(rule, None, time.time(), 0, lambda: None)
        self.assertEqual(rr.files, [])
        self.assertGreater(rr.skipped, 0)
        self.assertFalse(rr.absent, "present but refused is not 'absent'")

    def test_real_folder_still_scans(self):
        self.assertEqual(scanner.expand_targets(self.outside), [self.outside])


# --------------------------------------------------------------------------
# 4. free-space wipe only touches files it created
# --------------------------------------------------------------------------

class TestWipeFreeSpace(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="sweep-wipe-test-")
        self.old = os.path.join(self.root, ".sweep-wipe")
        os.makedirs(self.old)
        for name in ("keep.txt", "wipe-000000.bin"):
            with open(os.path.join(self.old, name), "w") as fh:
                fh.write("not yours")

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def test_existing_files_survive_and_nothing_is_left_behind(self):
        written, files, note = secure.wipe_free_space(self.root, max_bytes=2 << 20)
        self.assertGreater(files, 0, note)
        for name in ("keep.txt", "wipe-000000.bin"):
            with open(os.path.join(self.old, name)) as fh:
                self.assertEqual(fh.read(), "not yours", name)
        self.assertEqual(sorted(os.listdir(self.root)), [".sweep-wipe"],
                         "the run's own folder must be gone, and nothing else touched")


# --------------------------------------------------------------------------
# 5. the packaged exe runs the scheduled command instead of the window
# --------------------------------------------------------------------------

class TestPackagedEntryPoint(_StateDir):
    def setUp(self):
        super().setUp()
        spec = importlib.util.spec_from_file_location(
            "pyinstaller_entry", os.path.join(ROOT, "tools", "pyinstaller_entry.py"))
        self.entry = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.entry)
        from sweep import cli, gui
        self.cli, self.gui = cli, gui
        self.calls = []
        self._orig = (cli.main, gui.main)
        cli.main = lambda argv: self.calls.append(("cli", list(argv))) or 0
        gui.main = lambda argv=None: self.calls.append(("gui", list(argv or [])))

    def tearDown(self):
        self.cli.main, self.gui.main = self._orig
        super().tearDown()

    def test_scheduled_command_runs_the_command_line(self):
        had = hasattr(sys, "frozen")
        sys.frozen = True
        try:
            from sweep import schedule
            _exe, args, _work = schedule._launcher()
        finally:
            if not had:
                del sys.frozen
        self.entry.run(args.split())
        self.assertEqual(self.calls, [("cli", ["clean", "--apply", "--quiet"])])

    def test_no_arguments_and_options_open_the_window(self):
        self.entry.run([])
        self.entry.run(["--elevated"])
        self.assertEqual(self.calls, [("gui", []), ("gui", ["--elevated"])])

    def test_windowed_build_output_goes_to_a_log(self):
        out, err = sys.stdout, sys.stderr
        sys.stdout = sys.stderr = None
        try:
            self.entry.run(["clean", "--apply", "--quiet"])
            self.assertIsNotNone(sys.stdout)
            self.assertIsNotNone(sys.stderr)
            log = sys.stdout.name
        finally:
            for s in {id(sys.stdout): sys.stdout, id(sys.stderr): sys.stderr}.values():
                try:
                    s.close()
                except Exception:
                    pass
            sys.stdout, sys.stderr = out, err
        self.assertTrue(log.startswith(self.tmp), log)


# --------------------------------------------------------------------------
# 6. disabling a registry startup entry works, and never loses it
# --------------------------------------------------------------------------

RUN = r"Software\Microsoft\Windows\CurrentVersion\Run"


class TestStartupToggle(_FakeRegistry):
    def setUp(self):
        super().setUp()
        self._q = (system.QUARANTINE_DIR, system.QUARANTINE_DB)
        system.QUARANTINE_DIR = os.path.join(self.tmp, "disabled-startup")
        system.QUARANTINE_DB = os.path.join(system.QUARANTINE_DIR, "registry.json")
        self.put(RUN, "Updater", r'"C:\Apps\updater.exe" /background')
        self.item = system.StartupItem(name="Updater", command="", location="HKCU Run",
                                       kind="registry", hive="HKCU", key=RUN,
                                       value="Updater")

    def tearDown(self):
        system.QUARANTINE_DIR, system.QUARANTINE_DB = self._q
        super().tearDown()

    def _value(self):
        try:
            with self.reg.OpenKey(HKCU, RUN) as h:
                return self.reg.QueryValueEx(h, "Updater")[0]
        except FileNotFoundError:
            return None

    def test_disable_then_enable_round_trip(self):
        self.assertEqual(system.disable_startup(self.item),
                         "disabled (moved to Sweep quarantine)")
        self.assertIsNone(self._value())
        with open(system.QUARANTINE_DB, encoding="utf-8") as fh:
            self.assertEqual(json.load(fh)[0]["command"], r'"C:\Apps\updater.exe" /background')
        self.assertEqual(system.enable_startup(self.item), "re-enabled")
        self.assertEqual(self._value(), r'"C:\Apps\updater.exe" /background')

    def test_missing_entry_is_reported_as_missing(self):
        self.item.value = "NotThere"
        self.assertEqual(system.disable_startup(self.item), "entry no longer present")

    def test_unreadable_record_store_changes_nothing(self):
        os.makedirs(system.QUARANTINE_DIR)
        with open(system.QUARANTINE_DB, "w", encoding="utf-8") as fh:
            fh.write("[{broken")
        msg = system.disable_startup(self.item)
        self.assertTrue(msg.startswith("failed"), msg)
        self.assertIsNotNone(self._value(), "the entry must stay where it is")
        with open(system.QUARANTINE_DB, encoding="utf-8") as fh:
            self.assertEqual(fh.read(), "[{broken", "never save over an unreadable store")


# --------------------------------------------------------------------------
# the same two registry paths against the real Windows registry
# --------------------------------------------------------------------------

@unittest.skipUnless(base.IS_WINDOWS, "needs the real Windows registry")
class TestRealRegistry(_StateDir):
    """The fake registry pins the logic; this proves it against real winreg,
    in a scratch key under HKCU that the test creates and removes."""

    def setUp(self):
        super().setUp()
        import winreg
        self.w = winreg
        self.key = rf"Software\SweepSafetyTest-{os.getpid()}"
        try:
            with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, self.key + r"\Sub", 0,
                                    winreg.KEY_WRITE) as h:
                winreg.SetValueEx(h, "Bin", 0, winreg.REG_BINARY, b"\x01\x02")
            with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, self.key, 0,
                                    winreg.KEY_WRITE) as h:
                winreg.SetValueEx(h, "Run", 0, winreg.REG_SZ, r'"C:\x\a.exe" /q')
                winreg.SetValueEx(h, "N", 0, winreg.REG_DWORD, 9)
        except PermissionError:
            self.skipTest("registry writes not permitted here")

    def tearDown(self):
        try:
            registry._delete_tree(self.w.HKEY_CURRENT_USER, self.key)
        except OSError:
            pass
        super().tearDown()

    def _read(self, sub, name):
        with self.w.OpenKey(self.w.HKEY_CURRENT_USER, sub) as h:
            return self.w.QueryValueEx(h, name)

    def test_subkey_round_trip(self):
        entry = registry.RegEntry("HKCU", self.key, "subkey", None, "test")
        path = registry.backup([entry], os.path.join(self.tmp, "real.json"))
        self.assertEqual(registry.remove([entry]), (1, 0))
        with self.assertRaises(FileNotFoundError):
            self._read(self.key, "N")
        self.assertEqual(registry.restore(path), (1, 0))
        self.assertEqual(self._read(self.key, "N"), (9, self.w.REG_DWORD))
        self.assertEqual(self._read(self.key + r"\Sub", "Bin"),
                         (b"\x01\x02", self.w.REG_BINARY))

    def test_startup_disable_and_enable(self):
        q = (system.QUARANTINE_DIR, system.QUARANTINE_DB)
        system.QUARANTINE_DIR = os.path.join(self.tmp, "disabled-startup")
        system.QUARANTINE_DB = os.path.join(system.QUARANTINE_DIR, "registry.json")
        try:
            item = system.StartupItem(name="Run", command="", location="test",
                                      kind="registry", hive="HKCU", key=self.key,
                                      value="Run")
            self.assertEqual(system.disable_startup(item),
                             "disabled (moved to Sweep quarantine)")
            with self.assertRaises(FileNotFoundError):
                self._read(self.key, "Run")
            self.assertEqual(system.enable_startup(item), "re-enabled")
            self.assertEqual(self._read(self.key, "Run")[0], r'"C:\x\a.exe" /q')
        finally:
            system.QUARANTINE_DIR, system.QUARANTINE_DB = q


if __name__ == "__main__":
    unittest.main()
