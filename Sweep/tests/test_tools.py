"""Tests for secure erase, the cookie keep-list, apps, drivers and scheduling."""

from __future__ import annotations

import os
import sqlite3
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sweep import apps, base, drivers, keep, schedule, secure  # noqa: E402

TMP_ROOT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                        ".test-tmp")


def fresh_dir(name: str) -> str:
    os.makedirs(TMP_ROOT, exist_ok=True)
    d = os.path.join(TMP_ROOT, f"{name}-{os.getpid()}")
    os.makedirs(d, exist_ok=True)
    return d


class TestSecureErase(unittest.TestCase):
    def test_wipe_overwrites_then_deletes(self):
        d = fresh_dir("secure")
        path = os.path.join(d, "secret.bin")
        payload = b"A" * 4096
        with open(path, "wb") as fh:
            fh.write(payload)
        res = secure.wipe_file(path, passes=1)
        self.assertTrue(res.ok, res.error)
        self.assertEqual(res.size, 4096)
        self.assertFalse(os.path.exists(path), "file must be gone after a wipe")

    def test_three_pass_wipe(self):
        d = fresh_dir("secure3")
        path = os.path.join(d, "secret3.bin")
        with open(path, "wb") as fh:
            fh.write(os.urandom(2048))
        res = secure.wipe_file(path, passes=3)
        self.assertTrue(res.ok, res.error)
        self.assertFalse(os.path.exists(path))

    def test_wipe_missing_file_reports_error(self):
        res = secure.wipe_file(os.path.join(TMP_ROOT, "nope-does-not-exist.bin"))
        self.assertFalse(res.ok)
        self.assertTrue(res.error)

    def test_patterns_shape(self):
        self.assertEqual(len(secure._patterns(1)), 1)
        self.assertEqual(len(secure._patterns(3)), 3)
        self.assertIsNone(secure._patterns(1)[0])

    def test_free_space_writes_and_cleans_up(self):
        d = fresh_dir("freespace")
        written, files, note = secure.wipe_free_space(d, max_bytes=2 << 20)
        self.assertGreater(written, 0)
        self.assertGreater(files, 0)
        self.assertIn("overwrote", note)
        self.assertFalse(os.path.exists(os.path.join(d, ".sweep-wipe")),
                         "the wipe folder must be removed")


class TestKeepList(unittest.TestCase):
    def test_matching(self):
        doms = ["github.com", "example.org"]
        self.assertTrue(keep.matches("github.com", doms))
        self.assertTrue(keep.matches(".github.com", doms))
        self.assertTrue(keep.matches("api.github.com", doms))
        self.assertFalse(keep.matches("notgithub.com", doms))
        self.assertFalse(keep.matches("github.com.evil.net", doms))

    def test_normalise(self):
        self.assertEqual(keep._normalise("https://www.Example.COM/path?q=1"),
                         "example.com")

    def test_add_remove_save_load(self):
        d = fresh_dir("keep")
        path = os.path.join(d, "keep.json")
        kl = keep.KeepList(domains=[], path=path)
        kl.add("https://www.github.com/foo")
        kl.add("example.org")
        kl.remove("example.org")
        kl.save()
        again = keep.KeepList.load(path)
        self.assertEqual(again.domains, ["github.com"])

    def _make_db(self, path: str, table: str = "cookies", col: str = "host_key"):
        conn = sqlite3.connect(path)
        conn.execute(f"CREATE TABLE {table} (creation_utc INTEGER, {col} TEXT, "
                     f"name TEXT, value TEXT)")
        rows = [(".github.com", "session", "keep"),
                ("github.com", "pref", "keep2"),
                ("evil.example", "track", "drop"),
                (".ads.example", "t", "drop")]
        conn.executemany(f"INSERT INTO {table} ({col}, name, value) VALUES (?,?,?)",
                         rows)
        conn.commit()
        conn.close()

    def test_filter_preserves_kept_cookies(self):
        d = fresh_dir("cookies")
        db = os.path.join(d, "Cookies")
        self._make_db(db)
        res = keep.filter_cookies(db, ["github.com"])
        self.assertFalse(res.error, res.error)
        self.assertEqual(res.table, "cookies")
        self.assertEqual(res.kept, 2)
        self.assertEqual(res.removed, 2)
        self.assertTrue(os.path.isfile(res.backup), "a backup must be written")

        conn = sqlite3.connect(db)
        hosts = [r[0] for r in conn.execute("SELECT host_key FROM cookies")]
        conn.close()
        self.assertEqual(sorted(hosts), [".github.com", "github.com"])

    def test_filter_handles_firefox_layout(self):
        d = fresh_dir("mozcookies")
        db = os.path.join(d, "cookies.sqlite")
        self._make_db(db, table="moz_cookies", col="host")
        res = keep.filter_cookies(db, ["github.com"])
        self.assertFalse(res.error, res.error)
        self.assertEqual(res.table, "moz_cookies")
        self.assertEqual(res.removed, 2)

    def test_empty_keep_list_refuses(self):
        d = fresh_dir("cookies-empty")
        db = os.path.join(d, "Cookies")
        self._make_db(db)
        res = keep.filter_cookies(db, [])
        self.assertTrue(res.error)
        self.assertEqual(res.removed, 0)


class TestApps(unittest.TestCase):
    SAMPLE = (
        "Name                                     Id                     "
        "Version      Available    Source\n"
        "-------------------------------------------------------------------\n"
        "Google Chrome                            Google.Chrome          "
        "120.0.1      121.0.2      winget\n"
        "7-Zip 26.03 (x64)                        7zip.7zip             "
        "26.03        26.05        winget\n"
        "2 upgrades available.\n"
    )

    def test_parse_winget_upgrade(self):
        ups = apps.parse_winget_upgrade(self.SAMPLE)
        self.assertEqual(len(ups), 2, ups)
        self.assertEqual(ups[0].package_id, "Google.Chrome")
        self.assertEqual(ups[0].current, "120.0.1")
        self.assertEqual(ups[0].available, "121.0.2")
        self.assertEqual(ups[1].name, "7-Zip 26.03 (x64)")

    def test_parse_ignores_headers_and_summary(self):
        ups = apps.parse_winget_upgrade(self.SAMPLE)
        ids = [u.package_id for u in ups]
        self.assertNotIn("Name", ids)
        self.assertFalse(any("available" in i.lower() for i in ids))

    def test_list_apps_reads_the_registry(self):
        items = apps.list_apps()
        self.assertIsInstance(items, list)
        for a in items[:5]:
            self.assertTrue(a.name)
            self.assertEqual(a.name, a.name.strip())

    def test_app_key_id_stable(self):
        a = apps.App(name="X", hive="HKLM", key=r"Software\Uninstall\X")
        self.assertEqual(a.key_id, r"HKLM|Software\Uninstall\X")

    def test_leftovers_tokens(self):
        toks = apps._tokens("Adobe Acrobat Reader DC")
        self.assertIn("adobe", toks)
        self.assertNotIn("microsoft", toks)


class TestDrivers(unittest.TestCase):
    def test_inventory_has_entries(self):
        items = drivers.inventory()
        self.assertIsInstance(items, list)
        # registry fallback should find kernel drivers on any real Windows box
        self.assertGreater(len(items), 10)
        for d in items[:5]:
            self.assertTrue(d.module_name)
            self.assertIn(d.driver_type, ("Kernel Driver", "File System Driver", ""))

    def test_start_mode_mapping(self):
        self.assertEqual(drivers.START_MODES[2], "Automatic")
        self.assertEqual(drivers.START_MODES[4], "Disabled")

    def test_driver_type_is_normalised_across_paths(self):
        """driverquery says 'Kernel'; the registry path says 'Kernel Driver'.

        Both must yield the same label, or the UI changes depending on which
        inventory path ran. Only the elevated path uses driverquery, so this
        could not surface until the elevated verification pass existed.
        """
        self.assertEqual(drivers.normalize_type("Kernel"), "Kernel Driver")
        self.assertEqual(drivers.normalize_type("kernel"), "Kernel Driver")
        self.assertEqual(drivers.normalize_type("File System"),
                         "File System Driver")
        self.assertEqual(drivers.normalize_type("User"), "User Mode Driver")
        self.assertEqual(drivers.normalize_type("Kernel Driver"), "Kernel Driver")
        self.assertEqual(drivers.normalize_type(""), "")
        self.assertEqual(drivers.normalize_type("Something New"), "Something New")


class TestSchedule(unittest.TestCase):
    def test_launcher_is_absolute(self):
        exe, args, work = schedule._launcher()
        self.assertTrue(os.path.isabs(exe), exe)
        self.assertIn("clean", args)
        self.assertTrue(os.path.isdir(work), work)

    def test_weekday_mask(self):
        self.assertEqual(schedule._weekday_mask("MON"), "2")
        self.assertEqual(schedule._weekday_mask("SAT,SUN"), "65")
        self.assertEqual(schedule._weekday_mask("garbage"), "62")   # Mon-Fri default

    def test_status_never_raises(self):
        st = schedule.status()
        self.assertIsInstance(st.installed, bool)


if __name__ == "__main__":
    unittest.main(verbosity=2)


class TestConfig(unittest.TestCase):
    def setUp(self):
        from sweep import config
        self.config = config
        os.makedirs(TMP_ROOT, exist_ok=True)
        self.path = os.path.join(TMP_ROOT, f"config-{os.getpid()}.json")
        if os.path.exists(self.path):
            os.unlink(self.path)

    def tearDown(self):
        if os.path.exists(self.path):
            os.unlink(self.path)

    def test_defaults(self):
        data = self.config.load(self.path)
        self.assertEqual(data, self.config.DEFAULTS)
        self.assertFalse(data["auto_elevate"])

    def test_roundtrip(self):
        self.config.save({"auto_elevate": True, "recycle_bin": True}, self.path)
        data = self.config.load(self.path)
        self.assertTrue(data["auto_elevate"])
        self.assertTrue(data["recycle_bin"])

    def test_unknown_keys_are_dropped(self):
        import json
        with open(self.path, "w", encoding="utf-8") as fh:
            json.dump({"auto_elevate": True, "evil": "payload"}, fh)
        data = self.config.load(self.path)
        self.assertNotIn("evil", data)
        self.assertTrue(data["auto_elevate"])

    def test_wrong_type_is_ignored(self):
        import json
        with open(self.path, "w", encoding="utf-8") as fh:
            json.dump({"auto_elevate": "yes please"}, fh)
        self.assertFalse(self.config.load(self.path)["auto_elevate"])

    def test_corrupt_file_falls_back_to_defaults(self):
        with open(self.path, "w", encoding="utf-8") as fh:
            fh.write("{not json")
        self.assertEqual(self.config.load(self.path), self.config.DEFAULTS)

    def test_missing_file_falls_back_to_defaults(self):
        missing = os.path.join(TMP_ROOT, "definitely-not-here.json")
        self.assertEqual(self.config.load(missing), self.config.DEFAULTS)

    def test_save_preserves_other_keys(self):
        self.config.save({"auto_elevate": True}, self.path)
        self.config.save({"recycle_bin": True}, self.path)
        data = self.config.load(self.path)
        self.assertTrue(data["auto_elevate"], "writing one key must not reset another")
        self.assertTrue(data["recycle_bin"])


class TestCheckList(unittest.TestCase):
    """The picking mechanism the Tools lists rely on.

    These need a real Tk root; the suite skips itself where no display exists.
    """

    @classmethod
    def setUpClass(cls):
        try:
            import tkinter as tk
            from sweep import gui as guiwidgets
            cls.gui = guiwidgets
            cls.root = tk.Tk()
            cls.root.withdraw()
        except Exception as exc:                      # no display, no Tk
            raise unittest.SkipTest(f"Tk unavailable: {exc}")

    @classmethod
    def tearDownClass(cls):
        try:
            cls.root.destroy()
        except Exception:
            pass

    def make(self, n=3):
        self.changes = []
        cl = self.gui._CheckList(
            self.root,
            [("detail", "Detail", 100, "w")],
            on_change=lambda checked: self.changes.append(len(checked)),
        )
        keys = []
        for i in range(n):
            keys.append(cl.add(f"k{i}", f"item {i}", (f"detail {i}",)))
        return cl, keys

    def test_all_checked_by_default(self):
        cl, _ = self.make()
        self.assertEqual(len(cl.checked()), 3)

    def test_toggle_off_and_on(self):
        cl, keys = self.make()
        cl.toggle(keys[0])
        self.assertEqual(len(cl.checked()), 2)
        self.assertNotIn("k0", [m["key"] for m in cl.checked()])
        cl.toggle(keys[0])
        self.assertEqual(len(cl.checked()), 3)

    def test_set_all_false_then_true(self):
        cl, _ = self.make()
        cl.set_all(False)
        self.assertEqual(cl.checked(), [])
        cl.set_all(True)
        self.assertEqual(len(cl.checked()), 3)

    def test_on_change_fires(self):
        cl, keys = self.make()
        before = len(self.changes)
        cl.toggle(keys[1])
        self.assertGreater(len(self.changes), before)

    def test_payload_preserved(self):
        cl = self.gui._CheckList(self.root, [("d", "D", 80, "w")])
        iid = cl.add("k", "label", ("x",), payload={"id": "abc"})
        self.assertEqual(cl.rows_meta[iid]["payload"], {"id": "abc"})

    def test_mark_sets_column_and_tag(self):
        cl, keys = self.make()
        cl.mark(keys[0], "detail", "done", "ok")
        self.assertEqual(cl.rows_meta[keys[0]]["tag"], "ok")
        self.assertEqual(cl.tree.set(keys[0], "detail"), "done")


class TestPanelHelpers(unittest.TestCase):
    """Progress bookkeeping is pure arithmetic on a hidden root."""

    @classmethod
    def setUpClass(cls):
        try:
            import tkinter as tk
            cls.tk = tk
            cls.root = tk.Tk()
            cls.root.withdraw()
        except Exception as exc:
            raise unittest.SkipTest(f"Tk unavailable: {exc}")

    @classmethod
    def tearDownClass(cls):
        try:
            cls.root.destroy()
        except Exception:
            pass

    def test_parallel_scan_matches_serial(self):
        from sweep import scanner
        ids = ["windows.thumbnailcache", "windows.shadercache",
               "dev.vscode", "app.spotify"]
        a = scanner.scan(ids, workers=1)
        b = scanner.scan(ids, workers=4)
        self.assertEqual(a.total_size, b.total_size)
        self.assertEqual(a.total_count, b.total_count)
        self.assertEqual([r.rule_id for r in a.results],
                         [r.rule_id for r in b.results],
                         "rule order must be stable regardless of scheduling")

    def test_default_workers_bounded(self):
        from sweep import scanner
        self.assertGreaterEqual(scanner.default_workers(), 1)
        self.assertLessEqual(scanner.default_workers(), 8)


class TestConfigElevation(unittest.TestCase):
    def test_auto_elevate_default_off(self):
        from sweep import config
        self.assertFalse(config.DEFAULTS["auto_elevate"])

    def test_recycle_default_off(self):
        from sweep import config
        self.assertFalse(config.DEFAULTS["recycle_bin"])


class TestToolPanelsRender(unittest.TestCase):
    """A panel that builds a widget but never packs it looks completely empty.

    That is exactly how the Updates tab shipped with '5 selected' and no rows,
    so this test asserts every panel actually puts its content on screen.
    """

    @classmethod
    def setUpClass(cls):
        try:
            from sweep import gui
            cls.gui = gui
            cls.app = gui.SweepApp()
            cls.app.update()
        except Exception as exc:
            raise unittest.SkipTest(f"GUI unavailable: {exc}")

    @classmethod
    def tearDownClass(cls):
        try:
            cls.app.destroy()
        except Exception:
            pass

    def test_every_panel_shows_content(self):
        app = self.app
        app.nb.select(app.tools_tab)
        app.update()
        seen = []
        for i in range(len(app.tools_tab.tabs())):
            app.tools_tab.select(i)
            app.update()
            panel = app.tools_tab.nametowidget(app.tools_tab.tabs()[i])
            mapped = [w for w in panel.body.winfo_children()
                      if w.winfo_ismapped()]
            seen.append(type(panel).__name__)
            self.assertTrue(
                mapped,
                f"{type(panel).__name__} packs no visible content - "
                "the tab will look empty")
        self.assertEqual(len(seen), 6, seen)

    def test_update_list_packs_a_table(self):
        app = self.app
        app.nb.select(app.tools_tab)
        app.tools_tab.select(3)
        app.update()
        panel = app.tools_tab.nametowidget(app.tools_tab.tabs()[3])
        self.assertTrue(panel.list.winfo_ismapped(),
                        "the updates checkbox list must be visible")

    def test_update_list_can_display_rows(self):
        self.app.nb.select(self.app.tools_tab)
        self.app.tools_tab.select(3)
        self.app.update()
        panel = self.app.tools_tab.nametowidget(
            self.app.tools_tab.tabs()[3])
        panel.list.clear()
        panel.list.add("wu:test", "Test update", ("Windows", "10 MB", ""))
        self.assertEqual(len(panel.list.rows_meta), 1)
        self.assertTrue(panel.list.winfo_ismapped())
        self.assertIn("10 MB", panel.list.tree.item(
            panel.list.rows()[0], "values")[1])


class TestWingetErrorExplanations(unittest.TestCase):
    """Real failures seen on this machine must produce actionable text."""

    NETWORK = "0x80072ee7: unknown error"
    TECH = ("A newer version was found, but the install technology is "
            "different from the currently installed version")

    def test_network_error_explained(self):
        text = apps.explain_winget_error(self.NETWORK)
        self.assertIn("network", text.lower())

    def test_install_technology_explained(self):
        text = apps.explain_winget_error(self.TECH)
        self.assertIn("installer", text.lower())
        self.assertIn("vendor", text.lower())

    def test_unknown_message_returns_empty(self):
        self.assertEqual(apps.explain_winget_error("something novel"), "")

    def test_short_status_success(self):
        self.assertEqual(apps.short_status(True, "Successfully installed"), "ok")

    def test_short_status_network(self):
        self.assertIn("network", apps.short_status(False, self.NETWORK))

    def test_short_status_installer_type(self):
        self.assertIn("installer type", apps.short_status(False, self.TECH))

    def test_short_status_falls_back_to_message(self):
        label = apps.short_status(False, "some unexpected failure")
        self.assertIn("some unexpected", label)


class TestUpdateDetailPane(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        try:
            from sweep import gui
            cls.gui = gui
            cls.app = gui.SweepApp()
            cls.app.update()
        except Exception as exc:
            raise unittest.SkipTest(f"GUI unavailable: {exc}")

    @classmethod
    def tearDownClass(cls):
        try:
            cls.app.destroy()
        except Exception:
            pass

    def test_detail_shows_full_message(self):
        app = self.app
        app.nb.select(app.tools_tab)
        app.tools_tab.select(3)
        app.update()
        panel = app.tools_tab.nametowidget(app.tools_tab.tabs()[3])
        panel.list.clear()
        iid = panel.list.add("k", "AOMEI Backupper", ("winget", "8.4 -> 8.5", ""))
        panel.list.mark(iid, "result", "failed: network", "bad",
                        message="AOMEI Backupper - long full explanation here")
        self.assertTrue(panel.detail.winfo_ismapped())
        panel._show_message(panel.list.rows_meta[iid])
        self.assertIn("long full explanation", panel.detail.cget("text"))


class TestUpdateEmptyState(unittest.TestCase):
    """'Nothing found' and 'could not look' must not read the same.

    The Updates page once said "Everything Sweep can see is up to date" while
    both winget and Windows Update had failed - the one message a security tool
    must never get wrong.
    """

    def setUp(self):
        from sweep import gui
        self.gui = gui

    def test_clean_emptiness_says_up_to_date(self):
        msg = self.gui.update_empty_message(0, [])
        self.assertIn("up to date", msg.lower())

    def test_failure_emptiness_never_claims_up_to_date(self):
        msg = self.gui.update_empty_message(0, ["winget: could not activate"])
        self.assertNotIn("up to date", msg.lower())
        self.assertIn("could not be checked", msg.lower())

    def test_results_clear_the_empty_state(self):
        self.assertEqual(self.gui.update_empty_message(3, []), "")
        self.assertEqual(self.gui.update_empty_message(3, ["a note"]), "")

    def test_summary_counts_when_items_exist(self):
        self.assertIn("3 update", self.gui.update_summary(3, []))

    def test_summary_admits_failure(self):
        s = self.gui.update_summary(0, ["winget: could not activate"])
        self.assertIn("could not check", s.lower())
        self.assertNotIn("current", s.lower())

    def test_summary_clean_case(self):
        self.assertIn("current", self.gui.update_summary(0, []).lower())

    def test_long_notes_are_shortened(self):
        note = ("Windows Update: Windows Update refused access. This needs "
                "administrator rights - run 'sweep update --elevate' or start "
                "Sweep as admin.")
        s = self.gui.update_summary(0, [note])
        self.assertLess(len(s), 130, s)
        self.assertIn("could not check", s.lower())

    def test_partial_failure_names_both_sides(self):
        msg = self.gui.update_empty_message(
            0, ["Windows Update: access denied"], checked=["Software"],
            missed=["Windows", "Drivers"])
        self.assertIn("Software", msg)
        self.assertIn("Windows and Drivers could not be checked", msg)
        self.assertNotIn("up to date", msg.lower())

    def test_all_sources_checked_and_empty_is_up_to_date(self):
        msg = self.gui.update_empty_message(
            0, [], checked=["Software", "Windows", "Drivers"], missed=[])
        self.assertIn("up to date", msg.lower())

    def test_summary_names_the_missed_source(self):
        s = self.gui.update_summary(0, ["Windows Update: denied"], missed=["Windows"])
        self.assertIn("could not check Windows", s)


class TestUnreadableScheduler(unittest.TestCase):
    """A Task Scheduler that cannot be read is 'unknown', never 'not scheduled'."""

    def test_no_output_is_an_error_not_absence(self):
        from sweep import schedule
        orig = schedule._run_ps
        schedule._run_ps = lambda script, timeout=120: (1, "")
        try:
            st = schedule.status()
        finally:
            schedule._run_ps = orig
        self.assertFalse(st.installed)
        self.assertTrue(st.error)

    def test_missing_task_is_absence_not_an_error(self):
        from sweep import schedule
        orig = schedule._run_ps
        schedule._run_ps = lambda script, timeout=120: (0, "MISSING")
        try:
            st = schedule.status()
        finally:
            schedule._run_ps = orig
        self.assertFalse(st.installed)
        self.assertFalse(st.error)

    def test_health_reports_unknown_when_unreadable(self):
        from sweep import health, schedule
        orig = schedule.status
        schedule.status = lambda: schedule.ScheduleState(installed=False,
                                                         error="no response")
        try:
            c = health.check_sweep_state()
        finally:
            schedule.status = orig
        self.assertEqual(c.status, health.UNKNOWN)
        self.assertNotIn("not scheduled", c.value)


class TestFrozenBuild(unittest.TestCase):
    """A packaged exe must elevate by relaunching itself.

    There is no interpreter and no ``-m sweep`` inside a PyInstaller build, so
    the unfrozen relaunch path would silently do nothing. These tests pin both
    branches without triggering a real UAC prompt.
    """

    def setUp(self):
        import sys
        from sweep import base, gui
        self.sys = sys
        self.base = base
        self.gui = gui
        self.captured = {}
        self._orig = base.relaunch_elevated
        self._had = hasattr(sys, "frozen")
        base.relaunch_elevated = (
            lambda params, cwd=None, exe=None:
            (self.captured.update(params=params, cwd=cwd, exe=exe) or True))

    def tearDown(self):
        self.base.relaunch_elevated = self._orig
        if not self._had:
            try:
                del self.sys.frozen
            except AttributeError:
                pass

    def test_frozen_relaunch_uses_the_executable(self):
        self.sys.frozen = True
        ok = self.gui._relaunch_elevated_gui()
        self.assertTrue(ok)
        self.assertEqual(self.captured["params"], "--elevated")
        self.assertNotIn("-m sweep", self.captured["params"])
        self.assertEqual(self.captured["exe"], self.sys.executable)

    def test_unfrozen_relaunch_uses_the_module_form(self):
        if getattr(self.sys, "frozen", False):
            self.skipTest("running from a frozen build")
        ok = self.gui._relaunch_elevated_gui()
        self.assertTrue(ok)
        self.assertEqual(self.captured["params"], "-m sweep gui --elevated")
        self.assertIn("pythonw", self.captured["exe"].lower())


class TestCleanPageHonesty(unittest.TestCase):
    """A rule that could not be read must never look like an empty folder.

    The bug this pins: ``_rule_values`` returned on ``rr.empty`` before it
    looked at ``rr.denied``, so the one case that matters - every path denied,
    count therefore zero - showed no note at all.
    """

    def _rr(self, **kw):
        from sweep import scanner
        r = scanner.RuleResult(rule_id="x", name="X", group="Test",
                               needs_admin=False, risk="safe")
        for k, v in kw.items():
            setattr(r, k, v)
        return r

    def _values(self, rr):
        import types
        from sweep import gui
        fake = types.SimpleNamespace(_admin=True)
        return gui.CleanTab._rule_values(fake, {"id": "x", "needs_admin": False}, rr)

    def test_fully_denied_rule_reports_the_denial(self):
        size, _, notes = self._values(self._rr(count=0, size=0, denied=7))
        self.assertIn("7 denied", notes)
        self.assertEqual(size, "\u2013")

    def test_errored_rule_reports_the_error(self):
        _, _, notes = self._values(self._rr(count=0, size=0, error="boom"))
        self.assertIn("error", notes)

    def test_genuinely_empty_rule_stays_silent(self):
        size, _, notes = self._values(self._rr(count=0, size=0))
        self.assertEqual(notes, "", "an empty folder must not claim a problem")
        self.assertEqual(size, "\u2013")

    def test_normal_rule_shows_size(self):
        size, files, notes = self._values(self._rr(count=3, size=100))
        self.assertEqual(size, "100 B")
        self.assertEqual(files, "3")
        self.assertEqual(notes, "")


class TestUnreadableSources(unittest.TestCase):
    """Unreadable must be UNKNOWN, never OK."""

    def test_unreadable_event_log_is_not_an_empty_log(self):
        from sweep import health
        orig = health._ps
        try:
            health._ps = lambda *a, **k: (1, "")
            self.assertIsNone(health.fetch_events(), "no output means unreadable")
            health._ps = lambda *a, **k: (0, "ERR:Access is denied")
            self.assertIsNone(health.fetch_events(), "explicit error means unreadable")
            health._ps = lambda *a, **k: (0, "[]")
            self.assertEqual(health.fetch_events(), [],
                             "a successfully read empty log is a real empty list")
            health._ps = lambda *a, **k: (0, "{ this is not json")
            self.assertIsNone(health.fetch_events(), "unparsable means unreadable")
        finally:
            health._ps = orig

    def test_reliability_is_unknown_when_events_unavailable(self):
        from sweep import health
        c = health.check_reliability(None)
        self.assertEqual(c.status, health.UNKNOWN)
        self.assertIn("unavailable", c.value)

    def test_reliability_ok_only_with_a_real_empty_list(self):
        from sweep import health
        c = health.check_reliability([])
        self.assertEqual(c.status, health.OK)


class TestCoverageHonesty(unittest.TestCase):
    """A source that could not be read must not report a confident count."""

    def test_winget_output_without_a_table_is_not_current(self):
        self.assertFalse(apps._winget_table_recognised("unexpected output here"))
        self.assertTrue(apps._winget_table_recognised(""),
                        "empty output means nothing to upgrade")
        self.assertTrue(apps._winget_table_recognised(
            "Name   Id   Version   Available"))

    def test_list_upgrades_reports_unreadable_output(self):
        class R:
            returncode = 0
            stdout = "something entirely different\n"
            stderr = ""
        orig = apps.subprocess.run
        apps.subprocess.run = lambda *a, **k: R()
        try:
            items, err = apps.list_upgrades()
        finally:
            apps.subprocess.run = orig
        self.assertEqual(items, [])
        self.assertTrue(err, "unparsable output must not read as 'all current'")

    def test_driver_inventory_reports_when_both_sources_fail(self):
        errors: list[str] = []
        orig_dq = drivers._inventory_driverquery
        orig_reg = drivers._inventory_registry
        drivers._inventory_driverquery = lambda: []
        drivers._inventory_registry = lambda: []
        try:
            items = drivers.inventory(errors)
        finally:
            drivers._inventory_driverquery = orig_dq
            drivers._inventory_registry = orig_reg
        self.assertEqual(items, [])
        self.assertTrue(errors, "an empty inventory must say why it is empty")

    def test_apps_report_can_collect_unreadable_roots(self):
        errors: list[str] = []
        items = apps.list_apps(errors)
        self.assertIsInstance(items, list)
        self.assertIsInstance(errors, list)

    def test_scheduler_failure_is_not_not_installed(self):
        orig = schedule._run_ps
        schedule._run_ps = lambda *a, **k: (0, "ERR:Access is denied")
        try:
            st = schedule.status()
        finally:
            schedule._run_ps = orig
        self.assertFalse(st.installed)
        self.assertTrue(st.error, "an unreachable scheduler must carry an error")
        self.assertIn("Access", st.error)

    def test_cancelled_scan_flag_exists(self):
        from sweep import scanner
        self.assertFalse(scanner.ScanResult().cancelled)


class TestLowSeverityHonesty(unittest.TestCase):
    """The quieter versions of the same bug: work that was skipped silently."""

    def test_skipped_files_are_reported_on_the_clean_page(self):
        import types
        from sweep import gui, scanner
        r = scanner.RuleResult(rule_id="x", name="X", group="T",
                               needs_admin=False, risk="safe")
        r.count, r.size, r.skipped = 3, 300, 4
        fake = types.SimpleNamespace(_admin=True)
        _, _, notes = gui.CleanTab._rule_values(fake, {"id": "x"}, r)
        self.assertIn("4 skipped", notes)

    def test_corrupt_keep_list_is_not_an_empty_list(self):
        d = fresh_dir("keep-corrupt")
        path = os.path.join(d, "keep.json")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("{ this is not json")
        kl = keep.KeepList.load(path)
        self.assertEqual(kl.domains, [])
        self.assertTrue(kl.load_error, "a corrupt list must not look empty")
        kl.domains = ["example.com"]
        kl.save()
        self.assertTrue(os.path.exists(path + ".corrupt"),
                        "the unreadable file must be preserved before overwriting")

    def test_missing_keep_list_is_not_an_error(self):
        d = fresh_dir("keep-missing")
        kl = keep.KeepList.load(os.path.join(d, "nothing.json"))
        self.assertEqual(kl.domains, [])
        self.assertEqual(kl.load_error, "", "no file yet is normal, not an error")

    def test_secure_wipe_reports_and_removes(self):
        d = fresh_dir("wipe")
        p = os.path.join(d, "secret.bin")
        with open(p, "wb") as fh:
            fh.write(b"x" * 2048)
        res = secure.wipe_file(p)
        self.assertTrue(res.ok)
        self.assertFalse(os.path.exists(p))

    def test_registry_category_failures_can_be_collected(self):
        from sweep import registry
        errors: list[str] = []
        out = registry.scan_category("no.such.category", errors)
        self.assertEqual(out, [])


