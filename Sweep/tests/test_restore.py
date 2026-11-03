"""Restore points must be reported as they are, and tool pages must not crash
when Windows refuses to show them something.

Since Windows 8, SRSetRestorePointW skips the restore point when one was made in
the last 24 hours - and still returns TRUE, ERROR_SUCCESS and the *previous*
point's sequence number. Sweep used to report that as "restore point created".
"""

from __future__ import annotations

import os
import sys
import time
import unittest
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sweep import cleaner, system  # noqa: E402

UTC = timezone.utc


def point(seq: int, minutes_ago: float | None = 600, desc: str = "Windows Update"):
    created = (None if minutes_ago is None
               else datetime.now(UTC) - timedelta(minutes=minutes_ago))
    return system.RestorePoint(sequence=seq, created=created, description=desc)


class TestParseRestorePoint(unittest.TestCase):
    def test_parses_wmi_line(self):
        p = system.parse_restore_point("57|20261102213012.123456-000|Installed AOMEI")
        self.assertEqual(p.sequence, 57)
        self.assertEqual(p.description, "Installed AOMEI")
        self.assertEqual(p.created, datetime(2026, 11, 2, 21, 30, 12, tzinfo=UTC))

    def test_offset_is_honoured(self):
        p = system.parse_restore_point("3|20261102213012.000000+060|x")
        self.assertEqual(p.created.utcoffset(), timedelta(minutes=60))

    def test_bad_time_keeps_the_point(self):
        p = system.parse_restore_point("9|not-a-date|x")
        self.assertEqual(p.sequence, 9)
        self.assertIsNone(p.created)
        self.assertEqual(p.when(), "earlier")

    def test_garbage_is_none(self):
        self.assertIsNone(system.parse_restore_point(""))
        self.assertIsNone(system.parse_restore_point("abc|def"))


class TestRestoreOutcome(unittest.TestCase):
    def test_new_sequence_is_created(self):
        kind, msg = system.restore_outcome(True, 0, 58, point(57), True)
        self.assertEqual(kind, "created")
        self.assertIn("58", msg)

    def test_first_ever_point_is_created(self):
        kind, _ = system.restore_outcome(True, 0, 1, None, True)
        self.assertEqual(kind, "created")

    def test_24_hour_skip_is_not_created(self):
        # The trap: TRUE + ERROR_SUCCESS + the old sequence number.
        kind, msg = system.restore_outcome(True, 0, 57, point(57, 90, "Installed AOMEI"), True)
        self.assertEqual(kind, "skipped")
        self.assertTrue(msg.startswith("skipped - "))
        self.assertIn("24 hours", msg)
        self.assertIn("Installed AOMEI", msg)
        self.assertNotIn("created (", msg)

    def test_api_error_is_failed_in_plain_words(self):
        kind, msg = system.restore_outcome(True, 1058, 0, None, True)
        self.assertEqual(kind, "failed")
        self.assertIn("System Protection is turned off", msg)

    def test_documented_status_codes_are_explained(self):
        for code in (10, 13, 112, 1359, 1460):
            kind, msg = system.restore_outcome(True, code, 0, None, True)
            self.assertEqual(kind, "failed")
            self.assertNotIn("returned code", msg, code)

    def test_false_return_is_failed(self):
        kind, _ = system.restore_outcome(False, 0, 0, None, True)
        self.assertEqual(kind, "failed")

    def test_unreadable_list_falls_back_to_after_check(self):
        started = datetime.now(UTC)
        fresh = system.RestorePoint(58, started + timedelta(seconds=20), "Sweep")
        kind, _ = system.restore_outcome(True, 0, 58, None, False, fresh, True, started)
        self.assertEqual(kind, "created")
        old = system.RestorePoint(57, started - timedelta(hours=3), "Windows Update")
        kind, msg = system.restore_outcome(True, 0, 57, None, False, old, True, started)
        self.assertEqual(kind, "skipped")
        self.assertIn("Windows Update", msg)

    def test_unknowable_is_unconfirmed_not_created(self):
        kind, msg = system.restore_outcome(True, 0, 58, None, False, None, False,
                                           datetime.now(UTC))
        self.assertEqual(kind, "unconfirmed")
        self.assertTrue(msg.startswith("unconfirmed - "))

    def test_zero_sequence_is_never_called_created(self):
        kind, _ = system.restore_outcome(True, 0, 0, point(57), True)
        self.assertNotEqual(kind, "created")

    def test_scope_says_files_are_not_restored(self):
        self.assertIn("does not bring back deleted files", system.RESTORE_SCOPE)


class TestCleanReportWording(unittest.TestCase):
    def test_created(self):
        self.assertEqual(cleaner.restore_point_note(True, "sequence 58"),
                         "created - sequence 58")

    def test_failure(self):
        self.assertEqual(cleaner.restore_point_note(False, "needs administrator"),
                         "not created - needs administrator")

    def test_skip_and_unconfirmed_keep_their_words(self):
        for msg in ("skipped - one was already made at 21:30",
                    "unconfirmed - could not read the list"):
            note = cleaner.restore_point_note(False, msg)
            self.assertEqual(note, msg)
            self.assertNotIn("created -", note)


class TestRestoreDialogWording(unittest.TestCase):
    def setUp(self):
        try:
            from sweep import gui
        except Exception as exc:          # pragma: no cover - no Tk on this box
            raise unittest.SkipTest(f"GUI unavailable: {exc}")
        self.gui = gui

    def test_created(self):
        title, text, level, status = self.gui.restore_point_dialog(
            True, "“Sweep: manual restore point”, sequence 58", "SCOPE")
        self.assertEqual(level, "info")
        self.assertIn("Restore point created", text)
        self.assertIn("SCOPE", text)
        self.assertIn("created", status)

    def test_skipped_is_explained_not_called_created(self):
        _, text, level, status = self.gui.restore_point_dialog(
            False, "skipped - Windows lets programs make only one restore point per "
                   "24 hours, and one was already made at 2026-11-02 21:30", "SCOPE")
        self.assertEqual(level, "info")
        self.assertIn("No new restore point", text)
        self.assertIn("Windows lets programs", text)
        self.assertNotIn("Restore point created", text)
        self.assertNotIn("created (", status)

    def test_failure_does_not_talk_about_cleaning(self):
        _, text, level, _ = self.gui.restore_point_dialog(False, "needs administrator", "S")
        self.assertEqual(level, "warning")
        self.assertIn("No restore point was created", text)
        self.assertNotIn("clean", text.lower())

    def test_unconfirmed(self):
        _, text, level, status = self.gui.restore_point_dialog(
            False, "unconfirmed - System Restore accepted the request", "S")
        self.assertEqual(level, "warning")
        self.assertIn("could not confirm", text)
        self.assertIn("not confirmed", status)


class TestUnreadablePrograms(unittest.TestCase):
    """Loading Applications with an unreadable registry view used to raise
    AttributeError ('AppsPanel' has no 'notice') and leave the page stuck."""

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

    def _load(self, errors):
        from sweep import apps
        orig_list, orig_size = apps.list_apps, apps.app_size

        def fake_list(errs=None):
            if errs is not None:
                errs.extend(errors)
            return [apps.App(name="7-Zip", version="26.05", publisher="Igor Pavlov")]

        apps.list_apps, apps.app_size = fake_list, (lambda a: 0)
        callback_errors = []
        old_report = self.app.report_callback_exception
        self.app.report_callback_exception = lambda *a: callback_errors.append(a[1])
        try:
            self.app.show("Applications")
            panel = self.app.tools_tab.panels["Applications"]
            panel.list_apps()
            end = time.time() + 10
            while panel.worker.busy and time.time() < end:
                self.app.update()
                time.sleep(0.02)
            for _ in range(5):
                self.app.update()
        finally:
            apps.list_apps, apps.app_size = orig_list, orig_size
            self.app.report_callback_exception = old_report
        return panel, callback_errors

    def test_unreadable_view_shows_a_notice_without_crashing(self):
        panel, errs = self._load([r"SOFTWARE\WOW6432Node\...\Uninstall: Access is denied"])
        self.assertEqual(errs, [], f"callback raised: {errs}")
        self.assertTrue(panel.notice.winfo_ismapped(), "the notice must be visible")
        self.assertIn("may be incomplete", panel.notice.msg.cget("text"))
        self.assertIn("not readable", panel.status.cget("text"))
        self.assertEqual(len(panel.table.tree.get_children()), 1)

    def test_clean_read_hides_the_notice(self):
        self._load(["x: Access is denied"])
        panel, errs = self._load([])
        self.assertEqual(errs, [])
        self.assertFalse(panel.notice.winfo_ismapped())
        self.assertIn("select one", panel.status.cget("text"))


if __name__ == "__main__":
    unittest.main()
