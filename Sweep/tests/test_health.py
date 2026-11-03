"""Tests for the laptop health module."""

from __future__ import annotations

import json
import os
import sys
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sweep import health  # noqa: E402

TMP_ROOT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                        ".test-tmp")


def _mk(key, status, weight=1):
    return health.Check(key, key.title(), status, weight=weight)


def _ev(eid, when):
    return {"Id": eid, "Time": when, "Provider": "test", "Message": ""}


class TestScoring(unittest.TestCase):
    def test_all_ok_is_100(self):
        self.assertEqual(health.score([_mk("a", health.OK), _mk("b", health.OK)]), 100)

    def test_bad_costs_twelve_per_weight(self):
        self.assertEqual(health.score([_mk("a", health.BAD)]), 88)
        self.assertEqual(health.score([_mk("a", health.BAD, weight=2)]), 76)

    def test_warn_costs_five(self):
        self.assertEqual(health.score([_mk("a", health.WARN)]), 95)

    def test_unknown_is_free(self):
        self.assertEqual(health.score([_mk("a", health.UNKNOWN)]), 100)

    def test_floor_is_zero(self):
        checks = [_mk(f"c{i}", health.BAD, weight=3) for i in range(10)]
        self.assertEqual(health.score(checks), 0)

    def test_verdict_bands(self):
        self.assertEqual(health.verdict(95), "healthy")
        self.assertEqual(health.verdict(80), "needs attention")
        self.assertEqual(health.verdict(60), "degraded")
        self.assertEqual(health.verdict(10), "act now")


class TestIncidentGrouping(unittest.TestCase):
    """One crash is written to the log several times; counting rows triples the
    apparent problem."""

    def test_same_incident_collapses(self):
        events = [
            _ev(41, "2026-10-07 11:15"),
            _ev(6008, "2026-10-07 11:15"),
            _ev(1001, "2026-10-07 11:14"),
        ]
        incidents = health._distinct_incidents(events, health._SHUTDOWN_IDS)
        self.assertEqual(len(incidents), 1)

    def test_separate_days_stay_separate(self):
        events = [
            _ev(41, "2026-10-01 11:15"),
            _ev(41, "2026-10-07 11:15"),
            _ev(41, "2026-10-20 08:00"),
        ]
        incidents = health._distinct_incidents(events, health._SHUTDOWN_IDS)
        self.assertEqual(len(incidents), 3)

    def test_trailing_pair_groups_with_previous(self):
        events = [
            _ev(41, "2026-10-07 11:15"),
            _ev(6008, "2026-10-07 11:15"),
            _ev(41, "2026-10-08 09:00"),
            _ev(6008, "2026-10-08 09:00"),
        ]
        incidents = health._distinct_incidents(events, health._SHUTDOWN_IDS)
        self.assertEqual(len(incidents), 2)

    def test_reliability_severity(self):
        three = [_ev(41, f"2026-10-0{i} 10:00") for i in (1, 2, 3)]
        self.assertEqual(health.check_reliability(three).status, health.BAD)

        one = [_ev(41, "2026-10-01 10:00")]
        self.assertEqual(health.check_reliability(one).status, health.WARN)

        none = []
        self.assertEqual(health.check_reliability(none).status, health.OK)

    def test_disk_warnings_alone_are_a_warning(self):
        evs = [_ev(51, "2026-07-17 21:49"), _ev(153, "2026-10-13 14:47")]
        c = health.check_reliability(evs)
        self.assertEqual(c.status, health.WARN)
        self.assertIn("storage", c.value.lower())

    def test_shutdown_beats_disk(self):
        evs = [_ev(41, "2026-10-01 10:00"), _ev(51, "2026-07-17 21:49")]
        c = health.check_reliability(evs)
        self.assertEqual(c.status, health.WARN)
        self.assertIn("shutdown", c.value.lower())

    def test_unknown_when_events_unavailable(self):
        self.assertEqual(health.check_reliability(None).status, health.UNKNOWN)


class TestIndividualChecks(unittest.TestCase):
    def test_disk_space(self):
        c = health.check_disk_space()
        self.assertIn(c.status, (health.OK, health.WARN, health.BAD, health.UNKNOWN))
        self.assertTrue(c.title)

    def test_uptime(self):
        c = health.check_uptime()
        self.assertIn(c.status, (health.OK, health.WARN, health.UNKNOWN))

    def test_trim(self):
        c = health.check_trim()
        self.assertIn(c.status, (health.OK, health.BAD, health.UNKNOWN))

    def test_battery(self):
        c = health.check_battery()
        self.assertIn(c.status, (health.OK, health.WARN, health.UNKNOWN))

    def test_power_scheme(self):
        c = health.check_power_scheme()
        self.assertIn(c.status, (health.OK, health.WARN, health.UNKNOWN))

    def test_secure_boot(self):
        c = health.check_secure_boot()
        self.assertIn(c.status, (health.OK, health.WARN, health.UNKNOWN))

    def test_startup_load(self):
        c = health.check_startup_load()
        self.assertIn(c.status, (health.OK, health.WARN))

    def test_advice_present_when_not_ok(self):
        for c in (health.check_disk_space(), health.check_uptime(),
                  health.check_trim(), health.check_battery()):
            if c.status in (health.WARN, health.BAD):
                self.assertTrue(c.advice, f"{c.key} needs advice when {c.status}")


class TestRunAndHistory(unittest.TestCase):
    def test_run_checks_without_events(self):
        checks = health.run_checks(include_events=False)
        self.assertGreaterEqual(len(checks), 10)
        for c in checks:
            self.assertIn(c.status, (health.OK, health.WARN, health.BAD, health.UNKNOWN))
            self.assertTrue(c.key)
            self.assertTrue(c.title)

    def test_report_dict_shape(self):
        blob = health.to_dict(health.run_checks(include_events=False))
        self.assertIn("score", blob)
        self.assertIn("verdict", blob)
        self.assertEqual(len(blob["checks"]), len(health.run_checks(include_events=False)))

    def test_history_roundtrip(self):
        os.makedirs(TMP_ROOT, exist_ok=True)
        path = os.path.join(TMP_ROOT, f"history-{os.getpid()}.jsonl")
        if os.path.exists(path):
            os.unlink(path)
        try:
            checks = [_mk("a", health.OK), _mk("b", health.WARN)]
            health.save_snapshot(checks, path)
            health.save_snapshot(checks, path)
            hist = health.load_history(path)
            self.assertEqual(len(hist), 2)
            self.assertEqual(hist[0]["score"], 95)
            self.assertEqual(hist[0]["statuses"], {"a": "ok", "b": "warn"})
            with open(path, encoding="utf-8") as fh:
                first = json.loads(fh.readline())
            self.assertIn("ts", first)
        finally:
            if os.path.exists(path):
                os.unlink(path)

    def test_history_missing_file_is_empty(self):
        self.assertEqual(health.load_history(os.path.join(TMP_ROOT, "nope.jsonl")), [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
