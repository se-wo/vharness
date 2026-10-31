"""Rate-limit tests (SPEC 9.5, R-TST-27..29). Scripted backend; no model, no sandbox."""

import asyncio
import os
import sys
import tempfile
import time
import unittest

HERE = os.path.dirname(__file__)
sys.path.insert(0, os.path.dirname(HERE))
sys.path.insert(0, HERE)

from fake_model import FIXTURES, FakeModel  # noqa: E402

from vharness.backends import ScriptedBackend, rate_limited  # noqa: E402
from vharness.config import Config  # noqa: E402
from vharness.orchestrator import Harness  # noqa: E402

APP = os.path.join(FIXTURES, "notesapp")


def limited_hunter(times, message):
    """The first `times` hunter calls are refused with a usage-limit message."""
    state = {"n": 0}

    def hunter(req, model):
        state["n"] += 1
        if state["n"] <= times:
            return message() if callable(message) else message
        return None  # fall through to the cooperative fake
    return hunter, state


def run(model, out=None, **cfg):
    out = out or tempfile.mkdtemp(prefix="vh-rl-")
    cfg.setdefault("concurrency", 2)
    h = Harness(out, ScriptedBackend(model), Config(**cfg), log=lambda m: None)
    h.setup([APP])
    asyncio.run(h.execute())
    return h


def confirmed(h):
    return {r["fingerprint"] for r in h.store.records(h.run_id, verdicts=["confirmed"]) if r["final"]}


class Classification(unittest.TestCase):
    def test_r_tst_29_classification(self):
        self.assertEqual(rate_limited("Claude AI usage limit reached|1793400000"), (True, 1793400000.0))
        self.assertEqual(rate_limited("You've hit your limit · resets 3pm"), (True, None))
        self.assertEqual(rate_limited('API Error: 429 {"type":"rate_limit_error"}'), (True, None))
        self.assertEqual(rate_limited("", http_status=429), (True, None))
        self.assertEqual(rate_limited("", event_rejected=True, event_resets_at=1793401234), (True, 1793401234))
        self.assertEqual(rate_limited("API Error: 529 overloaded"), (False, None))  # transient: normal retry
        self.assertEqual(rate_limited("no candidates found"), (False, None))


class Pause(unittest.TestCase):
    def test_r_tst_27_wait_for_known_reset_then_complete(self):
        hunter, state = limited_hunter(2, lambda: f"Claude AI usage limit reached|{int(time.time()) + 1}")
        t0 = time.monotonic()
        h = run(FakeModel({"hunter": hunter}))
        run_row = h.store.run(h.run_id)
        self.assertEqual(run_row["status"], "complete", run_row["reason"])
        self.assertGreaterEqual(time.monotonic() - t0, 0.9)  # it waited for the reset
        self.assertEqual(len(confirmed(h)), 2)
        self.assertFalse(h.store.units(h.run_id, "notesapp", "blocked"))  # no unit lost to the limit
        limited = [r for r in h.store.x("SELECT status FROM invocations WHERE run_id=?", h.run_id) if r["status"] == "rate_limit"]
        self.assertTrue(limited)
        all_rows = h.store.x("SELECT COUNT(*) FROM invocations WHERE run_id=?", h.run_id).fetchone()[0]
        self.assertEqual(h.store.invocation_count(h.run_id, "notesapp"), all_rows - len(limited))  # R-RL-02
        for t in h.store.tasks(h.run_id, stages=["hunt"]):
            self.assertLessEqual(t["attempts"], 1, t)  # a refused call is not an attempt

    def test_unknown_reset_uses_backoff(self):
        hunter, state = limited_hunter(2, "You've hit your limit · resets 3pm")
        h = run(FakeModel({"hunter": hunter}), rate_limit_backoff_s=0.2, rate_limit_backoff_max_s=0.5)
        self.assertEqual(h.store.run(h.run_id)["status"], "complete", h.store.run(h.run_id)["reason"])
        self.assertEqual(len(confirmed(h)), 2)

    def test_r_tst_28_stop_as_paused_then_resume(self):
        hunter, state = limited_hunter(1, lambda: f"Claude AI usage limit reached|{int(time.time()) + 1}")
        h = run(FakeModel({"hunter": hunter}), on_rate_limit="stop")
        self.assertEqual(h.store.run(h.run_id)["status"], "paused")
        report = open(os.path.join(h.out, "REPORT.md")).read()
        self.assertIn("paused by a rate limit", report)
        self.assertIn("vharness resume", report)
        self.assertTrue(h.store.tasks(h.run_id, stages=["hunt"], statuses=["queued"]))
        self.assertFalse(h.store.units(h.run_id, "notesapp", "in_progress"))  # R-RL-04
        h2 = Harness(h.out, ScriptedBackend(FakeModel()), run_id=h.run_id, log=lambda m: None)
        h2.resume()
        asyncio.run(h2.execute())
        self.assertEqual(h2.store.run(h.run_id)["status"], "complete", h2.store.run(h.run_id)["reason"])
        self.assertEqual(len(confirmed(h2)), 2)

    def test_wait_longer_than_max_stops_as_paused(self):
        hunter, state = limited_hunter(1, lambda: f"Claude AI usage limit reached|{int(time.time()) + 3600}")
        t0 = time.monotonic()
        h = run(FakeModel({"hunter": hunter}), rate_limit_max_wait_s=60)
        self.assertEqual(h.store.run(h.run_id)["status"], "paused")
        self.assertLess(time.monotonic() - t0, 30)
        pause = h.store.doc(h.run_id, "", "pause", parse=True)
        self.assertTrue(pause["reset_known"])


if __name__ == "__main__":
    unittest.main()
