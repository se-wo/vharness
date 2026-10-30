"""Fixer tests (SPEC 13.2.6, R-TST-21..25). They need the real sandbox and skip where it cannot run."""

import asyncio
import hashlib
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(__file__)
sys.path.insert(0, os.path.dirname(HERE))
sys.path.insert(0, HERE)

import fake_model  # noqa: E402
from fake_model import FIXTURES, FakeModel, fix_output, record_fingerprint  # noqa: E402
from test_sandbox import AVAILABLE, PROBLEMS  # noqa: E402

from vharness import fixer  # noqa: E402
from vharness.backends import ScriptedBackend  # noqa: E402
from vharness.config import Config  # noqa: E402
from vharness.orchestrator import Harness  # noqa: E402

APP = os.path.join(FIXTURES, "notesapp")
needs_sandbox = unittest.skipUnless(AVAILABLE, f"sandbox unavailable here: {PROBLEMS}")


def tree_hash(root):
    h = hashlib.sha256()
    for dirpath, dirnames, filenames in sorted(os.walk(root)):
        dirnames.sort()
        for name in sorted(filenames):
            path = os.path.join(dirpath, name)
            h.update(path.encode())
            with open(path, "rb") as fh:
                h.update(fh.read())
    return h.hexdigest()


def run_fix(fixer_fn, profile="standard"):
    model = FakeModel({"fixer": fixer_fn})
    out = tempfile.mkdtemp(prefix="vh-fix-")
    cfg = Config(concurrency=4, profile=profile, sandbox="require", fix=True, sandbox_limits={"wall_s": 30, "disk_mb": 64})
    h = Harness(out, ScriptedBackend(model), cfg, log=lambda m: None)
    h.setup([APP])
    asyncio.run(h.execute())
    return h, model


def read(path):
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def fixes(h):
    return {f["fingerprint"]: f for f in h.store.fixes(h.run_id)}


IDOR = "idor:notesapp/notes.py:get_note"
TRAV = "path-traversal:notesapp/notes.py:export_note"


@needs_sandbox
class Fixer(unittest.TestCase):
    def test_r_tst_21_accepted_and_git_am_applies(self):
        before = tree_hash(APP)
        h, model = run_fix(lambda req, m: fix_output(record_fingerprint(req.prompt)))
        fx = fixes(h)
        self.assertEqual({k: v["status"] for k, v in fx.items()}, {IDOR: "accepted", TRAV: "accepted"}, {k: v["reason"] for k, v in fx.items()})
        gate = fx[IDOR]["attempts"][-1]["gate"]
        self.assertEqual((gate["test_unchanged"]["exit_code"], gate["test_patched"]["exit_code"]), (1, 0))
        self.assertEqual((gate["suite_unchanged"]["exit_code"], gate["suite_patched"]["exit_code"]), (0, 0))
        fixers = [r for r in model.calls if r.role == "fixer"]
        self.assertTrue(all(r.model == "claude-sonnet-5-5" and [t.name for t in r.tools] == ["sandbox_run"] for r in fixers))
        # R-FIX-10: the patch file applies with `git am` on a review copy (never on the target).
        repo = tempfile.mkdtemp()
        shutil.copytree(APP, repo, dirs_exist_ok=True)
        git = ["git", "-c", "user.email=t@t", "-c", "user.name=t", "-c", "core.hooksPath=/dev/null"]
        for cmd in (["init", "-q"], ["add", "-A"], ["commit", "-qm", "base"]):
            subprocess.run(git + cmd, cwd=repo, check=True)
        for f in fx.values():
            r = subprocess.run(git + ["am", "-q", os.path.join(h.out, f["patch_file"])], cwd=repo, capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue(os.path.exists(os.path.join(repo, "tests", "test_regression_idor.py")))
        self.assertIn("require_owner(user, note)", read(os.path.join(repo, "notesapp", "notes.py")))
        # R-TST-25 / R-FIX-11: the target is unchanged.
        self.assertEqual(tree_hash(APP), before)
        report = read(os.path.join(h.out, "REPORT.md"))
        self.assertIn("never merges", report)
        self.assertIn("| accepted |", report)
        self.assertTrue(os.path.exists(os.path.join(h.out, "FIXES.md")))

    def test_r_tst_22_retry_then_blocked(self):
        noop = fake_model._diff("notesapp/notes.py", lambda l: fake_model._insert_after(l, "def get_note(request, note_id):", ["    # TODO: check owner\n"]))

        def bad(req, m):
            fp = record_fingerprint(req.prompt)
            return fix_output(fp, patch=noop) if fp == IDOR else fix_output(fp)
        h, model = run_fix(bad)
        fx = fixes(h)[IDOR]
        self.assertEqual(fx["status"], "blocked")
        self.assertIn("the test still fails after the patch", fx["reason"])
        self.assertEqual(len(fx["attempts"]), 2)
        agents = [a["agent"] for a in fx["attempts"]]
        self.assertEqual(len(set(agents)), 2)  # R-FIX-08: a new agent per attempt
        retry = [r for r in model.calls if r.role == "fixer" and record_fingerprint(r.prompt) == IDOR][1]
        self.assertIn("Previous fix attempt failed the harness gate", retry.prompt)
        self.assertIn("[BLOCKED]", read(os.path.join(h.out, fx["patch_file"])))

    def test_retry_then_accepted(self):
        noop = fake_model._diff("notesapp/notes.py", lambda l: fake_model._insert_after(l, "def get_note(request, note_id):", ["    pass\n"]))
        seen = []

        def flaky(req, m):
            fp = record_fingerprint(req.prompt)
            seen.append(fp)
            return fix_output(fp, patch=noop) if fp == IDOR and seen.count(IDOR) == 1 else fix_output(fp)
        h, _ = run_fix(flaky)
        fx = fixes(h)[IDOR]
        self.assertEqual((fx["status"], len(fx["attempts"])), ("accepted", 2))

    def test_r_tst_23_regression_blocks(self):
        def breaks_suite(lines):
            out = fake_model._insert_after(lines, "return 200, note", ["    require_owner(user, note)\n"], before=True)
            return [l.replace('return 200, storage.list_for(user["id"])', 'return 500, storage.list_for(user["id"])') for l in out]
        patch = fake_model._diff("notesapp/notes.py", breaks_suite)
        h, _ = run_fix(lambda req, m: fix_output(record_fingerprint(req.prompt), patch=patch if record_fingerprint(req.prompt) == IDOR else None))
        fx = fixes(h)[IDOR]
        self.assertEqual(fx["status"], "blocked")
        self.assertIn("regression", fx["reason"])
        self.assertEqual(fixes(h)[TRAV]["status"], "accepted")

    def test_r_tst_24_patch_touching_existing_tests_needs_human(self):
        test_edit = fake_model._diff("tests/test_notes.py", lambda l: l + ["\n", "# relaxed\n"])
        patch = fake_model.idor_fix_patch() + test_edit
        h, _ = run_fix(lambda req, m: fix_output(record_fingerprint(req.prompt), patch=patch if record_fingerprint(req.prompt) == IDOR else None))
        fx = fixes(h)[IDOR]
        self.assertEqual(fx["status"], "needs_human")
        self.assertIn("R-FIX-04", fx["reason"])


class Mechanical(unittest.TestCase):
    def test_mechanical_rules(self):
        good = fix_output(IDOR)
        self.assertEqual(fixer.mechanical(good, APP, 200), ([], []))
        exists = dict(good, test=dict(good["test"], file_name="tests/test_notes.py"))
        self.assertTrue(any("already exists" in e for e in fixer.mechanical(exists, APP, 200)[0]))
        self.assertTrue(fixer.mechanical(dict(good, patch="make it safe"), APP, 200)[0])
        self.assertTrue(any("R-FIX-05" in r for r in fixer.mechanical(good, APP, 0)[1]))

    def test_fix_needs_sandbox(self):
        with self.assertRaises(ValueError):
            Config(fix=True, sandbox="off").validate()


if __name__ == "__main__":
    unittest.main()
