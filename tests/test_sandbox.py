"""Sandbox tests (SPEC 13.1.7, R-TST-14..20). They use the real sandbox and skip where it cannot run."""

import asyncio
import json
import os
import shlex
import sys
import tempfile
import unittest

HERE = os.path.dirname(__file__)
sys.path.insert(0, os.path.dirname(HERE))
sys.path.insert(0, HERE)

from fake_model import FIXTURES, FakeModel, idor_candidate  # noqa: E402

from vharness.backends import ScriptedBackend  # noqa: E402
from vharness.config import Config  # noqa: E402
from vharness.orchestrator import Harness  # noqa: E402
from vharness.report import check_outputs, findings_json, ledger_json  # noqa: E402
from vharness.sandbox import Limits, RunSpec, Sandbox, SandboxError  # noqa: E402

APP = os.path.join(FIXTURES, "notesapp")
WORK = tempfile.mkdtemp(prefix="vh-sbx-")
SB = Sandbox(os.path.join(WORK, "sbx"), Limits(wall_s=20, disk_mb=64, nproc=32))
AVAILABLE, PROBLEMS = (SB.probe(APP, os.path.join(WORK, "probe")) if os.geteuid() == 0 else (False, ["not root"]))
needs_sandbox = unittest.skipUnless(AVAILABLE, f"sandbox unavailable here: {PROBLEMS}")


def run(command, **kw):
    return SB.run(APP, RunSpec(command=command, **kw), tempfile.mkdtemp(dir=WORK))


@needs_sandbox
class Controls(unittest.TestCase):
    def test_r_tst_14_start_test_passes(self):
        self.assertTrue(AVAILABLE)
        self.assertEqual(PROBLEMS, [])

    def test_r_tst_15_no_network_and_empty_environment(self):
        st = run("python3 -I -c " + shlex.quote(
            "import json, os, socket\n"
            "s = socket.socket(); s.settimeout(2)\n"
            "try:\n    s.connect(('1.1.1.1', 443)); net = 'open'\n"
            "except OSError as e:\n    net = type(e).__name__\n"
            "print(json.dumps({'net': net, 'env': sorted(os.environ)}))"))
        out = json.loads(st["stdout"])
        self.assertNotEqual(out["net"], "open")
        self.assertTrue(set(out["env"]) <= {"PATH", "HOME", "TMPDIR", "LANG", "PYTHONDONTWRITEBYTECODE", "PYTHONNOUSERSITE",
                                            "PWD", "OLDPWD", "SHLVL", "_"}, out["env"])
        # Host secrets in the harness environment never reach the sandbox.
        os.environ["VH_TEST_SECRET"] = "s3cret"
        try:
            self.assertNotIn("s3cret", run("env")["stdout"])
        finally:
            del os.environ["VH_TEST_SECRET"]

    def test_r_tst_16_read_only_target_and_system(self):
        st = run("for p in /target/x /usr/x /etc/x /x /bin/x; do (echo hi > $p) 2>/dev/null && echo WROTE $p; done; "
                 "echo ok > /scratch/y && cat /scratch/y; mount -o remount,rw /target 2>/dev/null && echo REMOUNTED; "
                 "ls /root /home 2>&1 | head -2; id -u")
        self.assertNotIn("WROTE", st["stdout"])
        self.assertNotIn("REMOUNTED", st["stdout"])
        self.assertIn("ok", st["stdout"])
        self.assertNotEqual(st["stdout"].split()[-1], "0")
        self.assertFalse(os.path.exists(os.path.join(APP, "x")))

    def test_r_tst_17_limits(self):
        st = run("python3 -c " + shlex.quote(
            "import os, time\nn = 0\nwhile True:\n"
            "    try:\n        pid = os.fork()\n    except OSError:\n        print('forks', n); break\n"
            "    if pid == 0:\n        time.sleep(30); os._exit(0)\n    n += 1"))
        self.assertLessEqual(int(st["stdout"].split()[-1]), 32)
        st = run("for i in 1 2 3; do dd if=/dev/zero of=/scratch/f$i bs=1M count=40 2>/dev/null; done; "
                 "cat /scratch/f1 /scratch/f2 /scratch/f3 | wc -c")
        self.assertLessEqual(int(st["stdout"].split()[-1]), 64 * 1024 * 1024)  # 120 MB asked, 64 MB scratch
        st = run("sleep 60", timeout_s=2)
        self.assertTrue(st["timed_out"])
        self.assertLess(st["duration_ms"], 10_000)

    def test_r_tst_18_promotion_refusals(self):
        art = tempfile.mkdtemp(dir=WORK)
        st = SB.run(APP, RunSpec(
            command="mkdir e && echo good > e/ok.txt && ln -s /etc/passwd e/link && mkfifo e/fifo && "
                    "echo x > e/a && ln e/a e/hard && head -c 2000000 /dev/zero > e/big && mkdir e/dir",
            keep=["e/ok.txt", "e/link", "e/fifo", "e/hard", "e/big", "e/dir"]), art)
        self.assertEqual([p["path"] for p in st["promoted"]], ["e/ok.txt"])
        reasons = {r["path"]: r["reason"] for r in st["rejected"]}
        self.assertEqual(set(reasons), {"e/link", "e/fifo", "e/hard", "e/big", "e/dir"})
        with open(os.path.join(art, "e", "ok.txt")) as fh:
            self.assertEqual(fh.read(), "good\n")
        with self.assertRaises(SandboxError):  # unsafe keep paths are refused before anything runs
            SB.run(APP, RunSpec(command="true", keep=["../escape"]), art)

    def test_input_validation(self):
        for bad in (RunSpec(command=""), RunSpec(command="true", files=[{"path": "/etc/x", "content": ""}]),
                    RunSpec(command="true", env={"AWS_SECRET_ACCESS_KEY": "x"}), RunSpec(command="true", env={"LD_PRELOAD": "x"})):
            with self.assertRaises(SandboxError):
                SB.run(APP, bad, WORK)


def sandbox_harness(model, **cfg):
    out = tempfile.mkdtemp(prefix="vh-sbx-run-")
    cfg.setdefault("concurrency", 4)
    cfg.setdefault("sandbox", "require")
    cfg.setdefault("sandbox_limits", {"wall_s": 30, "disk_mb": 64})
    h = Harness(out, ScriptedBackend(model), Config(**cfg), log=lambda m: None)
    h.setup([APP])
    asyncio.run(h.execute())
    return h


@needs_sandbox
class Pipeline(unittest.TestCase):
    def test_r_tst_19_poc_fixed_and_local_evidence(self):
        async def hunter(req, model):
            out = FakeModel.hunter(model, req)
            tool = {t.name: t for t in req.tools}.get("sandbox_run")
            assert tool, "hunter did not get the sandbox tool"
            for c in out["candidates"]:
                if c["fingerprint"].startswith("idor"):
                    cmd = "python3 tests/poc_idor.py"
                    res = await tool.handler({"command": cmd, "copy_target": True,
                                              "files": [{"path": "src/tests/poc_idor.py", "content": c["poc_test"]["code"]}]})
                    assert res["exit_code"] == 1, res
                    c["evidence_level"] = "local"
                    c["execution"] = {"run_id": res["run_id"], "command": cmd, "input": "bob's token, note id 1",
                                      "observed_result": res["stdout"].strip()}
            return out

        model = FakeModel({"hunter": hunter})
        h = sandbox_harness(model)
        run = h.store.run(h.run_id)
        self.assertEqual(run["status"], "complete", run["reason"])
        recs = {r["fingerprint"]: r for r in h.store.records(h.run_id) if r["final"]}
        idor = recs["idor:notesapp/notes.py:get_note"]
        self.assertEqual(idor["data"]["evidence_level"], "local")
        self.assertEqual(idor["poc"]["result"], "fixed", idor["poc"])
        self.assertEqual(idor["poc"]["original"]["exit_code"], 1)
        self.assertEqual(idor["poc"]["patched"]["exit_code"], 0)
        # The traversal candidate has no PoC command: recorded as such, verdict unchanged (R-SBX-16).
        trav = recs["path-traversal:notesapp/notes.py:export_note"]
        self.assertEqual(trav["poc"]["result"], "no_command")
        self.assertEqual(trav["verdict"], "confirmed")
        # The verifier saw the PoC result (R-SBX-14); the report shows it (R-SBX-15) and the recorded output (R-SBX-12).
        verifier_prompts = [r.prompt for r in model.calls if r.role == "verifier"]
        self.assertTrue(any("Proof-of-concept result" in p and '"fixed"' in p for p in verifier_prompts))
        report = open(os.path.join(h.out, "REPORT.md")).read()
        self.assertIn("**sandboxed**", report)
        self.assertIn("| fixed | local |", report)
        detail = open(os.path.join(h.out, "FINDINGS-DETAIL.md")).read()
        self.assertIn("Harness-recorded result: exit 1", detail)
        self.assertIn("bob read:", detail)
        # Only hunters and validators get the tool (13.1.4.1).
        for req in model.calls:
            self.assertEqual(bool(req.tools), req.role in ("hunter", "validator"), req.role)
        self.assertEqual(check_outputs(h.store, h.run_id, findings_json(h.store, h.run_id), ledger_json(h.store, h.run_id)), [])

    def test_r_tst_20_unknown_run_id_fails_mechanical_check(self):
        def hunter(req, model):
            out = FakeModel.hunter(model, req)
            for c in out["candidates"]:
                c["evidence_level"] = "local"
                c["execution"] = {"run_id": "sbx-99999", "command": "true", "input": "-", "observed_result": "pwned"}
            return out
        h = sandbox_harness(FakeModel({"hunter": hunter}))
        self.assertFalse([r for r in h.store.records(h.run_id, verdicts=["confirmed"]) if r["final"]])
        rejected = h.store.records(h.run_id, verdicts=["rejected"])
        self.assertTrue(rejected and all("R-SBX-11" in r["data"]["reason"] for r in rejected), [r["data"]["reason"] for r in rejected])


class Modes(unittest.TestCase):
    def test_start_test_failure_modes(self):
        orig = Sandbox.probe
        Sandbox.probe = lambda self, *a: (False, ["R-SBX-01: external network is reachable"])
        try:
            with self.assertRaises(ValueError):
                sandbox_harness(FakeModel(), sandbox="require")
            h = sandbox_harness(FakeModel(), sandbox="auto")
            self.assertIsNone(h.sandbox)
            self.assertEqual(len([r for r in h.store.records(h.run_id, verdicts=["confirmed"]) if r["final"]]), 2)
            report = open(os.path.join(h.out, "REPORT.md")).read()
            self.assertIn("sandbox start test failed", report)
            self.assertIn("R-SBX-01", report)
        finally:
            Sandbox.probe = orig

    def test_local_evidence_refused_without_sandbox(self):
        from vharness import records
        rec = idor_candidate()
        rec.pop("proposed_verdict")
        rec = {"threat_model": rec.pop("threat_model"), "verdict": "confirmed", **rec,
               "evidence_level": "local", "execution": {"run_id": "sbx-00001", "command": "x", "input": "", "observed_result": "y"}}
        self.assertTrue(any("R-REC-12" in e for e in records.check_record(rec, APP, None)))


if __name__ == "__main__":
    unittest.main()
