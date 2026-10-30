"""Test suite for vharness (SPEC 12). Run: python3 -m unittest discover -s tests -v"""

import asyncio
import copy
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(__file__)
sys.path.insert(0, os.path.dirname(HERE))

from fake_model import FIXTURES, FakeModel, idor_candidate, traversal_candidate  # noqa: E402

from vharness import records  # noqa: E402
from vharness.backends import ScriptedBackend, classify  # noqa: E402
from vharness.config import Config  # noqa: E402
from vharness.guard import check_tool_call  # noqa: E402
from vharness.ids import coverage_id  # noqa: E402
from vharness.knowledge import Knowledge  # noqa: E402
from vharness.orchestrator import Harness, read_git_head  # noqa: E402
from vharness.report import check_outputs, findings_json, ledger_json  # noqa: E402

APP = os.path.join(FIXTURES, "notesapp")
CLIENT = os.path.join(FIXTURES, "notesclient")


def run_harness(model, targets=(APP,), quiet=True, **cfg):
    out = tempfile.mkdtemp(prefix="vh-test-")
    cfg.setdefault("concurrency", 4)
    h = Harness(out, ScriptedBackend(model), Config(**cfg), log=(lambda m: None) if quiet else None)
    h.setup(list(targets))
    asyncio.run(h.execute())
    return h


def confirmed(h):
    return {r["fingerprint"] for r in h.store.records(h.run_id, verdicts=["confirmed"]) if r["final"]}


class FullPipeline(unittest.TestCase):
    def test_r_tst_01_full_pipeline_standard(self):
        model = FakeModel()
        h = run_harness(model, targets=(APP, CLIENT))
        run = h.store.run(h.run_id)
        self.assertEqual(run["status"], "complete", run["reason"])
        self.assertEqual(confirmed(h), {"idor:notesapp/notes.py:get_note", "path-traversal:notesapp/notes.py:export_note"})
        findings = findings_json(h.store, h.run_id)
        self.assertEqual(check_outputs(h.store, h.run_id, findings, ledger_json(h.store, h.run_id)), [])
        for name in ("findings.json", "coverage-ledger.json", "REPORT.md", "FINDINGS-DETAIL.md", "NEEDS-VALIDATION.md", "WISHLIST.md"):
            self.assertTrue(os.path.exists(os.path.join(h.out, name)), name)
        report = open(os.path.join(h.out, "REPORT.md")).read()
        self.assertIn("not been executed", report)
        self.assertIn("P1", report)
        # Trace -> consumer: notesclient consumes export_note, so a consumer unit was hunted there.
        consumers = h.store.consumers(h.run_id)
        self.assertEqual({c["target"] for c in consumers}, {"notesclient"})
        trace_units = [u for u in h.store.units(h.run_id, "notesclient") if u["origin"] == "trace"]
        self.assertTrue(trace_units and all(u["status"] == "covered" for u in trace_units))
        # Every confirmed record went through a separate verifier on the validation model.
        roles = {(c.role, c.model) for c in model.calls}
        self.assertIn(("verifier", "claude-sonnet-5-5"), roles)
        self.assertIn(("hunter", "claude-opus-5-5"), roles)
        # Agent prompts and results are on disk for audit.
        self.assertTrue(os.listdir(os.path.join(h.out, "agents")))

    def test_quick_profile_merges_verify(self):
        model = FakeModel()
        h = run_harness(model, profile="quick")
        self.assertEqual(len(confirmed(h)), 2)
        self.assertNotIn("verifier", {c.role for c in model.calls})
        self.assertEqual(model.critic_calls, 1)

    def test_cli_check_and_status(self):
        h = run_harness(FakeModel())
        env = dict(os.environ, PYTHONPATH=os.path.dirname(HERE))
        r = subprocess.run([sys.executable, "-m", "vharness", "check", "--out", h.out], capture_output=True, text=True, env=env)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        r = subprocess.run([sys.executable, "-m", "vharness", "status", "--out", h.out], capture_output=True, text=True, env=env)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("records:", r.stdout)
        # R-CLI-03: a broken findings.json makes check fail.
        path = os.path.join(h.out, "findings.json")
        data = json.load(open(path))
        data[0]["record"]["trace"][0]["line"] = 99999
        json.dump(data, open(path, "w"))
        r = subprocess.run([sys.executable, "-m", "vharness", "check", "--out", h.out], capture_output=True, text=True, env=env)
        self.assertEqual(r.returncode, 1)


class Guard(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp()
        os.makedirs(os.path.join(self.root, "src"))
        open(os.path.join(self.root, "src", "a.py"), "w").close()
        self.outside = tempfile.mkdtemp()
        open(os.path.join(self.outside, "secret"), "w").close()
        os.symlink(os.path.join(self.outside, "secret"), os.path.join(self.root, "link"))
        os.symlink(self.outside, os.path.join(self.root, "dirlink"))

    def test_r_tst_02_outside_paths_refused(self):
        self.assertTrue(check_tool_call("Read", {"file_path": "src/a.py"}, self.root)[0])
        self.assertTrue(check_tool_call("Read", {"file_path": os.path.join(self.root, "src/a.py")}, self.root)[0])
        for bad in ("/etc/passwd", "../x", os.path.join(self.outside, "secret"), "src/../../etc"):
            self.assertFalse(check_tool_call("Read", {"file_path": bad}, self.root)[0], bad)
        self.assertFalse(check_tool_call("Grep", {"pattern": "x", "path": "/"}, self.root)[0])
        self.assertFalse(check_tool_call("Glob", {"pattern": "/etc/*"}, self.root)[0])
        self.assertFalse(check_tool_call("Glob", {"pattern": "../**"}, self.root)[0])
        self.assertTrue(check_tool_call("Grep", {"pattern": "/etc/passwd"}, self.root)[0])  # a regex, not a path

    def test_r_tst_03_symlink_escape_refused(self):
        self.assertFalse(check_tool_call("Read", {"file_path": "link"}, self.root)[0])
        self.assertFalse(check_tool_call("Grep", {"pattern": "x", "path": "dirlink"}, self.root)[0])

    def test_r_safe_01_only_read_tools(self):
        for tool in ("Bash", "Write", "Edit", "WebFetch", "WebSearch", "Task", "mcp__x__y"):
            self.assertFalse(check_tool_call(tool, {}, self.root)[0], tool)


class Robustness(unittest.TestCase):
    def test_r_tst_04_malformed_result_discarded(self):
        state = {"hunter": 0, "validator": 0}

        def bad_once(role):
            def f(req, model):
                state[role] += 1
                return {"nonsense": True} if state[role] == 1 else None
            return f
        model = FakeModel({"hunter": bad_once("hunter"), "validator": bad_once("validator")})
        h = run_harness(model)
        self.assertEqual(h.store.run(h.run_id)["status"], "complete", h.store.run(h.run_id)["reason"])
        self.assertEqual(len(confirmed(h)), 2)
        statuses = [t["status"] for t in h.store.tasks(h.run_id, stages=["hunt"])]
        self.assertIn("failed", statuses)  # the malformed attempt was not repaired

    def test_r_tst_05_validator_is_never_the_hunter(self):
        h = run_harness(FakeModel())
        for c in h.store.candidates(h.run_id):
            rec = h.store.record(h.run_id, c["target"], c["primary_fp"] or c["fingerprint"])
            if rec and rec["validator"] != "mechanical":
                self.assertNotEqual(rec["validator"], c["hunter"])
                self.assertNotIn(c["hunter"], rec["verifiers"])
                self.assertNotIn(rec["validator"], rec["verifiers"])

    def test_r_tst_07_resume_after_crash(self):
        class Crash(BaseException):
            pass
        state = {"n": 0}

        def crash_on_validator(req, model):
            state["n"] += 1
            if state["n"] == 1:
                raise Crash()
        model = FakeModel({"validator": crash_on_validator})
        out = tempfile.mkdtemp(prefix="vh-test-")

        class CrashBackend(ScriptedBackend):
            async def run(self, req):
                if req.role == "validator" and state["n"] == 0:
                    state["n"] += 1
                    raise Crash()
                return await super().run(req)
        h = Harness(out, CrashBackend(FakeModel()), Config(concurrency=1), log=lambda m: None)
        h.setup([APP])
        with self.assertRaises(Crash):
            asyncio.run(h.execute())
        self.assertTrue(h.store.tasks(h.run_id, statuses=["running"]))
        h2 = Harness(out, ScriptedBackend(FakeModel()), run_id=h.run_id, log=lambda m: None)
        h2.resume()
        asyncio.run(h2.execute())
        self.assertEqual(h2.store.run(h.run_id)["status"], "complete", h2.store.run(h.run_id)["reason"])
        self.assertEqual(len(confirmed(h2)), 2)

    def test_r_tst_08_context_split(self):
        model = FakeModel()
        # Measure the multi-unit hunter prompts, then pick a per-model window just below the smallest one.
        probe = FakeModel()
        run_harness(probe, profile="quick")
        size = lambda r: (len(r.system) + len(r.prompt)) // 4
        multi = min(size(r) for r in probe.calls if r.role == "hunter")
        limit = multi - 1
        h = run_harness(model, profile="quick", role_models={"hunter": "small-model"},
                        context_windows={"small-model": limit * 4}, context_fraction=0.25)
        split = [t for t in h.store.tasks(h.run_id, stages=["hunt"]) if t["status"] == "split"]
        self.assertTrue(split, "expected at least one split hunt task")
        for req in (r for r in model.calls if r.role == "hunter"):
            self.assertLessEqual(size(req) - len(h.store.target_root(h.run_id, "notesapp")) // 4, limit)
        self.assertEqual(len(confirmed(h)), 2)  # splitting lost no coverage
        # A window too small even for one unit blocks the unit with reason context_budget (SPEC 9.3.1 step 6).
        h = run_harness(FakeModel(), profile="quick", role_models={"hunter": "small-model"},
                        context_windows={"small-model": 1_000 * 4}, context_fraction=0.25)
        blocked = h.store.units(h.run_id, "notesapp", "blocked")
        self.assertTrue(blocked and all(u["unresolved"] == ["context_budget"] for u in blocked))

    def test_r_tst_11_api_error_text_is_an_error(self):
        ok, kind, _ = classify(None, "API Error: 529 {\"type\":\"overloaded_error\"}", False, "success", None, {})
        self.assertEqual((ok, kind), (False, "api_text"))
        ok, kind, _ = classify(None, "I looked around and found nothing.", False, "success", None, {})
        self.assertEqual((ok, kind), (False, "malformed"))
        state = {"n": 0}

        def flaky(req, model):
            state["n"] += 1
            return "API Error: 529 overloaded" if state["n"] == 1 else None
        model = FakeModel({"critic": flaky})
        h = run_harness(model)
        inv = [dict(r) for r in h.store.x("SELECT role, status FROM invocations WHERE role='critic'")]
        self.assertEqual([i["status"] for i in inv][:2], ["api_text", "ok"])  # retried with a new agent

    def test_r_tst_12_shallow_requeue(self):
        def shallow(req, model):
            out = FakeModel.hunter(model, req)
            for u in out["units"]:
                u.update(disposition="covered", candidate_fingerprints=[], checks=u["checks"][:1])
            out["candidates"] = []
            out["__turns__"] = 1
            return out
        h = run_harness(FakeModel({"hunter": shallow}))
        units = h.store.units(h.run_id, "notesapp")
        self.assertTrue(all(u["status"] == "blocked" and u["unresolved"] == ["shallow"] for u in units), [u["status"] for u in units])
        self.assertTrue(all(len(u["attempts"]) == 1 and u["feedback"] for u in units))
        self.assertTrue(h.store.notes(h.run_id, "notesapp", "feedback"))

    def test_r_tst_13_duplicate_not_validated(self):
        def dup_hunter(req, model):
            out = FakeModel.hunter(model, req)
            extra = []
            for c in out["candidates"]:
                if c["fingerprint"].startswith("idor"):
                    d = copy.deepcopy(c)
                    d["fingerprint"] = "idor:notesapp/notes.py:get_note-variant"
                    extra.append(d)
            out["candidates"] += extra
            return out

        def dedup(req, model):
            fm = __import__("fake_model")
            new = fm.section_json(req.prompt, "New candidate")
            sl = fm.section_json(req.prompt, "Shortlist of existing primary candidates")
            same = [c["fingerprint"] for c in sl if c["root_cause"] == new["root_cause"]]
            return {"duplicate_of": same[0] if same else None, "reason": "one fix closes both" if same else "different"}
        model = FakeModel({"hunter": dup_hunter, "dedup": dedup})
        h = run_harness(model)
        validated = {t["payload"]["fingerprint"] for t in h.store.tasks(h.run_id, stages=["validate"])}
        self.assertEqual(len([f for f in validated if f.startswith("idor")]), 1)
        dups = h.store.candidates(h.run_id, "notesapp", "duplicate")
        self.assertEqual(len(dups), 1)
        self.assertIn("dedup", {c.role for c in model.calls})


class Records(unittest.TestCase):
    def rec(self):
        c = idor_candidate()
        c.pop("proposed_verdict")
        return {"threat_model": c.pop("threat_model"), "verdict": "confirmed", **c}

    def test_r_tst_06_mechanical_checks(self):
        root = APP
        self.assertEqual(records.check_record(self.rec(), root), [])
        cases = {
            "R-REC-02 trace order": lambda r: r["trace"].reverse(),
            "R-REC-04 absolute path": lambda r: r["trace"][0].update(file="/etc/passwd"),
            "R-REC-04 traversal": lambda r: r["evidence"][0].update(file="../x.py"),
            "R-REC-05 missing file": lambda r: r["evidence"][0].update(file="notesapp/nope.py"),
            "R-REC-06 line past EOF": lambda r: r["trace"][1].update(line=10_000),
            "R-REC-07 no poc": lambda r: r.pop("poc_test"),
            "R-REC-08 severity > impact": lambda r: r["severity"].update(overall="critical"),
            "R-REC-09 bad patch": lambda r: r["remediation"].update(patch="just add a check"),
            "R-REC-09 patch unknown file": lambda r: r["remediation"].update(patch="--- a/x.py\n+++ b/x.py\n@@ -1 +1 @@\n-a\n+b\n"),
            "R-REC-12 evidence level": lambda r: r.update(evidence_level="local"),
            "R-REC-13 threat model": lambda r: r.pop("threat_model"),
            "fingerprint pattern": lambda r: r.update(fingerprint="has space"),
        }
        for name, mutate in cases.items():
            r = self.rec()
            mutate(r)
            self.assertTrue(records.check_record(r, root), name)

    def test_r_rec_10_11_verdict_fields(self):
        nv = self.rec()
        for k in ("root_cause", "intended_behavior", "severity", "remediation", "poc_test", "confidence", "conditions"):
            nv.pop(k)
        nv.update(verdict="needs_validation", claimed_root_cause="x", blockers=["proxy config"], validation_plan={"deployment": "check proxy"})
        self.assertEqual(records.check_record(nv, APP), [])
        bad = dict(nv, severity=self.rec()["severity"])
        self.assertTrue(records.check_record(bad, APP))
        self.assertTrue(records.check_record(dict(nv, validation_plan={}), APP))
        rj = dict(nv, verdict="rejected", reason="owner check exists")
        rj.pop("blockers")
        rj.pop("validation_plan")
        self.assertEqual(records.check_record(rj, APP), [])

    def test_priority_and_material_change(self):
        r = self.rec()
        self.assertEqual(records.priority(r, "reachable", "exploitable_now"), "P1")
        self.assertEqual(records.priority(r, "unreachable", "exploitable_now"), "P4")
        self.assertEqual(records.priority(r, "reachable", "latent"), "P4")
        moved = copy.deepcopy(r)
        moved["trace"][0]["line"] += 1
        self.assertFalse(records.is_material_change(r, moved))
        sev = copy.deepcopy(r)
        sev["severity"]["overall"] = "medium"
        self.assertTrue(records.is_material_change(r, sev))


class Budget(unittest.TestCase):
    def test_r_tst_09_budget_rules(self):
        with self.assertRaises(ValueError):  # R-BUD-01
            Config(budget=4).validate()
        model = FakeModel()
        h = run_harness(model, budget=6, profile="standard")
        run = h.store.run(h.run_id)
        self.assertEqual(run["status"], "incomplete")
        self.assertLessEqual(h.store.invocation_count(h.run_id, "notesapp"), 6)
        deferred = h.store.units(h.run_id, "notesapp", "deferred")
        self.assertTrue(deferred and all(u["unresolved"] == ["budget"] for u in deferred))
        # R-BUD-03: nothing unvalidated reaches findings.json.
        final = {f["record"]["fingerprint"] for f in findings_json(h.store, h.run_id)}
        for c in h.store.candidates(h.run_id, "notesapp", ["pending", "primary", "unvalidated"]):
            self.assertNotIn(c["fingerprint"], final)

    def test_r_mod_03_same_model_refused(self):
        with self.assertRaises(ValueError):
            Config(discovery_model="m", validation_model="m").validate()
        Config(discovery_model="m", validation_model="m", allow_same_model=True).validate()


class Identity(unittest.TestCase):
    def test_r_tst_10_coverage_id_stable(self):
        refs = {"surface": "src/router.ts#POST /users/:id", "boundary": "src/authz.ts#requireOwner",
                "subsystem": "packages/api", "attack_class": "ATTACK-CLASSES.md#Access control"}
        a = coverage_id(refs)
        self.assertEqual(a, coverage_id(dict(refs)))
        self.assertEqual(a, "src%2Frouter.ts%23POST%20%2Fusers%2F%3Aid::src%2Fauthz.ts%23requireOwner::packages%2Fapi::ATTACK-CLASSES.md%23Access%20control")
        self.assertEqual(coverage_id(dict(refs, surface="  é  ")), coverage_id(dict(refs, surface="é")))
        with self.assertRaises(ValueError):
            coverage_id(dict(refs, surface="a​b"))


class Safety(unittest.TestCase):
    def test_r_safe_10_git_head_without_executing_git(self):
        repo = tempfile.mkdtemp()
        os.makedirs(os.path.join(repo, ".git", "refs", "heads"))
        open(os.path.join(repo, ".git", "HEAD"), "w").write("ref: refs/heads/main\n")
        open(os.path.join(repo, ".git", "refs", "heads", "main"), "w").write("a" * 40 + "\n")
        open(os.path.join(repo, ".git", "config"), "w").write("[core]\n\tfsmonitor = touch PWNED\n")
        self.assertEqual(read_git_head(repo), "a" * 40)
        self.assertFalse(os.path.exists(os.path.join(repo, "PWNED")))

    def test_r_cli_01_output_inside_target_refused(self):
        h = Harness(os.path.join(tempfile.mkdtemp(), "o"), ScriptedBackend(FakeModel()), Config(), log=lambda m: None)
        tmp = tempfile.mkdtemp()
        shutil.copytree(APP, os.path.join(tmp, "app"))
        h2 = Harness(os.path.join(tmp, "app", "out"), ScriptedBackend(FakeModel()), Config(), log=lambda m: None)
        with self.assertRaises(ValueError):
            h2.setup([os.path.join(tmp, "app")])
        with self.assertRaises(ValueError):
            h.setup([os.path.join(tmp, "missing")])

    def test_prompts_mark_target_content_untrusted(self):
        model = FakeModel()
        run_harness(model, profile="quick")
        for req in model.calls:
            self.assertIn("UNTRUSTED DATA", req.system)


class KnowledgeAndSpec(unittest.TestCase):
    def test_knowledge_blocks(self):
        k = Knowledge()
        self.assertIn("ATTACK-CLASSES.md#Access control", k.classes())
        blocks = [r for r, _ in k.blocks_for_class("AI-AND-LLM.md#Persistent memory poisoning")]
        self.assertEqual(blocks, ["AI-AND-LLM.md#Core discipline", "AI-AND-LLM.md#Persistent memory poisoning",
                                  "AI-AND-LLM.md#Universal moves", "AI-AND-LLM.md#Validation rules"])
        self.assertNotIn("**Important**", k.block("ATTACK-CLASSES.md#Wildcard"))

    def test_spec_obeys_ste_limits(self):
        root = os.path.dirname(HERE)
        r = subprocess.run([sys.executable, os.path.join(root, "scripts", "ste_check.py"), os.path.join(root, "SPEC.md")],
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stdout)


if __name__ == "__main__":
    unittest.main()
