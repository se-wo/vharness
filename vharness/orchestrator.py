"""Orchestrator: worker pool over the task queue (SPEC 6.2) plus run setup and resume."""

import asyncio
import json
import os
import sys
import time
import traceback
import uuid

from . import schemas, stages
from .prompts import ROOT_PLACEHOLDER, SANDBOX
from .backends import AgentRequest, AgentResult, HarnessTool
from .sandbox import Limits, RunSpec, Sandbox, SandboxError
from .budget import Budget
from .config import Config
from .ids import agent_id as make_agent_id
from .knowledge import Knowledge
from .report import write_reports
from .store import OPEN_TASK, Store

UPSTREAM_OF_VERIFY = ("recon", "hunt", "gapfill", "dedup", "validate", "poc", "trace")


def read_git_head(root):
    """Read the commit from .git without executing git (R-SAFE-10).

    Running git inside an untrusted repository can execute commands from its
    .git/config (core.fsmonitor, filter drivers), so plain file reads are used.
    """
    git = os.path.join(root, ".git")
    if os.path.isfile(git):  # worktree / submodule: "gitdir: <path>"
        try:
            with open(git, encoding="utf-8") as fh:
                line = fh.read().strip()
            if line.startswith("gitdir:"):
                git = os.path.normpath(os.path.join(root, line.split(":", 1)[1].strip()))
        except OSError:
            return None
    try:
        with open(os.path.join(git, "HEAD"), encoding="utf-8") as fh:
            head = fh.read().strip()
    except OSError:
        return None
    if not head.startswith("ref:"):
        return head[:40] or None
    ref = head.split(":", 1)[1].strip()
    try:
        with open(os.path.join(git, ref), encoding="utf-8") as fh:
            return fh.read().strip()[:40]
    except OSError:
        pass
    try:
        with open(os.path.join(git, "packed-refs"), encoding="utf-8") as fh:
            for line in fh:
                parts = line.strip().split(" ")
                if len(parts) == 2 and parts[1] == ref:
                    return parts[0][:40]
    except OSError:
        pass
    return None


class Harness:
    def __init__(self, out, backend, cfg=None, run_id=None, log=None):
        self.out = os.path.realpath(out)
        os.makedirs(self.out, exist_ok=True)
        self.store = Store(os.path.join(self.out, "harness.db"))
        self.backend = backend
        self.knowledge = Knowledge()
        self._log = log or (lambda msg: print(msg, file=sys.stderr, flush=True))
        if run_id is None:
            self.cfg = cfg
            self.run_id = None
        else:
            run = self.store.run(run_id)
            self.run_id = run_id
            self.cfg = Config.from_dict(json.loads(run["config"]))
        self.budget = None
        self.sandbox = None
        self._sbx_sem = None
        self.prior_records = {}
        self.prior_exclusions = {}

    def log(self, msg):
        self._log(msg)

    # ------------------------------------------------------------------ setup

    def setup(self, targets):
        """Validate inputs, create the run and seed recon tasks."""
        self.cfg.validate()
        roots = []
        for t in targets:
            root = os.path.realpath(t)
            if not os.path.isdir(root):
                raise ValueError(f"target {t!r} is not a directory (R-CLI-02)")
            if os.path.commonpath([self.out, root]) == root:
                raise ValueError(f"output directory {self.out} is inside target {root} (R-CLI-01, R-SAFE-07)")
            if os.path.commonpath([self.out, root]) == self.out:
                raise ValueError(f"target {root} is inside the output directory {self.out}")
            roots.append(root)
        self.run_id = time.strftime("run-%Y%m%d-%H%M%S-") + uuid.uuid4().hex[:6]
        self.store.create_run(self.run_id, self.cfg.to_dict())
        self.budget = Budget(self.store, self.run_id, self.cfg)
        names = set()
        for root in roots:
            name = os.path.basename(root.rstrip("/")) or "target"
            base, n = name, 2
            while name in names:
                name, n = f"{base}-{n}", n + 1
            names.add(name)
            self.store.add_target(self.run_id, name, root, read_git_head(root), None)
        self.load_prior()
        self.start_sandbox()
        for t in self.store.targets(self.run_id):
            for focus in ("product", "authority", "surfaces"):
                self.store.add_task(self.run_id, t["target"], "recon", {"focus": focus, "attempt": 0})
            self.store.set_stage(self.run_id, t["target"], "recon", "running")
        self.log(f"run {self.run_id}: {len(roots)} target(s), profile {self.cfg.profile}, "
                 f"discovery {self.cfg.model_for('hunter')}, validation {self.cfg.model_for('validator')}")
        return self.run_id

    def load_prior(self):
        """SPEC 7.2.2 steps 4-6: carry earlier confirmed/needs_validation records into validation."""
        if not self.cfg.prior:
            return
        path = os.path.join(self.cfg.prior, "findings.json")
        try:
            with open(path, encoding="utf-8") as fh:
                prior = json.load(fh)
        except (OSError, ValueError) as exc:
            self.store.add_note(self.run_id, None, "prior", f"prior findings not usable: {exc}")
            return
        targets = {t["target"] for t in self.store.targets(self.run_id)}
        for item in prior:
            rec, target = item.get("record", {}), item.get("target")
            if target not in targets or rec.get("verdict") not in ("confirmed", "needs_validation"):
                continue
            self.prior_records[(target, rec["fingerprint"])] = rec
            self.prior_exclusions.setdefault(target, []).append(f"{rec['fingerprint']}: {rec.get('title')}")
            cand = {k: v for k, v in rec.items() if k not in ("verdict", "reason")}
            cand["proposed_verdict"] = rec["verdict"]
            if not schemas.validate(cand, schemas.CANDIDATE):
                self.store.put_candidate(self.run_id, target, rec["fingerprint"], cand, "prior", [], "primary")
                self.store.add_task(self.run_id, target, "validate", {"fingerprint": rec["fingerprint"], "attempt": 0})

    def start_sandbox(self):
        """SPEC 13.1.1.3 / 13.1.2.2: start test before each run; no tool unless every control holds."""
        if self.cfg.sandbox == "off":
            self.store.put_doc(self.run_id, "", "sandbox", {"mode": "off", "available": False, "problems": []})
            return
        sb = Sandbox(os.path.join(self.out, "sandbox"), Limits(**self.cfg.sandbox_limits), self.cfg.sandbox_binds)
        root = self.store.targets(self.run_id)[0]["root"]
        ok, problems = sb.probe(root, os.path.join(self.out, "sandbox", f"probe-{uuid.uuid4().hex[:6]}"))
        self.store.put_doc(self.run_id, "", "sandbox", {"mode": self.cfg.sandbox, "available": ok, "problems": problems,
                                                       "limits": sb.limits.__dict__, "toolchain": sb.toolchain})
        if ok:
            self.sandbox = sb
            self.log(f"sandbox: start test passed; hunters and validators get sandbox_run ({sb.limits.__dict__})")
            return
        msg = "sandbox start test failed: " + "; ".join(problems)
        if self.cfg.sandbox == "require":
            self.store.set_run_status(self.run_id, "incomplete", "sandbox_start_test_failed")
            raise ValueError(msg + " (--sandbox require)")
        self.log(msg + " -> source-only run (--sandbox auto)")

    def sandbox_lookup(self, target):
        """Lookup for R-SBX-11; None when the sandbox is not in use."""
        if not self.sandbox:
            return None

        def lookup(sbx_id):
            run = self.store.sandbox_run(sbx_id)
            return run if run and run["run_id"] == self.run_id and run["target"] == target and not run["error"] else None
        return lookup

    async def sandbox_exec(self, target, agent, kind, spec, artifacts_dir):
        """Run one sandbox command off the event loop and record it (SPEC 13.1.4.3)."""
        if self._sbx_sem is None:
            self._sbx_sem = asyncio.Semaphore(self.cfg.sandbox_concurrency)
        root = self.store.target_root(self.run_id, target)
        async with self._sbx_sem:
            try:
                status = await asyncio.to_thread(self.sandbox.run, root, spec, artifacts_dir)
                error = None
            except SandboxError as exc:
                status, error = None, str(exc)
        sbx_id = self.store.add_sandbox_run(self.run_id, target, agent, kind, spec, status, error)
        return sbx_id, status, error

    def sandbox_tool(self, target, agent):
        lim = self.sandbox.limits

        async def handler(args):
            spec = RunSpec(command=args.get("command", ""), files=list(args.get("files") or []), keep=list(args.get("keep") or []),
                           copy_target=bool(args.get("copy_target")), timeout_s=args.get("timeout_s"))
            sbx_id, st, error = await self.sandbox_exec(target, agent, "agent", spec,
                                                        os.path.join(self.out, "agents", agent, "artifacts"))
            self.log(f"[{target}] sandbox   {agent} {sbx_id} exit={st and st.get('exit_code')} "
                     f"timeout={st and st.get('timed_out')} {error or ''}".rstrip())
            if error:
                return {"run_id": sbx_id, "error": error}
            return {"run_id": sbx_id, "command": spec.command, "exit_code": st["exit_code"], "signal": st["signal"],
                    "timed_out": st["timed_out"], "duration_ms": st["duration_ms"],
                    "stdout": st["stdout"], "stderr": st["stderr"],
                    "stdout_truncated": st["stdout_bytes"] > len(st["stdout"].encode()),
                    "kept": [f"agents/{agent}/artifacts/{p['path']}" for p in st["promoted"]], "not_kept": st["rejected"]}

        schema = {
            "type": "object",
            "properties": {
                "command": {"type": "string", "description": "Shell command (sh -c), run in /scratch."},
                "files": {"type": "array", "description": "Input files written into /scratch first.",
                          "items": {"type": "object", "properties": {"path": {"type": "string"}, "content": {"type": "string"}},
                                    "required": ["path", "content"]}},
                "copy_target": {"type": "boolean", "description": "Copy the target to /scratch/src (writable) and start there."},
                "keep": {"type": "array", "items": {"type": "string"}, "description": "/scratch-relative files to keep as evidence."},
                "timeout_s": {"type": "integer", "minimum": 1, "maximum": lim.wall_s},
            },
            "required": ["command"],
        }
        return HarnessTool("sandbox_run", "Run a shell command in the isolated vharness sandbox (no network, target read-only "
                           "at /target, writable /scratch, strict limits). Returns run_id, exit code and output.", schema, handler)

    def resume(self):
        self.budget = Budget(self.store, self.run_id, self.cfg)
        self.start_sandbox()
        n = self.store.requeue_running(self.run_id)
        for t in self.store.targets(self.run_id):
            for u in self.store.units(self.run_id, t["target"], "in_progress"):
                u.update(status="planned", agent_id=None)
                self.store.put_unit(self.run_id, t["target"], u)
        self.store.set_run_status(self.run_id, "running")
        self.log(f"resume {self.run_id}: {n} task(s) requeued")

    # ------------------------------------------------------------------ helpers used by stages

    def incomplete(self, reason):
        self.store.set_run_status(self.run_id, "running", reason)

    def add_unit(self, target, unit):
        """Insert a unit unless its coverage_id already exists (R-PLAN-01). Returns True if added."""
        if self.store.unit(self.run_id, target, unit["coverage_id"]):
            return False
        self.store.put_unit(self.run_id, target, unit)
        return True

    def new_agent_id(self, role, target):
        return make_agent_id(role, target, self.store.next_seq("agent"))

    def fits(self, system, prompt, model, target=None):
        if target is not None:
            system = system.replace(ROOT_PLACEHOLDER, self.store.target_root(self.run_id, target))
        return (len(system) + len(prompt)) // 4 <= self.cfg.context_limit_tokens(model)

    def current_wave(self, target):
        waves = [int(s["stage"].split(":")[1]) for s in self.store.stages(self.run_id) if s["target"] == target and s["stage"].startswith("wave:")]
        return max(waves, default=1)

    def record_wishlist(self, task, target, agent, items):
        for item in items or []:
            self.store.add_wish(self.run_id, target, agent, task["task_id"], item)

    def _write(self, agent, name, content):
        d = os.path.join(self.out, "agents", agent)
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, name), "w", encoding="utf-8") as fh:
            fh.write(content)

    async def invoke(self, task, role, schema_key, system, prompt, agent_id=None, exclude=(), sandbox=False):
        """Run one agent; retry once on a backend error with a new agent ID (R-RTY-01..03)."""
        target = task["target"]
        model = self.cfg.model_for(role)
        schema = schemas.ROLE_SCHEMAS[schema_key]
        system = system.replace(ROOT_PLACEHOLDER, self.store.target_root(self.run_id, target))
        use_sandbox = sandbox and self.sandbox is not None
        if use_sandbox:
            lim = self.sandbox.limits
            system += "\n\n" + SANDBOX.format(limits=f"{lim.wall_s}s wall, {lim.cpu_s}s CPU, {lim.mem_mb} MB memory, "
                                                       f"{lim.nproc} processes, {lim.disk_mb} MB disk",
                                         toolchain=self.sandbox.toolchain_text())
        result = None
        for attempt in range(2):
            agent = agent_id if (attempt == 0 and agent_id) else self.new_agent_id(role, target)
            assert agent not in exclude, "independence violation"  # R-VAL-01, R-VER-01
            if not self.fits(system, prompt, model):
                return AgentResult(False, error="prompt exceeds context budget", error_kind="context"), agent
            self._write(agent, "prompt.md", f"# role: {role}\n# model: {model}\n# task: {task['task_id']}\n\n## system\n{system}\n\n## prompt\n{prompt}\n")
            req = AgentRequest(agent_id=agent, role=role, model=model, system=system, prompt=prompt, schema=schema,
                               cwd=self.store.target_root(self.run_id, target), max_turns=self.cfg.max_turns,
                               timeout_s=self.cfg.agent_timeout_s, effort=self.cfg.effort,
                               tools=[self.sandbox_tool(target, agent)] if use_sandbox else [])
            self.budget.begin(target)
            try:
                result = await self.backend.run(req)
            finally:
                self.budget.end(target)
            self.store.add_invocation(self.run_id, target, task["task_id"], role, agent, model, result, (len(system) + len(prompt)) // 4)
            self._write(agent, "result.json", json.dumps(
                {"ok": result.ok, "error": result.error, "error_kind": result.error_kind, "turns": result.turns,
                 "cost_usd": result.cost_usd, "output": result.output, "denials": result.denials}, indent=2, default=str))
            self.store.update_task(task["task_id"], agent_id=agent, model=model)
            status = "ok" if result.ok else f"{result.error_kind}: {(result.error or '')[:120]}"
            self.log(f"[{target}] {role:<9} {agent} {status} ({result.turns} turns, ${result.cost_usd:.3f})")
            if result.ok or not result.retryable or attempt == 1 or not self.budget.can_spend(target):
                return result, agent
        return result, agent

    # ------------------------------------------------------------------ loop

    async def dispatch(self, task):
        handler = stages.HANDLERS[task["stage"]]
        return await handler(self, task)

    def advance(self):
        """Apply the event rules of SPEC 6.3 that depend on queue state."""
        for t in self.store.targets(self.run_id):
            target = t["target"]
            if self.store.stage(self.run_id, target, "plan") is None and stages.recon_complete(self, target):
                self.store.set_stage(self.run_id, target, "recon", "done")
                stages.plan(self, target)
            if self.store.stage(self.run_id, target, "plan") != "done":
                continue
            open_tasks = self.store.tasks(self.run_id, target, statuses=OPEN_TASK)
            # The last hunt task of a wave is done -> one gapfill task.
            wave = self.current_wave(target)
            open_hunts = [x for x in open_tasks if x["stage"] == "hunt" and x["payload"].get("wave") == wave]
            if (not open_hunts and self.store.stage(self.run_id, target, f"wave:{wave}") == "running"
                    and not any(x["stage"] == "gapfill" for x in open_tasks)):
                self.store.set_stage(self.run_id, target, f"wave:{wave}", "closing")
                self.store.add_task(self.run_id, target, "gapfill", {"wave": wave})
                continue
            # No upstream or verify work open -> one fix task per verified confirmed record (SPEC 13.2.2.1).
            if (self.cfg.fix and self.sandbox is not None
                    and not any(x["stage"] in UPSTREAM_OF_VERIFY + ("verify",) for x in open_tasks)):
                queued = {x["payload"]["fingerprint"] for x in open_tasks if x["stage"] == "fix"}
                for rec in self.store.records(self.run_id, target, ["confirmed"]):
                    if rec["final"] and rec["fingerprint"] not in queued and not self.store.fix(self.run_id, target, rec["fingerprint"]):
                        order = {"P0": 0, "P1": 1, "P2": 2, "P3": 3, "P4": 4}.get(rec["priority"], 5)
                        self.store.add_task(self.run_id, target, "fix", {"fingerprint": rec["fingerprint"], "attempt": 0}, priority=order)
            # No upstream work open -> verify each unverified record.
            if self.cfg.prof.separate_verify and not any(x["stage"] in UPSTREAM_OF_VERIFY for x in open_tasks):
                queued = {x["payload"]["fingerprint"] for x in open_tasks if x["stage"] == "verify"}
                for rec in self.store.records(self.run_id, target, ["confirmed", "needs_validation"]):
                    if not rec["final"] and rec["fingerprint"] not in queued and not rec["verifiers"]:
                        self.store.add_task(self.run_id, target, "verify", {"fingerprint": rec["fingerprint"], "round": 1, "attempt": 0})

    async def run_loop(self):
        if not self.budget.minimum_fundable():
            self.incomplete("budget_cannot_fund_reconnaissance_and_reserves")
            return
        running = {}
        while True:
            while len(running) < self.cfg.concurrency:
                task = self.store.next_task(self.run_id)
                if not task:
                    break
                self.store.update_task(task["task_id"], status="running", attempts=task["attempts"] + 1)
                running[asyncio.ensure_future(self.dispatch(task))] = task
            if not running:
                self.advance()
                if self.store.next_task(self.run_id):
                    continue
                break
            done, _ = await asyncio.wait(running, return_when=asyncio.FIRST_COMPLETED)
            for fut in done:
                task = running.pop(fut)
                try:
                    status = fut.result() or "done"
                    self.store.update_task(task["task_id"], status=status)
                except Exception:
                    err = traceback.format_exc()
                    self.store.update_task(task["task_id"], status="failed", error=err[-2000:])
                    self.log(f"[{task['target']}] {task['stage']} task {task['task_id']} crashed:\n{err}")
                    self.incomplete(f"task_crash:{task['stage']}")
            self.advance()

    def finish(self):
        """Decide the terminal state (R-PIPE-06/07) and write reports (no model, R-PIPE-08)."""
        for t in self.store.targets(self.run_id):
            open_c = self.store.candidates(self.run_id, t["target"], ["pending", "dedup_pending", "primary", "unvalidated"])
            if open_c:
                self.incomplete("unvalidated_candidates")
            if self.store.units(self.run_id, t["target"], ["planned", "in_progress"]):
                self.incomplete("units_not_assigned")
        run = self.store.run(self.run_id)
        self.store.set_run_status(self.run_id, "incomplete" if run["reason"] else "complete")
        for t in self.store.targets(self.run_id):
            self.store.set_stage(self.run_id, t["target"], "report", "done")
        paths = write_reports(self.store, self.run_id, self.out)
        run = self.store.run(self.run_id)
        self.log(f"run {self.run_id} {run['status']}{' (' + run['reason'] + ')' if run['reason'] else ''}; "
                 f"cost ${self.store.cost(self.run_id):.2f}; reports in {self.out}")
        return paths

    async def execute(self):
        await self.run_loop()
        return self.finish()
