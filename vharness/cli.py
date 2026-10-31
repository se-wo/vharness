"""Command-line interface (SPEC 11)."""

import argparse
import asyncio
import json
import os
import sys
from collections import Counter

from .backends import make_backend
from .config import PROFILES, Config
from .orchestrator import Harness
from .report import check_outputs
from .store import Store


def _parser():
    p = argparse.ArgumentParser(prog="vharness", description="Security-focused multi-agent vulnerability harness (source-only).")
    sub = p.add_subparsers(dest="cmd", required=True)

    run = sub.add_parser("run", help="start a new run")
    run.add_argument("targets", nargs="+", help="target repository directories")
    run.add_argument("--out", required=True, help="output directory (outside every target)")
    run.add_argument("--profile", choices=sorted(PROFILES), default="standard")
    run.add_argument("--budget", type=int, help="max agent invocations per target")
    run.add_argument("--max-usd", type=float, help="max cost in USD for the run")
    run.add_argument("--concurrency", type=int, default=8)
    run.add_argument("--discovery-model", default=Config.discovery_model)
    run.add_argument("--validation-model", default=Config.validation_model)
    run.add_argument("--role-model", action="append", default=[], metavar="ROLE=MODEL", help="override one role's model")
    run.add_argument("--allow-same-model", action="store_true")
    run.add_argument("--scope", action="append", default=[], help="repository-relative path in scope (repeatable)")
    run.add_argument("--prior", help="output directory of an earlier run")
    run.add_argument("--backend", default="claude")
    run.add_argument("--effort", default="high", help="model effort level (low|medium|high|xhigh|max, or 'none')")
    run.add_argument("--max-turns", type=int, default=60)
    run.add_argument("--agent-timeout", type=int, default=1800, help="seconds per agent")
    run.add_argument("--context-window", type=int, default=1_000_000)
    run.add_argument("--sandbox", choices=("off", "auto", "require"), default="off",
                     help="execute target code in the sandbox of SPEC 13.1 (needs root; start test before each run)")
    run.add_argument("--sandbox-limit", action="append", default=[], metavar="NAME=VALUE",
                     help="sandbox limit override, e.g. wall_s=60, mem_mb=1024, disk_mb=256, nproc=64")
    run.add_argument("--on-rate-limit", choices=("wait", "stop"), default="wait",
                     help="on a usage or rate limit: wait for the reset (up to --rate-limit-max-wait), or stop as paused")
    run.add_argument("--rate-limit-max-wait", type=int, default=6 * 3600, metavar="SECONDS")
    run.add_argument("--fix", action="store_true", help="run the fixer on verified confirmed records (SPEC 13.2; needs --sandbox)")
    run.add_argument("--fix-attempts", type=int, default=2)
    run.add_argument("--sandbox-bind", action="append", default=[], metavar="DIR",
                     help="extra read-only toolchain directory, mounted at the same path")

    for name, help_ in (("resume", "continue the last run"), ("status", "show run status"),
                        ("report", "rewrite report files"), ("check", "validate findings.json and coverage-ledger.json")):
        sp = sub.add_parser(name, help=help_)
        sp.add_argument("--out", required=True)
        if name == "resume":
            sp.add_argument("--backend", default="claude")
    return p


def _open(out):
    db = os.path.join(out, "harness.db")
    if not os.path.exists(db):
        raise SystemExit(f"no harness.db in {out}")
    store = Store(db)
    run = store.latest_run()
    if not run:
        raise SystemExit("no run in the state store")
    return store, run


def cmd_run(a):
    role_models = {}
    for item in a.role_model:
        role, _, model = item.partition("=")
        role_models[role.strip()] = model.strip()
    cfg = Config(
        profile=a.profile, budget=a.budget, max_usd=a.max_usd, concurrency=a.concurrency,
        discovery_model=a.discovery_model, validation_model=a.validation_model, role_models=role_models,
        allow_same_model=a.allow_same_model, scope=a.scope, prior=a.prior, backend=a.backend,
        effort=None if a.effort == "none" else a.effort, max_turns=a.max_turns, agent_timeout_s=a.agent_timeout,
        context_window=a.context_window, sandbox=a.sandbox,
        sandbox_limits={k: int(v) for k, _, v in (x.partition("=") for x in a.sandbox_limit)},
        sandbox_binds=a.sandbox_bind, fix=a.fix, fix_attempts=a.fix_attempts,
        on_rate_limit=a.on_rate_limit, rate_limit_max_wait_s=a.rate_limit_max_wait,
    )
    h = Harness(a.out, make_backend(a.backend), cfg)
    try:
        h.setup(a.targets)
    except ValueError as exc:
        print(f"vharness: {exc}", file=sys.stderr)
        return 2
    asyncio.run(h.execute())
    return _exit_code(h)


def cmd_resume(a):
    store, run = _open(a.out)
    store.close()
    h = Harness(a.out, make_backend(a.backend), run_id=run["run_id"])
    h.resume()
    asyncio.run(h.execute())
    return _exit_code(h)


def _exit_code(h):
    status = h.store.run(h.run_id)["status"]
    return {"complete": 0, "paused": 4}.get(status, 3)  # R-CLI-05


def cmd_status(a):
    store, run = _open(a.out)
    rid = run["run_id"]
    print(f"run {rid}: {run['status']}" + (f" ({run['reason']})" if run["reason"] else ""))
    for t in store.targets(rid):
        units = Counter(u["status"] for u in store.units(rid, t["target"]))
        tasks = Counter(f"{x['stage']}:{x['status']}" for x in store.tasks(rid, t["target"]))
        recs = Counter(r["verdict"] for r in store.records(rid, t["target"]) if r["final"])
        print(f"\n[{t['target']}] {t['root']}")
        print("  units:   " + ", ".join(f"{k}={v}" for k, v in sorted(units.items())))
        print("  tasks:   " + ", ".join(f"{k}={v}" for k, v in sorted(tasks.items())))
        print("  records: " + ", ".join(f"{k}={v}" for k, v in sorted(recs.items())))
    print(f"\ncost: ${store.cost(rid):.3f}")
    for row in store.cost_by_role(rid):
        print(f"  {row['role']:<10} {row['model']:<20} n={row['n']:<4} ok={row['ok']:<4} ${row['cost_usd']:.3f}")
    return 0


def cmd_report(a):
    from .report import write_reports
    store, run = _open(a.out)
    for name, path in write_reports(store, run["run_id"], os.path.realpath(a.out)).items():
        print(path)
    return 0


def cmd_check(a):
    store, run = _open(a.out)
    try:
        with open(os.path.join(a.out, "findings.json"), encoding="utf-8") as fh:
            findings = json.load(fh)
        with open(os.path.join(a.out, "coverage-ledger.json"), encoding="utf-8") as fh:
            ledger = json.load(fh)
    except (OSError, ValueError) as exc:
        print(f"check failed: {exc}")
        return 1
    errors = check_outputs(store, run["run_id"], findings, ledger)
    for e in errors:
        print(e)
    print(f"{len(findings)} records, {len(ledger)} units, {len(errors)} error(s)")
    return 1 if errors else 0


def main(argv=None):
    a = _parser().parse_args(argv)
    return {"run": cmd_run, "resume": cmd_resume, "status": cmd_status, "report": cmd_report, "check": cmd_check}[a.cmd](a)
