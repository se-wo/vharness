"""Reports (SPEC 7.10). Plain code only: no model writes report text (R-PIPE-08)."""

import json
import os
import time
from collections import Counter

from . import records

PRIORITY_ORDER = {"P0": 0, "P1": 1, "P2": 2, "P3": 3, "P4": 4, None: 5}
SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}


def final_records(store, run_id):
    """Records that go into findings.json: final, not removed (R-BUD-03, R-VER)."""
    return [r for r in store.records(run_id) if r["final"]]


def findings_json(store, run_id):
    items = []
    for r in final_records(store, run_id):
        items.append({
            "target": r["target"],
            "priority": r["priority"],
            "reachability": r["reachability"],
            "exposure": r["exposure"],
            "poc": r["poc"],
            "record": r["data"],
        })
    return sorted(items, key=lambda x: (x["target"], x["record"]["fingerprint"]))


def ledger_json(store, run_id):
    out = []
    for t in store.targets(run_id):
        for u in store.units(run_id, t["target"]):
            out.append({"target": t["target"]} | {k: v for k, v in u.items()})
    return sorted(out, key=lambda u: (u["target"], u["coverage_id"]))


def check_outputs(store, run_id, findings, ledger):
    """`vharness check`: mechanical checks of findings.json and coverage-ledger.json."""
    errors = []
    roots = {t["target"]: t["root"] for t in store.targets(run_id)}
    fps = set()

    def lookup_for(target):
        def lookup(sbx_id):
            run = store.sandbox_run(sbx_id)
            return run if run and run["run_id"] == run_id and run["target"] == target and not run["error"] else None
        return lookup
    for i, item in enumerate(findings):
        rec = item.get("record", {})
        root = roots.get(item.get("target"))
        for e in records.check_record(rec, root, lookup_for(item.get("target"))):
            errors.append(f"findings[{i}] {rec.get('fingerprint')}: {e}")
        key = (item.get("target"), rec.get("fingerprint"))
        if key in fps:
            errors.append(f"findings[{i}]: duplicate fingerprint {key}")
        fps.add(key)
    ids = set()
    for i, u in enumerate(ledger):
        key = (u["target"], u["coverage_id"])
        if key in ids:
            errors.append(f"ledger[{i}]: duplicate coverage_id {u['coverage_id']}")
        ids.add(key)
        st = u["status"]
        has_ev = bool(u["reviewed_paths"]) and bool(u["checks"])
        if st == "planned" and (u["agent_id"] or has_ev or u["fingerprints"] or u["unresolved"]):
            errors.append(f"ledger[{i}]: planned unit carries owner or evidence")
        if st in ("deferred", "out_of_scope", "not_applicable") and (u["agent_id"] or has_ev or not u["unresolved"]):
            errors.append(f"ledger[{i}]: {st} unit needs a reason and no owner/evidence")
        if st == "covered" and (not u["agent_id"] or not has_ev or u["fingerprints"] or u["unresolved"]):
            errors.append(f"ledger[{i}]: covered unit needs owner, paths and checks, and no fingerprints/unresolved")
        if st == "candidate" and (not u["agent_id"] or not has_ev or not u["fingerprints"]):
            errors.append(f"ledger[{i}]: candidate unit needs owner, evidence and fingerprints")
        if st == "blocked" and not u["unresolved"]:
            errors.append(f"ledger[{i}]: blocked unit needs a blocker")
        if set(u["reviewed_paths"]) != {p for c in u["checks"] for p in c["reviewed_paths"]}:
            errors.append(f"ledger[{i}]: reviewed_paths is not the union of check paths")
    return errors


def group_wishlist(items, threshold=0.4):
    """Merge wishlist items that ask for the same resource; most-requested first."""
    import re
    tok = lambda t: {w for w in re.findall(r"[a-z0-9_./]{4,}", t.lower())}
    groups = []
    for w in items:
        t = tok(w["need"])
        for g in groups:
            if g["target"] == w["target"] and len(t & g["tokens"]) / max(len(t | g["tokens"]), 1) >= threshold:
                g["count"] += 1
                g["agents"].add(w["agent_id"])
                break
        else:
            groups.append(dict(w, tokens=t, count=1, agents={w["agent_id"]}))
    return sorted(groups, key=lambda g: (-g["count"], g["item_id"]))


POC_LABEL = {
    "fixed": "fails on unchanged code, passes after the patch",
    "reproduced": "fails on unchanged code (patch did not make it pass, or no patch)",
    "not_reproduced": "PASSES on unchanged code: the defect was not reproduced",
    "error": "could not run (setup, patch or sandbox error)",
    "no_command": "no command to run",
}


def _poc_line(poc):
    if not poc:
        return "not executed (sandbox not in use)"
    return f"`{poc['result']}`: {POC_LABEL.get(poc['result'], '')}"


def _md_escape(text):
    return str(text or "").replace("|", "\\|").replace("\n", " ")


def write_reports(store, run_id, out):
    run = store.run(run_id)
    cfg = json.loads(run["config"])
    findings = findings_json(store, run_id)
    ledger = ledger_json(store, run_id)
    paths = {}

    def write(name, content):
        path = os.path.join(out, name)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(content)
        paths[name] = path

    write("findings.json", json.dumps(findings, indent=2, sort_keys=False) + "\n")
    write("coverage-ledger.json", json.dumps(ledger, indent=2) + "\n")
    errors = check_outputs(store, run_id, findings, ledger)

    confirmed = sorted([f for f in findings if f["record"]["verdict"] == "confirmed"],
                       key=lambda f: (PRIORITY_ORDER.get(f["priority"], 5), SEV_ORDER.get(f["record"]["severity"]["overall"], 9), f["record"]["fingerprint"]))
    needs = [f for f in findings if f["record"]["verdict"] == "needs_validation"]
    rejected = [f for f in findings if f["record"]["verdict"] == "rejected"]
    targets = store.targets(run_id)
    partial = run["status"] != "complete" or cfg["profile"] == "quick" or cfg.get("scope")
    sbx = store.doc(run_id, "", "sandbox", parse=True) or {"mode": "off", "available": False, "problems": []}
    if sbx["available"]:
        lim = sbx.get("limits", {})
        execution = (f"- Execution: **sandboxed** (start test passed: no network, empty environment, read-only target, "
                     f"tmpfs scratch, new uid, no new privileges; {lim.get('wall_s')}s wall, {lim.get('cpu_s')}s CPU, "
                     f"{lim.get('mem_mb')} MB memory, {lim.get('nproc')} processes, {lim.get('disk_mb')} MB disk). "
                     f"{len(store.sandbox_runs(run_id))} sandbox runs recorded. PoC tests were run by the harness (see PoC column).")
    elif sbx["mode"] != "off":
        execution = ("- Execution: **source-only**. The sandbox start test failed, so no target code was executed: "
                     + "; ".join(sbx["problems"]) + ". Proof-of-concept tests and patches are proposals that have **not been executed**.")
    else:
        execution = ("- Execution: **source-only** (`--sandbox off`). No target code was executed. Proof-of-concept tests and "
                     "patches in this report are proposals that have **not been executed** (R-REP-05).")
    unvalidated = [c for t in targets for c in store.candidates(run_id, t["target"], ["pending", "dedup_pending", "primary", "unvalidated"])]

    L = ["# Security audit report", ""]
    # 1. Run data
    L += ["## 1. Run", ""]
    if run["status"] == "paused":  # R-RL-05
        pause = store.doc(run_id, "", "pause", parse=True) or {}
        until = time.strftime("%Y-%m-%d %H:%M:%S %Z", time.localtime(pause.get("until", 0)))
        L += [f"> **This run is paused by a rate limit** ({pause.get('message', '')}). The limit resets at about {until}"
              f"{'' if pause.get('reset_known') else ' (estimated)'}. Continue with `python3 -m vharness resume --out {out}`. "
              "This report covers only the work done so far.", ""]
    elif partial:
        reasons = run["reason"] or ("quick profile" if cfg["profile"] == "quick" else "scoped run")
        L += [f"> **This is a partial pass.** Status: `{run['status']}`. Reason: {reasons}.", ""]
    L += [
        f"- Run: `{run_id}`; status `{run['status']}`",
        f"- Profile: `{cfg['profile']}`; scope: {', '.join(cfg.get('scope') or []) or 'whole repository'}",
        f"- Budget: {cfg.get('budget') or 'none'} invocations per target; USD cap: {cfg.get('max_usd') or 'none'}",
        f"- Discovery model: `{cfg['discovery_model']}`; validation model: `{cfg['validation_model']}`",
        execution,
        f"- Prior run used: {cfg.get('prior') or 'none'}",
        "",
        "| Target | Root | Commit |",
        "|---|---|---|",
    ] + [f"| {t['target']} | `{t['root']}` | `{t['commit_sha'] or 'unknown'}` |" for t in targets] + [""]
    if unvalidated:
        L += ["**Unvalidated candidates (not findings):** " + ", ".join(f"`{c['fingerprint']}`" for c in unvalidated), ""]

    # 2. Posture
    sev = Counter(f["record"]["severity"]["overall"] for f in confirmed)
    L += ["## 2. Summary", ""]
    if confirmed:
        L.append(f"{len(confirmed)} confirmed vulnerabilities (" + ", ".join(f"{n} {s}" for s, n in sorted(sev.items(), key=lambda x: SEV_ORDER[x[0]]))
                 + f"), {len(needs)} leads that need validation, {len(rejected)} candidates rejected.")
    else:
        L.append(f"No confirmed vulnerabilities. {len(needs)} leads need validation; {len(rejected)} candidates were rejected. "
                 "This is not proof of absence; see the coverage section.")
    L.append("")

    # 3. Confirmed table
    L += ["## 3. Confirmed vulnerabilities", ""]
    if confirmed:
        L += ["| Priority | Severity | Exposure | PoC | Evidence | Target | Title | Boundary |", "|---|---|---|---|---|---|---|---|"]
        for f in confirmed:
            r = f["record"]
            L.append(f"| {f['priority'] or '-'} | {r['severity']['overall']} | {f['exposure'] or 'unknown'} | "
                     f"{(f['poc'] or {}).get('result', 'not run')} | {r['evidence_level']} | {f['target']} | "
                     f"{_md_escape(r['title'])} | {_md_escape(r['threat_model']['boundary'])} |")
    else:
        L.append("None.")
    L.append("")

    # 4. Details
    L += ["## 4. Details", ""]
    for f in confirmed:
        r = f["record"]
        tm = r["threat_model"]
        entry, sink = r["trace"][0], r["trace"][-1]
        L += [
            f"### [{f['priority'] or '-'}] {r['title']}",
            f"`{f['target']}` · fingerprint `{r['fingerprint']}` · severity **{r['severity']['overall']}** "
            f"(likelihood {r['severity']['likelihood']['level']}, impact {r['severity']['impact']['level']}) · confidence {r['confidence']}",
            "",
            f"- **Attacker:** {tm['attacker']} (starting with: {tm['starting_capability']})",
            f"- **Boundary / broken assumption:** {tm['boundary']} / {tm['assumption_broken']}",
            f"- **Affected resource:** {tm['affected_resource']}",
            f"- **Entry → sink:** `{entry['file']}:{entry['line']}` → `{sink['file']}:{sink['line']}`",
            f"- **Reachability:** {f['reachability'] or 'unknown'}; exposure {f['exposure'] or 'unknown'}",
            f"- **Root cause:** {r['root_cause']}",
            f"- **Fix:** {r['remediation']['strategy']}",
            f"- **PoC (harness-run):** {_poc_line(f['poc'])}",
            "",
        ]
    # 5. Needs validation
    L += ["## 5. Needs validation (no severity)", ""]
    if needs:
        L += ["| Target | Title | Blocker | Next step |", "|---|---|---|---|"]
        for f in needs:
            r = f["record"]
            plan = r["validation_plan"].get("local") or r["validation_plan"].get("deployment")
            L.append(f"| {f['target']} | {_md_escape(r['title'])} | {_md_escape('; '.join(r['blockers']))} | {_md_escape(plan)} |")
    else:
        L.append("None.")
    L.append("")
    # 6. Hardening
    hardening = [n for t in targets for n in store.notes(run_id, t["target"], "hardening")]
    L += ["## 6. Hardening notes (not vulnerabilities)", ""]
    L += [f"- ({n['target']}) {n['text']}" for n in hardening[:50]] or ["None."]
    L.append("")
    # 7. Coverage
    L += ["## 7. Coverage", ""]
    L += ["| Target | " + " | ".join(["covered", "candidate", "blocked", "deferred", "out_of_scope", "planned", "total"]) + " |",
          "|---" * 8 + "|"]
    for t in targets:
        c = Counter(u["status"] for u in ledger if u["target"] == t["target"])
        L.append(f"| {t['target']} | " + " | ".join(str(c.get(k, 0)) for k in ("covered", "candidate", "blocked", "deferred", "out_of_scope", "planned"))
                 + f" | {sum(c.values())} |")
    gaps = [u for u in ledger if u["status"] in ("blocked", "deferred")]
    if gaps:
        L += ["", "Gaps (blocked or deferred units):"]
        L += [f"- `{u['target']}` {u['surface']} / {u['boundary']} / {u['attack_class']}: {', '.join(u['unresolved'])}" for u in gaps[:40]]
        if len(gaps) > 40:
            L.append(f"- ... {len(gaps) - 40} more in coverage-ledger.json")
    waves = [s for s in store.stages(run_id) if s["stage"].startswith("wave:")]
    L += ["", f"Hunt waves: {len(waves)}. Each run adds coverage; one run does not exhaust a target.", ""]
    # 8. Wishlist
    wl = group_wishlist(store.wishlist(run_id))
    L += ["## 8. Wishlist", ""]
    L += [f"- ({w['target']}, asked by {w['count']} agent(s)) **{w['need']}**: unblocks {w['unblocks']}" for w in wl[:20]] or ["None."]
    L.append("")
    # 9. Cost
    L += ["## 9. Cost", "", "| Role | Model | Invocations | OK | Input tokens | Output tokens | USD |", "|---|---|---|---|---|---|---|"]
    for row in store.cost_by_role(run_id):
        L.append(f"| {row['role']} | {row['model']} | {row['n']} | {row['ok']} | {row['input_tokens'] or 0} | {row['output_tokens'] or 0} | {row['cost_usd']:.3f} |")
    L += ["", f"Total: ${store.cost(run_id):.3f}", ""]
    fixes = store.fixes(run_id)
    if cfg.get("fix"):
        L += ["## 10. Fixes (review required; vharness never merges)", ""]
        if fixes:
            L += ["Each fix is a `git am`-ready patch in `fixes/`. A person must review every fix before it is merged (R-FIX-12).", "",
                  "| Result | Target | Record | Reason | Patch file |", "|---|---|---|---|---|"]
            titles = {(f["target"], f["record"]["fingerprint"]): f["record"]["title"] for f in confirmed}
            for fx in fixes:
                L.append(f"| {fx['status']} | {fx['target']} | {_md_escape(titles.get((fx['target'], fx['fingerprint']), fx['fingerprint']))} | "
                         f"{_md_escape(fx['reason'])} | {('`' + fx['patch_file'] + '`') if fx['patch_file'] else '-'} |")
        else:
            L.append("No fix was made.")
        L.append("")
        for t in targets:
            fs = store.doc(run_id, t["target"], "fixset", parse=True)
            if fs and fs["status"] != "none":
                detail = {"ok": "all accepted fixes apply together and every regression test and suite passes",
                          "conflict": f"the patch of `{fs.get('failed')}` does not apply after the patches before it",
                          "interaction": f"the patches apply together, but these fail: {', '.join(f'`{x}`' for x in fs.get('failed', []))}",
                          "error": f"the combined gate could not run: {fs.get('failed')}"}[fs["status"]]
                L += [f"Combined gate for `{t['target']}` (R-FIX-13): **{fs['status']}**: {detail}. "
                      "Each patch is made against the unchanged commit; review each on its own branch.", ""]
    if errors:
        L += ["## Output check errors", ""] + [f"- {e}" for e in errors[:50]] + [""]
    write("REPORT.md", "\n".join(L))

    # FINDINGS-DETAIL.md
    D = ["# Findings detail", "", ("PoC tests were executed by the harness in its sandbox; each section gives the result."
                                    if sbx["available"] else "Proof-of-concept tests and patches were **not executed** by the harness."), ""]
    for f in confirmed:
        r = f["record"]
        if SEV_ORDER[r["severity"]["overall"]] > SEV_ORDER["medium"]:
            continue
        D += [f"## {r['title']}", "", f"`{f['target']}` · `{r['fingerprint']}` · {r['severity']['overall']} · {f['priority'] or '-'}", "",
              r["description"], "", "### Trace", ""]
        D += [f"{i}. **{s['kind']}** `{s['file']}:{s['line']}` ({s['scope']}): {s['description']}" for i, s in enumerate(r["trace"], 1)]
        D += ["", "### Evidence", ""] + [f"- `{e['file']}:{e['line']}`: {e['description']}" for e in r["evidence"]]
        D += ["", "### Conditions", ""] + ([f"- {c['kind']}: {c['description']}" for c in r["conditions"]] or ["- none"])
        D += ["", "### Intended behavior", "", r["intended_behavior"]]
        if f.get("reachability"):
            D += ["", "### Reachability", "", f"{f['reachability']} / {f['exposure']}"]
        if r.get("execution"):
            ex = r["execution"]
            run = store.sandbox_run(ex["run_id"]) or {}
            D += ["", "### Local evidence (sandbox)", "", f"Run `{ex['run_id']}`: `{ex['command']}`", "",
                  f"Agent's observed result: {ex['observed_result']}", "",
                  f"Harness-recorded result: exit {run.get('exit_code')}, timed out {bool(run.get('timed_out'))}", "",
                  "```text", (run.get("stdout") or "")[-1500:].rstrip() + ("\n" + run["stderr"][-800:].rstrip() if run.get("stderr") else ""), "```"]
        poc = f.get("poc")
        D += ["", f"### Proof-of-concept test — {_poc_line(poc)}", "", f"`{r['poc_test']['file_name']}` — {r['poc_test']['expectation']}"]
        if r["poc_test"].get("command"):
            D += ["", f"Command: `{r['poc_test']['command']}`"]
        for label in ("original", "patched"):
            if poc and poc.get(label):
                pr = poc[label]
                D += ["", f"{label.capitalize()} copy (`{pr['run_id']}`): exit {pr.get('exit_code')}"
                      + (f", error: {pr['error']}" if pr.get("error") else "")]
                tail = ((pr.get("stdout") or "") + (pr.get("stderr") or ""))[-800:].rstrip()
                if tail:
                    D += ["", "```text", tail, "```"]
        D += ["", f"```{r['poc_test']['language']}", r["poc_test"]["code"], "```", "", "### Remediation", "", r["remediation"]["strategy"]]
        if r["remediation"].get("patch"):
            D += ["", "```diff", r["remediation"]["patch"].rstrip("\n"), "```"]
        D.append("")
    write("FINDINGS-DETAIL.md", "\n".join(D))

    # NEEDS-VALIDATION.md
    N = ["# Needs validation", "", "These are source-grounded leads with an unresolved, decisive fact. They have no severity.", ""]
    for f in needs:
        r = f["record"]
        N += [f"## {r['title']}", "", f"`{f['target']}` · `{r['fingerprint']}`", "", r["description"], "",
              f"**Claimed root cause:** {r['claimed_root_cause']}", "", "**Trace:**"]
        N += [f"- {s['kind']} `{s['file']}:{s['line']}`: {s['description']}" for s in r["trace"]]
        N += ["", "**Blockers:**"] + [f"- {b}" for b in r["blockers"]]
        for k in ("local", "deployment"):
            if r["validation_plan"].get(k):
                N += ["", f"**{k.capitalize()} plan:** {r['validation_plan'][k]}"]
        N.append("")
    write("NEEDS-VALIDATION.md", "\n".join(N))

    # FIXES.md
    if cfg.get("fix"):
        X = ["# Fixes", "", "Every fix needs review by a person. vharness never writes to the target, never runs git, and never merges.", ""]
        for fx in fixes:
            X += [f"## {fx['fingerprint']} — {fx['status']}", "", f"`{fx['target']}` · {fx['reason']}", ""]
            if fx["patch_file"]:
                X += [f"Patch: `{fx['patch_file']}` (apply on a review branch with `git am`)", ""]
            if fx["test"]:
                X += [f"Regression test: `{fx['test']['file_name']}`, command `{fx['test']['command']}`",
                      f"Suite command: `{fx['suite_command'] or '(none)'}`", ""]
            if fx["notes"]:
                X += [f"Style notes: {fx['notes'].get('style') or '-'}", "", f"Risk notes: {fx['notes'].get('risk') or '-'}", ""]
            for a in fx["attempts"] or []:
                X += [f"### Attempt {a['attempt']} ({a.get('agent')})", ""]
                if a.get("error"):
                    X += [f"- {a['error']}"]
                for e in a.get("errors", []):
                    X += [f"- mechanical: {e}"]
                for step, st in (a.get("gate") or {}).items():
                    X += [f"- {step} (`{st['run_id']}`): {st.get('error') or 'exit ' + str(st.get('exit_code'))}"
                          + (", timed out" if st.get("timed_out") else "")]
                    tail = ((st.get("stdout") or "") + (st.get("stderr") or ""))[-600:].rstrip()
                    if tail:
                        X += ["", "```text", tail, "```", ""]
                X.append("")
            if fx["patch"]:
                X += ["### Patch", "", "```diff", fx["patch"].rstrip("\n"), "```", ""]
        write("FIXES.md", "\n".join(X) + "\n")

    # WISHLIST.md
    W = ["# Wishlist", "", "Resources that agents asked for. Supplying one lets the affected work run again.", ""]
    W += [f"- **{w['need']}** ({w['target']}; asked {w['count']}x by {', '.join(sorted(w['agents']))}): {w['reason']} — unblocks: {w['unblocks']}"
          for w in wl] or ["None."]
    write("WISHLIST.md", "\n".join(W) + "\n")
    return paths
