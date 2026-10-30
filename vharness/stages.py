"""Stage handlers (SPEC 7). Each handler takes the harness `h` and one task row.

Handlers return the final task status ("done", "skipped", "split", "failed").
All bookkeeping is plain code; agents only return JSON (P-05).
"""

import os
import re
from collections import Counter, defaultdict

from . import fixer, prompts, records, schemas
from .ids import QUICK_SUBSYSTEM, coverage_id, valid_fingerprint
from .sandbox import RunSpec, poc_result, poc_script

TRUST_RANK = {"unauthenticated": 0, "local": 1, "build_time": 1, "authenticated": 2, "privileged": 3}
VALUE_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}
ORIGIN_RANK = {"prior": 0, "trace": 0, "feedback": 1, "sibling": 1, "gapfill": 2, "recon": 3}
CHAINED = "ATTACK-CLASSES.md#Chained vulnerabilities and trust boundaries"
STOPWORDS = set("""the and that this with from into when where which while there their they them then than
does have been being were will would could should about after before other these those only also must
because without within between under over input output value values function method request response
user users data file files code path paths check checks missing allows allow""".split())


# =========================================================================== recon

async def recon(h, task):
    target, focus = task["target"], task["payload"]["focus"]
    if h.store.doc(h.run_id, target, f"recon:{focus}"):
        return "done"
    if not h.budget.can_spend(target):
        h.incomplete(f"budget_cannot_fund_recon:{target}")
        return "skipped"
    system, prompt = prompts.recon_prompt(focus, target, h.cfg.scope, h.knowledge, h.cfg.max_custom_classes)
    result, agent = await h.invoke(task, "recon", f"recon:{focus}", system, prompt)
    if not result.ok:
        if task["payload"].get("attempt", 0) == 0:
            h.store.add_task(h.run_id, target, "recon", {"focus": focus, "attempt": 1})
            return "failed"
        h.store.add_note(h.run_id, target, "error", f"recon {focus} failed twice: {result.error}")
        h.store.put_doc(h.run_id, target, f"recon:{focus}", {"__failed__": result.error})
        return "failed"
    h.record_wishlist(task, target, agent, result.output.get("wishlist", []))
    h.store.put_doc(h.run_id, target, f"recon:{focus}", result.output)
    return "done"


def recon_complete(h, target):
    docs = {f: h.store.doc(h.run_id, target, f"recon:{f}", parse=True) for f in ("product", "authority", "surfaces")}
    return docs if all(d is not None for d in docs.values()) else None


def _ok(doc):
    return doc if doc and "__failed__" not in doc else {}


def build_architecture(target, product, authority, surfaces, word_cap=1000):
    """SPEC 7.1.2 step 4: plain-code synthesis of the architecture document (~1000 words)."""
    lines = [f"# Architecture: {target}", ""]
    if product:
        lines += [
            f"**Product:** {product.get('product_type', '')}",
            f"**Users/operators:** {product.get('users_and_operators', '')}",
            f"**Stack:** {', '.join(product.get('stack', []))}",
            f"**Protected resources:** {', '.join(product.get('protected_resources', []))}",
        ]
        if product.get("comparable_software"):
            lines.append(f"**Comparable baseline:** {product['comparable_software']}")
        lines += ["", "## Subsystems"] + [f"- `{s['path']}` {s['name']}: {s['description']}" for s in product.get("subsystems", [])]
    if authority:
        lines += ["", "## Principals"] + [f"- {p['name']} ({p['trust']}): {p['allowed_actions']}" for p in authority.get("principals", [])]
        lines += ["", "## Trust boundaries and controls"] + [
            f"- {b['name']}: {b['control']} (`{b['control_ref']}`{'' if b['source_visible'] else ', NOT source-visible'})"
            for b in authority.get("boundaries", [])
        ]
        if authority.get("unobserved_controls"):
            lines += ["", "## Controls the repository cannot show"] + [f"- {c}" for c in authority["unobserved_controls"]]
    if surfaces:
        lines += ["", "## Entry surfaces"] + [
            f"- {s['name']} [{s['trust_level']}, value {s['resource_value']}] `{s['entry_ref']}` -> sinks: {', '.join(s.get('sinks', [])[:4])}"
            for s in surfaces.get("surfaces", [])
        ]
        if surfaces.get("custom_attack_classes"):
            lines += ["", "## Custom attack classes"] + [f"- {c['name']}: {c['reason']}" for c in surfaces["custom_attack_classes"]]
        if surfaces.get("companions_selected"):
            lines += ["", "## Companion files"] + [f"- {c['file']}: {c['reason']}" for c in surfaces["companions_selected"]]
    out, words = [], 0
    for line in lines:
        n = len(line.split())
        if words + n > word_cap:
            out.append("- ... (truncated to the architecture word cap)")
            break
        out.append(line)
        words += n
    return "\n".join(out) + "\n"


def plan(h, target):
    """SPEC 7.2: plain-code planning of coverage units from recon results."""
    docs = recon_complete(h, target)
    product, authority, surfaces = (_ok(docs[k]) for k in ("product", "authority", "surfaces"))
    arch = build_architecture(target, product, authority, surfaces)
    h.store.put_doc(h.run_id, target, "architecture", arch)
    tdir = os.path.join(h.out, "targets", target)
    os.makedirs(tdir, exist_ok=True)
    with open(os.path.join(tdir, "architecture.md"), "w", encoding="utf-8") as fh:
        fh.write(arch)
    if not surfaces:
        h.incomplete(f"recon_failed:{target}")
        h.store.set_stage(h.run_id, target, "plan", "failed")
        return
    customs = {}
    for c in surfaces.get("custom_attack_classes", [])[: h.cfg.max_custom_classes]:
        customs[f"CUSTOM#{c['name'].strip()}"] = f"**{c['name'].strip()}** (custom class from recon)\n{c['method']}"
    h.store.put_doc(h.run_id, target, "custom_classes", customs)
    excluded = [{"block": c["file"], "reason": c["reason"]} for c in surfaces.get("companions_excluded", [])]

    created = 0
    for s in surfaces.get("surfaces", []):
        in_scope = _in_scope(h.cfg.scope, [s["entry_ref"].split("#")[0]] + s.get("starting_paths", []))
        subsystem = QUICK_SUBSYSTEM if h.cfg.prof.single_subsystem else s["subsystem"]
        base = TRUST_RANK.get(s["trust_level"], 2) * 10 + VALUE_RANK.get(s["resource_value"], 2)
        classes = [c.strip() for c in s["attack_classes"]]
        for bi, b in enumerate(s["boundaries"]):
            for ci, cls in enumerate(classes):
                if not (h.knowledge.has(cls) or cls in customs):
                    h.store.add_note(h.run_id, target, "plan", f"unknown attack class {cls!r} on {s['name']} ignored")
                    continue
                unit = new_unit(
                    surface=s["name"], boundary=b["name"], subsystem=subsystem, attack_class=cls,
                    refs={"surface": s["entry_ref"], "boundary": b["control_ref"], "subsystem": subsystem, "attack_class": cls},
                    starting_paths=s.get("starting_paths", []), origin="recon", priority=base * 10 + ORIGIN_RANK["recon"],
                    excluded=excluded,
                )
                if not in_scope:
                    unit.update(status="out_of_scope", unresolved=["outside --scope"])
                elif bi >= h.cfg.max_boundaries_per_surface or ci >= h.cfg.max_classes_per_surface:
                    unit.update(status="deferred", unresolved=["plan_cap"])  # gapfill can promote it later
                if h.add_unit(target, unit):
                    created += 1
    h.store.add_note(h.run_id, target, "plan", f"planned {created} coverage units")
    h.store.set_stage(h.run_id, target, "plan", "done")
    start_wave(h, target, 1)


def _in_scope(scope, paths):
    if not scope:
        return True
    norm = [p.strip("/").rstrip("/") + "/" for p in scope]
    return any((p.strip("/") + "/").startswith(s) or p.strip("/") == s.rstrip("/") for p in paths for s in norm)


def new_unit(surface, boundary, subsystem, attack_class, refs, starting_paths, origin, priority,
             excluded=(), context=None, depth=0, parent=None):
    return {
        "coverage_id": coverage_id(refs),
        "canonical_refs": refs,
        "surface": surface, "boundary": boundary, "subsystem": subsystem, "attack_class": attack_class,
        "starting_paths": [p for p in starting_paths if records.safe_relpath(p)][:12],
        "excluded_blocks": list(excluded),
        "origin": origin, "parent": parent, "context": context, "depth": depth,
        "priority": priority, "wave": 1, "status": "planned", "agent_id": None,
        "reviewed_paths": [], "checks": [], "fingerprints": [], "unresolved": [],
        "attempts": [], "feedback": None, "feedback_count": 0, "decisions": {},
    }


def start_wave(h, target, wave):
    """Queue hunter tasks for the planned units of one wave (SPEC 7.3.2 step 1, 10.2)."""
    planned = [u for u in h.store.units(h.run_id, target, "planned")]
    if not planned:
        return 0
    groups = defaultdict(list)
    for u in sorted(planned, key=lambda u: (u["priority"], u["coverage_id"])):
        groups[(u["subsystem"], u["boundary"])].append(u)
    size = h.cfg.prof.units_per_hunter
    batches = []
    for key in sorted(groups, key=lambda k: (groups[k][0]["priority"], k)):
        g = groups[key]
        batches += [g[i:i + size] for i in range(0, len(g), size)]
    batches.sort(key=lambda b: (b[0]["priority"], b[0]["coverage_id"]))
    for batch in batches:
        for u in batch:
            u["wave"] = wave
            h.store.put_unit(h.run_id, target, u)
        h.store.add_task(h.run_id, target, "hunt", {"units": [u["coverage_id"] for u in batch], "wave": wave, "attempt": 0},
                         priority=batch[0]["priority"])
    h.store.set_stage(h.run_id, target, f"wave:{wave}", "running")
    h.log(f"[{target}] wave {wave}: {len(planned)} units in {len(batches)} hunter tasks")
    return len(batches)


# =========================================================================== hunt

def _blocks_for_units(h, target, units, include_companion_sections=True):
    customs = h.store.doc(h.run_id, target, "custom_classes", parse=True) or {}
    seen, blocks = set(), []
    for u in units:
        cls = u["attack_class"]
        pairs = [(cls, customs[cls])] if cls in customs else h.knowledge.blocks_for_class(cls, include_companion_sections)
        for ref, text in pairs:
            if ref not in seen:
                seen.add(ref)
                blocks.append((ref, text))
    return blocks


def set_units(h, target, units, **fields):
    for u in units:
        u.update(fields)
        h.store.put_unit(h.run_id, target, u)


def defer(h, target, units, reason):
    set_units(h, target, units, status="deferred", agent_id=None, reviewed_paths=[], checks=[], fingerprints=[], unresolved=[reason])


async def hunt(h, task):
    target, p = task["target"], task["payload"]
    root = h.store.target_root(h.run_id, target)
    units = [u for u in (h.store.unit(h.run_id, target, cid) for cid in p["units"]) if u and u["status"] in ("planned", "in_progress")]
    if not units:
        return "done"
    if not h.budget.hunt_allowed(target, task["task_id"]):
        defer(h, target, units, "budget" if not h.budget.usd_exhausted() else "usd_budget")
        h.incomplete("hunt_budget_exhausted")
        return "skipped"
    try:
        return await _hunt(h, task, target, p, root, units)
    finally:
        h.budget.hunt_done(target, task["task_id"])


async def _hunt(h, task, target, p, root, units):

    arch = h.store.doc(h.run_id, target, "architecture") or ""
    blocks = _blocks_for_units(h, target, units, include_companion_sections=not p.get("no_companion"))
    excluded = [e for u in units for e in u.get("excluded_blocks", [])]
    exclusions = [f"{r['fingerprint']}: {r['data']['title']}" for r in h.store.records(h.run_id, target, ["confirmed"])]
    exclusions += h.prior_exclusions.get(target, [])
    notes = []
    for cls in sorted({u["attack_class"] for u in units}):
        notes += [n["text"] for n in h.store.notes(h.run_id, target, "rejection", cls, limit=h.cfg.rejection_notes_per_class)]
    system, prompt = prompts.hunter_prompt(target, arch, units, blocks, excluded, exclusions, notes, sandbox=h.sandbox is not None)

    model = h.cfg.model_for("hunter")
    if not h.fits(system, prompt, model, target):  # SPEC 9.3
        if len(units) > 1:
            half = len(units) // 2
            for part in (units[:half], units[half:]):
                h.store.add_task(h.run_id, target, "hunt", dict(p, units=[u["coverage_id"] for u in part]), priority=part[0]["priority"])
            return "split"
        if not p.get("no_companion"):
            h.store.add_task(h.run_id, target, "hunt", dict(p, no_companion=True), priority=units[0]["priority"])
            return "split"
        set_units(h, target, units, status="blocked", unresolved=["context_budget"])
        return "done"

    agent = h.new_agent_id("hunter", target)
    set_units(h, target, units, status="in_progress", agent_id=agent, reviewed_paths=[], checks=[], fingerprints=[], unresolved=[])
    result, agent = await h.invoke(task, "hunter", "hunter", system, prompt, agent_id=agent, sandbox=True)
    if not result.ok:
        _hunt_failed(h, target, units, p, result.error)
        return "failed"
    out = result.output
    h.record_wishlist(task, target, agent, out.get("wishlist", []))
    known = [_tokens(n["text"]) for n in h.store.notes(h.run_id, target, "hardening")]
    for note in out.get("hardening", []):
        tok = _tokens(note)
        if any(len(tok & k) / max(len(tok | k), 1) >= 0.5 for k in known):
            continue  # the same note from another hunter
        known.append(tok)
        h.store.add_note(h.run_id, target, "hardening", note, coverage_id=units[0]["coverage_id"])

    # --- candidates: mechanical check, then dedup (SPEC 6.3) ---
    by_unit = {u["coverage_id"]: u for u in units}
    depth = max(u.get("depth", 0) for u in units)
    admitted = set()
    for cand in out.get("candidates", []):
        errors = records.check_candidate(cand, root, h.sandbox_lookup(target))
        if errors:
            reject_mechanical(h, target, cand, errors)
            continue
        linked = [cid for cid, ur in ((x["coverage_id"], x) for x in out.get("units", []))
                  if cand["fingerprint"] in ur.get("candidate_fingerprints", []) and cid in by_unit]
        admit_candidate(h, target, cand, agent, linked or [units[0]["coverage_id"]], depth=depth)
        admitted.add(cand["fingerprint"])

    # --- unit results (R-HUNT-01, state table 8.3, shallow detection 7.8.2) ---
    seen = Counter(ur["coverage_id"] for ur in out.get("units", []))
    retry = []
    for ur in out.get("units", []):
        cid = ur["coverage_id"]
        if cid not in by_unit or seen[cid] != 1:
            continue
        unit = by_unit.pop(cid)
        checks = [dict(c, agent_id=agent, method="source", artifact=None) for c in ur.get("checks", [])
                  if c.get("reviewed_paths") and all(records.safe_relpath(x) for x in c["reviewed_paths"])]
        paths = sorted({x for c in checks for x in c["reviewed_paths"]})
        fps = [f for f in ur.get("candidate_fingerprints", []) if f in admitted]
        disp = ur["disposition"]
        if disp == "candidate" and not fps:
            disp = "covered"
        if not checks or (disp == "blocked" and not ur.get("unresolved")):
            retry.append(unit)
            continue
        if disp == "covered" and _shallow(h, len(checks), result.turns):
            requeue_shallow(h, target, unit, agent, paths, checks)
            continue
        unit.update(status=disp, reviewed_paths=paths, checks=checks,
                    fingerprints=fps if disp == "candidate" else [],
                    unresolved=list(ur.get("unresolved", [])) if disp != "covered" else [])
        h.store.put_unit(h.run_id, target, unit)
    retry += list(by_unit.values())  # assigned but missing or duplicated
    if retry:
        _hunt_failed(h, target, retry, p, "unit missing, duplicated or without evidence in hunter result")

    # --- sibling units (R-HUNT-06/07) ---
    if all(u.get("origin") != "sibling" for u in units):
        for spec in out.get("uncovered", [])[: h.cfg.max_siblings_per_result]:
            add_spec_unit(h, target, spec, origin="sibling", wave=p["wave"], parent=units[0]["coverage_id"], queue=True)
    for spec in out.get("uncovered", [])[h.cfg.max_siblings_per_result:]:
        h.store.add_note(h.run_id, target, "uncovered", f"{spec['surface']} / {spec['boundary']} / {spec['attack_class']}: {spec['reason']}")
    return "done"


def _tokens(text):
    return {w for w in re.findall(r"[a-z0-9_./]{3,}", (text or "").lower()) if w not in STOPWORDS}


def _hunt_failed(h, target, units, payload, error):
    """R-HUNT-02: back to planned for a new owner once; then blocked."""
    if payload.get("attempt", 0) == 0:
        set_units(h, target, units, status="planned", agent_id=None, reviewed_paths=[], checks=[], fingerprints=[], unresolved=[])
        h.store.add_task(h.run_id, target, "hunt", dict(payload, units=[u["coverage_id"] for u in units], attempt=1),
                         priority=units[0]["priority"])
    else:
        set_units(h, target, units, status="blocked", unresolved=[f"agent_failure: {(error or '')[:200]}"])


def _shallow(h, n_checks, turns):
    return h.cfg.prof.shallow_requeue and n_checks < h.cfg.shallow_min_checks and turns < h.cfg.shallow_min_turns


def archive(unit, reason):
    unit["attempts"].append({k: unit.get(k) for k in ("wave", "status", "agent_id", "reviewed_paths", "checks", "fingerprints", "unresolved")}
                            | {"reassignment_reason": reason})


def requeue_shallow(h, target, unit, agent, paths, checks):
    """SPEC 7.8.2: archive the shallow attempt and requeue once with a feedback note."""
    unit.update(status="covered", agent_id=agent, reviewed_paths=paths, checks=checks, fingerprints=[], unresolved=[])
    if unit.get("feedback_count", 0) >= 1:
        unit.update(status="blocked", unresolved=["shallow"])
        h.store.put_unit(h.run_id, target, unit)
        return
    archive(unit, "shallow result")
    note = (f"The previous hunter finished quickly with {len(checks)} check(s) and no candidate. A quick empty "
            "result usually means the work was not done. Read the starting paths fully, trace every input to its sink, "
            "and record a check for each invariant you settle.")
    unit.update(status="planned", agent_id=None, reviewed_paths=[], checks=[], fingerprints=[], unresolved=[],
                feedback=note, feedback_count=unit.get("feedback_count", 0) + 1)
    h.store.put_unit(h.run_id, target, unit)
    h.store.add_note(h.run_id, target, "feedback", note, coverage_id=unit["coverage_id"])
    h.store.add_task(h.run_id, target, "hunt", {"units": [unit["coverage_id"]], "wave": unit["wave"], "attempt": 0}, priority=unit["priority"])


def add_spec_unit(h, target, spec, origin, wave, parent=None, queue=False, context=None, depth=0, status="planned", reason=None):
    cls = spec["attack_class"].strip()
    customs = h.store.doc(h.run_id, target, "custom_classes", parse=True) or {}
    if not (h.knowledge.has(cls) or cls in customs):
        cls = "ATTACK-CLASSES.md#Wildcard"
    subsystem = QUICK_SUBSYSTEM if h.cfg.prof.single_subsystem else spec["subsystem"]
    first = (spec.get("starting_paths") or ["?"])[0]
    refs = {"surface": f"{first}#{spec['surface']}", "boundary": spec["boundary"], "subsystem": subsystem, "attack_class": cls}
    unit = new_unit(spec["surface"], spec["boundary"], subsystem, cls, refs, spec.get("starting_paths", []), origin,
                    priority=ORIGIN_RANK[origin], context=context or spec.get("reason"), depth=depth, parent=parent)
    unit["wave"] = wave
    if not _in_scope(h.cfg.scope, unit["starting_paths"] or [first]):
        status, reason = "out_of_scope", "outside --scope"
    if status != "planned":
        unit.update(status=status, unresolved=[reason])
    if not h.add_unit(target, unit):
        return None
    if queue and status == "planned":
        h.store.add_task(h.run_id, target, "hunt", {"units": [unit["coverage_id"]], "wave": wave, "attempt": 0}, priority=unit["priority"])
    return unit


# =========================================================================== candidates & dedup

def reject_mechanical(h, target, cand, errors):
    reason = "mechanical: " + "; ".join(errors[:5])
    rec = records.candidate_to_rejected(cand, reason) if isinstance(cand, dict) else None
    if rec and valid_fingerprint(rec["fingerprint"]) and not h.store.record(h.run_id, target, rec["fingerprint"]):
        h.store.put_record(h.run_id, target, rec, validator="mechanical")
        h.store.update_record(h.run_id, target, rec["fingerprint"], final=1)
    else:
        h.store.add_note(h.run_id, target, "malformed_candidate", reason)


def _features(cand):
    trace = cand.get("trace", [])
    sink = trace[-1] if trace else {}
    tokens = lambda s: {w for w in re.findall(r"[a-z_][a-z0-9_]{4,}", (s or "").lower()) if w not in STOPWORDS}
    return {
        "files": {s["file"] for s in trace},
        "scopes": {(s["file"], s["scope"]) for s in trace},
        "sink": (sink.get("file"), sink.get("scope")),
        "boundary": tokens(cand.get("threat_model", {}).get("boundary")),
        "root": tokens(cand.get("root_cause") or cand.get("claimed_root_cause") or cand.get("description")),
    }


def shortlist(h, target, cand, exclude_fp):
    """SPEC 7.5.3: plain-code index lookup instead of an O(N^2) model comparison."""
    me = _features(cand)
    pool = [c for c in h.store.candidates(h.run_id, target, ["primary", "validated"]) if c["fingerprint"] != exclude_fp]
    doc_freq = Counter(t for c in pool for t in _features(c["data"])["root"])
    scored = []
    for c in pool:
        f = _features(c["data"])
        jac = lambda a, b: len(a & b) / len(a | b) if a | b else 0.0
        rare = {t for t in me["root"] & f["root"] if doc_freq[t] <= 2}
        score = (3 if me["sink"] == f["sink"] else 0) + 2 * len(me["scopes"] & f["scopes"]) + 0.5 * len(me["files"] & f["files"]) \
            + 2 * jac(me["boundary"], f["boundary"]) + 1.0 * len(rare)
        if score >= 3:
            scored.append((score, c["fingerprint"]))
    scored.sort(key=lambda x: (-x[0], x[1]))
    return [fp for _, fp in scored[: h.cfg.dedup_shortlist_max]]


def admit_candidate(h, target, cand, hunter, unit_ids, depth=0):
    fp = cand["fingerprint"]
    cand = dict(cand, __depth__=depth)
    existing = h.store.candidate(h.run_id, target, fp)
    if existing:  # same fingerprint: keep the longest trace (SPEC 7.5.2 step 1)
        data = cand if (existing["status"] in ("pending", "dedup_pending") and len(cand["trace"]) > len(existing["data"]["trace"])) else existing["data"]
        h.store.put_candidate(h.run_id, target, fp, data, existing["hunter"], existing["units"] + unit_ids, existing["status"], existing["primary_fp"])
        h.store.add_note(h.run_id, target, "duplicate", f"{fp} re-reported by {hunter}")
        return
    if h.store.record(h.run_id, target, fp):
        h.store.add_note(h.run_id, target, "duplicate", f"{fp} already has a record; re-report by {hunter} ignored")
        return
    h.store.put_candidate(h.run_id, target, fp, cand, hunter, unit_ids, "pending")
    sl = shortlist(h, target, cand, fp)
    if not sl:
        h.store.set_candidate_status(h.run_id, target, fp, "primary")
        h.store.add_task(h.run_id, target, "validate", {"fingerprint": fp, "attempt": 0})
    else:
        h.store.set_candidate_status(h.run_id, target, fp, "dedup_pending")
        h.store.add_task(h.run_id, target, "dedup", {"fingerprint": fp, "shortlist": sl})


def _brief(c):
    d = c["data"]
    return {"fingerprint": c["fingerprint"], "title": d.get("title"), "threat_model": d.get("threat_model"),
            "root_cause": d.get("root_cause") or d.get("claimed_root_cause"), "trace": d.get("trace")}


async def dedup(h, task):
    target, fp, sl = task["target"], task["payload"]["fingerprint"], task["payload"]["shortlist"]
    cand = h.store.candidate(h.run_id, target, fp)
    if not cand or cand["status"] != "dedup_pending":
        return "done"
    others = [c for c in (h.store.candidate(h.run_id, target, f) for f in sl) if c]
    dup = None
    if others and h.budget.can_spend(target):
        system, prompt = prompts.dedup_prompt(target, _brief(cand), [_brief(c) for c in others])
        result, _ = await h.invoke(task, "dedup", "dedup", system, prompt)
        if result.ok and result.output.get("duplicate_of") in sl:
            dup = result.output["duplicate_of"]
    if dup:
        primary = h.store.candidate(h.run_id, target, dup)
        h.store.put_candidate(h.run_id, target, dup, primary["data"], primary["hunter"], primary["units"] + cand["units"],
                              primary["status"], primary["primary_fp"])
        h.store.set_candidate_status(h.run_id, target, fp, "duplicate", dup)
        h.store.add_note(h.run_id, target, "duplicate", f"{fp} is a duplicate of {dup}")
    else:
        h.store.set_candidate_status(h.run_id, target, fp, "primary")
        h.store.add_task(h.run_id, target, "validate", {"fingerprint": fp, "attempt": 0})
    return "done"


# =========================================================================== validate

async def validate(h, task):
    target, p = task["target"], task["payload"]
    fp = p["fingerprint"]
    root = h.store.target_root(h.run_id, target)
    cand = h.store.candidate(h.run_id, target, fp)
    if not cand or cand["status"] != "primary":
        return "done"
    data = {k: v for k, v in cand["data"].items() if not k.startswith("__")}
    lookup = h.sandbox_lookup(target)
    errors = records.check_candidate(data, root, lookup)  # R-VAL-07: mechanical first
    if errors:
        reject_mechanical(h, target, data, errors)
        h.store.set_candidate_status(h.run_id, target, fp, "validated", fp)
        return "done"
    if not h.budget.can_spend(target):
        h.store.set_candidate_status(h.run_id, target, fp, "unvalidated")
        h.incomplete("validation_budget_exhausted")
        return "skipped"

    units = [h.store.unit(h.run_id, target, cid) for cid in cand["units"]]
    units = [u for u in units if u]
    checks = [c for u in units for c in u.get("checks", [])][:20]
    vblocks, seen = [], set()
    for u in units:
        for ref, text in h.knowledge.validation_blocks(u["attack_class"]):
            if ref not in seen:
                seen.add(ref)
                vblocks.append((ref, text))
    prior = h.prior_records.get((target, fp))
    runs = None
    if h.sandbox is not None:
        cited = (data.get("execution") or {}).get("run_id")
        runs = [_run_brief(h.store.sandbox_run(cited))] if cited and lookup(cited) else []
    system, prompt = prompts.validator_prompt(target, data, checks, vblocks, prior, runs)
    if p.get("previous_error"):
        prompt += f"\n\nNOTE: a previous validator's record failed the harness's mechanical checks: {p['previous_error']}"
    result, agent = await h.invoke(task, "validator", "validator", system, prompt, exclude=[cand["hunter"]], sandbox=True)
    error = None if result.ok else result.error
    record = None
    if result.ok:
        record = records.drop_empty_forbidden(result.output["record"])
        if record["verdict"] != result.output["decision"]:
            error = "decision and record.verdict disagree"
        else:
            errs = records.check_record(record, root, lookup)
            if errs:
                error = "; ".join(errs[:5])
    if error:  # R-VAL-05
        if p.get("attempt", 0) == 0:
            h.store.add_task(h.run_id, target, "validate", {"fingerprint": fp, "attempt": 1, "previous_error": error[:500]})
        else:
            h.store.set_candidate_status(h.run_id, target, fp, "unvalidated")
            h.incomplete("validation_failed")
        return "failed"

    h.record_wishlist(task, target, agent, result.output.get("wishlist", []))
    new_fp = record["fingerprint"]
    if new_fp != fp and h.store.record(h.run_id, target, new_fp):
        h.store.set_candidate_status(h.run_id, target, fp, "duplicate", new_fp)
        h.store.add_note(h.run_id, target, "duplicate", f"validator mapped {fp} to existing record {new_fp}")
        return "done"
    h.store.put_record(h.run_id, target, record, validator=agent, depth=cand["data"].get("__depth__", 0))
    h.store.set_candidate_status(h.run_id, target, fp, "validated", new_fp)
    for u in units:
        u.setdefault("decisions", {})[new_fp] = record["verdict"]
        h.store.put_unit(h.run_id, target, u)
    if record["verdict"] == "rejected":
        for cls in {u["attack_class"] for u in units}:
            h.store.add_note(h.run_id, target, "rejection", f"{record['title']} -> rejected: {record['reason'][:300]}", attack_class=cls)
    if not h.cfg.prof.separate_verify:  # R-VER-02: quick merges validate and verify
        h.store.update_record(h.run_id, target, new_fp, final=1, verifiers=[agent])
    if record["verdict"] == "confirmed" and h.sandbox is not None:
        h.store.add_task(h.run_id, target, "poc", {"fingerprint": new_fp})
    elif record["verdict"] in ("confirmed", "needs_validation"):
        h.store.add_task(h.run_id, target, "trace", {"fingerprint": new_fp})
    elif h.cfg.prof.separate_verify:
        h.store.update_record(h.run_id, target, new_fp, final=1)
    return "done"


# =========================================================================== trace

def find_consumers(h, source_target, record, max_files=10, max_bytes=512_000):
    """Plain-code cross-target symbol index (SPEC 7.7): which other targets use the vulnerable symbols?"""
    symbols = set()
    for step in record.get("trace", []):
        for word in re.findall(r"[A-Za-z_][A-Za-z0-9_]{3,}", step.get("scope", "")):
            if word.lower() not in STOPWORDS:
                symbols.add(word)
    if not symbols:
        return {}
    names = {source_target, source_target.replace("-", "_")}
    found = {}
    for t in h.store.targets(h.run_id):
        if t["target"] == source_target:
            continue
        hits = []
        for dirpath, dirnames, filenames in os.walk(t["root"]):
            dirnames[:] = [d for d in dirnames if d not in (".git", "node_modules", "vendor", ".venv", "dist", "build")]
            for name in filenames:
                path = os.path.join(dirpath, name)
                try:
                    if os.path.islink(path) or os.path.getsize(path) > max_bytes:
                        continue
                    with open(path, encoding="utf-8", errors="ignore") as fh:
                        text = fh.read()
                except OSError:
                    continue
                if any(n in text for n in names) and any(re.search(rf"\b{re.escape(s)}\b", text) for s in symbols):
                    hits.append(os.path.relpath(path, t["root"]))
                if len(hits) >= max_files:
                    break
            if len(hits) >= max_files:
                break
        if hits:
            found[t["target"]] = sorted(hits)
    return found


async def trace(h, task):
    target, fp = task["target"], task["payload"]["fingerprint"]
    rec = h.store.record(h.run_id, target, fp)
    if not rec or rec["removed"]:
        return "done"
    reach, exposure, tdata = "unknown", None, None
    if h.budget.can_spend(target):
        system, prompt = prompts.tracer_prompt(target, rec["data"])
        result, _ = await h.invoke(task, "tracer", "tracer", system, prompt)
        if result.ok:
            tdata = result.output
            reach, exposure = tdata["reachability"], tdata["exposure"]
    else:
        h.incomplete("trace_budget_exhausted")
    h.store.update_record(h.run_id, target, fp, reachability=reach, exposure=exposure, trace_data=tdata,
                          priority=records.priority(rec["data"], reach, exposure))
    # Consumers and consumer hunts (R-TRACE-02/03).
    if rec["depth"] == 0 and rec["data"]["verdict"] == "confirmed":
        for other, paths in find_consumers(h, target, rec["data"]).items():
            h.store.put_consumer(h.run_id, fp, target, other, paths, "symbol index match")
            spec = {
                "surface": f"consumer of {target}:{fp}", "boundary": rec["data"]["threat_model"]["boundary"],
                "subsystem": os.path.dirname(paths[0]) or ".", "attack_class": CHAINED, "starting_paths": paths,
                "reason": f"Consumes code from {target} with confirmed defect {fp}",
            }
            ctx = (f"{target} has a confirmed defect {fp}: {rec['data']['root_cause']}. Decide whether this repository "
                   f"passes attacker-controlled input to the affected code and what it exposes.")
            wave = h.current_wave(other)
            queue = h.store.stage(h.run_id, other, "plan") == "done"
            add_spec_unit(h, other, spec, origin="trace", wave=wave, queue=queue, context=ctx, depth=1)
    return "done"


# =========================================================================== gapfill

def coverage_matrix(units):
    matrix = defaultdict(lambda: defaultdict(list))
    for u in units:
        matrix[u["subsystem"]][u["attack_class"]].append(u["status"])
    return {s: dict(c) for s, c in matrix.items()}


async def gapfill(h, task):
    target, wave = task["target"], task["payload"]["wave"]
    units = h.store.units(h.run_id, target)
    matrix = coverage_matrix(units)
    thin = [{"subsystem": s, "attack_class": c, "statuses": st} for s, cs in matrix.items() for c, st in cs.items()
            if not any(x in ("covered", "candidate") for x in st)]
    summary = {
        "statuses": dict(Counter(u["status"] for u in units)),
        "units": [{k: u[k] for k in ("coverage_id", "surface", "boundary", "subsystem", "attack_class", "status", "reviewed_paths")}
                  for u in units][:300],
        "candidates": [c["fingerprint"] for c in h.store.candidates(h.run_id, target)],
    }
    uncovered = [n["text"] for n in h.store.notes(h.run_id, target, "uncovered", limit=30)]
    h.store.set_stage(h.run_id, target, f"wave:{wave}", "done")
    if not h.budget.can_spend(target):
        h.incomplete("critic_budget_exhausted")
        return "skipped"
    arch = h.store.doc(h.run_id, target, "architecture") or ""
    system, prompt = prompts.critic_prompt(target, arch, summary, matrix, thin, uncovered, wave, h.cfg.prof.max_waves)
    result, _ = await h.invoke(task, "critic", "critic", system, prompt)
    if not result.ok:
        h.store.add_note(h.run_id, target, "error", f"critic for wave {wave} failed: {result.error}")
        return "failed"
    out = result.output
    last_wave = wave >= h.cfg.prof.max_waves
    stop_reason = "quick_profile_final_critic" if h.cfg.profile == "quick" else ("max_waves" if last_wave else None)
    new = 0
    for spec in out.get("missing_units", []):
        unit = add_spec_unit(h, target, spec, origin="gapfill", wave=wave + 1,
                             status="deferred" if stop_reason else "planned", reason=stop_reason)
        new += bool(unit and unit["status"] == "planned")
    for item in out.get("reassign", []):
        unit = h.store.unit(h.run_id, target, item["coverage_id"])
        if not unit or unit["status"] not in ("covered", "candidate", "blocked"):
            continue
        archive(unit, item["reason"])
        unit.update(wave=wave + 1, agent_id=None, reviewed_paths=[], checks=[], fingerprints=[], unresolved=[],
                    feedback=f"A coverage critic reopened this unit: {item['reason']}")
        unit.update(status="deferred", unresolved=[stop_reason]) if stop_reason else unit.update(status="planned")
        h.store.put_unit(h.run_id, target, unit)
        new += not stop_reason
    if not stop_reason:  # the cost-to-coverage lever: reopen units the plan caps held back
        capped = [u for u in units if u["status"] == "deferred" and u["unresolved"] == ["plan_cap"]]
        for u in capped[: max(4, h.cfg.prof.units_per_hunter * 4)]:
            u.update(status="planned", unresolved=[], wave=wave + 1)
            h.store.put_unit(h.run_id, target, u)
            new += 1
    if new and not stop_reason:
        if start_wave(h, target, wave + 1) == 0:
            h.store.set_stage(h.run_id, target, "gapfill", "done")
    else:
        h.store.set_stage(h.run_id, target, "gapfill", "done")
        h.log(f"[{target}] gapfill stopped after wave {wave} ({stop_reason or 'critic found no new work'})")
    return "done"


# =========================================================================== poc (SPEC 13.1.6)

def _run_brief(run):
    if not run:
        return None
    return {k: run[k] for k in ("sbx_id", "kind", "command", "exit_code", "signal", "timed_out", "duration_ms", "stdout", "stderr")}


async def poc(h, task):
    """Plain code: run the PoC test on an unchanged copy and on a patched copy, in the sandbox."""
    target, fp = task["target"], task["payload"]["fingerprint"]
    rec = h.store.record(h.run_id, target, fp)
    if not rec or rec["removed"] or rec["verdict"] != "confirmed":
        return "done"
    data = rec["data"]
    test = data.get("poc_test") or {}
    result = {"result": "no_command"}
    if test.get("command") and h.sandbox is not None:
        if not records.safe_relpath(test["file_name"]):
            result = {"result": "error", "reason": "poc_test.file_name is not repository-relative"}
        else:
            patch = (data.get("remediation") or {}).get("patch") or ""
            runs = {}
            for label, patched in (("original", False), ("patched", True)):
                if patched and not patch.strip():
                    continue
                files = [{"path": ".vhin/poc", "content": test["code"]}]
                if patched:
                    files.append({"path": ".vhin/fix.patch", "content": patch if patch.endswith("\n") else patch + "\n"})
                spec = RunSpec(command=poc_script(data, patched), files=files)
                sbx_id, st, error = await h.sandbox_exec(target, "harness", f"poc-{label}", spec,
                                                         os.path.join(h.out, "sandbox", "poc-artifacts"))
                runs[label] = {"run_id": sbx_id, "error": error} | ({} if not st else {
                    "exit_code": st["exit_code"], "signal": st["signal"], "timed_out": st["timed_out"],
                    "stdout": st["stdout"][-2000:], "stderr": st["stderr"][-2000:]})
            orig, pat = runs.get("original"), runs.get("patched")
            ok = lambda r: r if r and not r.get("error") else None
            result = {"result": poc_result(ok(orig), ok(pat), bool(patch.strip())), "command": test["command"], **runs}
    h.store.update_record(h.run_id, target, fp, poc=result)
    h.log(f"[{target}] poc       {fp}: {result['result']}")
    h.store.add_task(h.run_id, target, "trace", {"fingerprint": fp})
    return "done"


# =========================================================================== verify

async def verify(h, task):
    target, p = task["target"], task["payload"]
    fp = p["fingerprint"]
    root = h.store.target_root(h.run_id, target)
    rec = h.store.record(h.run_id, target, fp)
    if not rec or rec["removed"] or rec["final"]:
        return "done"
    if not h.budget.can_spend(target):
        h.store.update_record(h.run_id, target, fp, removed=1)
        h.incomplete("verification_budget_exhausted")
        return "skipped"
    cand = h.store.candidates(h.run_id, target)
    hunters = {c["hunter"] for c in cand if c["primary_fp"] == fp or c["fingerprint"] == fp}
    exclude = list(hunters | {rec["validator"]} | set(p.get("exclude", [])))  # R-VER-01
    round_ = p.get("round", 1)
    subject = p["replacement"] if round_ == 2 else rec["data"]
    note = None
    if round_ == 2:
        note = ("This is a proposed replacement for an earlier record; a different verifier proposed it because: "
                f"{p['reason']}. Verify the replacement independently.")
    cited = (subject.get("execution") or {}).get("run_id")
    runs = [_run_brief(h.store.sandbox_run(cited))] if cited and h.store.sandbox_run(cited) else None
    system, prompt = prompts.verifier_prompt(target, subject, note, poc=rec["poc"], runs=runs)
    result, agent = await h.invoke(task, "verifier", "verifier", system, prompt, exclude=exclude)
    error = None if result.ok else result.error
    out = result.output if result.ok else None
    if out and out["decision"] == "replace":
        new = records.drop_empty_forbidden(out["record"]) if out.get("record") else None
        if not new:
            error = "replace decision without a record"
        elif new["fingerprint"] != fp:
            error = "replacement changes the fingerprint"
        else:
            errs = records.check_record(new, root, h.sandbox_lookup(target))
            error = "; ".join(errs[:5]) if errs else None
    if error:
        if p.get("attempt", 0) == 0:
            h.store.add_task(h.run_id, target, "verify", dict(p, attempt=1))
        else:
            h.store.update_record(h.run_id, target, fp, removed=1)
            h.incomplete("verification_failed")
        return "failed"
    verifiers = rec["verifiers"] + [agent]
    if out["decision"] == "verified":
        data = subject
        h.store.update_record(h.run_id, target, fp, data=data, final=1, verifiers=verifiers,
                              priority=records.priority(data, rec["reachability"], rec["exposure"]))
        return "done"
    new = out["record"]
    if round_ == 2:  # second verifier does not agree (SPEC 7.9.2 step 6)
        h.store.update_record(h.run_id, target, fp, removed=1, verifiers=verifiers)
        h.incomplete("verification_disagreement")
        return "done"
    if records.is_material_change(rec["data"], new):
        h.store.update_record(h.run_id, target, fp, verifiers=verifiers)
        h.store.add_task(h.run_id, target, "verify", {"fingerprint": fp, "round": 2, "replacement": new,
                                                      "reason": out["reason"], "exclude": exclude + [agent], "attempt": 0})
        return "done"
    h.store.update_record(h.run_id, target, fp, data=new, final=1, verifiers=verifiers,
                          priority=records.priority(new, rec["reachability"], rec["exposure"]))
    return "done"


# =========================================================================== fix (SPEC 13.2)

async def fix(h, task):
    target, p = task["target"], task["payload"]
    fp, attempt = p["fingerprint"], p.get("attempt", 0)
    rec = h.store.record(h.run_id, target, fp)
    if not rec or rec["removed"] or not rec["final"] or rec["verdict"] != "confirmed":
        return "done"
    history = list(p.get("history", []))
    if h.sandbox is None:
        h.store.put_fix(h.run_id, target, fp, "skipped", "the sandbox is not in use", history)
        return "skipped"
    if not h.budget.can_spend(target):
        h.store.put_fix(h.run_id, target, fp, "skipped", "no agent budget left for the fixer", history)
        return "skipped"
    root = h.store.target_root(h.run_id, target)
    product = h.store.doc(h.run_id, target, "recon:product", parse=True) or {}
    system, prompt = prompts.fixer_prompt(target, h.store.doc(h.run_id, target, "architecture") or "", rec["data"], rec["poc"],
                                          product.get("build_and_test_commands", []), p.get("previous"), h.cfg.fix_max_lines)
    exclude = [a for a in history_agents(history)]
    result, agent = await h.invoke(task, "fixer", "fixer", system, prompt, exclude=exclude, sandbox=True)  # R-FIX-08: new agent
    entry = {"attempt": attempt + 1, "agent": agent}
    if not result.ok:
        entry["error"] = f"agent failed: {result.error}"
        return _fix_next(h, target, fp, attempt, history + [entry], entry["error"], None)
    out = result.output
    h.record_wishlist(task, target, agent, out.get("wishlist", []))
    errors, human = fixer.mechanical(out, root, h.cfg.fix_max_lines)
    if errors:
        entry["errors"] = errors
        return _fix_next(h, target, fp, attempt, history + [entry], "mechanical: " + "; ".join(errors), out)
    passed, reason, steps, baseline_failing = await fixer.run_gate(h, target, out)
    entry["gate"] = steps
    if not passed:
        return _fix_next(h, target, fp, attempt, history + [entry], reason, out, steps)
    if baseline_failing:
        human.append("the suite already fails on unchanged code, so a regression cannot be ruled out")
    status = "needs_human" if human else "accepted"
    reason = "; ".join(human) if human else ("gate passed: the test fails before and passes after the patch"
                                              + ("; the suite passes" if "suite_patched" in steps else "; no suite was run"))
    _write_fix(h, target, rec, status, reason, history + [entry], out, steps)
    return "done"


def history_agents(history):
    return [e["agent"] for e in history if e.get("agent")]


def _fix_next(h, target, fp, attempt, history, reason, out, steps=None):
    """Retry with a fresh agent and the gate output (R-FIX-07/08), or block."""
    if attempt + 1 < h.cfg.fix_attempts:
        previous = {"reason": reason, "patch": out and out["patch"], "test": out and out["test"],
                    "suite_command": out and out["suite_command"], "gate": steps}
        h.store.add_task(h.run_id, target, "fix", {"fingerprint": fp, "attempt": attempt + 1, "history": history,
                                                   "previous": previous}, priority=0)
        return "failed"
    rec = h.store.record(h.run_id, target, fp)
    if out:
        _write_fix(h, target, rec, "blocked", reason, history, out, steps or {})
    else:
        h.store.put_fix(h.run_id, target, fp, "blocked", reason, history)
    return "failed"


def _write_fix(h, target, rec, status, reason, history, out, steps):
    """Store the fix and write a `git am` patch file (R-FIX-10). Nothing is written to the target (R-FIX-11)."""
    d = os.path.join(h.out, "fixes")
    os.makedirs(d, exist_ok=True)
    name = fixer.patch_filename(len(h.store.fixes(h.run_id)) + 1, status, rec["fingerprint"])
    with open(os.path.join(d, name), "w", encoding="utf-8") as fh:
        fh.write(fixer.mbox(rec["data"], out["patch"], out["test"], out["suite_command"], status, reason, steps))
    h.store.put_fix(h.run_id, target, rec["fingerprint"], status, reason, history, out["patch"], out["test"],
                    out["suite_command"], {"style": out.get("style_notes"), "risk": out.get("risk_notes")}, f"fixes/{name}")
    h.log(f"[{target}] fix       {rec['fingerprint']}: {status} ({reason})")


HANDLERS = {"recon": recon, "hunt": hunt, "gapfill": gapfill, "dedup": dedup, "validate": validate, "poc": poc,
            "trace": trace, "verify": verify, "fix": fix}
