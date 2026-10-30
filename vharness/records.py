"""Mechanical checks (SPEC 8.5): plain-code checks that run before any model check."""

import os
import re

from . import schemas
from .ids import valid_fingerprint

SEVERITY_RANK = {name: i for i, name in enumerate(schemas.SEVERITY_LEVELS)}
DIFF_FILE_RE = re.compile(r"^(?:---|\+\+\+) (?:[ab]/)?(\S+)")
HUNK_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+\d+(?:,\d+)? @@")
_line_cache = {}


def safe_relpath(path):
    """R-REC-04: repository-relative, no traversal, no absolute paths."""
    if not isinstance(path, str) or not path or path.startswith(("/", "\\", "~")):
        return False
    if re.match(r"^[A-Za-z]:", path):
        return False
    parts = re.split(r"[\\/]", path)
    return ".." not in parts and "\x00" not in path


def line_count(root, rel):
    real_root = os.path.realpath(root)
    full = os.path.realpath(os.path.join(real_root, rel))
    if os.path.commonpath([full, real_root]) != real_root or not os.path.isfile(full):
        return None
    key = (full, os.path.getmtime(full))
    if key not in _line_cache:
        with open(full, "rb") as fh:
            _line_cache[key] = fh.read().count(b"\n") + 1
    return _line_cache[key]


def check_locations(record, root):
    """R-REC-04..06: every cited file exists and every line is inside the file."""
    errors = []
    items = [("trace", s) for s in record.get("trace", [])] + [("evidence", e) for e in record.get("evidence", [])]
    for label, item in items:
        f, line = item.get("file"), item.get("line")
        if not safe_relpath(f):
            errors.append(f"{label}: path {f!r} is not repository-relative")
            continue
        if root is None:
            continue
        count = line_count(root, f)
        if count is None:
            errors.append(f"{label}: file {f!r} does not exist in the target")
        elif not isinstance(line, int) or line < 1 or line > count:
            errors.append(f"{label}: line {line} is outside {f!r} (1..{count})")
    return errors


def check_trace_order(trace):
    """R-REC-02/03."""
    kinds = [s.get("kind") for s in trace]
    if len(kinds) > 1:
        if kinds[0] != "entrypoint" or kinds[-1] != "sink" or any(k != "propagation" for k in kinds[1:-1]):
            return [f"trace kinds must be entrypoint, propagation..., sink; got {kinds}"]
    return []


def check_patch(patch, root):
    """R-REC-09: a unified diff whose files exist in the target."""
    if not patch or not patch.strip():
        return []  # an empty patch is allowed when the strategy is not a code change
    errors, files, hunks = [], [], 0
    for line in patch.splitlines():
        m = DIFF_FILE_RE.match(line)
        if m and m.group(1) != "/dev/null":
            files.append(m.group(1))
        if HUNK_RE.match(line):
            hunks += 1
    if not files or hunks == 0:
        return ["remediation.patch is not a unified diff (needs ---/+++ headers and @@ hunks)"]
    for f in sorted(set(files)):
        if not safe_relpath(f):
            errors.append(f"patch path {f!r} is not repository-relative")
        elif root is not None and line_count(root, f) is None and "/dev/null" not in patch:
            errors.append(f"patch file {f!r} does not exist in the target")
    return errors


def check_severity(sev):
    """R-REC-08: overall severity must not exceed demonstrated impact."""
    try:
        if SEVERITY_RANK[sev["overall"]] > SEVERITY_RANK[sev["impact"]["level"]]:
            return [f"overall severity {sev['overall']} exceeds impact {sev['impact']['level']}"]
    except (KeyError, TypeError):
        return ["severity is incomplete"]
    return []


def check_verdict_fields(record, verdict):
    rules = schemas.VERDICT_FIELDS[verdict]
    errors = [f"{verdict} record is missing {f!r}" for f in rules["required"] if f not in record]
    errors += [f"{verdict} record must not contain {f!r}" for f in rules["forbidden"] if f in record]
    if verdict == "needs_validation":
        if not record.get("blockers"):
            errors.append("needs_validation record needs at least one blocker")
        plan = record.get("validation_plan") or {}
        if not any((plan.get(k) or "").strip() for k in ("local", "deployment")):
            errors.append("needs_validation record needs a local or deployment validation plan")
    return errors


def check_record(record, root, evidence_level="source"):
    """Full mechanical check of a final record. Returns a list of errors."""
    errors = schemas.validate(record, schemas.RECORD)
    if errors:
        return errors
    verdict = record["verdict"]
    if not valid_fingerprint(record["fingerprint"]):
        errors.append(f"fingerprint {record['fingerprint']!r} does not match the fingerprint pattern")
    if record.get("evidence_level") != evidence_level:
        errors.append(f"evidence_level must be {evidence_level!r} (R-REC-12)")
    errors += check_verdict_fields(record, verdict)
    errors += check_trace_order(record["trace"])
    errors += check_locations(record, root)
    if verdict == "confirmed":
        errors += check_severity(record.get("severity", {}))
        errors += check_patch(record.get("remediation", {}).get("patch", ""), root)
    return errors


def check_candidate(candidate, root):
    """Mechanical check of a hunter candidate before dedup and validation."""
    errors = schemas.validate(candidate, schemas.CANDIDATE)
    if errors:
        return errors
    if not valid_fingerprint(candidate["fingerprint"]):
        errors.append(f"fingerprint {candidate['fingerprint']!r} does not match the fingerprint pattern")
    verdict = candidate["proposed_verdict"]
    probe = dict(candidate)
    probe.pop("proposed_verdict")
    errors += [e for e in check_verdict_fields(probe, verdict) if "must not contain" not in e]
    errors += check_trace_order(candidate["trace"])
    errors += check_locations(candidate, root)
    if verdict == "confirmed":
        if "severity" in candidate:
            errors += check_severity(candidate["severity"])
        errors += check_patch(candidate.get("remediation", {}).get("patch", ""), root)
    return errors


def candidate_to_rejected(candidate, reason):
    """Build a rejected record from a candidate that failed a mechanical check, if possible."""
    rec = {
        "threat_model": candidate.get("threat_model"),
        "verdict": "rejected",
        "fingerprint": candidate.get("fingerprint"),
        "title": candidate.get("title"),
        "description": candidate.get("description"),
        "evidence_level": "source",
        "trace": candidate.get("trace"),
        "evidence": candidate.get("evidence"),
        "claimed_root_cause": candidate.get("root_cause") or candidate.get("claimed_root_cause") or candidate.get("description"),
        "reason": reason,
    }
    return rec if not schemas.validate(rec, schemas.RECORD) else None


def is_material_change(old, new):
    """SPEC 7.9.3: a replacement is material if it changes meaning or evidence."""
    order = {"rejected": 0, "needs_validation": 1, "confirmed": 2}
    if order[new["verdict"]] > order[old["verdict"]]:
        return True
    if (old.get("root_cause") or old.get("claimed_root_cause")) != (new.get("root_cause") or new.get("claimed_root_cause")):
        return True
    strip = lambda t: [(s["kind"], s["file"], s["scope"]) for s in t]  # line-only changes are not material
    if strip(old.get("trace", [])) != strip(new.get("trace", [])):
        return True
    if (old.get("severity") or {}).get("impact") != (new.get("severity") or {}).get("impact"):
        return True
    if (old.get("severity") or {}).get("overall") != (new.get("severity") or {}).get("overall"):
        return True
    return False


def priority(record, reachability, exposure):
    """SPEC 8.7."""
    if record.get("verdict") != "confirmed":
        return None
    if reachability == "unreachable" or exposure in ("latent", "wrong_component"):
        return "P4"
    sev = record["severity"]["overall"]
    if sev == "critical" and exposure == "exploitable_now":
        return "P0"
    if (sev == "high" and exposure == "exploitable_now") or (sev == "critical" and reachability == "conditional"):
        return "P1"
    if (sev == "medium" and exposure == "exploitable_now") or (sev == "high" and reachability in ("conditional", "unknown")):
        return "P2"
    return "P3"
