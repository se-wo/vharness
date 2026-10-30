"""A scripted stand-in for a model, used by the test suite (SPEC 12.1)."""

import json
import os
import re

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


def line_of(target, rel, needle):
    with open(os.path.join(FIXTURES, target, rel), encoding="utf-8") as fh:
        for i, line in enumerate(fh, 1):
            if needle in line:
                return i
    raise AssertionError(f"{needle!r} not in {rel}")


def section_json(prompt, heading):
    start = prompt.index(f"## {heading}\n") + len(heading) + 4
    return json.JSONDecoder().raw_decode(prompt[start:])[0]


def recon_output(focus):
    if focus == "product":
        return {
            "product_type": "multi-user notes HTTP service", "users_and_operators": "note owners; operator",
            "protected_resources": ["notes of each user", "export directory files"], "stack": ["python"],
            "subsystems": [{"name": "api", "path": "notesapp", "description": "HTTP handlers and storage"}],
            "build_and_test_commands": ["pytest"], "comparable_software": "",
        }
    if focus == "authority":
        return {
            "principals": [{"name": "user", "trust": "authenticated", "allowed_actions": "manage own notes"}],
            "boundaries": [{"name": "note ownership", "control": "require_owner", "control_ref": "notesapp/auth.py#require_owner", "source_visible": True},
                           {"name": "export directory confinement", "control": "none visible", "control_ref": "notesapp/notes.py#export_note", "source_visible": True}],
            "unobserved_controls": ["reverse proxy rules"],
        }
    return {
        "surfaces": [
            {"name": "GET /notes/<id>", "kind": "http", "entry_ref": "notesapp/app.py#GET /notes/<id>", "subsystem": "notesapp",
             "trust_level": "authenticated", "resource_value": "high",
             "boundaries": [{"name": "note ownership", "control_ref": "notesapp/auth.py#require_owner"}],
             "attack_classes": ["ATTACK-CLASSES.md#Access control"], "starting_paths": ["notesapp/notes.py", "notesapp/auth.py"],
             "sinks": ["storage.get"]},
            {"name": "GET /export", "kind": "http", "entry_ref": "notesapp/app.py#GET /export", "subsystem": "notesapp",
             "trust_level": "authenticated", "resource_value": "high",
             "boundaries": [{"name": "export directory confinement", "control_ref": "notesapp/notes.py#export_note"}],
             "attack_classes": ["ATTACK-CLASSES.md#Resource and file handling", "CUSTOM#Export filename abuse"],
             "starting_paths": ["notesapp/notes.py"], "sinks": ["open"]},
            {"name": "DELETE /notes/<id>", "kind": "http", "entry_ref": "notesapp/app.py#DELETE /notes/<id>", "subsystem": "notesapp",
             "trust_level": "authenticated", "resource_value": "high",
             "boundaries": [{"name": "note ownership", "control_ref": "notesapp/auth.py#require_owner"}],
             "attack_classes": ["ATTACK-CLASSES.md#Access control"], "starting_paths": ["notesapp/notes.py"], "sinks": ["storage.delete"]},
        ],
        "companions_selected": [],
        "companions_excluded": [{"file": "AI-AND-LLM.md", "reason": "no model in the product"}],
        "custom_attack_classes": [{"name": "Export filename abuse", "method": "Trace the name parameter to open().", "reason": "export feature"}],
    }


IDOR_POC = """import sys
sys.path.insert(0, ".")
from notesapp import notes
from notesapp.auth import AuthError


class Req:
    headers = {"Authorization": "Bearer change-me-b"}  # bob
    args = {}


try:
    status, body = notes.get_note(Req(), "1")  # alice's note
except AuthError:
    sys.exit(0)  # refused: the defect is fixed
print("bob read:", body)
sys.exit(1 if status == 200 and body["owner"] == "alice" else 0)
"""


def idor_patch():
    import difflib
    path = os.path.join(FIXTURES, "notesapp", "notesapp", "notes.py")
    old = open(path).read().splitlines(keepends=True)
    new, done = [], False
    for line in old:
        if not done and line.strip() == "return 200, note":
            new.append("    require_owner(user, note)\n")
            done = True
        new.append(line)
    return "".join(difflib.unified_diff(old, new, "a/notesapp/notes.py", "b/notesapp/notes.py"))


def idor_candidate():
    t = "notesapp"
    return {
        "threat_model": {"attacker": "authenticated user bob", "starting_capability": "valid bearer token",
                         "boundary": "note ownership", "assumption_broken": "get_note checks the owner",
                         "affected_resource": "alice's notes"},
        "proposed_verdict": "confirmed",
        "fingerprint": "idor:notesapp/notes.py:get_note",
        "title": "Any user can read any note (missing owner check in get_note)",
        "description": "get_note returns a note without calling require_owner.",
        "evidence_level": "source",
        "trace": [
            {"kind": "entrypoint", "file": "notesapp/app.py", "line": line_of(t, "notesapp/app.py", "def dispatch"), "scope": "dispatch", "description": "route /notes/<id>"},
            {"kind": "sink", "file": "notesapp/notes.py", "line": line_of(t, "notesapp/notes.py", "return 200, note"), "scope": "get_note", "description": "returns note"},
        ],
        "evidence": [{"file": "notesapp/notes.py", "line": line_of(t, "notesapp/notes.py", "require_owner(user, note)"), "description": "delete_note checks the owner; get_note does not"}],
        "root_cause": "get_note omits require_owner", "intended_behavior": "only the owner can read a note",
        "conditions": [{"kind": "authentication_level", "description": "any valid token"}],
        "severity": {"likelihood": {"level": "high", "rationale": "trivial"}, "impact": {"level": "high", "rationale": "cross-user read"}, "overall": "high"},
        "confidence": "high",
        "remediation": {"strategy": "call require_owner in get_note", "patch": idor_patch()},
        "poc_test": {"file_name": "tests/poc_idor.py", "language": "python", "code": IDOR_POC,
                     "expectation": "exits 1 while bob can read alice's note", "command": "python3 tests/poc_idor.py"},
    }


def traversal_candidate():
    t = "notesapp"
    c = idor_candidate()
    c.update({
        "threat_model": {"attacker": "authenticated user", "starting_capability": "valid token", "boundary": "export directory confinement",
                         "assumption_broken": "name stays inside EXPORT_DIR", "affected_resource": "server files"},
        "fingerprint": "path-traversal:notesapp/notes.py:export_note",
        "title": "Path traversal in export_note",
        "description": "name is joined to EXPORT_DIR without normalization.",
        "trace": [
            {"kind": "entrypoint", "file": "notesapp/app.py", "line": line_of(t, "notesapp/app.py", "def dispatch"), "scope": "dispatch", "description": "route /export"},
            {"kind": "sink", "file": "notesapp/notes.py", "line": line_of(t, "notesapp/notes.py", 'open(path, "rb")'), "scope": "export_note", "description": "opens joined path"},
        ],
        "evidence": [{"file": "notesapp/notes.py", "line": line_of(t, "notesapp/notes.py", "os.path.join(storage.EXPORT_DIR"), "description": "unvalidated join"}],
        "root_cause": "export_note joins an attacker-controlled name to EXPORT_DIR",
        "intended_behavior": "only files inside EXPORT_DIR are readable",
        "remediation": {"strategy": "reject names that resolve outside EXPORT_DIR", "patch": ""},
        "poc_test": {"file_name": "tests/test_export.py", "language": "python", "code": "# manual check",
                     "expectation": "reads a file outside EXPORT_DIR"},
    })
    return c


class FakeModel:
    """Responds like a cooperative model. Tests override behaviors per role."""

    def __init__(self, overrides=None):
        self.overrides = overrides or {}
        self.calls = []
        self.critic_calls = 0

    def __call__(self, req):
        self.calls.append(req)
        if req.role in self.overrides:
            out = self.overrides[req.role](req, self)
            if out is not None:
                return out
        return getattr(self, req.role)(req)

    def recon(self, req):
        for focus, marker in (("product", "Map the PRODUCT"), ("authority", "Map PRINCIPALS"), ("surfaces", "Map ENTRY SURFACES")):
            if marker in req.prompt:
                out = recon_output(focus)
                if "notesclient" in req.prompt.split("\n", 1)[0] and focus == "surfaces":
                    out["surfaces"] = [{
                        "name": "sync_export", "kind": "library", "entry_ref": "client/sync.py#sync_export", "subsystem": "client",
                        "trust_level": "authenticated", "resource_value": "medium",
                        "boundaries": [{"name": "server response trust", "control_ref": "client/sync.py#sync_export"}],
                        "attack_classes": ["ATTACK-CLASSES.md#Injection"], "starting_paths": ["client/sync.py"], "sinks": ["export_note"]}]
                    out["custom_attack_classes"] = []
                return out
        raise AssertionError("unknown recon focus")

    def hunter(self, req):
        units = section_json(req.prompt, "Assigned coverage units")
        result = {"units": [], "candidates": [], "hardening": ["tokens have no expiry"], "uncovered": [], "wishlist": []}
        for u in units:
            paths = u.get("starting_paths") or ["README.md"]
            check = {"invariant": f"{u['boundary']} holds", "reviewed_paths": paths, "result": "examined"}
            entry = {"coverage_id": u["coverage_id"], "disposition": "covered", "reviewed_paths": paths,
                     "checks": [check, dict(check, invariant="sibling paths agree")], "candidate_fingerprints": [], "unresolved": []}
            cand = None
            if u["surface"] == "GET /notes/<id>":
                cand = idor_candidate()
            elif u["surface"] == "GET /export" and u["attack_class"].startswith("ATTACK-CLASSES.md#Resource"):
                cand = traversal_candidate()
            if cand:
                entry.update(disposition="candidate", candidate_fingerprints=[cand["fingerprint"]])
                result["candidates"].append(cand)
            result["units"].append(entry)
        return result

    def critic(self, req):
        self.critic_calls += 1
        return {"missing_units": [], "reassign": [], "stop": True}

    def dedup(self, req):
        return {"duplicate_of": None, "reason": "different root causes"}

    def validator(self, req):
        cand = section_json(req.prompt, "Candidate (proposed by a different agent)")
        rec = {k: v for k, v in cand.items() if k != "proposed_verdict"}
        rec = {"threat_model": rec.pop("threat_model"), "verdict": cand["proposed_verdict"], **rec}
        return {"decision": rec["verdict"], "record": rec, "wishlist": []}

    def tracer(self, req):
        return {"reachability": "reachable", "exposure": "exploitable_now", "external_entrypoint": "HTTP",
                "call_path": [{"file": "notesapp/app.py", "line": 1, "description": "dispatch"}], "rationale": "public route"}

    def fixer(self, req):
        return fix_output(record_fingerprint(req.prompt))

    def verifier(self, req):
        rec = section_json(req.prompt, "Record")
        return {"decision": "verified", "fingerprint": rec["fingerprint"], "reason": "re-checked"}


# ---- fixer helpers (SPEC 13.2 tests)

def _diff(rel, transform):
    import difflib
    path = os.path.join(FIXTURES, "notesapp", rel)
    old = open(path).read().splitlines(keepends=True)
    new = transform(list(old))
    return "".join(difflib.unified_diff(old, new, f"a/{rel}", f"b/{rel}"))


def _insert_after(lines, needle, extra, before=False):
    out = []
    for line in lines:
        if before and line.strip() == needle:
            out += extra
        out.append(line)
        if not before and line.strip() == needle:
            out += extra
    return out


def idor_fix_patch():
    return _diff("notesapp/notes.py", lambda l: _insert_after(l, "return 200, note", ["    require_owner(user, note)\n"], before=True))


def traversal_fix_patch():
    def t(lines):
        out = []
        for line in lines:
            if line.strip() == "path = os.path.join(storage.EXPORT_DIR, name)":
                out += ["    base = os.path.realpath(storage.EXPORT_DIR)\n",
                        "    path = os.path.realpath(os.path.join(base, name))\n",
                        "    if os.path.commonpath([path, base]) != base:\n",
                        "        return 403, {\"error\": \"forbidden\"}\n"]
            else:
                out.append(line)
        return out
    return _diff("notesapp/notes.py", t)


TRAVERSAL_TEST = """import sys
sys.path.insert(0, ".")
from notesapp import notes


class Req:
    headers = {"Authorization": "Bearer change-me-b"}
    args = {"name": "/etc/hosts"}


try:
    status, body = notes.export_note(Req())
except OSError:
    sys.exit(0)
sys.exit(1 if status == 200 else 0)
"""

SUITE = ("python3 -c \"import sys; sys.path.insert(0, '.'); import tests.test_notes as t; "
         "t.test_list_only_own(); print('suite ok')\"")


def fix_output(fingerprint, patch=None):
    if fingerprint.startswith("idor"):
        return {"patch": patch or idor_fix_patch(),
                "test": {"file_name": "tests/test_regression_idor.py", "language": "python", "code": IDOR_POC,
                         "command": "python3 tests/test_regression_idor.py"},
                "suite_command": SUITE, "style_notes": "reuses require_owner like delete_note", "risk_notes": "none", "wishlist": []}
    return {"patch": patch or traversal_fix_patch(),
            "test": {"file_name": "tests/test_regression_export.py", "language": "python", "code": TRAVERSAL_TEST,
                     "command": "python3 tests/test_regression_export.py"},
            "suite_command": SUITE, "style_notes": "returns (status, body) like other handlers", "risk_notes": "none", "wishlist": []}


def record_fingerprint(prompt):
    return section_json(prompt, "Verified record")["fingerprint"]
