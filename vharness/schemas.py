"""JSON schemas for each agent role (SPEC 9.1) and for final records (SPEC 8.5).

Agent-facing schemas are kept simple (no oneOf) so that every provider's
structured-output mode can enforce them. Verdict-specific completeness is
checked by plain code in records.py.
"""

import jsonschema

STR = {"type": "string", "minLength": 1}
STRS = {"type": "array", "items": STR}
PATHS = {"type": "array", "items": STR}


def obj(props, required=None):
    return {
        "type": "object",
        "properties": props,
        "required": list(props) if required is None else required,
        "additionalProperties": False,
    }


LOCATION = obj({"file": STR, "line": {"type": "integer", "minimum": 1}})
TRACE_STEP = obj({
    "kind": {"type": "string", "enum": ["entrypoint", "propagation", "sink"]},
    "file": STR,
    "line": {"type": "integer", "minimum": 1},
    "scope": STR,
    "description": STR,
})
EVIDENCE = obj({"file": STR, "line": {"type": "integer", "minimum": 1}, "description": STR})
CONDITION_KINDS = [
    "authentication_level", "authorization_role", "user_interaction", "system_configuration",
    "network_routing", "environmental_dependency", "data_state", "timing_dependency",
    "third_party_dependency",
]
CONDITION = obj({"kind": {"type": "string", "enum": CONDITION_KINDS}, "description": STR})
SEVERITY_LEVELS = ["informational", "low", "medium", "high", "critical"]
LEVEL3 = {"type": "string", "enum": ["low", "medium", "high"]}
SEVERITY = obj({
    "likelihood": obj({"level": LEVEL3, "rationale": STR}),
    "impact": obj({"level": {"type": "string", "enum": SEVERITY_LEVELS}, "rationale": STR}),
    "overall": {"type": "string", "enum": SEVERITY_LEVELS},
})
# The threat model is the first property of every candidate, so the agent
# writes it before the claim (SPEC 7.3.5).
THREAT_MODEL = obj({
    "attacker": STR,
    "starting_capability": STR,
    "boundary": STR,
    "assumption_broken": STR,
    "affected_resource": STR,
})
POC_TEST = obj({
    "file_name": STR,
    "language": STR,
    "code": STR,
    "expectation": STR,
    "command": STR,  # run from the repository root; exits non-zero when the defect is present
}, required=["file_name", "language", "code", "expectation"])
EXECUTION = obj({"run_id": STR, "command": STR, "input": {"type": "string"}, "observed_result": STR})
REMEDIATION = obj({"strategy": STR, "patch": {"type": "string"}}, required=["strategy", "patch"])
VALIDATION_PLAN = obj({"local": {"type": "string"}, "deployment": {"type": "string"}}, required=[])
WISHLIST = {
    "type": "array",
    "items": obj({"need": STR, "reason": STR, "unblocks": STR}),
}

# Record properties; the order puts threat_model first.
RECORD_PROPS = {
    "threat_model": THREAT_MODEL,
    "verdict": {"type": "string", "enum": ["confirmed", "needs_validation", "rejected"]},
    "fingerprint": STR,
    "title": STR,
    "description": STR,
    "evidence_level": {"type": "string", "enum": ["source", "local"]},
    "trace": {"type": "array", "minItems": 1, "items": TRACE_STEP},
    "evidence": {"type": "array", "minItems": 1, "items": EVIDENCE},
    "root_cause": STR,
    "intended_behavior": STR,
    "conditions": {"type": "array", "items": CONDITION},
    "severity": SEVERITY,
    "confidence": LEVEL3,
    "remediation": REMEDIATION,
    "poc_test": POC_TEST,
    "execution": EXECUTION,
    "claimed_root_cause": STR,
    "blockers": STRS,
    "validation_plan": VALIDATION_PLAN,
    "reason": STR,
}
COMMON_REQUIRED = ["threat_model", "verdict", "fingerprint", "title", "description", "evidence_level", "trace", "evidence"]
VERDICT_FIELDS = {
    "confirmed": {
        "required": ["root_cause", "intended_behavior", "conditions", "severity", "confidence", "remediation", "poc_test"],
        "forbidden": ["claimed_root_cause", "blockers", "validation_plan", "reason"],
    },
    "needs_validation": {
        "required": ["claimed_root_cause", "blockers", "validation_plan"],
        "forbidden": ["root_cause", "intended_behavior", "severity", "remediation", "poc_test", "reason", "confidence"],
    },
    "rejected": {
        "required": ["claimed_root_cause", "reason"],
        "forbidden": ["root_cause", "intended_behavior", "severity", "remediation", "poc_test", "blockers", "validation_plan", "confidence"],
    },
}
RECORD = obj(RECORD_PROPS, required=COMMON_REQUIRED)

CANDIDATE_PROPS = {"threat_model": THREAT_MODEL, "proposed_verdict": {"type": "string", "enum": ["confirmed", "needs_validation"]}}
CANDIDATE_PROPS.update({k: v for k, v in RECORD_PROPS.items() if k not in ("threat_model", "verdict", "reason")})
CANDIDATE = obj(CANDIDATE_PROPS, required=["threat_model", "proposed_verdict", "fingerprint", "title", "description", "trace", "evidence"])

UNIT_SPEC = obj({
    "surface": STR, "boundary": STR, "subsystem": STR, "attack_class": STR,
    "starting_paths": PATHS, "reason": STR,
})

# ---- recon (SPEC 7.1.3) ----
RECON_PRODUCT = obj({
    "product_type": STR,
    "users_and_operators": STR,
    "protected_resources": STRS,
    "stack": STRS,
    "subsystems": {"type": "array", "items": obj({"name": STR, "path": STR, "description": STR})},
    "build_and_test_commands": STRS,
    "comparable_software": {"type": "string"},
})
RECON_AUTHORITY = obj({
    "principals": {"type": "array", "items": obj({"name": STR, "trust": STR, "allowed_actions": STR})},
    "boundaries": {"type": "array", "items": obj({
        "name": STR, "control": STR, "control_ref": STR, "source_visible": {"type": "boolean"},
    })},
    "unobserved_controls": STRS,
})
RECON_SURFACES = obj({
    "surfaces": {"type": "array", "items": obj({
        "name": STR,
        "kind": STR,
        "entry_ref": STR,
        "subsystem": STR,
        "trust_level": {"type": "string", "enum": ["unauthenticated", "authenticated", "privileged", "local", "build_time"]},
        "resource_value": {"type": "string", "enum": ["low", "medium", "high", "critical"]},
        "boundaries": {"type": "array", "minItems": 1, "items": obj({"name": STR, "control_ref": STR})},
        "attack_classes": {"type": "array", "minItems": 1, "items": STR},
        "starting_paths": PATHS,
        "sinks": STRS,
    })},
    "companions_selected": {"type": "array", "items": obj({"file": STR, "reason": STR})},
    "companions_excluded": {"type": "array", "items": obj({"file": STR, "reason": STR})},
    "custom_attack_classes": {"type": "array", "items": obj({"name": STR, "method": STR, "reason": STR})},
})

# ---- hunter (SPEC 7.3) ----
CHECK = obj({"invariant": STR, "reviewed_paths": PATHS, "result": STR})
HUNTER = obj({
    "units": {"type": "array", "items": obj({
        "coverage_id": STR,
        "disposition": {"type": "string", "enum": ["covered", "candidate", "blocked"]},
        "reviewed_paths": PATHS,
        "checks": {"type": "array", "items": CHECK},
        "candidate_fingerprints": STRS,
        "unresolved": STRS,
    })},
    "candidates": {"type": "array", "items": CANDIDATE},
    "hardening": STRS,
    "uncovered": {"type": "array", "items": UNIT_SPEC},
    "wishlist": WISHLIST,
})

# ---- critic / gapfill (SPEC 7.4) ----
CRITIC = obj({
    "missing_units": {"type": "array", "items": UNIT_SPEC},
    "reassign": {"type": "array", "items": obj({"coverage_id": STR, "reason": STR})},
    "stop": {"type": "boolean"},
})

# ---- dedup (SPEC 7.5) ----
DEDUP = obj({"duplicate_of": {"type": ["string", "null"]}, "reason": STR})

# ---- validator (SPEC 7.6) ----
VALIDATOR = obj({
    "decision": {"type": "string", "enum": ["confirmed", "needs_validation", "rejected"]},
    "record": RECORD,
    "wishlist": WISHLIST,
}, required=["decision", "record"])

# ---- tracer (SPEC 7.7) ----
TRACER = obj({
    "reachability": {"type": "string", "enum": ["reachable", "conditional", "unreachable", "unknown"]},
    "exposure": {"type": "string", "enum": ["exploitable_now", "latent", "wrong_component"]},
    "external_entrypoint": {"type": "string"},
    "call_path": {"type": "array", "items": obj({"file": STR, "line": {"type": "integer", "minimum": 1}, "description": STR})},
    "rationale": STR,
})

# ---- verifier (SPEC 7.9) ----
VERIFIER = obj({
    "decision": {"type": "string", "enum": ["verified", "replace"]},
    "fingerprint": STR,
    "reason": STR,
    "record": RECORD,
}, required=["decision", "fingerprint", "reason"])

ROLE_SCHEMAS = {
    "recon:product": RECON_PRODUCT,
    "recon:authority": RECON_AUTHORITY,
    "recon:surfaces": RECON_SURFACES,
    "hunter": HUNTER,
    "critic": CRITIC,
    "dedup": DEDUP,
    "validator": VALIDATOR,
    "tracer": TRACER,
    "verifier": VERIFIER,
}


def validate(instance, schema):
    """Return a list of schema error strings (empty when valid)."""
    validator = jsonschema.Draft202012Validator(schema)
    errors = sorted(validator.iter_errors(instance), key=lambda e: list(e.absolute_path))
    return [f"{'/'.join(str(p) for p in e.absolute_path) or '<root>'}: {e.message}" for e in errors[:50]]
