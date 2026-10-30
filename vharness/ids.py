"""Stable identifiers: coverage IDs (SPEC 8.2), fingerprints (8.4), agent IDs (R-AGT-04)."""

import re
import unicodedata

AGENT_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
FINGERPRINT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/@+-]*$")
WINDOWS_DEVICE_NAMES = {"con", "prn", "aux", "nul"} | {f"com{i}" for i in range(1, 10)} | {f"lpt{i}" for i in range(1, 10)}
UNRESERVED = set(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~")
QUICK_SUBSYSTEM = "profile/quick/all-in-scope-subsystems"
DIMENSIONS = ("surface", "boundary", "subsystem", "attack_class")


def canonical_ref(value):
    """Normalize one canonical reference (NFC, trimmed, visible)."""
    if not isinstance(value, str):
        raise ValueError("canonical reference must be a string")
    ref = unicodedata.normalize("NFC", value).strip()
    if not ref:
        raise ValueError("canonical reference is empty")
    for ch in ref:
        if unicodedata.category(ch) in ("Cc", "Cf", "Zl", "Zp"):
            raise ValueError(f"canonical reference contains control/format character U+{ord(ch):04X}")
    return ref


def percent_encode(ref):
    out = []
    for byte in ref.encode("utf-8"):
        out.append(chr(byte) if byte in UNRESERVED else f"%{byte:02X}")
    return "".join(out)


def coverage_id(refs):
    """Derive a coverage_id from a dict with surface/boundary/subsystem/attack_class refs."""
    return "::".join(percent_encode(canonical_ref(refs[d])) for d in DIMENSIONS)


def valid_fingerprint(fp):
    return isinstance(fp, str) and bool(FINGERPRINT_RE.match(fp)) and len(fp) <= 200


def valid_agent_id(agent_id):
    return isinstance(agent_id, str) and bool(AGENT_ID_RE.match(agent_id)) and agent_id not in WINDOWS_DEVICE_NAMES


def slug(text, limit=24):
    s = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")
    return (s or "x")[:limit].strip("-") or "x"


def agent_id(role, target, seq):
    """Build a fresh canonical agent ID such as `hunter-myrepo-0012`."""
    aid = f"{slug(role, 12)}-{slug(target, 24)}-{seq:04d}"
    if not valid_agent_id(aid):
        raise ValueError(f"cannot build a valid agent id from {role!r}/{target!r}")
    return aid
