#!/usr/bin/env python3
"""Check a Markdown spec against the measurable ASD-STE100 rules.

Rules checked:
  - procedural sentences (numbered steps, imperative) <= 20 words
  - descriptive sentences <= 25 words
  - paragraphs <= 6 sentences
  - no words from a small list of common unapproved words
  - no -ing words outside an allowlist of technical names

Code spans, tables headers, and WARNING/CAUTION lines are handled specially.
Usage: python3 scripts/ste_check.py SPEC.md
"""

import re
import sys

PROCEDURAL_MAX = 20
DESCRIPTIVE_MAX = 25
PARAGRAPH_MAX = 6

UNAPPROVED = {
    "utilize", "utilise", "shall", "should", "via", "e.g.", "i.e.", "etc.",
    "leverage", "perform", "ensure", "prior", "subsequent", "approximately-",
    "please", "simply", "just", "basically", "obviously",
}
ING_ALLOWED = {
    "during", "string", "strings", "thing", "things", "nothing", "something",
    "anything", "everything", "bring", "single", "ring", "king",
    # Technical names (ASD-STE100 permits -ing forms inside technical names).
    "writing", "sibling", "hardening", "starting", "bookkeeping",
    "percent-encoding", "forking",
}


def strip_code(text):
    return re.sub(r"`[^`]*`", "X", text)


def sentences(text):
    text = strip_code(text)
    text = re.sub(r"\[[^\]]*\]\([^)]*\)", "X", text)
    parts = re.split(r"(?<=[.!?:;])\s+(?=[A-Z\"“(\[])", text.strip())
    return [p for p in parts if p.strip()]


def words(sentence):
    return [w for w in re.findall(r"[A-Za-z0-9][A-Za-z0-9'’/-]*", sentence)]


def check(path):
    problems = []
    in_code = False
    paragraph = []
    paragraph_start = 0

    def flush():
        if len(paragraph) > PARAGRAPH_MAX:
            problems.append((paragraph_start, f"paragraph has {len(paragraph)} sentences (max {PARAGRAPH_MAX})"))
        paragraph.clear()

    with open(path, encoding="utf-8") as fh:
        lines = fh.read().splitlines()

    for n, raw in enumerate(lines, 1):
        line = raw.rstrip()
        if line.startswith("```"):
            in_code = not in_code
            continue
        if in_code:
            continue
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or set(stripped) <= set("-|: "):
            flush()
            continue

        cells = [c.strip() for c in stripped.strip("|").split("|")] if stripped.startswith("|") else [stripped]
        for cell in cells:
            procedural = False
            text = cell
            m = re.match(r"^(\d+\.\s+|[-*]\s+)", text)
            if m:
                procedural = bool(re.match(r"\d+\.\s", text))
                text = text[m.end():]
            text = re.sub(r"^(\d+(\.\d+)*\.)\s+", "", text)  # section numbers like 7.3.4.
            if text.startswith(("WARNING:", "CAUTION:", "NOTE:")):
                text = text.split(":", 1)[1].strip()
            for s in sentences(text):
                ws = words(s)
                first = ws[0].lower() if ws else ""
                is_proc = procedural or (first in IMPERATIVES)
                limit = PROCEDURAL_MAX if is_proc else DESCRIPTIVE_MAX
                if len(ws) > limit:
                    kind = "procedural" if is_proc else "descriptive"
                    problems.append((n, f"{kind} sentence has {len(ws)} words (max {limit}): {s[:70]}..."))
                for w in ws:
                    lw = w.lower()
                    if lw in UNAPPROVED:
                        problems.append((n, f"unapproved word '{w}'"))
                    if lw.endswith("ing") and lw not in ING_ALLOWED and not w.isupper():
                        problems.append((n, f"-ing word '{w}'"))
                if not stripped.startswith("|") and not m:
                    if not paragraph:
                        paragraph_start = n
                    paragraph.append(s)
        if stripped.startswith("|"):
            flush()
    flush()
    return problems


IMPERATIVES = {
    "use", "do", "give", "make", "write", "start", "set", "add", "record", "read",
    "calculate", "find", "validate", "get", "sort", "mark", "group", "encode", "join",
    "normalize", "count", "reserve", "assign", "archive", "queue", "run", "tell",
    "ask", "stop", "apply", "remove", "keep", "merge", "update", "examine",
}


def main(argv):
    if len(argv) != 2:
        print(__doc__)
        return 2
    problems = check(argv[1])
    for line, msg in problems:
        print(f"{argv[1]}:{line}: {msg}")
    print(f"{len(problems)} problem(s)")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
