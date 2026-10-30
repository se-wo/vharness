"""Attack-class knowledge loaded from the vendored security-audit-skill files.

A block reference is `FILE.md#Name`, where Name is a bold block title
(`**Access control**`) or a heading title before any parenthetical
(`## Core discipline (include ...)` -> `Core discipline`). Custom classes made
by recon use `CUSTOM#Name`.
"""

import os
import re

KNOWLEDGE_DIR = os.path.join(os.path.dirname(__file__), "knowledge")
ORDINARY_FILE = "ATTACK-CLASSES.md"
COMPANION_SECTIONS = ("Core discipline", "Universal moves", "Validation rules")
BOLD_BLOCK_RE = re.compile(r"^\*\*([^*]+)\*\*(\s*\(.*\))?\s*$")
HEADING_RE = re.compile(r"^(#+)\s+(.*?)\s*$")


def _heading_name(title):
    return re.split(r"\s+\(", title, maxsplit=1)[0].strip()


class Knowledge:
    def __init__(self, directory=KNOWLEDGE_DIR):
        self.directory = directory
        self.files = {}
        self.blocks = {}  # ref -> text
        self.kinds = {}  # ref -> "class" | "section"
        for name in sorted(os.listdir(directory)):
            if name.endswith(".md"):
                with open(os.path.join(directory, name), encoding="utf-8") as fh:
                    text = fh.read()
                self.files[name] = text
                self._index(name, text)

    def _index(self, fname, text):
        lines = text.splitlines()
        starts = []  # (line index, kind, name, heading level or None)
        for i, line in enumerate(lines):
            h = HEADING_RE.match(line)
            if h:
                starts.append((i, "heading", _heading_name(h.group(2)), len(h.group(1))))
                continue
            b = BOLD_BLOCK_RE.match(line)
            if b:
                starts.append((i, "class", b.group(1).strip(), None))
        for idx, (i, kind, name, level) in enumerate(starts):
            end = len(lines)
            for j, kind2, _, level2 in starts[idx + 1:]:
                if kind == "class" or (kind2 == "heading" and level2 <= level):
                    end = j
                    break
            body = "\n".join(lines[i:end]).strip()
            ref = f"{fname}#{name}"
            if kind == "class" or name in COMPANION_SECTIONS or name == "When to use this file":
                self.blocks.setdefault(ref, body)
                self.kinds.setdefault(ref, "class" if kind == "class" else "section")

    def companion_files(self):
        return [f for f in self.files if f != ORDINARY_FILE]

    def classes(self, fname=None):
        return sorted(r for r, k in self.kinds.items() if k == "class" and (fname is None or r.startswith(fname + "#")))

    def when_to_use(self, fname):
        ref = f"{fname}#When to use this file"
        return self.blocks.get(ref, "")

    def has(self, ref):
        return ref in self.blocks

    def block(self, ref):
        return self.blocks[ref]

    def blocks_for_class(self, ref, include_companion_sections=True):
        """Return the ordered list of (ref, text) a hunter needs for one attack class."""
        fname = ref.split("#", 1)[0]
        if fname == ORDINARY_FILE or fname == "CUSTOM" or not include_companion_sections:
            return [(ref, self.blocks[ref])] if ref in self.blocks else []
        out = []
        for section in ("Core discipline",):
            sref = f"{fname}#{section}"
            if sref in self.blocks:
                out.append((sref, self.blocks[sref]))
        if ref in self.blocks:
            out.append((ref, self.blocks[ref]))
        for section in ("Universal moves", "Validation rules"):
            sref = f"{fname}#{section}"
            if sref in self.blocks:
                out.append((sref, self.blocks[sref]))
        return out

    def validation_blocks(self, ref):
        fname = ref.split("#", 1)[0]
        sref = f"{fname}#Validation rules"
        return [(sref, self.blocks[sref])] if sref in self.blocks else []

    def catalog(self):
        """Compact catalog for the recon prompt: classes per file plus 'when to use'."""
        parts = [f"### {ORDINARY_FILE} (ordinary classes)\n" + "\n".join(f"- `{r}`" for r in self.classes(ORDINARY_FILE))]
        for fname in self.companion_files():
            when = self.when_to_use(fname).replace("#### When to use this file", "").strip()
            classes = "\n".join(f"- `{r}`" for r in self.classes(fname))
            parts.append(f"### {fname}\nWhen to use: {when}\nClasses:\n{classes}")
        return "\n\n".join(parts)
