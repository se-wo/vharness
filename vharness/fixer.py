"""Fixer gate and patch output (SPEC 13.2). Plain code; the fixer agent itself is in stages.py."""

import email.utils
import os
import re

from . import records
from .sandbox import SETUP_EXIT, RunSpec

TEST_PATH_RE = re.compile(r"(^|/)(tests?|spec|specs|__tests__|testdata)/|(^|/)test_[^/]*$|_test\.\w+$|\.(spec|test)\.\w+$|(^|/)conftest\.py$")
DIFF_PATH_RE = re.compile(r"^(?:---|\+\+\+) (?:[ab]/)?(\S+)")


def patch_files(patch):
    return sorted({m.group(1) for line in patch.splitlines() if (m := DIFF_PATH_RE.match(line)) and m.group(1) != "/dev/null"})


def changed_lines(patch):
    return sum(1 for line in patch.splitlines()
               if line[:1] in "+-" and not line.startswith(("+++", "---")))


def mechanical(out, root, max_lines):
    """SPEC 13.2.3. Returns (errors, needs_human_reasons)."""
    errors, human = [], []
    patch, test = out["patch"], out["test"]
    patch_errors = records.check_patch(patch, root)  # R-FIX-01
    errors += patch_errors
    if not patch_errors and not patch_files(patch):
        errors.append("patch changes no file")
    name = test["file_name"]
    if not records.safe_relpath(name):
        errors.append(f"test file {name!r} is not repository-relative")  # R-FIX-02
    elif records.line_count(root, name) is not None or os.path.lexists(os.path.join(root, name)):
        errors.append(f"test file {name!r} already exists; the regression test must be a new file")
    files = patch_files(patch)
    if name in files:
        errors.append("the patch must not create or change the test file of the fix")  # R-FIX-03
    touched_tests = [f for f in files if TEST_PATH_RE.search(f)]
    if touched_tests:
        human.append(f"patch changes existing test files: {', '.join(touched_tests)} (R-FIX-04)")
    n = changed_lines(patch)
    if n > max_lines:
        human.append(f"patch changes {n} lines, more than {max_lines} (R-FIX-05)")
    return errors, human


def gate_script(command, patched, with_test):
    lines = ["cp -R /target/. /scratch/src || exit 98", "cd /scratch/src || exit 98"]
    if patched:
        lines.append("patch -p1 -s --no-backup-if-mismatch -r /dev/null < /scratch/.vhin/fix.patch >/dev/null 2>&1 || exit 97")
    if with_test:
        lines += ['mkdir -p "$(dirname "$VH_TEST_FILE")" || exit 98', 'cp /scratch/.vhin/test "$VH_TEST_FILE" || exit 98']
    lines.append(command)
    return "\n".join(lines)


def _brief(sbx_id, st, error):
    if error or st is None:
        return {"run_id": sbx_id, "error": error or "no status"}
    return {"run_id": sbx_id, "exit_code": st["exit_code"], "signal": st["signal"], "timed_out": st["timed_out"],
            "stdout": st["stdout"][-1500:], "stderr": st["stderr"][-1500:]}


def _setup_failed(step):
    return step.get("error") or step.get("exit_code") in (97, 98, SETUP_EXIT) or step.get("timed_out")


def _passed(step):
    return not _setup_failed(step) and step.get("signal") is None and step.get("exit_code") == 0


def _failed_cleanly(step):
    return not _setup_failed(step) and (step.get("signal") is not None or step.get("exit_code") not in (0, None))


async def run_gate(h, target, out):
    """SPEC 13.2.4: four sandbox runs, each on a fresh copy. Returns (passed, reason, steps, baseline_failing)."""
    test = out["test"]
    code = test["code"] if test["code"].endswith("\n") else test["code"] + "\n"
    patch = out["patch"] if out["patch"].endswith("\n") else out["patch"] + "\n"
    files_base = [{"path": ".vhin/test", "content": code}]
    files_patched = files_base + [{"path": ".vhin/fix.patch", "content": patch}]
    env = {"VH_TEST_FILE": test["file_name"]}
    art = os.path.join(h.out, "sandbox", "fix-artifacts")
    plan = [("test_unchanged", test["command"], False, True), ("test_patched", test["command"], True, True)]
    if out["suite_command"].strip():
        plan += [("suite_unchanged", out["suite_command"], False, False), ("suite_patched", out["suite_command"], True, True)]
    steps = {}
    for name, command, patched, with_test in plan:
        spec = RunSpec(command=gate_script(command, patched, with_test), files=files_patched if patched else files_base, env=env)
        sbx_id, st, error = await h.sandbox_exec(target, "harness", f"fix-{name}", spec, art)
        steps[name] = _brief(sbx_id, st, error)
        if name == "test_unchanged" and not _failed_cleanly(steps[name]):
            why = "setup failed" if _setup_failed(steps[name]) else "the test passes on unchanged code"
            return False, f"gate step 1: {why}", steps, False
        if name == "test_patched" and not _passed(steps[name]):
            why = ("the patch does not apply" if steps[name].get("exit_code") == 97 else
                   "setup failed" if _setup_failed(steps[name]) else "the test still fails after the patch")
            return False, f"gate step 2: {why}", steps, False
    baseline_failing = False
    if "suite_unchanged" in steps:
        base, after = steps["suite_unchanged"], steps["suite_patched"]
        if _setup_failed(after) or (not _passed(after) and _passed(base)):
            return False, "gate step 4: the suite fails after the patch (regression)", steps, False
        if not _passed(base):
            baseline_failing = True
    return True, "gate passed", steps, baseline_failing


def mbox(record, fix, test, suite_command, status, reason, steps):
    """R-FIX-10: one `git am`-ready patch: the fix plus the new test file."""
    code = test["code"] if test["code"].endswith("\n") else test["code"] + "\n"
    lines = code.splitlines()
    test_diff = (f"diff --git a/{test['file_name']} b/{test['file_name']}\nnew file mode 100644\n--- /dev/null\n"
                 f"+++ b/{test['file_name']}\n@@ -0,0 +1,{len(lines)} @@\n" + "".join(f"+{l}\n" for l in lines))
    subject = re.sub(r"\s+", " ", record["title"])[:68]
    flip = []
    for name in ("test_unchanged", "test_patched", "suite_unchanged", "suite_patched"):
        if name in steps:
            st = steps[name]
            flip.append(f"  {name}: {st.get('error') or 'exit ' + str(st.get('exit_code'))} ({st['run_id']})")
    body = "\n".join([
        f"Fix {record['fingerprint']}.",
        "",
        f"Root cause: {record['root_cause']}",
        "",
        f"Fix strategy: {record['remediation']['strategy']}",
        "",
        f"vharness fixer result: {status.upper()} - {reason}",
        "Gate (each step a fresh sandbox copy):",
        *flip,
        f"Regression test: {test['command']}",
        f"Suite: {suite_command or '(none)'}",
        "",
        "Generated by the vharness fixer. A person must review this change; vharness never merges.",
    ])
    patch = fix if fix.endswith("\n") else fix + "\n"
    return (f"From 0000000000000000000000000000000000000000 Mon Sep 17 00:00:00 2001\n"
            f"From: vharness fixer <vharness@localhost>\n"
            f"Date: {email.utils.formatdate()}\n"
            f"Subject: [PATCH] {'' if status == 'accepted' else '[' + status.upper() + '] '}{subject}\n\n"
            f"{body}\n---\n{patch}{test_diff}-- \nvharness\n\n")


def patch_filename(index, status, fingerprint):
    slug = re.sub(r"[^A-Za-z0-9]+", "-", fingerprint).strip("-")[:60]
    return f"{index:04d}-{status}-{slug}.patch"

