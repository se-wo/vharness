"""Fixer gate and patch output (SPEC 13.2). Plain code; the fixer agent itself is in stages.py."""

import email.utils
import os
import re

from . import records
from .sandbox import SETUP_EXIT, RunSpec

TEST_PATH_RE = re.compile(r"(^|/)(tests?|spec|specs|__tests__|testdata)/|(^|/)test_[^/]*$|_test\.\w+$|\.(spec|test)\.\w+$|(^|/)conftest\.py$")
TEST_CONFIG_RE = re.compile(r"(^|/)(conftest\.py|pytest\.ini|tox\.ini|setup\.cfg|pyproject\.toml|jest\.config\.\w+|"
                            r"karma\.conf\.\w+|vitest\.config\.\w+|\.mocharc\.\w+|phpunit\.xml|Makefile)$")
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
    existing = [f for f in files if TEST_PATH_RE.search(f) and records.line_count(root, f) is not None]
    if existing:
        human.append(f"patch changes existing test files: {', '.join(existing)} (R-FIX-04)")
    config = [f for f in files if TEST_CONFIG_RE.search(f) and f not in existing]
    if config:
        human.append(f"patch adds or changes test configuration that changes how existing tests run: {', '.join(config)} (R-FIX-04)")
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


NOT_RUNNABLE_RE = re.compile(r"No module named|command not found|not found|No such file or directory|can't open file", re.I)


def suite_failure_reason(step):
    out = (step.get("stdout") or "") + (step.get("stderr") or "")
    if NOT_RUNNABLE_RE.search(out):
        first = next((l for l in out.splitlines() if NOT_RUNNABLE_RE.search(l)), "").strip()[:160]
        return f"the suite command does not run in the sandbox ({first})"
    return "the suite already fails on unchanged code"


def combined_script(patch_count, test_files, command):
    """One fresh copy with every accepted patch applied in order (SPEC 13.2.4.6)."""
    lines = ["cp -R /target/. /scratch/src || exit 98", "cd /scratch/src || exit 98"]
    for i in range(patch_count):
        lines.append(f"patch -p1 -s --no-backup-if-mismatch -r /dev/null < /scratch/.vhin/fix{i}.patch >/dev/null 2>&1 || exit {60 + i}")
    for i, name in enumerate(test_files):
        lines += [f'mkdir -p "$(dirname "$VH_TEST_{i}")" || exit 98', f'cp /scratch/.vhin/test{i} "$VH_TEST_{i}" || exit 98']
    if command:
        lines.append(command)
    return "\n".join(lines)


async def run_combined(h, target, fixes):
    """SPEC 13.2.4.6: do the accepted fixes of one target work together?"""
    if not fixes:
        return None
    files, env = [], {}
    for i, fx in enumerate(fixes):
        patch = fx["patch"] if fx["patch"].endswith("\n") else fx["patch"] + "\n"
        code = fx["test"]["code"] if fx["test"]["code"].endswith("\n") else fx["test"]["code"] + "\n"
        files += [{"path": f".vhin/fix{i}.patch", "content": patch}, {"path": f".vhin/test{i}", "content": code}]
        env[f"VH_TEST_{i}"] = fx["test"]["file_name"]
    tests = [fx["test"]["file_name"] for fx in fixes]
    art = os.path.join(h.out, "sandbox", "fix-artifacts")
    order = [fx["fingerprint"] for fx in fixes]
    sbx_id, st, error = await h.sandbox_exec(target, "harness", "fixset-apply", RunSpec(
        command=combined_script(len(fixes), tests, "true"), files=files, env=env), art)
    step = _brief(sbx_id, st, error)
    if step.get("error") or step.get("exit_code") != 0:
        code = step.get("exit_code")
        culprit = order[code - 60] if isinstance(code, int) and 60 <= code < 60 + len(fixes) else None
        status = "conflict" if culprit else "error"
        return {"status": status, "order": order, "failed": culprit or step.get("error") or f"exit {code}", "steps": {"apply": step}}
    steps, failed = {"apply": step}, []
    commands = [(f"test:{fx['fingerprint']}", fx["test"]["command"]) for fx in fixes]
    for suite in dict.fromkeys(fx["suite_command"] for fx in fixes if fx["suite_command"].strip()):
        commands.append((f"suite:{suite}", suite))
    for label, command in commands:
        sbx_id, st, error = await h.sandbox_exec(target, "harness", "fixset-check", RunSpec(
            command=combined_script(len(fixes), tests, command), files=files, env=env), art)
        steps[label] = _brief(sbx_id, st, error)
        if not _passed(steps[label]):
            failed.append(label)
    return {"status": "interaction" if failed else "ok", "order": order, "failed": failed, "steps": steps}


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
        "This patch is made against the unchanged commit that vharness audited. Review it on its own",
        "branch; see FIXES.md for whether the accepted fixes also work together.",
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

