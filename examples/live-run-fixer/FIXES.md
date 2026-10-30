# Fixes

Every fix needs review by a person. vharness never writes to the target, never runs git, and never merges.

## default-credential:notesapp/storage.py:USERS — needs_human

`notesapp` · patch changes existing test files: tests/conftest.py (R-FIX-04)

Patch: `fixes/0003-needs_human-default-credential-notesapp-storage-py-USERS.patch` (apply on a review branch with `git am`)

Regression test: `tests/test_default_credentials.py`, command `python3 tests/test_default_credentials.py`
Suite command: `ALICE_TOKEN=change-me-a BOB_TOKEN=change-me-b python3 -c "import sys; sys.path.insert(0,'tests'); import test_notes; test_notes.test_list_only_own()"`

Style notes: Matches the repo: stdlib only, plain RuntimeError, small helper in storage.py. The existing tests/test_notes.py is untouched. A new tests/conftest.py supplies the env vars so the existing test, which uses 'change-me-a', still runs under pytest.

Risk notes: 1) Behavior change: the service now fails at import with RuntimeError unless ALICE_TOKEN and BOB_TOKEN are set, non-empty and distinct. Deployments that relied on the defaults will not start until the operator sets them. 2) I did not add a minimum-length check. The existing test hard-codes the 11-character 'change-me-a', and the rules forbid editing it. Strength remains the operator's job. Raising the bar would mean changing that test. 3) tests/conftest.py sets 'change-me-a' and 'change-me-b' as test-only values through os.environ.setdefault. They have no effect on production. 4) pytest is not installed in the sandbox. I verified the new test with unittest: 3 of 4 tests fail before the patch and all 4 pass after. I ran the existing test function directly with the env vars set, and it passes. I did not run pytest and so did not exercise conftest.py loading. 5) Tokens passed through other config sources are not covered.

### Attempt 1 (fixer-notesapp-0024)

- suite_patched (`sbx-00036`): exit 0
- suite_unchanged (`sbx-00035`): exit 0
- test_patched (`sbx-00034`): exit 0

```text
authenticated as alice
....
----------------------------------------------------------------------
Ran 4 tests in 0.076s

OK
```

- test_unchanged (`sbx-00033`): exit 1

```text
public_default_token_not_accepted_when_env_unset (__main__.DefaultCredentialTests.test_public_default_token_not_accepted_when_env_unset)
----------------------------------------------------------------------
Traceback (most recent call last):
  File "/scratch/src/tests/test_default_credentials.py", line 37, in test_public_default_token_not_accepted_when_env_unset
    self.assertEqual(run({}, "change-me-a"), 0)
    ~~~~~~~~~~~~~~~~^^^^^^^^^^^^^^^^^^^^^^^^^^^
AssertionError: 1 != 0

----------------------------------------------------------------------
Ran 4 tests in 0.077s

FAILED (failures=3)
```


### Patch

```diff
--- a/notesapp/storage.py
+++ b/notesapp/storage.py
@@ -4,7 +4,18 @@
 
+
+def _required_token(var):
+    value = os.environ.get(var, "")
+    if not value:
+        raise RuntimeError(f"{var} must be set to a non-empty secret token")
+    return value
+
+
 USERS = {
-    "alice": {"id": "alice", "token": os.environ.get("ALICE_TOKEN", "change-me-a")},
-    "bob": {"id": "bob", "token": os.environ.get("BOB_TOKEN", "change-me-b")},
+    "alice": {"id": "alice", "token": _required_token("ALICE_TOKEN")},
+    "bob": {"id": "bob", "token": _required_token("BOB_TOKEN")},
 }
 
+if len({u["token"] for u in USERS.values()}) != len(USERS):
+    raise RuntimeError("each user must have a distinct token")
+
 NOTES = {
--- /dev/null
+++ b/tests/conftest.py
@@ -0,0 +1,5 @@
+import os
+
+# The app has no default tokens; supply credentials for the test run.
+os.environ.setdefault("ALICE_TOKEN", "change-me-a")
+os.environ.setdefault("BOB_TOKEN", "change-me-b")
```

## idor:notesapp/notes.py:get_note — accepted

`notesapp` · gate passed: the test fails before and passes after the patch; the suite passes

Patch: `fixes/0001-accepted-idor-notesapp-notes-py-get-note.patch` (apply on a review branch with `git am`)

Regression test: `tests/test_get_note_idor.py`, command `python3 tests/test_get_note_idor.py`
Suite command: `python3 -c "import sys;sys.path.insert(0,'.');import tests.test_notes as t;[getattr(t,n)() for n in dir(t) if n.startswith('test_')]"`

Style notes: One-line change that reuses the existing require_owner helper, placed as in delete_note. A non-owner gets AuthError, the same as the delete path. The new test uses unittest, so it runs without pytest.

Risk notes: A non-owner now gets AuthError (forbidden) for an existing note and 404 for a missing one. That difference reveals whether an id exists. This matches delete_note, so I kept it. Returning 404 in both cases would hide existence. Nothing in the repo maps AuthError to an HTTP status, so the HTTP layer must handle it. The separate unvalidated `name` path in export_note is not touched. I ran the new test before and after the patch in the sandbox: it failed before and passed after. The existing test_notes functions also ran cleanly, called directly because pytest isn't available there.

### Attempt 1 (fixer-notesapp-0025)

- suite_patched (`sbx-00025`): exit 0
- suite_unchanged (`sbx-00024`): exit 0
- test_patched (`sbx-00023`): exit 0

```text
..
----------------------------------------------------------------------
Ran 2 tests in 0.000s

OK
```

- test_unchanged (`sbx-00022`): exit 1

```text
note)
----------------------------------------------------------------------
Traceback (most recent call last):
  File "/scratch/src/tests/test_get_note_idor.py", line 21, in test_cannot_read_other_users_note
    self.assertNotEqual(status, 200, "alice read bob's note: %r" % (body,))
    ~~~~~~~~~~~~~~~~~~~^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
AssertionError: 200 == 200 : alice read bob's note: {'id': 2, 'owner': 'bob', 'title': 'bob private', 'body': 'bob secret'}

----------------------------------------------------------------------
Ran 2 tests in 0.001s

FAILED (failures=1)
```


### Patch

```diff
--- a/notesapp/notes.py
+++ b/notesapp/notes.py
@@ -14,6 +14,7 @@ def get_note(request, note_id):
     note = storage.get(int(note_id))
     if note is None:
         return 404, {"error": "not found"}
+    require_owner(user, note)
     return 200, note
 
 
```

## path-traversal:notesapp/notes.py:export_note — accepted

`notesapp` · gate passed: the test fails before and passes after the patch; the suite passes

Patch: `fixes/0002-accepted-path-traversal-notesapp-notes-py-export-note.patch` (apply on a review branch with `git am`)

Regression test: `tests/test_export_traversal.py`, command `python3 tests/test_export_traversal.py`
Suite command: `python3 -c "import sys; sys.path.insert(0,'.'); import tests.test_notes as t; t.test_list_only_own()"`

Style notes: Fix is in export_note, the last decision point before open(). It returns a (status, body) tuple with 400 and {"error": ...}, the same shape get_note uses for 404. It uses only os, which is already imported.

Risk notes: In the sandbox the test failed on the unpatched copy (exit 1) and passed on the patched copy (exit 0), including a symlink-escape case. The existing test_list_only_own passes when called directly. pytest is not available there, so I did not run the suite through pytest. Symlinks inside EXPORT_DIR that point outside it are now rejected with 400. That is intended, but an operator who deliberately symlinks exports would see them break. A missing file still raises FileNotFoundError, as before. Nothing in the repo maps exceptions to HTTP status codes, so I did not change that.

### Attempt 1 (fixer-notesapp-0026)

- suite_patched (`sbx-00029`): exit 0
- suite_unchanged (`sbx-00028`): exit 0
- test_patched (`sbx-00027`): exit 0

```text
PASS test_export_in_dir_still_works
PASS test_export_rejects_dotdot
PASS test_export_rejects_absolute
PASS test_export_rejects_symlink_escape
```

- test_unchanged (`sbx-00026`): exit 1

```text
PASS test_export_in_dir_still_works
FAIL test_export_rejects_dotdot '..' escaped EXPORT_DIR
FAIL test_export_rejects_absolute absolute name escaped EXPORT_DIR
FAIL test_export_rejects_symlink_escape symlink escaped EXPORT_DIR
```


### Patch

```diff
--- a/notesapp/notes.py
+++ b/notesapp/notes.py
@@ -30,6 +30,9 @@
 def export_note(request):
     user = current_user(request)
     name = request.args.get("name", "export.txt")
-    path = os.path.join(storage.EXPORT_DIR, name)
+    base = os.path.realpath(storage.EXPORT_DIR)
+    path = os.path.realpath(os.path.join(base, name))
+    if os.path.commonpath([base, path]) != base or path == base:
+        return 400, {"error": "invalid export name"}
     with open(path, "rb") as fh:
         return 200, fh.read()
```

