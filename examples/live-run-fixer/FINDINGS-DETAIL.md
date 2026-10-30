# Findings detail

PoC tests were executed by the harness in its sandbox; each section gives the result.

## Hard-coded fallback bearer tokens (and accepted empty tokens) authenticate as any user when env vars are unset

`notesapp` · `default-credential:notesapp/storage.py:USERS` · high · P1

notesapp/storage.py builds USERS with os.environ.get('ALICE_TOKEN', 'change-me-a') and os.environ.get('BOB_TOKEN', 'change-me-b'). Nothing checks that these variables are set, non-empty, strong or distinct. current_user (auth.py:10-19) compares the presented token with each USERS entry using hmac.compare_digest and returns the first match. A deployment that omits the variables therefore accepts 'Authorization: Bearer change-me-a' as alice and 'Bearer change-me-b' as bob, and tests/test_notes.py:11 relies on this. If a variable is set but empty, 'Authorization: Bearer ' (empty token) matches, because compare_digest('', '') is True. An anonymous caller can then call list_notes, delete_note and export_note as that user. The source confirms the path: every handler gates only on current_user, and no startup check exists.

### Trace

1. **entrypoint** `notesapp/app.py:11` (dispatch): An anonymous HTTP request is routed to a handler. The routing layer does no authentication.
2. **propagation** `notesapp/notes.py:8` (list_notes): Each handler (get_note at line 13, delete_note at line 21, export_note at line 31) calls current_user(request) as its only gate.
3. **propagation** `notesapp/auth.py:15` (current_user): The token is taken from 'Authorization: Bearer <token>' with no non-empty or minimum-length check.
4. **propagation** `notesapp/storage.py:6` (USERS): If ALICE_TOKEN is unset, alice's stored token is the public value 'change-me-a'. BOB_TOKEN falls back to 'change-me-b' at line 7. An empty env value is stored as ''.
5. **sink** `notesapp/auth.py:17` (current_user): hmac.compare_digest(user['token'], token) is True for the public default or an empty token, so the user object is returned and the attacker acts as that user.

### Evidence

- `notesapp/storage.py:6`: ALICE_TOKEN falls back to the hard-coded 'change-me-a'.
- `notesapp/storage.py:7`: BOB_TOKEN falls back to the hard-coded 'change-me-b'.
- `notesapp/auth.py:17`: The constant-time comparison is correct, but it is against a public or empty secret, and the code never validates that the secret is non-empty.
- `tests/test_notes.py:11`: The test authenticates with 'change-me-a', which shows the default works as a credential.
- `notesapp/app.py:12`: The docstring says every route is reachable by any client over HTTP.

### Conditions

- system_configuration: The operator leaves ALICE_TOKEN and/or BOB_TOKEN unset, which activates the 'change-me-*' defaults, or sets one to an empty string. Nothing warns or fails in either case.
- network_routing: The attacker can reach the service's routes over HTTP (app.py:12).

### Intended behavior

The service must refuse to start, or refuse all authentication, unless every user's token is explicitly configured with a non-empty, sufficiently long and distinct secret. A publicly known or empty token must never authenticate.

### Reachability

conditional / exploitable_now

### Proof-of-concept test — `fixed`: fails on unchanged code, passes after the patch

`tests/test_default_credentials.py` — Fails on the current code: both subprocesses print 'authenticated as alice', giving 2 failures and a non-zero exit. Passes after the patch, because the import raises RuntimeError for missing or short tokens and both checks exit 0.

Command: `python3 tests/test_default_credentials.py`

Original copy (`sbx-00010`): exit 1

```text
" * 32}, ""), 0)
    ~~~~~~~~~~~~~~~~^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
AssertionError: 1 != 0

======================================================================
FAIL: test_public_default_token_not_accepted_when_env_unset (__main__.DefaultCredentialTests.test_public_default_token_not_accepted_when_env_unset)
----------------------------------------------------------------------
Traceback (most recent call last):
  File "/scratch/src/tests/test_default_credentials.py", line 37, in test_public_default_token_not_accepted_when_env_unset
    self.assertEqual(run({}, "change-me-a"), 0)
    ~~~~~~~~~~~~~~~~^^^^^^^^^^^^^^^^^^^^^^^^^^^
AssertionError: 1 != 0

----------------------------------------------------------------------
Ran 2 tests in 0.039s

FAILED (failures=2)
```

Patched copy (`sbx-00011`): exit 0

```text
..
----------------------------------------------------------------------
Ran 2 tests in 0.039s

OK
```

```python
import os
import subprocess
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Child process: exit 0 if the configuration is refused or the token is rejected,
# exit 1 if the token authenticates.
CHECK = r'''
import sys
try:
    from notesapp import auth
except Exception:
    sys.exit(0)
class R:
    pass
r = R()
r.headers = {"Authorization": "Bearer " + sys.argv[1]}
try:
    user = auth.current_user(r)
except auth.AuthError:
    sys.exit(0)
print("authenticated as", user["id"])
sys.exit(1)
'''


def run(env, token):
    child_env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin")}
    child_env.update(env)
    return subprocess.run([sys.executable, "-c", CHECK, token], cwd=ROOT, env=child_env).returncode


class DefaultCredentialTests(unittest.TestCase):
    def test_public_default_token_not_accepted_when_env_unset(self):
        self.assertEqual(run({}, "change-me-a"), 0)

    def test_empty_configured_token_does_not_allow_empty_bearer(self):
        self.assertEqual(run({"ALICE_TOKEN": "", "BOB_TOKEN": "b" * 32}, ""), 0)


if __name__ == "__main__":
    unittest.main()

```

### Remediation

Remove the hard-coded defaults. At import or startup, require each token env var to be set to a secret of at least 16 characters, and require tokens to be distinct across users. Fail closed with RuntimeError otherwise. Update the existing test to supply its own tokens through the environment.

```diff
--- a/notesapp/storage.py
+++ b/notesapp/storage.py
@@ -2,10 +2,21 @@
 
 EXPORT_DIR = os.environ.get("NOTES_EXPORT_DIR", "/var/lib/notesapp/exports")
 
+
+def _required_token(var):
+    value = os.environ.get(var, "")
+    if len(value) < 16:
+        raise RuntimeError(f"{var} must be set to a secret token of at least 16 characters")
+    return value
+
+
 USERS = {
-    "alice": {"id": "alice", "token": os.environ.get("ALICE_TOKEN", "change-me-a")},
-    "bob": {"id": "bob", "token": os.environ.get("BOB_TOKEN", "change-me-b")},
+    "alice": {"id": "alice", "token": _required_token("ALICE_TOKEN")},
+    "bob": {"id": "bob", "token": _required_token("BOB_TOKEN")},
 }
+
+if len({u["token"] for u in USERS.values()}) != len(USERS):
+    raise RuntimeError("each user must have a distinct token")
 
 NOTES = {
     1: {"id": 1, "owner": "alice", "title": "alice private", "body": "alice secret"},
--- a/tests/test_notes.py
+++ b/tests/test_notes.py
@@ -1,3 +1,8 @@
+import os
+
+os.environ.setdefault("ALICE_TOKEN", "test-token-alice-0123456789")
+os.environ.setdefault("BOB_TOKEN", "test-token-bob-0123456789")
+
 from notesapp import notes
 
 
@@ -8,5 +13,5 @@
 
 
 def test_list_only_own():
-    status, body = notes.list_notes(Req("change-me-a"))
+    status, body = notes.list_notes(Req(os.environ["ALICE_TOKEN"]))
     assert status == 200 and all(n["owner"] == "alice" for n in body)
```

## IDOR: GET /notes/<id> returns any user's note without an owner check

`notesapp` · `idor:notesapp/notes.py:get_note` · high · P1

get_note resolves the caller with current_user and then returns storage.get(int(note_id)) without checking ownership. The resolved `user` is never used. Any authenticated user can read every other user's note (title and body) by iterating the small sequential integer ids. The sibling delete_note handler calls require_owner, which shows the check was intended. The source shows no other control on the path: dispatch only routes, and storage.get has no owner filter. The hunter's sandbox run showed alice's token on GET /notes/2 returning 200 with bob's note.

### Trace

1. **entrypoint** `notesapp/app.py:15` (dispatch): GET /notes/<id> is routed to notes.get_note with the last path segment as note_id. No authorization middleware exists in dispatch.
2. **propagation** `notesapp/notes.py:13` (get_note): current_user authenticates the caller. The result is stored in `user` but never used afterwards.
3. **propagation** `notesapp/notes.py:14` (get_note): storage.get(int(note_id)) fetches any note by id with no owner filter.
4. **sink** `notesapp/notes.py:17` (get_note): Returns 200 with the full note dict (owner, title, body) of another user.

### Evidence

- `notesapp/notes.py:17`: The note is returned without require_owner(user, note).
- `notesapp/notes.py:25`: Sibling delete_note enforces require_owner, so the control exists but is missing from the read path.
- `notesapp/auth.py:23`: require_owner raises AuthError when note.owner != user.id.
- `notesapp/storage.py:12`: Seeded note id 2 belongs to bob and has body 'bob secret'; ids are small sequential integers.
- `README.md:4`: Stated invariant: users must only see and change their own notes.

### Conditions

- authentication_level: The attacker needs a valid bearer token for any user, for example their own account.
- data_state: The target note exists. Ids are small sequential integers, so they are easy to enumerate.

### Intended behavior

GET /notes/<id> returns the note only when note['owner'] equals the authenticated user's id. Otherwise it rejects the request with AuthError, or with a 404 so that note existence is not revealed.

### Reachability

reachable / exploitable_now

### Proof-of-concept test — `fixed`: fails on unchanged code, passes after the patch

`tests/test_get_note_idor.py` — Fails on the current code because alice receives 200 with bob's note. Passes after the patch because AuthError is raised for a non-owned note, while alice can still read her own note 1.

Command: `python3 tests/test_get_note_idor.py`

Original copy (`sbx-00014`): exit 1

```text
.F
======================================================================
FAIL: test_cannot_read_other_users_note (__main__.GetNoteOwnership.test_cannot_read_other_users_note)
----------------------------------------------------------------------
Traceback (most recent call last):
  File "/scratch/src/tests/test_get_note_idor.py", line 22, in test_cannot_read_other_users_note
    self.assertNotEqual(status, 200, "alice read bob's note: %r" % (body,))
    ~~~~~~~~~~~~~~~~~~~^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
AssertionError: 200 == 200 : alice read bob's note: {'id': 2, 'owner': 'bob', 'title': 'bob private', 'body': 'bob secret'}

----------------------------------------------------------------------
Ran 2 tests in 0.001s

FAILED (failures=1)
```

Patched copy (`sbx-00015`): exit 0

```text
..
----------------------------------------------------------------------
Ran 2 tests in 0.000s

OK
```

```python
import os, sys, unittest
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from notesapp import notes, app
from notesapp.auth import AuthError


class Req:
    def __init__(self, token, method="GET", path="/", args=None):
        self.headers = {"Authorization": f"Bearer {token}"}
        self.method = method
        self.path = path
        self.args = args or {}


class GetNoteOwnership(unittest.TestCase):
    def test_cannot_read_other_users_note(self):
        # alice requests bob's note (id 2) via the public dispatcher
        try:
            status, body = app.dispatch(Req("change-me-a", "GET", "/notes/2"))
        except AuthError:
            return
        self.assertNotEqual(status, 200, "alice read bob's note: %r" % (body,))

    def test_can_read_own_note(self):
        status, body = app.dispatch(Req("change-me-a", "GET", "/notes/1"))
        self.assertEqual(status, 200)
        self.assertEqual(body["owner"], "alice")


if __name__ == "__main__":
    unittest.main()

```

### Remediation

Call require_owner(user, note) in get_note before returning the note, matching delete_note. Optionally return 404 for notes the caller does not own, so existence is not leaked.

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

## Path traversal in GET /export lets any authenticated user read arbitrary server files

`notesapp` · `path-traversal:notesapp/notes.py:export_note` · high · P1

export_note builds the file path as os.path.join(storage.EXPORT_DIR, request.args['name']) and opens it with no normalization or containment check. Any authenticated user can send name=/etc/passwd (os.path.join drops the base) or name=../../../etc/passwd and get back the raw bytes of any file the server process can read. For example, /proc/self/environ would expose the other tenant's bearer token and allow account takeover of that tenant. I re-ran the PoC test in the sandbox (sbx-00016) against the unchanged code. The '..' and absolute-path cases both returned a file outside EXPORT_DIR. The source-level path is complete: auth is the only control, and nothing normalizes or validates `name`.

### Trace

1. **entrypoint** `notesapp/app.py:7` (ROUTES): GET /export is routed straight to notes.export_note. dispatch() applies no other filtering.
2. **propagation** `notesapp/notes.py:31` (export_note): current_user only checks that the bearer token is valid. This is the only control on the path.
3. **propagation** `notesapp/notes.py:32` (export_note): `name` is taken directly from request.args, which the client controls.
4. **propagation** `notesapp/notes.py:33` (export_note): os.path.join(EXPORT_DIR, name) is used with no realpath and no containment check. An absolute name replaces EXPORT_DIR, and '..' escapes it.
5. **sink** `notesapp/notes.py:34` (export_note): open(path, 'rb') reads the file, and the next line returns its bytes to the client with status 200.

### Evidence

- `notesapp/notes.py:33`: Unvalidated os.path.join of the base directory and the client-supplied name.
- `notesapp/notes.py:34`: The file is opened, and its contents are returned verbatim at line 35.
- `notesapp/storage.py:3`: EXPORT_DIR (default /var/lib/notesapp/exports) is the intended containment root.
- `notesapp/auth.py:10`: current_user only authenticates the caller. No check is applied to the file path.
- `notesapp/storage.py:6`: Tokens come from env vars (with weak hard-coded fallbacks), so reading /proc/self/environ through this bug exposes the other tenant's token.

### Conditions

- authentication_level: The attacker needs a valid bearer token. Any tenant's token works, and so do the hard-coded defaults change-me-a/change-me-b if the operator never overrode them.
- environmental_dependency: What can be read is limited by the OS permissions of the service process, which the repository does not define.

### Intended behavior

GET /export should only serve files located inside EXPORT_DIR. It should reject absolute names, '..' traversal and symlink escapes.

### Reachability

reachable / exploitable_now

### Proof-of-concept test — `fixed`: fails on unchanged code, passes after the patch

`tests/test_export_traversal.py` — On the current code it exits 1 because the '..' and absolute-path tests return the out-of-directory secret. With the patch it exits 0.

Command: `python3 tests/test_export_traversal.py`

Original copy (`sbx-00017`): exit 1

```text
PASS test_export_in_dir_still_works
FAIL test_export_rejects_dotdot '..' escaped EXPORT_DIR
FAIL test_export_rejects_absolute absolute name escaped EXPORT_DIR
```

Patched copy (`sbx-00018`): exit 0

```text
PASS test_export_in_dir_still_works
PASS test_export_rejects_dotdot
PASS test_export_rejects_absolute
```

```python
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from notesapp import notes, storage


class Req:
    def __init__(self, token, args=None):
        self.headers = {"Authorization": f"Bearer {token}"}
        self.args = args or {}


def _setup():
    root = tempfile.mkdtemp()
    export_dir = os.path.join(root, "exports")
    os.mkdir(export_dir)
    with open(os.path.join(export_dir, "export.txt"), "wb") as fh:
        fh.write(b"ok-export")
    secret = os.path.join(root, "secret.txt")
    with open(secret, "wb") as fh:
        fh.write(b"HOST-SECRET")
    storage.EXPORT_DIR = export_dir
    return secret


def _leaks(name):
    try:
        status, body = notes.export_note(Req("change-me-a", {"name": name}))
    except Exception:
        return False
    return status == 200 and body == b"HOST-SECRET"


def test_export_in_dir_still_works():
    _setup()
    status, body = notes.export_note(Req("change-me-a", {"name": "export.txt"}))
    assert status == 200 and body == b"ok-export"


def test_export_rejects_dotdot():
    _setup()
    assert not _leaks("../secret.txt"), "'..' escaped EXPORT_DIR"


def test_export_rejects_absolute():
    secret = _setup()
    assert not _leaks(secret), "absolute name escaped EXPORT_DIR"


if __name__ == "__main__":
    failed = 0
    for fn in (test_export_in_dir_still_works, test_export_rejects_dotdot, test_export_rejects_absolute):
        try:
            fn()
            print("PASS", fn.__name__)
        except AssertionError as e:
            failed += 1
            print("FAIL", fn.__name__, e)
    sys.exit(1 if failed else 0)

```

### Remediation

Resolve the joined path with os.path.realpath and require that it lies strictly inside realpath(EXPORT_DIR). Reject anything else with a 400. Consider also scoping exports per user (for example EXPORT_DIR/<user id>/).

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
