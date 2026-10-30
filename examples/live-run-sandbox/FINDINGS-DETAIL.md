# Findings detail

PoC tests were executed by the harness in its sandbox; each section gives the result.

## Hard-coded fallback bearer tokens and empty-token acceptance let anyone authenticate as any user

`notesapp` · `default-credentials:notesapp/storage.py:USERS` · high · P1

storage.USERS reads each user's token with os.environ.get(VAR, 'change-me-x'). If an operator does not set ALICE_TOKEN or BOB_TOKEN, the service accepts the publicly known tokens 'change-me-a' and 'change-me-b', and nothing warns the operator. The repository's own test uses one of them. If a variable is set but empty, the stored token is ''. current_user then strips the 'Bearer ' prefix, gets an empty token, and hmac.compare_digest('', '') returns True. A request carrying only 'Authorization: Bearer ' is then authenticated as that user. Either way, an unauthenticated client takes over the account: it can list and delete the victim's notes and reach the authenticated export endpoint. The source has no deployment config, so whether a given deployment leaves the variables unset is outside the repository. The code defect is that provisioning fails open. Sandbox run sbx-00001 shows the exploit behavior under both conditions.

### Trace

1. **entrypoint** `notesapp/app.py:16` (dispatch): Any HTTP client's request is routed to a handler, for example notes.list_notes for GET /notes. The dispatcher adds no authentication of its own.
2. **propagation** `notesapp/notes.py:8` (list_notes): The handler authenticates the caller only through current_user(request).
3. **propagation** `notesapp/auth.py:15` (current_user): The token is taken verbatim from the header after 'Bearer '. An empty token is allowed.
4. **propagation** `notesapp/storage.py:6` (USERS): The expected token is os.environ.get('ALICE_TOKEN', 'change-me-a'): the hard-coded public default when unset, '' when set empty.
5. **sink** `notesapp/auth.py:17` (current_user): hmac.compare_digest(user['token'], token) matches the public default, or '' against '', and returns the victim user object. The handler then acts as that user.

### Evidence

- `notesapp/storage.py:6`: Fallback token 'change-me-a' for alice when ALICE_TOKEN is unset. An empty env value is accepted as-is.
- `notesapp/storage.py:7`: Fallback token 'change-me-b' for bob when BOB_TOKEN is unset.
- `notesapp/auth.py:13`: The only pre-check is the 'Bearer ' prefix. An empty token is not rejected.
- `notesapp/auth.py:17`: Comparison against the possibly default or empty stored token, with no check that the stored token is configured and non-empty.
- `tests/test_notes.py:11`: The test suite authenticates with the default 'change-me-a', which shows the fallback is the effective default credential.

### Conditions

- system_configuration: ALICE_TOKEN or BOB_TOKEN is unset in the deployed environment (the default token works) or set to an empty string (the empty token works).

### Intended behavior

An account whose token is not configured (unset or empty) must be impossible to log into. An empty presented token must always be rejected. No credential value may live in source.

### Reachability

conditional / exploitable_now

### Proof-of-concept test — `fixed`: fails on unchanged code, passes after the patch

`tests/test_default_credentials.py` — On the current code it exits 1 with AssertionError 'ACCEPTED change-me-a as alice'. After the patch it prints 'ok' and exits 0.

Command: `python3 tests/test_default_credentials.py`

Original copy (`sbx-00010`): exit 1

```text
Traceback (most recent call last):
  File "/scratch/src/tests/test_default_credentials.py", line 44, in <module>
    test_default_tokens_rejected_when_env_unset()
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~^^
  File "/scratch/src/tests/test_default_credentials.py", line 35, in test_default_tokens_rejected_when_env_unset
    assert r.returncode == 0, r.stdout + r.stderr
           ^^^^^^^^^^^^^^^^^
AssertionError: ACCEPTED 'change-me-a' as alice
```

Patched copy (`sbx-00011`): exit 0

```text
ok
```

```python
"""Regression: no publicly known or empty bearer token may authenticate."""
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

PROBE = r'''
import sys
sys.path.insert(0, sys.argv[1])
from notesapp import auth
class Req:
    def __init__(self, token):
        self.headers = {"Authorization": "Bearer " + token}
        self.args = {}
for tok in sys.argv[2:]:
    try:
        u = auth.current_user(Req(tok))
    except auth.AuthError:
        continue
    print("ACCEPTED", repr(tok), "as", u["id"])
    sys.exit(1)
'''


def _run(env_overrides, tokens):
    env = {k: v for k, v in os.environ.items() if k not in ("ALICE_TOKEN", "BOB_TOKEN")}
    env.update(env_overrides)
    return subprocess.run([sys.executable, "-I", "-c", PROBE, ROOT] + tokens,
                          env=env, capture_output=True, text=True)


def test_default_tokens_rejected_when_env_unset():
    r = _run({}, ["change-me-a", "change-me-b"])
    assert r.returncode == 0, r.stdout + r.stderr


def test_empty_token_rejected_when_env_empty():
    r = _run({"ALICE_TOKEN": "", "BOB_TOKEN": ""}, [""])
    assert r.returncode == 0, r.stdout + r.stderr


if __name__ == "__main__":
    test_default_tokens_rejected_when_env_unset()
    test_empty_token_rejected_when_env_empty()
    print("ok")

```

### Remediation

Remove the hard-coded fallback tokens. Treat an unset or empty token as a disabled account. Reject an empty presented token. Compare bytes so non-ASCII input raises AuthError instead of TypeError. Update the existing test to provision its own token through the environment.

```diff
--- a/notesapp/storage.py
+++ b/notesapp/storage.py
@@ -2,9 +2,16 @@
 
 EXPORT_DIR = os.environ.get("NOTES_EXPORT_DIR", "/var/lib/notesapp/exports")
 
+
+def _token(var):
+    """Return the configured token, or None (account disabled) if unset/empty."""
+    value = os.environ.get(var, "")
+    return value or None
+
+
 USERS = {
-    "alice": {"id": "alice", "token": os.environ.get("ALICE_TOKEN", "change-me-a")},
-    "bob": {"id": "bob", "token": os.environ.get("BOB_TOKEN", "change-me-b")},
+    "alice": {"id": "alice", "token": _token("ALICE_TOKEN")},
+    "bob": {"id": "bob", "token": _token("BOB_TOKEN")},
 }
 
 NOTES = {
--- a/notesapp/auth.py
+++ b/notesapp/auth.py
@@ -13,8 +13,14 @@
     if not header.startswith("Bearer "):
         raise AuthError("missing token")
     token = header[len("Bearer "):]
+    if not token:
+        raise AuthError("missing token")
+    presented = token.encode("utf-8", "surrogatepass")
     for user in USERS.values():
-        if hmac.compare_digest(user["token"], token):
+        expected = user["token"]
+        if not expected:
+            continue
+        if hmac.compare_digest(expected.encode("utf-8", "surrogatepass"), presented):
             return user
     raise AuthError("invalid token")
 
--- a/tests/test_notes.py
+++ b/tests/test_notes.py
@@ -1,3 +1,7 @@
+import os
+
+os.environ.setdefault("ALICE_TOKEN", "test-token-alice")
+
 from notesapp import notes
 
 
@@ -8,5 +12,5 @@
 
 
 def test_list_only_own():
-    status, body = notes.list_notes(Req("change-me-a"))
+    status, body = notes.list_notes(Req(os.environ["ALICE_TOKEN"]))
     assert status == 200 and all(n["owner"] == "alice" for n in body)
```

## GET /notes/<id> returns any user's note (missing ownership check in get_note)

`notesapp` · `idor:notesapp/notes.py:get_note` · high · P1

get_note authenticates the caller but never checks that the caller owns the requested note. Note ids are small sequential integers, so any authenticated user can enumerate /notes/1, /notes/2, ... and read other users' private title and body. The sibling delete_note enforces require_owner and list_notes filters by owner. get_note is the only note-access path without per-owner isolation. No middleware, decorator or dispatch-level check compensates: dispatch routes straight to the handler.

### Trace

1. **entrypoint** `notesapp/app.py:15` (dispatch): Any path /notes/<x> is routed to get_note with the client-controlled x as note_id; no authorization happens in dispatch
2. **propagation** `notesapp/notes.py:13` (get_note): The caller is authenticated via current_user, but the resolved user is never used afterwards
3. **propagation** `notesapp/notes.py:14` (get_note): The client-supplied id is parsed and looked up with no owner filter
4. **sink** `notesapp/notes.py:17` (get_note): The full note dict, including another owner's body, is returned with status 200

### Evidence

- `notesapp/notes.py:17`: Returns the note without calling require_owner or comparing note owner to user id
- `notesapp/notes.py:25`: Sibling delete_note calls require_owner, showing the intended control
- `notesapp/auth.py:22`: require_owner exists but get_note does not use it
- `README.md:4`: States users must only see and change their own notes
- `notesapp/storage.py:11`: Note ids are sequential small integers (1, 2), so they are trivially enumerable; storage.get has no owner filter (line 16-17)

### Conditions

- authentication_level: The attacker needs any valid bearer token (any authenticated user)
- data_state: The target note exists. Ids are sequential integers and easy to guess.

### Intended behavior

GET /notes/<id> returns a note only to its owner. Other users should get the same response as for a nonexistent note (404) or a 403.

### Reachability

reachable / exploitable_now

### Proof-of-concept test — `fixed`: fails on unchanged code, passes after the patch

`tests/test_get_note_idor.py` — On current code bob gets (200, alice's note), so the assertion fails and the script exits non-zero. With the patch bob gets 404 and the script prints 'ok' and exits 0.

Command: `python3 tests/test_get_note_idor.py`

Original copy (`sbx-00013`): exit 1

```text
Traceback (most recent call last):
  File "/scratch/src/tests/test_get_note_idor.py", line 32, in <module>
    test_get_note_rejects_other_owner()
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~^^
  File "/scratch/src/tests/test_get_note_idor.py", line 21, in test_get_note_rejects_other_owner
    assert status in (403, 404), (status, body)
           ^^^^^^^^^^^^^^^^^^^^
AssertionError: (200, {'id': 1, 'owner': 'alice', 'title': 'alice private', 'body': 'alice secret'})
```

Patched copy (`sbx-00014`): exit 0

```text
ok
```

```python
import sys, os
sys.path.insert(0, os.getcwd())
from notesapp import app, notes, storage
from notesapp.auth import AuthError


class Req:
    def __init__(self, token, method="GET", path="/", args=None):
        self.headers = {"Authorization": f"Bearer {token}"}
        self.method = method
        self.path = path
        self.args = args or {}


def test_get_note_rejects_other_owner():
    bob_token = storage.USERS["bob"]["token"]
    try:
        status, body = app.dispatch(Req(bob_token, "GET", "/notes/1"))
    except AuthError:
        return
    assert status in (403, 404), (status, body)
    assert not (isinstance(body, dict) and body.get("body") == "alice secret"), body


def test_get_note_allows_owner():
    status, body = app.dispatch(Req(storage.USERS["alice"]["token"], "GET", "/notes/1"))
    assert status == 200 and body["owner"] == "alice"


if __name__ == "__main__":
    test_get_note_allows_owner()
    test_get_note_rejects_other_owner()
    print("ok")

```

### Remediation

Enforce ownership in get_note. Treat a non-owned note the same as a missing one (404) so ids do not become an existence oracle. Alternatively call require_owner, as delete_note does.

```diff
--- a/notesapp/notes.py
+++ b/notesapp/notes.py
@@ -12,6 +12,6 @@ def list_notes(request):
 def get_note(request, note_id):
     user = current_user(request)
     note = storage.get(int(note_id))
-    if note is None:
+    if note is None or note["owner"] != user["id"]:
         return 404, {"error": "not found"}
     return 200, note
```
