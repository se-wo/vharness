# Findings detail

Proof-of-concept tests and patches were **not executed** by the harness.

## IDOR: any authenticated user can read any other user's note through GET /notes/<id>

`notesapp` · `idor:notesapp/notes.py:get_note` · high · P1

notes.get_note resolves the caller with current_user but never checks that the requested note belongs to them. Any authenticated user can loop over note ids (small sequential integers) and read every user's private note title and body. delete_note enforces ownership with require_owner and list_notes filters by owner, so this handler alone breaks the isolation the README promises. No other control sits on the path: dispatch in app.py only routes, and storage.get does no owner scoping.

### Trace

1. **entrypoint** `notesapp/app.py:15` (dispatch): GET /notes/<x> goes to notes.get_note with the attacker-controlled last path segment as note_id. No authorization is applied in routing.
2. **propagation** `notesapp/notes.py:13` (get_note): current_user authenticates bob from his token. The returned user is never used again.
3. **propagation** `notesapp/notes.py:14` (get_note): storage.get(int(note_id)) fetches any note by id, with no owner filter.
4. **sink** `notesapp/notes.py:17` (get_note): The full note, including another user's owner/title/body, is returned with status 200.

### Evidence

- `notesapp/notes.py:17`: Returns the note without calling require_owner.
- `notesapp/notes.py:25`: The sibling delete_note calls require_owner(user, note), which shows the intended control.
- `notesapp/auth.py:22`: require_owner exists and raises AuthError when note['owner'] != user['id'].
- `notesapp/storage.py:17`: storage.get returns NOTES.get(note_id) with no owner scoping.
- `notesapp/storage.py:11`: Note 1 belongs to alice and holds the private body 'alice secret'.

### Conditions

- authentication_level: The attacker needs any valid bearer token, i.e. any user account.
- data_state: The target note id exists. Ids are small sequential integers and easy to enumerate.

### Intended behavior

GET /notes/<id> should return the note only when note['owner'] equals the caller's id. Otherwise it should respond the same way as for a missing note (404), so the endpoint does not reveal which ids exist.

### Reachability

reachable / exploitable_now

### Proof-of-concept test (not executed)

`tests/test_get_note_idor.py` — On the current code test_bob_cannot_read_alice_note fails: get_note returns (200, alice's note). After the patch it returns (404, {'error': 'not found'}) and the test passes. test_owner_can_read_own_note passes before and after.

```python
from notesapp import notes


class Req:
    def __init__(self, token, args=None):
        self.headers = {"Authorization": f"Bearer {token}"}
        self.args = args or {}


def test_bob_cannot_read_alice_note():
    # note 1 is owned by alice; bob authenticates with his own token
    status, body = notes.get_note(Req("change-me-b"), "1")
    assert status != 200
    assert not (isinstance(body, dict) and body.get("body") == "alice secret")


def test_owner_can_read_own_note():
    status, body = notes.get_note(Req("change-me-a"), "1")
    assert status == 200 and body["owner"] == "alice"

```

### Remediation

Enforce ownership in get_note. Answer 404 when the note is missing or belongs to someone else, so the endpoint is not an existence oracle. Optionally add a storage helper scoped by owner.

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

## Path traversal in GET /export lets any authenticated user read arbitrary server files

`notesapp` · `path-traversal:notesapp/notes.py:export_note` · high · P1

export_note builds the file path with os.path.join(storage.EXPORT_DIR, request.args.get('name', ...)) and opens it with no normalization or containment check. An absolute name such as '/etc/passwd' makes os.path.join discard EXPORT_DIR. A name with '..' segments climbs out of it. The handler returns the raw file bytes with status 200. The only control on the path is bearer-token authentication, which any user passes. The router (app.py) adds no filtering. Reading /proc/self/environ would disclose ALICE_TOKEN and BOB_TOKEN when the operator set them through the environment, which lets the attacker impersonate other users.

### Trace

1. **entrypoint** `notesapp/app.py:7` (ROUTES[('GET','/export')]): GET /export is routed to notes.export_note. dispatch (line 16) passes the request straight through with no input filtering.
2. **propagation** `notesapp/notes.py:31` (export_note): current_user(request) authenticates the caller by bearer token. This is the only gate, and the result is never used again.
3. **propagation** `notesapp/notes.py:32` (export_note): The client-controlled 'name' is read from request.args with no validation.
4. **propagation** `notesapp/notes.py:33` (export_note): os.path.join(storage.EXPORT_DIR, name): an absolute name replaces the base, and '..' is neither resolved nor checked.
5. **sink** `notesapp/notes.py:34` (export_note): open(path, 'rb') opens the attacker-chosen path. Line 35 returns its bytes to the caller with status 200.

### Evidence

- `notesapp/notes.py:33`: Unvalidated join of client input onto EXPORT_DIR.
- `notesapp/notes.py:35`: File contents are returned to the client.
- `notesapp/storage.py:3`: EXPORT_DIR is the intended confinement root (default /var/lib/notesapp/exports).
- `notesapp/auth.py:17`: Bearer-token comparison is the only control on this path. It does not restrict the file path.
- `notesapp/storage.py:6`: User tokens come from the process environment, with public hardcoded defaults. /proc/self/environ would expose real tokens when they are set.

### Conditions

- authentication_level: The caller needs a valid bearer token for any user, or the hardcoded defaults 'change-me-a'/'change-me-b' if the operator did not override them.
- environmental_dependency: The impact depends on which files the notesapp process can read on the host. Examples are /proc/self/environ, config files and source. The token-theft escalation also requires that the tokens be set via the environment.

### Intended behavior

GET /export should only serve files whose resolved real path is strictly inside the resolved EXPORT_DIR. Absolute names, '..' traversal and symlink escapes should be rejected with a 4xx response.

### Reachability

reachable / exploitable_now

### Proof-of-concept test (not executed)

`tests/test_export_traversal.py` — On the current code, test_export_rejects_dotdot and test_export_rejects_absolute fail because export_note returns (200, b'TOP-SECRET') for a file outside EXPORT_DIR. With the patch both return 400. test_export_allows_file_inside_dir passes before and after the patch.

```python
import os

from notesapp import notes, storage


class Req:
    def __init__(self, token, args=None):
        self.headers = {"Authorization": f"Bearer {token}"}
        self.args = args or {}


def _setup(tmp_path, monkeypatch):
    export_dir = tmp_path / "exports"
    export_dir.mkdir()
    (export_dir / "export.txt").write_bytes(b"ok")
    secret = tmp_path / "secret.txt"
    secret.write_bytes(b"TOP-SECRET")
    monkeypatch.setattr(storage, "EXPORT_DIR", str(export_dir))
    return secret


def test_export_rejects_dotdot(tmp_path, monkeypatch):
    _setup(tmp_path, monkeypatch)
    status, body = notes.export_note(Req("change-me-b", {"name": "../secret.txt"}))
    assert status == 400
    assert body != b"TOP-SECRET"


def test_export_rejects_absolute(tmp_path, monkeypatch):
    secret = _setup(tmp_path, monkeypatch)
    status, body = notes.export_note(Req("change-me-b", {"name": str(secret)}))
    assert status == 400
    assert body != b"TOP-SECRET"


def test_export_allows_file_inside_dir(tmp_path, monkeypatch):
    _setup(tmp_path, monkeypatch)
    status, body = notes.export_note(Req("change-me-b", {"name": "export.txt"}))
    assert status == 200 and body == b"ok"

```

### Remediation

Resolve both the base directory and the joined path with os.path.realpath, then reject the request unless the resolved path is strictly inside the base (os.path.commonpath). This also handles absolute names and symlinks. As an optional extra layer, reject names that are absolute or contain path separators.

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
+    if path == base or os.path.commonpath([base, path]) != base:
+        return 400, {"error": "invalid export name"}
     with open(path, "rb") as fh:
         return 200, fh.read()
```
