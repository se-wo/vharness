# Needs validation

These are source-grounded leads with an unresolved, decisive fact. They have no severity.

## Hard-coded fallback bearer tokens (and empty-token acceptance) authenticate anonymous clients as alice/bob when env vars are unset or empty

`notesapp` · `auth:notesapp/storage.py:USERS:default-or-empty-token-fallback`

storage.USERS reads each user's token with os.environ.get(<VAR>, '<public default>'). current_user() takes everything after 'Bearer ' as the token and compares it to each stored token with hmac.compare_digest. Nothing checks that a configured token is non-default, non-empty or unique, and there is no fail-closed startup check. If ALICE_TOKEN is unset, 'Authorization: Bearer change-me-a' authenticates as alice (the repo's own test uses this value). If ALICE_TOKEN is set to the empty string, 'Authorization: Bearer ' gives token == '' and compare_digest('', '') is True. Either case gives an unauthenticated client the user's scope: list notes, delete owned notes, and use /export. Source review found no other control on the path. All four handlers call current_user first, the line numbers and descriptions in the candidate's trace and evidence match the source, and the repo has no deployment config. Whether this is exploitable depends only on how production sets the two env vars, so the verdict is needs_validation.

**Claimed root cause:** Credential configuration is not validated: storage.USERS silently falls back to public hard-coded tokens and accepts empty tokens. current_user then authenticates any presented token equal to that configured value, including '' and the published defaults.

**Trace:**
- entrypoint `notesapp/app.py:11`: Any client's request reaches dispatch, and every route is reachable over HTTP
- propagation `notesapp/notes.py:8`: The handler resolves identity only via current_user(request)
- propagation `notesapp/auth.py:15`: The token is taken verbatim after 'Bearer ' and can be empty. Nothing checks for an empty or default token
- propagation `notesapp/storage.py:6`: alice's token falls back to the public literal 'change-me-a', or is '' if ALICE_TOKEN is set to empty (bob: line 7, 'change-me-b')
- sink `notesapp/auth.py:17`: hmac.compare_digest(user['token'], token) matches the known default or the empty string and returns the user record

**Blockers:**
- Whether production sets ALICE_TOKEN and BOB_TOKEN to strong, non-empty, distinct secrets. The repository has no deployment config, IaC or env files.
- Whether the HTTP server or middleware in front of dispatch (not in the repo) strips or rejects an 'Authorization: Bearer ' header with an empty token before it reaches current_user.

**Local plan:** In a fresh interpreter with ALICE_TOKEN and BOB_TOKEN unset, run notes.list_notes(Req('change-me-a')) using the Req class from tests/test_notes.py and confirm it returns alice's notes. Then in a separate process set ALICE_TOKEN='' before importing notesapp and confirm notes.list_notes(Req('')) (header 'Bearer ') returns alice's notes. Expected on current code: both succeed.

**Deployment plan:** Owner-observed only. Check the deployment's process environment or secret manager to confirm ALICE_TOKEN and BOB_TOKEN are set, non-empty, distinct, and not 'change-me-a'/'change-me-b'. Alternatively, as owner, send one GET /notes to a staging instance with 'Authorization: Bearer change-me-a' and confirm it is rejected. Also send 'Authorization: Bearer ' through the real front end to see whether it reaches current_user.

## sync_export passes a remote-server-controlled filename unvalidated to export_note with the user's bearer token

`notesclient` · `confused-deputy:client/sync.py:sync_export`

sync_export (client/sync.py:11-13) puts filename_from_server into Request.args['name']. The comment at line 12 says this value comes from a remote server response. It then calls notesapp.notes.export_note in-process, and the Request carries the user's token as a Bearer Authorization header (line 7). The client does not validate, normalize, or allowlist the name. The repository holds only client/sync.py and an empty README, so no other control exists on the path. Whether this is exploitable depends on notesapp.notes.export_note, which is not in the repository. If it joins 'name' to a filesystem path, or looks the note up without an ownership check against the token, a malicious server could pick which file or note is exported or overwritten. If export_note confines the name to the token owner's notes, the issue does not exist. The source cannot settle this.

**Claimed root cause:** The client sends an untrusted, server-chosen resource selector to a privileged export handler using the user's credentials, with no client-side validation. Exploitability depends on export_note lacking path confinement or owner checks.

**Trace:**
- entrypoint `client/sync.py:11`: filename_from_server arrives from the remote server response (comment at line 12) together with the user's token.
- propagation `client/sync.py:8`: The name is stored unchanged as args['name']. The bearer token goes into the Authorization header at line 7.
- sink `client/sync.py:13`: export_note(Request(token, filename_from_server)) runs in-process. Its handling of args['name'] is external and not visible.

**Blockers:**
- The source of notesapp.notes.export_note is not in the repository. It is unknown whether request.args['name'] is joined to a filesystem path (traversal via '../' or an absolute path), used as a cross-user lookup key, or checked against the token owner.
- It is unknown whether export_note reads (disclosure) or writes (overwrite) a name-derived path.
- The installed notesapp version is unknown because there is no dependency manifest.
- It is unknown whether the real caller of sync_export fetches the filename over an authenticated channel. That determines whether an attacker can control the server response.

**Local plan:** Get the notesapp source at the version deployed alongside notesclient. Read export_note to find where request.args['name'] reaches os.path.join, open, or a storage lookup, and whether it checks ownership against the user resolved from the Authorization header. In a scratch environment with two users, A and B, call sync_export(token_A, '../B/secret'), sync_export(token_A, '/etc/passwd'), and sync_export(token_A, '<B note id>'). Check whether any of them returns or writes data outside user A's notes.

**Deployment plan:** The owner confirms which notesapp version is installed and whether the sync server channel is authenticated (TLS, pinning), so the attacker precondition (control of the server response) can be judged.
