# Security audit report

## 1. Run

> **This is a partial pass.** Status: `incomplete`. Reason: hunt_budget_exhausted.

- Run: `run-20261030-232722-dead66`; status `incomplete`
- Profile: `standard`; scope: whole repository
- Budget: 30 invocations per target; USD cap: 12.0
- Discovery model: `claude-opus-5-5`; validation model: `claude-sonnet-5-5`
- Execution: **sandboxed** (start test passed: no network, empty environment, read-only target, tmpfs scratch, new uid, no new privileges; 120s wall, 60s CPU, 2048 MB memory, 128 processes, 512 MB disk). 41 sandbox runs recorded. PoC tests were run by the harness (see PoC column).
- Prior run used: none

| Target | Root | Commit |
|---|---|---|
| notesapp | `tests/fixtures/notesapp` | `unknown` |

## 2. Summary

3 confirmed vulnerabilities (3 high), 0 leads that need validation, 0 candidates rejected.

## 3. Confirmed vulnerabilities

| Priority | Severity | Exposure | PoC | Evidence | Target | Title | Boundary |
|---|---|---|---|---|---|---|---|
| P1 | high | exploitable_now | fixed | source | notesapp | Hard-coded fallback bearer tokens (and accepted empty tokens) authenticate as any user when env vars are unset | Anonymous client to authenticated user (bearer-token authentication in current_user) |
| P1 | high | exploitable_now | fixed | source | notesapp | IDOR: GET /notes/<id> returns any user's note without an owner check | User to another user's note (read) |
| P1 | high | exploitable_now | fixed | source | notesapp | Path traversal in GET /export lets any authenticated user read arbitrary server files | HTTP request parameter to the server filesystem: the client should only be able to read files inside EXPORT_DIR |

## 4. Details

### [P1] Hard-coded fallback bearer tokens (and accepted empty tokens) authenticate as any user when env vars are unset
`notesapp` · fingerprint `default-credential:notesapp/storage.py:USERS` · severity **high** (likelihood medium, impact high) · confidence high

- **Attacker:** An anonymous HTTP client who can read the public source code or guess the 'change-me-*' convention (starting with: Can send requests to any route in ROUTES (app.py:12 says every route is reachable over HTTP). Has no credentials.)
- **Boundary / broken assumption:** Anonymous client to authenticated user (bearer-token authentication in current_user) / Bearer tokens are secrets that only the operator provisions. If ALICE_TOKEN or BOB_TOKEN is unset, the service silently accepts the public tokens 'change-me-a' and 'change-me-b'. If a variable is set but empty, it accepts an empty bearer string.
- **Affected resource:** The accounts of alice and bob: reading and deleting their notes, plus authenticated access to GET /export
- **Entry → sink:** `notesapp/app.py:11` → `notesapp/auth.py:17`
- **Reachability:** conditional; exposure exploitable_now
- **Root cause:** storage.py derives user credentials from os.environ.get with hard-coded public defaults and never validates the result (non-empty, minimum strength, distinct per user). current_user trusts USERS without question, so a missing or empty configuration becomes a known or empty credential instead of a startup failure.
- **Fix:** Remove the hard-coded defaults. At import or startup, require each token env var to be set to a secret of at least 16 characters, and require tokens to be distinct across users. Fail closed with RuntimeError otherwise. Update the existing test to supply its own tokens through the environment.
- **PoC (harness-run):** `fixed`: fails on unchanged code, passes after the patch

### [P1] IDOR: GET /notes/<id> returns any user's note without an owner check
`notesapp` · fingerprint `idor:notesapp/notes.py:get_note` · severity **high** (likelihood high, impact high) · confidence high

- **Attacker:** Authenticated low-privilege user (for example alice) who holds a valid bearer token (starting with: Can send GET /notes/<id> with their own valid Authorization: Bearer token and any integer id)
- **Boundary / broken assumption:** User to another user's note (read) / Users must only see their own notes (README.md:4). get_note authenticates the caller but never authorizes ownership.
- **Affected resource:** Title and body of every other user's note, including the seeded 'bob secret' note (id 2)
- **Entry → sink:** `notesapp/app.py:15` → `notesapp/notes.py:17`
- **Reachability:** reachable; exposure exploitable_now
- **Root cause:** get_note in notesapp/notes.py performs authentication only and omits the require_owner authorization check that delete_note applies before acting on the note.
- **Fix:** Call require_owner(user, note) in get_note before returning the note, matching delete_note. Optionally return 404 for notes the caller does not own, so existence is not leaked.
- **PoC (harness-run):** `fixed`: fails on unchanged code, passes after the patch

### [P1] Path traversal in GET /export lets any authenticated user read arbitrary server files
`notesapp` · fingerprint `path-traversal:notesapp/notes.py:export_note` · severity **high** (likelihood high, impact high) · confidence high

- **Attacker:** An authenticated low-trust user (alice or bob), or any HTTP client holding a valid bearer token, including the hard-coded defaults change-me-a/change-me-b if the operator never set ALICE_TOKEN or BOB_TOKEN (starting with: Can send GET /export with a chosen `name` query argument)
- **Boundary / broken assumption:** HTTP request parameter to the server filesystem: the client should only be able to read files inside EXPORT_DIR / export_note assumes `name` is a plain filename under EXPORT_DIR. os.path.join does not enforce that: an absolute name replaces the base, and '..' segments climb out of it.
- **Affected resource:** Any host file the service process can read, such as /etc/passwd, /proc/self/environ (which contains ALICE_TOKEN and BOB_TOKEN when they are set via env), application source, and other tenants' export files
- **Entry → sink:** `notesapp/app.py:7` → `notesapp/notes.py:34`
- **Reachability:** reachable; exposure exploitable_now
- **Root cause:** export_note treats a client-controlled `name` as a path component and passes os.path.join(EXPORT_DIR, name) to open() without resolving the result or checking that it stays inside EXPORT_DIR.
- **Fix:** Resolve the joined path with os.path.realpath and require that it lies strictly inside realpath(EXPORT_DIR). Reject anything else with a 400. Consider also scoping exports per user (for example EXPORT_DIR/<user id>/).
- **PoC (harness-run):** `fixed`: fails on unchanged code, passes after the patch

## 5. Needs validation (no severity)

None.

## 6. Hardening notes (not vulnerabilities)

- (notesapp) The existing test suite has only a positive test for list_notes. Add negative cross-user tests for get, delete and export so missing owner checks are caught.
- (notesapp) dispatch does not handle int(note_id) ValueError, unknown-route KeyError or AuthError. Map them to 400/404/401/403 so the server does not return 500s or leak tracebacks, depending on the HTTP binding.
- (notesapp) get_note and delete_note return 404 for a missing id before the ownership check, and AuthError for an existing note owned by someone else. Together with sequential integer ids, this lets a user tell whether other users' notes exist. Consider returning the same 404 for both cases.
- (notesapp) export_note reads whole files into memory with no size cap (fh.read()). Device or very large files reachable inside EXPORT_DIR could exhaust memory. Consider a size limit and regular-file check (os.path.isfile).
- (notesapp) export_note does not handle a missing file or a directory name (FileNotFoundError/IsADirectoryError), and dispatch does not map exceptions to HTTP statuses. Return a 404 instead of an unhandled exception, which may leak paths depending on the server layer.
- (notesapp) export_note resolves `user` but never uses it. All tenants share one EXPORT_DIR namespace, so alice can read any export file bob produces there. Scope exports per user (for example EXPORT_DIR/<user id>/) once the intended export semantics are defined.
- (notesapp) Add startup validation (or at least a loud warning) when ALICE_TOKEN/BOB_TOKEN are missing, and document the required env vars in README.md.
- (notesapp) notesapp/app.py:15: authentication is done per handler rather than centrally in dispatch. Any future route added without current_user would be unauthenticated. Consider enforcing authentication in dispatch.
- (notesapp) notesapp/app.py:11-16: dispatch does not map AuthError, KeyError (unknown route/method) or ValueError (non-integer note id from int() in notes.py:14,22) to HTTP statuses. Whether stack traces or internal paths reach clients depends on the server wrapper, which is not in the repository. Add explicit 401/403/404/400 mapping in dispatch.
- (notesapp) notesapp/auth.py:17: hmac.compare_digest on str raises TypeError for non-ASCII bearer tokens (sbx-00003), so a malformed header yields an unhandled exception instead of AuthError. It is still rejected (no bypass). Compare utf-8 bytes, which the candidate patch includes.
- (notesapp) notesapp/storage.py:3: NOTES_EXPORT_DIR silently defaults to /var/lib/notesapp/exports. Consider requiring explicit configuration, in the same way the token fix does.
- (notesapp) notesapp/app.py:14-16: unknown routes raise KeyError, and non-numeric ids raise ValueError from int() after authentication. Neither is mapped to 404 or 400. No exception-to-response mapping exists, so whether internals leak depends on the server binding, which is not in the repository.
- (notesapp) notesapp/auth.py:15: the scheme check is case-sensitive ('Bearer ') and the token is not stripped. This is not a bypass, but RFC 6750 clients that send 'bearer' will be rejected. Also reject an empty token explicitly in current_user as defense in depth, independent of the configuration validation.
- (notesapp) notesapp/auth.py:16-18: the loop returns as soon as a user matches, and compare_digest leaks only length. Timing could reveal which slot matched or the token length, which is negligible with long random tokens. Consider comparing against all users and choosing the result afterwards, or using a dict keyed by a token hash.
- (notesapp) notesapp/auth.py:13-17: hmac.compare_digest raises TypeError when the presented token contains non-ASCII characters (verified in sbx-00006). This fails closed, but the exception is unhandled. Compare bytes instead (token.encode() against user['token'].encode()) and map the failure to AuthError so the server returns a clean 401 rather than an unhandled 500.
- (notesapp) notesapp/app.py:11-16: dispatch never maps any exception (AuthError included) to an HTTP status. Add a central handler in dispatch that turns AuthError into 401/403, lookup and parse errors into 400/404, and everything else into a generic 500, so stack traces and exception text do not leak.
- (notesapp) notesapp/notes.py:14,22: int(note_id) raises ValueError on non-numeric, empty or over-4300-digit ids. Validate with str.isdecimal() plus a length cap (or catch ValueError) and return 400/404.
- (notesapp) notesapp/auth.py:15-17: hmac.compare_digest on str raises TypeError for non-ASCII tokens. Encode both sides first (token.encode('utf-8'), user['token'].encode('utf-8')) so malformed tokens get the consistent AuthError/401 path.
- (notesapp) notesapp/app.py:15-16: dispatch indexes ROUTES directly, so unknown routes raise KeyError. Use ROUTES.get(...) and return (404/405, error) so that unknown routes don't show up as 500s or reach the server's generic exception handler.
- (notesapp) notesapp/notes.py:14,22: int(note_id) on a client-supplied path segment raises ValueError for non-numeric input or for more than 4300 digits (CPython int-conversion limit). Validate with str.isdigit()/a length cap and return 400/404.
- (notesapp) notesapp/app.py:15-16: unknown (method, path) raises KeyError, and dispatch has no top-level handler that maps AuthError/KeyError/ValueError to 401/404/400. Add explicit route lookup with a 404/405 response and an exception-to-status mapping in dispatch.
- (notesapp) notesapp/auth.py:17: hmac.compare_digest(str, str) raises TypeError for non-ASCII tokens (a WSGI latin-1-decoded header such as 'Bearer \xe9'). The request then fails with an unexpected exception rather than AuthError, which can turn into a 500 or bypass AuthError->401 mapping. Fix: compare bytes, e.g. hmac.compare_digest(user['token'].encode(), token.encode('utf-8', 'surrogateescape')), or catch TypeError and raise AuthError('invalid token').

## 7. Coverage

| Target | covered | candidate | blocked | deferred | out_of_scope | planned | total |
|---|---|---|---|---|---|---|---|
| notesapp | 2 | 8 | 0 | 33 | 0 | 0 | 43 |

Gaps (blocked or deferred units):
- `notesapp` Repository-shipped agent hooks and instruction file / agent/IDE workspace trust before running repo-defined hooks (no control in repo) / CUSTOM#Repo-planted agent hooks and instructions: budget
- `notesapp` Repository-shipped agent hooks and instruction file / agent/IDE workspace trust before running repo-defined hooks (no control in repo) / SUPPLY-CHAIN-AND-RELEASE.md#Untrusted code in a privileged workflow: budget
- `notesapp` GET /export?name= / HTTP request parameter -> server filesystem / ATTACK-CLASSES.md#Wildcard: budget
- `notesapp` GET /notes/<id> read / User -> other user's note (read) / ATTACK-CLASSES.md#Wildcard: budget
- `notesapp` DELETE /notes/<id> delete note / bearer-token authentication / ATTACK-CLASSES.md#Access control: budget
- `notesapp` DELETE /notes/<id> delete note / bearer-token authentication / DATA-ISOLATION-AND-LIFECYCLE.md#Enumeration and aggregate oracles: budget
- `notesapp` DELETE /notes/<id> delete note / bearer-token authentication / WEB-PROTOCOL-AND-AUTH.md#Ordinary CSRF: budget
- `notesapp` DELETE /notes/<id> delete note / per-note owner check / ATTACK-CLASSES.md#Access control: budget
- `notesapp` DELETE /notes/<id> delete note / per-note owner check / DATA-ISOLATION-AND-LIFECYCLE.md#Enumeration and aggregate oracles: budget
- `notesapp` DELETE /notes/<id> delete note / per-note owner check / WEB-PROTOCOL-AND-AUTH.md#Ordinary CSRF: budget
- `notesapp` GET /export file export by name / bearer-token authentication / ATTACK-CLASSES.md#Access control: budget
- `notesapp` GET /export file export by name / bearer-token authentication / ATTACK-CLASSES.md#Resource and file handling: budget
- `notesapp` GET /export file export by name / bearer-token authentication / DATA-ISOLATION-AND-LIFECYCLE.md#Export and backup scope expansion: budget
- `notesapp` GET /export file export by name / bearer-token authentication / RESOURCE-EXHAUSTION-AND-AVAILABILITY.md#Unbounded buffering and cardinality: budget
- `notesapp` GET /export file export by name / export directory confinement (os.path.join on EXPORT_DIR, no normalization or owner scoping) / ATTACK-CLASSES.md#Access control: budget
- `notesapp` GET /export file export by name / export directory confinement (os.path.join on EXPORT_DIR, no normalization or owner scoping) / ATTACK-CLASSES.md#Resource and file handling: budget
- `notesapp` GET /export file export by name / export directory confinement (os.path.join on EXPORT_DIR, no normalization or owner scoping) / DATA-ISOLATION-AND-LIFECYCLE.md#Export and backup scope expansion: budget
- `notesapp` GET /export file export by name / export directory confinement (os.path.join on EXPORT_DIR, no normalization or owner scoping) / RESOURCE-EXHAUSTION-AND-AVAILABILITY.md#Unbounded buffering and cardinality: budget
- `notesapp` GET /notes/<id> read single note / bearer-token authentication / ATTACK-CLASSES.md#Access control: budget
- `notesapp` GET /notes/<id> read single note / bearer-token authentication / CUSTOM#Sibling-handler owner-check drift: budget
- `notesapp` GET /notes/<id> read single note / bearer-token authentication / DATA-ISOLATION-AND-LIFECYCLE.md#Missing tenant or owner enforcement: budget
- `notesapp` GET /notes/<id> read single note / bearer-token authentication / RESOURCE-EXHAUSTION-AND-AVAILABILITY.md#Reachable fatal error or deadlock: budget
- `notesapp` GET /notes/<id> read single note / per-note owner check (present on delete_note, not called in get_note) / ATTACK-CLASSES.md#Access control: budget
- `notesapp` GET /notes/<id> read single note / per-note owner check (present on delete_note, not called in get_note) / CUSTOM#Sibling-handler owner-check drift: budget
- `notesapp` GET /notes/<id> read single note / per-note owner check (present on delete_note, not called in get_note) / DATA-ISOLATION-AND-LIFECYCLE.md#Missing tenant or owner enforcement: budget
- `notesapp` GET /notes/<id> read single note / per-note owner check (present on delete_note, not called in get_note) / RESOURCE-EXHAUSTION-AND-AVAILABILITY.md#Reachable fatal error or deadlock: budget
- `notesapp` GET /notes list own notes / bearer-token authentication / ATTACK-CLASSES.md#Access control: budget
- `notesapp` GET /notes list own notes / bearer-token authentication / DATA-ISOLATION-AND-LIFECYCLE.md#Policy and query disagreement: budget
- `notesapp` GET /notes list own notes / owner-filtered query / ATTACK-CLASSES.md#Access control: budget
- `notesapp` GET /notes list own notes / owner-filtered query / DATA-ISOLATION-AND-LIFECYCLE.md#Policy and query disagreement: budget
- `notesapp` Bearer token authentication when ALICE_TOKEN or BOB_TOKEN is set but empty / Anonymous client -> authenticated user (bearer token authentication) / ATTACK-CLASSES.md#Wildcard: budget
- `notesapp` Environment configuration (NOTES_EXPORT_DIR, ALICE_TOKEN, BOB_TOKEN) / process environment set by operator / ATTACK-CLASSES.md#Cryptography and secrets: budget
- `notesapp` Environment configuration (NOTES_EXPORT_DIR, ALICE_TOKEN, BOB_TOKEN) / process environment set by operator / CUSTOM#Default credential fallback from env: budget

Hunt waves: 2. Each run adds coverage; one run does not exhaust a target.

## 8. Wishlist

- (notesapp, asked by 2 agent(s)) **The production HTTP server / WSGI or ASGI binding and its worker/supervisor configuration that calls notesapp.app.dispatch**: unblocks Upgrading the unhandled-exception hardening notes to a shared-availability candidate (or ruling it out)
- (notesapp, asked by 1 agent(s)) **The HTTP server or WSGI binding and the production deployment environment (how ALICE_TOKEN and BOB_TOKEN are provisioned)**: unblocks Turns the default-credential likelihood into a deployment fact, and settles whether error responses leak stack traces or internal paths.
- (notesapp, asked by 1 agent(s)) **Deployment configuration (process env / service unit / container spec) showing whether ALICE_TOKEN and BOB_TOKEN are set to non-empty, non-default values**: unblocks Whether the default-credential candidate is exploitable in a specific production environment right now
- (notesapp, asked by 1 agent(s)) **The HTTP server/WSGI wrapper that calls dispatch()**: unblocks Assessment of error-response leakage and of how Authorization headers are normalized before current_user
- (notesapp, asked by 1 agent(s)) **The deployment's service user and filesystem permissions, plus whether /proc is mounted in the container**: unblocks A more precise impact assessment of path-traversal:notesapp/notes.py:export_note

## 9. Cost

| Role | Model | Invocations | OK | Input tokens | Output tokens | USD |
|---|---|---|---|---|---|---|
| critic | claude-opus-5-5 | 2 | 2 | 130830 | 5323 | 0.441 |
| dedup | claude-opus-5-5 | 2 | 2 | 27001 | 1419 | 0.099 |
| fixer | claude-sonnet-5-5 | 3 | 3 | 199576 | 13789 | 0.347 |
| hunter | claude-opus-5-5 | 6 | 6 | 512842 | 57901 | 2.004 |
| recon | claude-opus-5-5 | 3 | 3 | 81871 | 12190 | 0.446 |
| tracer | claude-opus-5-5 | 3 | 3 | 89547 | 6145 | 0.302 |
| validator | claude-sonnet-5-5 | 4 | 4 | 162949 | 18269 | 0.363 |
| verifier | claude-sonnet-5-5 | 3 | 3 | 66798 | 2676 | 0.123 |

Total: $4.125

## 10. Fixes (review required; vharness never merges)

Each fix is a `git am`-ready patch in `fixes/`. A person must review every fix before it is merged (R-FIX-12).

| Result | Target | Record | Reason | Patch file |
|---|---|---|---|---|
| needs_human | notesapp | Hard-coded fallback bearer tokens (and accepted empty tokens) authenticate as any user when env vars are unset | patch changes existing test files: tests/conftest.py (R-FIX-04) | `fixes/0003-needs_human-default-credential-notesapp-storage-py-USERS.patch` |
| accepted | notesapp | IDOR: GET /notes/<id> returns any user's note without an owner check | gate passed: the test fails before and passes after the patch; the suite passes | `fixes/0001-accepted-idor-notesapp-notes-py-get-note.patch` |
| accepted | notesapp | Path traversal in GET /export lets any authenticated user read arbitrary server files | gate passed: the test fails before and passes after the patch; the suite passes | `fixes/0002-accepted-path-traversal-notesapp-notes-py-export-note.patch` |

Combined gate for `notesapp` (R-FIX-13): **ok**: all accepted fixes apply together and every regression test and suite passes. Each patch is made against the unchanged commit; review each on its own branch.
