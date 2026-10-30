# Security audit report

## 1. Run

> **This is a partial pass.** Status: `incomplete`. Reason: hunt_budget_exhausted.

- Run: `run-20261030-230610-6d04c0`; status `incomplete`
- Profile: `standard`; scope: whole repository
- Budget: 24 invocations per target; USD cap: 10.0
- Discovery model: `claude-opus-5-5`; validation model: `claude-sonnet-5-5`
- Execution: **sandboxed** (start test passed: no network, empty environment, read-only target, tmpfs scratch, new uid, no new privileges; 120s wall, 60s CPU, 2048 MB memory, 128 processes, 512 MB disk). 14 sandbox runs recorded. PoC tests were run by the harness (see PoC column).
- Prior run used: none

| Target | Root | Commit |
|---|---|---|
| notesapp | `tests/fixtures/notesapp` | `unknown` |

## 2. Summary

2 confirmed vulnerabilities (2 high), 0 leads that need validation, 0 candidates rejected.

## 3. Confirmed vulnerabilities

| Priority | Severity | Exposure | PoC | Evidence | Target | Title | Boundary |
|---|---|---|---|---|---|---|---|
| P1 | high | exploitable_now | fixed | source | notesapp | Hard-coded fallback bearer tokens and empty-token acceptance let anyone authenticate as any user | Unauthenticated client -> authenticated user identity (current_user) |
| P1 | high | exploitable_now | fixed | source | notesapp | GET /notes/<id> returns any user's note (missing ownership check in get_note) | User A -> User B note read (per-owner isolation) |

## 4. Details

### [P1] Hard-coded fallback bearer tokens and empty-token acceptance let anyone authenticate as any user
`notesapp` · fingerprint `default-credentials:notesapp/storage.py:USERS` · severity **high** (likelihood medium, impact high) · confidence medium

- **Attacker:** Any HTTP client who can reach dispatch() and has read the public source or test fixture (starting with: Can send arbitrary requests with an Authorization header. Knows the literal strings 'change-me-a' and 'change-me-b' from notesapp/storage.py and tests/test_notes.py.)
- **Boundary / broken assumption:** Unauthenticated client -> authenticated user identity (current_user) / Bearer tokens are operator-provisioned secrets. The code instead silently uses publicly known fallback tokens when the variables are unset, and accepts an empty token when a variable is set to ''.
- **Affected resource:** Every user account (alice, bob): all of their private notes (read via GET /notes) and deletion authority over them (DELETE /notes/<id>), plus the authenticated-only GET /export surface
- **Entry → sink:** `notesapp/app.py:16` → `notesapp/auth.py:17`
- **Reachability:** conditional; exposure exploitable_now
- **Root cause:** Credential provisioning fails open. storage.USERS substitutes hard-coded, publicly known tokens when the env vars are missing and keeps empty values. current_user never checks that the expected token is configured and non-empty, or that the presented token is non-empty.
- **Fix:** Remove the hard-coded fallback tokens. Treat an unset or empty token as a disabled account. Reject an empty presented token. Compare bytes so non-ASCII input raises AuthError instead of TypeError. Update the existing test to provision its own token through the environment.
- **PoC (harness-run):** `fixed`: fails on unchanged code, passes after the patch

### [P1] GET /notes/<id> returns any user's note (missing ownership check in get_note)
`notesapp` · fingerprint `idor:notesapp/notes.py:get_note` · severity **high** (likelihood high, impact high) · confidence high

- **Attacker:** Authenticated user of notesapp (e.g. bob) (starting with: A valid bearer token for their own account; can send GET /notes/<id> with arbitrary integer ids)
- **Boundary / broken assumption:** User A -> User B note read (per-owner isolation) / The README invariant that users may only see their own notes; get_note assumes authentication implies authorization
- **Affected resource:** Title and body of every other user's notes in storage.NOTES
- **Entry → sink:** `notesapp/app.py:15` → `notesapp/notes.py:17`
- **Reachability:** reachable; exposure exploitable_now
- **Root cause:** notes.get_note resolves the caller with current_user but drops the result and never calls require_owner (or filters by owner) before returning storage.get(id).
- **Fix:** Enforce ownership in get_note. Treat a non-owned note the same as a missing one (404) so ids do not become an existence oracle. Alternatively call require_owner, as delete_note does.
- **PoC (harness-run):** `fixed`: fails on unchanged code, passes after the patch

## 5. Needs validation (no severity)

None.

## 6. Hardening notes (not vulnerabilities)

- (notesapp) get_note returns the live storage dict object (notesapp/notes.py:17). If a serializer or caller mutates it, the stored note changes. Return a copy or a serialized view.
- (notesapp) get_note and delete_note call int(note_id) on the raw path segment with no error handling (notesapp/notes.py:14,22). A non-numeric id raises an uncaught ValueError. Validate the id and map the error to 400/404.
- (notesapp) delete_note returns 404 for a missing id but raises AuthError (forbidden) for an existing note owned by someone else (notesapp/notes.py:23-25). This lets a user tell which note ids exist. Return the same 404 for non-owned notes.
- (notesapp) There is no .gitignore in the repository. Add one that covers .env files and export data, so operator token files are not committed by accident.
- (notesapp) Static shared bearer tokens have no expiry, rotation or revocation, so a leaked token is valid until the environment is changed and the process restarted.
- (notesapp) There is no startup or config validation anywhere (notesapp/storage.py). Consider refusing to start when no account has a usable token, and logging which accounts are disabled.
- (notesapp) notesapp/auth.py:16-18: the token-to-user loop returns the first match. If two users were set to the same token, the second becomes impossible to log in as, and the caller is silently resolved to the first. Add a startup check that tokens are unique.
- (notesapp) notesapp/auth.py:17: hmac.compare_digest on str raises TypeError (not AuthError) for a non-ASCII bearer token, which escapes the auth error path (confirmed in sbx-00006). Compare UTF-8 bytes instead; the candidate patch includes this.
- (notesapp) notesapp/app.py:11-16: authentication is enforced separately in each handler, not centrally in dispatch. Any future route that forgets current_user would be unauthenticated. Consider authenticating in dispatch.
- (notesapp) No .gitignore exists in the repository. Add one that covers .env and other secret files before deployment configuration is added.
- (notesapp) notesapp/auth.py:16-18: the loop returns early on the first match, which reveals by timing only which user index matched, not secret bytes. Acceptable, though a lookup keyed by HMAC(token) would remove it entirely.
- (notesapp) notesapp/storage.py:5-8: there is no check that configured tokens are distinct or have minimum length/entropy. If ALICE_TOKEN == BOB_TOKEN, the first entry in the USERS iteration wins and bob can never authenticate (and is confused with alice). Add a startup validation for uniqueness and a minimum length (for example >= 32 random bytes).
- (notesapp) notesapp/auth.py:17: hmac.compare_digest on str raises TypeError for non-ASCII tokens (seen in sbx-00002). The request fails closed, but with an unmapped exception instead of AuthError. Compare UTF-8 bytes instead (included in the patch).
- (notesapp) There are no token expiry, rotation or revocation mechanics. Tokens are static env-var values for the life of the process.
- (notesapp) notesapp/auth.py:13: the 'Bearer ' scheme match is case-sensitive and whitespace-exact. This is not a security issue, but it is brittle across proxies or clients that send 'bearer'.
- (notesapp) notesapp/auth.py:16-18: if an operator sets two users to the same token, the first entry in USERS wins silently, so one user authenticates as another. Reject duplicate tokens at startup.
- (notesapp) notesapp/auth.py:17: hmac.compare_digest(str, str) raises TypeError when either string has non-ASCII characters (for example 'Authorization: Bearer é'). current_user then surfaces an unhandled exception instead of AuthError. Compare UTF-8 bytes instead (included in the remediation patch).
- (notesapp) tests/test_notes.py:11 hard-codes a credential literal. Tests should provision their own token through the environment, as in the patch.
- (notesapp) Tokens are read once at import (notesapp/storage.py:5-8), so rotation or revocation needs a process restart and there is no per-token expiry. Consider a revocable token store if this grows beyond a fixture.
- (notesapp) notesapp/auth.py:16-18 returns the first user whose token matches. If an operator gives two users the same token, every request resolves to the first user in dict order. Reject duplicate tokens at load time.
- (notesapp) notesapp/auth.py:17 passes str values to hmac.compare_digest. A non-ASCII presented token raises TypeError ('comparing strings with non-ASCII characters is not supported') instead of AuthError (seen in sbx-00001). Compare UTF-8 bytes so invalid tokens always map to AuthError. The proposed patch does this.

## 7. Coverage

| Target | covered | candidate | blocked | deferred | out_of_scope | planned | total |
|---|---|---|---|---|---|---|---|
| notesapp | 0 | 9 | 0 | 35 | 0 | 0 | 44 |

Gaps (blocked or deferred units):
- `notesapp` Repository AI-agent hook configuration / Agent tool hooks execute shell commands on SessionStart and every PreToolUse when the repo is opened by an agent that honors project settings / SUPPLY-CHAIN-AND-RELEASE.md#Plugin and extension trust expansion: budget
- `notesapp` Repository AI-agent hook configuration / Agent tool hooks execute shell commands on SessionStart and every PreToolUse when the repo is opened by an agent that honors project settings / SUPPLY-CHAIN-AND-RELEASE.md#Untrusted code in a privileged workflow: budget
- `notesapp` Repository AI-agent instruction file (CLAUDE.md) / Repository content -> AI reviewer or agent instructions (untrusted text treated as directives) / ATTACK-CLASSES.md#Wildcard: budget
- `notesapp` Request router / dispatch / Route table lookup and /notes/<id> path-shape match (path.count('/') == 2, rsplit) / ATTACK-CLASSES.md#Obvious things: budget
- `notesapp` Request router / dispatch / Route table lookup and /notes/<id> path-shape match (path.count('/') == 2, rsplit) / CUSTOM#Exception-to-response mapping gap: budget
- `notesapp` Request router / dispatch / Route table lookup and /notes/<id> path-shape match (path.count('/') == 2, rsplit) / CUSTOM#Route-shape and id-parsing confusion: budget
- `notesapp` Bearer-token parsing in current_user (Authorization header -> token string) / Unauthenticated client -> authenticated user identity (token edge cases: empty token, non-ASCII token) / ATTACK-CLASSES.md#Wildcard: budget
- `notesapp` GET /export?name= / Authenticated user -> server filesystem (path confinement) / ATTACK-CLASSES.md#Wildcard: budget
- `notesapp` GET /notes/<id> / User A -> User B note read (per-owner isolation) / ATTACK-CLASSES.md#Wildcard: budget
- `notesapp` DELETE /notes/<id> - delete a note / Bearer-token authentication / ATTACK-CLASSES.md#Access control: budget
- `notesapp` DELETE /notes/<id> - delete a note / Bearer-token authentication / DATA-ISOLATION-AND-LIFECYCLE.md#Enumeration and aggregate oracles: budget
- `notesapp` DELETE /notes/<id> - delete a note / Bearer-token authentication / WEB-PROTOCOL-AND-AUTH.md#Ordinary CSRF: budget
- `notesapp` DELETE /notes/<id> - delete a note / Note ownership check / ATTACK-CLASSES.md#Access control: budget
- `notesapp` DELETE /notes/<id> - delete a note / Note ownership check / DATA-ISOLATION-AND-LIFECYCLE.md#Enumeration and aggregate oracles: budget
- `notesapp` DELETE /notes/<id> - delete a note / Note ownership check / WEB-PROTOCOL-AND-AUTH.md#Ordinary CSRF: budget
- `notesapp` GET /export?name= - read an export file / Bearer-token authentication (the only gate; no per-user export scoping) / ATTACK-CLASSES.md#Access control: budget
- `notesapp` GET /export?name= - read an export file / Bearer-token authentication (the only gate; no per-user export scoping) / ATTACK-CLASSES.md#Resource and file handling: budget
- `notesapp` GET /export?name= - read an export file / Bearer-token authentication (the only gate; no per-user export scoping) / CUSTOM#Exception-to-response mapping gap: budget
- `notesapp` GET /export?name= - read an export file / Bearer-token authentication (the only gate; no per-user export scoping) / DATA-ISOLATION-AND-LIFECYCLE.md#Export and backup scope expansion: budget
- `notesapp` GET /export?name= - read an export file / Export directory confinement (os.path.join with EXPORT_DIR; no normalization, containment, or absolute-path check on name) / ATTACK-CLASSES.md#Access control: budget
- `notesapp` GET /export?name= - read an export file / Export directory confinement (os.path.join with EXPORT_DIR; no normalization, containment, or absolute-path check on name) / ATTACK-CLASSES.md#Resource and file handling: budget
- `notesapp` GET /export?name= - read an export file / Export directory confinement (os.path.join with EXPORT_DIR; no normalization, containment, or absolute-path check on name) / CUSTOM#Exception-to-response mapping gap: budget
- `notesapp` GET /export?name= - read an export file / Export directory confinement (os.path.join with EXPORT_DIR; no normalization, containment, or absolute-path check on name) / DATA-ISOLATION-AND-LIFECYCLE.md#Export and backup scope expansion: budget
- `notesapp` GET /notes/<id> - read a single note by numeric id / Bearer-token authentication (any valid user) / ATTACK-CLASSES.md#Access control: budget
- `notesapp` GET /notes/<id> - read a single note by numeric id / Bearer-token authentication (any valid user) / DATA-ISOLATION-AND-LIFECYCLE.md#Enumeration and aggregate oracles: budget
- `notesapp` GET /notes/<id> - read a single note by numeric id / Bearer-token authentication (any valid user) / DATA-ISOLATION-AND-LIFECYCLE.md#Missing tenant or owner enforcement: budget
- `notesapp` GET /notes/<id> - read a single note by numeric id / Bearer-token authentication (any valid user) / WEB-PROTOCOL-AND-AUTH.md#API-key scope and resource binding: budget
- `notesapp` GET /notes/<id> - read a single note by numeric id / Note ownership check (require_owner is defined but get_note never calls it; delete_note at notes.py:25 does) / ATTACK-CLASSES.md#Access control: budget
- `notesapp` GET /notes/<id> - read a single note by numeric id / Note ownership check (require_owner is defined but get_note never calls it; delete_note at notes.py:25 does) / DATA-ISOLATION-AND-LIFECYCLE.md#Enumeration and aggregate oracles: budget
- `notesapp` GET /notes/<id> - read a single note by numeric id / Note ownership check (require_owner is defined but get_note never calls it; delete_note at notes.py:25 does) / DATA-ISOLATION-AND-LIFECYCLE.md#Missing tenant or owner enforcement: budget
- `notesapp` GET /notes/<id> - read a single note by numeric id / Note ownership check (require_owner is defined but get_note never calls it; delete_note at notes.py:25 does) / WEB-PROTOCOL-AND-AUTH.md#API-key scope and resource binding: budget
- `notesapp` GET /notes - list caller's notes / Bearer-token authentication / ATTACK-CLASSES.md#Access control: budget
- `notesapp` GET /notes - list caller's notes / Bearer-token authentication / DATA-ISOLATION-AND-LIFECYCLE.md#Policy and query disagreement: budget
- `notesapp` GET /notes - list caller's notes / Owner filter on listing / ATTACK-CLASSES.md#Access control: budget
- `notesapp` GET /notes - list caller's notes / Owner filter on listing / DATA-ISOLATION-AND-LIFECYCLE.md#Policy and query disagreement: budget

Hunt waves: 2. Each run adds coverage; one run does not exhaust a target.

## 8. Wishlist

- (notesapp, asked by 2 agent(s)) **The HTTP server or framework that builds the request object passed to dispatch**: unblocks Whether tokens leak through logs or transport at layers not visible in the repository.
- (notesapp, asked by 1 agent(s)) **Deployment environment configuration (process env or secret manager) for ALICE_TOKEN and BOB_TOKEN**: unblocks Whether the default-credential candidate is reachable in a specific deployment, not just in the shipped default.
- (notesapp, asked by 1 agent(s)) **The production or staging process environment (or deployment manifest) that shows how ALICE_TOKEN and BOB_TOKEN are provisioned**: unblocks Confirming whether real accounts are exploitable now, as opposed to only having a latent fail-open default
- (notesapp, asked by 1 agent(s)) **Production deployment environment / service unit definition showing whether ALICE_TOKEN and BOB_TOKEN are set**: unblocks Turns the likelihood rating for hardcoded-default-credentials into an observed fact for the deployed instance
- (notesapp, asked by 1 agent(s)) **pytest installed in the sandbox**: unblocks Confirms that the patch together with conftest keeps test_list_only_own passing
- (notesapp, asked by 1 agent(s)) **The production deployment environment configuration (env file, systemd unit or container spec) that sets ALICE_TOKEN, BOB_TOKEN and NOTES_EXPORT_DIR**: unblocks Moves the likelihood of the default-credentials candidate from conditional to observed, in one direction or the other.

## 9. Cost

| Role | Model | Invocations | OK | Input tokens | Output tokens | USD |
|---|---|---|---|---|---|---|
| critic | claude-opus-5-5 | 2 | 2 | 152953 | 5456 | 0.456 |
| dedup | claude-opus-5-5 | 3 | 3 | 39957 | 2026 | 0.141 |
| hunter | claude-opus-5-5 | 5 | 5 | 525724 | 62553 | 2.250 |
| recon | claude-opus-5-5 | 3 | 3 | 82075 | 12978 | 0.463 |
| tracer | claude-opus-5-5 | 2 | 2 | 72620 | 4690 | 0.222 |
| validator | claude-sonnet-5-5 | 2 | 2 | 92014 | 8837 | 0.197 |
| verifier | claude-sonnet-5-5 | 2 | 2 | 44014 | 2050 | 0.119 |

Total: $3.848
