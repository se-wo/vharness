# Security audit report

## 1. Run

> **This is a partial pass.** Status: `incomplete`. Reason: hunt_budget_exhausted.

- Run: `run-20261030-224446-cec13e`; status `incomplete`
- Profile: `standard`; scope: whole repository
- Budget: 30 invocations per target; USD cap: 15.0
- Discovery model: `claude-opus-5-5`; validation model: `claude-sonnet-5-5`
- Execution: **source-only**. No target code was executed. Proof-of-concept tests and patches in this report are proposals that have **not been executed** (SPEC 1.4, R-REP-05).
- Prior run used: none

| Target | Root | Commit |
|---|---|---|
| notesapp | `tests/fixtures/notesapp` | `unknown` |
| notesclient | `tests/fixtures/notesclient` | `unknown` |

## 2. Summary

2 confirmed vulnerabilities (2 high), 2 leads that need validation, 0 candidates rejected.

## 3. Confirmed vulnerabilities

| Priority | Severity | Exposure | Target | Title | Boundary |
|---|---|---|---|---|---|
| P1 | high | exploitable_now | notesapp | IDOR: any authenticated user can read any other user's note through GET /notes/<id> | User <-> user note isolation when reading one note |
| P1 | high | exploitable_now | notesapp | Path traversal in GET /export lets any authenticated user read arbitrary server files | application -> host filesystem (export directory) |

## 4. Details

### [P1] IDOR: any authenticated user can read any other user's note through GET /notes/<id>
`notesapp` · fingerprint `idor:notesapp/notes.py:get_note` · severity **high** (likelihood high, impact high) · confidence high

- **Attacker:** Authenticated low-privilege user, for example bob (starting with: A valid bearer token for their own account. They can send GET /notes/<id> with any integer id.)
- **Boundary / broken assumption:** User <-> user note isolation when reading one note / README.md:4 says users must only see their own notes. get_note assumes that authenticating the caller is enough and never checks note ownership.
- **Affected resource:** Title and body of every other user's note in storage.NOTES, for example note 1 ('alice secret')
- **Entry → sink:** `notesapp/app.py:15` → `notesapp/notes.py:17`
- **Reachability:** reachable; exposure exploitable_now
- **Root cause:** get_note does not apply the per-note ownership check (require_owner) that delete_note applies, so being authenticated is treated as being authorized for any note id.
- **Fix:** Enforce ownership in get_note. Answer 404 when the note is missing or belongs to someone else, so the endpoint is not an existence oracle. Optionally add a storage helper scoped by owner.

### [P1] Path traversal in GET /export lets any authenticated user read arbitrary server files
`notesapp` · fingerprint `path-traversal:notesapp/notes.py:export_note` · severity **high** (likelihood high, impact high) · confidence high

- **Attacker:** Any authenticated end user, for example bob holding his own bearer token. If the operator never set ALICE_TOKEN/BOB_TOKEN, anyone who knows the public default 'change-me-b' or 'change-me-a' also qualifies. (starting with: Can send GET /export?name=<arbitrary string> with a valid 'Authorization: Bearer <token>' header.)
- **Boundary / broken assumption:** application -> host filesystem (export directory) / Files outside EXPORT_DIR cannot be read through GET /export.
- **Affected resource:** Any file the notesapp process can read on the host: /etc/passwd, application source, /proc/self/environ (which holds ALICE_TOKEN/BOB_TOKEN if set), and other secrets.
- **Entry → sink:** `notesapp/app.py:7` → `notesapp/notes.py:34`
- **Reachability:** reachable; exposure exploitable_now
- **Root cause:** export_note treats the client-supplied 'name' as a trusted relative filename. It never resolves the joined path or checks that the result stays under EXPORT_DIR, and os.path.join drops the base when the second argument is absolute.
- **Fix:** Resolve both the base directory and the joined path with os.path.realpath, then reject the request unless the resolved path is strictly inside the base (os.path.commonpath). This also handles absolute names and symlinks. As an optional extra layer, reject names that are absolute or contain path separators.

## 5. Needs validation (no severity)

| Target | Title | Blocker | Next step |
|---|---|---|---|
| notesapp | Hard-coded fallback bearer tokens (and empty-token acceptance) authenticate anonymous clients as alice/bob when env vars are unset or empty | Whether production sets ALICE_TOKEN and BOB_TOKEN to strong, non-empty, distinct secrets. The repository has no deployment config, IaC or env files.; Whether the HTTP server or middleware in front of dispatch (not in the repo) strips or rejects an 'Authorization: Bearer ' header with an empty token before it reaches current_user. | In a fresh interpreter with ALICE_TOKEN and BOB_TOKEN unset, run notes.list_notes(Req('change-me-a')) using the Req class from tests/test_notes.py and confirm it returns alice's notes. Then in a separate process set ALICE_TOKEN='' before importing notesapp and confirm notes.list_notes(Req('')) (header 'Bearer ') returns alice's notes. Expected on current code: both succeed. |
| notesclient | sync_export passes a remote-server-controlled filename unvalidated to export_note with the user's bearer token | The source of notesapp.notes.export_note is not in the repository. It is unknown whether request.args['name'] is joined to a filesystem path (traversal via '../' or an absolute path), used as a cross-user lookup key, or checked against the token owner.; It is unknown whether export_note reads (disclosure) or writes (overwrite) a name-derived path.; The installed notesapp version is unknown because there is no dependency manifest.; It is unknown whether the real caller of sync_export fetches the filename over an authenticated channel. That determines whether an attacker can control the server response. | Get the notesapp source at the version deployed alongside notesclient. Read export_note to find where request.args['name'] reaches os.path.join, open, or a storage lookup, and whether it checks ownership against the user resolved from the Authorization header. In a scratch environment with two users, A and B, call sync_export(token_A, '../B/secret'), sync_export(token_A, '/etc/passwd'), and sync_export(token_A, '<B note id>'). Check whether any of them returns or writes data outside user A's notes. |

## 6. Hardening notes (not vulnerabilities)

- (notesapp) notesapp/app.py:11-16: dispatch has no exception boundary. KeyError (unknown method/path, e.g. POST /notes/1), ValueError (int('abc') in notes.py:14/22), TypeError (non-ASCII token) and OSError (export open) all propagate to the external server untyped. Add a single try/except in dispatch that maps AuthError→401/403, KeyError→404/405, ValueError→400, and logs everything else, returning a generic 500 with no details.
- (notesapp) notesapp/auth.py:16-18: the loop returns on the first match, so timing shows which USERS entry matched. It compares against every token, so a non-ASCII token configured by the operator in ALICE_TOKEN would make authentication fail for every user (TypeError). Encode tokens to bytes when loading the configuration and check them at startup.
- (notesapp) notesapp/auth.py:15-17: compare_digest gets the raw str token. A non-ASCII token (for example, a latin-1-decoded 'Authorization: Bearer \xe9') raises TypeError instead of AuthError, so any AuthError→401 mapping is bypassed, and the request likely ends in a generic 500 that may expose a traceback, depending on the server. Fix: encode both sides before comparing and treat a failure as invalid, e.g. `try: tok = token.encode('ascii') except UnicodeEncodeError: raise AuthError('invalid token')`, then `hmac.compare_digest(user['token'].encode('utf-8'), tok)`. Regression test: a Req whose headers are {'Authorization': 'Bearer é'} should make pytest.raises(AuthError) succeed.
- (notesapp) tests/test_notes.py has no tests for export_note, get_note ownership or delete_note ownership. Add regression tests that reject '../', absolute names and cross-owner access.
- (notesapp) Confine with os.path.realpath plus os.path.commonpath([real_base, real_target]) == real_base, not a startswith check on a string prefix. That defeats symlinks inside EXPORT_DIR and sibling-prefix directories such as /var/lib/notesapp/exports-old.
- (notesapp) notesapp/notes.py:34-35 reads the whole file into memory with fh.read(). Besides confining the path, check os.path.isfile on the resolved realpath and cap the read size so device files, FIFOs or very large files cannot exhaust worker memory.
- (notesapp) notesapp/notes.py:30-35 export_note ignores the authenticated user. When the traversal fix lands, consider scoping exports per user (for example EXPORT_DIR/<user id>/<basename>) so the export namespace is not shared by all tenants.
- (notesapp) The README does not say ALICE_TOKEN, BOB_TOKEN, or NOTES_EXPORT_DIR are required. Document the required configuration.
- (notesapp) current_user returns the first matching user. If two env tokens are configured to the same value, the identity resolves silently to whichever user is first. A startup check should require the tokens to be unique.
- (notesapp) Tokens are static, long-lived, stored in plaintext in process memory, and have no rotation or expiry. Consider storing only a hash (e.g. SHA-256) of each token, comparing digests, and supporting rotation.
- (notesapp) auth.current_user passes the raw header suffix to hmac.compare_digest. A str token with non-ASCII characters raises TypeError instead of AuthError. This fails closed but may surface as an unhandled 500. Encode both sides as UTF-8 bytes, or catch TypeError and raise AuthError.
- (notesapp) storage.USERS falls back to the hardcoded tokens 'change-me-a'/'change-me-b' when the environment variables are unset. Combined with the export traversal, a deployment on defaults gives effectively unauthenticated arbitrary file read. Refuse to start when the token env vars are unset.
- (notesapp) current_user passes the client token to hmac.compare_digest. A non-ASCII str token raises TypeError instead of AuthError, which may surface as a 500. Encode both sides to bytes before comparing.
- (notesapp) export_note reads the whole file into memory with fh.read(). A name pointing at a huge file or a device such as /dev/zero (reachable through the traversal) could exhaust memory. After fixing containment, also check that the target is a regular file (os.path.isfile) and consider a size cap.
- (notesapp) export_note lets open() exceptions (FileNotFoundError, IsADirectoryError, ValueError on embedded NUL) propagate. Depending on the unseen HTTP layer, these may leak absolute paths or stack traces, which also gives an existence oracle for arbitrary paths. Map them to a generic 404/400.
- (notesapp) export_note authenticates the user but never uses the identity, so every user shares one export namespace. If per-user exports are ever written to EXPORT_DIR, scope them by user (for example EXPORT_DIR/<user_id>/) and confine the path to that subdirectory.
- (notesapp) notesapp/auth.py:13: the 'Bearer ' scheme match is case-sensitive and takes the remainder verbatim (no strip). This fails closed and is only an interoperability note, not a security issue.
- (notesapp) notesapp/storage.py:5-8: tokens are kept in plaintext in process memory and compared directly. Storing a SHA-256 digest of each token and comparing digests would limit exposure if USERS is ever serialized or logged.
- (notesapp) notesapp/auth.py:16-18: authentication returns the first user whose token matches. If an operator configures the same value for ALICE_TOKEN and BOB_TOKEN, bob's token silently authenticates as alice. Reject duplicate tokens at startup (included in the proposed patch).
- (notesapp) notesapp/auth.py:17: hmac.compare_digest raises TypeError when the bearer value contains non-ASCII characters. This fails closed, but it is an unhandled exception. Catch it, or compare encoded bytes (token.encode()), and return AuthError so the HTTP layer does not produce a 500 response that may expose a stack trace.
- (notesapp) delete_note returns 404 for a missing note and AuthError for someone else's note. This difference tells an authenticated user which note ids exist. Return the same 404 in both cases.
- (notesapp) notesapp/notes.py:14 and 22: int(note_id) on a non-numeric path segment raises ValueError, which reaches the unseen server error handling. Validate the id and return 404 instead.
- (notesapp) notesapp/auth.py:17: hmac.compare_digest raises TypeError when given str arguments that contain non-ASCII characters. A bearer token with non-ASCII text therefore raises TypeError instead of AuthError, which may show up as a 500 or a traceback depending on the unseen server. Compare the values as bytes (encode both to UTF-8) instead.
- (notesapp) Tokens are static, with no expiry, rotation or revocation path, and no per-route scope. Every token grants the user's full capability set, including /export. Consider hashed and scoped tokens if the service grows.
- (notesapp) notesapp/auth.py:12: header lookup uses the exact key 'Authorization' and the case-sensitive scheme 'Bearer '. Whether the unseen server's headers object is case-insensitive affects availability, not security, but it should be documented or normalized.
- (notesapp) notesapp/auth.py:16-18: current_user returns the first USERS entry whose token matches. If an operator sets ALICE_TOKEN == BOB_TOKEN, bob's requests resolve to alice (identity confusion). At startup, require configured tokens to be distinct.
- (notesapp) notesapp/auth.py:17: hmac.compare_digest raises TypeError when both arguments are str and either contains non-ASCII characters. A client-supplied token with non-ASCII characters therefore raises an exception instead of AuthError, so the server may return a 500 or an error trace, depending on the unseen error-to-HTTP mapping. Compare encoded bytes instead (token.encode('utf-8')) and catch the error so it maps to AuthError.
- (notesclient) Packaging: there is no requirements, lock or setup metadata, so the notesapp version that actually runs cannot be identified. Pin the notesapp dependency.
- (notesclient) client/sync.py:5-8: the hand-built Request shim calls a server-style handler in-process and skips any framework middleware (auth decorators, request context). Document which notesapp version and entry point is supported, or call a library-level API that does not depend on middleware.
- (notesclient) client/sync.py:11-13: check filename_from_server on the client before calling export_note. Allow only a strict pattern (for example ^[A-Za-z0-9._-]{1,128}$) and reject '..', '/', '\\', NUL and absolute paths. That way a hostile or spoofed sync server can't use the user's bearer token (client/sync.py:7) to pick arbitrary export targets, whatever export_note does internally.
- (notesclient) Pin the notesapp dependency (requirements or lock file) to a version where export_note enforces containment under EXPORT_DIR. The repository currently has no dependency metadata.
- (notesclient) Request (client/sync.py:5-8) is a hand-built duck-typed request passed straight to a server-side handler. Any auth or path middleware in notesapp is skipped. Prefer a client API in notesapp meant for in-process use, or go through the HTTP stack.
- (notesclient) client/sync.py:7: the bearer token goes into a hand-built Request handed to an in-process handler. Any future fetch or transport code should require TLS with certificate verification enabled (no verify=False) for the sync server channel that supplies the filename.
- (notesclient) client/sync.py:11-13: sync_export does no client-side validation of filename_from_server before passing it, together with the user's bearer token, to export_note. Defense in depth against a compromised or spoofed sync server: reject empty names, names containing '/', '\\' or NUL, names that are '.' or '..' or start with '..', and absolute paths, or match them against an allowlist such as ^[A-Za-z0-9._-]{1,255}$. Then a tampered response cannot steer the export even if notesapp's own checks are weak.
- (notesclient) The repository has no dependency or lock metadata (no requirements.txt, pyproject or setup.py), so neither the notesapp version nor the HTTP or TLS library used by the fetcher can be pinned or audited. Add pinned dependency metadata.
- (notesclient) client/sync.py:11-13 passes filename_from_server to export_note unvalidated, with the user's bearer token attached. Because the fetching transport cannot be seen, the client should not depend on transport authenticity alone. Add a client-side check: reject empty names, names with '/', '\\', '..' or NUL, absolute paths, and over-long names, or match against an allowlist regex such as ^[A-Za-z0-9._-]{1,128}$ that also excludes '.' and '..'. Then a compromised or spoofed sync server cannot pick arbitrary targets under the user's authority.
- (notesclient) client/sync.py:7: sync_export does not reject an empty token or a token containing CR or LF before building the Authorization header. Validating the token stops malformed headers from reaching a handler whose header parsing is unknown.
- (notesclient) client/sync.py:2,13: the client calls a server-side handler in-process with a duck-typed Request. Prefer a documented notesapp client or service API, or the real HTTP endpoint, so that framework-level authentication, authorization, and path controls are certain to run.
- (notesclient) client/sync.py:11-13: sync_export does not validate filename_from_server before calling export_note. Add a client-side allowlist that rejects empty names, absolute paths, path separators ('/' and '\'), '..' segments, NUL bytes, and names over a length cap. Then the client does not depend on notesapp middleware being present when it calls the handler in-process.
- (notesclient) client/sync.py:6-8: reject tokens that contain CR/LF or whitespace before formatting the Authorization header. This guards against header-structure confusion if the shim is later sent over HTTP.
- (notesclient) client/sync.py:11-13: check that filename_from_server is a str and matches a strict note-name pattern (no path separators, no '..', no NUL, bounded length) before building the Request. That way the client does not depend only on export_note's undocumented handling.
- (notesclient) Call the notes service over its authenticated HTTP API, or through a documented client function, instead of calling a server-side handler in-process with a duck-typed request object. This keeps framework middleware such as auth, rate limiting and path checks on the path.
- (notesclient) client/sync.py#Request: build the request with explicit types (str for token and name) and reject an empty or None token before calling export_note. That way a missing token cannot reach a handler that might treat 'Bearer None' or 'Bearer ' leniently.
- (notesclient) Add a dependency manifest that pins notesapp, so the export_note implementation the client relies on can be identified and audited.
- (notesclient) Instead of calling a server-side request handler in-process with a hand-built Request shim, call a documented library API that takes explicit (user_id, note_id) arguments, or go through the real HTTP endpoint so that middleware-based authentication and path checks apply.
- (notesclient) Validate filename_from_server in sync_export before calling export_note, regardless of what export_note does: require isinstance(str), reject empty values, '/', '\\', '..', NUL and leading '.', and ideally match against an allowlisted pattern (for example ^[A-Za-z0-9._-]{1,255}$ with no leading dot) or the user's known note IDs.
- (notesclient) Pin the notesapp dependency (requirements/lock file) so reviewers can identify and audit the export_note implementation the client actually runs.
- (notesclient) Do not call a server-side request handler (export_note) in-process with a hand-built Request object. Any controls that live in decorators or middleware (auth, request context, rate limits) are skipped. Use a public library API or the HTTP endpoint instead.
- (notesclient) In sync_export, validate filename_from_server on the client side whatever export_note does: require isinstance(name, str), reject empty strings, NUL, os.sep/os.altsep, '..' components, and absolute paths, and preferably match a strict note-name regex such as ^[A-Za-z0-9._-]{1,255}$ with no leading dot. Example patch: `import re
_NAME_RE = re.compile(r'^[A-Za-z0-9_-][A-Za-z0-9._-]{0,254}$')
def sync_export(token, filename_from_server):
    if not isinstance(filename_from_server, str) or not _NAME_RE.fullmatch(filename_from_server) or '..' in filename_from_server:
        raise ValueError('invalid note name from server')
    return export_note(Request(token, filename_from_server))`.
- (notesclient) Calling the server-side handler export_note directly with a hand-built Request shim may skip framework middleware such as auth decorators. Prefer the public client API or HTTP endpoint, which goes through the full auth stack.

## 7. Coverage

| Target | covered | candidate | blocked | deferred | out_of_scope | planned | total |
|---|---|---|---|---|---|---|---|
| notesapp | 2 | 9 | 0 | 34 | 0 | 0 | 45 |
| notesclient | 0 | 7 | 7 | 0 | 0 | 0 | 14 |

Gaps (blocked or deferred units):
- `notesapp` Repository-checked-in Claude Code project hooks (SessionStart/PreToolUse shell commands) / repository content to developer or agent shell execution / SUPPLY-CHAIN-AND-RELEASE.md#Plugin and extension trust expansion: budget
- `notesapp` Repository-checked-in Claude Code project hooks (SessionStart/PreToolUse shell commands) / repository content to developer or agent shell execution / SUPPLY-CHAIN-AND-RELEASE.md#Untrusted code in a privileged workflow: budget
- `notesapp` Request dispatcher (method + path routing) / route table lookup before any auth runs / ATTACK-CLASSES.md#Business logic: budget
- `notesapp` Request dispatcher (method + path routing) / route table lookup before any auth runs / CUSTOM#Dispatcher path-shape confusion: budget
- `notesapp` Request dispatcher (method + path routing) / route table lookup before any auth runs / RESOURCE-EXHAUSTION-AND-AVAILABILITY.md#Reachable fatal error or deadlock: budget
- `notesapp` Bearer-token authentication on the Authorization header (runs before every handler) / token provisioning from env, falling back to hardcoded defaults / WEB-PROTOCOL-AND-AUTH.md#API-key scope and resource binding: budget
- `notesapp` GET /export?name= (notes.export_note) / Application -> host filesystem (export directory) / ATTACK-CLASSES.md#Wildcard: budget
- `notesapp` GET /notes/<id> (notes.get_note) / User <-> user note isolation: reading one note / ATTACK-CLASSES.md#Wildcard: budget
- `notesapp` DELETE /notes/<id> - delete a note / bearer-token authentication / ATTACK-CLASSES.md#Access control: budget
- `notesapp` DELETE /notes/<id> - delete a note / bearer-token authentication / DATA-ISOLATION-AND-LIFECYCLE.md#Enumeration and aggregate oracles: budget
- `notesapp` DELETE /notes/<id> - delete a note / bearer-token authentication / WEB-PROTOCOL-AND-AUTH.md#Ordinary CSRF: budget
- `notesapp` DELETE /notes/<id> - delete a note / owner check before delete / ATTACK-CLASSES.md#Access control: budget
- `notesapp` DELETE /notes/<id> - delete a note / owner check before delete / DATA-ISOLATION-AND-LIFECYCLE.md#Enumeration and aggregate oracles: budget
- `notesapp` DELETE /notes/<id> - delete a note / owner check before delete / WEB-PROTOCOL-AND-AUTH.md#Ordinary CSRF: budget
- `notesapp` GET /export?name= - read a file from the export directory / bearer-token authentication / ATTACK-CLASSES.md#Access control: budget
- `notesapp` GET /export?name= - read a file from the export directory / bearer-token authentication / ATTACK-CLASSES.md#Resource and file handling: budget
- `notesapp` GET /export?name= - read a file from the export directory / bearer-token authentication / DATA-ISOLATION-AND-LIFECYCLE.md#Export and backup scope expansion: budget
- `notesapp` GET /export?name= - read a file from the export directory / bearer-token authentication / RESOURCE-EXHAUSTION-AND-AVAILABILITY.md#Unbounded buffering and cardinality: budget
- `notesapp` GET /export?name= - read a file from the export directory / export directory confinement (no control present; os.path.join(EXPORT_DIR, name) with no normalization, containment check or owner scoping) / ATTACK-CLASSES.md#Access control: budget
- `notesapp` GET /export?name= - read a file from the export directory / export directory confinement (no control present; os.path.join(EXPORT_DIR, name) with no normalization, containment check or owner scoping) / ATTACK-CLASSES.md#Resource and file handling: budget
- `notesapp` GET /export?name= - read a file from the export directory / export directory confinement (no control present; os.path.join(EXPORT_DIR, name) with no normalization, containment check or owner scoping) / DATA-ISOLATION-AND-LIFECYCLE.md#Export and backup scope expansion: budget
- `notesapp` GET /export?name= - read a file from the export directory / export directory confinement (no control present; os.path.join(EXPORT_DIR, name) with no normalization, containment check or owner scoping) / RESOURCE-EXHAUSTION-AND-AVAILABILITY.md#Unbounded buffering and cardinality: budget
- `notesapp` GET /notes/<id> - fetch a single note by numeric id / bearer-token authentication / ATTACK-CLASSES.md#Access control: budget
- `notesapp` GET /notes/<id> - fetch a single note by numeric id / bearer-token authentication / CUSTOM#Handler auth-to-ownership omission: budget
- `notesapp` GET /notes/<id> - fetch a single note by numeric id / bearer-token authentication / DATA-ISOLATION-AND-LIFECYCLE.md#Enumeration and aggregate oracles: budget
- `notesapp` GET /notes/<id> - fetch a single note by numeric id / bearer-token authentication / DATA-ISOLATION-AND-LIFECYCLE.md#Missing tenant or owner enforcement: budget
- `notesapp` GET /notes/<id> - fetch a single note by numeric id / per-note owner isolation (README.md says users must only see their own notes); get_note never calls require_owner / ATTACK-CLASSES.md#Access control: budget
- `notesapp` GET /notes/<id> - fetch a single note by numeric id / per-note owner isolation (README.md says users must only see their own notes); get_note never calls require_owner / CUSTOM#Handler auth-to-ownership omission: budget
- `notesapp` GET /notes/<id> - fetch a single note by numeric id / per-note owner isolation (README.md says users must only see their own notes); get_note never calls require_owner / DATA-ISOLATION-AND-LIFECYCLE.md#Enumeration and aggregate oracles: budget
- `notesapp` GET /notes/<id> - fetch a single note by numeric id / per-note owner isolation (README.md says users must only see their own notes); get_note never calls require_owner / DATA-ISOLATION-AND-LIFECYCLE.md#Missing tenant or owner enforcement: budget
- `notesapp` GET /notes - list the caller's notes / bearer-token authentication / ATTACK-CLASSES.md#Access control: budget
- `notesapp` GET /notes - list the caller's notes / bearer-token authentication / DATA-ISOLATION-AND-LIFECYCLE.md#Policy and query disagreement: budget
- `notesapp` GET /notes - list the caller's notes / owner-filtered listing / ATTACK-CLASSES.md#Access control: budget
- `notesapp` GET /notes - list the caller's notes / owner-filtered listing / DATA-ISOLATION-AND-LIFECYCLE.md#Policy and query disagreement: budget
- `notesclient` Code that fetches filename_from_server from the remote sync server (not in this repository) / Remote sync server -> local client (authenticity and integrity of the response) / ATTACK-CLASSES.md#Chained vulnerabilities and trust boundaries: Source of the code that fetches filename_from_server from the remote sync server (URL scheme, HTTP library, verify= / CA settings, certificate pinning, response signing), Whether an attacker on the network path, or a compromised or malicious sync server, can control the filename. That decides whether the missing client-side name validation can be exploited., How notesapp.notes.export_note handles request.args['name'] (path join, traversal, ownership), since this decides the impact of an attacker-controlled name
- `notesclient` Code that fetches filename_from_server from the remote sync server and handles the return value of sync_export / Remote sync server <-> client transport (authenticity/integrity) and export output egress / ATTACK-CLASSES.md#Wildcard: Source of the code that fetches filename_from_server from the remote sync server: transport security, server authentication, response integrity., Source of the callers of sync_export and what they do with the returned export (whether it is sent back to the server or anywhere else)., Source of notesapp.notes.export_note: how it joins and opens request.args['name'], and whether it checks ownership.
- `notesclient` Fetching filename_from_server from the remote sync server (transport authenticity) / Network -> client: integrity and authenticity of the sync server response that supplies the filename / ATTACK-CLASSES.md#Chained vulnerabilities and trust boundaries: The source of the code that fetches filename_from_server from the remote sync server and then calls sync_export, including its HTTP client, TLS verify settings, certificate pinning and any response signature check. This code is not in the repository., How notesapp.notes.export_note uses request.args['name'] (path join/open/lookup, ownership check). This decides whether an attacker-controlled name has any effect beyond the user's own notes.
- `notesclient` Hand-built Request object passed to notesapp.notes.export_note in-process / Framework middleware/decorator controls skipped by calling the handler directly / CUSTOM#Duck-typed forged request into in-process handler: The notesapp.notes.export_note source, including any decorators, and the notesapp app setup (before_request hooks, WSGI middleware, request-context requirements). This shows whether auth, ownership, or name/path checks run only on the HTTP route and are skipped by the direct call at client/sync.py:13., Which notesapp version is installed. The repository has no requirements, setup metadata, or lock file.
- `notesclient` Hand-built Request shim passed to the in-process handler notesapp.notes.export_note / Client-constructed request object -> server handler that may rely on middleware-enforced auth / CUSTOM#Duck-typed forged request into in-process handler: notesapp.notes.export_note source: does it authenticate request.headers['Authorization'] itself, or does it rely on framework middleware or decorators that the in-process call skips?, Does export_note read request attributes the shim lacks (user, session, remote_addr, environ) through getattr with permissive defaults?, Which notesapp version is installed, and where does export_note store or read data in-process? Is it a shared or privileged store that the local caller could not otherwise reach?
- `notesclient` sync_export: server-supplied filename forwarded as export name with user bearer token / User credential binding: the caller's bearer token goes into a forged Request object together with the attacker-influenced name, so export_note runs with the user's authority on a name the user did not choose / CUSTOM#Duck-typed forged request into in-process handler: Is export_note wrapped by a decorator that checks auth inside the function itself, or does it depend on framework middleware that this in-process call skips?, Does export_note check the bearer token at all, or does it assume an upstream layer already authenticated the request?
- ... 1 more in coverage-ledger.json

Hunt waves: 3. Each run adds coverage; one run does not exhaust a target.

## 8. Wishlist

- (notesclient, asked by 9 agent(s)) **The notesapp package source (notesapp/notes.py, export_note) at the version installed alongside notesclient**: unblocks Confirming or refuting confused-deputy:client/sync.py:sync_export (path traversal, cross-user export, or overwrite) and the duck-typed request middleware-bypass question
- (notesclient, asked by 4 agent(s)) **The code or configuration that fetches filename_from_server from the remote sync server (transport, TLS/pinning)**: unblocks Likelihood rating for the confused-deputy candidate
- (notesapp, asked by 4 agent(s)) **The HTTP server/adapter code that builds the request object and calls app.dispatch**: unblocks The empty-token variant and the error-leak hardening note
- (notesapp, asked by 2 agent(s)) **The deployed service's process environment, or its service/container/secret-manager config, showing whether ALICE_TOKEN and BOB_TOKEN are set**: unblocks Moving hardcoded-default-credential:notesapp/storage.py:USERS from needs_validation to confirmed or rejected
- (notesclient, asked by 1 agent(s)) **A sandbox that can install notesapp and run Python**: unblocks Turning the needs_validation candidate into confirmed or rejected
- (notesapp, asked by 1 agent(s)) **Production deployment environment / secret configuration for ALICE_TOKEN and BOB_TOKEN**: unblocks Promotion of auth:notesapp/storage.py:USERS:default-or-empty-token-fallback to confirmed or its rejection
- (notesclient, asked by 1 agent(s)) **Source of the installed notesapp package, mainly notesapp/notes.py#export_note with its decorators, plus the notesapp app factory and middleware or before_request registrations.**: unblocks The decision on whether the in-process call skips middleware-only controls, and whether the server-chosen name reaches a file sink without checks (shared with the sibling confused-deputy unit).
- (notesclient, asked by 1 agent(s)) **A requirements or lock file, or an owner observation of `pip show notesapp` in the deployed environment.**: unblocks Matching the reviewed notesapp source to the code that actually runs.
- (notesclient, asked by 1 agent(s)) **The caller or fetching code (outside this repository) that gets filename_from_server from the remote sync server and calls client/sync.py#sync_export, with its HTTP client configuration (TLS verification, pinning, response signing).**: unblocks Settles the transport-authenticity coverage unit as covered or as a candidate (for example, TLS verification disabled lets a MITM choose the export name).
- (notesapp, asked by 1 agent(s)) **The deployment's process user and file permissions**: unblocks Exact blast-radius assessment for the export path traversal
- (notesapp, asked by 1 agent(s)) **The HTTP server or adapter that builds request.args and calls app.dispatch, plus its exception-to-response mapping**: unblocks Exact exploit encoding for the known export traversal, and the impact of the error paths in export_note and current_user.
- (notesapp, asked by 1 agent(s)) **The deployment's NOTES_EXPORT_DIR contents and how files get written there**: unblocks Whether the unscoped export namespace is a cross-tenant read separate from the traversal.
- (notesclient, asked by 1 agent(s)) **The application code that calls sync_export and talks to the remote sync server**: unblocks Whether a remote attacker can exfiltrate data and how likely response tampering is
- (notesclient, asked by 1 agent(s)) **Source of the code that fetches filename_from_server and consumes sync_export's return value (the full client application, not just client/sync.py)**: unblocks Whether a spoofed or hostile server can choose the name and receive the exported contents back. That would settle whether a confused-deputy file read leaks data.
- (notesapp, asked by 1 agent(s)) **The HTTP server/adapter code or deployment config that builds the request object (headers, args) and calls notesapp.app.dispatch, including how it handles unhandled exceptions (worker model, supervisor, debug mode).**: unblocks Final decision on whether the non-AuthError path in current_user has any shared-availability or information-disclosure impact beyond the hardening note.

## 9. Cost

| Role | Model | Invocations | OK | Input tokens | Output tokens | USD |
|---|---|---|---|---|---|---|
| critic | claude-opus-5-5 | 3 | 3 | 155739 | 7101 | 0.555 |
| dedup | claude-opus-5-5 | 5 | 5 | 62659 | 3124 | 0.200 |
| hunter | claude-opus-5-5 | 17 | 17 | 772849 | 83055 | 2.972 |
| recon | claude-opus-5-5 | 6 | 6 | 176201 | 18617 | 0.603 |
| tracer | claude-opus-5-5 | 4 | 4 | 94902 | 7980 | 0.349 |
| validator | claude-sonnet-5-5 | 4 | 4 | 118827 | 11968 | 0.235 |
| verifier | claude-sonnet-5-5 | 4 | 4 | 73418 | 3392 | 0.127 |

Total: $5.041
