# vharness

A security-focused, multi-agent vulnerability harness. It audits source repositories with
stateless AI agents, keeps all state in SQLite, and has a different model check every finding.

It follows Cloudflare's [Build your own vulnerability harness](https://blog.cloudflare.com/build-your-own-vulnerability-harness)
architecture. It also uses the methodology and attack-class knowledge of
[cloudflare/security-audit-skill](https://github.com/cloudflare/security-audit-skill) (MIT; vendored in
`vharness/knowledge/`). The specification is [`SPEC.md`](SPEC.md), written in ASD-STE100 Simplified Technical English.

> Defensive use only. Audit code that you own or are authorized to audit. By default the audit is
> **source-only**: no target code runs. With `--sandbox auto|require`, target code runs only inside the
> sandbox of SPEC 13.1.

## Pipeline

```
recon (3 agents) ─► plan (code) ─► ┌──────────── continuous task queue ─────────────┐
                                   │ hunt ─► mechanical check ─► dedup ─► validate   │
                                   │  │ ▲ sibling/feedback      ▲ code shortlist │    │
                                   │  ▼ │                       │ + agent       ▼    │
                                   │ gapfill (critic per wave)       trace ─► consumer│
                                   │                                  hunts in other  │
                                   │                                  targets         │
                                   └─────────────────────► verify ──────────────────────┘
                                                              ─► report (code)
```

| Stage | Who | What |
|---|---|---|
| recon | 3 parallel agents | product, authority (principals/boundaries/controls), surfaces + attack classes (incl. custom classes) |
| plan | code | coverage units = surface × boundary × subsystem × attack class, stable `coverage_id` |
| hunt | agents (discovery model) | threat-model-first candidates; sibling units for out-of-scope paths; wishlist |
| gapfill | critic agent | thin (subsystem × class) cells, reassignments; waves until no new work |
| dedup | code index + agent | shortlist by trace scopes/sink/boundary/rare tokens; "would one fix close both?" |
| validate | mechanical checks, then agent (validation model) | tries to disprove; can only decide on its candidate |
| poc | code, in the sandbox | PoC test must fail on an unchanged copy and pass on a patched copy (only with `--sandbox`) |
| trace | agent + code symbol index | reachability, exposure (`exploitable_now`/`latent`/`wrong_component`), consumers in other targets |
| feedback | code | shallow results requeued with a sharper prompt; rejection lessons fed to later hunters |
| verify | fresh agent (validation model) | independent re-check of every confirmed and needs_validation record |
| fix | fixer agent (validation model), then a code gate in the sandbox | style-adapted patch + new regression test; test must fail before and pass after, suite must not regress (only with `--fix`) |
| report | code | `REPORT.md`, `findings.json`, `FINDINGS-DETAIL.md`, `NEEDS-VALIDATION.md`, `WISHLIST.md`, `coverage-ledger.json` |

## Safety properties

- Agents get only `Read`, `Grep`, `Glob`. A PreToolUse hook refuses every path that resolves (after symlinks) outside the target.
- No settings, hooks, plugins, skills or MCP servers are loaded from disk. A target's `.claude/settings.json` cannot run commands.
- Every prompt marks target content as untrusted data (prompt-injection canary in `tests/fixtures/notesapp/CLAUDE.md`).
- The harness never runs `git` in a target. It reads `.git/HEAD` directly, because `git status` can execute `core.fsmonitor` or filter commands from the target's config.
- Output must be outside every target. The harness never writes to a target.
- An API error returned as text in a "successful" response is classified as an error and retried, not counted as an empty success.

## Sandboxed execution (`--sandbox`)

With `--sandbox auto` or `--sandbox require`, the harness runs a start test before each run. If every control holds,
hunters and validators get a `sandbox_run` tool, and a plain-code `poc` stage runs each confirmed PoC test.

| Control | How |
|---|---|
| No network | new network namespace with no interface up |
| Empty environment | only `PATH`, `HOME=/scratch`, `TMPDIR`, `LANG`, two Python flags |
| Read-only target and toolchain | new root on tmpfs; `/usr`, `/lib*`, `/bin`, `/sbin` and the target are bind-mounted read-only, `nosuid`, `nodev`; `/etc` is synthetic |
| Writes only to scratch | fresh size-limited tmpfs at `/scratch`; the new root itself is read-only |
| Limits | CPU, address space, processes (per fresh uid), file size, open files, disk (tmpfs size), wall clock |
| Process cleanup | new PID namespace; init kills and reaps everything when the command ends or times out |
| No privileges | fresh unprivileged uid per run, `no_new_privs`, no capabilities |
| Evidence promotion | trusted init copies only allowlisted files, with the no-follow procedure (no symlinks, FIFOs, hard links, oversized or changing files) |

Every sandbox call is logged with a run ID. A record with `evidence_level: "local"` must cite a logged run ID and its
exact command, and the report prints the harness-recorded output next to the agent's claim. The sandbox needs root
on the host. In Docker, it also needs `seccomp=unconfined` and `apparmor=unconfined`; the start test detects a broken
setup. `--sandbox-limit wall_s=60` changes a limit; `--sandbox-bind DIR` adds a read-only toolchain directory.

## Fixer (`--fix`)

With `--fix` (requires `--sandbox`), each verified confirmed record goes to a `fixer` agent on the validation model.
It reads the repository, tries changes in its own sandbox copies, and returns a minimal patch in the repository's style,
one new regression test with its command, and the suite command. Then plain code gates it, each step on a fresh
sandbox copy of the target:

1. The test fails on the unchanged code.
2. The test passes on the patched code.
3. The suite runs on the unchanged code (baseline).
4. The suite passes on the patched code, unless it already failed at the baseline.

A failure gets one retry with a fresh agent that sees the gate output; after that the fix is `blocked`. A patch that edits
existing tests or exceeds 200 changed lines is `needs_human`, even if the gate passes, because agents tend to overreach.
Each fix is written to `<out>/fixes/NNNN-<status>-<fingerprint>.patch` in `git am` format (the patch plus the new test
file), and `FIXES.md` shows every gate step's output. vharness never writes to the target, never runs git, and never
merges: a person applies the patch on a review branch.

Each patch is made against the unchanged commit. When a target's fixes are done, a combined gate applies all
`accepted` patches together, in priority order, and reruns every regression test and suite. It reports `ok`,
`conflict` or `interaction`, so a reviewer knows whether the fixes can be stacked on one branch.

## Rate limits and usage windows

A refusal for a usage limit or a rate limit is its own error kind, `rate_limit`. That covers a rejected rate-limit
event from the CLI, HTTP 429, or usage-limit text even inside a "successful" response. A refused call is not counted
as an attempt or against `--budget`. Its task goes back in the queue, and an interrupted hunter's units go back to
`planned`. No new agent starts until the reset time, and agents already running finish first. If the provider gives no
reset time, the wait backs off from 60 seconds to 15 minutes.

- `--on-rate-limit wait` (default) waits up to `--rate-limit-max-wait` seconds (default 6 hours), then carries on.
- `--on-rate-limit stop`, or a reset further away than the maximum, ends the run as `paused` (exit code 4) with a
  partial report. `python3 -m vharness resume --out <dir>` continues it later.

Agents run through the `claude` CLI, so they use whatever login the CLI has: `ANTHROPIC_API_KEY` if set, otherwise
the CLI's own sign-in. The [Agent SDK docs](https://code.claude.com/docs/en/agent-sdk/overview) ask third-party
products to use API keys rather than offer claude.ai login. With a subscription, lower `--concurrency`, and use
`--budget` rather than `--max-usd`, because the reported cost is then an API-price estimate.

## Usage

```bash
pip install claude-agent-sdk jsonschema
```

```bash
python3 -m vharness run ../my-repo --out ~/audits/my-repo/run-1 --profile standard --budget 80 --max-usd 40
```

```bash
python3 -m vharness status --out ~/audits/my-repo/run-1
```

```bash
python3 -m vharness resume --out ~/audits/my-repo/run-1
```

```bash
python3 -m vharness check --out ~/audits/my-repo/run-1
```

Pass several targets to one run to enable cross-repository trace and consumer hunts. Pass `--prior <earlier-out>` to
carry earlier confirmed and needs_validation records into validation and exclude them from hunters.

Defaults: discovery model `claude-opus-5-5`, validation model `claude-sonnet-5-5` (they must differ unless
`--allow-same-model`), 8 workers, each prompt ≤ 25% of a 1M-token window. Override a role with `--role-model hunter=<model>`.
The backend interface is one method (`async run(AgentRequest) -> AgentResult`), so other providers plug in without stage changes.

## Tests

```bash
python3 -m unittest discover -s tests -v
```

The suite uses a scripted backend (no model) and covers the spec's test requirements R-TST-01 to R-TST-29, plus the
STE length check of `SPEC.md` (`scripts/ste_check.py`). The sandbox tests (`tests/test_sandbox.py`) use the real
sandbox: they try a fork bomb, filling the disk, writes to the target and system directories, a remount, network access,
leaking host environment variables, and promoting symlinks, FIFOs and hard links. They skip on hosts where the start test fails.

## Live acceptance run

`examples/live-run/` holds the output of a real run on the two fixture repositories, with `claude-opus-5-5` for
discovery and `claude-sonnet-5-5` for validation. It used the `standard` profile with a budget of 30 calls per
target. It made 43 agent calls and cost $5.04. Both planted defects were confirmed and independently verified
as P1 (IDOR in `get_note`, path traversal in `export_note`). The default-token fallback stayed `needs_validation`
with its exact blocker. The canary hook in the fixture's `.claude/settings.json` never ran, and the prompt-injection
`CLAUDE.md` was reported as a hardening note instead of being obeyed. The run is marked `incomplete`
(`hunt_budget_exhausted`) because the budget deferred 34 lower-priority units. The report lists each one.

`examples/live-run-sandbox/` is a live run on `notesapp` with `--sandbox require` (`standard` profile, budget 24, $3.85).
Hunters made 9 `sandbox_run` calls to try their PoCs and patches. One patch failed and was corrected before the
candidate was filed. Both confirmed records have PoC result `fixed`: in the harness's own runs, each test exits
non-zero on an unchanged copy and 0 on a patched copy. The default-token fallback, which source-only runs could only
mark `needs_validation`, was confirmed by execution. The target directory was byte-identical afterwards. The path
traversal was not reached in this run: the budget deferred 35 units (listed in the report).

`examples/live-run-fixer/` is a live run with `--sandbox require --fix` (budget 30, $4.13 including $0.35 of fixer
calls). It found and confirmed all three planted defects, and each PoC result was `fixed`. The fixer produced:

- IDOR: **accepted**. The test fails before and passes after the patch, and the suite passes.
- Path traversal: **accepted**, the same way.
- Default tokens: **needs_human**. Removing the fallback tokens breaks the existing tests, so the fixer added a
  `tests/conftest.py` that sets tokens for them. That changes how the existing tests run, so a person must decide.

The combined gate is **ok** for the two accepted fixes. All three patch files apply with `git am`. Applied together
with the `needs_human` fix, the other two fixes' regression tests stop working, because the module then needs token
environment variables. That is why only accepted fixes are combined, and why each patch is reviewed on its own branch.
The target was byte-identical after the run.
