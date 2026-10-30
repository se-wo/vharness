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

The suite uses a scripted backend (no model) and covers the spec's test requirements R-TST-01 to R-TST-20, plus the
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

## Not built yet

An automated Fixer (SPEC 13.2) is a reserved extension. A human must review every patch.
