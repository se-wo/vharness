# vharness

A security-focused, multi-agent vulnerability harness. It audits source repositories with
stateless AI agents, keeps all state in SQLite, and has a different model check every finding.

It follows Cloudflare's [Build your own vulnerability harness](https://blog.cloudflare.com/build-your-own-vulnerability-harness)
architecture. It also uses the methodology and attack-class knowledge of
[cloudflare/security-audit-skill](https://github.com/cloudflare/security-audit-skill) (MIT; vendored in
`vharness/knowledge/`). The specification is [`SPEC.md`](SPEC.md), written in ASD-STE100 Simplified Technical English.

> Defensive use only. Audit code that you own or are authorized to audit. Issue 1 is **source-only**:
> agents never execute target code.

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

The suite uses a scripted backend (no model) and covers the spec's test requirements R-TST-01 to R-TST-13, plus the
STE length check of `SPEC.md` (`scripts/ste_check.py`).

## Not in issue 1

Sandboxed execution of PoC tests (`unshare`-based, see SPEC 13.1) and an automated Fixer (SPEC 13.2) are reserved
extensions. Until then, each confirmed record carries a proposed PoC test and patch that are explicitly marked
not executed.
