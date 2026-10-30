# VHARNESS — Security Vulnerability Harness

## Specification

| Item | Value |
|---|---|
| Document | VH-SPEC-001 |
| Issue | 4 |
| Date | 2026-10-30 |
| Writing standard | ASD-STE100 (Simplified Technical English) |
| Status | Approved for build |

---

## 0. How to read this specification

0.1. This specification uses ASD-STE100 rules.

0.2. Each procedural sentence has a maximum of 20 words.

0.3. Each descriptive sentence has a maximum of 25 words.

0.4. Each paragraph has a maximum of six sentences.

0.5. Each instruction has one action, except when two actions occur at the same time.

0.6. Words in `code font` are technical names or values. Section 3 gives their definitions.

0.7. The word "must" identifies a requirement. Each requirement has an identifier, for example `R-HUNT-03`.

0.8. A WARNING identifies a risk of injury to persons, data, or systems. A CAUTION identifies a risk of damage to the result. A NOTE gives more data.

---

## 1. Scope

1.1. This specification describes the vulnerability harness `vharness`.

1.2. The harness finds security vulnerabilities in source code. It uses a set of AI agents that operate in stages.

1.3. The harness is for defensive use. Use it only on code that you own or that you have permission to audit.

1.4. Issue 1 of the harness does a source-only audit. It does not execute target code. Section 13 describes the reserved extensions.

1.5. This specification does not describe the internal design of the AI models.

---

## 2. References

| Ref | Title | Use in this specification |
|---|---|---|
| [REF-1] | Cloudflare, "Build your own vulnerability harness", blog.cloudflare.com, 2026-06-18 | Stage list, state store, task queue, model separation, context limit, gapfill, dedup, trace, feedback, wishlist |
| [REF-2] | Cloudflare, `security-audit-skill`, github.com/cloudflare/security-audit-skill, MIT licence | Coverage ledger, candidate gate, verdict contracts, severity anchors, attack-class text |
| [REF-3] | ASD-STE100, Issue 9 | Writing rules for this document |

NOTE: The harness includes the attack-class text of [REF-2] in the `vharness/knowledge/` directory. The MIT licence of [REF-2] applies to that text.

NOTE: [REF-1] does not publish its database schema, its prompts, or its model names. The schemas in this specification are an original design.

---

## 3. Technical names

| Name | Definition |
|---|---|
| Harness | The `vharness` program. |
| Operator | The person who starts and controls a run. |
| Target | One source repository that the harness audits. |
| Run | One execution of the harness on one or more targets. |
| Stage | One type of work in the pipeline. Section 6 lists the stages. |
| Task | One unit of work in a stage. One task starts one agent, or one step of plain code. |
| Task queue | The table of tasks in the state store. Workers take tasks from it. |
| Worker | One process slot that does one task at a time. |
| Agent | One model session that does one task and returns one JSON object. |
| Role | The function of an agent: `recon`, `hunter`, `critic`, `dedup`, `validator`, `tracer`, or `verifier`. |
| Backend | The software layer that connects the harness to a model provider. |
| State store | The SQLite database that holds all run state. |
| Architecture document | The summary of one target that plain code makes from the `recon` results. |
| Threat model | The attacker, the starting capability, the crossed boundary, and the broken assumption of one candidate. |
| Attack class | A named category of vulnerability, for example "Access control". |
| Custom attack class | An attack class that a `recon` agent makes for one target, with its own method. |
| Block | The text of one attack class or one discipline section in a knowledge file. |
| Coverage unit | One combination of surface, boundary, subsystem, and attack class. |
| Coverage ledger | The set of all coverage units of a run. |
| Wave | One generation of `hunter` tasks. A `critic` task closes each wave. |
| Sibling unit | A coverage unit that a hunter found outside its scope. |
| Shallow result | A `hunter` result with no candidate and too little evidence. |
| Candidate | A possible vulnerability that a `hunter` agent reports. |
| Primary candidate | A candidate that is not a duplicate of a different candidate. |
| Fingerprint | A stable identifier for one root cause. |
| Mechanical check | A check by plain code, with no model. |
| Record | The final structured result for one fingerprint. |
| Verdict | The decision in a record: `confirmed`, `needs_validation`, or `rejected`. |
| Blocker | A decisive fact that the source code cannot show. |
| Wishlist item | A request from an agent for a resource that it does not have. |
| Reachability | The result of the `trace` stage: `reachable`, `conditional`, `unreachable`, or `unknown`. |
| Exposure | The class from the `trace` stage: `exploitable_now`, `latent`, or `wrong_component`. |
| Consumer | A target that calls code in a different target of the same run. |
| Budget | The maximum number of agent invocations for each target, and an optional maximum cost in USD. |
| Profile | A preset of breadth and redundancy: `quick`, `standard`, or `deep`. |
| Context budget | The maximum prompt size for one agent, as a fraction of the model context window. |
| Discovery model | The model for the `recon`, `hunter`, `critic`, `dedup`, and `tracer` roles. |
| Validation model | The model for the `validator` and `verifier` roles. |

---

## 4. Safety

WARNING: DO NOT AUDIT CODE WITHOUT PERMISSION. AN AUDIT OF CODE THAT YOU DO NOT OWN CAN BE ILLEGAL.

WARNING: DO NOT LET AN AGENT EXECUTE TARGET CODE. TARGET CODE CAN CONTAIN MALWARE. ISSUE 1 GIVES AGENTS READ-ONLY TOOLS ONLY.

WARNING: DO NOT LET AN AGENT READ FILES OUTSIDE THE TARGET. FILES OUTSIDE THE TARGET CAN CONTAIN CREDENTIALS.

WARNING: DO NOT LOAD SETTINGS, HOOKS, PLUGINS, OR MCP SERVERS FROM THE TARGET. A TARGET CAN USE THESE TO EXECUTE COMMANDS.

WARNING: DO NOT SEND AUDIT TRAFFIC TO A DEPLOYED SYSTEM. THIS CAN CAUSE DAMAGE TO A LIVE SERVICE.

WARNING: DO NOT EXECUTE GIT OR OTHER PROGRAMS IN A TARGET. THE GIT CONFIGURATION OF A TARGET CAN EXECUTE COMMANDS.

CAUTION: Target files are data, not instructions. A target can contain text that tries to change the behavior of an agent.

4.1. Safety requirements

| ID | Requirement |
|---|---|
| R-SAFE-01 | Each agent must have only these tools: `Read`, `Grep`, `Glob`. |
| R-SAFE-02 | The harness must refuse each tool call with a path outside the target root. |
| R-SAFE-03 | The harness must resolve symbolic links before the check in R-SAFE-02. |
| R-SAFE-04 | The backend must load no settings files, hooks, plugins, skills, or MCP servers. |
| R-SAFE-05 | Each agent prompt must tell the agent that target content is untrusted data. |
| R-SAFE-06 | The harness must write output only to the output directory. |
| R-SAFE-07 | The output directory must be outside each target. |
| R-SAFE-08 | The harness must not change target files. |
| R-SAFE-09 | Agents must not have network tools. |
| R-SAFE-10 | The harness must read the commit of a target from the `.git` files. It must not execute `git` in a target. |

---

## 5. General description

5.1. Purpose

5.1.1. The harness finds vulnerabilities that cross a real trust boundary.

5.1.2. The harness gives each owner a source trace, the conditions, the priority, a proposed patch, and a proposed test.

5.1.3. The harness tells the operator which parts of the target it examined. It also tells the operator which parts it did not examine.

5.2. Design principles

| ID | Principle | Source |
|---|---|---|
| P-01 | Agents are stateless. All state is in the state store. | [REF-1] |
| P-02 | The agent that validates a candidate is never the agent that found it. | [REF-1], [REF-2] |
| P-03 | The validation model is different from the discovery model. | [REF-1] |
| P-04 | Each agent prompt uses less than 25% of the model context window. | [REF-1] |
| P-05 | Plain code does all bookkeeping. Mechanical checks occur before model checks. | [REF-1] |
| P-06 | Coverage is a ledger of units, not a count of agents. | [REF-2] |
| P-07 | A hunter states the threat model before it files a candidate. | [REF-1] |
| P-08 | Only a `confirmed` record has a severity. | [REF-2] |
| P-09 | A gap in defense-in-depth is a hardening note, not a vulnerability. | [REF-2] |
| P-10 | The harness is model-agnostic. A new backend needs no change to the stages. | [REF-1] |
| P-11 | Each run adds to the coverage of earlier runs. | [REF-2] |
| P-12 | A malformed agent result is discarded. The harness does not repair it. | [REF-2] |
| P-13 | Persistence comes before parallelism. A crash loses only the tasks in progress. | [REF-1] |

5.3. Components

| Component | Module | Function |
|---|---|---|
| Command-line interface | `vharness/cli.py` | Reads operator commands. |
| Configuration | `vharness/config.py` | Holds profiles, models, limits, and the budget. |
| State store | `vharness/store.py` | Keeps runs, targets, units, tasks, candidates, records, and invocations. |
| Backend | `vharness/backends.py` | Runs one agent and returns one validated JSON object. |
| Path guard | `vharness/guard.py` | Refuses tool calls outside the target root. |
| Knowledge | `vharness/knowledge.py` | Loads attack-class blocks from the knowledge files. |
| Schemas | `vharness/schemas.py` | Defines the JSON schema for each agent role and each verdict. |
| Record checks | `vharness/records.py` | Does the mechanical checks. |
| Prompts | `vharness/prompts.py` | Makes the prompt for each role. |
| Budget | `vharness/budget.py` | Counts invocations and cost, and keeps reserves. |
| Stages | `vharness/stages.py` | Contains one handler for each stage. |
| Orchestrator | `vharness/orchestrator.py` | Runs the workers and the task queue. |
| Reports | `vharness/report.py` | Writes the report files from the state store, with plain code. |

---

## 6. Pipeline

6.1. Stages

6.1.1. The harness has these stages:

| Stage | Executor | Input | Output |
|---|---|---|---|
| `recon` | 3 agents | Target root | Architecture document, surfaces, boundaries, attack classes |
| `plan` | Plain code | `recon` results | Coverage units |
| `hunt` | Agent | Coverage units | Unit evidence, candidates, sibling units, wishlist items |
| `gapfill` | Agent | Coverage ledger | New units, reassigned units |
| `dedup` | Plain code, then agent | One candidate | Primary candidate or duplicate link |
| `validate` | Plain code, then agent | One primary candidate | One record |
| `trace` | Agent | One record | Reachability, exposure, consumers |
| `feedback` | Plain code | Shallow results, rejections, consumers | Requeued tasks, new units |
| `verify` | Agent | One record | `verified` or a replacement |
| `report` | Plain code | State store | Report files |

6.2. Task queue

6.2.1. The `recon` and `plan` stages run first for each target.

6.2.2. After `plan`, the stages `hunt` to `verify` run as one continuous producer-consumer loop [REF-1].

6.2.3. Each completed task can add new tasks to the queue. The table in 6.3 gives the rules.

6.2.4. Each worker takes the queued task with the highest stage priority. The stage priority, from high to low, is: `verify`, `trace`, `validate`, `dedup`, `gapfill`, `hunt`, `recon`.

NOTE: The stage priority moves each candidate to a final record quickly. Thus a crash loses little work.

6.2.5. The loop for a target stops when no task of that target is `queued` or `running`. Then the `report` stage runs.

6.3. Transition rules

| Event | Action |
|---|---|
| All 3 `recon` tasks of a target are `done` | Run `plan`. Queue the `hunt` tasks of wave 1. |
| A `hunt` task returns a candidate | Run the mechanical check. If it passes, queue a `dedup` step. |
| A `hunt` task returns an `uncovered` entry | Make a sibling unit. Queue a `hunt` task for it in the same wave. |
| A `hunt` task returns a shallow result | Queue the `feedback` step for that unit. |
| The last `hunt` task of a wave is `done` | Queue one `gapfill` task. |
| A `gapfill` task returns new work | Queue the `hunt` tasks of the next wave. |
| A `dedup` step finds a primary candidate | Queue a `validate` task. |
| A `validate` task returns `confirmed` or `needs_validation` | Queue a `trace` task. |
| A `trace` task returns a consumer | Make a unit in the consumer target. Queue a `hunt` task for it. |
| No `hunt`, `gapfill`, `dedup`, `validate`, or `trace` task of a target is open | Queue one `verify` task for each record. |

6.4. Pipeline requirements

| ID | Requirement |
|---|---|
| R-PIPE-01 | The harness must write each result to the state store when the task ends. |
| R-PIPE-02 | The harness must run tasks in parallel, up to the concurrency limit. |
| R-PIPE-03 | The default concurrency limit must be 8. The operator can change it. |
| R-PIPE-04 | The harness must continue a stopped run from the state store. |
| R-PIPE-05 | On continuation, the harness must set each `running` task back to `queued`. |
| R-PIPE-06 | A run must end in one of two terminal states: `complete` or `incomplete`. |
| R-PIPE-07 | An `incomplete` run must record the exact reason. |
| R-PIPE-08 | The `report` stage must not use a model. |

---

## 7. Stage procedures

### 7.1. Stage `recon`

7.1.1. Input: the target root and the source reference.

7.1.2. Procedure:

1. Record the Git commit of the target. Record if the work tree has changes.
2. Start three `recon` agents in parallel. Each agent has one focus from 7.1.3.
3. Validate each result against its `recon` schema.
4. Make the architecture document from the three results with plain code.
5. Write the architecture document to the state store.
6. Write the architecture document to `<out>/targets/<target>/architecture.md`.

7.1.3. The three `recon` focuses:

| Focus | Result |
|---|---|
| `product` | Product type, users, stack, subsystems, build and test commands, protected resources |
| `authority` | Principals, trust boundaries, the strongest control on each boundary, controls that the source cannot show |
| `surfaces` | Entry surfaces with paths and sinks, the boundaries that each surface crosses, the attack classes for each surface, custom attack classes |

7.1.4. The `surfaces` agent gets the "When to use" section of each knowledge file. It selects companion files from these sections.

7.1.5. The `surfaces` agent can make custom attack classes [REF-1]. Each custom attack class has a name and a method.

7.1.6. Requirements

| ID | Requirement |
|---|---|
| R-RECON-01 | The architecture document must have a maximum of approximately 1000 words. |
| R-RECON-02 | Each path in a result must be repository-relative. |
| R-RECON-03 | The agent must select a companion file only for a boundary that it found in the source. |
| R-RECON-04 | The harness must cap custom attack classes at 6 for each target. |

### 7.2. Stage `plan`

7.2.1. Input: the `recon` results and the records of earlier runs.

7.2.2. Procedure:

1. Make one coverage unit for each surface, each boundary of that surface, and each attack class of that surface.
2. Calculate the `coverage_id` of each unit with the procedure in 8.2.
3. Set the status of each new unit to `planned`.
4. Read the records of earlier runs on the same target, if they exist.
5. Make a `planned` unit for each earlier `needs_validation` record.
6. Add each earlier `confirmed` fingerprint to the exclusion list for hunters.
7. Sort the units by priority. Use the rules in 7.2.3.

7.2.3. Priority rules, in this sequence:

1. Unauthenticated or lowest-trust surfaces come first.
2. Boundaries that protect the most valuable resources come next.
3. Units from earlier gaps, `trace`, or changed source come next.
4. Ties use the lexicographic order of `coverage_id`.

7.2.4. Requirements

| ID | Requirement |
|---|---|
| R-PLAN-01 | Two units with the same `coverage_id` must not exist in one run and one target. |
| R-PLAN-02 | The `quick` profile must use one subsystem value: `profile/quick/all-in-scope-subsystems`. |
| R-PLAN-03 | A unit that the budget cannot reach must have the status `deferred` and a reason. |
| R-PLAN-04 | The `plan` stage must not use a model. |
| R-PLAN-05 | Each surface must have a maximum of 4 attack classes and 2 boundaries in wave 1. The harness must record the other units as `deferred` with the reason `plan_cap`. |

### 7.3. Stage `hunt`

7.3.1. Input: the `planned` units of one wave.

7.3.2. Procedure:

1. Group units that share one subsystem and one boundary. Each group has a maximum of `units_per_hunter` units.
2. Make a prompt for each group. Use the content in 7.3.3.
3. Do the context check in 9.3.
4. Set the status of each unit in the group to `in_progress`.
5. Start one `hunter` agent for each group.
6. Validate the result against the `hunter` schema.
7. Update each unit with the result. Use the state table in 8.3.
8. Write each candidate to the state store with its fingerprint.
9. Write each wishlist item to the state store.

7.3.3. A `hunter` prompt contains these parts, in this sequence:

1. The role statement.
2. The untrusted-data statement.
3. The architecture document.
4. The assigned units, with starting paths.
5. The full text of each selected block, and the method of each custom attack class.
6. The excluded blocks, with reasons.
7. The hunt method.
8. The candidate gate.
9. The exclusion list of known fingerprints.
10. The feedback notes from 7.8, if they exist.
11. The result contract.

7.3.4. The candidate gate:

1. Write the threat model first. Name the attacker, the starting capability, the boundary, and the broken assumption.
2. Give a complete source trace from an entrypoint to a sink.
3. Name the strongest control on the path.
4. Do not make a crash into code execution.
5. Do not make a same-principal action into a privilege gain.
6. If a decisive fact is not in the source, use `needs_validation`.
7. If no principal is affected, the absence of a best practice is a hardening note.
8. For a proposed `confirmed` candidate, give a proof-of-concept test and a patch.

7.3.5. The candidate schema puts the `threat_model` property first. Thus the agent writes the threat model before the claim [REF-1].

7.3.6. Requirements

| ID | Requirement |
|---|---|
| R-HUNT-01 | Each assigned `coverage_id` must occur exactly once in the hunter result. |
| R-HUNT-02 | A malformed result must set its units back to `planned` for a new owner. |
| R-HUNT-03 | A hunter must not propose the verdict `rejected`. |
| R-HUNT-04 | A hunter must report each path outside its scope as an `uncovered` entry. |
| R-HUNT-05 | A `covered` unit must have reviewed paths and at least one check. |
| R-HUNT-06 | The harness must accept a maximum of 2 sibling units from one hunter result. |
| R-HUNT-08 | The harness must not store a hardening note that is the same as an earlier note of the target. |
| R-HUNT-07 | A sibling unit of a sibling unit must not get a new sibling unit. |

### 7.4. Stage `gapfill`

7.4.1. Input: the coverage ledger after a wave.

7.4.2. Procedure:

1. Calculate the coverage matrix of subsystem by attack class with plain code.
2. Find each cell with no `covered` or `candidate` unit.
3. Start one `critic` agent. Give it the ledger summary, the matrix, and the thin cells.
4. Validate the result against the `critic` schema.
5. Add each accepted new unit as a `planned` unit in the next wave.
6. For each accepted reassignment, archive the earlier attempt. Then set the unit to `planned`.

7.4.3. The gapfill loop stops when one of these conditions occurs:

- the `critic` agent finds no new work;
- the last wave gave no new candidate and the `critic` agent found no thin cell;
- the profile maximum of waves occurs;
- the budget cannot pay for one more wave.

7.4.4. NOTE: Each gapfill wave costs approximately half of the first hunt wave [REF-1]. Gapfill is the main control of cost against coverage.

7.4.5. Requirements

| ID | Requirement |
|---|---|
| R-GAP-01 | The `quick` profile must not start a second hunt wave. It must record new work as `deferred`. |
| R-GAP-02 | The `standard` profile must have a maximum of 3 waves. |
| R-GAP-03 | The `deep` profile must have a maximum of 5 waves. |
| R-GAP-04 | The harness must reserve the budget for the critic before it starts a wave. |
| R-GAP-05 | A reassigned unit must get a new owner. The archive must keep the evidence of the earlier owner. |
| R-GAP-06 | Each new wave must also include `deferred` units with the reason `plan_cap`, in priority order. |

### 7.5. Stage `dedup`

7.5.1. Input: one candidate that passed the mechanical check.

7.5.2. Procedure:

1. If a primary candidate has the same fingerprint, mark the new candidate as a duplicate. Stop.
2. Make a shortlist of primary candidates with plain code. Use the indexes in 7.5.3.
3. If the shortlist is empty, mark the candidate as primary. Stop.
4. Start one `dedup` agent. Give it the candidate and the shortlist only.
5. Ask the agent: "Does one fix close this candidate and a candidate on the shortlist?"
6. Mark the candidate as a duplicate or as primary.

7.5.3. Shortlist indexes:

- the files and scopes in the trace;
- the boundary in the threat model;
- the rare tokens in the root cause.

7.5.4. NOTE: The harness does not compare all pairs with a model. That cost increases as O(N²) [REF-1].

7.5.5. NOTE: The `dedup` stage occurs before the `validate` stage. Thus the harness does not validate a duplicate.

7.5.6. Requirements

| ID | Requirement |
|---|---|
| R-DEDUP-01 | One root cause with more than one entry path must become one primary candidate. |
| R-DEDUP-02 | Two independent control gaps must keep two fingerprints. |
| R-DEDUP-03 | Only primary candidates go to the `validate` stage. |
| R-DEDUP-04 | The shortlist must have a maximum of 8 candidates. |
| R-DEDUP-05 | A fingerprint from an earlier run must reopen its earlier record. It must not make a new record. |

### 7.6. Stage `validate`

7.6.1. Input: one primary candidate.

7.6.2. Procedure:

1. Do the mechanical checks in 8.5.
2. If a mechanical check fails, write a `rejected` record. Use a reason that starts with `mechanical:`.
3. Make a `validator` prompt. Use the candidate, its unit checks, and the validation blocks.
4. Start one `validator` agent with the validation model.
5. Tell the agent to try to disprove the candidate.
6. Validate the result against the `validator` schema and the verdict schema.
7. Do the mechanical checks in 8.5 on the new record.
8. Write the record to the state store.

7.6.3. Verdict rules:

1. Use `confirmed` only if the agent found the complete path and the result in the source.
2. Use `needs_validation` if a specific deployment or runtime fact stays unknown.
3. Use `rejected` if the source, a visible control, or the absence of impact disproves the claim.
4. Do not use `needs_validation` for a speculative idea.

7.6.4. Examples of empty claims that the validator must reject [REF-1]:

- "The code calls `exec()`. Thus this is a critical vulnerability."
- "A principal has write access to the database. Thus this is a vulnerability."

7.6.5. Requirements

| ID | Requirement |
|---|---|
| R-VAL-01 | The validator must not be the hunter of the candidate. |
| R-VAL-02 | The validator must use the validation model. |
| R-VAL-03 | The validator must not get the decision of a different validator. |
| R-VAL-04 | The validator must keep the fingerprint, unless it finds a different root cause. |
| R-VAL-05 | A malformed result must start a new validator once. A second failure must leave the candidate unvalidated. |
| R-VAL-06 | A validator can only decide on its candidate. It must not create new candidates. |
| R-VAL-07 | Mechanical checks must occur before the validator agent starts. |
| R-VAL-08 | The harness can remove an empty field that the verdict does not permit. It must not change a field that has content. |

### 7.7. Stage `trace`

7.7.1. Input: one `confirmed` record or one `needs_validation` record.

7.7.2. Procedure:

1. Start one `tracer` agent for the record.
2. Tell the agent to find a path from an external attacker to the vulnerable code.
3. Validate the result against the `tracer` schema.
4. Write the reachability, the exposure, and the call path to the record.
5. Calculate the priority with the table in 8.7.
6. Search the other targets for the symbols of the trace, with plain code.
7. Write each target with a match to the state store as a consumer.

7.7.3. Exposure classes:

| Exposure | Definition |
|---|---|
| `exploitable_now` | An external attacker can reach the defect in the current code. |
| `latent` | The defect is real. No current path gives attacker input to it. |
| `wrong_component` | The defect is in a different component than the record says. |

7.7.4. Requirements

| ID | Requirement |
|---|---|
| R-TRACE-01 | A record with reachability `unreachable` must have the priority `P4`. |
| R-TRACE-02 | Each consumer must name a target of the same run and repository-relative paths in that target. |
| R-TRACE-04 | The consumer search must use plain code. An agent cannot read a different target. |
| R-TRACE-03 | The trace depth across targets must have a maximum of 1. |

### 7.8. Stage `feedback`

7.8.1. The `feedback` stage is plain code. It improves queued work with data from earlier tasks [REF-1].

7.8.2. Shallow results

7.8.2.1. A `hunter` result is shallow for a unit if all these conditions are true:

- the result has no candidate for the unit;
- the result has fewer than `shallow_min_checks` checks for the unit;
- the agent used fewer than `shallow_min_turns` turns.

NOTE: A quick empty result often shows a failure, not clean code [REF-1].

7.8.2.2. Procedure:

1. Archive the shallow attempt in the unit.
2. Add a feedback note to the unit. The note tells the next hunter that the last attempt was shallow.
3. Set the unit to `planned`.
4. Queue a `hunt` task for the unit with a new owner.

7.8.3. Rejection notes

7.8.3.1. When a validator rejects a candidate, plain code writes a rejection note for the target and the attack class.

7.8.3.2. The harness adds the last 5 rejection notes of that attack class to each later `hunter` prompt.

7.8.4. Requirements

| ID | Requirement |
|---|---|
| R-FEED-01 | The harness must requeue a shallow unit a maximum of 1 time. |
| R-FEED-02 | A requeued unit must obey the same budget rules as other units. |
| R-FEED-03 | A unit that is shallow two times must have the status `blocked` with the reason `shallow`. |

### 7.9. Stage `verify`

7.9.1. Input: each `confirmed` record and each `needs_validation` record.

7.9.2. Procedure:

1. Start one fresh `verifier` agent for each record, with the validation model.
2. Give the agent the structured record only. Do not give it the hunter text.
3. Get the decision `verified` or `replace`.
4. If the replacement is not material, apply it.
5. If the replacement is material, start one more fresh verifier for the replacement.
6. If the second verifier does not agree, remove the record. Set the run to `incomplete`.

7.9.3. A replacement is material if it changes one of these:

- the verdict, to a stronger verdict;
- the root cause;
- the trace;
- the demonstrated impact;
- the severity.

7.9.4. Requirements

| ID | Requirement |
|---|---|
| R-VER-01 | The verifier must not be the hunter, the validator, or the replacement author of the record. |
| R-VER-02 | In the `quick` profile, the `validate` and `verify` stages must be one stage. |
| R-VER-03 | The harness must verify `needs_validation` records, not only `confirmed` records. |

### 7.10. Stage `report`

7.10.1. Input: the verified records, the coverage ledger, and the wishlist.

7.10.2. Procedure:

1. Write `findings.json`. Sort the records by fingerprint.
2. Validate `findings.json` against the record schema.
3. Write `coverage-ledger.json`.
4. Write `REPORT.md`.
5. Write `FINDINGS-DETAIL.md` for each `confirmed` record with severity `medium` or higher.
6. Write `NEEDS-VALIDATION.md`.
7. Write `WISHLIST.md`.

7.10.3. `REPORT.md` contains these sections, in this sequence:

1. The run data: profile, scope, budget, source references, and the source-only statement.
2. A short summary of the security posture.
3. A table of `confirmed` records: priority, severity, exposure, title, and boundary.
4. The details of each `confirmed` record.
5. A table of `needs_validation` records, with no severity.
6. The hardening notes.
7. The coverage summary, with the counts for each unit status.
8. The wishlist summary.
9. The cost summary: invocations, tokens, and USD for each role.

7.10.4. Requirements

| ID | Requirement |
|---|---|
| R-REP-01 | The report must not show a `rejected` record as a vulnerability. |
| R-REP-02 | The report text must not change a verdict, a severity, or a blocker. |
| R-REP-03 | A partial run must say that it is partial in the first section. |
| R-REP-04 | A run with zero `confirmed` records must say so. It must not invent low findings. |
| R-REP-05 | The report must say that each proof-of-concept test and patch is not executed in issue 1. |

---

## 8. Data

8.1. State store

8.1.1. The state store is the file `<out>/harness.db`.

8.1.2. The state store has these tables:

| Table | Key | Content |
|---|---|---|
| `runs` | `run_id` | Profile, budget, models, status, reason, configuration |
| `targets` | `run_id`, `target` | Root path, commit, dirty flag |
| `stages` | `run_id`, `target`, `stage` | Stage status and time |
| `docs` | `run_id`, `target`, `kind` | Architecture document and `recon` results |
| `units` | `run_id`, `target`, `coverage_id` | Coverage unit fields and state |
| `tasks` | `task_id` | Run, target, stage, payload, status, attempts, agent, model, error |
| `candidates` | `run_id`, `target`, `fingerprint` | Proposed record, hunter, units, status, primary fingerprint |
| `records` | `run_id`, `target`, `fingerprint` | Verdict, record, validator, verifiers, reachability, exposure, priority |
| `consumers` | `run_id`, `fingerprint`, `target` | Consumer target and paths |
| `notes` | `note_id` | Hardening notes, feedback notes, rejection notes |
| `wishlist` | `item_id` | Agent, task, need, reason, and the unit that it unblocks |
| `invocations` | `invocation_id` | Role, agent, model, turns, tokens, cost, duration, result status |

8.1.3. The harness writes each agent prompt and each agent result to `<out>/agents/<agent_id>/`.

8.2. Coverage identifier

8.2.1. Calculate the `coverage_id` with this procedure:

1. Get the canonical reference of each dimension: surface, boundary, subsystem, attack class.
2. Normalize each reference to Unicode NFC. Remove the whitespace at the two ends.
3. Encode each reference with RFC 3986 percent-encoding. Keep only `A-Z a-z 0-9 - . _ ~` unencoded.
4. Join the four encoded references with `::`.

8.2.2. Do not put a wave, an agent, a verdict, a severity, or a line number in a `coverage_id`.

8.3. Unit states

| Status | Owner | Reviewed paths and checks | Fingerprints | Unresolved |
|---|---|---|---|---|
| `planned` | none | empty | empty | empty |
| `deferred`, `out_of_scope`, `not_applicable` | none | empty | empty | a reason |
| `in_progress` | agent | empty | empty | empty |
| `blocked` | agent | not empty, or empty for `context_budget` and `shallow` | empty | a blocker |
| `covered` | agent | not empty | empty | empty |
| `candidate` | agent | not empty | not empty | optional |

8.4. Fingerprint

8.4.1. A fingerprint must match the pattern `^[A-Za-z0-9][A-Za-z0-9._:/@+-]*$`.

8.4.2. A fingerprint must not contain a line number, a wave, an agent, a severity, or a verdict.

8.4.3. The same root cause must have the same fingerprint in each state.

8.5. Mechanical checks

| ID | Requirement |
|---|---|
| R-REC-01 | Each record must agree with the JSON schema of its verdict. |
| R-REC-02 | A trace with more than one step must start with `entrypoint` and end with `sink`. |
| R-REC-03 | Steps between the first and the last must be `propagation`. |
| R-REC-04 | Each path must be repository-relative. It must not contain `..` or start with `/`. |
| R-REC-05 | Each cited file must exist in the target. |
| R-REC-06 | Each cited line must be 1 or more, and not more than the line count of its file. |
| R-REC-07 | A `confirmed` record must have a severity, a remediation, conditions, a proof-of-concept test, and a confidence. |
| R-REC-08 | The overall severity of a `confirmed` record must not be more than its impact. |
| R-REC-09 | A patch must be a unified diff. Each file in the patch must exist in the target. |
| R-REC-10 | A `needs_validation` record must have blockers and a validation plan. It must not have a severity. |
| R-REC-11 | A `rejected` record must have a reason. It must not have a severity or a remediation. |
| R-REC-12 | Each record must use `evidence_level: "source"` in issue 1. |
| R-REC-13 | Each candidate and record must have a threat model. |

8.6. Severity anchors

| Severity | Use when |
|---|---|
| `critical` | An unauthenticated actor gets code execution, full data-store access, or takeover of all accounts. |
| `high` | An actor fully defeats an explicit control with real effects. Examples: authentication bypass, cross-tenant access, stored script execution. |
| `medium` | A real boundary violation with a limited effect, uncommon conditions, or a small set of resources. |
| `low` | A disclosure of non-secret internals, or an effect that needs much work for little gain. |
| `informational` | A confirmed observation with minimal effect. |

8.7. Priority

8.7.1. The harness does not use fixed deadlines for each severity [REF-1]. Priority comes from severity, reachability, and exposure.

| Priority | Rule |
|---|---|
| `P0` | Severity `critical`, and exposure `exploitable_now`. |
| `P1` | Severity `high` and exposure `exploitable_now`, or severity `critical` and reachability `conditional`. |
| `P2` | Severity `medium` and exposure `exploitable_now`, or severity `high` and reachability `conditional` or `unknown`. |
| `P3` | All other `confirmed` records that are not `P4`. |
| `P4` | Reachability `unreachable`, or exposure `latent`, or exposure `wrong_component`. |

---

## 9. Agent contract

9.1. General

| ID | Requirement |
|---|---|
| R-AGT-01 | Each agent must return exactly one JSON object that agrees with its role schema. |
| R-AGT-02 | The backend must use structured output when the provider supports it. |
| R-AGT-03 | The harness must validate each result again with the role schema. |
| R-AGT-04 | Each agent must get a new identifier that matches `^[a-z0-9][a-z0-9_-]{0,63}$`. |
| R-AGT-05 | An agent must not get the conversation of a different agent. |
| R-AGT-06 | Each agent must have a maximum number of turns. The default is 60. |
| R-AGT-07 | Each agent must have a maximum time. The default is 30 minutes. |
| R-AGT-08 | The backend must examine the result text for API error text. It must classify such a result as an error, not as a success. |
| R-AGT-09 | The backend must classify a result with no structured output as an error. |
| R-AGT-10 | Each agent can return wishlist items. A wishlist item must name the need, the reason, and the unit that it unblocks. |

NOTE: A temporary API error can arrive as text inside a successful response [REF-1]. R-AGT-08 prevents a false empty success.

9.2. Models

| ID | Requirement |
|---|---|
| R-MOD-01 | The default discovery model must be `claude-opus-5-5`. |
| R-MOD-02 | The default validation model must be `claude-sonnet-5-5`. |
| R-MOD-03 | The harness must stop with an error if the two models are the same. The operator can override this with `--allow-same-model`. |
| R-MOD-04 | The operator can set a model for each role. |
| R-MOD-05 | A new backend must implement one function: run one agent request and return one result. |

9.3. Context budget

9.3.1. Procedure:

1. Calculate the prompt size in tokens. Use 4 characters for each token.
2. Calculate the limit: context window multiplied by the context fraction.
3. If the prompt size is less than the limit, start the agent.
4. If the prompt is too large and it has more than one unit, split the units into two tasks.
5. If the prompt is too large and it has one unit, remove the companion blocks and try again.
6. If the prompt is still too large, set the unit to `blocked` with the reason `context_budget`.

9.3.2. Requirements

| ID | Requirement |
|---|---|
| R-CTX-01 | The default context fraction must be 0.25. |
| R-CTX-02 | The default context window must be 1,000,000 tokens. The operator can change it for each model. |

9.4. Retry

| ID | Requirement |
|---|---|
| R-RTY-01 | The harness must retry a task once after a backend error, for example a rate limit or a timeout. |
| R-RTY-02 | A retry must use a new agent identifier. |
| R-RTY-03 | The harness must not retry a malformed result in the same agent. |

---

## 10. Budget and profiles

10.1. Profiles

| Item | `quick` | `standard` | `deep` |
|---|---|---|---|
| Subsystem dimension | one value | per subsystem | per subsystem |
| Maximum hunt waves | 1 | 3 | 5 |
| Critic after each wave | yes | yes | yes |
| Separate `verify` stage | no | yes | yes |
| Units for each hunter | 4 | 3 | 2 |
| Shallow requeue | no | yes | yes |

10.2. Budget procedure:

1. Count each agent invocation against the budget of its target.
2. Before the `recon` stage, reserve three `recon` calls for the target.
3. Before each wave, reserve one critic call.
4. Before each hunter starts, calculate the open demand. Count validate, trace, and verify calls for each open candidate. Count the same calls for each other hunter that has started.
5. Reserve the open demand, one critic call, and 30% of the budget that remains after them.
6. Start the hunter only if the budget also pays for the hunter and one expected candidate.
7. Set each unit that the budget cannot reach to `deferred` with the reason `budget`. Set the run to `incomplete`.

10.3. Requirements

| ID | Requirement |
|---|---|
| R-BUD-01 | If the budget cannot pay for `recon`, one critic, and one validator, the harness must start no agent. |
| R-BUD-02 | If the budget cannot validate all candidates, the harness must validate in fingerprint order and set the run to `incomplete`. |
| R-BUD-03 | An unvalidated candidate must not go into `findings.json`. |
| R-BUD-04 | If the operator sets a USD limit, the harness must stop new tasks when the cost reaches the limit. |
| R-BUD-05 | The harness must not exceed a budget without a record in the report. |
| R-BUD-06 | The harness must count each agent against the budget when the agent starts. |

---

## 11. Operator interface

11.1. Commands

| Command | Function |
|---|---|
| `vharness run <target>... --out <dir>` | Starts a new run. |
| `vharness resume --out <dir>` | Continues the last run in the output directory. |
| `vharness status --out <dir>` | Shows the stage status, the unit counts, and the cost. |
| `vharness report --out <dir>` | Writes the report files again from the state store. |
| `vharness check --out <dir>` | Validates `findings.json` and `coverage-ledger.json`. |

11.2. Options of `run`

| Option | Default | Function |
|---|---|---|
| `--profile` | `standard` | Sets the profile. |
| `--budget` | none | Sets the maximum number of agent invocations for each target. |
| `--max-usd` | none | Sets the maximum cost in USD for the run. |
| `--concurrency` | 8 | Sets the maximum number of agents at the same time. |
| `--discovery-model` | `claude-opus-5-5` | Sets the discovery model. |
| `--validation-model` | `claude-sonnet-5-5` | Sets the validation model. |
| `--allow-same-model` | off | Lets the two models be the same. |
| `--scope` | all | Limits the audit to repository-relative paths. |
| `--prior` | none | Gives the output directory of an earlier run. |
| `--backend` | `claude` | Sets the backend. |

11.3. Requirements

| ID | Requirement |
|---|---|
| R-CLI-01 | The `run` command must refuse an output directory inside a target. |
| R-CLI-02 | The `run` command must refuse a target that is not a directory. |
| R-CLI-03 | The `check` command must return a non-zero exit code if a check fails. |
| R-CLI-04 | The harness must show progress for each task on the standard error stream. |

---

## 12. Verification of the harness

12.1. The harness has a test suite in `tests/`. The test suite uses a scripted backend. It does not use a model.

12.2. Test requirements

| ID | Requirement |
|---|---|
| R-TST-01 | A test must run the full pipeline on a fixture target with the scripted backend. |
| R-TST-02 | A test must show that the path guard refuses a path outside the target. |
| R-TST-03 | A test must show that the path guard refuses a symbolic link that goes outside the target. |
| R-TST-04 | A test must show that the harness discards a malformed agent result. |
| R-TST-05 | A test must show that a validator is never the hunter of its candidate. |
| R-TST-06 | A test must show the mechanical checks R-REC-01 to R-REC-13. |
| R-TST-07 | A test must show that the harness continues a stopped run. |
| R-TST-08 | A test must show the context split in 9.3. |
| R-TST-09 | A test must show the budget rules R-BUD-01 to R-BUD-03. |
| R-TST-10 | A test must show that the `coverage_id` procedure gives the same value for the same input. |
| R-TST-11 | A test must show that the backend classifies API error text as an error. |
| R-TST-12 | A test must show the shallow requeue in 7.8.2. |
| R-TST-13 | A test must show that a duplicate candidate does not go to the `validate` stage. |

12.3. Acceptance

12.3.1. All tests in `tests/` pass.

12.3.2. A run on the fixture target with the `claude` backend gives a valid `findings.json`.

12.3.3. The run in 12.3.2 finds at least one planted vulnerability.

12.3.4. Each sentence in this specification obeys the length limits in 0.2 and 0.3. The script `scripts/ste_check.py` does this check.

---

## 13. Reserved extensions

### 13.1. Sandboxed execution

13.1.1. Issue 1 does not execute target code. A source trace is the evidence for each `confirmed` record.

13.1.2. [REF-1] says that execution in a sandbox gave the largest single increase in quality. A future issue can add a `sandbox_run` tool. This tool must obey all the controls below.

WARNING: DO NOT ADD THE `sandbox_run` TOOL IF ONE CONTROL IS NOT AVAILABLE. TARGET CODE CAN DAMAGE THE HOST.

1. No external network. Use a new network namespace, for example with `unshare`.
2. An empty environment with an allowlist of variables.
3. A read-only target and toolchain.
4. Write access to the agent scratch directory only.
5. Limits for CPU, memory, processes, file size, disk, and time.
6. Promotion of evidence files only by trusted harness code, with the no-follow procedure of [REF-2].

CAUTION: In a Docker container, an `unshare` sandbox can fail to start with no error message. The container needs `seccomp=unconfined` and `apparmor=unconfined` [REF-1]. The harness must do a start test of the sandbox before each run.

13.1.3. With this extension, a record can use `evidence_level: "local"`. Such a record must contain the command, the input, and the observed result.

13.1.4. With this extension, the proof-of-concept test must fail on the unchanged target. The test must pass after the patch.

### 13.2. Fixer

13.2.1. A future issue can add a `fixer` role. The `fixer` adapts the patch to the style of the target. It runs the proof-of-concept test before and after the patch.

13.2.2. A fix is accepted only when the test changes from fail to pass with no regression.

WARNING: DO NOT LET THE `fixer` MERGE A CHANGE. A PERSON MUST EXAMINE EACH BRANCH.

---

## 14. Traceability

| Source feature | Section |
|---|---|
| [REF-1] Recon, Hunt, Validate, Gapfill, Dedup, Trace, Feedback, Report stages | 6, 7 |
| [REF-1] Stages 4 to 8 as a producer-consumer loop | 6.2 |
| [REF-1] State in one SQLite database, keyed by run, repository, and stage | 8.1 |
| [REF-1] Stateless agents, context below 25% of the window | P-01, P-04, 9.3 |
| [REF-1] Three parallel recon agents, custom attack classes | 7.1 |
| [REF-1] Threat model first, enforced by schema order | P-07, 7.3.5 |
| [REF-1] Sibling forking | 7.3, R-HUNT-06 |
| [REF-1] Wishlist | R-AGT-10, 7.10 |
| [REF-1] Mechanical checks before the model validator | P-05, 7.6, 8.5 |
| [REF-1] Validator cannot file its own findings | R-VAL-06 |
| [REF-1] Gapfill cells of area by attack class | 7.4 |
| [REF-1] Dedup with code indexes and an agent on a shortlist | 7.5 |
| [REF-1] Trace across repositories with one symbol index, and consumer hunts | 7.7 |
| [REF-1] Shallow results and requeue | 7.8 |
| [REF-1] Different models for discovery and validation | P-03, 9.2 |
| [REF-1] Errors that look like success | R-AGT-08 |
| [REF-1] Priority from reachability, not from fixed deadlines | 8.7 |
| [REF-1] Sandbox and Fixer | 13 |
| [REF-2] Coverage ledger and state table | 7.2, 8.2, 8.3 |
| [REF-2] Coverage critic waves | 7.4 |
| [REF-2] Candidate gate | 7.3.4 |
| [REF-2] Verdict contracts | 7.6.3, 8.5 |
| [REF-2] Independent record verification | 7.9 |
| [REF-2] Severity anchors | 8.6 |
| [REF-2] Profiles and budget | 10 |
