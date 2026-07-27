# CANA Sovereign Work OS — Candidate v0.1.0

Status: **candidate / not promoted / launch gate closed**

## Protected baseline

The candidate extends the existing governed RSI-Hermes baseline; it does not replace it.

| Repository | Protected branch | Protected commit | Role |
|---|---|---:|---|
| `princeleuel-code/rsi-sitemind-core` | `main` | `9333c1d572a6be39df30e98ee07c451624190a8f` | authorization, tenant isolation, receipts, promotion, revocation and rollback authority |
| `princeleuel-code/rsi-hermes-runtime` | `rsi-runtime-main` | `d97d91c6542a071337a244262fc1f68426a03ab8` | governed Hermes runtime overlay; upstream mirror remains separate |
| `princeleuel-code/rsi-hermes-bridge` | `main` | `b0d067939dbec69520706adcc38f43a9168c8fe6` | signed authorization and action-contract enforcement before connector calls |
| `princeleuel-code/rsi-skills` | `main` | `e9aa9e8d64b28f4de5ae8831e682701e324db987` | proposal-only versioned procedures |
| `princeleuel-code/rsi-evaluations` | `main` | `5dc9ea2dc83e27b29dc3156fb0eb9743b79863a7` | cross-repository fail-closed evaluation court |
| `princeleuel-code/rsi-domain-connectors` | `main` | `4b48c13f83764b5f85c145b460044aa19711991d` | typed tenant-scoped connector operations |
| `princeleuel-code/rsi-deployment` | `main` | `56794a4cfe7f83f392f063f116780be790dc0373` | supervised isolated container deployment baseline |

No connected repository named CANA, ORBIT, or ORDERWEEDDC was found during this inspection. Those project instances remain migration targets rather than verified integrations.

No GitHub CI status or workflow run was attached to the protected `rsi-sitemind-core` commit. The new candidate foundation was exercised in an isolated local reconstruction: **13/13 candidate tests passed**. This is evidence for the new modules only, not proof that the full remote repository test suite or production deployment passed.

## Candidate branch and rollback

Candidate branch:

`candidate/cana-sovereign-work-os-v0.1.0`

Rollback is immediate because the protected `main` ref was not moved. Delete or abandon the candidate branch to return to the exact protected commit. Promotion must occur through the existing promotion court after full repository, cross-repository, security, shadow and canary gates pass.

## Architecture

```text
Signals and connected systems
        |
        v
Normalization -> source/confidence classification -> project routing
        |
        v
MissionRegistry + MemoryRegistry + SkillRegistry
        |
        v
ProviderNeutralRouter -> governed Hermes bridge -> authorized tools
        |
        v
Verification -> receipts -> TruthGraph -> canonical vault
        |
        v
FeedbackToCapabilityCompiler -> replay evaluation -> promotion court
```

Authority remains in `rsi-sitemind-core`. Hermes is an execution worker, not a source of authorization. Provider names do not receive hard-coded preference.

## Implemented candidate capabilities

### Durable memory

`MemoryRegistry` provides:

- stable IDs and structured metadata;
- duplicate detection by canonical payload hash;
- explicit contradiction state instead of silent overwrite;
- explicit supersession links;
- review-date based stale detection;
- project and scope isolation fields.

### Mission workspaces

`MissionRegistry` enforces state transitions across planned, active, blocked, partial, completed-unverified, verified, failed, rolled-back and superseded states. A mission cannot become `VERIFIED` without receipt references.

`CANAVault.create_mission_workspace` produces:

- `GOAL.md`
- `PLAN.md`
- `WORKLOG.md`
- `RECEIPTS.md`
- `DECISIONS.md`
- `RISKS.md`
- `OPEN_GAPS.md`
- `ROLLBACK.md`
- `MISSION.json`

### Heartbeat governance

`HeartbeatGovernor` is an idempotent and resumable state machine. It records checkpoints and refuses completion until every required step has run and at least one receipt exists. It intentionally does not execute tools; actual execution must pass through authorization, capability and action contracts.

### Provider-neutral routing

`ProviderNeutralRouter` applies hard capability, privacy, context, cost, latency and provider-exclusion policies. It fails closed when no endpoint satisfies every policy and returns ordered fallbacks when several endpoints qualify.

### Skill registry and anti-bloat

`SkillRegistry` versions skills, scopes them by project, requires trigger and non-trigger rules, enforces tool availability and maximum autonomy, records usage, detects high correction rates and identifies overlapping triggers. Rare skills are reported for review rather than automatically deleted.

### Gated self-improvement

`FeedbackToCapabilityCompiler` requires repeated durable feedback across distinct sessions before emitting a candidate patch. The candidate remains `PROPOSED`. Replay comparison rejects safety, quality, correction-count or unnecessary-tool regressions and only recommends eligibility for later shadow/canary review.

### TruthGraph

`TruthGraph` distinguishes planned, attempted, partial, completed-unverified, verified, failed, rolled-back and superseded claims. It rejects verified claims without evidence.

### Canonical vault and security

`CANAVault` creates the required thirteen top-level directories, content-addresses receipt artifacts and performs a fail-closed scan for common credential patterns. This scanner is a first gate, not a substitute for dedicated secret-scanning infrastructure.

## Default heartbeat contract

All first deployments begin at autonomy level 0 or 2.

| Heartbeat | Initial autonomy | Required outcome |
|---|---:|---|
| Morning intelligence | 0 — observe | ranked brief with direct evidence references |
| Midday execution | 2 — draft | progress reconciliation and proposed next actions |
| Evening verification | 0 — observe | receipt reconciliation and honest status classification |
| Condition watch | 0 — observe | notification only when the defined condition is met |

No heartbeat may publish, spend, send external messages, connect credentials or change production state merely because it runs on a schedule.

## Autonomy and permission matrix

| Level | Permitted by this candidate | Still required |
|---|---|---|
| 0 Observe | read authorized sources and summarize | tenant/source policy |
| 1 Recommend | produce proposals | evidence and uncertainty |
| 2 Draft | create reviewable candidate artifacts | no external side effect |
| 3 Reversible internal | not automatically granted | signed action contract and rollback proof |
| 4 Approved external | not automatically granted | explicit approval, signed contract and receipts |
| 5 Policy-bounded | not automatically granted | capability-specific certification, canary, monitoring and revocation |

## Plugin packaging plan

Recommended packages:

1. `cana-core-governance`: mission state, memory, TruthGraph, receipts and evidence verification.
2. `hermes-operations`: heartbeat coordination, delegation, close-loop drafts and progress review.
3. `orbit-research-fusion`: source escalation, contradiction mapping, cross-source fusion and evidence boundaries.
4. `orderweeddc-governor`: competitor intelligence, website review, listing/menu provenance, compliant copy, provider certification and launch-gate review.

Apps and connectors remain separate permission surfaces. Installing a package must not widen read or write authority.

## Threat model

The candidate explicitly addresses:

- poisoned or contradictory memory;
- unsupported completion claims;
- duplicate scheduled execution;
- unsafe self-promotion;
- provider lock-in;
- cross-project routing;
- credential leakage in vault text;
- ambiguous skill routing;
- false cleanup pressure on rare recovery skills.

Still required before promotion:

- dedicated prompt-injection fixtures against real connectors;
- cross-tenant integration tests;
- external transparency anchoring for receipt checkpoints;
- dependency and artifact signing;
- full secret scanning across generated artifacts and history;
- chaos tests for provider, tool and storage failures;
- real shadow and canary evidence.

## Migration plan

1. Inventory every existing vault, repository, project note, skill and receipt store.
2. Import metadata only; do not overwrite source artifacts.
3. Assign stable object IDs and project/scope labels.
4. Classify each object as observed, inferred, disputed, stale, superseded or unknown.
5. Detect duplicate and contradictory claims before activating retrieval.
6. Register persistent project workspaces and create mission files.
7. Start read-only heartbeats.
8. Collect feedback events without changing production skills.
9. Run historical replay and cross-repository evaluation.
10. Promote one capability at a time through signed receipts.

## Operator procedure

1. Pin the protected commit and record the candidate head.
2. Run the complete existing test suite and record the exact count.
3. Run the new work-OS tests.
4. Run `rsi-evaluations` attack court against the candidate.
5. Generate a secret-scan report and software bill of materials.
6. Initialize a disposable CANA vault and validate it.
7. Execute duplicate, contradiction, stale-memory and supersession fixtures.
8. Execute heartbeat replay, interruption and receipt-gate fixtures.
9. Execute provider-routing failure and fallback fixtures.
10. Replay representative historical feedback and verify no candidate self-promotes.
11. Perform read-only shadow operation.
12. Review receipts and either reject, continue to canary or promote through the court.

## Deliverable status

| Deliverable | Status |
|---|---|
| Protected baseline report | completed for accessible GitHub repositories |
| Architecture map | completed |
| Canonical vault schema/runtime | candidate implemented |
| Mission registry | candidate implemented |
| Heartbeat configuration/runtime | state machine implemented; scheduler integration pending |
| Mission templates | generated by runtime |
| Skill registry | candidate implemented |
| Initial project-specific skills | separate skills-repository candidate required |
| Plugin packaging plan | completed as design; packages not published |
| Autonomy matrix | completed |
| Feedback-to-Capability Compiler | candidate implemented |
| Replay evaluation logic | candidate implemented; historical corpus pending |
| Memory contradiction/supersession | candidate implemented |
| Anti-bloat review | candidate implemented |
| TruthGraph integration | candidate primitive implemented; existing receipt-ledger binding pending |
| Security threat model | completed at foundation level |
| Tests and results | 13/13 isolated candidate tests passed; full remote suite pending |
| Migration plan | completed |
| Rollback plan | completed and branch-isolated |
| Operator documentation | completed |
| Evidence bundle | commit chain plus local test output; signed/anchored bundle pending |
| Final status | candidate only; launch gate remains closed |

## Launch gate

**CLOSED.**

The following must not be claimed yet: complete CANA deployment, active scheduled heartbeats, connected ORDERWEEDDC operations, full historical-memory migration, production plugin publication, provider credentials, full repository test pass, cross-repository attack-court pass, shadow pass, canary pass or production promotion.
