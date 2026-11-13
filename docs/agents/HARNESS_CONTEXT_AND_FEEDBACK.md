# Agent harness context and feedback contract

This is the detailed owner for Setjoin's agent-harness rules. The root
`AGENTS.md` and child DOX files are directory pages and hard invariants; this
document describes how an agent should carry context, isolate work, and prove
results without turning the instruction rail into a second project manual.

## Governing model

Setjoin borrows the portable parts of an open agent harness:

- **Repository as the system of record.** Durable decisions, plans, evidence,
  source fingerprints, corrections and unresolved risks are written to owned
  files. A conversation, model response or attachment is not a durable fact
  until the root records it with scope and provenance.
- **Invariants over implementation.** Agent rules state authority, ownership,
  safety boundaries, outputs and acceptance checks. They do not prescribe
  incidental algorithms, prompt style or a preferred implementation when the
  contract does not require it.
- **Product boundary stays explicit.** Codex's `exec`, SDK and app-server
  lifecycle is a reference for agent tooling only. Setjoin does not claim to
  implement a Codex-compatible agent runtime or protocol unless a separate
  approved plan says so.

## Write — persist the useful state

At the end of a meaningful unit, write the smallest durable record that lets a
fresh agent continue without replaying the conversation:

1. objective and bounded scope;
2. owner and reviewer stage;
3. approved inputs and source fingerprint or file hashes;
4. changes, commands, exit status and retained evidence;
5. accepted findings, deferred findings and residual risk;
6. next queue item or explicit `HOLD` reason.

Use the owning plan, verification receipt or agent-governance record. Do not
put transient narration, raw model traces, credentials, customer data or a
second copy of a completed program history in `AGENTS.md` or the issue queue.

## Select — load only the needed context

- Known-path work can read source directly. Read ancestor/nearest AGENTS rails once,
  then only the owning DOX/standard sections needed for the task. Do not load every
  reference or every program before a small edit.
- Treat each bounded review or implementation unit as a required-input
  manifest: paths, byte counts or token estimates, source version and expected
  outputs. Read only that manifest and its approved dependencies.
- Reuse a receipt only when its input hash and applicable invariants are
  unchanged. A changed path, source fingerprint, contract or boundary
  invalidates the dependent result and requires a focused re-review.
- Pass environment changes as deltas (`changed_paths`, new services,
  invalidated evidence), not as a repeated copy of the full project context.

## Compress — preserve decisions, not transcript volume

- Summaries must retain exact verdicts, hashes, unresolved risks and next
  actions. They may omit narration and repeated source text.
- A bounded packet's `SHIP` is not a whole-plan 10/10. Aggregate scores and
  release claims require every required packet, integration boundary and
  external gate to be present and usable.
- Compaction or a new session must consume the durable receipt, not infer
  completion from a truncated stream or a remembered conversation.
- If a required review, input, tool result or terminal event is unavailable,
  malformed or truncated, preserve the local work as `HOLD`/unavailable; never
  convert missing evidence into a pass.

## Isolate — make task boundaries physical and logical

- Split work by ownership and security boundary. Parallel writers own disjoint
  paths; read-only reviewers receive a bounded dossier and cannot edit.
- Writers and runners use a root-controlled isolated worktree or equivalent
  filesystem boundary. Read-only exploration may use the current checkout when
  it cannot mutate state.
- Every delegated unit has one lifecycle: `prepared → running → review →
  correction → accepted` or `held`. The root owns transitions, integration,
  credentials, external state, destructive actions and final verification.
- Review sessions are fresh per module. Do not carry one module's conversation
  history, assumptions or tool permissions into another module.
- Record task-specific temporary paths, processes, containers, images and
  volumes; clean only owned resources and retain evidence/caches with a reason.

## Feedback loop and acceptance

Every meaningful change has a feedback path before it is called complete:

1. name the deterministic command, test, lint, browser lane or source-bound
   checker that can falsify the claim;
2. run it against the same source version and fixtures named in the manifest;
3. retain the result, exit status, source fingerprint and artifact hashes;
4. have the required reviewer inspect the bounded result;
5. integrate only after the root checks links, ownership, scope and stale
   evidence.

A review is an independent read-only re-evaluation, never a substitute for missing
tests. Historical reviewer names and scores remain historical.

## Directory-page maintenance

When a hot instruction file approaches its budget or repeats detail already
owned elsewhere:

- keep the invariant, owner and stable link in the hot file;
- move procedural detail, examples and completed history to the owning guide,
  plan or archive;
- update the parent index and run the context-budget guard;
- do not delete a durable decision merely to make the file shorter.

All first-party rails (including hidden/new files) and their ancestor chains are checked
by `bash scripts/check-agent-context-budget.sh`; `bash scripts/check-agent-docs.sh` adds
links, anchors and the `.claude` self-tests. After changing AGENTS/DOX, run it. Reference movement preserves domain contracts and approval state.

For authorized implementation, completion includes relevant checks, inspection, fixing
task-caused failures and cleanup. Unrelated failures get a separate record. Do not
rerun all suites or ask for approval at every mechanical step. Required CI, fresh-run
and owner gates retain their original authority.
