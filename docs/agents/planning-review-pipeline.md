# Planning review pipeline

Contract for planning and review work. The root session owns integration and final
verification; the user owns material decisions and any approval not already granted for
this exact scope. Existing implementation/release holds remain binding. Reuse a recorded
approval; routine corrections and completed sections need no fresh approval.

## Stage contracts

- **Plans carry their requirements.** Original requirements, follow-up owner input and
  attachments reach the author unfiltered (sanitized); summaries navigate, they do not
  replace the source text. A plan states requirements, acceptance criteria and steps, and
  never overrides the original requirements.
- **Mechanical checks first.** File hashes vs receipts, acceptance-check greps, path
  existence, context-budget and link guards. Scripts verify what scripts can verify.
- **Review is a fresh read.** A reviewer is not the authoring session. Delta review
  covers affected invariants and integration boundaries; read the full relevant scope
  when no accepted baseline exists. Correct actionable findings within the authorized
  scope.
- **The user owns material decisions** (scope, provenance, visual/user gates and
  ungranted implementation authority). An existing approval remains valid for
  unchanged scope.

## Handoffs and receipts

Every stage exits into a frozen artifact: input hashes, per-finding IDs and a receipt
(findings with accepted/rejected dispositions). A later stage reviews only the changed
delta against those hashes; unchanged accepted evidence is reused.

## Stop rule

After at most two correction cycles per stage, reassess remaining findings. Continue
safe, actionable corrections or isolate the next bounded unit when authorized. A new
material user decision or unavailable irreplaceable evidence is a named hold for that
unit. Never repeat an unchanged review to seek a better score.
