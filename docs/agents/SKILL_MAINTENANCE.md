# Skill maintenance

This owner implements the 2026-09-11 instruction-audit decision. Keep installed skills
discoverable for their actual task, with short entrypoints and conditional references.
Do not load full planning workflows for routine corrections or documentation moves.

## Canonical entrypoints

Skills are installed per developer machine from each harness's own plugin or skill
directory; this repository ships no agent skills, hooks or harness configuration.
Contributors keep their own entrypoints and releases consistent.

## Update procedure

1. Inspect the actual launcher/interpreter and package manager before updating a skill.
2. Back up only affected skill files/hooks/configuration to a task-owned directory;
   do not touch unrelated plugins.
3. Review upstream changes before updating. Never infer latest from a skill's version
   marker alone. Validate frontmatter, references, package invocation and package/skill
   parity. New sessions reload the skill catalog; already-running tasks may still carry
   the old metadata.
4. Preserve unrelated hooks and configuration.
5. Clean task-only artifacts; retain installed runtime caches and upstream snapshots
   needed for rollback/reapplication, with provenance recorded in the task receipt.

## Project design guidance

Select the smallest suitable design workflow; do not run overlapping audits or preload
every design manual. Project authority wins over any skill default: keep Svelte 5, the
existing components, semantic design tokens, approved fonts/icons, localization,
accessibility and CSP. Do not add React/Next.js, Tailwind, animation libraries, remote
fonts or placeholder assets because a skill suggests them. Dense dashboards, tables,
multi-step workflows, native mobile and real-time collaboration keep their existing UI
owners and approved design plans. An `audit` or `critique` request is read-only unless
the user also asks for corrections.

## DOX maintenance

Root ≤10,000 bytes, each child ≤16,000, ancestor chain ≤32,000. The dynamic guard
includes new/untracked first-party rails; generated/dependency directories
and directory symlinks are not first-party traversal roots. Instruction-file symlinks
must resolve within the project. Do not exploit exclusions to hide oversized rules.

Detailed references retain domain authority, with task-selected section reading.
Same-heading redirects preserve old AGENTS anchors. Keep pure mechanical preservation
and explicitly reviewed procedural corrections separate in the receipt. Historical
domain contradictions require their current standard/ADR, not invented policy.
