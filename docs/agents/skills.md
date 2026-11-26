# Agent skills configuration

Repo-specific mappings consumed by local engineering skills: GitHub issue tracker, canonical triage labels, and single-context domain documentation.

## Issue tracker

Issues and PRDs for this repo live as GitHub issues on **`github.com/setjoin/setjoin`**. Use the `gh` CLI for all operations (it infers the repo from `git remote -v` when run inside the clone).

### Conventions

- **Create an issue**: `gh issue create --title "..." --body "..."`. Use a heredoc for multi-line bodies.
- **Read an issue**: `gh issue view <number> --comments`, filtering comments by `jq` and also fetching labels.
- **List issues**: `gh issue list --state open --json number,title,body,labels,comments --jq '[.[] | {number, title, body, labels: [.labels[].name], comments: [.comments[].body]}]'` with appropriate `--label` and `--state` filters.
- **Comment on an issue**: `gh issue comment <number> --body "..."`
- **Apply / remove labels**: `gh issue edit <number> --add-label "..."` / `--remove-label "..."`
- **Close**: `gh issue close <number> --comment "..."`

### Skill phrase mappings

- **"publish to the issue tracker"** → create a GitHub issue.
- **"fetch the relevant ticket"** → run `gh issue view <number> --comments`.

## Triage labels

The skills speak in terms of five canonical triage roles. This table maps those roles to the actual label strings used in this repo's GitHub issues.

| Canonical role    | Label in our tracker | Meaning                                  |
| ----------------- | -------------------- | ---------------------------------------- |
| `needs-triage`    | `needs-triage`       | Maintainer needs to evaluate this issue  |
| `needs-info`      | `needs-info`         | Waiting on reporter for more information |
| `ready-for-agent` | `ready-for-agent`    | Fully specified, ready for an AFK agent  |
| `ready-for-human` | `ready-for-human`    | Requires human implementation            |
| `wontfix`         | `wontfix`            | Will not be actioned                     |

When a skill mentions a role (e.g. "apply the AFK-ready triage label"), use the corresponding label string from this table.

## Domain docs

How engineering skills consume this repo's domain documentation when exploring the codebase. This is a **single-context** repo: one `CONTEXT.md` + one `docs/adr/` at the root.

### Before exploring, read these

- **`CONTEXT.md`** at the repo root — the ubiquitous-language glossary.
- **`docs/adr/`** — read the ADRs that touch the area you're about to work in (named `ARCH-NNN-*.md` / `DES-NNN-*.md`, e.g. `ARCH-003-account-scope-currency.md`).
- The nearest **`AGENTS.md`** for the path you're touching — this repo runs a "DOX rail" of per-area `AGENTS.md` files (root → child index → owning doc). Read root `AGENTS.md` first, then walk down to the nearest one that owns your path.

If any of these don't exist for a given area, **proceed silently** — don't flag their absence or suggest creating them upfront. `/grill-with-docs` creates `CONTEXT.md` entries / ADRs lazily when terms or decisions actually get resolved.

### File structure

```
/
├── AGENTS.md            ← root DOX rail (CLAUDE.md is a symlink to it)
├── CONTEXT.md           ← the glossary
├── docs/
│   ├── adr/
│   │   ├── ARCH-003-account-scope-currency.md
│   │   ├── ARCH-006-app-level-isolation-posture.md
│   │   └── …
│   └── agents/
│       └── skills.md    ← this config (issue tracker / triage labels / domain docs)
├── mailserver/AGENTS.md ← per-area DOX
└── …
```

No `CONTEXT-MAP.md` exists, so there is exactly one context. If the repo ever splits into multiple contexts, add a `CONTEXT-MAP.md` at the root pointing to per-context `CONTEXT.md` files and update this doc.

### Use the glossary's vocabulary

When your output names a domain concept (an issue title, a refactor proposal, a hypothesis, a test name), use the term as defined in `CONTEXT.md` — and avoid the synonyms it explicitly lists under each term's `_Avoid_`.

If the concept you need isn't in the glossary yet, that's a signal — either you're inventing language the project doesn't use (reconsider) or there's a real gap (note it for `/grill-with-docs`).

### Flag ADR conflicts

If your output contradicts an existing ADR, surface it explicitly rather than silently overriding:

> _Contradicts ARCH-006 (app-level isolation posture) — but worth reopening because…_
