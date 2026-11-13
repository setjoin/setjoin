# Domain Docs

How the engineering skills should consume this repo's domain documentation when exploring the codebase.

This is a **single-context** repo: one `CONTEXT.md` + one `docs/adr/` at the root.

## Before exploring, read these

- **`CONTEXT.md`** at the repo root — the ubiquitous-language glossary.
- **`docs/adr/`** — read the ADRs that touch the area you're about to work in (named `ARCH-NNN-*.md` / `DES-NNN-*.md`, e.g. `ARCH-003-account-scope-currency.md`).
- The nearest **`AGENTS.md`** for the path you're touching — this repo runs a "DOX rail" of per-area `AGENTS.md` files (root → child index → owning doc). Read root `AGENTS.md` first, then walk down to the nearest one that owns your path.

If any of these don't exist for a given area, **proceed silently** — don't flag their absence or suggest creating them upfront. `/grill-with-docs` creates `CONTEXT.md` entries / ADRs lazily when terms or decisions actually get resolved.

## File structure

```
/
├── AGENTS.md            ← root DOX rail (CLAUDE.md is a symlink to it)
├── CONTEXT.md           ← the glossary
├── docs/
│   ├── adr/
│   │   ├── ARCH-003-account-scope-currency.md
│   │   ├── ARCH-006-app-level-isolation-posture.md
│   │   └── …
│   └── agents/          ← this config (issue-tracker / triage-labels / domain)
├── mailserver/AGENTS.md ← per-area DOX
└── …
```

No `CONTEXT-MAP.md` exists, so there is exactly one context. If the repo ever splits into multiple contexts, add a `CONTEXT-MAP.md` at the root pointing to per-context `CONTEXT.md` files and update this doc.

## Use the glossary's vocabulary

When your output names a domain concept (an issue title, a refactor proposal, a hypothesis, a test name), use the term as defined in `CONTEXT.md` — and avoid the synonyms it explicitly lists under each term's `_Avoid_`.

If the concept you need isn't in the glossary yet, that's a signal — either you're inventing language the project doesn't use (reconsider) or there's a real gap (note it for `/grill-with-docs`).

## Flag ADR conflicts

If your output contradicts an existing ADR, surface it explicitly rather than silently overriding:

> _Contradicts ARCH-006 (app-level isolation posture) — but worth reopening because…_
