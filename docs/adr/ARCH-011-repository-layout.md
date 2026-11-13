# ADR: ARCH-011 — Repository layout: canonical `setjoin.com/` modules, a `go.work` workspace, and a flat one-dir-per-concern tree

**Status:** Accepted
**Date:** 2026-06-01

## Context

The repository grew non-canonical Go module paths (`module authserver`, `module shared`, `module mailserver/gateway`) that are not importable, an extra `mailserver/gateway/` nesting level wrapping the whole backend, orphan empty directories, root clutter, date-prefixed docs with no lifecycle, and no home for client (desktop/mobile) code. Multi-module local development leaned on fragile `replace` directives. A one-time restructuring (executed as `github.com/setjoin/setjoin`, local ``) settled the layout the tree converges on.

## Decision

1. **Canonical Go module paths under `setjoin.com/`** — `setjoin.com/authserver`, `setjoin.com/mailserver` (flattened out of `gateway/`), `setjoin.com/mailctl`, `setjoin.com/shared`. Real, importable paths; no vanity-domain hosting implied.
2. **A `go.work` multi-module workspace** is the source of cross-module wiring — `replace` directives are removed. Each module keeps its own `go.mod`; the workspace `use`s them (and any future `apps/*` module as it is created).
3. **A flat, one-directory-per-concern hierarchy.** Each server is `cmd/<bin>/` + `internal/<concern>/` + `sql/{migrations,reducers,schema,tests}/`; no wrapper levels, no orphan empty dirs. `shared/` holds the cross-cutting Go packages.
4. **`clients/` is the single home for all client code** — Tauri cross-platform desktop (`clients/desktop/`, reusing the webmail UI), native mobile (`clients/ios/`, `clients/android/`), and HTML previews. Client code does **not** live under `mailserver/`.
5. **Docs are organized by type, not by date** — `standards/` (enforced rules), `guides/` (operator runbooks), `ref/` (implementation reference), `compliance/`, `adr/`, `design/` (by topic subdirectory), `plans/` (with `plans/archive/` for completed work).
6. **`apps/` is the reserved location for future self-contained platform services** (each its own Go module + deployment); the agent orchestrator (`symphony`) is extracted to its own repository, out of this tree.

## Consequences

- Imports are canonical and IDE/tooling-friendly; a new contributor builds all modules through one `go.work` with no `replace` bookkeeping.
- A new platform service has an obvious, planned home (`apps/<name>/`) without re-litigating layout; new client work lands under `clients/`.
- The flat tree maps one concern to one directory, which the per-area `AGENTS.md` DOX rail and architecture-review skills navigate directly.
- Calendar/Contacts stay in `mailserver/internal/{caldav,carddav}/` (already built; an `apps/` copy would duplicate); `apps/` is for genuinely new services only.
- Reversibility: layout is structural and load-bearing; changing module paths again is a mechanical-but-wide `sed` over imports plus a `go.work` edit.
