# e2e — Playwright suite (DOX rail)

Owns Playwright specs/fixtures/helpers. New specs read admin-crud.spec.ts, routing, seeded fixtures and deterministic rules. Use describe-level @user/@admin tags, not body skips; workers:1 until real fixture isolation. Capture mutation ACK before action and await before reload; no networkidle/timed-sleep synchronization. Destructive arrangements use dedicated identities, run/project names and captured IDs. Restore through strict product API; SQL arrange/assert must not bypass deletion/audit. Shared Alice is not disposable. Install first-document state before navigation; preserve SW fencing and dedicated real lifecycle tests. Never relax errors/skips/snapshot tolerance/retries to fabricate pass. Read selected stack/runtime/lane and COVERAGE.md; preserve source-bound cases and resource ownership. Onboarding only uses disposable uninitialized DB front door.

## DOX sections

- [Stack](DOX.md#stack)
- [Project routing — tags, not skips](DOX.md#project-routing--tags-not-skips)
- [Seeded fixtures (fixtures/seed.sql)](DOX.md#seeded-fixtures-fixturesseedsql)
- [The rules that keep the suite deterministic](DOX.md#the-rules-that-keep-the-suite-deterministic)
- [Helpers (helpers.ts)](DOX.md#helpers-helpersts)
- [Live-stack gated specs](DOX.md#live-stack-gated-specs)
- [Local repeat-runs](DOX.md#local-repeat-runs)
# First-boot onboarding

[Details](DOX.md#first-boot-onboarding)

- [Supported Linux browser runtime](DOX.md#supported-linux-browser-runtime)
