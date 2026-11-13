# M1 UI Primitive Library — Agent Guide

Owns shared Svelte primitives, barrel/helpers/tests; token authority is webmail theme/DESIGN.md. Public imports use $lib/components/ui and index.ts. Semantic styling is token-only; spacing baselines only decrease with documented structural exceptions. Caption/hint contrast, focus-visible rings, keyboard/ARIA and disabled-label behavior are contracts. Use Svelte 5 runes/onclick and $props.id(), not random IDs/counters. Pure geometry stays outside component state; avatarHash is cross-client stable. Preserve sizes and shared dialog/focus behavior. Read affected component contract; test variants, keyboard/ARIA/disabled paths and affected barrel/consumers. Historical test counts are not current acceptance.

## DOX sections

- [1. Purpose](DOX.md#1-purpose)
- [2. Ownership](DOX.md#2-ownership)
- [3. Local Contracts](DOX.md#3-local-contracts)
  - [Token-only styling](DOX.md#token-only-styling)
  - [Svelte 5 runes throughout](DOX.md#svelte-5-runes-throughout)
  - [Focus-ring convention](DOX.md#focus-ring-convention)
  - [Disabled-handler guard pattern](DOX.md#disabled-handler-guard-pattern)
  - [Auto-generated IDs](DOX.md#auto-generated-ids)
  - [Plain-module helpers](DOX.md#plain-module-helpers)
  - [Barrel (`index.ts`)](DOX.md#barrel-indexts)
  - [Key files](DOX.md#key-files)
- [4. Features / Capabilities](DOX.md#4-features--capabilities)
  - [Buttons](DOX.md#buttons)
  - [Forms](DOX.md#forms)
  - [Display & Navigation](DOX.md#display--navigation)
  - [Feedback & Data Display](DOX.md#feedback--data-display)
  - [Controls](DOX.md#controls)
  - [Types & Shared Utilities](DOX.md#types--shared-utilities)
- [5. Work Guidance](DOX.md#5-work-guidance)
- [6. Verification](DOX.md#6-verification)
- [7. Child DOX Index](DOX.md#7-child-dox-index)
