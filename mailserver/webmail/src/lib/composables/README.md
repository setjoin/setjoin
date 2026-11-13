# Composables

Shared Svelte 5 composables for webmail routes. State is per instance (runes
`$state` exposed through getters) — never module-global route state. Both
composables delegate ALL transport policy (timeout, abort merging, 401/403
handling, login redirect, typed/display-safe errors) to the existing seams:
`$lib/http.ts`, `$lib/stores/session.ts`, `$lib/stores/auth.ts`,
`$lib/admin/client.ts`, `$lib/jmap/client.ts`.

## `settings-resource.svelte.ts` — `createSettingsResource<TData>`

Route-side state machine for one settings resource, wrapping the `$lib/http`
typed path (`typedFetch` for loads, `httpRequest` for saves).

Caller contract:

```ts
import { createSettingsResource } from '$lib/composables/settings-resource.svelte';

const res = createSettingsResource<Sig[]>({ load: { url: '/api/settings/signatures-list' } });
const sigs = $derived(res.data ?? []);

// Component setup: register cleanup so unmount aborts in-flight work.
onMount(() => () => res.cleanup());

// Load (and refreshes): resolves null on failure/cancellation; res.error is
// the seam's display-safe message.
const data = await res.load();

// Save: never throws. { ok: false } covers failure, cancellation and
// supersede; res.saveError carries the display-safe message.
const result = await res.save({ url: '/api/settings/signatures', method: 'PUT', body });
```

Lifecycle rules:

- **Per-call AbortController.** Each `load()`/`save()` owns a controller; the
  external `signal` field (e.g. an authed-bootstrap unmount signal) is merged
  into the wire call via `AbortSignal.any`.
- **Supersede protection.** A newer call in the same lane aborts the older
  one; a stale completion (success OR failure) can never overwrite newer
  state, and `pending`/`saving` settle exactly once by the lane's current
  call. Load and save are independent lanes.
- **Cancellation is not failure.** An abort from supersede, `cleanup()` or the
  external signal resolves `{ok: false}` / `null` WITHOUT writing an error.
  The seam's own timeout (its internal abort, ours still live) IS a failure
  and surfaces with the seam's authored text.
- **No-content saves.** Default save handling treats any 2xx as success
  (204-friendly). Pass `parse: 'json'` to decode a typed save result.
- **Display-safe errors only.** Error state is a string normalized by
  `$lib/errors:parseError` from the seam's already-authored message. To
  surface an authored backend problem message, pass the seam's `onError` hook
  — never read/echo raw response bodies in the page.

## `authed-bootstrap.svelte.ts` — `authedBootstrap(loader)`

The shared authenticated bootstrap for route initial loads. Call it during
component setup (it registers `onMount` synchronously and returns cleanup
through it); it no-ops under SSR.

```ts
import { authedBootstrap } from '$lib/composables/authed-bootstrap.svelte';

authedBootstrap(
	async (signal) => {
		const data = await res.load({ signal });
		// ...
	},
	{ onUnproven: () => { loading = false; } }
);
```

Lifecycle rules:

- **Probe, then prove.** It awaits `loadSessionStore()` (the
  `/.well-known/jmap` probe through the seam, `loginRedirect: null` — the
  probe itself never redirects). `loadSessionStore` catches its own failures
  and may retain a STALE session object, so its resolution alone is NOT
  authentication proof. Proof is a session document this probe freshly
  produced: non-null and reference-different from the pre-probe snapshot
  (successes always install a newly decoded document; failures leave the
  store untouched).
- **Never redirects by itself.** Expiry/anonymous outcomes stay in the
  auth/HTTP seams: a loader request that hits a 401 is redirected BY THE SEAM.
- **Bootstrap only.** Post-action redirects (e.g. settings/security's
  `goto('/login')` after revoking the CURRENT session) are domain behavior
  and stay in the pages — this composable never owns them.
- **`onUnproven` settles the page.** When the probe proves nothing
  (anonymous visitor or unavailable probe), the loader never runs — the
  optional `onUnproven` callback is where a page drops its initial
  `loading` flag so it renders its silent-empty/default surface instead of a
  stranded spinner. Not invoked after a proven probe or an aborted unmount.
- **Unmount aborts.** The cleanup aborts the controller passed to the loader;
  an unmount during the probe skips the loader entirely.
- **SSR no-op.** No browser/network bootstrap happens outside the browser.

## Raw-fetch census (frozen 2026-09-30, WP5 + completion round)

The pre-WP5 census froze **20 route files / 71 raw fetch calls** under
`src/routes/**`. WP5 and its completion round migrated the four named worst
offenders to **zero raw fetches** — all four now adopt `authedBootstrap` for
their mount-time bootstrap:

| File | Before | After | Migration |
| --- | --- | --- | --- |
| `settings/signatures/+page.svelte` | 4 | 0 | list load + 3 action saves → settings-resource; bootstrap → authedBootstrap |
| `settings/privacy/+page.svelte` | 4 | 0 | both loads + both saves → settings-resource; bootstrap → authedBootstrap |
| `quarantine/+page.svelte` | 4 | 0 | list load + post-action reloads → settings-resource; preview read + release/reject actions → typed seam / resource saves; bootstrap → authedBootstrap |
| `settings/security/+page.svelte` | 17 | 0 | all loaders (devices, security-score, `/auth/me`, sign-ins, sessions, secure-list, S/MIME, contact-certs, cert-status) and actions (revoke, revoke-all, secure-account, set-default, deletes) → settings-resource / `$lib/http`; the two FormData uploads and the 401-terminal secure-account call use `httpRequest` directly; bootstrap → authedBootstrap |

The remaining **16 files / 42 calls** are frozen verbatim as the
`route-raw-fetch` ESLint baseline in `mailserver/webmail/eslint.config.mjs`
(route-scoped ratchet). Each grandfathered exception is bound to the **exact
call fingerprint** — `callee + METHOD + first-argument source text`,
whitespace collapsed — so a NEW raw `fetch`/`window.fetch`/`globalThis.fetch`
call in `src/routes/**` fails lint, and REPLACING an old grandfathered call
with a new one fails even at an unchanged per-file count (the new fingerprint
is unknown, the removed one stale). Dropping a call without shrinking the
baseline fails the entry as stale; route test files are exempt. Reasons per
entry live with the baseline.

Remaining offenders (file → calls):

- `settings/migration/+page.svelte` → 7
- `admin/(mail)/migration/+page.svelte` → 6
- `inbox/+page.svelte` → 5
- `settings/+page.svelte` → 3
- `admin/(identity)/terms-of-use/+page.svelte` → 3
- `+page.svelte` (root, pre-login probes) → 3
- `settings/notifications/+page.svelte` → 2
- `settings/automatic-replies/+page.svelte` → 2
- `settings/approval-delegation/+page.svelte` → 2
- `blocked/+page.svelte` → 2 (pre-auth)
- `admin/(access)/user-risk/+page.svelte` → 2
- `setup/+page.svelte` → 1 (pre-auth)
- `settings/storage/+page.svelte` → 1
- `settings/about/+page.svelte` → 1
- `recover/+page.svelte` → 1 (pre-auth)
- `admin/+page.svelte` → 1 (readable-stream monitor)

**Next migration owner:** recorded as a TODOS follow-up (root to file) —
continue in bounded slices, settings storage/language-loader patterns first
(`settings/storage`, `settings/+page` offline-caps/profile), then the
mechanical load/save twins (`settings/notifications`,
`settings/automatic-replies`, `settings/approval-delegation`,
`settings/about`), adopting `authedBootstrap` for their initial loads.
Pre-auth pages (`+page.svelte`, `blocked`, `setup`, `recover`) need a root
decision: their hand-rolled shape mirrors the deliberately raw pre-login
flows in `stores/auth.ts`. Shrink the ESLint baseline (per fingerprint) and
this census in the same change that removes calls.
