# Webmail browser E2E coverage contract

“Complete browser E2E” is bounded and testable; it is not an unbounded global
Cartesian product.

- Within a feature, enumerate every user-visible discriminator and materially
  distinct transition: success, validation error, authorization error,
  network/semantic failure, persistence/reload, and teardown.
- Across orthogonal dimensions, use equivalence classes and pairwise coverage:
  user/admin/limited-admin/public guest; English/Chinese; light/dark;
  360/768/1024/1440 CSS pixels; fresh/existing state; OFF/ON/report-only;
  keyboard/pointer; online/error/retry.
- A new option is incomplete until its visible selection, emitted request or
  persisted value, reopened state, invalid input, and permission boundary are
  asserted. Merely clicking a control is not coverage.
- Peripherals are real in their phase: LiveKit is container-backed, CA uses the
  built mailctl and live gateway, and onboarding uses an uninitialized DB.

## Canonical phases

| Phase        | Authority exercised                               | Main contracts                                                                                     |
| ------------ | ------------------------------------------------- | -------------------------------------------------------------------------------------------------- |
| `main`       | Seeded gateway, authserver, PostgreSQL, SeaweedFS | User/admin CRUD, persistence, errors, authorization, a11y, responsive/visual states, health        |
| `ca`         | Live CA/device reducers + built mailctl           | OFF/report-only/enforced, proof/no-proof, cert, risk/terms remediation, sign-in evidence           |
| `csp`        | Production static build                           | Hash-only script CSP and bootability                                                               |
| `onboarding` | Dedicated uninitialized DB and ports              | Read-only browser setup, public-mutation 404s, local CLI bootstrap, login, terminal initialized state |
| `meet`       | Pinned real LiveKit SFU                           | Two members/media, lock/unlock, kick/BZ186, re-admit, guest lobby/kick/re-knock, end/terminal view |

Run all phases and verify their cross-phase skip ledger:

```bash
bash scripts/verify-all.sh browser-complete
```

Reports and logs live under `mailserver/webmail/test-results/browser-complete/`.

## Feature-option ownership

| Surface           | Dimensions pinned by specs                                                                                                                                                                                                                                                                                             |
| ----------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Login/security    | valid/invalid login, unauthenticated API, CA report/enforce, device proof/no-proof, risk, terms, certificate/no-certificate                                                                                                                                                                                            |
| Mail list/read    | focused/other, flat/threaded, sort property/direction, filter/search/highlight, HTML/plain/quoted, read/archive/snooze/mute/tags                                                                                                                                                                                       |
| Compose/send      | mention/table/voting, inline/file attachments, autosave/reload, reply/forward, quota error, NDR resend, S/MIME                                                                                                                                                                                                         |
| Delegation/shared | full-access/read-only/send-on-behalf, shared Sent, revoke/removal, limited-admin 403 and console absence                                                                                                                                                                                                               |
| Calendar          | color/show-as/private, work week/hours, dual timezone, attendee role, counterproposal, reminder, print, ICS/webcal success/failure                                                                                                                                                                                     |
| Contacts/tasks    | vCard/photo, start date, assignee/recurrence/subtask persistence, email-to-task                                                                                                                                                                                                                                        |
| Booking           | owner create/edit/reload/delete, numeric and weekly availability options, required questions, live/disabled state, unauthenticated 401 and cross-owner denial, public unknown/disabled parity, slot selection, required-answer UX, honeypot, success, stale-slot 409, confirmation/cancellation/reload, invalid tokens |
| Drive/Office/guest | secure-original/export/office fallback; Office/History OFF and mixed-toggle states; web/electron choice projection; viewer denial; WOPI info/get/lock/conflict/save/idempotent replay/stale branch; signed history pagination/tamper rejection; provider ready/draining/removed fencing with Drive bytes/history preserved; guest exclusion, member grant/revoke, invite disclosure/lifecycle |
| MAM admin         | real `device_registry` + `mdm_device_state` list wire (platform/name/compliance/last check-in), registry-only fallback, platform/compliance filters, detail projection                                                                                                                                                 |
| Admin             | domain/user sad path, approval CRUD/decisions, policy apply job, LDAP network/redaction, identity/updater durable states                                                                                                                                                                                               |
| Layout/a11y       | login structure, app routes, tour focus/Escape/replay, EN/ZH × light/dark × 360/768/1024/1440, narrow sheets                                                                                                                                                                                                           |
| Runtime           | cold/warm/compressed, CacheStorage boundary, `/health`, `/ready`, CSP, isolated cleanup/repeatability                                                                                                                                                                                                                  |

`admin-route-matrix.spec.ts` derives its cases from the canonical admin console
catalog and opens every registered admin route (52 at the current catalog
version). Each case requires a visible heading, the canonical URL, no unexpected
HTTP failure, and no unexpected console error. Default-stack dependencies and
OFF-gated surfaces are accepted only through an exact endpoint/status/visible-
state ledger in that spec; a generic 404/503 allow-list is not sufficient. This
route inventory complements the deeper per-feature option tests—it catches
missing SPA aliases, phantom client endpoints, stale schema reads, and pages
that render while their initial data requests fail.

### Booking honesty ledger

`booking-owner.spec.ts`, `booking-public.spec.ts`, and
`booking-confirm.spec.ts` use the disposable stack, real owner/public API
responses, reducer-backed DB arrange/assert, and product API teardown. The
browser evidence is intentionally separated from lower-layer coverage:

- Missing required answers are browser-tested through native form validation;
  the same semantic BZ135/HTTP 400 path is asserted through the real public API
  because the current form cannot submit an invalid required control. The
  reducer contract remains covered by `sql/tests/booking_pages.pg`.
- The owner route has no 403 contract. Unauthenticated access is HTTP 401 and
  a cross-owner ID is BZ134/HTTP 404 (enumeration-safe); the owner spec asserts
  those actual boundaries rather than inventing a 403.
- Public slot transport failure is fault-injected at the browser boundary. The
  page renders a localized alert with a Retry action, emits no slot controls
  while failed, and recovers through the real public metadata/slot endpoints
  without a full-page reload.
- Verification-email delivery and invite egress are lower-layer/sidecar
  concerns. Confirmation browser coverage arranges a pending request through
  `booking_create`, then exercises the real confirm/cancel HTTP and persisted
  state without reading retained email artifacts.

## Honest non-browser gate

`offline-mail.spec.ts` runs browser-negative checks for absence of native controls.
Its active sync/draft/drain/relock/conflict journey requires
`SETJOIN_NATIVE_E2E` and a real native bridge. The aggregate verifier permits
only that file as an unresolved browser skip; client/mobile release evidence
must close it.
