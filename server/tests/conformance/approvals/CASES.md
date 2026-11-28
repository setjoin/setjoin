# F10 approval oracle (#269)

The seam is the real HTTP front door, with committed rows, audit and NOTIFY
observed for writes. Frozen Go is recorded with coverage; replay has no Go
upstream. `approvals` is the gateway integration target. All twelve bundled registrations are qualified ON; route-catalog.json binds
exact replay selectors, row-effect files and planted adapter/reducer faults.

| Inventory registration | External path | Go contract |
| --- | --- | --- |
| GET /me/approvals | /api/me/approvals | Own submissions and active assigned approvals; safe payload allowlist. Unknown query parameters are ignored. |
| POST /me/approvals/hr | /api/me/approvals/hr | Kind toggle, form reducer, token-owned requester. |
| POST /me/approvals/{id}/decide | /api/me/approvals/{id}/decide | Strict JSON, scoped visibility, consumer reducer, worker credential for mail replay. |
| POST /me/approvals/{id}/cancel | /api/me/approvals/{id}/cancel | Requester-owned pending guard, audit and approval_decided. |
| GET /admin/approval-policies | /api/admin/approval-policies | Live approvals.view/manage; global policy collection. |
| POST /admin/approval-policies | /api/admin/approval-policies | Live approvals.manage; consumer/name/object validation, max priority + insert. |
| PUT /admin/approval-policies/{id} | /api/admin/approval-policies/{id} | Live approvals.manage; nullable patch, missing-row 404. |
| DELETE /admin/approval-policies/{id} | /api/admin/approval-policies/{id} | Live approvals.manage; referenced policy conflict. |
| POST /admin/approval-policies/reorder | /api/admin/approval-policies/reorder | Live approvals.manage; negative then positive renumbering. |
| GET /admin/approval-requests/audit | /api/admin/approval-requests/audit | Live approvals.view/manage; narrowest current domain scope, pagination. |
| GET /approvals/email/{token} | unchanged | HMAC capability, prefetch-safe confirmation; no session. |
| POST /approvals/email/{token} | unchanged | HMAC actor; narrower consumer switch than authenticated decide. |

Policy data is global: the denial seam is a caller without the required live
governed permission, including a signed admin with expired/revoked assignments.
A domain-scoped policy manager can still manage global policies in frozen Go.
Approvals do not have a JMAP approval state counter; engine decisions publish
approval_decided, while mail replay/delivery can bump mailbox state.

`guest.invite` decision preparation/delivery uses the Guests helper (#272).
The `guests` integration target records apply, deny, delivery failure and
metadata rollback through this authenticated F10 seam.

The floor retains Go's actual outcomes: the list ignores malformed query fields,
audit pagination defaults malformed values, and HR ignores forged requester IDs
while creating a token-owned request (201). Admin policies are global resources;
the negative case is missing live governed authority, not a domain fence absent
from Go. A valid foreign email capability yields GET 400 / POST inactive 200.
These are parity cases, not accepted divergences.

Repeats preserve Go: policy/HR creation creates another row, update/reorder runs
again, delete/cancel returns opaque 404, authenticated redecision returns 409,
and an email redecision renders inactive 200. HR/guest/Drive-access email POSTs
retain Go's narrower consumer dispatch. Notification recordings cover one real
LISTEN event, active role-member fan-out, RBAC/malformed skips and Go's named
GO_WORKERS_OFF=approval-notify suppression. The executable suite checks every
registration with bundled ON and both rollback switches, including F10 counters.

Edge cases include create-priority collision, equivalent Go base64 signatures,
fractional token expiry, case-folded worker keys and typed mail/Drive errors.
Real DB error injections are conditional on exact owned fixture IDs/names, and
are removed before cleanup. Error recordings assert rollback and opaque detail.
