# #333 closing audit

#333 qualifies 13 F21 registrations plus F14 native Drive issuance. The
conflict-resolution merge includes #332's established sessions, refresh and
credential writes. The orchestrator assigned the 25 mailserver-only self-service
registrations below to **IDLOGIN4**; they no longer block #333's closing criterion.
Their inventory remains unchanged until that ticket proves their own recordings.
Other unfinished security/federation shapes retain the named owners below.

## Named prerequisite shapes

- Sessions/refresh/password operations: #332, included by the integration merge.
- Guest invitation completion: #406. Device checkin/policy: #405/#420 device
  proof and runtime enforcement. WebPush is native; native provider possession
  remains #334. Shared threat/GeoIP/password admission remains #420; CA/DPoP
  enforcement remains #405. Kerberos proof remains #339. PKCE is an OAuth
  authorization-code concern in #340, not these authenticated token primitives.
- Applicable local security cases are the recorded reset/refresh/wrong-type,
  expiry, credential-secret, CSRF, revocation, tier and ownership cases.
  Bootstrap's omitted revocation/DPoP checks and direct impersonation's domain
  omission are frozen-Go security bugs, preserved and separately reported.
- The process-local chain cache runs in both Go and Rust until Go deletion,
  per the user's worker override. It must never enter GO_WORKERS_OFF.

## Mailserver-only ownership gap

The inventory's prefix classifier puts the following **25** mailserver-local
self-service registrations in F21/token-issuance. They are not authserver aliases:
`mailserver/cmd/mailserverd/main.go::registerUserRoutes` registers actual handlers
from admin/migration/mailsecurity/user services. Sending them to Go auth currently
returns 404, a pre-existing Rust routing/census bug. No native implementation or
matching parity suite exists here. The identity DOX explicitly retains this
provenance for the closing audit. These business operations are assigned to
IDLOGIN4 by the orchestrator and require that port before
Go deletion (related domain work: migration #293/#431, S/MIME #328, DLP #325,
user profile #309, webhooks #457; those tickets' current inventory does not own
these registrations). Do not mark them ON based on another endpoint's recording.

| Method | Registration |
| --- | --- |
| GET | `/auth/me/app-passwords` |
| POST | `/auth/me/app-passwords` |
| DELETE | `/auth/me/app-passwords/{id}` |
| POST | `/auth/me/dlp-check` |
| GET | `/auth/me/mailtips` |
| DELETE | `/auth/me/migration` |
| GET | `/auth/me/migration` |
| POST | `/auth/me/migration` |
| POST | `/auth/me/migration/cancel` |
| POST | `/auth/me/migration/pause` |
| POST | `/auth/me/migration/resume` |
| POST | `/auth/me/migration/test-imap` |
| POST | `/auth/me/migration/upload` |
| GET | `/auth/me/org-chart` |
| POST | `/auth/me/read-receipt` |
| GET | `/auth/me/smime/certs` |
| POST | `/auth/me/smime/certs` |
| DELETE | `/auth/me/smime/certs/{id}` |
| POST | `/auth/me/smime/certs/{id}/default` |
| GET | `/auth/me/smime/recipient-certs` |
| POST | `/auth/me/smime/recipient-certs` |
| DELETE | `/auth/me/smime/recipient-certs/{id}` |
| GET | `/auth/me/webhooks` |
| POST | `/auth/me/webhooks` |
| DELETE | `/auth/me/webhooks/{id}` |

The remaining token-issuance OFF registrations are the gateway `/auth/admin/`
proxy subtree, guest GET/POST listener aliases, and device checkin/policy. Only
those unfinished shapes retain named-owner forwarding. Qualified handlers have
no completed-shape back-to-Go switches.
