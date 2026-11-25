# mailserver/internal — Go Gateway Packages (DOX child)

Owns stateless Go translators, not reducer authority. Claims supply identity; mailbox and user IDs are distinct. Preserve transaction-local scope, typed worker pools, direct LISTEN, fail-closed startup/reconnect and drain gates. Private registrars and exact proxy allowlists remain authoritative. Shared problem responses must not expose raw errors; use runtime configuration seams. Read the Package index then the affected capability. Query changes require docs/standards/DATABASE_SECURITY.md and SQL ownership; protocols require their references/RFCs. Children: chat/AGENTS.md and meet/AGENTS.md.

Frozen Go TLS worker recorders live in `tlsutil/*_oracle_test.go`; replay and
recording contracts are in [`server-rust/DOX.md`](../../server-rust/DOX.md#worker-oracle).

## DOX sections

- [Purpose](DOX.md#purpose)
- [Ownership](DOX.md#ownership)
- [Local Contracts](DOX.md#local-contracts)
  - [Architecture invariant](DOX.md#architecture-invariant)
  - [Credential-reset and push-revocation seams](DOX.md#credential-reset-and-push-revocation-seams)
  - [Key files](DOX.md#key-files)
  - [Startup order (mandatory, enforced in `main.go`)](DOX.md#startup-order-mandatory-enforced-in-maingo)
  - [DB connection model](DOX.md#db-connection-model)
  - [Package index](DOX.md#package-index)
  - [Drive node ACL and managed-cache revocation](DOX.md#drive-node-acl-and-managed-cache-revocation)
  - [Guest G4 Drive tier contract](DOX.md#guest-g4-drive-tier-contract)
  - [Drive canonical object lifecycle](DOX.md#drive-canonical-object-lifecycle)
- [Features / Capabilities](DOX.md#features--capabilities)
  - [SMTP — Inbound MTA (port 25) — `smtp/inbound.go`, `smtp/pipeline*.go`](DOX.md#smtp--inbound-mta-port-25--smtpinboundgo-smtppipelinego)
  - [SMTP — Submission MSA (port 587) — `smtp/submission.go`](DOX.md#smtp--submission-msa-port-587--smtpsubmissiongo)
  - [SMTP — Outbound Worker — `smtp/outbound.go`](DOX.md#smtp--outbound-worker--smtpoutboundgo)
  - [SMTP — Journaling — `smtp/journal.go`](DOX.md#smtp--journaling--smtpjournalgo)
  - [IMAP4rev2 Bridge — `imap/imap.go`, `imap/imap_limits.go`](DOX.md#imap4rev2-bridge--imapimapgo-imapimap_limitsgo)
  - [JMAP Core + Mail — `jmap/handler.go`, `jmap/blob.go`](DOX.md#jmap-core--mail--jmaphandlergo-jmapblobgo)
  - [JMAP Calendar — `jmap/handler.go`](DOX.md#jmap-calendar--jmaphandlergo)
  - [JMAP Contacts — `jmap/handler.go`](DOX.md#jmap-contacts--jmaphandlergo)
  - [JMAP Tasks — `jmap/handler.go`](DOX.md#jmap-tasks--jmaphandlergo)
  - [CalDAV Bridge — `caldav/caldav.go`, `caldav/ical.go`, `caldav/freebusy_batch.go`](DOX.md#caldav-bridge--caldavcaldavgo-caldavicalgo-caldavfreebusy_batchgo)
  - [CardDAV Bridge — `carddav/carddav.go`, `carddav/vcard.go`](DOX.md#carddav-bridge--carddavcarddavgo-carddavvcardgo)
  - [LDAP GAL Server — `ldap/server.go`, `ldap/dn.go`](DOX.md#ldap-gal-server--ldapservergo-ldapdngo)
  - [Admin REST API — `admin/`](DOX.md#admin-rest-api--admin)
  - [AI Assist — `assist/` (B4.3)](DOX.md#ai-assist--assist-b43)
  - [User-Facing REST API — `user/`](DOX.md#user-facing-rest-api--user)
  - [Migration Connectors — `migration/`](DOX.md#migration-connectors--migration)
  - [Link Protection — `linkprotect/`](DOX.md#link-protection--linkprotect)
  - [S/MIME — `smime/smime.go`](DOX.md#smime--smimesmimego)
  - [MDM & MAM — `mdm/`](DOX.md#mdm--mam--mdm)
  - [SCIM 2.0 — `scim/`](DOX.md#scim-20--scim)
  - [Webhooks — `webhook/`](DOX.md#webhooks--webhook)
  - [Telemetry — `telemetry/`](DOX.md#telemetry--telemetry)
  - [ACME Certificate Automation — `acme/`](DOX.md#acme-certificate-automation--acme)
  - [Geo/Network — `geoip/`, `network/`](DOX.md#geonetwork--geoip-network)
  - [Cron / Scheduled Tasks and per-task transfer gates — `cron/`](DOX.md#cron--scheduled-tasks--cron)
  - [Backup & Restore — `backup/`, `restore/`, `storage/`](DOX.md#backup--restore--backup-restore-storage)
  - [Deploy & HA — `deploy/`](DOX.md#deploy--ha--deploy)
  - [Notification / WebSocket — `notify/`, `ws/`](DOX.md#notification--websocket--notify-ws)
  - [Well-Known & Discovery — `wellknown/`, `discovery/`](DOX.md#well-known--discovery--wellknown-discovery)
  - [Air-Gap Updates — `updates/`](DOX.md#air-gap-updates--updates)
  - [Transactional updater — `updater/`, `cmd/setjoin-updater`](DOX.md#transactional-updater--updater-cmdsetjoin-updater)
  - [Connectivity-aware sync E1 gateway seams](DOX.md#connectivity-aware-sync-e1-gateway-seams)
  - [Xinchuang (国产) DB Adapter — `xinchuang/db/`](DOX.md#xinchuang-国产-db-adapter--xinchuangdb)
  - [Supporting Infrastructure](DOX.md#supporting-infrastructure)
- [Work Guidance](DOX.md#work-guidance)
- [Verification](DOX.md#verification)
- [Child DOX Index](DOX.md#child-dox-index)

The frozen backup worker recording adapter is `backup/backup_oracle_record_test.go`
(build tag `gofree_record`); replay and publication contracts live in
[`server-rust/crates/backup/DOX.md`](../../server-rust/crates/backup/DOX.md).

Recovery cleanup oracle recording and Rust replay: [Blobs DOX](../../server-rust/crates/domains/blobs/DOX.md#recovery-cleanup-worker).

LDAP listener oracle: [Rust LDAP contract](../../server-rust/crates/protocols/ldap/DOX.md) (#342).
Federation peer oracle: [Rust protocol contract](../../server-rust/crates/protocols/federation/DOX.md) (#346).
SMTP listener oracle: [Rust protocol contract](../../server-rust/crates/protocols/smtp/DOX.md) (#348).

SMTP mail-auth recording fixtures (`gofree_record`, #349): [protocol contract](../../server-rust/crates/protocols/smtp/DOX.md#mail-authentication-349).

SMTP outbound worker recording (`gofree_record`, #350): [outbound contract](../../server-rust/crates/protocols/smtp/src/outbound/DOX.md).

Auth runtime IMAP policy recording (#202): [threat corpus](../../server-rust/crates/threat/DOX.md).

Toggle-ON SMTP security recording (#526): [inbound oracle contract](../../server-rust/crates/protocols/smtp/src/inbound/DOX.md).
