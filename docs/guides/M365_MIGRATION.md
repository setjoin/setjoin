# Migration Guide: M365, On-Prem Exchange (EWS), IMAP, Zimbra

setjoin ships three self-service/admin migration connectors — generic IMAP, on-prem
Exchange (EWS), and Microsoft 365/Graph — plus `.ics`/`.vcf` file upload for
calendar/contacts. All three connector types are reachable from both the admin
console (`Admin > Migration`, bulk/org-wide jobs) and the per-user self-service
page (`Settings > Migration`). Source: `mailserver/internal/migration/`
(`imap_client.go`, `ews_client.go`, `m365_client.go`, `ics_import.go`,
`vcf_import.go`), wired through `orchestrator.go` and exposed via
`admin_api.go` (admin) and `internal/user/migration.go` (self-service).

## Coverage matrix

Every cell below cites either a passing test (`file:TestName`) or an explicit
lossy/non-goal note. "Wired" means the admin UI source-type union AND
`orchestrator.go`'s dispatch both carry the source; "e2e" tests require a real
server and are build-tag-gated (`-tags e2e`) — they compile and skip-guard
clean in this repo but have not been run against a live box in this pass (see
"Live-run status" below each connector's section).

| Source | Mail | Calendar | Contacts | Delta/incremental | Rules |
|---|---|---|---|---|---|
| **On-prem Exchange (EWS)** — Exchange 2013/2016/2019, `ews_client.go` | have — stable `ItemId` identity and MIME fetch | have — native EWS calendar folder | have — native EWS contacts folder | have — folder-scoped `SyncFolderItems` state is connected to the typed checkpoint rail; invalid state performs one bounded full-folder reset and never advances a partial checkpoint | non-goal — no mail-rules/filter migration for any connector (rules are not portable across mail systems; recreate manually post-migration) |
| **Microsoft 365 / Exchange Online (Graph)** — `m365_client.go` | have — one selected Graph user per target, immutable IDs, per-folder message delta and `$value` via `/users/{id}` | have — paginated full enumeration; calendar delta is not claimed because v1 only supports bounded calendar-view delta | have — per-contact-folder delta in global cloud; China cloud uses honest full enumeration because contact delta is unavailable there | have — every `nextLink` is exhausted before the final delta link is staged; 410 performs one bounded full baseline reset | non-goal (see above) |
| **Generic IMAP** — any IMAP-speaking source (Gmail, Zimbra, cPanel, etc.), `imap_client.go` | have — stable identity is source instance + folder + `UIDVALIDITY` + UID | **not native to IMAP** — lossy fallback: upload a `.ics` export as a separate step | **not native to IMAP** — lossy fallback: upload a `.vcf` export | have — resume cursors are bound to folder `UIDVALIDITY`; a namespace reset starts a new folder generation rather than suppressing new messages | non-goal (see above) |
| **Zimbra** — no native connector | lossy — via the generic IMAP connector (Zimbra ships a standard IMAP server); same test coverage as IMAP row above | lossy — export Zimbra calendar as `.ics`, upload via Settings > Migration; `ics_import_test.go:TestSplitAndParseICS` | lossy — export Zimbra address book as `.vcf`, upload via Settings > Migration; `vcf_import_test.go` | n/a — one-shot export/upload, no incremental resync | non-goal (see above) |

All three connector types are reachable from both the admin migration console
(`mailserver/webmail/src/routes/admin/(mail)/migration/+page.svelte:509-511`,
tabs `IMAP` / `Exchange EWS` / `Microsoft 365`) and the self-service page
(`mailserver/webmail/src/routes/settings/migration/+page.svelte:270-293`), and
each is dispatched by `orchestrator.go:275`
(`job.SourceType == "imap" || "ews" || "m365"`). Zimbra has no native
connector by design. Exactly-once source identity, source-object mapping,
checkpoint publication and bounded thread reconciliation are enabled only by
`feature.mail_migration_source_identity`, which remains OFF until its shadow
readiness gate passes.

## Correctness and reset contract

- One migration job binds one immutable source mailbox to one target mailbox.
  The encrypted selector is re-resolved before enumeration; drift fails before
  target mutation.
- A transport cursor is never object identity. Every upsert/delete must carry a
  non-empty connector-specific stable object ID and version.
- The source-object ledger and target mutation commit together. A page cursor,
  Graph delta link, EWS SyncState, or IMAP folder cursor is published only after
  every preceding object is committed or durably classified.
- Graph message delta is per mail folder. Contact delta is per contact folder.
  Microsoft Graph v1 does not provide an unbounded mailbox-calendar delta, so
  Setjoin performs paginated full calendar enumeration rather than claiming an
  unsafe incremental cursor.
- Graph 410 and invalid EWS SyncState reset only the affected bounded baseline.
  IMAP `UIDVALIDITY` change creates a new folder generation. None of these reset
  paths delete target mail merely to make counts match.
- Thread reconciliation runs after import and is resumable. A job cannot report
  terminal success while a reconciliation continuation remains.

## Prerequisites

- A Microsoft 365 tenant with Exchange Online
- An account with Global Administrator or Privileged Role Administrator rights
- PowerShell 7+ with the Exchange Online Management module installed:
  ```powershell
  Install-Module -Name ExchangeOnlineManagement -Scope CurrentUser
  ```

---

## 1. App Registration in Azure

Create a service principal that Prism uses for application-level (daemon) access to Exchange Online data.

1. Navigate to the Azure Portal: [https://portal.azure.com](https://portal.azure.com)
2. Go to **Microsoft Entra ID** > **App registrations** > **+ New registration**
3. Fill in the registration form:

   | Field | Value |
   |---|---|
   | Name | `Prism Migration` (or any name your organization prefers) |
   | Supported account types | Accounts in this organizational directory only (Single tenant) |
   | Redirect URI | Leave blank — not needed for client credential flow |

4. Click **Register**
5. After registration completes, note these two values from the Overview page:
   - **Application (client) ID** — identifies the app to Azure AD
   - **Directory (tenant) ID** — identifies your tenant

Save both values. You will enter them into the Prism admin UI later.

---

## 2. Required Application Permissions

Prism requires three Application (not Delegated) permissions. Application permissions grant the service principal access to all mailboxes in the tenant without a signed-in user.

1. In the app registration page, go to **API permissions** > **+ Add a permission**
2. Select **Microsoft Graph** > **Application permissions**
3. Add each of the following permissions:

| Permission | Purpose |
|---|---|
| `Mail.Read` | Read mail in all mailboxes |
| `Calendars.Read` | Read calendar events in all mailboxes |
| `Contacts.Read` | Read contacts in all mailboxes |

4. Verify each row shows **Type: Application** (not Delegated)
5. Click **Grant admin consent for &lt;tenant&gt;** and confirm

After consent, each permission row should show a green checkmark under **Status** and "Granted for &lt;tenant&gt;" in the details.

---

## 3. Client Secret Creation

The client secret is used in the OAuth2 client credentials grant (`grant_type=client_credentials`).

1. In the app registration page, go to **Certificates & secrets** > **Client secrets** > **+ New client secret**
2. Fill in:
   | Field | Value |
   |---|---|
   | Description | `Prism Migration Secret` (or any label) |
   | Expires | 24 months (recommended; rotate before expiry) |

3. Click **Add**
4. **Copy the secret value immediately.** It is shown only once — if you navigate away, you must create a new secret.
5. Store the value securely (password manager, secrets vault). You will enter it into the Prism admin UI.

---

## 4. RBAC for Applications Scoping

RBAC for Applications (also called Application Access Policy) lets you restrict which mailboxes the service principal can access, instead of granting blanket access to every mailbox in the tenant. Skip this section only if you intend to migrate every mailbox.

### 4.1 Connect to Exchange Online

```powershell
Connect-ExchangeOnline
```

### 4.2 Register the Service Principal

```powershell
$appId = "your-client-id"   # replace with the Application (client) ID from step 1
$sp = Get-MgServicePrincipal -Filter "appId eq '$appId'"
New-ServicePrincipal -AppId $appId -ObjectId $sp.Id
```

### 4.3 Create a Mail-Enabled Security Group

Create a mail-enabled security group in the Exchange admin center (Recipients > Groups > Mail-enabled security group) or via PowerShell:

```powershell
New-DistributionGroup -Name "Migration Users" `
  -Type Security `
  -Members @("user1@contoso.com", "user2@contoso.com")
```

Add the mailboxes you want to migrate as members of this group.

### 4.4 Create a Management Scope

```powershell
$group = Get-DistributionGroup "Migration Users"

New-ManagementScope -Name "MigrationMailboxes" `
  -RecipientRestrictionFilter "MemberOfGroup -eq '$($group.DistinguishedName)'"
```

### 4.5 Assign Roles with Custom Scope

```powershell
New-ManagementRoleAssignment -App $appId `
  -Role "Application Mail.Read" `
  -CustomResourceScope "MigrationMailboxes"

New-ManagementRoleAssignment -App $appId `
  -Role "Application Calendars.Read" `
  -CustomResourceScope "MigrationMailboxes"

New-ManagementRoleAssignment -App $appId `
  -Role "Application Contacts.Read" `
  -CustomResourceScope "MigrationMailboxes"
```

### 4.6 Verify Access

```powershell
Test-ServicePrincipalAuthorization -Identity "Prism Migration" `
  -Resource "user@domain.com" | Format-Table
```

Replace `user@domain.com` with an email address that should be in scope. A successful test shows `True` for each role. Run the same test with an address outside the scope to confirm it is denied.

---

## 5. 21Vianet (China) Differences

Organizations using Microsoft 365 operated by 21Vianet in China use separate endpoints and a separate Azure portal.

| Resource | Global / GCC | China (21Vianet) |
|---|---|---|
| Azure Portal | [https://portal.azure.com](https://portal.azure.com) | [https://portal.azure.cn](https://portal.azure.cn) |
| OAuth2 token endpoint | `https://login.microsoftonline.com` | `https://login.chinacloudapi.cn` |
| Microsoft Graph API | `https://graph.microsoft.com` | `https://microsoftgraph.chinacloudapi.cn` |

The app registration, permission consent, and client secret steps are identical. When configuring the Prism admin UI, select **China (21Vianet)** from the cloud dropdown so Prism uses the correct endpoints.

---

## 6. Troubleshooting

### "Need admin approval" during permission consent

You are signed in with an account that does not have permission to grant tenant-wide consent. Sign in with a Global Administrator or Privileged Role Administrator account, or ask your admin to run the consent step.

### "Insufficient privileges" when testing access

Verify each API permission row shows **Type: Application** (not Delegated). Delegated permissions require a signed-in user context; application permissions do not. Remove any Delegated version of the same permission and re-add as Application.

### "Tenant not found" in Prism

Verify the Directory (tenant) ID is correct. Ensure the cloud selector in the Prism admin UI matches your tenant's home cloud (Global or China/21Vianet).

### "Access denied to mailbox"

1. Confirm the mailbox is a member of the security group referenced in the management scope.
2. Confirm the management role assignments were created with the correct service principal (`-App $appId`).
3. Run `Test-ServicePrincipalAuthorization` again — scope changes can take up to 30 minutes to propagate.
4. Verify the client secret has not expired. In the Azure portal, go to the app registration > Certificates & secrets and check the expiration date. If expired, create a new secret and update Prism.

### Connection test fails in Prism

- Verify the client secret value was copied correctly (no extraneous whitespace).
- Check that the client secret has not expired.
- Ensure the tenant ID and client ID match the app registration.
- If using 21Vianet, confirm the cloud selector is set to China.
- Check that no Conditional Access policy blocks the service principal.

---

# On-Prem Exchange (EWS) Migration

Exchange Web Services (EWS) is the native protocol of on-premises Exchange
2013/2016/2019 (Exchange Online also speaks EWS, but Microsoft Graph is the
modern/recommended path for M365 — see above). setjoin's on-prem-Exchange
connector (`mailserver/internal/migration/ews_client.go`) speaks EWS directly:
no Graph, no cloud dependency, works fully air-gapped/on-prem.

## Prerequisites

- An on-prem Exchange 2013, 2016, or 2019 server with the EWS endpoint
  reachable from the setjoin server (default: `https://<exchange-host>/EWS/Exchange.asmx`).
- A service/admin account with **Application Impersonation** rights (RBAC role
  `ApplicationImpersonation`), so a single account can pull every target
  mailbox rather than needing each user's own credentials:

  ```powershell
  New-ManagementRoleAssignment -Name "Migration Impersonation" `
    -Role ApplicationImpersonation -User "svc-migration@corp.local"
  ```

- TLS reachability from the setjoin host to the Exchange CAS/EWS endpoint on
  port 443. Self-signed certs are supported (the connector's TLS client can be
  configured to skip verification for lab/test connections — do not do this in
  production without also pinning the cert).

## EWS endpoint and auth

Configured from **Admin > Migration > Exchange EWS** tab (or **Settings >
Migration** for a single self-service user):

| Field | Value |
|---|---|
| Server URL | `https://mail.corp.local/EWS/Exchange.asmx` |
| Domain\User | `CORP\svc-migration` (the impersonation service account) |
| Password | the service account's password |

`TestConnection` (the **Test Connection** button) issues a lightweight
`GetFolder` SOAP call before any job starts, so a bad URL/credential/impersonation
setup fails fast instead of mid-migration
(`mailserver/internal/migration/admin_api.go`'s `"ews"` case →
`validateEWSServerURL` + `EWSConnector.TestConnection`).

## What transfers

- **Mail** — every well-known folder (Inbox, Sent, Drafts, Deleted Items,
  Junk Email) via `FindItem` + `GetItem` MIME fetch, preserving the original
  RFC822 body and read/flagged state.
- **Calendar** — native EWS calendar folder, converted to the same internal
  event representation the M365 connector produces.
- **Contacts** — native EWS contacts folder.
- **Incremental awareness** — `SyncFolderItems` returns stable `ItemId` plus
  `ChangeKey`; the orchestrator stages the folder SyncState and publishes it
  only after the corresponding reducer applications commit. An invalid state
  triggers one bounded full-folder reset, with the reset outcome retained in
  migration evidence.

## Known-lossy items

- Mail filter/inbox rules do not transfer (no connector supports this — see
  the coverage matrix's "Rules" column). Users recreate rules manually.
- Public folders are not migrated (only the well-known personal mailbox
  folders listed above).
- Free/busy and delegate permissions are not migrated; recreate delegation in
  setjoin after cutover if needed.

## Launching from the admin UI

1. **Admin > Migration** — select the **Exchange EWS** tab, enter the server
   URL and impersonation credentials, click **Save EWS Config**, then **Test
   Connection**.
2. Add migration targets (source email → target setjoin mailbox), either one
   at a time or via CSV bulk upload.
3. Click **Start Migration** — one job is created per target
   (`POST /admin/migration/start`, `admin_api.go`), and job status/progress
   is visible in the jobs table on the same page (list, cancel, retry, pause,
   resume).

## Live-run status

`ews_client_e2e_test.go`'s `TestEWSRealServer` (build tag `e2e`) exercises the
full surface above — `TestConnection`, `DiscoverFolders`, `FetchAllMail`,
`CalendarItems`, `ContactItems`, `Impersonation`, `NTLMAuth`, and
`DeltaSyncInbox` — against a real Exchange server named via the
`TEST_EWS_CONFIG` environment variable. Confirmed this pass:

```
go test -tags e2e -run TestEWSRealServer ./mailserver/internal/migration/ -v
--- SKIP: TestEWSRealServer (0.00s)
    ews_client_e2e_test.go:37: TEST_EWS_CONFIG not set
```

The test compiles and skip-guards correctly with no credentials configured —
it has **not** been run against a live Exchange 2016/2019 box in this
environment (none is available here). Running it against a real box is
**operator-deferred to cutover**, the same way the client-unification
program's mobile e2e was deferred: point `TEST_EWS_CONFIG` at a real Exchange
server + service account before a live on-prem-Exchange customer migration and
capture the output as that customer's go-live evidence.

---

# Generic IMAP Migration

Any IMAP4-capable mail server (Gmail/Google Workspace, Zimbra, cPanel/Dovecot,
legacy on-prem mail, etc.) can be migrated via the generic IMAP connector
(`mailserver/internal/migration/imap_client.go`). This is the lossy fallback
for any source without a dedicated connector: **mail only** natively; calendar
and contacts travel via separate `.ics`/`.vcf` file upload
(`ics_import.go`/`vcf_import.go`), not automatically pulled.

- **Launching**: **Admin > Migration** or **Settings > Migration**, select the
  **IMAP** tab, enter host/port/SSL + credentials, **Test Connection**, then
  **Start Migration**.
- **Coverage**: folder discovery (respecting IMAP `\Sent`/`\Drafts`/`\Trash`/`\Junk`
  attributes and common non-English folder names —
  `imap_client_test.go:TestIMAPFolderTags_NonEnglish`), full-folder UID fetch
  with crash-resume (`imap_client_test.go:TestIMAPFetchItems`), verified
  end-to-end against a real Dovecot container
  (`imap_client_docker_test.go:TestIMAPDocker_FetchItems`, build tag `e2e`,
  `deploy/docker/test-imap/docker-compose.yml`).
- **Calendar/contacts**: not part of the IMAP protocol. From **Settings >
  Migration**, after the IMAP mail step, upload the source's calendar/contact
  export as `.ics`/`.vcf` files — these run through the same
  `ics_import.go`/`vcf_import.go` import path the M365/EWS connectors' native
  calendar/contact conversion also feeds, so the storage/dedup path is
  identical regardless of source.

---

# Zimbra Migration

**There is no native Zimbra connector, and none is planned for GA.** This is a
deliberate scope decision, not an oversight (tracked as an accepted risk —
see `docs/audit/2026-07-04-ga-gap-list.md` G0-007): Zimbra is architecturally
just an IMAP server with a standard `.ics`/`.vcf` export, both of which
setjoin already ingests. A bespoke Zimbra SOAP/admin-API connector would be a
real build for capability the generic IMAP connector already covers, lossily,
today. Build one only if a named customer's cutover proves IMAP + ICS/VCF
insufficient.

## Runbook: migrate a Zimbra mailbox with the generic IMAP connector

1. **Confirm IMAP is enabled** on the Zimbra server (Zimbra enables IMAP by
   default on port 993/TLS; verify with your Zimbra admin if unsure —
   `zmprov gcf zimbraImapCleartextLoginEnabled` / the COS IMAP feature flag).
2. **Migrate mail**: in setjoin, go to **Settings > Migration** (self-service,
   per user) or **Admin > Migration** (bulk, whole org), select the **IMAP**
   tab, and enter:
   - Host: the Zimbra IMAP hostname (e.g. `mail.company.com`)
   - Port: `993`, SSL: on (Zimbra's IMAP defaults)
   - Username/password: the Zimbra mailbox credentials (or an app-specific
     password if 2FA is enabled on the Zimbra account)
   Click **Test Connection**, then **Start Migration**.
3. **Export calendar**: in Zimbra webmail, open the Calendar app, use
   **Export** (the gear/settings menu) to download a `.ics` file for the
   calendar(s) to migrate.
4. **Export contacts**: in Zimbra webmail, open Contacts, use **Export** to
   download a `.vcf` (vCard) file of the address book.
5. **Upload calendar/contacts**: on setjoin's **Settings > Migration** page,
   after the IMAP step completes, upload the `.ics` file (calendar) and `.vcf`
   file (contacts) in the same migration flow — they run through
   `ics_import.go`/`vcf_import.go`, the same import path M365/EWS use
   internally.

## Known-lossy items

- No incremental/delta re-sync — this is a one-shot export+upload, re-run the
  whole export if more time passes before cutover.
- Zimbra-specific features (briefcase/files, tasks, shared folder ACLs, mail
  filters) do not transfer. Recreate filters manually; briefcase/tasks have no
  migration path today.
- A UI "Zimbra" preset (a labeled shortcut that pre-selects the IMAP tab and
  fills in Zimbra-typical defaults) was considered for this pass and deferred
  as a low-value nicety: Zimbra installs are self-hosted with no fixed
  hostname to prefill, so a preset would save at most the port/SSL toggle
  (which already default to Zimbra-compatible values: 993/SSL). The admin
  migration UI's IMAP setup guide now includes an explicit Zimbra callout
  pointing here instead
  (`mailserver/webmail/src/routes/admin/(mail)/migration/+page.svelte`).
