# SetJoin Hardening / Rename / Restructure — Audit Report

> Generated 2026-06-11 by a multi-agent audit workflow (141 agents): 7 change-set reviewers + 9 security/structure finder lenses, every finding adversarially verified by 1–2 independent skeptic agents. Only findings where **all** verifiers agreed `isReal` are listed. Severities are post-verification (verifiers could downgrade).

**Confirmed: 87** — critical 1, high 6, medium 31, low 49. Refuted/dropped by verifiers: 6.

## Verdicts per change set

| Change set | Verdict | Confirmed | Refuted |
|---|---|---|---|
| rename-binaries | sound-with-issues | 7 | 0 |
| admin-routes | sound-with-issues | 3 | 0 |
| authenticator-iface | sound-with-issues | 6 | 0 |
| ci-hardening | problematic | 8 | 0 |
| observability | sound-with-issues | 8 | 0 |
| lifecycle-protocol | problematic | 7 | 1 |
| policy-consolidation | problematic | 5 | 2 |

## CRITICAL (1)

### C1. Authenticated SSRF: any user can register a webhook to an arbitrary internal URL and the server POSTs to it
- **Lens/source:** security/structure hunt → `ssrf-outbound`
- **Location:** `mailserver/internal/webhook/dispatcher.go:77-100`
- **Issue:** Dispatcher.deliverOne dials a URL read verbatim from webhook_subscriptions using a plain http.Client{Timeout:30s} with no validation of scheme or destination IP. The URL is fully attacker-controlled: POST /auth/me/webhooks is gated by requireAuth only (cmd/mailserverd/main.go:989), so any authenticated mailbox user can create a subscription whose url is http://127.0.0.1:<port>/..., http://169.254.169.254/latest/meta-data/ (cloud metadata), or any RFC1918 host. There is NO allowlist/denylist for private/loopback/link-local ranges, no resolve-then-pin against DNS rebinding, no CheckRedirect override (Go's default follows up to 10 redirects, so a public 302 -> http://169.254.169.254 also works), and no scheme restriction (cleartext http allowed). Each event fires d.deliverOne in a goroutine (line 73) on internal mail events the user can trigger (e.g. new mail), giving a reliable outbound request primitive. The request is signed with X-Webhook-Signature using the per-subscription secret returned to the attacker in the Create response (user_webhooks.go:83), so requests to internal services that validate that HMAC can be forged. A grep across mailserver/ and shared/ for any private-IP/loopback guard (IsPrivate, IsLoopback, 169.254, ssrf, etc.) returns zero hits — no protection exists anywhere.
- **Evidence:** `req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
...
resp, err := d.httpClient.Do(req)   // url straight from webhook_subscriptions, no IP/scheme/redirect guard`
- **Fix:** Add a shared SSRF guard used by deliverOne: (1) require https scheme (or an explicit admin allowlist), (2) resolve the host, reject if any resolved IP is loopback/private/link-local/ULA/unspecified (net.IP.IsLoopback/IsPrivate/IsLinkLocalUnicast/IsLinkLocalMulticast plus 169.254/16, 100.64/10, ::1, fc00::/7), (3) use a custom http.Transport with a DialContext/Control that re-checks the actual connected IP (resolve-then-pin) to defeat DNS rebinding, and (4) set CheckRedirect to re-run the same validation on every hop (or disallow redirects). Validate at Create time too, but the dial-time check is the authoritative one.
- **Verifier note:** Verified end to end. dispatcher.go:29 uses a bare http.Client{Timeout:30s} (no Transport/DialContext/Control, no CheckRedirect so Go follows up to 10 redirects); dispatcher.go:50,92,100 read `url` verbatim from webhook_subscriptions and POST to it with zero scheme/IP/host validation. POST /auth/me/webhooks is gated only by requireAuth (cmd/mailserverd/main.go:989), and user_webhooks.go:60-77 inser

## HIGH (6)

### H1. V008 migration targets a non-existent `devices` table and drops push_devices that live code still uses
- **Lens/source:** change-set review → `policy-consolidation`
- **Location:** `authserver/sql/migrations/V008__unified_devices.sql:6-23`
- **Issue:** V008 runs `ALTER TABLE devices ADD COLUMN ...` and `INSERT INTO devices (...)`, but no `CREATE TABLE devices` exists anywhere in authserver or mailserver SQL (grep for `CREATE TABLE (IF NOT EXISTS )?devices[ (]` returns nothing; only push_devices, device_registry, managed_devices exist). The migration therefore fails on apply (relation "devices" does not exist) and the whole pass is un-deployable. Compounding this, V008 line 23 `DROP TABLE IF EXISTS push_devices`, yet authserver/internal/handlers/device.go:54 and authserver/internal/authn/push.go:195,220,298,351 still INSERT/SELECT from push_devices for native push-MFA registration and delivery — if the drop ever succeeded it would break push MFA at runtime. The new RegisterDevice insert also relies on `ON CONFLICT (user_id, fingerprint)`, a unique constraint that is never created.
- **Evidence:** `ALTER TABLE devices ADD COLUMN IF NOT EXISTS push_token_enc BYTEA;
...
INSERT INTO devices (user_id, device_name, push_token_enc, ...)
...
DROP TABLE IF EXISTS push_devices;`
- **Fix:** Add a CREATE TABLE devices (with user_id, fingerprint, hmac_secret, compliance_status, wipe_requested, trust_tier, UNIQUE(user_id,fingerprint), RLS) before the ALTERs, and do not drop push_devices until handlers/device.go and authn/push.go are migrated off it. Add a pgTAP test that applies V008 against a fresh DB.
- **Verifier note:** Verified no `devices` table is created anywhere: a strict repo-wide search for `CREATE TABLE/VIEW ... devices` (excluding managed_devices, push_devices, device_registry, device_policy, device_events) returns nothing, and the authserver migration chain V001-V007 \i-includes schema files 001-019 which create push_devices/device_registry/managed_devices but never `devices`. V008 (authserver/sql/migra

### H2. H8 domain-scope query references a non-existent column and fails open
- **Lens/source:** change-set review → `policy-consolidation`
- **Location:** `authserver/internal/handlers/auth.go:1000-1009`
- **Issue:** issueTokens joins `admin_role_assignments ra JOIN admin_role_groups rg ON rg.name = ra.role_group`, but admin_role_assignments has no `role_group` text column — it has `role_group_id BIGINT` referencing admin_role_groups(id) (mailserver/sql/migrations/V057__rbac_permissions.sql:25-36). At runtime PostgreSQL errors with 'column ra.role_group does not exist', so `err != nil`, the `if err == nil && ...` guard is skipped, and domainScope stays nil — i.e. every scoped user_admin is issued an UNRESTRICTED (all-domains) token. The logic is also wrong even if the column existed: `MIN()` collapses multiple role scopes to the smallest domain id, and `WHERE rg.domain_scope IS NOT NULL` drops assignments that have a domain_override but a global role group.
- **Evidence:** ``SELECT COALESCE(MIN(COALESCE(ra.domain_override, rg.domain_scope)), 0)
 FROM admin_role_assignments ra
 JOIN admin_role_groups rg ON rg.name = ra.role_group
 WHERE ra.user_id = $1 AND rg.domain_scope IS NOT NULL``
- **Fix:** Join on `rg.id = ra.role_group_id`, drop the MIN/IS NOT NULL collapse (a user with multiple scoped roles needs all scopes, not the min), and fail CLOSED — on query error deny rather than issue an unrestricted token. Add a test that a scoped user_admin gets a non-nil domain claim.
- **Verifier note:** Confirmed against code. auth.go:1003 joins `JOIN admin_role_groups rg ON rg.name = ra.role_group`, but admin_role_assignments has no `role_group` column — only `role_group_id BIGINT` (V057__rbac_permissions.sql:28); grep found no migration adding a `role_group` text column. Postgres errors at plan time ("column ra.role_group does not exist") so err != nil, the `if err == nil && ...` guard (auth.go

### H3. Resolved domain scope is never enforced by any admin endpoint
- **Lens/source:** change-set review → `policy-consolidation`
- **Location:** `mailserver/internal/middleware/auth.go:102-121`
- **Issue:** Even setting aside the broken query, the H8 'authorization' authorizes nothing. The middleware stuffs claims.DomainScope into context, and DomainScopeFromContext exists to read it, but a whole-repo grep shows it has zero non-test callers. The admin domain handlers ignore it entirely — DomainsHandler.List runs `SELECT ... FROM domains ORDER BY ...` with no scope predicate, and Get/Create are likewise unscoped — so a user_admin scoped to one domain can enumerate and mutate every domain. H8 ships the plumbing but none of the actual access-control checks.
- **Evidence:** `func DomainScopeFromContext(ctx context.Context) int64 { v, ok := ctx.Value(ctxKeyDomainScope).(int64) ... }  // callers: only perm_test.go
// admin_domains.go List: `FROM domains ORDER BY is_primary DESC, name ASC` (no WHERE)`
- **Fix:** Apply DomainScopeFromContext in every admin handler that reads/writes domain-scoped data (domains, mailboxes, rules, DNS, DMARC...) — filter SELECTs and reject cross-domain mutations with 403. Add tests proving a scoped admin cannot see/modify another domain.
- **Verifier note:** Verified all three load-bearing claims. (1) DomainScopeFromContext (mailserver/internal/middleware/auth.go:115-121) has zero non-test callers: a whole-repo grep returns only perm_test.go. (2) admin_domains.go ignores scope entirely: List runs `FROM domains ORDER BY is_primary DESC, name ASC` with no predicate (line 54); Get/Update/Delete filter only by `id`; Create inserts unconditionally — none r

### H4. JMAP authorization conflates user_id with mailbox_id — reducers trust an unverified account id with no DB backstop
- **Lens/source:** security/structure hunt → `authz-tenancy`
- **Location:** `mailserver/internal/jmap/handler.go:260-274, 772-774`
- **Issue:** Every JMAP Email/Mailbox/Thread method authorizes via parseAccountID, which only checks that the client-supplied accountId equals the authenticated user's numeric user id, then passes that value to the reducers as p_account_id. The reducers (jmap_email_get/query/set, jmap_calendar_*, jmap_contact_*) interpret p_account_id as a MAILBOX id and filter solely on it (`FROM mailboxes WHERE id = p_account_id`, `WHERE m.mailbox_id = p_account_id`) — they never verify mailboxes.user_id matches the caller. So the entire authorization model rests on the unstated invariant users.id == primary mailbox.id. That invariant is NOT enforced: users.id (003_users.sql:4) and mailboxes.id (004_mailboxes.sql:3) are independent BIGSERIAL sequences, and user-less mailboxes (shared/resource mailboxes, plus SCIM group mailboxes inserted with no user_id in scim_upsert_group.sql:51) advance the mailboxes sequence independently. Once the two id spaces diverge, a JMAP request with accountId == user.UserID is accepted by parseAccountID and routed by the reducer to `mailboxes WHERE id = user.UserID` — a mailbox the schema does not associate with the caller (another tenant's mailbox or a shared mailbox), granting full read/write/delete. There is no database backstop: grep over sql/ shows ZERO `ROW LEVEL SECURITY`/`CREATE POLICY` and no per-user GUC is ever set, and the reducers are SECURITY INVOKER running as the shared gateway role. The codebase even contradicts itself: GetAccountID (handler.go:637) and Session (handler.go:472) emit the REAL primary mailbox id as accountId, which parseAccountID would then reject whenever it differs from user.UserID.
- **Evidence:** `func parseAccountID(reqAccountID string, userID int64) (int64, json.RawMessage) {
	...
	if accountID != userID {
		errJSON, _ := json.Marshal(Error{Type: "accountNotFound", Description: "accountId does not match authenticated user"})
		return 0, errJSON
	}
	return accountID, nil
}
// emailGet: accountID, errResp := parseAccountID(req.AccountID, user.UserID) ... `SELECT jmap_email_get($1, $2, $3)`, accountID, ids, req.Properties
// jmap_email.sql: SELECT jmap_email_state INTO v_state FROM mailboxes WHERE id = p_account_id; ... WHERE m.mailbox_id = p_account_id`
- **Fix:** Stop treating the user id as a mailbox id. Resolve the caller's authorized mailbox id server-side (as GetAccountID already does) and pass THAT to reducers, or change reducers to take the authenticated user id and join mailboxes on user_id (`WHERE mb.user_id = p_user_id AND mb.id = p_mailbox_id`). Have parseAccountID validate the requested accountId against the set of mailboxes the user actually owns/is delegated, not against user.UserID. Add RLS (ENABLE + FORCE) with per-user policies on mailboxes/messages and set a per-request app.user_id GUC as the R4 defense-in-depth backstop.
- **Verifier note:** Verified the full chain. parseAccountID (handler.go:270) rejects unless reqAccountID == user.UserID, and user.UserID is users.id (pwhash.go:74 `SELECT u.id ... FROM users u`; jwt.go:57). All Email handlers pass that value to reducers as p_account_id (handler.go:773-774, 808-809, 1138). The email reducer treats p_account_id strictly as a mailbox id with NO user_id ownership join: jmap_email.sql:17 

### H5. IMAP command reader uses unbounded ReadString with no read deadline — memory-exhaustion / slowloris DoS
- **Lens/source:** security/structure hunt → `protocol-parsing`
- **Location:** `mailserver/internal/imap/imap.go:123, 143, 1641, 1569`
- **Issue:** The IMAP connection uses a plain *bufio.Reader (line 123: `reader: bufio.NewReader(conn)`), and the main command loop reads each line with `c.reader.ReadString('\n')` (line 143). bufio.ReadString accumulates into an unbounded internal buffer until it sees '\n'. A client that opens a connection and streams bytes without ever sending a newline forces the buffer to grow without limit -> heap exhaustion. There is NO per-line size cap anywhere, and grep for SetReadDeadline/SetDeadline/LimitReader/MaxBytes in imap.go returns zero results — unlike the SMTP server which sets `conn.SetReadDeadline(...)` per command (inbound.go:283). The same unbounded ReadString is used in the IDLE loop (line 1641) and the post-literal trailing-CRLF read (line 1569: `c.reader.ReadString('\n')`), so even a client that never authenticates can pin a goroutine and grow memory indefinitely. The APPEND literal path IS bounded (size > 50_000_000 rejected at line 1550), but the line reader that precedes/surrounds it is not.
- **Evidence:** `reader: bufio.NewReader(conn),
...
line, err := c.reader.ReadString('\n')
if err != nil {
	return
}`
- **Fix:** Wrap the connection in an io.LimitReader or use bufio.Reader.ReadSlice with an explicit max-line cap (RFC 9051 has no command-line limit, but 8 KiB for non-literal lines is standard), returning `BAD line too long` on overflow. Set conn.SetReadDeadline before every read (matching the SMTP 5-minute idle pattern) so an idle/slow client is disconnected instead of holding a goroutine and buffer forever.
- **Verifier note:** Verified in mailserver/internal/imap/imap.go: the connection uses a plain `bufio.NewReader(conn)` (line 123) and the pre-auth command loop reads with `c.reader.ReadString('\n')` (line 143), with identical unbounded reads in AUTH (1398), the post-literal trailing CRLF (1569), and the IDLE loop (1641). A grep across internal/imap/ returns zero `Deadline`/`SetReadDeadline`/`LimitRe

### H6. Webhook Create handlers persist an unvalidated destination URL (no scheme/host check)
- **Lens/source:** security/structure hunt → `ssrf-outbound`
- **Location:** `mailserver/internal/user/user_webhooks.go:60-84`
- **Issue:** UserWebhooksHandler.Create accepts req.URL and inserts it into webhook_subscriptions with no validation beyond non-empty. There is no url.Parse, no scheme allowlist (http/https), no rejection of internal hosts or non-http schemes. The same pattern exists in admin_webhooks.go:61-84 (admin path is requireSuperAdmin, so lower exposure, but it persists the same unvalidated value). This is the entry point that feeds the SSRF sink in dispatcher.go; even with a dial-time guard, storing arbitrary strings (e.g. file://, gopher://-style values, or hosts that later resolve internally) is unsafe and should be rejected at write time with a clear error.
- **Evidence:** `if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.URL == "" || len(req.EventTypes) == 0 {
    httputil.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "url and eventTypes required"})
    return
}
...
`INSERT INTO webhook_subscriptions (user_id, url, secret, event_types) VALUES ($1, $2, $3, $4) RETURNING id`,
user.UserID, req.URL, secret, string(typesJSON)`
- **Fix:** Parse req.URL, require scheme in {https} (or https+http only on an explicit admin opt-in), require a non-empty host, and run the same private/loopback/link-local IP rejection used at dial time before INSERT. Return a 400 with a non-technical message on failure.
- **Verifier note:** Confirmed end to end. In user_webhooks.go:66-77 req.URL is validated only for non-empty (`req.URL == ""`) then inserted via INSERT INTO webhook_subscriptions; grep found zero url.Parse/scheme/loopback/IsPrivate checks across shared/webhook/, internal/webhook/, and the handler. The route POST /auth/me/webhooks (main.go:989) is gated only by requireAuth, so any authenticated non-admin user can store

## MEDIUM (31)

### M1. build.sh, dev.sh, cross-build.sh still build authserver from deleted ./cmd/authserver
- **Lens/source:** change-set review → `rename-binaries`
- **Location:** `scripts/build.sh (also scripts/dev.sh:8, scripts/cross-build.sh:34):5`
- **Issue:** Commit 98a3d1c renamed authserver/cmd/authserver -> cmd/authserverd and updated the gateway build line in each script, but left the authserver build line in the same files untouched. Verified: `go build ./cmd/authserver` fails with "stat authserver/cmd/authserver: directory not found". With `set -euo pipefail` from scripts/_base.sh, `bash scripts/build.sh`, `bash scripts/dev.sh` (full local stack), and `bash scripts/cross-build.sh` (Xinchuang builds) all abort at the authserver step. CI passed only because xinchuang-ci.yml builds inline and was separately fixed in ccf6735.
- **Evidence:** `build.sh:5 `cd "$ROOT/authserver" && go build -o authserver ./cmd/authserver`; dev.sh:8 `(cd "$ROOT/authserver" && go build -o authserver ./cmd/authserver)`; cross-build.sh:34 `-o "$OUTDIR/authserver" ./cmd/authserver``
- **Fix:** Change all three to `./cmd/authserverd` (and decide on the output name, see binary-name issue). Add a CI job or pre-commit check that actually executes scripts/build.sh so script rot is caught.
- **Verifier note:** Verified directly. The directory `authserver/cmd/authserver` does not exist; `git show --stat 98a3d1c` shows it was renamed to `authserver/cmd/authserverd`. All three scripts still reference the deleted path: build.sh:5 `cd "$ROOT/authserver" && go build -o authserver ./cmd/authserver`, dev.sh:8 `(cd "$ROOT/authserver" && go build -o authserver ./cmd/authserver)`, cross-build.sh:34 `-o "$OUTDIR/au

### M2. build.sh and cross-build.sh cd into nonexistent mailserver/gateway directory (edited but not fixed by the rename commit)
- **Lens/source:** change-set review → `rename-binaries`
- **Location:** `scripts/build.sh (also scripts/cross-build.sh:37):8`
- **Issue:** The Go module lives at mailserver/ (mailserver/go.mod, cmd under mailserver/cmd/), but these scripts cd into $ROOT/mailserver/gateway — a path that today is a stale 215MB compiled binary file, not a directory. Verified: `cd mailserver/gateway` -> "not a directory". Commit 98a3d1c modified these exact lines (changing only `./cmd/gateway` to `./cmd/mailserverd`) and kept the dead cd, so the gateway half of build.sh/cross-build.sh is just as broken as the authserver half.
- **Evidence:** `build.sh:8 `cd "$ROOT/mailserver/gateway" && go build -o gateway ./cmd/mailserverd`; cross-build.sh:37 `cd "$ROOT/mailserver/gateway"``
- **Fix:** Use `cd "$ROOT/mailserver"` (as dev.sh already does) in build.sh and cross-build.sh.
- **Verifier note:** Confirmed with code and filesystem. build.sh:8 `cd "$ROOT/mailserver/gateway" && go build -o gateway ./cmd/mailserverd` and cross-build.sh:37 `cd "$ROOT/mailserver/gateway"` both cd into a path that is a 215MB Mach-O binary, not a directory (`file mailserver/gateway` → "Mach-O 64-bit executable"; `cd` → "not a directory", exit 1). The module lives at mailserver/ (go.mod present) and the command is

### M3. lint.sh, test.sh (govulncheck), and e2e.sh (via deploy/test.sh) also reference the dead mailserver/gateway path
- **Lens/source:** change-set review → `rename-binaries`
- **Location:** `scripts/lint.sh (also scripts/test.sh:27, mailserver/deploy/test.sh:51):8`
- **Issue:** Plan Task 1 Step 3 explicitly scoped 'Update build scripts — scripts/build.sh, scripts/dev.sh, scripts/test.sh' but test.sh and lint.sh were not touched at all. lint.sh:8 and test.sh:27 cd into the nonexistent mailserver/gateway, so `bash scripts/lint.sh` fails outright and `bash scripts/test.sh` dies at the govulncheck section when govulncheck is installed. scripts/e2e.sh:5 delegates to mailserver/deploy/test.sh, whose line 51 `cd "$PROJECT_DIR/gateway"` fails the same way, breaking the entire documented Go E2E suite (`bash scripts/e2e.sh imap|smtp|ldap`).
- **Evidence:** `lint.sh:8 `cd "$ROOT/mailserver/gateway" && golangci-lint run ./...`; test.sh:27 `(cd "$ROOT/mailserver/gateway" && govulncheck ./...)`; deploy/test.sh:51 `cd "$PROJECT_DIR/gateway"``
- **Fix:** Replace all `mailserver/gateway` cds with `mailserver` (and `$PROJECT_DIR` in deploy/test.sh). Also fix scripts/gen-confusables.go comments referencing mailserver/gateway/internal/smtp/.
- **Verifier note:** Verified the premise: `mailserver/gateway` is not a directory but a stale 215MB gitignored Mach-O binary (`file mailserver/gateway` => "Mach-O 64-bit executable arm64"; module root is `mailserver/` per `mailserver/go.mod`), so every cited `cd .../mailserver/gateway` fails with "Not a directory". For deploy/test.sh:51 `cd "$PROJECT_DIR/gateway"` is a standalone cd under `set -euo pipefail` — a fait

### M4. Production deployment chain (systemd unit, install.sh, upgrade.sh, UPGRADE.md) never renamed; runbooks now give commands that fail
- **Lens/source:** change-set review → `rename-binaries`
- **Location:** `mailserver/deploy/scripts/upgrade.sh (also deploy/mailserver.service:12, deploy/scripts/install.sh:16, docs/guides/UPGRADE.md:13,24):9`
- **Issue:** Plan Task 1 Step 4 ('Update systemd units — deploy/mailserver.service, deploy/authserver.service') was claimed complete in the archived plan but nothing changed: mailserver.service still ExecStart=/opt/mailserver/gateway, install.sh still copies `../gateway`, and upgrade.sh / docs/guides/UPGRADE.md instruct operators to run `cd gateway && go build -o gateway ./cmd/gateway`, which fails post-rename (cmd/gateway no longer exists, and the gateway/ module dir is long gone). The chain is internally consistent only if you build with the OLD output name, directly contradicting the new CLAUDE.md instruction `go build -o mailserverd ./cmd/mailserverd`. Note also deploy/authserver.service does not exist anywhere in the repo despite being named in the plan.
- **Evidence:** `upgrade.sh:9 `echo "  1. Build: cd gateway && go build -o gateway ./cmd/gateway"`; mailserver.service:12 `ExecStart=/opt/mailserver/gateway`; install.sh:16 `cp "$(dirname "$0")/../gateway" "$INSTALL_DIR/gateway"`; UPGRADE.md:24 `CGO_ENABLED=0 go build -o gateway -ldflags="-s -w" ./cmd/gateway``
- **Fix:** Either complete the rename end-to-end (ExecStart=/opt/mailserver/mailserverd, install/upgrade scripts and UPGRADE.md use mailserverd, keep a compat symlink for upgrades from old installs) or explicitly document that the on-disk install name remains `gateway`. At minimum fix the now-broken build commands in upgrade.sh and UPGRADE.md.
- **Verifier note:** Verified every cited line verbatim and empirically. mailserver.service:12 still has `ExecStart=/opt/mailserver/gateway`; install.sh:16 still `cp .../../gateway "$INSTALL_DIR/gateway"`; upgrade.sh:9 and UPGRADE.md:13,23-24 instruct `go build -o gateway ./cmd/gateway` and `cd mailserver/gateway`. I confirmed `mailserver/cmd/gateway/` no longer exists (only `cmd/mailserverd/`) and `mailserver/gateway

### M5. admin.test.ts imports 18 moved pages by old paths — entire admin test suite fails to load
- **Lens/source:** change-set review → `admin-routes`
- **Location:** `mailserver/webmail/src/routes/admin.test.ts:6-26`
- **Issue:** Commit 306c1e8 moved 18 admin pages into (mail)/(identity)/(system) route groups but did not update src/routes/admin.test.ts, which imports each page component by its pre-move relative path. Vitest cannot transform the file ('Error: Failed to resolve import "./admin/users/+page.svelte" from "src/routes/admin.test.ts". Does the file exist?'), so all ~22 admin page-mount tests in the suite are dead, `npm test` fails, and `npm run check` gains 18 'Cannot find module' errors — violating the project rule that check must report 0 errors, 0 warnings. Reproduced locally: `npx vitest run src/routes/admin.test.ts` → 'Test Files 1 failed (1), Tests no tests'. Only the imports of the four ungrouped routes (dashboard, audit, ediscovery, content-search) still resolve.
- **Evidence:** `import AdminUsers from './admin/users/+page.svelte';
import AdminDomains from './admin/domains/+page.svelte';
... (18 imports) ...
vitest: Error: Failed to resolve import "./admin/users/+page.svelte" from "src/routes/admin.test.ts". Does the file exist?`
- **Fix:** Update the 18 import paths to include the group segment, e.g. `import AdminUsers from './admin/(mail)/users/+page.svelte';`, `import AdminIdentity from './admin/(identity)/identity/+page.svelte';`, `import AdminSystem from './admin/(system)/system/+page.svelte';`. Then run `npx vitest run src/routes/admin.test.ts` and `npm run check` to confirm the suite loads again. Consider $lib-relative or per-group co-located tests to avoid this class of breakage on future moves.
- **Verifier note:** Confirmed by direct reproduction. Commit 306c1e8 moved 18 admin pages into (mail)/(identity)/(system) route groups (verified: e.g. admin/(mail)/users/+page.svelte, admin/(identity)/identity/+page.svelte, admin/(system)/system/+page.svelte), but src/routes/admin.test.ts:6-26 still imports them by pre-move relative paths like './admin/users/+page.svelte'. Filesystem check shows 18 of those 22 import

### M6. Cross-service reuse claim not realized — middleware is still service-private and authserver keeps a duplicate RequireAuth
- **Lens/source:** change-set review → `authenticator-iface`
- **Location:** `shared/auth/authenticator.go:1-4`
- **Issue:** The package comment claims the interface 'lets RequireAuth/RequireAdmin/RequireRole work across authserver, mailserver, and future services without importing any service-specific code', and the commit message says 'Enables cross-service RBAC reuse'. In reality the only consumer is mailserver/internal/middleware/auth.go, which still imports setjoin.com/mailserver/internal/auth for ContextWithUser/UserFromContext (line 8, 38, 58), so the middleware cannot be shared as-is. authserver/internal/middleware/auth.go:14 retains a separate implementation: 'func RequireAuth(jwt *token.JWTProvider, logger *slog.Logger)'. The plan (docs/plans/archive/2026-06-10-repo-structure-naming.md, Task 4) explicitly said 'Modify: shared/middleware/auth.go — depend on interface, not *auth.Chain', but no such file exists in shared/middleware/ (only csrf, device_compliance, requestid, slow_request) — the implementer adapted by changing mailserver's private middleware instead, and the plan was archived as '✅ Complete' anyway. The remaining work (move middleware + context helpers to shared, adapt authserver) is not tracked anywhere.
- **Evidence:** `// This is the seam that
// lets RequireAuth/RequireAdmin/RequireRole work across authserver, mailserver,
// and future services without importing any service-specific code.`
- **Fix:** Either complete the move (relocate RequireAuth/RequireAdmin/RequireRole and the Claims context helpers to shared/middleware + shared/auth, and have authserver consume them), or soften the godoc in shared/auth/authenticator.go and CLAUDE.md to say the interface is a seam for future reuse, and add a tracked follow-up task for the shared-middleware move.
- **Verifier note:** Every factual claim is confirmed by quoted code. The godoc at shared/auth/authenticator.go:2-4 claims the interface lets RequireAuth/RequireAdmin/RequireRole 'work across authserver, mailserver, and future services without importing any service-specific code,' and commit 38a6c74 says 'Enables cross-service RBAC reuse.' But grep shows the only importer of setjoin.com/shared/auth is mailserver/inter

### M7. SQL injection CI check regex is backwards — misses the canonical injection pattern
- **Lens/source:** change-set review → `ci-hardening`
- **Location:** `.github/workflows/xinchuang-ci.yml:92-95`
- **Issue:** The grep requires %s to appear BEFORE the SQL keyword inside the Sprintf call: 'fmt\.Sprintf\([^)]*%s[^)]*SELECT'. The standard injection shape fmt.Sprintf("SELECT * FROM users WHERE name = '%s'", name) has the keyword first and %s after, so it does NOT match (verified empirically: of 6 test cases, only the contrived fmt.Sprintf("%s SELECT", prefix) matched). It is also case-sensitive (lowercase 'select' bypasses), single-line only (backtick multi-line queries bypass), Sprintf-only (string concatenation '"SELECT..." + name' bypasses), and ignores %d/%v/%q verbs. Real dynamic-SQL call sites in the repo (mailserver/internal/ad/sync.go:238, internal/ldapsync/sync.go:249: fmt.Sprintf("UPDATE users SET %s WHERE id = $%d", ...)) are not matched. This matters doubly because commit 7b9bc1a's message names this check as a compensating control for removing the lint gate.
- **Evidence:** `! grep -rnP 'fmt\.Sprintf\([^)]*%s[^)]*SELECT|fmt\.Sprintf\([^)]*%s[^)]*INSERT|fmt\.Sprintf\([^)]*%s[^)]*UPDATE|fmt\.Sprintf\([^)]*%s[^)]*DELETE' \
  mailserver/ authserver/ shared/ --include="*.go"`
- **Fix:** Replace the homegrown grep with gosec rules G201/G202 (SQL string formatting/concatenation) — gosec is already enabled in mailserver/.golangci.yml but never executes in CI since the lint step was deleted. At minimum, fix the regex to put the keyword before the verb, add -i for case-insensitivity, and include %d/%v/%q and '+' concatenation patterns.
- **Verifier note:** Empirically verified at .github/workflows/xinchuang-ci.yml:92-95. The regex `fmt\.Sprintf\([^)]*%s[^)]*SELECT|...` requires %s BEFORE the SQL keyword; running it against 6 test cases matched only the contrived `fmt.Sprintf("%s SELECT", prefix)` and NOT the canonical `fmt.Sprintf("SELECT * FROM users WHERE name = '%s'", name)`. Case-sensitivity (no -i), Sprintf-only, %d/%v/%q-bli

### M8. golangci-lint gate added then deleted from CI; gosec never runs anywhere in CI
- **Lens/source:** change-set review → `ci-hardening`
- **Location:** `.github/workflows/xinchuang-ci.yml:83-112 (lint step absent from unit-tests-amd64 job)`
- **Issue:** fa33efe added a golangci-lint step (incl. newly-enabled gosec); after timeout fixes (8724ab7, b9d576f) commit 7b9bc1a removed the step entirely, claiming 'Lint is enforced locally before commit' — an honor-system control, while CLAUDE.md says lint 'must pass before commit'. The slowness was largely self-inflicted: 'go install .../golangci-lint@latest' compiles the linter from source on every run (minutes by itself), no cache was used, and '--new-from-rev=HEAD~1' does not reduce analysis cost (it only filters reported issues — all 40 packages are still type-checked) and breaks anyway under actions/checkout's default fetch-depth:1 where HEAD~1 does not exist. The end state: the S4 'CI lint gate' marked Complete in the archived hardening plan (5bd4c91) does not exist.
- **Evidence:** `-      - name: Run golangci-lint
-        run: |
-          go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest
-          cd mailserver && golangci-lint run --timeout=10m --new-from-rev=HEAD~1 ./...   (7b9bc1a)`
- **Fix:** Restore lint via the official golangci/golangci-lint-action (downloads a prebuilt binary and caches analysis between runs — typically 1-3 min) as a blocking PR job, or run a fast subset (gosec, govet, unused) blocking and the full set in a non-required job. Lint authserver/ and shared/ too — the deleted step only ever covered mailserver/.
- **Verifier note:** Every factual claim is confirmed. fa33efe added a golangci-lint step (with gosec enabled — mailserver/.golangci.yml:21 lists gosec, only G104 excluded); 7b9bc1a deleted it with message "Lint is enforced locally before commit"; the current unit-tests-amd64 job (.github/workflows/xinchuang-ci.yml:83-112) has no lint step and gosec runs nowhere else (only the narrow fmt.Sprintf+%s+SQL-keyword grep at

### M9. govulncheck made non-blocking with blanket continue-on-error — all future CVEs are silently ignored
- **Lens/source:** change-set review → `ci-hardening`
- **Location:** `.github/workflows/xinchuang-ci.yml:97-103`
- **Issue:** 5bd4c91 set continue-on-error: true to mask one known unfixable CVE (GO-2026-4753 in goxmldsig/SAML), but this suppresses every future finding too: the job and workflow stay green, there is no scheduled scan, no issue creation, and the workflow header explicitly says 'No email on failure'. For a security product whose auth server has a live SAML CVE, new vulnerabilities will arrive unnoticed. Also, since the workflow has path filters, vuln scans only run when authserver/mailserver/shared files change — a CVE published against an unchanged dependency is never re-scanned.
- **Evidence:** `- name: Run govulncheck
        continue-on-error: true  # non-blocking: reports CVEs but doesn't fail CI`
- **Fix:** Make the PR step blocking again and allowlist the single known OSV ID (run govulncheck -format json and diff findings against a checked-in known-vulns file), plus add a scheduled (cron) workflow that runs govulncheck on main and opens/updates a GitHub issue or notification on findings, independent of push path filters.
- **Verifier note:** Confirmed from the file: `.github/workflows/xinchuang-ci.yml:97-98` sets `continue-on-error: true # non-blocking: reports CVEs but doesn't fail CI` on the govulncheck step, so any current or future finding leaves the job/workflow green. The whole workflow is path-filtered to authserver/mailserver/shared/cross-build.sh/workflow changes (lines 10-22), only triggers on push/pull_request/workflow_disp

### M10. Schema version guard is stale at birth and structurally cannot detect missing migrations after V000
- **Lens/source:** change-set review → `ci-hardening`
- **Location:** `mailserver/cmd/mailserverd/main.go:174-176`
- **Issue:** The guard checks MAX(version) >= 65, but only V000__bootstrap_migrations.sql ever inserts into schema_migrations (it backfills the single value 65); none of V001-V066 insert their own version, despite V000's comment saying they should. V066__pg_stat_statements.sql landed in d2f3fa5 at 12:02 — two minutes after the guard (a38290e, 12:00) — without inserting 66 or bumping any constant, so a database missing V066 passes the guard and the admin badge shows up-to-date. expectedVersion is hardcoded in three places (mailserverd/main.go:174 = 65, internal/admin/admin_system.go:98 = 65, authserver main.go = 8) with no CI check tying it to the migration files. Beyond detecting 'V000 itself not applied', the guard is decorative.
- **Evidence:** `const expectedVersion = 65
var actualVersion int
pool.QueryRow(ctx, `SELECT COALESCE(MAX(version), 0) FROM schema_migrations`).Scan(&actualVersion)`
- **Fix:** Either have every migration INSERT its version (and add a CI step asserting max Vxxx filename == the Go constant == max INSERT value), or derive expected version at build time from the migrations directory (go:embed + parse) so it cannot drift. Deduplicate the constant into one shared package.
- **Verifier note:** Confirmed by code. mailserverd/main.go:174-176 hardcodes `const expectedVersion = 65` and checks `COALESCE(MAX(version),0) FROM schema_migrations`. V000__bootstrap_migrations.sql:12-14 is the ONLY writer to schema_migrations across all migrations (grep for "INSERT INTO schema_migrations" returns only V000) and it backfills the single value 65; V066__pg_stat_statements.sql contains only `CREATE EXT

### M11. Dependabot cargo entry points at a directory with no Cargo.toml; mailctl, src-tauri, and desktop npm uncovered
- **Lens/source:** change-set review → `ci-hardening`
- **Location:** `.github/dependabot.yml:12-22`
- **Issue:** directory: "/clients/rust" contains only the crate subdirectories desktop-core/, guard-core/, mail-core/ (each with its own Cargo.toml) and no root manifest, so Dependabot will fail to locate a Cargo.toml for that entry and produce zero cargo updates. Additional gaps: /mailctl has its own go.mod (listed in go.work) but is absent from the gomod directories; /clients/desktop/src-tauri/Cargo.toml (the Tauri app, built in release.yml) is not covered by any cargo entry; /clients/desktop/package.json is not covered by the npm entry. github-actions coverage at "/" is correct.
- **Evidence:** `- package-ecosystem: "cargo"
    directory: "/clients/rust"`
- **Fix:** Use directories: ["/clients/rust/desktop-core", "/clients/rust/guard-core", "/clients/rust/mail-core", "/clients/desktop/src-tauri"] for cargo (or add a workspace Cargo.toml at /clients/rust), add "/mailctl" to the gomod directories, and add "/clients/desktop" to npm.
- **Verifier note:** Verified .github/dependabot.yml:12-13 sets cargo `directory: "/clients/rust"`, but `ls /clients/rust` shows only desktop-core/, guard-core/, mail-core/ subdirs and no Cargo.toml at that path — the actual workspace manifest and lockfile are at /clients/Cargo.toml and /clients/Cargo.lock (one level up). Dependabot's cargo updater needs a Cargo.toml at the configured directory, so this entry resolves

### M12. shared_preload_libraries never configured or documented — pg_stat_statements view unusable even after CREATE EXTENSION
- **Lens/source:** change-set review → `observability`
- **Location:** `mailserver/sql/migrations/V066__pg_stat_statements.sql:6`
- **Issue:** pg_stat_statements collects nothing and its view raises 'pg_stat_statements must be loaded via shared_preload_libraries' unless postgresql.conf sets shared_preload_libraries = 'pg_stat_statements' and the server restarts. The plan (Task 6 Step 2) explicitly required adding this note to deploy docs, but a repo-wide grep finds 'shared_preload_libraries' only in the plan document itself — nothing in mailserver/deploy/ (config samples, patroni.yml.template) or docs/guides/ was updated. The migration silently produces a non-functional extension on every deployment.
- **Evidence:** `grep -rln shared_preload_libraries → only docs/plans/archive/2026-06-10-production-hardening.md; mailserver/deploy/ contains patroni.yml.template, config.env.sample etc. with no pg_stat_statements entry`
- **Fix:** Add shared_preload_libraries='pg_stat_statements' to the deploy templates (patroni.yml.template, install/upgrade guides) plus a restart note, and have the admin endpoint surface a clear 'extension not loaded' state.
- **Verifier note:** Verified V066__pg_stat_statements.sql:6 contains only `CREATE EXTENSION IF NOT EXISTS pg_stat_statements;` — which does not configure shared_preload_libraries, a documented PostgreSQL prerequisite for the extension to collect stats and for its view to be queryable. A repo-wide grep finds `shared_preload_libraries` only in docs/plans/archive/2026-06-10-production-hardening.md (the plan); the Patron

### M13. lifecycle.Stop() shuts down in reverse registration order, not reverse initialization order, ignores what actually started, and aborts on first error
- **Lens/source:** change-set review → `lifecycle-protocol`
- **Location:** `mailserver/internal/lifecycle/lifecycle.go:64-72`
- **Issue:** Start() computes a topological order and tracks `initialized`, but both are discarded; Stop() iterates `l.subsystems` (registration order) in reverse. If callers register in non-topological order (the entire point of the package), a dependency can be shut down before its dependents — e.g. register(http, db) with http→db: topo init order is [db, http], but Stop runs [db.Shutdown, http.Shutdown], killing the DB while HTTP still uses it. Stop() also calls Shutdown on every registered subsystem regardless of whether Start succeeded (double-shutdown after a failed Start, since Start already rolled back), and it returns on the first Shutdown error (line 67-69), leaving all remaining subsystems running. No test covers Stop ordering (lifecycle_test.go has no Stop() test and its testSubsystem.Shutdown is a no-op). Severity capped at medium only because the package is currently dead code.
- **Evidence:** `func (l *Lifecycle) Stop(ctx context.Context) error {
	for i := len(l.subsystems) - 1; i >= 0; i-- {
		if err := l.subsystems[i].Shutdown(ctx); err != nil {
			return fmt.Errorf("subsystem %s shutdown: %w", l.subsystems[i].Name(), err)
		}
	}`
- **Fix:** Store the sorted/initialized slice on the Lifecycle in Start(); Stop() should reverse that slice only, continue past per-subsystem errors (aggregating with errors.Join), and be a no-op for subsystems that never initialized. Add a Stop-ordering test.
- **Verifier note:** Verified against lifecycle.go. Stop() (lines 65-72) iterates `l.subsystems` in reverse — that is the raw registration-order slice (struct holds only `subsystems`, line 22-24), NOT the topologically `sorted`/`initialized` slices which are local to Start() (lines 44-58) and discarded. So shutdown order is reverse-of-registration, not reverse-of-init; the finding's http→db example (register order [ht

### M14. WebSocket push channel keyed by user id while reducers notify by mailbox id — cross-tenant push leak / missed notifications
- **Lens/source:** security/structure hunt → `authz-tenancy`
- **Location:** `mailserver/internal/ws/handler.go:159`
- **Issue:** The WebSocket handler subscribes each connection to the NOTIFY channel `tag:{claims.UserID}` (the authenticated user's id). But the delivery and send reducers publish new-mail/sent events on `tag:{mailbox_id}` (deliver_group_vacation.sql:333 `'tag:' || v_mailbox.id`, send.sql:272 `'tag:' || p_mailbox_id`). These match only when user id == mailbox id — the same unenforced conflation as the JMAP path. When the id spaces diverge, two failure modes occur: (1) a user receives NO push updates for their own mailbox (availability), and (2) if user A's user id numerically equals user B's mailbox id, user A's WebSocket receives user B's `new_message`/`sent` events, leaking message_id, thread_id, tag_id and the mailbox jmap_email_state of another tenant's mailbox. Because there is no RLS or principal check on the NOTIFY payload, the gateway forwards whatever arrives on the subscribed channel.
- **Evidence:** `pgChannel := fmt.Sprintf("tag:%d", claims.UserID)
subID, err := h.dispatcher.Subscribe(ctx, pgChannel, notifyCh)
// deliver_group_vacation.sql: PERFORM pg_notify('tag:' || v_mailbox.id, json_build_object('event','new_message','message_id', v_message_id, 'thread_id', v_thread_id, 'state', ...))
// send.sql: PERFORM pg_notify('tag:' || p_mailbox_id, json_build_object('event','sent','message_id', v_message_id, ...))`
- **Fix:** Subscribe to the channel keyed by the caller's actual resolved mailbox id (via the same lookup as GetAccountID), not claims.UserID, so producer and consumer agree on the id space. Verify the resolved mailbox is owned by/delegated to the authenticated user before subscribing.
- **Verifier note:** Confirmed the id-space mismatch is real. handler.go:159 subscribes to fmt.Sprintf("tag:%d", claims.UserID) (user-id space), while every tag: producer keys on mailbox id: deliver_group_vacation.sql:333 ('tag:' || v_mailbox.id), send.sql:272 ('tag:' || p_mailbox_id), plus import_export.sql:100 and recall.sql:98 — none use user_id. The schema proves the spaces are distinct independent sequences: user

### M15. Core user-data tables (mailboxes, messages, calendars, contacts) have no RLS — R4 backstop entirely absent
- **Lens/source:** security/structure hunt → `authz-tenancy`
- **Location:** `mailserver/sql/schema/004_mailboxes.sql:1-119 (whole file)`
- **Issue:** DATABASE_SECURITY.md rule R4 mandates that every user-data table have RLS enabled and FORCE'd with per-user policies. A grep across the entire sql/ tree returns zero occurrences of `ROW LEVEL SECURITY` or `CREATE POLICY`, and no per-user session variable (app.user_id / app.account_id / app.mailbox) is ever set by the gateway or reducers (only app.encryption_key is set in internal/db/pool.go:33). The JMAP reducers are plain LANGUAGE plpgsql (SECURITY INVOKER) executing as the single shared gateway DB role. This means there is NO database-level enforcement of tenant isolation — the only thing standing between an authenticated user and another tenant's mailbox is the application-layer p_account_id value, which (per the primary finding) is derived from the caller's user id rather than a verified mailbox ownership check. The absence of RLS converts the id-conflation bug above from 'defense-in-depth would have caught it' into 'a single application mistake fully breaks isolation'.
- **Evidence:** `$ grep -rln 'ROW LEVEL SECURITY|CREATE POLICY' sql/   ->  (no output)
$ grep -rn 'app.user_id|app.account_id|app.mailbox' sql/ internal/  ->  (no output)
-- 004_mailboxes.sql defines mailboxes with no ALTER TABLE ... ENABLE ROW LEVEL SECURITY and no policies; 006_messages.sql likewise.`
- **Fix:** Apply `ALTER TABLE ... ENABLE ROW LEVEL SECURITY; ... FORCE ROW LEVEL SECURITY;` with per-user policies (`USING (user_id = current_setting('app.user_id')::bigint)` or via a mailbox-ownership join) on mailboxes, messages, message_tags, calendars, calendar_events, addressbooks, contacts and related tables, and set app.user_id per request from the auth context. This provides the mandated R4 backstop independent of any single reducer's filtering.
- **Verifier note:** Verified every claim against code. Repo-wide grep of all .sql files (mailserver/, authserver/, shared/) returns ZERO occurrences of 'ROW LEVEL SECURITY', 'CREATE POLICY', or 'FORCE ROW LEVEL' — confirming no R4 backstop. Read 004_mailboxes.sql in full (lines 1-119): the mailboxes table has a user_id column but no ENABLE ROW LEVEL SECURITY / policies; 006_messages.sql, 010_calendar.sql, 011_contact

### M16. R4 Row-Level Security is 0% implemented — no user-data table has RLS, gateway never sets app.current_user_id
- **Lens/source:** security/structure hunt → `sql-rls`
- **Location:** `mailserver/sql/schema/*.sql, mailserver/internal/db/pool.go:pool.go:33; schema-wide`
- **Issue:** DATABASE_SECURITY.md Rule 4 (mirrored in CLAUDE.md) mandates that EVERY user-data table have `ENABLE ROW LEVEL SECURITY` + `FORCE ROW LEVEL SECURITY` + per-user policies, and that the gateway inject `app.current_user_id`/`app.current_mailbox_id`/`app.is_admin` per transaction via set_config. Neither half exists. `grep -rn "ENABLE ROW LEVEL SECURITY" --include="*.sql"` over the entire repo returns 0; there are no CREATE POLICY statements anywhere. The doc's own audit command (`grep ... mailserver/sql/schema/ | wc -l`) evaluates to 0. The only set_config the gateway ever issues is for app.encryption_key (pool.go:33) — it never sets app.current_user_id, so even if policies existed they would read NULL. Affected tables include messages, message_tags, contacts, calendar_events, tasks, user_devices (016_identity_sync.sql:36), migration_jobs (037_migration.sql:2), webhook_subscriptions (V021__webhooks.sql:3), vacation_settings, user_smime_certs, user_spam_model, tags. Tenant isolation therefore rests entirely on application-layer correctness (reducer p_account_id filters + parseAccountID enforcing accountID==userID in handler.go:270). That primary control appears present, so this is a defense-in-depth gap rather than a demonstrated cross-tenant read — but it removes the safety net behind every direct-SQL admin handler (e.g. admin_content_search.go, admin_ediscovery.go query `messages` with no ownership backstop) and any future SQL bug.
- **Evidence:** `pool.go:33  `_, err := conn.Exec(ctx, "SELECT set_config('app.encryption_key', $1, false)", encryptionKey)`  // the ONLY set_config; app.current_user_id is never set. Repo-wide: grep -rn "ENABLE ROW LEVEL SECURITY" --include="*.sql" => 0 matches.`
- **Fix:** Either (a) implement R4 as the standard prescribes: ALTER TABLE ... ENABLE/FORCE ROW LEVEL SECURITY + per-action policies keyed on current_setting('app.current_user_id'), and add transaction-scoped set_config('app.current_user_id', userID, true) in the request path before any handler/reducer touches user data; or (b) if RLS is intentionally deferred, downgrade R4 in DATABASE_SECURITY.md/CLAUDE.md from an enforced rule to a roadmap item so the stated control matches reality. Until then the audit checklist item 'New user-data tables have ENABLE ROW LEVEL SECURITY + FORCE + policies' is impossible to satisfy and silently false for all existing tables.
- **Verifier note:** Verified every factual claim. Repo-wide `grep -rni "ENABLE ROW LEVEL SECURITY" --include="*.sql"` and `grep -rni "CREATE POLICY"` both return 0 matches; the doc's own audit command (`grep ... mailserver/sql/schema/ | wc -l`, DATABASE_SECURITY.md:222) thus evaluates to 0 against a stated expectation that it "Should equal the number of user-data tables." Confirmed mailserver/internal/db/pool.go:33 i

### M17. app.encryption_key set at session scope via AfterConnect is unreliable under PgBouncer transaction pooling
- **Lens/source:** security/structure hunt → `sql-rls`
- **Location:** `mailserver/internal/db/pool.go:33`
- **Issue:** The pgcrypto key used to encrypt/decrypt S/MIME private keys is loaded once per pgx connection with `set_config('app.encryption_key', $1, false)` — the `false` third argument makes it a SESSION-level GUC. The pool comment (pool.go:11) states it points at 'PgBouncer (transaction mode)'. In PgBouncer transaction pooling, the pgx connection is a client connection that is multiplexed across different server backends per transaction, and session-level SET/set_config is explicitly unsupported (PgBouncer docs warn SET does not persist in transaction mode). Consumers read this GUC at query time: admin_smime.go:139 `pgp_sym_encrypt($4, current_setting('app.encryption_key'))` and smtp/outbound.go:622 `pgp_sym_decrypt(sc.private_key_enc, current_setting('app.encryption_key'))`. If a transaction lands on a server backend that did not run AfterConnect, current_setting raises 'unrecognized configuration parameter app.encryption_key' (or returns empty), causing intermittent S/MIME sign/store failures. Severity is environment-conditional: harmless if the pool is actually session-mode, broken if transaction-mode as the comment claims.
- **Evidence:** `pool.go:33  `_, err := conn.Exec(ctx, "SELECT set_config('app.encryption_key', $1, false)", encryptionKey)`  (third arg false = session scope) vs. comment line 11 `// NewPool creates a pgxpool pointing at PgBouncer (transaction mode).``
- **Fix:** Do not rely on a session GUC across a transaction-pooling proxy. Options: pass the key as a transaction-scoped param inside each pgcrypto call (set_config(...,true) within the same tx, or supply the key as a bound $N parameter to pgp_sym_encrypt/decrypt), route S/MIME crypto through the DB_DIRECT_DSN connection that bypasses PgBouncer, or configure PgBouncer server_reset_query / a dedicated session-mode pool for these operations. Add an integration test that exercises encrypt-then-decrypt across two separate pool acquisitions.
- **Verifier note:** Verified the core mechanism is correct. The live pool (mailserver/cmd/mailserverd/main.go:165 -> shared/pgxutil/pool.go:41) sets the pgcrypto key with `set_config('app.encryption_key', $1, false)` (session scope) in AfterConnect, and main DB_DSN points at PgBouncer (config.env.sample:13 port 6432; deployment-guide.md:132) running `pool_mode = transaction` (mailserver/deploy/pgbouncer.ini:19, guide

### M18. SMTP DATA terminator accepts bare-LF / mixed line endings (SMTP smuggling surface) on the inbound MTA
- **Lens/source:** security/structure hunt → `protocol-parsing`
- **Location:** `mailserver/internal/smtp/inbound.go:498, 284`
- **Issue:** Inbound DATA is read via Go's `c.tp.DotReader()` (line 498). Go's net/textproto dotReader state machine (verified in GOROOT src/net/textproto/reader.go:368-420) treats a bare-LF as a line terminator: from stateData a '\n' -> stateBeginLine, and from stateBeginLine a '.' followed by '\n' (no CR) -> stateEOF. Therefore `<LF>.<LF>`, `<CRLF>.<LF>`, and `<LF>.<CRLF>` all terminate the message body, and the reader rewrites trailing CRLF to LF but preserves bare LF inside the body. The command loop likewise uses `c.tp.ReadLine()` (line 284), which splits on bare '\n'. The server never enforces canonical CRLF nor rejects bare LF on the inbound path; `validateLineLengths` (helpers.go:126) splits on '\n' and happily passes bare-LF messages. This is the classic SMTP-smuggling primitive (a permissive end-of-DATA detection that disagrees with a downstream parser). The outbound relay re-normalizes to CRLF via dotStuff (helpers.go:88-123), which mitigates relay smuggling, but locally delivered messages are stored with attacker-chosen bare-LF/embedded-dot boundaries.
- **Evidence:** `reader := c.tp.DotReader()
limitReader := io.LimitReader(reader, maxSize+1)
data, tmpFile, err := spooledRead(limitReader, maxSize)`
- **Fix:** Reject messages containing bare LF or bare CR in the DATA stream (per RFC 5321 §2.3.8 / the 2023 SMTP-smuggling guidance), or normalize the body to strict CRLF before any downstream processing and storage. At minimum, fail the transaction with 5xx when a bare-LF line or a bare-LF `.` line is seen, rather than silently treating it as a body/terminator.
- **Verifier note:** Every load-bearing claim is verified in code. inbound.go:498 reads DATA via `reader := c.tp.DotReader()` and inbound.go:284 reads commands via `c.tp.ReadLine()` (both match the quoted evidence). Go's textproto state machine in GOROOT reader.go:368-420 confirms bare-LF terminates: `stateData` on `'\n'`->stateBeginLine and `stateDot` on `'\n'`->stateEOF (no CR required), so `<LF>.<LF>` ends DATA and

### M19. LDAP filter parser recurses without depth limit and runs before any bind check
- **Lens/source:** security/structure hunt → `protocol-parsing`
- **Location:** `mailserver/internal/ldap/search.go:737, 754, 76`
- **Issue:** parseFilterExpr is a recursive-descent parser with no recursion-depth guard: each '&'/'|'/'!' descends via `parseFilterExpr(rest)` (line 754) for every nested sub-expression. A filter such as `(&(&(&...)))` nested tens of thousands deep recurses one frame per level and can exhaust the goroutine stack, crashing the process. Critically, handleSearch (line 76) parses the client-supplied filter (`filter := r.FilterString()`, line 80) and dispatches to searchPeople/etc. WITHOUT verifying the connection completed a successful bind — there is no `if !bound` / authenticated-session check in handleSearch, so the recursive parse is reachable by an unbound/anonymous LDAP client even though handleBind rejects anonymous binds for actual data access. The SQL it produces is parameterized (attrToColumn is a fixed allowlist with a safe default, filterToSQL uses $N placeholders), so this is a DoS rather than injection.
- **Evidence:** `if expr[0] == '&' || expr[0] == '|' || expr[0] == '!' {
	...
	for len(rest) > 0 && rest[0] == '(' {
		child, n, err := parseFilterExpr(rest)`
- **Fix:** Pass and enforce a maximum nesting depth (e.g. 32) through parseFilterExpr, returning an error past the limit. Also gate handleSearch on a successful bound session so unauthenticated clients cannot drive the parser, matching the security posture already taken in handleBind.
- **Verifier note:** Confirmed both sub-claims with quoted code. parseFilterExpr (search.go:742-765) recurses at line 754 `child, n, err := parseFilterExpr(rest)` for each nested &/|/! with no depth counter or limit. handleSearch (search.go:76-140) reads `filter := r.FilterString()` (line 80) and dispatches to searchPeople (line 128) with no bind check — the Server struct (server.go:20-31) has NO per-connection bound-

### M20. Unauthenticated SSRF probe via /api/discover (SRV/MX targets fetched over HTTPS with no IP filtering)
- **Lens/source:** security/structure hunt → `ssrf-outbound`
- **Location:** `mailserver/internal/discovery/handler.go:83-120`
- **Issue:** HandleDiscover is an unauthenticated GET /api/discover?domain=... endpoint. discover() does net.LookupSRV("jmap","tcp",domain) and net.LookupMX(domain), then constructs https://<target>:<port> from the DNS answer and fetches /.well-known/setjoin with a plain http.Client (fetchWellKnown). An attacker who controls DNS for a domain they own can publish an SRV/MX record whose target is an internal IP/hostname (e.g. _jmap._tcp pointing at an internal host, or MX -> internal host), causing the server to make an HTTPS request to an internal address chosen by the attacker. There is no validation that the SRV/MX target resolves to a public IP, no loopback/private-range rejection, and no resolve-then-pin. It is blind/semi-blind (only well-known JSON shape is reflected, and only port 443 / SRV-specified port), and TLS to internal hosts will usually fail cert validation, which limits impact — but it is still an unauthenticated outbound-request primitive against operator-controlled internal infrastructure on attacker-chosen host:port.
- **Evidence:** `url := fmt.Sprintf("https://%s:%d", target, addr.Port)   // trySRV: target from attacker DNS
...
url := fmt.Sprintf("https://%s:443", host)                // tryMX: host from attacker DNS
...
client := &http.Client{Timeout: 5 * time.Second}
resp, err := client.Get(serverURL + "/.well-known/setjoin")`
- **Fix:** Before fetchWellKnown, resolve the SRV/MX target and reject any that resolve to loopback/private/link-local/ULA ranges; pin the dialed IP (custom DialContext re-checking the connected address). Consider rate-limiting and/or requiring auth on /api/discover, and constrain the SRV port to 443 or a small allowlist.
- **Verifier note:** Verified every claim against source. /api/discover is registered unauthenticated at mailserver/cmd/mailserverd/main.go:555 (`mux.Handle("GET /api/discover", discovery.HandleDiscover())`, explicit comment "no auth required"); the only global wrappers are RequestID, Metrics, SecurityHeaders, and HSTS (main.go:1065,1239,1255) — none authenticate or rate-limit. trySRV uses attacker-controlled DNS: `ne

### M21. Gateway hardcodes SM2 key to nil, so it cannot validate SM2-signed JWTs from authserver under the smx/hybrid crypto profile
- **Lens/source:** security/structure hunt → `secrets-crypto`
- **Location:** `mailserver/internal/auth/chain.go:53`
- **Issue:** The gateway's auth chain constructs its JWTProvider with sm2Key passed as nil unconditionally, ignoring cfg.CryptoProfile and cfg.SM2PrivateKeyFile. When CRYPTO_ALGORITHM_PROFILE=smx (or hybrid with an SM2 key), the authserver signs access/refresh tokens with alg=SM2 / kid=authserver-sm2-1 (authserver/internal/token/jwt.go:227-230). The gateway's Validate() takes the SM2 branch (mailserver/internal/auth/jwt.go:132) and, because p.sm2Key==nil, returns 'SM2 token but no SM2 key configured' (jwt.go:136-138). Every SM2 token from the authserver is therefore rejected by the gateway. This fails closed (no auth bypass), but it is a real correctness/availability defect for the smx deployment path: all authenticated requests to the gateway would 401 once the smx profile is enabled, since no code path loads an SM2 key into the gateway provider. The NewChain caller in main.go (mailserver/cmd/mailserverd/main.go:340) passes no SM2 key either.
- **Evidence:** `jwtProvider := NewJWTProvider(cfg.JWTSecret, nil, cfg.CryptoProfile, cfg.JWTExpiry, 0)`
- **Fix:** Load the SM2 key from cfg.SM2PrivateKeyFile when cfg.CryptoProfile is smx or hybrid and pass it into NewJWTProvider, mirroring the authserver. Add a startup self-check that round-trips an SM2 token between issuer and verifier so the smx profile cannot silently lock everyone out.
- **Verifier note:** Confirmed by reading the full causal chain. mailserver/internal/auth/chain.go:53 builds the gateway's JWTProvider with `NewJWTProvider(cfg.JWTSecret, nil, cfg.CryptoProfile, cfg.JWTExpiry, 0)` — sm2Key is hardcoded nil regardless of cfg.CryptoProfile/cfg.SM2PrivateKeyFile, and the only caller mailserverd/main.go:340 (`auth.NewChain(cfg, pool)`) passes no key. The gateway's Validate() (jwt.go:132-1

### M22. Gateway mutating routes (POST /jmap, settings, blobs) accept cookie auth but have NO CSRF protection
- **Lens/source:** security/structure hunt → `web-frontend`
- **Location:** `mailserver/cmd/mailserverd/main.go:582`
- **Issue:** The mailserver gateway authenticates requests via the `access_token` HttpOnly cookie (mailserver/internal/auth/chain.go:251-256: the JWT method falls back to `r.Cookie("access_token")` when no Bearer header is present). All state-changing gateway routes — `POST /jmap` (every JMAP mutation: send/delete/move mail, change settings), `PUT /settings/imap`, `PUT /settings/view`, `PUT /blobs/{sha256}`, etc. — are wrapped only in `requireAuth`, never in a CSRF middleware. The project HAS a CSRF middleware (`shared/middleware/csrf.go`, Origin/Referer same-origin check) and the AUTHSERVER applies it to all its state-changing routes (authserver/cmd/authserverd/main.go:413-461 wrap Login/Refresh/Logout/ChangePassword/etc. in `sharedmw.CSRF(...)`). The gateway mounts it on zero routes (grep for `sharedmw.CSRF`/`middleware.CSRF` in mailserver/cmd/mailserverd/main.go returns nothing). Because a browser sends the `access_token` cookie automatically, a cross-origin POST to `/jmap` would authenticate; the only remaining defense is the cookie's SameSite attribute, and `issueTokens` (authserver/internal/handlers/auth.go:993-1046, the login success path) returns tokens ONLY in the JSON body and sets NO cookie at all — so the SameSite value of the cookie the gateway actually trusts is not even locatable in the auth issuance code, making the CSRF posture unverifiable rather than defense-in-depth.
- **Evidence:** `mux.Handle("POST /jmap", requireAuth(http.HandlerFunc(jmapH.Request)))   // no sharedmw.CSRF
// chain.go: cookie, err := r.Cookie(accessTokenCookie); if err == nil && cookie.Value != "" { tokenStr = cookie.Value }`
- **Fix:** Wrap all non-GET gateway routes in `sharedmw.CSRF` exactly as authserver/cmd/authserverd/main.go does, OR drop cookie-based auth on the gateway and require the `Authorization: Bearer` header (a custom header cannot be set cross-origin without a preflight, which is itself CSRF-proof). At minimum, verify and pin the `access_token` cookie to `SameSite=Strict; HttpOnly; Secure` at the single point it is set, and add a test asserting it.
- **Verifier note:** Verified end to end. The gateway trusts the access_token HttpOnly cookie for auth (chain.go:251-256; ws/handler.go:122), and cookie auth is the LIVE production path: the SPA JMAP client and settings API call mutating routes with fetch(..., {credentials:'include'}) and NO Authorization/Bearer header anywhere in mailserver/webmail/src (client.ts:37-39, settings.ts) — so this is not a mere test-only 

### M23. Third-party GitHub Actions pinned to mutable tags/branches, not commit SHA — release pipeline handles signing secrets
- **Lens/source:** security/structure hunt → `supply-chain-ci`
- **Location:** `.github/workflows/release.yml:17, 95, 112, 135 (rust-toolchain@stable); 15/45/101/168 (actions/*@v4|v5)`
- **Issue:** Every third-party action is referenced by a floating, attacker-mutable ref instead of a pinned commit SHA. dtolnay/rust-toolchain@stable is the most dangerous: @stable is a moving branch ref on a third-party repo, and it runs inside the build-macos/build-windows/build-linux jobs that import the Apple Developer cert (APPLE_DEVELOPER_CERT), notarization password, and GPG_PRIVATE_KEY secrets. If that action's repo or tag is compromised/repointed, the malicious action executes in a job with full access to code-signing material and can exfiltrate it or inject a trojaned binary into the published release. actions/checkout, upload-artifact, download-artifact, setup-go are likewise @v4/@v5/@v6 floating tags. GitHub's own hardening guidance and the tj-actions/changed-files (2025) incident specifically warn against this.
- **Evidence:** `uses: dtolnay/rust-toolchain@stable
        with:
          toolchain: stable
          targets: aarch64-apple-darwin`
- **Fix:** Pin all third-party actions to a full 40-char commit SHA with a trailing version comment (e.g. dtolnay/rust-toolchain@<sha> # stable). Pin actions/* to SHAs too. Enable Dependabot github-actions updates (already configured) to bump the SHAs. Consider a permissions-restricted, allow-listed actions policy at the org level.
- **Verifier note:** Evidence is accurate: .github/workflows/release.yml pins dtolnay/rust-toolchain@stable (a mutable branch ref on a third-party repo) at lines 17, 56, 95, 112, 135, and actions/checkout@v5, upload-artifact@v4, download-artifact@v4 at floating tags. Crucially the exploitability claim holds: the build-macos-arm/x86 and build-linux jobs run @stable AND contain the secret-bearing 'Sign and Notarize' (AP

### M24. Release signing/notarization steps use continue-on-error: true — unsigned binaries get published silently
- **Lens/source:** security/structure hunt → `supply-chain-ci`
- **Location:** `.github/workflows/release.yml:24, 63, 142`
- **Issue:** All three signing jobs (macOS arm, macOS x86, Linux GPG) wrap signing in continue-on-error: true, and the macOS step additionally `exit 0`s when no cert is present. The downstream github-release job (needs: [...all build jobs...]) only depends on build success, not signing success, and unconditionally runs `gh release create ... artifacts/**/*.dmg artifacts/**/*.msi ...`. Therefore if signing fails for any reason — expired/rotated Apple cert, notarization timeout, missing GPG passphrase, a tampered keychain step — the workflow proceeds and publishes UNSIGNED artifacts to the public GitHub Release with no failure surfaced. Note Windows builds (build-windows-x64/arm64, lines 90-121) have NO signing step at all, so every .msi is always unsigned. Users on Windows have no Authenticode trust anchor.
- **Evidence:** `- name: Sign and Notarize
        continue-on-error: true
        env:
          APPLE_DEVELOPER_CERT: ${{ secrets.APPLE_DEVELOPER_CERT }}`
- **Fix:** Make signing failures fatal (remove continue-on-error) or gate the github-release job on an explicit 'signed' output. Generate and publish SHA-256 checksum files (and detached signatures) for every artifact, and fail the release if any expected signature/checksum is missing. Add Windows Authenticode signing (signtool) or document that .msi is intentionally unsigned.
- **Verifier note:** Verified every claim against .github/workflows/release.yml. continue-on-error: true wraps all three signing steps (lines 24, 63, 142) and macOS/GPG steps `exit 0` when no cert is present (lines 32, 71, 147). The github-release job's needs: list (line 165) only depends on the build jobs, which report success despite signing failures because of continue-on-error, and `gh release create` (lines 175-1

### M25. Dependabot does not cover the desktop Tauri crate root or the workspace lockfile
- **Lens/source:** security/structure hunt → `supply-chain-ci`
- **Location:** `.github/dependabot.yml:12-16`
- **Issue:** The cargo ecosystem entry covers only directory /clients/rust. But the actual desktop application — which pulls in tauri, tauri-plugin-updater, webkit bindings, objc2, windows-rs and their large transitive trees — lives at clients/desktop/src-tauri (has its own Cargo.toml + Cargo.lock), and there is a separate workspace at clients/ (clients/Cargo.toml + clients/Cargo.lock). Neither is listed, so the most security-sensitive Rust dependencies (the auto-updater, the webview, native FFI) receive NO automated vulnerability/version updates. This is exactly the code that runs with desktop privileges and performs auto-update.
- **Evidence:** `- package-ecosystem: "cargo"
    directory: "/clients/rust"`
- **Fix:** Add cargo entries for /clients (workspace) and /clients/desktop/src-tauri (or switch to the `directories:` list form like the gomod block already uses). Verify each listed directory actually contains a Cargo.lock so updates are produced.
- **Verifier note:** Confirmed via the actual files. `.github/dependabot.yml:12-13` has exactly one cargo entry: `directory: "/clients/rust"`. The only git-tracked cargo lockfiles are `clients/Cargo.lock` (workspace root whose `clients/Cargo.toml` explicitly `exclude = ["desktop/src-tauri"]`) and `clients/desktop/src-tauri/Cargo.lock` — neither directory is listed. The desktop crate (`clients/desktop/src-tauri/Cargo.t

### M26. GeoIP database auto-downloaded from internet at startup with no checksum or signature verification
- **Lens/source:** security/structure hunt → `supply-chain-ci`
- **Location:** `mailserver/internal/geoip/dbip.go:17, 76-86`
- **Issue:** On first startup the gateway downloads a .mmdb GeoIP database over HTTPS from a hard-coded external URL (download.db-ip.com) and writes it straight to disk with no integrity check — no published checksum, no signature, no certificate pinning. The downloaded mmdb is then parsed and used for security decisions (GEO_BLOCK_COUNTRIES country blocking and authserver geo policy). A compromise of the db-ip CDN, a DNS hijack, or any MITM that can present a valid cert for that host can feed a malicious/garbage database that silently disables geo-blocking (fail-open: EnsureGeoIPDB returns nil on every failure) or crashes the maxmind parser. There is also no provenance record of what was fetched.
- **Evidence:** `const dbipLiteURL = "https://download.db-ip.com/free/dbip-country-lite-%d-%02d.mmdb"
...
	if err == nil {
		return os.WriteFile(dbPath, data, 0644)
	}`
- **Fix:** Publish/verify a known-good SHA-256 (or GPG signature) for each monthly db-ip release and validate the download before writing. Alternatively ship the mmdb as a vendored release artifact. Log the fetched file's hash for provenance.
- **Verifier note:** Confirmed by reading the cited code and its full call chain. mailserver/internal/geoip/dbip.go:17 hard-codes `dbipLiteURL = "https://download.db-ip.com/free/dbip-country-lite-%d-%02d.mmdb"`; HTTPDownloader.Download (lines 36-53) only checks HTTP 200 and a 100MB cap, then EnsureGeoIPDB (lines 76-86) writes the bytes straight to disk via `os.WriteFile(dbPath, data, 0644)` with no SHA-256, signature,

### M27. Rules-engine regex (matches_regex) is a ReDoS vector with no effective timeout — runs in DB on every delivered message
- **Lens/source:** security/structure hunt → `dos-limits`
- **Location:** `mailserver/sql/reducers/rule_engine.sql:37`
- **Issue:** eval_condition implements the 'matches_regex' operator as `v_actual ~ lower(v_value)`, where v_value is a user-supplied regular expression taken verbatim from a per-user (or transport) rule's stored conditions JSON. PostgreSQL's regex engine is NOT RE2-based and is vulnerable to catastrophic backtracking. This condition is evaluated for EVERY incoming/outgoing message inside the delivery transaction (apply_rules → eval_condition), holding a pgxpool connection. A user who creates a rule with a pathological pattern (e.g. value `(a+)+$`) and then receives a message whose subject/body triggers backtracking will pin a CPU core and hold a DB pool connection indefinitely. The rule Create handler (internal/user/rules.go ~148-176) stores the raw conditions JSON with no regex validation (no regexp.Compile pre-check, no length cap). Combined with finding #2 (the intended statement_timeout guard is a no-op), nothing bounds execution.
- **Evidence:** `WHEN 'matches_regex' THEN v_actual ~ lower(v_value)`
- **Fix:** Validate user regexes at rule-creation time (compile with Go's regexp which is RE2/linear-time, reject on failure, cap pattern length), and/or set a REAL `statement_timeout` (not the app.* namespace — see finding #2) around apply_rules. Consider running matches_regex via a RE2-backed function rather than PostgreSQL's backtracking `~`.
- **Verifier note:** Confirmed the technical core: rule_engine.sql:37 runs PostgreSQL's backtracking regex (`v_actual ~ lower(v_value)`) on user-controlled fields incl. `body` (line 16), with v_value taken verbatim from stored rule JSON; PG regex is not RE2. The claimed timeout no-op is real: rule_engine_or.sql:71 sets `app.statement_timeout` (a custom GUC namespace with zero cancellation effect), and grep confirms no

### M28. Intended regex/ReDoS statement-timeout guard is a no-op: sets custom GUC `app.statement_timeout` instead of real `statement_timeout`
- **Lens/source:** security/structure hunt → `dos-limits`
- **Location:** `mailserver/sql/reducers/rule_engine_or.sql:71`
- **Issue:** apply_rules and the DLP path both attempt to bound runaway/regex execution via `PERFORM set_config('app.statement_timeout', '1000ms', true)` (rule_engine_or.sql:71) and `set_config('app.statement_timeout', '500ms', true)` (send.sql:171, with the explicit comment 'Set statement timeout to prevent catastrophic regex backtracking'). `app.statement_timeout` is a custom GUC in the user-defined `app.` namespace — PostgreSQL does NOT use it to cancel long-running queries. The real parameter is `statement_timeout` (no namespace), used correctly elsewhere in this same codebase (internal/user/rules.go:303 `SET LOCAL statement_timeout = '5s'` and sql/schema/047_dlp_consolidate.sql:48 `SET LOCAL statement_timeout = '5s'`). Grep confirms `app.statement_timeout` is never read back via current_setting() and applied. Result: the rules engine and DLP regex evaluation have zero execution-time bound, defeating the author's stated ReDoS mitigation.
- **Evidence:** `PERFORM set_config('app.statement_timeout', '1000ms', true);`
- **Fix:** Replace with the real parameter, e.g. `PERFORM set_config('statement_timeout', '1000ms', true)` or `SET LOCAL statement_timeout = '1s'` inside the function, matching the correct usage in rules.go:303 and 047_dlp_consolidate.sql:48. Apply the same fix to send.sql:171.
- **Verifier note:** Confirmed via direct reads: rule_engine_or.sql:71 `PERFORM set_config('app.statement_timeout', '1000ms', true);` and send.sql:171 `PERFORM set_config('app.statement_timeout', '500ms', true);` (with comment "Set statement timeout to prevent catastrophic regex backtracking"). `app.statement_timeout` is a custom namespaced GUC — PostgreSQL accepts the write but never uses it to cancel queries; only t

### M29. HybridRateLimiter in-memory `local`/`dirtyKeys` maps grow unbounded — no eviction of per-IP keys
- **Lens/source:** security/structure hunt → `dos-limits`
- **Location:** `mailserver/internal/middleware/ratelimit.go:193-227`
- **Issue:** HybridRateLimiter is the limiter actually wired into production (main.go:521 authRateLimiter, :523 adminRateLimiter). Allow() inserts a windowCounter into rl.local for every unique key (client IP) and marks rl.dirtyKeys[key]=true. The only place keys are removed is sync(), which resets rl.dirtyKeys but NEVER deletes from rl.local — it only reads it. There is no Cleanup/prune/evict for rl.local across the whole type. Over time, every distinct source IP that ever hits /auth/* or admin endpoints leaves a permanent entry in rl.local; an attacker rotating source IPs (or IPv6 /64 churn) grows the map without bound until OOM. Note the simpler in-memory RateLimiter has a Cleanup() method (line 136) but it is never called in production either (only in middleware_test.go), and that type isn't the one used here.
- **Evidence:** `wc = &windowCounter{startTime: windowStart}
		rl.local[key] = wc
		rl.dirtyKeys[key] = true   // ... rl.local is never deleted from anywhere`
- **Fix:** In sync() (or a periodic goroutine), delete keys from rl.local whose windowStart is older than the current window (mirror loadFromDB's `window_start >= now-2*window` cutoff). Cap total map size and evict oldest entries when exceeded.
- **Verifier note:** Verified in ratelimit.go: HybridRateLimiter.Allow inserts a windowCounter into rl.local for every new key (lines 196-198, matching the quoted evidence) where the key is the client IP (RateLimit middleware lines 298-299 call rl.Allow(clientIP(r))). I traced every rl.local reference (lines 194, 197, 230, 280-281) — all are read/insert/overwrite; there is NO delete(rl.local, ...) anywhere. sync() onl

### M30. JMAP Email/get and Mailbox/get do not cap the number of requested ids (maxObjectsInGet:256 advertised but unenforced)
- **Lens/source:** security/structure hunt → `dos-limits`
- **Location:** `mailserver/internal/jmap/handler.go:749-783`
- **Issue:** emailGet parses req.Ids ([]string), converts every entry to int64, and passes the entire slice to jmap_email_get($1,$2,$3) with no count limit, despite the Session object advertising maxObjectsInGet:256 (handler.go:483). The request body is capped at 10 MB (handler.go:384) and a single method call at 2 MB (handler.go:415), but a 2 MB args blob holds on the order of 100k+ numeric ids. The reducer jmap_email.sql jmap_email_get does `m.id = ANY(p_ids)` with no cardinality check, so it materializes the full result set for every id in one query, holding a pool connection. The blob handler enforces this correctly (`if len(req.Ids) > 256` at internal/jmap/blob.go:35 and :118), proving the intended cap — but mailboxGet (handler.go:653) and emailGet omit it. emailQuery (handler.go:798) and contactCardQuery (handler.go:1158) DO cap limit at 256, so the gap is specifically in the /get id-list paths.
- **Evidence:** `var ids []int64
	for _, id := range req.Ids { if v, err := strconv.ParseInt(id, 10, 64); err == nil { ids = append(ids, v) } }
	... SELECT jmap_email_get($1, $2, $3) ... accountID, ids, req.Properties`
- **Fix:** Enforce `if len(req.Ids) > 256 { return tooLarge }` in emailGet/mailboxGet (and other *Get handlers) mirroring blob.go:35, returning the JMAP requestTooLarge error before hitting the DB.
- **Verifier note:** Verified every claim against source. emailGet (handler.go:764-775) builds `ids []int64` by ParseInt over `req.Ids` with no count check and passes the full slice to `jmap_email_get($1,$2,$3)`; mailboxGet (handler.go:668-684) is identical. The session advertises `"maxObjectsInGet": 256` (handler.go:483) but no handler enforces it — grep confirms `len(req.Ids) > 256` exists ONLY in blob.go:35 and :11

### M31. SMTP inbound has no cap on RCPT TO count per transaction — one connection drives unbounded recipient-validation DB queries
- **Lens/source:** security/structure hunt → `dos-limits`
- **Location:** `mailserver/internal/smtp/inbound.go:436-486`
- **Issue:** handleRcpt does `c.to = append(c.to, addr)` with no limit on how many RCPT TO commands a single connection may issue. Each RCPT triggers at least one recipient-existence query (lines 456-464, a 3-way UNION/LIKE over aliases/mailboxes/domains) plus a greylist_check() query (lines 474-477) when greylisting is enabled. There is no per-message recipient cap (RFC 5321 §4.5.3.1.8 requires supporting >=100 but explicitly permits a server limit). A single inbound connection can therefore issue effectively unlimited RCPT commands, each costing multiple DB round-trips, while the c.to slice grows without bound. The per-IP connection rate limit (20/min, inbound.go:215) and maxConns=100 (inbound.go:58/81) bound connection count but NOT per-connection RCPT count, so the amplification is uncapped per accepted connection.
- **Evidence:** `c.to = append(c.to, addr)
	c.reply(250, "OK")  // no len(c.to) limit anywhere`
- **Fix:** Add a recipient cap (e.g. 100-1000) in handleRcpt: if len(c.to) >= max, reply `452 Too many recipients` (RFC 5321) and stop accepting further RCPT for this transaction.
- **Verifier note:** Confirmed by reading inbound.go. The command loop (lines 276-347) reads commands unbounded; RCPT dispatches to handleRcpt (332-333). In handleRcpt each RCPT runs the recipient-existence query (456-464, a 3-way UNION over aliases/mailboxes/domains) plus, when greylisting is on, a greylist_check() query (474-477), then `c.to = append(c.to, addr)` at line 484 with no length check and `c.reply(250, "O

## LOW (49)

### L1. Half-rename: output binary names still 'gateway'/'authserver'; new .gitignore patterns match nothing the scripts produce
- **Lens/source:** change-set review → `rename-binaries`
- **Location:** `scripts/dev.sh (also scripts/cross-build.sh:40,43, scripts/xinchuang-smoke-test.sh:9, .gitignore:25-26, .github/workflows/xinchuang-ci.yml:50):11`
- **Issue:** The 'daemon convention' was applied only to source directories and docs. Every script still emits the old artifact names: dev.sh `-o gateway`, cross-build.sh `-o "$OUTDIR/gateway"`, xinchuang-smoke-test.sh defaults to `$BIN_DIR/gateway`, and the CI workflow names artifacts inconsistently within one job (`authserver-${{ matrix.arch }}` old-style vs `mailserverd-${{ matrix.arch }}` new-style). Meanwhile a208464 added `**/authserverd` and `**/mailserverd` to .gitignore — patterns that only manual builds following CLAUDE.md will ever create. The result is two naming schemes coexisting depending on which entry point you use.
- **Evidence:** `dev.sh:11 `go build -o gateway ./cmd/mailserverd`; xinchuang-ci.yml:50 `go build -o ../build/authserver-${{ matrix.arch }} ./cmd/authserverd`; .gitignore adds `**/authserverd` and `**/mailserverd``
- **Fix:** Pick one artifact name per service (mailserverd/authserverd per the ADR) and apply it across dev.sh, cross-build.sh, smoke test defaults, CI artifact names, and the run/ExecStart paths in dev.sh lines 56/64.
- **Verifier note:** Every cited evidence point is confirmed in the code. dev.sh:11 is `go build -o gateway ./cmd/mailserverd` (old output name, new input path); dev.sh:8 and build.sh:5 emit `-o authserver`; cross-build.sh:34/40 emit `-o "$OUTDIR/authserver"`/`-o "$OUTDIR/gateway"`; xinchuang-smoke-test.sh:9 defaults `GATEWAY=${GATEWAY:-$BIN_DIR/gateway}`; xinchuang-ci.yml:50 names the artifact `authserver-${matrix.ar

### L2. CLAUDE.md Key Files table still lists old entry-point paths despite docs commit 0d24db0
- **Lens/source:** change-set review → `rename-binaries`
- **Location:** `CLAUDE.md:317, 321`
- **Issue:** Commit 0d24db0 ('Binary paths: gateway→mailserverd, authserver→authserverd') updated the layout tree and build commands but missed the Key Files table, which still points at the deleted paths. Since CLAUDE.md drives agent/code-assistant behavior in this repo, stale entry-point paths actively mislead.
- **Evidence:** `CLAUDE.md:317 `| \`mailserver/cmd/gateway/main.go\` | Entry point — startup order and route registration |`; CLAUDE.md:321 `| \`authserver/cmd/authserver/main.go\` | Auth server entry point ... |``
- **Fix:** Update both rows to mailserver/cmd/mailserverd/main.go and authserver/cmd/authserverd/main.go. Also sweep docs/guides/ (UPGRADE.md) which is a live runbook, unlike the acceptable stale references in docs/plans/archive/.
- **Verifier note:** Verified directly: CLAUDE.md:317 reads `| \`mailserver/cmd/gateway/main.go\` | Entry point — startup order and route registration |` and CLAUDE.md:321 reads `| \`authserver/cmd/authserver/main.go\` | Auth server entry point ... |`, but `ls mailserver/cmd/gateway/` and `ls authserver/cmd/authserver/` both return "No such file or directory" — the real entry points are `mailserver/cmd/mailserverd/mai

### L3. Plan archived as 'Complete' while Task 1 Steps 3/4/6 are demonstrably unfinished; commit message overclaims
- **Lens/source:** change-set review → `rename-binaries`
- **Location:** `docs/plans/archive/2026-06-10-repo-structure-naming.md:3, 36-39`
- **Issue:** Commit 1b6eff0 archived the plan with 'Status: ✅ Complete — All 5 tasks implemented', and 98a3d1c's message says 'Updated: build.sh, dev.sh, cross-build.sh' and 'Both binaries compile clean. All Go tests pass.' In reality build.sh/dev.sh/cross-build.sh are broken (see above), systemd units (Step 4) were never touched, and guide docs (Step 6, docs/guides/UPGRADE.md) were never updated. The binaries do compile via direct `go build ./cmd/...`, but not via the scripts the commit claims to have fixed — verification was done against the wrong target.
- **Evidence:** `Plan header: '> **Status: ✅ Complete — 2026-06-10**' with unchecked '- [ ] **Step 4: Update systemd units** — `deploy/mailserver.service`, `deploy/authserver.service`'`
- **Fix:** Reopen the plan (or file a follow-up) covering: authserver paths in 3 scripts, mailserver/gateway dead cds in 5 scripts, systemd/install/upgrade/UPGRADE.md rename, artifact-name unification, and CLAUDE.md Key Files. Verify by actually running scripts/build.sh, dev.sh, lint.sh, test.sh, e2e.sh before re-archiving.
- **Verifier note:** Every claim is confirmed by code/runtime evidence. The plan header (docs/plans/archive/2026-06-10-repo-structure-naming.md:3-4) declares "Status: Complete — All 5 tasks implemented" while Task 1 Step 4 (systemd units, line 38) and Step 6 (guide docs, line 40) checkboxes remain unchecked. Commit 98a3d1c's message claims "Updated: build.sh, dev.sh, cross-build.sh" and "Both binaries compile clean. A

### L4. Four admin route dirs left ungrouped (audit, content-search, ediscovery, mam) — restructure incomplete vs stated goal
- **Lens/source:** change-set review → `admin-routes`
- **Location:** `mailserver/webmail/src/routes/admin:audit/, content-search/, ediscovery/, mam/`
- **Issue:** The commit message says admin routes were reorganized into domain groups, but `audit/`, `content-search/`, `ediscovery/`, and `mam/` (devices, devices/[id], policies) remain at the admin root with no group and no recorded rationale. URLs and access control are unaffected (they still inherit admin/+layout.svelte), so this is purely a completeness/consistency gap — these compliance/MDM pages arguably belong in a future (compliance) or (system) group, and leaving them mixed with group dirs blurs the new convention for where future pages go.
- **Evidence:** `ls src/routes/admin → (identity)/ (mail)/ (system)/ audit/ content-search/ ediscovery/ mam/`
- **Fix:** Either move these four routes into an appropriate group (e.g. a new (compliance) group, matching the commit's stated pattern for future domains) or document in the commit/plan that they are intentionally deferred.
- **Verifier note:** Verified factually. `ls mailserver/webmail/src/routes/admin/` shows `(identity)/ (mail)/ (system)/ audit/ content-search/ ediscovery/ mam/` — the four named dirs sit ungrouped at admin root alongside the three group dirs. `git ls-tree 306c1e8~1` confirms all four existed before the reorg commit 306c1e8, whose --stat shows it moved exactly 30 other route files into groups and touched none of the fo

### L5. Sidebar nav remains a flat role-ordered list, not aligned with the new domain groups; several grouped routes have no inbound nav link
- **Lens/source:** change-set review → `admin-routes`
- **Location:** `mailserver/webmail/src/routes/admin/+layout.svelte:39-68`
- **Issue:** All 28 sidebar entries point to routes that still exist at unchanged URLs (verified each path against the new tree), so nothing is broken. However the nav is ordered by role rank, not by the new (mail)/(identity)/(system) domains, and the grouped routes /admin/conditional-access, /admin/migration, /admin/smtp-pipeline, /admin/spam, /admin/tls, and /admin/updates have no `<a href>` or goto() anywhere in webmail src (only API fetch strings) — they are reachable only by typing the URL. Both conditions predate this commit; the restructure neither caused nor addressed them.
- **Evidence:** `const allNavItems = [
  { label: 'admin.sidebar.dashboard', path: '/admin', ... },
  { label: 'admin.sidebar.system', path: '/admin/system', ... },
  ... ] // flat list; no entries for conditional-access, migration, smtp-pipeline, spam, tls, updates`
- **Fix:** As a follow-up, group the sidebar items under Mail / Identity / System section headers to match the route groups, and add nav entries (or links from parent pages) for conditional-access, migration, smtp-pipeline, spam, tls, and updates.
- **Verifier note:** Verified all claims in mailserver/webmail/src/routes/admin/+layout.svelte. allNavItems (lines 39-68) is a flat array of 28 entries rendered via {#each navItems} (lines 128-135) with no section headers; ordering follows roleRank clusters (super_admin/user_admin/read_only/auditor blocks) not the (mail)/(identity)/(system) groups, so e.g. user_admin items like /admin/users and /admin/identity are int

### L6. Misattached godoc: AuthenticateRequest's doc block now documents Authenticate, leaving AuthenticateRequest undocumented
- **Lens/source:** change-set review → `authenticator-iface`
- **Location:** `mailserver/internal/auth/chain.go:150-166`
- **Issue:** The new Authenticate method was inserted between AuthenticateRequest's 10-line doc comment and the function it documents. Go attaches the entire contiguous comment block (which begins 'AuthenticateRequest resolves the authenticated user...') to func (c *Chain) Authenticate, while AuthenticateRequest at line 166 now has no doc comment at all. The behavioral notes about priority order and multi-credential fallback are important security documentation and are now attached to the wrong symbol. revive is not enabled in .golangci.yml so lint won't catch this, but godoc output is wrong.
- **Evidence:** `// multiple credential types simultaneously.
// Authenticate implements shared/auth.Authenticator. It wraps AuthenticateRequest
// so the shared middleware can depend on the interface, not the concrete chain.
func (c *Chain) Authenticate(ctx context.Context, r *http.Request) (*Claims, error) {
	return c.AuthenticateRequest(r)
}

func (c *Chain) AuthenticateRequest(r *http.Request) (*Claims, error) {`
- **Fix:** Add a blank line and move the original 'AuthenticateRequest resolves...' comment block back above func AuthenticateRequest; keep only the two new 'Authenticate implements shared/auth.Authenticator...' lines on Authenticate.
- **Verifier note:** Confirmed by reading mailserver/internal/auth/chain.go:150-166. The doc block beginning `// AuthenticateRequest resolves the authenticated user...` (lines 150-159, including the security notes about priority order and multi-credential fallback) is fully contiguous (no blank line at 159→160) with two new lines `// Authenticate implements shared/auth.Authenticator...` (160-161), a

### L7. Authenticate ignores its ctx parameter — interface context contract is ambiguous
- **Lens/source:** change-set review → `authenticator-iface`
- **Location:** `mailserver/internal/auth/chain.go:162-164`
- **Issue:** The interface signature is Authenticate(ctx context.Context, r *http.Request), but the sole implementation discards ctx and delegates to AuthenticateRequest(r), which uses r.Context() internally (chain.go:182 c.resolvePermissions(r.Context(), claims) and the Kerberos method's DB lookups). Today the only caller passes r.Context() (middleware/auth.go:22), so behavior is identical, but the contract is ambiguous: a future caller passing a derived context (timeout, values) would be silently ignored, and a future implementation honoring ctx would behave differently from Chain. Since *http.Request already carries a context, the ctx parameter is arguably redundant.
- **Evidence:** `func (c *Chain) Authenticate(ctx context.Context, r *http.Request) (*Claims, error) {
	return c.AuthenticateRequest(r)
}`
- **Fix:** Either have the wrapper honor ctx (return c.AuthenticateRequest(r.WithContext(ctx)) or thread ctx through AuthenticateRequest), or drop ctx from the interface and document that r.Context() governs cancellation. At minimum rename the parameter to _ and document the contract in shared/auth/authenticator.go.
- **Verifier note:** Confirmed all cited facts. The interface (shared/auth/authenticator.go:19) declares Authenticate(ctx context.Context, r *http.Request); the sole implementation (chain.go:162-164) is `func (c *Chain) Authenticate(ctx context.Context, r *http.Request) (*Claims, error) { return c.AuthenticateRequest(r) }`, discarding ctx and delegating to AuthenticateRequest, which uses r.Context() internally (chain.

### L8. No tests exercise the new interface seam — RequireAuth/RequireAdmin/RequireRole remain untested
- **Lens/source:** change-set review → `authenticator-iface`
- **Location:** `mailserver/internal/middleware/middleware_test.go:1`
- **Issue:** The main practical payoff of an Authenticator interface is that middleware becomes unit-testable with a fake authenticator, yet the commit adds no tests. grep over mailserver *_test.go shows zero references to RequireAuth/RequireAdmin/RequireRole; middleware_test.go covers only rate limiting, ClientIP, security headers, and metrics auth, and perm_test.go covers RequirePerm only. The 401 WWW-Authenticate challenge, the non-TypeAccess 403 path, and the role-set logic are all uncovered. Plan Task 4 Step 5 said to run middleware tests, but there were none to run for these functions.
- **Evidence:** `grep -rn "RequireAuth\|RequireAdmin\|RequireRole" mailserver --include="*_test.go" → (no matches)`
- **Fix:** Add table-driven tests using a stub Authenticator (func type or small struct) covering: auth failure → 401 + WWW-Authenticate header; claims.Type != TypeAccess → 403; success → claims in context; RequireRole accept/reject by AdminRole and IsAdmin=false.
- **Verifier note:** Verified by direct reading. `grep -rn "RequireAuth|RequireAdmin|RequireRole" --include="*_test.go" .` returns no matches across the whole repo (exit 1). middleware_test.go (lines 11-256) only tests RateLimiter, clientIP, SecurityHeaders/HSTS, and MetricsAuth; perm_test.go (lines 30-194) only tests RequirePerm, DomainScopeFromContext, and HasPermission. The uncovered paths are real: 401 + `WWW-Auth

### L9. Referenced ADR ('ADR Task 4' / ADR-NNNN) does not exist in docs/adr/
- **Lens/source:** change-set review → `authenticator-iface`
- **Location:** `docs/plans/archive/2026-06-10-repo-structure-naming.md:4, 15`
- **Issue:** The commit subject cites 'ADR Task 4' and the plan says 'Implement the 5 moves from ADR-NNNN' and 'ADR accepted', but docs/adr/ contains only ARCH-002-shared-db-architecture.md and DES-005-smtp-outbound-auth.md. No decision record for the repo-structure/naming decision (including the Authenticator extraction rationale and the choice of where the middleware lives) was ever numbered or committed, so the implementation cannot be checked against the accepted decision — the placeholder 'NNNN' was never resolved.
- **Evidence:** `**Goal:** Implement the 5 moves from ADR-NNNN. ... > All 5 tasks implemented and pushed. ADR accepted.`
- **Fix:** Write the ADR into docs/adr/ with a real number (e.g. ARCH-003-repo-structure-naming.md) capturing the five decisions and the Authenticator seam, and replace 'ADR-NNNN' in the archived plan with the real identifier.
- **Verifier note:** Every cited fact checks out against the actual files and git history. The plan file docs/plans/archive/2026-06-10-repo-structure-naming.md line 4 reads "All 5 tasks implemented and pushed. ADR accepted." and line 15 reads "Goal: Implement the 5 moves from ADR-NNNN." with the placeholder "NNNN" unresolved. `ls docs/adr/` shows only ARCH-002-shared-db-architecture.md and DES-005-s

### L10. Unrelated drive-by: mailserverd added to authserver/.gitignore
- **Lens/source:** change-set review → `authenticator-iface`
- **Location:** `authserver/.gitignore:3-4`
- **Issue:** The commit adds both 'authserverd' and 'mailserverd' to authserver/.gitignore. Ignoring authserverd is correct fallout from the Task 1 binary rename, but mailserverd is the mailserver module's binary and would not be produced inside authserver/. This is unrelated to the Authenticator extraction (belongs with Task 1/5 cleanup commits 98a3d1c/a208464) and slightly muddies the commit's scope. The pre-existing first line 'authserver/.gitignore' is also junk content, though untouched by this commit.
- **Evidence:** `authserver/.gitignore
/authserver
authserverd
mailserverd`
- **Fix:** Remove the 'mailserverd' entry from authserver/.gitignore (or move binary ignores to the repo-root .gitignore as commit a208464 did) and clean up the stray 'authserver/.gitignore' first line.
- **Verifier note:** Confirmed by reading authserver/.gitignore (4 lines: "authserver/.gitignore", "/authserver", "authserverd", "mailserverd") and the git diff of commit 38a6c74 "feat(auth): extract Authenticator interface (ADR Task 4)", which added both "+authserverd" and "+mailserverd" in the same commit whose body describes only the Authenticator interface extraction (~50 lines, shared/auth/authenticator.go) with 

### L11. Local lint config is heavily neutered, undermining the 'lint is enforced locally' justification for removing CI lint
- **Lens/source:** change-set review → `ci-hardening`
- **Location:** `mailserver/.golangci.yml:157-170`
- **Issue:** The 'Broad exclusions' block disables funlen, goconst, gocritic, gocyclo, ineffassign, and staticcheck entirely via text: ".*" rules — staticcheck (the highest-signal linter enabled) reports nothing. errcheck is not in the enabled list at all, yet gosec G104 (unchecked errors) is excluded with the comment 'covered by errcheck linter', so unchecked errors are caught by nothing. The unchecked Scan in the new migration guard (mailserverd/main.go:176, admin_system.go MigrationStatus) is exactly the class of bug this leaves undetected. Combined with the CI lint removal (7b9bc1a), lint enforcement is effectively dupl+govet+unused+partial-gosec on one of four Go modules, locally, on the honor system.
- **Evidence:** `- linters: [staticcheck]
        text: ".*"
...
        - G104  # audit: allow unchecked errors (covered by errcheck linter)`
- **Fix:** Re-enable staticcheck and errcheck (use targeted path/text exclusions for genuine false positives rather than text: ".*"), or remove the misleading G104 comment and enable G104. Burn down the excluded findings incrementally instead of blanket-suppressing whole linters.
- **Verifier note:** All core claims verified against mailserver/.golangci.yml. Lines 159-170 contain unrestricted `text: ".*"` exclusion rules (no `path:`) for funlen, goconst, gocritic, gocyclo, ineffassign, and staticcheck — staticcheck (lines 169-170) is thus fully suppressed. The `enable:` block (lines 10-21) does NOT include errcheck, yet gosec G104 is excluded at line 25 with the comment "cov

### L12. Migration guard and MigrationStatus ignore Scan errors; the 'Outdated' unit test is vacuous
- **Lens/source:** change-set review → `ci-hardening`
- **Location:** `mailserver/internal/admin/admin_system_test.go:36-57 (also mailserver/cmd/mailserverd/main.go:176, internal/admin/admin_system.go:100-103)`
- **Issue:** Both the startup guard and the admin endpoint call pool.QueryRow(...).Scan(&v) without checking the error. The startup path fails closed by accident (v stays 0 < 65 → exit), but a transient DB error at boot produces the misleading message 'schema migrations not applied — run V000 bootstrap migration first'. TestSystemHandler_MigrationStatus_Outdated cannot fail: with a nil pool, current=0 < expected=65, so its only assertion ('if resp.Current >= resp.Expected && !resp.UpToDate') is never reached — the outdated path is asserted by a condition that is false by construction.
- **Evidence:** `// If current >= expected, up_to_date must be true.
if resp.Current >= resp.Expected && !resp.UpToDate {
	t.Errorf("up_to_date should be true when current (%d) >= expected (%d)", ...)`
- **Fix:** Check the Scan error and distinguish 'table missing/DB error' from 'version too low' in the log message. Rewrite the Outdated test to inject a known current value (e.g. via an interface or pgxmock) and assert up_to_date == false directly.
- **Verifier note:** Verified all three cited locations. main.go:176 `pool.QueryRow(ctx, ...).Scan(&actualVersion)` and admin_system.go:102-104 `h.pool.QueryRow(...).Scan(&current)` both discard the Scan error. At main.go:175-181 a transient DB error leaves actualVersion=0, so 0<65 triggers the misleading log "schema migrations not applied — run V000 bootstrap migration first" then os.Exit(1). The Outdated test (admin

### L13. cross-compile-check job cannot fail: go build piped through tail without pipefail
- **Lens/source:** change-set review → `ci-hardening`
- **Location:** `.github/workflows/xinchuang-ci.yml:127-135`
- **Issue:** Pre-existing (db77acc) but load-bearing for the post-hardening end state, since unit tests + this job are most of what CI still gates. Each build runs 'go build ./... 2>&1 | tail -5'. GitHub Actions' default run shell is 'bash -e {0}' (pipefail is only added when shell: bash is explicitly declared), so the pipeline's exit status is tail's (always 0) and a failed cross-compile never fails the step. The compliance-check job then reports 'READY FOR CERTIFICATION SUBMISSION' based on a gate that cannot trip. Note also that mailctl/ is excluded from the workflow's path filters and has no test/build step anywhere in CI.
- **Evidence:** `cd authserver && GOOS=linux GOARCH=${{ matrix.arch }} CGO_ENABLED=0 go build ./... 2>&1 | tail -5`
- **Fix:** Add 'shell: bash' (which enables -o pipefail) or drop the '| tail -5' pipes so go build's exit code propagates. Add mailctl/** to the path filters and a 'cd mailctl && go test ./...' step.
- **Verifier note:** Confirmed verbatim at .github/workflows/xinchuang-ci.yml:130,132,134 — each cross-compile step runs `go build ./... 2>&1 | tail -5`. grep found no `shell: bash`, no `defaults`, and no `pipefail` anywhere in the workflow, so steps run under GitHub Actions' default `bash -e {0}` (pipefail is only added when `shell: bash` is explicitly set), meaning the pipeline exit status is tail's (0) and a failed

### L14. V066 CREATE EXTENSION pg_stat_statements requires superuser and fails the migration chain non-gracefully
- **Lens/source:** change-set review → `observability`
- **Location:** `mailserver/sql/migrations/V066__pg_stat_statements.sql:6`
- **Issue:** pg_stat_statements is not a 'trusted' extension, so CREATE EXTENSION requires superuser. The repo's documented migration flow runs as the regular app role (CLAUDE.md: 'psql -h 127.0.0.1 -U mail -d mailserver -f V001__initial_schema.sql'; admin_upgrade.go:204 plan string: 'systemctl stop → psql -f migrations → systemctl start'). When run as `mail`, V066 fails with 'permission denied to create extension' and aborts the upgrade mid-chain. There is no DO-block exception handler to degrade gracefully when the extension or privilege is unavailable, and IF NOT EXISTS only helps if it was already created.
- **Evidence:** `CREATE EXTENSION IF NOT EXISTS pg_stat_statements;`
- **Fix:** Wrap in DO $$ BEGIN CREATE EXTENSION IF NOT EXISTS pg_stat_statements; EXCEPTION WHEN insufficient_privilege OR undefined_file THEN RAISE NOTICE 'pg_stat_statements unavailable — skipping (requires superuser + shared_preload_libraries)'; END $$; or move extension creation to the superuser-run install/provisioning step instead of the app-role migration chain.
- **Verifier note:** V066__pg_stat_statements.sql:6 is a bare `CREATE EXTENSION IF NOT EXISTS pg_stat_statements;` with no exception handler, and pg_stat_statements is genuinely an untrusted extension requiring superuser + shared_preload_libraries — so on a hardened deployment where the `mail` role lacks superuser, this statement fails with "permission denied to create extension". The V001 precedent (`CREATE EXTENSION

### L15. LogSlowRequests middleware is dead code — never wired into gateway or authserver
- **Lens/source:** change-set review → `observability`
- **Location:** `shared/middleware/slow_request.go:12`
- **Issue:** The commit message advertises 'slow-request middleware (>500ms warning)' and the plan (docs/plans/archive/2026-06-10-production-hardening.md, Task 5 Step 4) requires wiring it 'into gateway middleware chain (as outermost layer, after metrics)'. Grep across the repo at HEAD finds no caller: mailserver/cmd/mailserverd/main.go wraps handlers only with sharedmw.RequestID + metricsWrap (lines 1211/1239/1255) and authserver/cmd/authserverd/main.go:508 uses only sharedmw.RequestID. No 500ms threshold exists anywhere. The feature has zero production effect; only the unit tests exercise it.
- **Evidence:** `func LogSlowRequests(logger *slog.Logger, threshold time.Duration) func(http.Handler) http.Handler {  // only references: slow_request.go definition + slow_request_test.go`
- **Fix:** Wire LogSlowRequests(logger, 500*time.Millisecond) into both servers' middleware chains (inside RequestID so GetRequestID resolves), e.g. sharedmw.RequestID(sharedmw.LogSlowRequests(...)(metricsWrap(secureMux))).
- **Verifier note:** Verified the finding directly against code. LogSlowRequests is defined at shared/middleware/slow_request.go:12 and grep across all *.go files shows references ONLY in slow_request.go (definition) and slow_request_test.go (tests) — no production caller. mailserverd/main.go middleware chains (lines 1211, 1215, 1239, 1255) wrap handlers with only sharedmw.RequestID(metricsWrap(...)) plus HSTS, never 

### L16. Client-supplied X-Request-ID trusted verbatim — spoofable trace poisoning, unbounded length, now propagated cross-service
- **Lens/source:** change-set review → `observability`
- **Location:** `shared/middleware/requestid.go:23-27`
- **Issue:** The internet-facing gateway reuses any incoming X-Request-ID without length or format validation, reflects it in the response header, stamps it on every slog line via logger.With, and (new in this commit, mailserver/internal/authproxy/proxy.go:38-40) forwards it to the authserver, whose own RequestID middleware also reuses it. An attacker can inject arbitrary printable strings up to the header-size limit (~1MB default), collide with or replay other requests' IDs to poison correlation, and bloat every log line. Mitigating factors: Go's net/http rejects inbound header values containing CR/LF/control bytes, and slog Text/JSON handlers quote/escape values, so literal CRLF log injection is blocked — the residual risk is trace poisoning and log-volume abuse, not line splitting.
- **Evidence:** `id := r.Header.Get("X-Request-ID")
	if id == "" {
		id = newUUID()
	}
	w.Header().Set("X-Request-ID", id)`
- **Fix:** Validate the inbound header (e.g. accept only 36-char UUID-shaped values, else regenerate), or only trust X-Request-ID from internal hops (authproxy → authserver) and always generate fresh IDs at the public edge.
- **Verifier note:** requestid.go:23-27 reads exactly as quoted: `id := r.Header.Get("X-Request-ID")` with only an empty-check, then reflected verbatim into the response header (line 27) and stamped on every log line via `slog.Default().With("request_id", id)` (line 29) — no length or format validation anywhere (grep over shared/, mailserver/internal/, authserver/internal/ found zero validators). The cross-service for

### L17. V066 does not record itself in schema_migrations and expectedVersion guards were not bumped to 66
- **Lens/source:** change-set review → `observability`
- **Location:** `mailserver/sql/migrations/V066__pg_stat_statements.sql:1-6`
- **Issue:** V000__bootstrap_migrations.sql states 'All subsequent Vxxx migrations should INSERT their version into this table at the end', but V066 contains no INSERT INTO schema_migrations. Correspondingly, the startup guard in mailserver/cmd/mailserverd/main.go:174 ('const expectedVersion = 65') and the admin endpoint in mailserver/internal/admin/admin_system.go:98 ('const expectedVersion = 65 // bump when adding new migrations') were not updated. The migration guard and /admin/system badge are therefore blind to whether V066 was applied — the system reports up_to_date either way.
- **Evidence:** `V000: "All subsequent Vxxx migrations should INSERT their version into this table at the end." / main.go:174: const expectedVersion = 65 / V066 has no INSERT INTO schema_migrations`
- **Fix:** Append INSERT INTO schema_migrations (version) VALUES (66) ON CONFLICT DO NOTHING; to V066 and bump both expectedVersion constants to 66 (after fixing the superuser issue so the version check cannot demand a migration that fails for the app role).
- **Verifier note:** Verified all three citations: V066__pg_stat_statements.sql:1-6 contains only `CREATE EXTENSION IF NOT EXISTS pg_stat_statements;` with no INSERT; main.go:174 has `const expectedVersion = 65`; admin_system.go:98 has `const expectedVersion = 65 // bump when adding new migrations`. The only writer to schema_migrations in the whole repo is V000's hardcoded `INSERT ... VALUES (65)` (grep across .go/.sh

### L18. Migration comment claims an admin slow-queries page that does not exist
- **Lens/source:** change-set review → `observability`
- **Location:** `mailserver/sql/migrations/V066__pg_stat_statements.sql:4`
- **Issue:** The header comment asserts 'Admin /admin/system page shows top 10 slow queries', but no Go or Svelte code references pg_stat_statements anywhere in the repo (the planned GET /admin/system/slow-queries endpoint and the Svelte card, Task 6 Steps 3-4, were never implemented). The extension currently has zero consumers, and the 'Zero overhead (<1% CPU)' claim is marketing-grade rather than accurate (overhead is low but nonzero, plus fixed shared memory).
- **Evidence:** `-- Zero overhead (<1% CPU). Admin /admin/system page shows top 10 slow queries.`
- **Fix:** Either implement the planned /admin/system/slow-queries endpoint + UI card, or correct the comment to say the consumer is pending.
- **Verifier note:** Verified line 4 of V066__pg_stat_statements.sql reads exactly "-- Zero overhead (<1% CPU). Admin /admin/system page shows top 10 slow queries." Grep across all Go/Svelte/TS/SQL/reducer source found zero consumers of pg_stat_statements (only the migration itself plus docs); no GET /admin/system/slow-queries route is registered in mailserver/cmd/mailserverd/main.go (21 admin/system routes exist, non

### L19. Default pg_stat_statements.track='top' will not see statements inside PL/pgSQL reducers, where all business logic lives
- **Lens/source:** change-set review → `observability`
- **Location:** `mailserver/sql/migrations/V066__pg_stat_statements.sql:6`
- **Issue:** This codebase deliberately puts all business logic in PL/pgSQL reducers ('logic where the data is'); top-level statements from the gateway are mostly 'SELECT some_reducer($1,...)'. With the default pg_stat_statements.track='top', statements nested inside functions are not tracked, so the extension will only show per-reducer-call aggregates, not the individual slow statements inside reducers. Cardinality is conversely low (parameterized reducer calls normalize well under the default pg_stat_statements.max=5000), so there is no cardinality risk — but the observability value is much smaller than the migration implies unless track='all' is set.
- **Evidence:** `CREATE EXTENSION IF NOT EXISTS pg_stat_statements;  -- no accompanying pg_stat_statements.track configuration anywhere in deploy/`
- **Fix:** Document/configure pg_stat_statements.track='all' (and consider track_planning=off to bound overhead) in the deploy templates if intra-reducer visibility is the goal; otherwise note that results are per-reducer aggregates.
- **Verifier note:** Verified the migration at V066__pg_stat_statements.sql:6 is a bare `CREATE EXTENSION IF NOT EXISTS pg_stat_statements;` with no `pg_stat_statements.track` GUC; grep across all *.conf/*.sql/*.sh/*.service files and mailserver/deploy/ templates (patroni.yml.template, config.env.sample, pgbouncer.ini) finds no track config anywhere, so the runtime value is PostgreSQL's default 'top'. The architecture

### L20. Slow-request log writes percent-decoded r.URL.Path — safe only because slog handlers quote control characters
- **Lens/source:** change-set review → `observability`
- **Location:** `shared/middleware/slow_request.go:18-23`
- **Issue:** r.URL.Path is the percent-decoded path, so a request to /a%0d%0afake-line yields a Path containing literal CR/LF. The current slog Text/JSON handlers escape/quote such values, so no log-line injection occurs today, and the middleware otherwise has a good privacy posture (no query string, no headers, no emails — tokens in query parameters are not logged). The safety, however, depends entirely on the log sink: any future raw-writing handler would reintroduce CRLF injection via both path and the attacker-controllable request_id.
- **Evidence:** `logger.Warn("slow request",
					"path", r.URL.Path,
					"method", r.Method,
					"duration_ms", d.Milliseconds(),
					"request_id", GetRequestID(r.Context()),`
- **Fix:** Optionally log r.URL.EscapedPath() instead of the decoded Path, and cap/sanitize request_id at the RequestID middleware (see the X-Request-ID issue) so log safety does not depend on handler choice.
- **Verifier note:** Verified all claims against actual code. slow_request.go:18-23 matches the cited evidence exactly, logging "path", r.URL.Path and "request_id", GetRequestID(...). I empirically confirmed r.URL.Path is percent-decoded: url.Parse("/a%0d%0afake-line").Path yields raw bytes 47 97 13 10 ... (CR=13, LF=10 literal in the string). request_id is attacker-controllable: GetRequestID reads the context value s

### L21. Comma-separated deps headers are mis-parsed — every dependency except the last is silently dropped
- **Lens/source:** change-set review → `lifecycle-protocol`
- **Location:** `scripts/reload-reducers.sh:23-37`
- **Issue:** All 14 deps headers use comma separation (e.g. journal.sql: `-- deps: deliver, get_tag_id, send`). The script strips only the prefix (`sed 's/^-- deps: *//'`) and word-splits, yielding tokens with trailing commas ('deliver,', 'get_tag_id,'). The lookup grep `CREATE.*FUNCTION $df\s*(` then never matches for those tokens, so the dependency is silently discarded. Empirically verified: '[deliver,] -> [MISSED] [get_tag_id,] -> [MISSED] [send] -> [send.sql]'. Even on bash 4+, the topological sort therefore operates on a mostly-empty graph — the feature does not do what the commit claims.
- **Evidence:** `local dep_funcs=$(echo "$dep_line" | sed 's/^-- deps: *//')
            local dep_files=""
            for df in $dep_funcs; do
                local def_file=$(grep -l "CREATE.*FUNCTION $df\s*(" "$dir"/*.sql 2>/dev/null | head -1)`
- **Fix:** Strip commas before splitting (e.g. `tr ',' ' '`), and emit a warning (or error) when a declared dep cannot be resolved to a file, so typos and unresolvable deps are visible instead of silently ignored.
- **Verifier note:** The parsing bug is empirically confirmed under bash (script declares `#!/usr/bin/env bash`). All 14 `-- deps:` headers are comma-separated (e.g. journal.sql line 1: `-- deps: deliver, get_tag_id, send`). Line 30 `sed 's/^-- deps: *//'` strips only the prefix, and default-IFS word-splitting yields tokens with trailing commas: my run produced `TOKEN 1: [deliver,]  TOKEN 2: [get_tag_id,]  TOKEN 3: [s

### L22. Declared reducer dependency graph contains real file-level cycles — a correct topological sort would refuse to load
- **Lens/source:** change-set review → `lifecycle-protocol`
- **Location:** `mailserver/sql/reducers/send.sql:1 (also journal.sql:1, retention.sql:1)`
- **Issue:** send.sql declares `-- deps: ... journal_if_policy_matches ... tag_retention ...`; journal_if_policy_matches is defined in journal.sql and tag_retention in retention.sql (verified by grep). But journal.sql declares `-- deps: deliver, get_tag_id, send` and retention.sql declares `-- deps: adjust_folder_counters, deliver, send, trace` — both depend back on send.sql. So the file-level graph has at least two 2-cycles (send↔journal, send↔retention). Today this is masked by the comma-parsing bug (issue above); if that bug is fixed, sort_reducers will hit its cycle branch and (because of the process-substitution bug) silently apply zero files. The design itself — deriving a file-level DAG from function-level deps — is unsound for this codebase. Note also that for PL/pgSQL `CREATE OR REPLACE FUNCTION`, callee existence is not checked at definition time, so load order was already a non-problem for 35 of 37 files (only health_check.sql and utils_tags.sql contain LANGUAGE sql functions), making the whole feature low-value as well as broken.
- **Evidence:** `send.sql:1: -- deps: apply_rules, bump_email_state, check_quota, compute_thread_id, deliver, get_tag_id, journal_if_policy_matches, next_imap_uid_for_tag, set_message_location, tag_retention
journal.sql:1: -- deps: deliver, get_tag_id, send
retention.sql:1: -- deps: adjust_folder_counters, deliver, send, trace`
- **Fix:** Either drop the topological feature (the previous glob order was correct for CREATE OR REPLACE plpgsql) or break the cycles by removing runtime-only call edges from the headers (deps should mean 'must exist at load time', which only applies to LANGUAGE sql functions), and add a CI check that runs sort_reducers and fails on cycles/unresolved deps.
- **Verifier note:** Verified by reading the files and running the actual sort logic. The declared file-level cycles are real: send.sql:1 deps include `journal_if_policy_matches` (defined in journal.sql) and `tag_retention` (defined in retention.sql), while journal.sql:1 (`deps: deliver, get_tag_id, send`) and retention.sql:1 (`deps: ..., send, trace`) both depend back on `send`. Today this is masked by a comma-parsin

### L23. lifecycle package is dead code — not wired into cmd/mailserverd/main.go or anywhere else
- **Lens/source:** change-set review → `lifecycle-protocol`
- **Location:** `mailserver/internal/lifecycle/lifecycle.go:1-138`
- **Issue:** grep for `internal/lifecycle` across mailserver finds no importers outside the package itself. cmd/mailserverd/main.go was not modified by e0edc0d; its only 'lifecycle' references are a pre-existing local variable `lifecycleCtx` (main.go:159) unrelated to this package. The commit and CLAUDE.md present this as the server's dependency-ordered startup/shutdown manager, but the actual mandatory startup sequence (pool → S3 → startup_recovery → dispatcher → auth → HTTP) is still hand-coded in main.go. As shipped, the package adds maintenance surface with zero behavior change.
- **Evidence:** `grep -rn "internal/lifecycle" mailserver --include="*.go" (excluding the package itself) → no results; main.go:159: lifecycleCtx, lifecycleCancel := context.WithCancel(context.Background())`
- **Fix:** Either wire main.go's startup sequence through lifecycle.Lifecycle in a follow-up (the commit says 'Wave 4b' — make that wave land) or mark the package as not-yet-integrated in CLAUDE.md so reviewers don't assume the server uses it.
- **Verifier note:** Verified every claim against code. `grep -rn "internal/lifecycle"` over both mailserver and the full monorepo returns zero importers outside lifecycle/ itself. `git show --stat e0edc0d` confirms the commit added only lifecycle.go (+138) and lifecycle_test.go (+122), never touching cmd/mailserverd/main.go. The 7 `lifecycle` hits in main.go are the unrelated local `lifecycleCtx, l

### L24. Cassette 'regression framework' is unwired: cassettes are never replayed by any test, and the advertised fuzz corpus was not committed
- **Lens/source:** change-set review → `lifecycle-protocol`
- **Location:** `mailserver/internal/protocoltest/cassette.go:63 (Match); testdata/001_capability.cassette, 002_select_inbox.cassette`
- **Issue:** No code outside internal/protocoltest references the package or the two .cassette files (grep for 'protocoltest' and 'cassette' across mailserver finds only the package's own files). Cassette.Match's doc says it replays 'against a live server', but there is no replay harness, no IMAP test loads testdata/*.cassette, and nothing in CI enforces the commit's stated rule that protocol changes 'MUST include or update a cassette test' — the cassettes are dead fixtures. The fuzz tests do run their F.Add seed corpus via `go test ./...` in xinchuang-ci.yml (verified passing), but the commit message's '80 interesting' corpus inputs were not committed (no internal/imap/testdata/fuzz/ directory), so none of the discovered inputs are regression-tested. Determinism was handled by simply omitting variable lines (002_select_inbox.cassette's header comment says the response 'must include EXISTS' yet no `S: * <n> EXISTS` step exists), and fuzzyMatch's bare substring rule (`strings.Contains(actual, expected)`) is loose enough that short expectations match almost anything — both secondary while nothing replays them.
- **Evidence:** `grep -rn "protocoltest" mailserver --include="*.go" | grep -v internal/protocoltest/ → empty; ls internal/imap/testdata/fuzz → 'no fuzz corpus dir'; cassette comment: '# IMAP SELECT INBOX — response must include EXISTS...' with no EXISTS step`
- **Fix:** Add a replay test in internal/imap that walks testdata/*.cassette against an in-process IMAP session (skipping via testutil.SkipIfNoEnv if a DB is required), commit the interesting fuzz inputs under testdata/fuzz/<FuzzName>/, and tighten fuzzyMatch (anchor substring matches or require prefix-token match only).
- **Verifier note:** All factual claims verified against code. grep -rn "protocoltest" and grep -rin "cassette" over mailserver Go files find ONLY internal/protocoltest/cassette.go and cassette_test.go — nothing wires the package in. cassette_test.go tests ParseCassette/Match/String with inline string literals only (lines 9-13, 67-77); it never reads testdata. The two fixtures live in internal/imap/testdata/ but no Go

### L25. Commit 17fbd0c bundles an unrelated 882-line mail-core Rust rewrite that did not compile
- **Lens/source:** change-set review → `lifecycle-protocol`
- **Location:** `clients/rust/mail-core/src/lib.rs:1-225 (rewrite in 17fbd0c)`
- **Issue:** The 'feat(sql): add -- deps: headers' commit includes a full rewrite of clients/rust/mail-core/src/lib.rs (the source of the 741 deletions) converting MailCore from a tokio Runtime handle to UniFFI async exports, plus error.rs changes — none of it mentioned in the commit message. The immediately following commit 61259e4 is titled 'fix(rust): fix pre-existing MailCore lib.rs compilation errors', meaning 17fbd0c left mail-core in a non-compiling state. This pollutes history (a SQL-tooling revert would also revert the Rust client) and made the stat misleading during review.
- **Evidence:** `git show --stat 17fbd0c: 'clients/rust/mail-core/src/lib.rs | 882 ++++-----------------' under message 'feat(sql): add -- deps: headers to 36 reducer files'; next commit on the file: '61259e4 fix(rust): fix pre-existing MailCore lib.rs compilation errors'`
- **Fix:** Already landed and fixed downstream; going forward keep unrelated subsystems in separate commits and run the relevant build (cargo check) before committing client crate changes.
- **Verifier note:** Confirmed via git. Commit 17fbd0c (message: "feat(sql): add -- deps: headers to 36 reducer files + topological reload script") bundles clients/rust/mail-core/src/lib.rs (+150/-732, 807→225 lines) and error.rs (+2), none of it mentioned in the message. The lib.rs diff is a real rewrite converting MailCore from `rt: Arc<Runtime>` + `block_on` to `#[uniffi::export(async_runtime = "tokio")]` async exp

### L26. lifecycle misreports a missing dependency as a circular dependency and silently swallows rollback shutdown errors
- **Lens/source:** change-set review → `lifecycle-protocol`
- **Location:** `mailserver/internal/lifecycle/lifecycle.go:53-54, 90-95, 119-134`
- **Issue:** If a subsystem declares DependsOn("x") and no subsystem named x is registered, its in-degree (initialized to len(DependsOn())) is never decremented, so topologicalSort reports 'circular dependency detected' — a misleading diagnosis for a typo'd or unregistered dependency. The `byName` map (lines 81-84) is built and never read (dead code). During Start's rollback, Shutdown errors are discarded with `_ = initialized[i].Shutdown(ctx)` and nothing is logged, contradicting the project rule 'Never swallow errors silently' (no slog usage in the package at all). The rollback also reuses the possibly-cancelled startup ctx with no timeout for cleanup.
- **Evidence:** `_ = initialized[i].Shutdown(ctx)  // line 54;  byName := map[string]Subsystem{} ... (never read);  return nil, fmt.Errorf("circular dependency detected in: %v", remaining)`
- **Fix:** Validate that every DependsOn name resolves via byName and return a distinct 'unknown dependency %q required by %q' error; log rollback shutdown failures via slog.Warn; use a context.WithTimeout(context.Background(), ...) for rollback so cleanup isn't aborted by the cancelled startup context.
- **Verifier note:** All factual claims verified against mailserver/internal/lifecycle/lifecycle.go. (1) Missing-dep-as-cycle: line 91 sets inDegree[s.Name()] = len(s.DependsOn()) including phantom deps; the only decrement (line 112) iterates dependents[s.Name()] for actually-processed subsystems, so an unregistered dep name never decrements its dependent's in-degree, the dependent never queues, len

### L27. Device checkin/policy endpoints trust client-supplied device_id with no ownership check (IDOR)
- **Lens/source:** change-set review → `policy-consolidation`
- **Location:** `authserver/internal/device/checkin.go:48-59, 115-153, 186-195`
- **Issue:** HandleCheckin and HandleGetDevicePolicy take device_id straight from the request body/query and pass it to resolveDevicePolicy, which queries `devices`, `device_policy`, and wipe state by id alone with no `user_id` filter and never reads the authenticated caller's claims. Any authenticated user can check in as, inject events for, and read the policy + remote-wipe state of ANY other user's device by guessing the integer id (CWE-639 / DATABASE_SECURITY R1 violation). The HMAC device-attestation primitives in identity.go (GenerateDeviceSecret/ValidateHMAC) are never invoked here, so device compliance is pure unauthenticated client self-attestation. These handlers are also not registered in authserver/cmd/authserverd/main.go, so as shipped they are dead code that nonetheless encodes an unsafe contract.
- **Evidence:** `var req CheckinRequest
if err := decodeJSON(r, &req); err != nil { ... }
if req.DeviceID <= 0 { ... }
policy, err := resolveDevicePolicy(ctx, pool, req.DeviceID)
...
pool.QueryRow(ctx, `SELECT COALESCE(wipe_requested, false) FROM devices WHERE id = $1`, deviceID)`
- **Fix:** Derive the user from the JWT claims in context and scope every query to that user (`WHERE id = $1 AND user_id = $2`), or require a per-device HMAC proof via ValidateHMAC. Reject mismatches with 403. Wire the routes behind requireAuth before considering this done.
- **Verifier note:** The code defect is real and accurately quoted. HandleCheckin (checkin.go:48-59) takes req.DeviceID from the JSON body and HandleGetDevicePolicy (checkin.go:186-195) takes device_id from the query string; both flow into resolveDevicePolicy (checkin.go:115-153) which queries `device_policy WHERE device_id = $1` and `devices WHERE id = $1` with no user_id filter and never reads JWT claims — a clear R

### L28. device_events JSON built with fmt.Sprintf over client-controlled input
- **Lens/source:** change-set review → `policy-consolidation`
- **Location:** `authserver/internal/device/identity.go:84-88, 133-136`
- **Issue:** RegisterDevice constructs the event_data JSON via fmt.Sprintf interpolating client-supplied platform/os_version/app_version, and Quarantine does the same with `reason`. The value is passed as a bound parameter so this is not SQL injection, but it is JSON injection: an os_version of `"}` produces invalid JSON that fails the JSONB insert (silently swallowed by `_, _ =`), and crafted values can forge additional keys in the event record. This violates the project rule against fmt.Sprintf with user input into SQL/JSON; the sibling checkin.go path correctly uses json.Marshal.
- **Evidence:** `fmt.Sprintf(`{"platform":"%s","os_version":"%s","app_version":"%s"}`,
    id.Platform, id.OSVersion, id.AppVersion)`
- **Fix:** Build event_data with json.Marshal(map[string]string{...}) (as checkin.go already does) instead of fmt.Sprintf, and stop discarding the insert error with `_, _ =`.
- **Verifier note:** Confirmed by code. identity.go:84-88 builds event_data via `fmt.Sprintf(`{"platform":"%s","os_version":"%s","app_version":"%s"}`, id.Platform, id.OSVersion, id.AppVersion)` and identity.go:133-136 via `fmt.Sprintf(`{"reason":"%s"}`, reason)`, both discarding the error with `_, _ = pool.Exec(...)`. The inputs are client-controlled: the Identity struct is populated by `decodeJSON(r, &id)` from the r

### L29. Inbound header/body boundary parsing assumes CRLF while the DATA reader yields bare-LF messages
- **Lens/source:** security/structure hunt → `protocol-parsing`
- **Location:** `mailserver/internal/smtp/inbound.go:1260, 1272, 1287`
- **Issue:** isSMIMESigned and extractSMIMEParts locate the header/body boundary with `strings.Index(msg, "\r\n\r\n")` ONLY, and extractSMIMEBoundary splits headers on `"\r\n"` only (lines 1260, 1272, 1318). But, as shown above, the inbound DotReader accepts and preserves messages whose lines are terminated by bare LF, so a message using LF separators has no `\r\n\r\n` sequence at all. The result is parser disagreement: header extraction (and S/MIME signature splitting) sees the entire message as headers or finds no boundary, while other code paths in the same file (extractSMIMEParts at 1294 falls back to `\n\n`, but isSMIMESigned/extractSMIMEBoundary do not). An attacker can craft a message that one routine treats as signed/unsigned or with different header values than another, undermining DMARC/S-MIME decisions that are driven off these extracted headers.
- **Evidence:** `func isSMIMESigned(msg string) bool {
	headerEnd := strings.Index(msg, "\r\n\r\n")
	if headerEnd < 0 {
		return false
	}`
- **Fix:** Normalize the message to canonical CRLF immediately after DotReader (or reject bare LF, per the smuggling finding), and make every header/body boundary search tolerate both `\r\n\r\n` and `\n\n` consistently across isSMIMESigned, extractSMIMEParts, and extractSMIMEBoundary so all routines agree on where headers end.
- **Verifier note:** The cited code is accurate: isSMIMESigned (inbound.go:1260) and extractSMIMEParts (1272) locate the header/body boundary with strings.Index(msg,"\r\n\r\n") only, extractSMIMEBoundary splits on "\r\n" only (1318), and the text/calendar branch (1287) lacks the "\n\n" fallback that the pkcs7 branch has (1292-1294). I empirically confirmed Go's net/textproto.DotReader (used at line 498 via c.tp.DotRea

### L30. CalDAV/CardDAV/WebDAV handlers read request bodies with unbounded io.ReadAll (no MaxBytesReader)
- **Lens/source:** security/structure hunt → `protocol-parsing`
- **Location:** `mailserver/internal/caldav/caldav.go:123, 297, 540, 723`
- **Issue:** Every CalDAV/CardDAV verb handler reads the full request body with `body, _ := io.ReadAll(r.Body)` and no http.MaxBytesReader wrapper (caldav.go:123,297,540,723; carddav.go:70,213,351). A grep for MaxBytesReader/MaxBodyBytes/LimitReader across mailserver/cmd, internal/middleware, and shared/middleware returns nothing, so there is no global body-size cap either. A PUT/REPORT/PROPFIND with a multi-gigabyte body is buffered entirely into memory and then handed to xml.Unmarshal / ParseICal / parseVCard. The error from ReadAll is also discarded (`_`), so a truncated/aborted body is parsed as if complete. Severity is reduced because the HTTP server sets ReadTimeout: 30s (cmd/mailserverd/main.go:1237), bounding how long an attacker can stream, and these routes require auth — but a fast authenticated client can still push large allocations within the window. Go's encoding/xml does not expand DTD/external entities, so XXE/billion-laughs is not a concern here.
- **Evidence:** `body, _ := io.ReadAll(r.Body)
var pf propfind
if len(body) > 0 {
	if err := xml.Unmarshal(body, &pf); err != nil {`
- **Fix:** Wrap r.Body with http.MaxBytesReader (e.g. a few MB for PROPFIND/REPORT XML, a larger documented cap for calendar/contact PUTs) before io.ReadAll, and stop discarding the ReadAll error so truncated bodies are rejected with 4xx instead of silently parsed.
- **Verifier note:** All cited code is confirmed verbatim. caldav.go:123,297,540,723 and carddav.go:70,213,351 each do `body, _ := io.ReadAll(r.Body)` with no http.MaxBytesReader and the ReadAll error discarded, feeding directly into xml.Unmarshal / parseICal / parseVCard (e.g. caldav.go:540-541 reads then `parseICal(string(body))`). A grep across cmd, internal/middleware, shared/middleware, and the dav packages finds

### L31. SMTP inbound and submission accept unlimited RCPT TO recipients (unbounded slice growth)
- **Lens/source:** security/structure hunt → `protocol-parsing`
- **Location:** `mailserver/internal/smtp/inbound.go:484`
- **Issue:** handleRcpt appends each recipient to c.to with no cap (`c.to = append(c.to, addr)` at inbound.go:484 and submission.go:467). RFC 5321 §4.5.3.1.10 sets a 100-recipient minimum and explicitly permits a configured maximum after which the server replies 452. Neither path enforces an upper bound, so a single session can issue millions of RCPT commands, growing c.to without limit (bounded only by the 5-minute command timeout) and, on inbound, later spawning one delivery goroutine per recipient in handleData (errgroup loop at inbound.go:535). This amplifies into many concurrent DB transactions for one connection.
- **Evidence:** `c.to = append(c.to, addr)
c.reply(250, "OK")`
- **Fix:** Cap recipients per message (e.g. reject with `452 4.5.3 Too many recipients` past a configurable limit such as 100-1000) in both handleRcpt implementations, and bound the per-message delivery fan-out accordingly.
- **Verifier note:** Confirmed both cited lines: inbound.go:484 and submission.go:467 each do `c.to = append(c.to, addr)` with no cap, followed by `c.reply(250, "OK")`. Grep of the whole smtp package found no recipient limit — the only `len(c.to)` checks are `== 0` minimums (submission.go:476), and there is no `452`, `maxRcpt`, or recipient counter anywhere. The 5-minute deadline (inbound.go:283) is reset on every `Re

### L32. MTA-STS policy fetch over HTTPS with no destination IP filtering (sender-domain controlled host)
- **Lens/source:** security/structure hunt → `ssrf-outbound`
- **Location:** `mailserver/internal/smtp/mtasts.go:106-203`
- **Issue:** LookupMTASTS builds policyHost = "mta-sts."+domain and fetches https://mta-sts.<domain>/.well-known/mta-sts.txt via httpsGet, which uses a bare http.Client{Timeout:10s} with no check that mta-sts.<domain> resolves to a public IP and no resolve-then-pin. The domain originates from inbound/outbound mail counterparties (sender/recipient domains), so a hostile counterparty can publish an A record for mta-sts.<their-domain> pointing at an internal IP, causing the MTA to issue an HTTPS GET to an internal address. Impact is constrained: the path is fixed to /.well-known/mta-sts.txt, scheme is always https, response is capped at 64KB and only parsed as a key:value policy (no reflection to the attacker), and TLS validation to an internal host usually fails. Still, it is an outbound request to an attacker-influenced host with no private-range guard, so it belongs in the SSRF inventory.
- **Evidence:** `policyHost := "mta-sts." + domain
url := "https://" + policyHost + "/.well-known/mta-sts.txt"
body, err := httpsGet(url)
...
func httpsGet(url string) ([]byte, error) {
    client := &http.Client{Timeout: 10 * time.Second}
    resp, err := client.Get(url)`
- **Fix:** Use a shared safe HTTP client that resolves mta-sts.<domain> and rejects private/loopback/link-local IPs with a pinned DialContext. Keep TLS verification mandatory (already implied by https) and the 64KB cap. This same hardened client should be reused by discovery and webhook delivery.
- **Verifier note:** Verified mtasts.go: lines 107-109 build `policyHost := "mta-sts." + domain`, `url := "https://" + policyHost + "/.well-known/mta-sts.txt"`, then `httpsGet(url)`. httpsGet (lines 188-190) uses a bare `&http.Client{Timeout: 10 * time.Second}` with the default transport — no custom DialContext, no IsPrivate/IsLoopback/IsLinkLocal check; a repo-wide grep found no SSRF guard or shared safe HTTP client 

### L33. EWS migration connector allows admin-toggled TLS verification bypass on a connector-supplied URL
- **Lens/source:** security/structure hunt → `ssrf-outbound`
- **Location:** `mailserver/internal/migration/ews_client.go:67-80`
- **Issue:** NewEWSConnector builds an http.Transport with TLSClientConfig{InsecureSkipVerify: cfg.InsecureSkipVerify} and POSTs to cfg.ServerURL (ews_client.go:555). The server URL and the InsecureSkipVerify flag both come from migration job/global config. While migration is an admin-configured feature (so pointing it at an internal/self-signed Exchange is partly by design), the combination of (a) an arbitrary admin-supplied URL with no private-range awareness and (b) an opt-in flag that disables certificate validation means a misconfigured or attacker-influenced source config can both reach internal hosts and accept any cert (MITM / no integrity). The IMAP connector (imap_client.go:154-170) similarly dials cfg.Host:cfg.Port directly. Flagging the TLS bypass specifically because InsecureSkipVerify is broadly discouraged for any externally-influenced endpoint.
- **Evidence:** `transport := &ntlmssp.Negotiator{
    RoundTripper: &http.Transport{
        TLSClientConfig: &tls.Config{InsecureSkipVerify: cfg.InsecureSkipVerify},
    },
}`
- **Fix:** Gate InsecureSkipVerify behind an explicit, audited admin override with a UI warning; default it off. Validate cfg.ServerURL is https with a host that is not a loopback/link-local address unless an operator explicitly allows internal targets, and record the chosen target in the migration audit log.
- **Verifier note:** The cited code is accurate. ews_client.go:71 builds `tls.Config{InsecureSkipVerify: cfg.InsecureSkipVerify}` inside the http.Transport, and soapRequest POSTs to `e.serverURL` (ews_client.go:555). Both values are admin/job-controlled: orchestrator.go:458-475 sources InsecureSkipVerify from the encrypted `ews.global` system_config (global.InsecureSkipVerify) and lets a job override ServerURL (line 4

### L34. Successful-auth cache returns stale admin/role/flags for up to 60s with no invalidation hook on privilege change
- **Lens/source:** security/structure hunt → `secrets-crypto`
- **Location:** `shared/pwhash/pwhash.go:57-109`
- **Issue:** CheckPassword caches the full resolved User record (IsAdmin, AdminRole, MustChangePassword, MFAExempt) keyed by email + sha256(password)[:8] for 60 seconds. On a cache hit (lines 91-94) it returns the previously-cached e.user, NOT the freshly-queried u from lines 73-81. There is no invalidation hook: grep shows nothing calls into authCache on privilege change, role change, MFA-exempt toggle, or admin-role revocation. Consequence: if an admin demotes a user or revokes admin_role while that user actively authenticates via Basic Auth (DAV/IMAP) with the same password, the user keeps stale elevated IsAdmin/AdminRole for up to 60s. Account disable IS handled (the always-run query at line 73 has WHERE u.enabled = TRUE and errors out before the cache check), and password change naturally misses the cache because the key embeds the password hash. So this is a bounded privilege-staleness window, not a full bypass.
- **Evidence:** `if e, ok := entry.(cacheEntry); ok && time.Now().Before(e.expiresAt) {
			return e.user, nil
		}`
- **Fix:** On the cache-hit path, return the freshly queried u (which already reflects current enabled/role state) rather than the cached e.user, or store only a 'password verified' boolean and always re-read role/flags. Alternatively add an InvalidateAuthCache(email) hook called from password-change, role-change, and disable handlers.
- **Verifier note:** Verified in shared/pwhash/pwhash.go: line 90 keys the cache as `email + ":" + hashSlug(password)`, and lines 91-94 on a cache hit `return e.user, nil` — the previously cached User (with IsAdmin, AdminRole, MustChangePassword, MFAExempt per struct lines 24-28), NOT the fresh `u` queried at lines 73-81. The fresh query has `WHERE u.email = $1 AND u.enabled = TRUE` and errors out a

### L35. AES-GCM envelope decryption ignores AAD that the sealing functions accept, making the AAD integrity-binding feature dead and a misuse trap
- **Lens/source:** security/structure hunt → `secrets-crypto`
- **Location:** `shared/cryptokey/envelope.go:147`
- **Issue:** SealEnvelope / SealEnvelopeDeterministic / buildEnvelope all accept an aad []byte parameter and pass it to gcm.Seal (line 106), so a caller can bind associated data (e.g. a blob ID or column name) to the ciphertext. But OpenEnvelope hardcodes nil for the AAD argument to gcm.Open (line 147) and offers no parameter to pass aad in. Any envelope sealed with non-nil aad cannot be opened at all (GCM tag mismatch), and any future caller relying on AAD for context binding (preventing ciphertext substitution across columns/blobs) silently gets no protection. EncryptColumn (cryptokey.go:68) and the migration-credential path pass nil today so nothing is currently broken, but the asymmetric API is a latent crypto-misuse trap.
- **Evidence:** `plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)`
- **Fix:** Either add an aad parameter to OpenEnvelope and thread the same AAD through Seal and Open at every call site, or remove the aad parameter from the Seal functions so the API cannot promise integrity binding it does not verify.
- **Verifier note:** Verified directly in shared/cryptokey/envelope.go: SealEnvelope (line 67), SealEnvelopeDeterministic (line 84), and buildEnvelope (line 97) all accept aad []byte and pass it to gcm.Seal at line 106 (`sealed := gcm.Seal(nil, nonce, plaintext, aad)`), but OpenEnvelope (line 117) has no aad parameter and hardcodes nil at line 147 (`plaintext, err := gcm.Open(nil, nonce, ciphertext,

### L36. Gateway JWT validator accepts two distinct HMAC key-IDs, so kid provides no real issuer separation
- **Lens/source:** security/structure hunt → `secrets-crypto`
- **Location:** `mailserver/internal/auth/jwt.go:146`
- **Issue:** The gateway's Validate() HMAC branch accepts kid of either 'authserver-hmac-1' OR the gateway's own kidHMAC 'mailserver-hmac-1'. Both services share the same JWT_SECRET and the same audience ('mailserver-gateway'), and the gateway also self-issues tokens (jwt.go:26,168). The kid field therefore provides no cryptographic separation: any holder of JWT_SECRET can mint a token with either kid and it is accepted. Issuer and audience are identical across the two services, so there is no defense-in-depth boundary between authserver-issued and gateway-issued tokens. Low severity because possession of JWT_SECRET is already total compromise, but the dual-kid acceptance gives a false impression of key-ID-based separation.
- **Evidence:** `if kid != "authserver-hmac-1" && kid != kidHMAC {
			return nil, fmt.Errorf("unexpected kid: %v", t.Header["kid"])
		}`
- **Fix:** If issuer separation is desired, derive two distinct subkeys from a root secret via cryptokey.DeriveEncryptionKey with different info strings and bind each kid to its own key, so a gateway-minted kid cannot validate as an authserver token and vice versa.
- **Verifier note:** Verified directly in code. mailserver/internal/auth/jwt.go:146 accepts both kids: `if kid != "authserver-hmac-1" && kid != kidHMAC` (kidHMAC="mailserver-hmac-1", jwt.go:26), and line 149 returns the single shared `p.secret` for both — so kid provides no cryptographic separation. Same secret: both providers take `cfg.JWTSecret` (mailserver chain.go:53, authserver main.go:229); same audience "mailse

### L37. Attachment Content-Disposition built with unescaped filename allows quoted-string breakout / spoofing
- **Lens/source:** security/structure hunt → `web-frontend`
- **Location:** `mailserver/internal/jmap/blob.go:386`
- **Issue:** The JMAP Download handler builds the Content-Disposition header by interpolating the URL-supplied `name` path value directly into a quoted-string with fmt.Sprintf and no escaping. Go's net/http rejects CR/LF in header values (so classic response splitting is prevented), but a filename containing a double-quote (`"`) is NOT rejected and breaks out of the `filename="..."` quoting, letting an attacker-crafted download link inject additional Content-Disposition parameters or spoof the displayed filename / disposition. The `name` comes straight from `r.PathValue("name")` with no sanitization or quoting of embedded quotes/backslashes, and RFC 6266 filename* / token escaping is not applied.
- **Evidence:** `name := r.PathValue("name")
...
w.Header().Set("Content-Disposition", fmt.Sprintf(`%s; filename="%s"`, disp, name))`
- **Fix:** Use `mime.FormatMediaType` or RFC 6266-compliant encoding: percent-encode/strip control and quote characters, and emit both `filename=` (ASCII-sanitized) and `filename*=UTF-8''<pct-encoded>`. At minimum, reject or backslash-escape `"` and `\` in `name` before interpolation.
- **Verifier note:** Verified at mailserver/internal/jmap/blob.go:378 `name := r.PathValue("name")` and :386 `w.Header().Set("Content-Disposition", fmt.Sprintf(`%s; filename="%s"`, disp, name))` — the URL path segment is interpolated verbatim into a quoted-string with no escaping. The route mailserver/cmd/mailserverd/main.go:584 `GET /jmap/download/{accountId}/{blobId}/{name}` makes `{name}` an arbitrary path wildcard

### L38. Dependabot gomod coverage misses the mailctl module
- **Lens/source:** security/structure hunt → `supply-chain-ci`
- **Location:** `.github/dependabot.yml:3-9`
- **Issue:** The gomod entry lists /mailserver, /authserver, /shared but omits /mailctl, which is a genuine separate Go module (module setjoin.com/mailctl in mailctl/go.mod). mailctl is the admin CLI that performs restore, upgrade, DANE and SCIM operations — privileged operational tooling. Its dependencies receive no automated security updates, leaving a blind spot for CVEs in a high-privilege binary.
- **Evidence:** `- package-ecosystem: "gomod"
    directories:
      - "/mailserver"
      - "/authserver"
      - "/shared"`
- **Fix:** Add "/mailctl" to the gomod directories list.
- **Verifier note:** Verified the cited evidence exactly: .github/dependabot.yml:3-7 lists gomod directories "/mailserver", "/authserver", "/shared" and omits "/mailctl". mailctl/go.mod is a genuine separate, git-tracked Go module ("module setjoin.com/mailctl") listed in go.work alongside the three covered modules, and it has real CVE-relevant direct deps (github.com/jackc/pgx/v5 v5.9.2, golang.org/x/crypto v0.52.0, g

### L39. CI runs `go install golang.org/x/vuln/cmd/govulncheck@latest` — unpinned tool fetch in build environment
- **Lens/source:** security/structure hunt → `supply-chain-ci`
- **Location:** `.github/workflows/xinchuang-ci.yml:100-103`
- **Issue:** The unit-tests job installs govulncheck at @latest, pulling whatever the newest tag resolves to at run time into the CI runner. Unpinned @latest tool installs are a supply-chain risk: a malicious or broken release of the tool (or its dependencies) executes in the CI environment. The step is wrapped in continue-on-error so its findings are non-blocking, meaning a compromised/broken govulncheck would not even be noticed via a red build. Impact is lower than the actions findings because it runs in the test job (not the release/secrets job), but it still executes attacker-influenceable code on every push/PR.
- **Evidence:** `go install golang.org/x/vuln/cmd/govulncheck@latest
          cd mailserver && govulncheck ./...`
- **Fix:** Pin govulncheck to a specific version tag (e.g. @v1.1.4) and update via Dependabot, or install it via a SHA-pinned action. Reconsider continue-on-error so genuine vuln findings are visible.
- **Verifier note:** Verified the cited code at .github/workflows/xinchuang-ci.yml:100-103. Line 100 is exactly `go install golang.org/x/vuln/cmd/govulncheck@latest` (unpinned @latest tool fetch), and lines 101-103 run `govulncheck ./...` across mailserver/authserver/shared. The step (lines 97-98) carries `continue-on-error: true # non-blocking`, confirming findings would not produce a red build, and it lives in the `

### L40. fetch-ref-docs.sh pipes remote curl output directly to files without TLS-fail or integrity check, and runs `docker run` on a local image
- **Lens/source:** security/structure hunt → `supply-chain-ci`
- **Location:** `docs/ref/scripts/fetch-ref-docs.sh:104, 138`
- **Issue:** The reference-docs fetcher downloads RFC text via `curl -sLf ... > $out` with -L (follow redirects) and no checksum/signature, and separately executes `docker run --rm test-imap-imap-test dovecot -n` capturing output to a tracked file. While this is a developer/maintenance script (not in the runtime or release path), the curl|>file pattern with -L silently follows redirects into an untrusted location and writes the result into the repo's docs/ref tree that other tooling (MANIFEST staleness checks) trusts. There is no pinning of the docker image digest either, so the local image could be a stale/poisoned build. Lower severity because it is opt-in developer tooling, not CI/runtime.
- **Evidence:** `if curl -sLf "https://www.rfc-editor.org/rfc/rfc${rfc}.txt" > "$out" 2>/dev/null; then`
- **Fix:** If these docs are committed, verify them against a recorded checksum in MANIFEST.md before overwriting, drop -L (or restrict redirect host), and pin the docker image by digest. Treat fetched content as untrusted input.
- **Verifier note:** The cited code matches exactly. fetch-ref-docs.sh:104 is `if curl -sLf "https://www.rfc-editor.org/rfc/rfc${rfc}.txt" > "$out" 2>/dev/null; then` — `-L` follows redirects and there is no checksum/signature verification before writing to the tracked file `$out`. Line 138 is `docker run --rm test-imap-imap-test dovecot -n > "$dovecot_out"` with no image digest pinning, output to a tracked file. So t

### L41. Air-gap update bundle upload uses attacker-controlled filename in destination path
- **Lens/source:** security/structure hunt → `dos-limits`
- **Location:** `mailserver/internal/updates/airgap.go:101`
- **Issue:** HandleUpload builds the on-disk destination as filepath.Join(s.dir, slug+"_"+header.Filename) where header.Filename comes from the multipart upload. filepath.Join cleans `..` segments relative to the joined path, but because the basename is `slug+"_"+Filename` an attacker-supplied Filename containing path separators (e.g. `../../etc/foo`) can still redirect the write outside s.dir (Join resolves `s.dir/slug_../../...`). Body size is bounded to 100 MB (airgap.go:79) and the route is super-admin-gated (main.go:567 requireSuperAdmin), so impact and exploitability are limited — flagged for completeness since it sits in the upload path examined under this lens.
- **Evidence:** `destPath := filepath.Join(s.dir, slug+"_"+header.Filename)`
- **Fix:** Sanitize the basename: use filepath.Base(header.Filename) and reject names containing path separators or `..`; store under a server-generated name (e.g. the SHA-256) rather than the client filename.
- **Verifier note:** Verified airgap.go:101 reads exactly `destPath := filepath.Join(s.dir, slug+"_"+header.Filename)` with `header.Filename` taken straight from the multipart upload and only `slug != ""` checked (line 88) — no filepath.Base, no separator/`..` rejection. I reproduced the traversal in a Go program: `filename="../../../etc/cron.d/x"` yields destPath `/var/lib/mail/etc/cron.d/x`, escaping s.dir (the lite

### L42. Dead package: internal/lifecycle (topological startup/shutdown manager) is never wired in
- **Lens/source:** security/structure hunt → `structure-debt`
- **Location:** `mailserver/internal/lifecycle/lifecycle.go:27-72`
- **Issue:** The lifecycle.Lifecycle dependency-ordered startup/shutdown manager (New/Register/Start/Stop, Kahn's topological sort, cycle detection) has ZERO inbound imports anywhere in the codebase. Verified: grep -rln 'internal/lifecycle"' matches only its own files; grep -rn 'lifecycle.' (New/Register/etc) outside the package returns nothing. cmd/mailserverd/main.go (1570 lines) instead does all startup ordering and shutdown manually with inline defers and explicit httpServer.Shutdown/migrationOrch.Shutdown()/authRateLimiter.Shutdown() calls (main.go:1472-1480). The package is fully built and self-tested (lifecycle_test.go) but unused. CLAUDE.md's package table lists it as the active 'Dependency-ordered startup/shutdown manager', misrepresenting a dead package as wired infrastructure.
- **Evidence:** `// Package lifecycle provides a dependency-ordered startup/shutdown manager.
func New() *Lifecycle { return &Lifecycle{} }
func (l *Lifecycle) Start(ctx context.Context) error { ... }  // never called anywhere`
- **Fix:** Either wire main.go's manual startup ordering through lifecycle.Lifecycle (the apparent original intent), or delete internal/lifecycle and remove its row from CLAUDE.md. Do not leave a tested-but-unused subsystem documented as active.
- **Verifier note:** Verified all factual claims. mailserver/internal/lifecycle/lifecycle.go defines New/Register/Start/Stop/Subsystem with Kahn topological sort and cycle detection (lines 27-72, 75-138). `grep -rln 'internal/lifecycle"'` over *.go returns nothing (no importers); the only non-test reference anywhere is docs/plans/archive/2026-06-10-production-hardening.md. The `lifecycle` hits in cmd/mailserverd/main.

### L43. 27 of 53 internal/ packages are absent from CLAUDE.md's mandatory package table
- **Lens/source:** security/structure hunt → `structure-debt`
- **Location:** `CLAUDE.md:Gateway Package Structure section`
- **Issue:** CLAUDE.md states 'Every new Go package must be listed here' immediately after the Gateway Package Structure table, making this an enforced convention. The table lists 26 packages, but ls mailserver/internal/ shows 53 directories. 27 packages are undocumented: acme, ad, admin, blob, cron, handlerutil, health, jmap, kql, ldapsync, ldaputil, linkprotect, mdm, metrics, pst, scim, smime, spam, testutil, threatstore, tlsutil, user, webdav, webhook, wellknown, ws, xinchuang. Several are security-relevant (mdm device policy, scim provisioning, linkprotect URL scanning, threatstore, smime).
- **Evidence:** `Table lists: auth authproxy backup caldav carddav config db deploy discovery downloads geoip imap ldap lifecycle middleware migration mimeutil network notify protocoltest restore smtp startup storage telemetry updates (26)
Actual dirs missing from table: acme ad admin blob cron handlerutil health jmap kql ldapsync ldaputil linkprotect mdm metrics pst scim smime spam testutil threatstore tlsutil user webdav webhook wellknown ws xinchuang (27)`
- **Fix:** Add the 27 missing packages to the Gateway Package Structure table, or relax the 'every package must be listed' rule. As written, the convention is violated for more than half the tree, which erodes the value of the table as a reliability signal.
- **Verifier note:** Verified factually: `ls mailserver/internal/` yields exactly 53 directories, and the Gateway Package Structure table (CLAUDE.md lines 242-267) lists exactly 26 packages (auth...updates). The set difference is precisely the 27 packages the finding names (acme, ad, admin, blob, cron, handlerutil, health, jmap, kql, ldapsync, ldaputil, linkprotect, mdm, metrics, pst, scim, smime, spam, testutil, thre

### L44. Stale entry-point paths in CLAUDE.md after binary rename (cmd/gateway, cmd/authserver)
- **Lens/source:** security/structure hunt → `structure-debt`
- **Location:** `CLAUDE.md:317, 321`
- **Issue:** The repo-structure plan (Task 1) renamed cmd/gateway -> cmd/mailserverd and cmd/authserver -> cmd/authserverd, and Step 6 explicitly required updating CLAUDE.md. Two Key Files rows were missed and still point to non-existent paths. ls mailserver/cmd/gateway/main.go -> No such file; actual is cmd/mailserverd/main.go. ls authserver/cmd/ -> only authserverd. These are the two most-referenced 'where do I start reading' pointers in the doc.
- **Evidence:** `Line 317: | `mailserver/cmd/gateway/main.go` | Entry point ... |
Line 321: | `authserver/cmd/authserver/main.go` | Auth server entry point ... |
(actual: mailserver/cmd/mailserverd/main.go, authserver/cmd/authserverd/main.go)`
- **Fix:** Update lines 317 and 321 to cmd/mailserverd/main.go and cmd/authserverd/main.go.
- **Verifier note:** Verified both cited lines verbatim: CLAUDE.md:317 reads "| `mailserver/cmd/gateway/main.go` | Entry point — startup order and route registration |" and CLAUDE.md:321 reads "| `authserver/cmd/authserver/main.go` | Auth server entry point ... |". Filesystem checks confirm both paths are stale: `ls mailserver/cmd/gateway/main.go` and `ls authserver/cmd/authserver/main.go` both return "No such file or

### L45. Stale threat-package pointer: CLAUDE.md cites authserver/internal/threat but it lives in shared/threat
- **Lens/source:** security/structure hunt → `structure-debt`
- **Location:** `CLAUDE.md:324`
- **Issue:** CLAUDE.md Key Files row points the 8-step pre-auth threat pipeline to authserver/internal/threat/interceptor.go. That path does not exist (ls authserver/internal/threat/ -> No such file). The threat pipeline was moved to shared/ (shared/threat/interceptor.go, 25KB, with interceptor_test.go) so it can be consumed cross-service. A reader following this pointer hits a dead end, and the architectural fact that threat detection is now a SHARED package (not authserver-internal) is hidden.
- **Evidence:** `Line 324: | `authserver/internal/threat/interceptor.go` | 8-step pre-auth threat pipeline ... |
$ ls authserver/internal/threat/  -> No such file or directory
$ ls shared/threat/interceptor.go  -> exists (25071 bytes)`
- **Fix:** Update the pointer to shared/threat/interceptor.go and note it is a shared package consumed by authserver.
- **Verifier note:** Verified every factual claim. CLAUDE.md:324 reads `| `authserver/internal/threat/interceptor.go` | 8-step pre-auth threat pipeline (feed→IP rules→geo→lockout→spray→CAPTCHA→tarpit→rate) |`. `ls authserver/internal/threat/` returns No such file or directory, and `find . -type d -name threat` finds only `./shared/threat`. The package now lives at shared/threat/interceptor.go (25071 bytes, `package th

### L46. Repo-structure plan marked 'Complete / ADR accepted' but referenced ADR was never created and Task-5 cleanups not done
- **Lens/source:** security/structure hunt → `structure-debt`
- **Location:** `docs/plans/archive/2026-06-10-repo-structure-naming.md:4, 15, 186-198`
- **Issue:** The archived plan header says 'Status: Complete - All 5 tasks implemented and pushed. ADR accepted.' Verification against the tree contradicts several claims: (1) it references 'ADR-NNNN' and 'ADR accepted' but docs/adr/ contains only ARCH-002 and DES-005 - no repo-structure/naming ADR exists (grep for 'repo-structure|binary rename|mailserverd' in docs/adr/ -> no matches). (2) Task 5 Step 1-2 (delete dead mailserver/mobile/) was not done - mailserver/mobile/{ios,android} still present (empty, untracked, referenced nowhere in Go). (3) Task 5 Step 4 (complete internal/mdm/ -> authserver move) was not done - internal/mdm still in mailserver with 19 files, authserver/internal/mdm does not exist.
- **Evidence:** `Plan line 4: 'All 5 tasks implemented and pushed. ADR accepted.'
Plan line 15: 'Implement the 5 moves from ADR-NNNN.'
$ ls docs/adr/ -> ARCH-002-shared-db-architecture.md, DES-005-smtp-outbound-auth.md (no repo-structure ADR)
Plan line 198: '- [ ] Step 4: Complete the internal/mdm/ -> authserver move' ($ ls mailserver/internal/mdm -> 19 files; authserver/internal/mdm -> No such file)`
- **Fix:** Either finish the outstanding items (create the ADR, delete mailserver/mobile/, complete or formally defer the mdm move) or amend the plan status to reflect what actually shipped. Do not mark plans Complete with unchecked boxes and a phantom ADR reference.
- **Verifier note:** All three factual claims verified against the tree. (1) Plan line 4 reads "All 5 tasks implemented and pushed. ADR accepted." and line 15 references "ADR-NNNN", yet `find docs/adr -type f` returns only ARCH-002 and DES-005, grep for repo-structure/binary/mailserverd/naming in docs/adr/ returns nothing (exit 1), and "ADR-NNNN" appears only in the plan itself — the ADR is a phantom placeholder. (2) 

### L47. Auth-enforcement package authserver/internal/middleware has no unit tests
- **Lens/source:** security/structure hunt → `structure-debt`
- **Location:** `authserver/internal/middleware/auth.go:14-30`
- **Issue:** authserver/internal/middleware contains only auth.go (RequireAuth - the JWT Bearer gate that rejects missing/invalid tokens and non-Access token types) and apikey.go (API-key validation used to protect the RFC 7662 token-introspection endpoint). The directory has ZERO *_test.go files (ls internal/middleware/*_test.go -> no matches). This is the authentication boundary of the auth server: a regression that, e.g., stops rejecting TypeRefresh/TypeMFAPending tokens or mishandles a malformed Authorization header would be caught by nothing here. By contrast mailserver/internal/middleware has middleware_test.go + perm_test.go.
- **Evidence:** `$ ls authserver/internal/middleware/ -> apikey.go  auth.go  (no _test.go)
if claims.Type != jwtutil.TypeAccess { http.Error(w, "Invalid token type", http.StatusForbidden) }  // untested`
- **Fix:** Add unit tests for RequireAuth (missing header, malformed Bearer, invalid signature, expired token, TypeRefresh/TypeMFAPending rejection) and for the API-key middleware (empty/wrong/correct key, constant-time compare).
- **Verifier note:** All factual claims verified. `ls authserver/internal/middleware/` shows only `apikey.go` and `auth.go`, zero `*_test.go`; `find authserver -name '*_test.go' | grep middleware` returns nothing and no test file imports `setjoin.com/authserver/internal/middleware`. The cited code at auth.go:14-30 is verbatim accurate (missing/malformed Bearer rejection, `jwt.Validate` error rejection, and `if claims.

### L48. Authenticator-interface refactor (plan Task 4) only half-done: middleware never moved to shared/middleware
- **Lens/source:** security/structure hunt → `structure-debt`
- **Location:** `mailserver/internal/middleware/auth.go:19-70`
- **Issue:** Plan Task 4 specified extracting RequireAuth/RequireRole/RequireAdmin into shared/middleware/auth.go (Step 3) so they depend on the shared Authenticator interface and can be reused. Only Step 1 (the Authenticator interface in shared/auth) was completed: mailserver/internal/middleware/auth.go now takes sharedauth.Authenticator, but the middleware functions themselves still live in mailserver/internal/middleware - shared/middleware/auth.go does not exist (ls -> No such file). So the interface extraction bought decoupling on paper but the RBAC middleware was never actually relocated/shared; authserver still carries its own separate RequireAuth. The refactor's stated goal (one shared RBAC middleware over the interface) is unrealized while the plan is marked complete.
- **Evidence:** `shared/middleware/ contains: csrf.go device_compliance.go requestid.go slow_request.go (+tests) - NO auth.go
mailserver/internal/middleware/auth.go:19  func RequireAuth(authn sharedauth.Authenticator, logger *slog.Logger) ...  // still in mailserver, not shared`
- **Fix:** Either move RequireAuth/RequireRole/RequireAdmin/RequirePerm into shared/middleware so both services share one implementation over the Authenticator interface, or update the plan/ADR to record that the middleware intentionally stays per-service and only the interface was shared.
- **Verifier note:** Every factual claim verified. shared/middleware/auth.go does not exist (ls returns "No such file"; the dir holds only csrf.go, device_compliance.go, requestid.go, slow_request.go). RequireAuth/RequireRole/RequireAdmin/RequirePerm still live in mailserver/internal/middleware/auth.go (lines 19, 45, 50, 87) and now take sharedauth.Authenticator. The plan docs/plans/archive/2026-06-10-repo-structure-n

### L49. Config env vars read by config.go are undocumented in CLAUDE.md env tables
- **Lens/source:** security/structure hunt → `structure-debt`
- **Location:** `mailserver/internal/config/config.go:413-531`
- **Issue:** config.go reads several environment variables that appear in NEITHER the 'Gateway Environment Variables' table nor elsewhere in CLAUDE.md (grep counts are 0): MINIO_ENDPOINT/MINIO_ACCESS_KEY/MINIO_SECRET_KEY/MINIO_BUCKET/MINIO_SECURE (legacy fallbacks for the S3_* vars, lines 413-429), SETJOIN_CONFIG (the config-file path, line 592), SETJOIN_DEV (line 645), WORM_LEGAL_HOLD_ENABLED (compliance toggle, line 531), and INTERNAL_DOMAINS (line 512). SETJOIN_CONFIG in particular is the primary configuration mechanism (the struct is loaded from a file), yet an operator reading CLAUDE.md would never learn it exists.
- **Evidence:** `config.go:592  configPath := os.Getenv("SETJOIN_CONFIG")
config.go:531  if _, ok := os.LookupEnv("WORM_LEGAL_HOLD_ENABLED"); !ok {
config.go:413  if v := os.Getenv("MINIO_ENDPOINT"); ...
$ grep -c 'MINIO_|SETJOIN_CONFIG|WORM_LEGAL_HOLD|INTERNAL_DOMAINS' CLAUDE.md -> 0`
- **Fix:** Document SETJOIN_CONFIG, SETJOIN_DEV, INTERNAL_DOMAINS, WORM_LEGAL_HOLD_ENABLED, and the MINIO_* legacy fallbacks (noting they are deprecated aliases of S3_*) in the Gateway Environment Variables table.
- **Verifier note:** Every cited fact is verified in mailserver/internal/config/config.go: lines 413-431 read MINIO_ENDPOINT/MINIO_ACCESS_KEY/MINIO_SECRET_KEY/MINIO_BUCKET/MINIO_SECURE as legacy fallbacks for S3_* (e.g. `if v := os.Getenv("MINIO_ENDPOINT"); cfg.S3Endpoint == "127.0.0.1:9000" && v != ""`); line 512 reads INTERNAL_DOMAINS; line 531 reads WORM_LEGAL_HOLD_ENABLED; line 592 `configPath := os.Getenv("SETJOI

## Reference docs fetched

- `docs/ref/standards/owasp-2026-asvs5-top10.md`
- `docs/ref/rfc/rfc9700.txt`
- `docs/ref/rfc/rfc8725.txt`
- `docs/ref/rfc/rfc9700-rfc8725-notes.md`
- `docs/ref/go/go-security-best-practices-2026.md`
- `docs/ref/infra/github-actions-hardening-2026.md`
- `docs/ref/infra/postgres-rls-security-definer-2026.md`
- `docs/ref/protocols/email-security-2026-update.md`

### Key takeaways from research
- Wrote docs/ref/standards/owasp-2026-asvs5-top10.md (217 lines, under the 400 cap). YAML frontmatter has source_urls + fetched: 2026-06-10. All content fetched from authoritative sources (owasp.org and raw GitHub OWASP/ASVS@v5.0.0) - nothing fabricated.
- ASVS 5.0.0 released May 2025: ~350 requirements across 17 chapters (V1-V17). Exact chapter titles captured from the repo, including the new chapters V9 Self-contained Tokens and V10 OAuth and OIDC. Each chapter now opens with a 'Documented Security Decisions' section; levels are L1/L2/L3.
- OWASP Top 10:2025 official order (confirmed from owasp.org/Top10/2025): A01 Broken Access Control (SSRF folded in), A02 Security Misconfiguration (up from #5), A03 Software Supply Chain Failures (NEW), A04 Cryptographic Failures (down from #2), A05 Injection (down from #3), A06 Insecure Design, A07 Authentication Failures (renamed), A08 Software or Data Integrity Failures, A09 Security Logging & Alerting Failures (reworded), A10 Mishandling of Exceptional Conditions (NEW).
- Note: an early secondary blog source (practical-devsecops) listed a DIFFERENT/incorrect 2025 ordering (e.g. Injection at A03, a fabricated 'Unsafe Direct Object Consumption' A10). I discarded it and used the canonical owasp.org/Top10/2025 ordering. Be cautious of third-party summaries.
- Both RFCs downloaded and verified on disk: rfc9700.txt (2569 lines, OAuth 2.0 Security BCP / BCP 240, Jan 2025) and rfc8725.txt (680 lines, JWT BCP / BCP 225). Headers confirmed (T. Lodderstedt / Y. Sheffer). Notes file is 337 lines with frontmatter source_urls + fetched: 2026-06-10.
- JWT alg/key confusion (8725 §2.1/§3.1) is already mitigated in authserver/internal/token/jwt.go:Validate — it type-asserts *jwt.SigningMethodHMAC on the HS256 path, only returns the SM2 public key for alg==SM2, and validates kid against fixed constants (kidHMAC/kidSM2). No path returns the HMAC secret for an asymmetric alg, so alg:none and RS256→HS256 swaps are blocked. golang-jwt/v5 rejects alg:none by default.
- iss and aud are enforced on both issue and verify: every issuance path sets Audience=mailserver-gateway and Validate() passes jwt.WithIssuer + jwt.WithAudience. OPEN ITEM: confirm the mailserver GATEWAY-side verifier (RequireAuth) enforces the same aud/iss and Type=access — the notes flag this as unverified because I only read the authserver side.
- Cross-JWT confusion (8725 §2.8/§3.12): the authserver mints 6+ token kinds (access, refresh, MFA-pending, force-password-change, password-reset, impersonation) that all share ONE aud and ONE HMAC key. Isolation rests entirely on the private Type claim being checked at every consumption point. Recommend auditing every accept-site and considering an explicit typ header for short-lived/one-shot kinds.
- Wrote docs/ref/go/go-security-best-practices-2026.md (277 lines, under the ~300 budget) with frontmatter source_urls + fetched: 2026-06-10. All primary sources fetched successfully via WebFetch/WebSearch; nothing was unreachable.
- govulncheck (install via `go install golang.org/x/vuln/cmd/govulncheck@latest`; run `govulncheck ./...`) does call-graph reachability analysis so it only fails CI when a vuln is actually called. It supports `-mode=binary`, `-json`, and `-format openvex` (OpenVEX justification `vulnerable_code_not_in_execute_path`). Backed by GOVULNDB at vuln.go.dev in OSV format.
- govulncheck CI guidance: doc recommends blocking on PRs OR a scheduled/cron full scan. This repo currently runs it non-blocking per-module in xinchuang-ci.yml (lines 97-103: mailserver/authserver/shared) which matches the pragmatic 'report-only PR + nightly scan' pattern — recommend pinning the action version and adding a scheduled full scan, then promote to blocking once deps stabilize.
- golangci-lint CI speed: the #1 fix is persisting cache ($GOLANGCI_LINT_CACHE + Go build cache) — first run is always slow because it builds full type info/SSA. The golangci/golangci-lint-action has caching ON by default (do not set skip-cache). Second biggest win is lint only the diff.
- Wrote docs/ref/infra/github-actions-hardening-2026.md (255 lines, verified via wc -l), a 9-section repo-tailored checklist with frontmatter source_urls + fetched: 2026-06-10. All 7 source URLs fetched successfully; nothing fabricated.
- [P0] Both workflows pin actions only to floating tags; dtolnay/rust-toolchain@stable is a moving BRANCH ref (worst case). GitHub: SHA pinning is 'the only way to use an action as an immutable release.' Checklist gives the table of every action to pin (checkout@v5, setup-go@v6, upload/download-artifact@v4) plus the SHA-with-version-comment pattern for Dependabot.
- [P0] GITHUB_TOKEN permissions: release.yml sets top-level `permissions: contents: write` so all 5 build jobs inherit release-write unnecessarily — move write down to only the github-release job, default top-level to `contents: read`. xinchuang-ci.yml has NO permissions block at all (inherits repo default) — add explicit `permissions: contents: read`.
- [P1] Release artifact provenance: add actions/attest-build-provenance@<sha> # v3 with permissions id-token: write + attestations: write + contents: read and subject-path globbing the dmg/msi/AppImage/deb/rpm; consumers verify via `gh attestation verify <artifact> -R setjoin/setjoin`. Keyless Sigstore via OIDC, no long-lived key. Apply same to xinchuang cross-build binaries for certification trail. Note: existing Apple/GPG signing steps use continue-on-error:true so unsigned releases can ship silently.
- Wrote docs/ref/infra/postgres-rls-security-definer-2026.md (254 lines, verified via wc -l). Confirmed current PostgreSQL is 18 (PG 19 beta1 released 2026-06-04) from postgresql.org/docs/current/release.html. All 5 substantive pages fetched successfully via WebFetch.
- RLS for reducers needs BOTH ENABLE and FORCE ROW LEVEL SECURITY: SECURITY DEFINER reducers run as the owner, and owners bypass RLS by default unless FORCE is set. ENABLE without a policy is default-deny (no rows visible/modifiable).
- Tenant key pattern: set_config('app.account_id', p_account_id::text, true) at reducer entry (txn-local), then policy USING (account_id = current_setting('app.account_id')::bigint). Keep the predicate index-aligned and state WITH CHECK explicitly so UPDATE cannot move a row to another tenant (USING is only implicitly reused as WITH CHECK).
- Policy combination rule: effective predicate = (all RESTRICTIVE AND'd) AND (any PERMISSIVE OR'd); at least one PERMISSIVE must pass or zero rows are accessible. Default class is PERMISSIVE. RLS performance: predicates run per-row before user WHERE; avoid per-row subqueries (race + FOR SHARE locks). LEAKPROOF functions/operators may run BEFORE the policy filter; RI checks (UNIQUE/PK/FK/TRUNCATE) bypass RLS, so use surrogate keys to avoid duplicate-key existence leaks.
- SMTP smuggling vector is LIVE in SetJoin inbound: inbound.go:498 uses Go's net/textproto DotReader, whose implementation (go.dev/src/net/textproto/reader.go) leniently accepts bare \n as a line terminator and \n.\n as end-of-data — the exact SEC Consult 2023 / CVE-2023-51764/65/66 vector. validateLineLengths (helpers.go:125) is a length check only and does NOT guard against bare LF. Fix: scan raw DATA for any \n not preceded by \r (and lone \r) and reject (550) or normalize to CRLF before trusting dot framing. Add a regression test feeding <LF>.<LF> and <LF>.<CR><LF> mid-DATA.
- STARTTLS buffer discard is implemented CORRECTLY on the SMTP inbound side: inbound.go:320-329 builds a fresh textproto.NewConn(tlsConn) and calls c.reset() after the handshake, discarding the pre-TLS read buffer — the right mitigation for the nostarttls/CERT VU#555316 class and the new MailKit CVE-2026-41319 (unflushed buffer → SASL downgrade). Keep it; verify nothing reads c.tp between the 220 reply and the handshake, and confirm the internal/imap STARTTLS path does the identical reset (IMAP/POP3 are equally exposed — Apache James CVE-2021-38542).
- Outbound envelope CRLF injection needs a guard: outbound.go:482/489 call tp.Cmd("MAIL FROM:<%s>", from) and tp.Cmd("RCPT TO:<%s>", rcpt). If from/rcpt contain bare \r or \n, an attacker can split one SMTP command into two (the 2024-2026 wave: Symfony CVE-2026-45067, MimeKit GHSA-g7hc-96xr-gvvx, Netty, libcurl 8.16.0 DSN suffix). Reject control chars in addresses before they reach Cmd; add a unit test for an embedded \r\nDATA address.
- ARC verification: inbound.go:647 calls sealARC (defined inbound.go:860) and rebuilds trace/Received headers from the sealed bytes. Confirm ARC-Seal is computed over the final message including the just-added Received/Authentication-Results in correct i= instance order, that an existing inbound ARC chain (cv=) is evaluated per RFC 8617 §5 rather than blindly overwritten, and that sealing runs after SPF/DKIM/DMARC but before trace-header injection. Treat a valid ARC chain as supporting evidence only — DMARC alignment still governs accept/reject.
