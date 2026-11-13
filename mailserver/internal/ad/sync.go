package ad

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"setjoin.com/mailserver/internal/directorysync"
	"setjoin.com/mailserver/internal/identitysource"
	"setjoin.com/mailserver/internal/ldaputil"
	"setjoin.com/shared/identity"
	"setjoin.com/shared/reducererr"
)

type directoryClient interface {
	connect() (*ldap.Conn, error)
	Bind(*ldap.Conn) error
	SearchUsers(context.Context, *ldap.Conn, int64) ([]ADUser, int64, error)
}

type SyncWorker struct {
	client    directoryClient
	pool      *pgxpool.Pool
	logger    *slog.Logger
	interval  time.Duration
	source    directorysync.PageStore
	sourceKey string
	instance  uuid.UUID
	enabled   func() bool
	// syncLogAppended, when non-nil, receives the id of every identity_sync_log
	// row this worker's legacy sync appends — reported straight from the
	// INSERT's RETURNING clause (the actual writer), so a test fixture can own
	// EXACTLY the rows its own runs created and never a watermark range that a
	// concurrent run's rows also satisfy (D-3).
	syncLogAppended func(id int64)
}

// SetEnabledResolver binds every cycle to the current feature decision. The
// handler also cancels disabled worker generations; this is the last-resort
// fence for a cycle that was already scheduled.
func (w *SyncWorker) SetEnabledResolver(enabled func() bool) {
	w.enabled = enabled
}

// SetIdentitySource enables the normalized I2 inbox/cursor path. It is kept as
// an explicit setter during the dual-write window so old binaries and tests
// retain the legacy singleton path until the source catalog is activated.
func (w *SyncWorker) SetIdentitySource(store *identitysource.Store, sourceKey string) {
	if store == nil {
		w.source = nil
		w.sourceKey = ""
		return
	}
	w.source = store
	w.sourceKey = sourceKey
	if w.instance == uuid.Nil {
		w.instance = uuid.New()
	}
}

func NewSyncWorker(client *Client, pool *pgxpool.Pool, logger *slog.Logger, intervalMin int) *SyncWorker {
	return &SyncWorker{
		client:   client,
		pool:     pool,
		logger:   logger,
		interval: time.Duration(intervalMin) * time.Minute,
	}
}

func (w *SyncWorker) Run(ctx context.Context) {
	w.logger.Info("AD sync worker started", "interval", w.interval)
	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()

	// Run immediately on start
	w.runCycle(ctx)

	for {
		select {
		case <-ctx.Done():
			w.logger.Info("AD sync worker stopped")
			return
		case <-ticker.C:
			w.runCycle(ctx)
		}
	}
}

func (w *SyncWorker) runCycle(ctx context.Context) {
	if _, err := w.sync(ctx); err != nil && w.logger != nil {
		w.logger.Error("AD sync cycle failed", "error", err)
	}
}

func (w *SyncWorker) SyncNow(ctx context.Context) (SyncResult, error) {
	return w.sync(ctx)
}

// DryRunResult is the "Test connection" outcome: connectivity + a count. ZERO
// directory or database writes — contrast with the old TestConnection, which
// called SyncNow and mutated the users table under the name "Test".
type DryRunResult struct {
	Checked int `json:"checked"`
}

// DryRun binds to the directory and reads the user set WITHOUT any DB write:
// no upsertUser, no cursor write, no identity_sync_log insert. Safe to call
// from the admin "Test connection" button before sync is enabled. ctx is
// honored by SearchUsers between pages (mirrors the ldapsync sibling and the
// handler's r.Context() call).
//
// ponytail: cursor 0 = full read (no size cap), matching sync()'s and
// ldapsync's accepted 300–10k-user-scale tradeoff; add a size limit if
// directories grow large enough for that to matter.
func (w *SyncWorker) DryRun(ctx context.Context) (DryRunResult, error) {
	conn, err := w.client.connect()
	if err != nil {
		return DryRunResult{}, err
	}
	defer func() { _ = conn.Close() }()

	if err := w.client.Bind(conn); err != nil {
		return DryRunResult{}, err
	}

	users, _, err := w.client.SearchUsers(ctx, conn, 0)
	if err != nil {
		return DryRunResult{}, err
	}
	return DryRunResult{Checked: len(users)}, nil
}

// SyncResult aliases the shared type so both engines emit identical
// identity_sync_log JSON without duplicating the struct.
type SyncResult = ldaputil.SyncResult

func (w *SyncWorker) sync(ctx context.Context) (SyncResult, error) {
	if w.enabled != nil && !w.enabled() {
		return SyncResult{Skipped: 1}, nil
	}
	if w.source != nil {
		return w.syncNormalized(ctx)
	}
	start := time.Now()
	var result SyncResult

	conn, err := w.client.connect()
	if err != nil {
		w.logger.Error("AD sync: connect failed", "error", err)
		return result, err
	}
	defer func() { _ = conn.Close() }()

	if err := w.client.Bind(conn); err != nil {
		w.logger.Error("AD sync: bind failed", "error", err)
		return result, err
	}

	// Read cursor
	var cursor int64
	if err := w.pool.QueryRow(ctx,
		`SELECT COALESCE((value #>> '{}')::BIGINT, 0) FROM system_config WHERE key = 'ad_sync_last_usn'`,
	).Scan(&cursor); err != nil {
		return result, fmt.Errorf("AD sync: read cursor: %w", err)
	}

	users, maxUSN, err := w.client.SearchUsers(ctx, conn, cursor)
	if err != nil {
		w.logger.Error("AD sync: search failed", "error", err)
		return result, err
	}

	result.Checked = len(users)

	autoDepts := ldaputil.GetBoolConfig(ctx, w.pool, "ad_sync_auto_create_depts")
	proxyAliases := ldaputil.GetBoolConfig(ctx, w.pool, "ad_sync_proxy_as_aliases")

	for _, u := range users {
		if err := w.upsertUser(ctx, u, autoDepts, proxyAliases, &result); err != nil {
			result.Errors++
			w.logger.Warn("AD sync: upsert failed", "user", u.Email, "error", err)
		}
	}

	w.resolveManagerIDs(ctx, users)

	// Update cursor
	if maxUSN > cursor && result.Errors == 0 {
		if _, err := w.pool.Exec(ctx,
			`INSERT INTO system_config (key, value, description) VALUES ('ad_sync_last_usn', $1, 'AD uSNChanged cursor')
			 ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now()`,
			fmt.Sprintf("%d", maxUSN),
		); err != nil {
			return result, fmt.Errorf("AD sync: update cursor: %w", err)
		}
	}

	// Log sync run. The appended row's id is RETURNED so a registered
	// syncLogAppended observer owns exactly what THIS run wrote (D-3) — no
	// watermark range that a concurrent run's rows also satisfy.
	var syncLogID int64
	if err := w.pool.QueryRow(ctx,
		`INSERT INTO identity_sync_log (
			source, users_checked, users_created, users_updated, users_disabled,
			fields_skipped, duration_ms, error, details
		) VALUES ($1, $2, $3, $4, $5, $6, $7, NULLIF($8, ''), $9)
		 RETURNING id`,
		"ad", result.Checked, result.Created, result.Updated, result.Disabled,
		result.Skipped, int(time.Since(start).Milliseconds()), ldaputil.SyncErrorSummary(result.Errors),
		fmt.Sprintf(`{"cursor_before":%d,"cursor_after":%d}`, cursor, maxUSN),
	).Scan(&syncLogID); err != nil {
		w.logger.Warn("AD sync: failed to insert sync log", "error", err)
	} else if w.syncLogAppended != nil {
		w.syncLogAppended(syncLogID)
	}

	result.Duration = time.Since(start).String()
	return result, nil
}

func (w *SyncWorker) syncNormalized(ctx context.Context) (SyncResult, error) {
	return (directorysync.Engine{
		Store:       w.source,
		Connector:   normalizedConnector{client: w.client},
		SourceKey:   w.sourceKey,
		Instance:    w.instance,
		Logger:      w.logger,
		Quarantines: directorysync.PgxQuarantineStore{Pool: w.pool},
	}).Sync(ctx)
}

func (w *SyncWorker) upsertUser(ctx context.Context, u ADUser, autoDepts, proxyAliases bool, result *SyncResult) error {
	// Deprovisioning is security-relevant and must stay reachable
	// (D-MAILSERVER-INTERNAL-AD-002): a directory-disabled entry whose mail
	// attribute was CLEARED still carries its ad_object_guid, so the disable
	// arm below runs keyed on the GUID even without an email. Only the
	// attribute-sync/provision machinery needs an address, so the guard is
	// provision-only: an empty-email, still-enabled entry keeps skipping sync
	// exactly as before.
	if u.Email == "" && !u.Disabled {
		return nil
	}

	var deptID *int64
	if autoDepts && u.Department != "" && u.Email != "" {
		var id int64
		err := w.pool.QueryRow(ctx,
			`INSERT INTO departments (name,path,ldap_ou) VALUES ($1,$1,$1)
				 ON CONFLICT (path) DO UPDATE SET
				     name = EXCLUDED.name,
				     ldap_ou = EXCLUDED.ldap_ou
				 RETURNING id`, u.Department,
		).Scan(&id)
		if err == nil {
			deptID = &id
		}
	}

	var localOverrides map[string]interface{}
	var overrides []byte
	_ = w.pool.QueryRow(ctx,
		`SELECT local_overrides::TEXT::BYTEA FROM users WHERE ad_object_guid = $1`, u.ObjectGUID,
	).Scan(&overrides)
	if len(overrides) > 2 {
		_ = json.Unmarshal(overrides, &localOverrides)
	}

	var existingID int64
	err := w.pool.QueryRow(ctx,
		`SELECT id FROM users WHERE ad_object_guid = $1`, u.ObjectGUID,
	).Scan(&existingID)

	if err != nil {
		// New directory entry: creation requires an address (the canonicalizer
		// and provision_account are email-keyed). An empty-email entry that is
		// not in the local DB has nothing to disable locally — skip it.
		if u.Email == "" {
			return nil
		}
		// New AD user: provision the person + their primary mailbox via the
		// single seam. The previous hand-rolled INSERT omitted the NOT NULL
		// `username` and `domain_id` columns and never created a primary
		// mailbox (so proxyAddress aliases had nothing to attach to and the
		// address received no mail). provision_account fixes all three.
		//
		// CANONICAL WRITE: the verbatim AD attributes u.Email / u.UPN are routed
		// through the ONE canonicalizer (identity.CanonicalizeAddress). The
		// ProvisionAccount Email param is ValidatedAddress and ADUPN is
		// CanonicalAddress, so binding a raw u.Email / u.UPN here would not compile
		// — that is what makes users.email / users.ad_upn Go-canonical BY
		// CONSTRUCTION and retires fold_stored_address's live-twin role (a
		// TAB-prefixed / mixed-case UPN from AD is trimmed + ASCII-folded before
		// the write, so the matcher can't match-miss it).
		//
		// AD is a TRUSTED DIRECTORY source: its `mail` attribute may legitimately
		// not pass RFC-5321, so Email is lifted via the named validation-free
		// CanonicalAddress.AssumeValidated escape (NOT ValidateAndCanonicalizeEmail
		// — that would reject valid directory rows). Directory sync stays
		// validation-free, exactly as before ValidatedAddress existed.
		enabled := !u.Disabled
		objectGUID := u.ObjectGUID
		usnChanged := u.USNChanged
		// Directory mirror sync: intentionally NO welcome email. The initial mirror
		// creates every existing directory user as created=true; sending welcomes
		// here would flood the whole org (spec §7). Welcomes are interactive-only.
		var res []byte
		if res, err = identity.ProvisionAccount(ctx, w.pool, identity.ProvisionAccountParams{
			Email:        identity.CanonicalizeAddress(u.Email).AssumeValidated(),
			ADUPN:        identity.CanonicalizeAddress(u.UPN),
			DisplayName:  u.DisplayName,
			Enabled:      &enabled,
			SyncSource:   "ad",
			FirstName:    u.FirstName,
			LastName:     u.LastName,
			JobTitle:     u.Title,
			Phone:        u.Phone,
			DepartmentID: deptID,
			// krb5_principal keeps the RAW UPN: a Kerberos principal's realm is
			// case-sensitive by convention (alice@CORP.EXAMPLE.COM), so it is
			// NOT an address column and must NOT be ASCII-folded. Only the
			// match column ad_upn is canonicalized.
			Krb5Principal: u.UPN,
			ADObjectGUID:  &objectGUID,
			ADUSNChanged:  &usnChanged,
		}); err != nil {
			return err
		}
		// provision_account locates an existing person by GUID → SCIM id →
		// email. This branch ran because the GUID was unmatched, so
		// created=false means the reducer fell through to an existing-email
		// match and took its UPDATE branch: the row adopted the GUID and the
		// reducer's floor-protected SET list left krb5_principal untouched —
		// the SQL mirror of ldaputil's always-local-only floor, so a
		// directory UPN can never rewrite the SSO identity of an existing
		// account through the provisioner (the same guarantee ApplyUserUpdate
		// enforces on the matched-GUID path). Only a genuine INSERT counts as
		// a created user.
		var provisioned struct {
			Created bool `json:"created"`
		}
		if err := json.Unmarshal(res, &provisioned); err != nil {
			return fmt.Errorf("AD sync: decode provision_account result for %s: %w", u.Email, err)
		}
		if provisioned.Created {
			result.Created++
		} else {
			result.Updated++
		}
		if proxyAliases && len(u.ProxyAddresses) > 0 {
			// Look up the freshly-created user id to attach proxy aliases.
			var newID int64
			if err := w.pool.QueryRow(ctx,
				`SELECT id FROM users WHERE ad_object_guid = $1`, u.ObjectGUID,
			).Scan(&newID); err == nil {
				w.syncProxyAliases(ctx, newID, u, result)
			}
		}
		return nil
	}

	// Deprovisioning is security-relevant: a DB error must NOT be swallowed and
	// counted as a success. DisableUser returns wrapped errors; the caller counts
	// them as result.Errors, never result.Disabled. This arm is deliberately
	// BEFORE any email requirement — it is keyed on ad_object_guid, so a
	// directory-disabled entry with a cleared mail attribute still deprovisions
	// instead of silently keeping an enabled local account with live sessions.
	if u.Disabled {
		if err := ldaputil.DisableUser(ctx, w.pool, existingID); err != nil {
			return err
		}
		result.Disabled++
		return nil
	}

	localOnlyFields, err := w.getLocalOnlyFields(ctx, existingID)
	if err != nil {
		// Fail closed (D-MAILSERVER-INTERNAL-AD-003): a transient DB error in
		// the field_policy read must NOT collapse to "no locks" and overwrite
		// admin-locked local_only fields (including krb5_principal) with
		// directory values. Returning the error counts it in result.Errors,
		// which gates the cursor advance — the same discipline as DisableUser.
		return err
	}

	// Sync attributes, respecting local overrides and field policy. AD carries one
	// extra column beyond the shared set: its uSNChanged cursor watermark.
	if err := ldaputil.ApplyUserUpdate(ctx, w.pool, existingID, buildSyncAttrs(u),
		localOnlyFields, localOverrides, deptID, "ad",
		map[string]interface{}{"ad_usn_changed": u.USNChanged}, result, w.logger); err != nil {
		return err
	}

	if proxyAliases && len(u.ProxyAddresses) > 0 {
		w.syncProxyAliases(ctx, existingID, u, result)
	}

	return nil
}

// syncProxyAliases populates the aliases table from a user's AD proxyAddresses.
//
// Only SMTP proxy entries (`smtp:`/`SMTP:` prefix) become aliases; non-SMTP
// types (X400:, X500:, sip:, …) are skipped. Each alias is keyed to the user's
// primary mailbox and its address domain must be a local domain — if the user
// has no primary mailbox yet, or the alias domain is not local, that alias is
// logged and skipped rather than failing the whole user sync. The insert is
// idempotent via the case-insensitive UNIQUE index on aliases.lower(email).
//
// ADMISSION DISPOSITION (V249 + L2-C3 r2/r3): the aliases BEFORE-row trigger
// (trg_identity_address_admission_aliases) is the SOLE admission authority —
// this writer runs no precheck of its own, checks no enabledness, and never
// re-derives the enabled-claimant union; every alias passes trigger + INSERT
// unchanged. Outcomes are classified, not redirected:
//
//   - BZ328 (another ENABLED person claims the address through
//     users.email/users.ad_upn/an alias): an expected rejection of
//     directory-supplied data by the authoritative DB contract. Logged as a
//     rejected-by-admission warn (user, alias, rejection kind) and counted as
//     result.Skipped — NOT result.Errors — so the uSN cursor keeps advancing
//     (sync only advances it when result.Errors == 0). Remaining safe aliases
//     of the same user and all subsequent users continue to process; the sync
//     never fails the page on one directory-supplied address.
//   - INSERT reaches the index and lands on ON CONFLICT DO NOTHING (0 rows
//     affected — the surviving row's holder is not an enabled claimant, e.g. a
//     disabled person's alias): classified by reading the surviving row's
//     mailbox + owner back through mailboxes.user_id. Same person (any of
//     their mailboxes) → same-person idempotency, silent. Anything else keeps
//     the address — a different holder, or a NULL binding: a retained mailbox
//     (mailbox_lifecycle detach_retain) legitimately keeps aliases after
//     mailboxes.user_id is cleared, and that NULL is OCCUPIED, never the
//     syncing person. Logged occupied-alias no-op, counted result.Skipped. The
//     occupied row is NEVER transferred, reassigned, or rewritten — alias
//     ownership changes belong to V249's re-enable/revival contract, never
//     this writer.
//   - Any other INSERT error: today's shape (logged warn, sync continues) —
//     this writer does not redefine general alias-failure accounting.
//
// result must be non-nil (the caller's sync accounting).
func (w *SyncWorker) syncProxyAliases(ctx context.Context, userID int64, u ADUser, result *SyncResult) {
	// Resolve the user's primary mailbox once — aliases hang off the mailbox,
	// not the user (the aliases table has no user_id column).
	mailboxID, err := identity.ResolvePrimaryMailbox(ctx, w.pool, userID)
	if err != nil {
		w.logger.Warn("AD sync: no primary mailbox for user; skipping proxy aliases",
			"user", u.Email, "id", userID, "error", err)
		return
	}

	primary := strings.ToLower(u.Email)
	for _, parsed := range parseProxyAliases(u.ProxyAddresses, primary) {
		// parseProxyAliases lowercases+trims, but that is NOT the identity fold
		// (no ASCII-fold-only guarantee, no RFC-5322 display-name strip). Route
		// through the one canonicalizer so aliases.email matches the users.email
		// fold the matcher resolves against.
		addr := identity.CanonicalizeAddress(parsed).String()
		domain := addr[strings.LastIndexByte(addr, '@')+1:]

		var domainID int64
		err := w.pool.QueryRow(ctx,
			`SELECT id FROM domains WHERE lower(name) = $1 AND is_local = TRUE LIMIT 1`,
			domain,
		).Scan(&domainID)
		if err != nil {
			// Non-local (or unknown) domain — skip this alias, keep syncing.
			w.logger.Warn("AD sync: proxy alias domain not local; skipping alias",
				"user", u.Email, "alias", addr, "domain", domain)
			continue
		}

		tag, err := w.pool.Exec(ctx,
			// Idempotent: aliases has a case-insensitive UNIQUE index on
			// lower(email) (migration V054), so re-syncs are no-ops. The V249
			// admission trigger (BZ328) fires BEFORE this index for enabled
			// competing claimants.
			`INSERT INTO aliases (mailbox_id, email, domain_id)
			 VALUES ($1, $2, $3)
			 ON CONFLICT (lower(email)) DO NOTHING`,
			mailboxID, addr, domainID,
		)
		if err != nil {
			if kind, admission := admissionConflictKind(err); admission {
				// Expected rejection of directory-supplied data by the
				// authoritative admission trigger — skip + count, never fail
				// the user or the page.
				w.logger.Warn("AD sync: proxy alias rejected by identity address admission",
					"user", u.Email, "alias", addr, "rejection", kind)
				result.Skipped++
				continue
			}
			// Non-admission DB fault — unchanged shape: logged warn, sync
			// continues, general alias-failure accounting untouched.
			w.logger.Warn("AD sync: failed to upsert proxy alias",
				"user", u.Email, "alias", addr, "error", err)
			continue
		}
		if tag.RowsAffected() == 0 {
			// DO NOTHING fired: an aliases row with this lower(email) already
			// exists and no enabled claimant tripped BZ328. The readback is
			// outcome classification only — it exempts no insert and checks no
			// enabledness; the DB trigger already ruled.
			heldMailbox, owner, readErr := aliasOwner(ctx, w.pool, addr)
			if readErr != nil {
				w.logger.Warn("AD sync: occupied proxy alias could not be classified",
					"user", u.Email, "alias", addr, "error", readErr)
				continue
			}
			if owner != nil && *owner == userID {
				// Same-person idempotency: the trigger excludes the owner, so
				// an alias colliding only with its own person's claims lands
				// here on re-syncs. A NULL binding is nobody — only a real
				// match counts. Silent no-op — no warn.
				continue
			}
			// A different holder keeps the address — including a retained
			// mailbox whose user binding was cleared (NULL mailboxes.user_id):
			// that row is OCCUPIED and must reach the Skipped accounting, not
			// escape it as an unclassifiable readback. No transfer, no
			// reassignment — the existing row stays exactly as it is.
			w.logger.Warn("AD sync: proxy alias already held by another owner; leaving occupied alias untouched",
				"user", u.Email, "alias", addr,
				"holder_mailbox_id", heldMailbox, "holder_user_id", owner)
			result.Skipped++
		}
	}
}

// aliasOwner resolves which person (if any) an existing alias row belongs to,
// through mailboxes.user_id — so a same-person alias on ANY of the person's
// mailboxes classifies as same-person (unequal mailbox ids alone do not
// establish different people). ownerUserID is NULL when the surviving mailbox
// has no user binding: a retained mailbox (mailbox_lifecycle detach_retain)
// legitimately keeps aliases after that binding is cleared, so the NULL must
// come back as an explicit nil — scanning it into int64 would fail the readback
// and let the occupied row escape Skipped accounting. The mailbox id travels
// with it because a NULL-bound row has no holder person to name in the warn.
// Classification seam only; it never gates an insert.
func aliasOwner(ctx context.Context, pool *pgxpool.Pool, addr string) (mailboxID int64, ownerUserID *int64, err error) {
	err = pool.QueryRow(ctx,
		`SELECT a.mailbox_id, m.user_id FROM aliases a
		 JOIN mailboxes m ON m.id = a.mailbox_id
		 WHERE lower(a.email) = $1`, addr,
	).Scan(&mailboxID, &ownerUserID)
	return mailboxID, ownerUserID, err
}

// admissionConflictKind reports whether err is the V249 identity-address
// admission rejection — ERRCODE 'BZ328' carrying the
// {"type":"identity_address_admission_conflict"} HINT — and returns its kind
// for the warn log. Every other error (including non-pg errors and other
// constraints) is reported as not-admission so general alias-failure
// accounting stays untouched.
func admissionConflictKind(err error) (string, bool) {
	// Semantic BZ-code branch goes through the shared contract seam
	// (check-reducererr-contract): IsCode unwraps the pg error and compares
	// against the catalogue without hand-rolling a .Code literal compare.
	if reducererr.IsCode(err, "BZ328") {
		return "identity_address_admission_conflict", true
	}
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) {
		return "", false
	}
	var hint struct {
		Type string `json:"type"`
	}
	if json.Unmarshal([]byte(pgErr.Hint), &hint) == nil && hint.Type == "identity_address_admission_conflict" {
		return hint.Type, true
	}
	return "", false
}

// parseProxyAliases normalizes a user's AD proxyAddresses into the set of
// local-part@domain SMTP aliases to persist. It keeps only SMTP entries
// (`smtp:` primary / `SMTP:` reply — case-insensitive prefix), lowercases the
// address, skips the user's own primary address, requires a single `@`, and
// de-duplicates. Non-SMTP proxy types (X400:, X500:, sip:, …) are dropped.
// Pure function — no DB access — so the parsing rules are unit-testable.
func parseProxyAliases(proxyAddresses []string, primaryEmail string) []string {
	primaryEmail = strings.ToLower(primaryEmail)
	seen := make(map[string]struct{}, len(proxyAddresses))
	var out []string
	for _, pa := range proxyAddresses {
		// Prefix is case-insensitive: "SMTP:" marks the primary, "smtp:" a
		// secondary address; both are real mail addresses.
		if len(pa) < 5 || !strings.EqualFold(pa[:5], "smtp:") {
			continue // not an SMTP proxy entry (X400:, X500:, sip:, raw, …)
		}
		addr := strings.ToLower(strings.TrimSpace(pa[5:]))
		if addr == "" || addr == primaryEmail {
			continue
		}
		// Require exactly one "@" with a non-empty local part and domain.
		at := strings.IndexByte(addr, '@')
		if at <= 0 || at != strings.LastIndexByte(addr, '@') || at == len(addr)-1 {
			continue
		}
		if _, dup := seen[addr]; dup {
			continue
		}
		seen[addr] = struct{}{}
		out = append(out, addr)
	}
	return out
}

// resolveManagerIDs is pass 2 of the AD sync: resolves each user's ManagerDN to a
// DB user_id via an in-memory DN→id map built from the sync set, then sets
// users.manager_id. Managers outside the sync scope are silently skipped (NULL).
func (w *SyncWorker) resolveManagerIDs(ctx context.Context, users []ADUser) {
	guids := make([]string, 0, len(users))
	for _, u := range users {
		if u.ObjectGUID != "" {
			guids = append(guids, u.ObjectGUID)
		}
	}
	if len(guids) == 0 {
		return
	}

	// ponytail: clears stale manager links on every re-sync — departed/out-of-scope managers become NULL.
	if _, err := w.pool.Exec(ctx,
		`UPDATE users SET manager_id = NULL WHERE ad_object_guid = ANY($1::uuid[])`, guids,
	); err != nil {
		w.logger.Warn("AD sync: manager pass: failed to clear stale manager_ids", "error", err)
		return
	}

	// Batch-fetch guid → DB id for the whole sync set.
	guidToID := make(map[string]int64, len(guids))
	rows, err := w.pool.Query(ctx,
		`SELECT ad_object_guid::TEXT, id FROM users WHERE ad_object_guid = ANY($1::uuid[])`, guids)
	if err != nil {
		w.logger.Warn("AD sync: manager pass: failed to fetch user ids", "error", err)
		return
	}
	defer rows.Close()
	for rows.Next() {
		var guid string
		var id int64
		if err := rows.Scan(&guid, &id); err == nil {
			guidToID[guid] = id
		}
	}
	if err := rows.Err(); err != nil {
		w.logger.Warn("AD sync: manager pass: row iteration error", "error", err)
		return
	}

	// Build normalized DN → user_id.
	dnToID := make(map[string]int64, len(users))
	for _, u := range users {
		if u.DN == "" {
			continue
		}
		if id, ok := guidToID[u.ObjectGUID]; ok {
			dnToID[ldaputil.NormalizeDN(u.DN)] = id
		}
	}

	// Update manager_id for each user whose manager is in the sync set.
	for _, u := range users {
		if u.ManagerDN == "" {
			continue
		}
		selfID, ok := guidToID[u.ObjectGUID]
		if !ok {
			continue
		}
		managerID, ok := dnToID[ldaputil.NormalizeDN(u.ManagerDN)]
		if !ok {
			continue // manager outside scope — leave NULL, no error
		}
		if _, err := w.pool.Exec(ctx,
			`UPDATE users SET manager_id = $1 WHERE id = $2`, managerID, selfID,
		); err != nil {
			w.logger.Warn("AD sync: failed to update manager_id",
				"user_id", selfID, "manager_id", managerID, "error", err)
		}
	}
}

// buildSyncAttrs returns the AD attributes to sync to the users table. The email
// is canonicalized through the ONE seam before it reaches the UPDATE-path writer
// (SyncAttrs demands CanonicalAddress), so users.email stays Go-canonical on
// every sync, not just first provision.
func buildSyncAttrs(u ADUser) map[string]string {
	return ldaputil.SyncAttrs(identity.CanonicalizeAddress(u.Email), u.DisplayName,
		u.FirstName, u.LastName, u.Title, u.Phone, u.UPN)
}

// getLocalOnlyFields returns the set of fields locked as local_only for a
// user. It FAILS CLOSED (D-MAILSERVER-INTERNAL-AD-003): a query or scan error
// is returned to the caller instead of collapsing to the always-local floor,
// because "no locks" on a degraded read would let one sync run overwrite
// admin-locked fields with directory values.
func (w *SyncWorker) getLocalOnlyFields(ctx context.Context, userID int64) (map[string]bool, error) {
	rows, err := w.pool.Query(ctx,
		`SELECT field FROM field_policy WHERE user_id = $1 AND policy = 'local_only'`, userID)
	if err != nil {
		return nil, fmt.Errorf("read field_policy for user %d: %w", userID, err)
	}
	defer rows.Close()
	fields, err := ldaputil.ScanFieldPolicyRows(rows)
	if err != nil {
		return nil, fmt.Errorf("scan field_policy for user %d: %w", userID, err)
	}
	// Code-level custody floor: krb5_principal is the SSO authentication
	// identity and is never sync-writable on an existing user. field_policy can
	// add more local-only fields; it can never unlock this one (an explicit
	// 'ad_managed' row is filtered out by the merge).
	return ldaputil.EnforceAlwaysLocalOnly(fields), nil
}
