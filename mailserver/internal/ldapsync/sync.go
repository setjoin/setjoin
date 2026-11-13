package ldapsync

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"setjoin.com/mailserver/internal/directorysync"
	"setjoin.com/mailserver/internal/identitysource"
	"setjoin.com/mailserver/internal/ldaputil"
	"setjoin.com/shared/identity"
)

// SyncResult aliases the shared type so both engines emit identical
// identity_sync_log JSON without duplicating the struct.
type SyncResult = ldaputil.SyncResult

// defaultAbsenceSweepHours is the default cadence for the absent-entry
// deprovisioning sweep (LDAPSYNC-003). Overridable (and disable-able with 0)
// via the ldap_sync_absence_sweep_hours system_config key.
const defaultAbsenceSweepHours = 24

// SyncWorker runs periodic LDAP sync operations.
type directoryClient interface {
	Connect() (*ldap.Conn, error)
	Bind(*ldap.Conn) error
	SearchUsers(*ldap.Conn, string, int) ([]LDAPUser, error)
	SubjectAttribute() string
}

type SyncWorker struct {
	client    directoryClient
	pool      *pgxpool.Pool
	logger    *slog.Logger
	interval  time.Duration
	filter    string // custom search filter; empty = SearchUsers' (objectClass=person) default
	source    directorysync.PageStore
	sourceKey string
	instance  uuid.UUID
	enabled   func() bool
}

// SetEnabledResolver binds every mutating cycle to the current feature
// decision. DryRun and Preview intentionally bypass this resolver so an
// administrator can validate a configured directory before enabling sync.
func (w *SyncWorker) SetEnabledResolver(enabled func() bool) {
	w.enabled = enabled
}

// SetIdentitySource enables the normalized, generation-fenced inbox path.
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

func (w *SyncWorker) SubjectAttributeConfigured() bool {
	return w.client.SubjectAttribute() != ""
}

// NewSyncWorker creates a sync worker.
func NewSyncWorker(client *Client, pool *pgxpool.Pool, logger *slog.Logger, intervalMin int) *SyncWorker {
	return &SyncWorker{
		client:   client,
		pool:     pool,
		logger:   logger,
		interval: time.Duration(intervalMin) * time.Minute,
	}
}

// SetFilter overrides the default (objectClass=person) directory search
// filter — the admin console's "filter" field (system_config
// ldap_sync_user_filter). Empty resets to the default. Invalid filters fail at
// config admission rather than after a worker generation has started.
func (w *SyncWorker) SetFilter(filter string) error {
	if filter != "" {
		if _, err := ldap.CompileFilter(filter); err != nil {
			return fmt.Errorf("invalid LDAP user filter: %w", err)
		}
	}
	w.filter = filter
	return nil
}

// buildSyncFilter composes sync()'s effective search filter: base (the
// admin's override, or the (objectClass=person) default when empty) AND'd
// with an incremental modifyTimestamp bound when a cursor is present.
func buildSyncFilter(base, cursor string) string {
	if base == "" {
		base = "(objectClass=person)"
	}
	if cursor == "" {
		return base
	}
	return fmt.Sprintf("(&%s(modifyTimestamp>=%s))", base, cursor)
}

// Run starts the periodic sync loop. Blocks until ctx is cancelled.
func (w *SyncWorker) Run(ctx context.Context) {
	w.logger.Info("LDAP sync worker started", "interval", w.interval)
	w.runCycle(ctx)

	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			w.logger.Info("LDAP sync worker stopped")
			return
		case <-ticker.C:
			w.runCycle(ctx)
		}
	}
}

func (w *SyncWorker) runCycle(ctx context.Context) {
	if _, err := w.sync(ctx); err != nil && w.logger != nil {
		w.logger.Error("LDAP sync cycle failed", "error", err)
	}
}

// SyncNow runs a single sync cycle and returns the result.
func (w *SyncWorker) SyncNow(ctx context.Context) (SyncResult, error) {
	return w.sync(ctx)
}

// ConnClass classifies a directory dry-run failure so the admin console can
// show distinct, actionable copy instead of one undifferentiated "could not
// connect" — a wrong password reads very differently from an unreachable
// host.
type ConnClass string

const (
	ConnClassNetwork  ConnClass = "network"
	ConnClassBindAuth ConnClass = "bind_auth"
)

// ConnError wraps a dry-run/preview connection failure with its class.
// Callers type-assert via errors.As to pick the console's user-facing message.
type ConnError struct {
	Class ConnClass
	Err   error
}

func (e *ConnError) Error() string { return e.Err.Error() }
func (e *ConnError) Unwrap() error { return e.Err }

// DryRunResult is the "Test connection" outcome: connectivity + a count.
// ZERO directory or database writes — contrast with the old TestConnection,
// which called SyncNow and mutated the users table under the name "Test".
type DryRunResult struct {
	Checked int `json:"checked"`
}

// DryRun binds to the directory and searches up to `limit` entries. It never
// calls upsertUser / resolveManagerIDs / the cursor writer / the sync-log
// writer — the DB-write seams sync() uses — so it is safe to call from a
// "Test connection" button before the admin has committed to enabling sync.
func (w *SyncWorker) DryRun(ctx context.Context, limit int) (DryRunResult, error) {
	if limit <= 0 {
		limit = 5
	}
	users, err := w.searchOnly(limit)
	if err != nil {
		return DryRunResult{}, err
	}
	return DryRunResult{Checked: len(users)}, nil
}

// PreviewRow is one directory user as the sync engine would map it, with the
// per-row action/skip-reason the AD tab's conflict table already established
// as the console's UX pattern.
type PreviewRow struct {
	Email       string `json:"email"`
	DisplayName string `json:"displayName"`
	Action      string `json:"action"` // create | update | disable | skip
	Reason      string `json:"reason,omitempty"`
}

// PreviewResult is the full directory count plus a bounded, mapped sample.
type PreviewResult struct {
	Total int          `json:"total"`
	Rows  []PreviewRow `json:"rows"`
}

// Preview binds, searches (unbounded — the same read sync() performs), and
// maps up to `limit` entries to their would-be action by consulting the DB
// READ-ONLY (existing-user lookup + local_only field policy). Zero writes.
func (w *SyncWorker) Preview(ctx context.Context, limit int) (PreviewResult, error) {
	if limit <= 0 {
		limit = 25
	}
	users, err := w.searchOnly(0)
	if err != nil {
		return PreviewResult{}, err
	}
	result := PreviewResult{Total: len(users)}
	n := limit
	if n > len(users) {
		n = len(users)
	}
	for _, u := range users[:n] {
		result.Rows = append(result.Rows, w.previewRow(ctx, u))
	}
	return result, nil
}

// searchOnly binds and searches without touching the database — the shared
// leg of DryRun and Preview. limit>0 caps the directory-side page size (0 =
// unbounded, matching sync()'s full read).
//
// ponytail: SearchUsers has no total-result cap (pageSize is a paging hint,
// not a size limit) — a dry run/preview reads the WHOLE matching set, same as
// sync(). Fine at the 300–10k-user scale this product targets; add
// ldap.NewSearchRequest's sizeLimit param if directories grow large enough
// for that to matter.
func (w *SyncWorker) searchOnly(limit int) ([]LDAPUser, error) {
	conn, err := w.client.Connect()
	if err != nil {
		return nil, &ConnError{Class: ConnClassNetwork, Err: err}
	}
	defer func() { _ = conn.Close() }()

	if err := w.client.Bind(conn); err != nil {
		class := ConnClassNetwork
		if ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials) {
			class = ConnClassBindAuth
		}
		return nil, &ConnError{Class: class, Err: err}
	}

	pageSize := 500
	if limit > 0 && limit < pageSize {
		pageSize = limit
	}
	users, err := w.client.SearchUsers(conn, w.filter, pageSize)
	if err != nil {
		return nil, &ConnError{Class: ConnClassNetwork, Err: err}
	}
	return users, nil
}

// previewRow classifies a directory user's would-be sync action WITHOUT
// writing: a plain SELECT against users + field_policy, mirroring upsertUser's
// read-side checks but stopping before any INSERT/UPDATE/DELETE.
func (w *SyncWorker) previewRow(ctx context.Context, u LDAPUser) PreviewRow {
	row := PreviewRow{Email: u.Email, DisplayName: u.DisplayName}
	if u.Email == "" {
		row.Action = "skip"
		row.Reason = "no email attribute"
		return row
	}
	canon := identity.CanonicalizeAddress(u.Email).String()
	var existingID int64
	err := w.pool.QueryRow(ctx, `SELECT id FROM users WHERE email = $1`, canon).Scan(&existingID)
	if err != nil {
		row.Action = "create"
		return row
	}
	if u.Disabled {
		row.Action = "disable"
		return row
	}
	localOnly, err := w.getLocalOnlyFields(ctx, canon)
	if err != nil {
		// Fail closed: an unreadable protection set must not present the
		// update as unprotected in the preview.
		row.Action = "skip"
		row.Reason = "local-only field policy read failed"
		return row
	}
	if len(localOnly) > 0 {
		row.Action = "update"
		row.Reason = fmt.Sprintf("%d locked local-only field(s) will be skipped", len(localOnly))
		return row
	}
	row.Action = "update"
	return row
}

func (w *SyncWorker) sync(ctx context.Context) (SyncResult, error) {
	if w.enabled != nil && !w.enabled() {
		return SyncResult{Skipped: 1}, nil
	}
	if w.source != nil {
		return w.syncNormalized(ctx)
	}
	start := time.Now()
	var result SyncResult

	conn, err := w.client.Connect()
	if err != nil {
		w.logger.Error("LDAP sync: connect failed", "error", err)
		return result, err
	}
	defer conn.Close()

	if err := w.client.Bind(conn); err != nil {
		w.logger.Error("LDAP sync: bind failed", "error", err)
		return result, err
	}

	// Read cursor for incremental sync
	var cursor string
	_ = w.pool.QueryRow(ctx,
		`SELECT value #>> '{}' FROM system_config WHERE key = 'ldap_sync_last_cursor'`,
	).Scan(&cursor)

	// ABSENCE DEPROVISIONING (LDAPSYNC-003): only a completed FULL enumeration
	// of the directory proves an entry is gone. An incremental (cursor-filtered)
	// pass, a failed search, or a cycle with per-entry errors is never treated
	// as absence evidence — it is surfaced and the accounts stay enabled. To
	// keep absence revisited (instead of only on the very first sync before any
	// cursor exists), a cycle whose last sweep is older than
	// ldap_sync_absence_sweep_hours (system_config, default 24; <=0 disables
	// sweeping) is promoted to a full enumeration: the cursor filter is dropped
	// for that cycle, and the sweep runs after a clean present-entry pass.
	sweepHours := w.absenceSweepInterval(ctx)
	full := cursor == ""
	sweepDue := full && sweepHours > 0
	if !full && sweepHours > 0 {
		if last := w.lastAbsenceSweep(ctx); time.Since(last) >= time.Duration(sweepHours)*time.Hour {
			full = true
			sweepDue = true
		}
	}
	cursorForSearch := cursor
	if full {
		cursorForSearch = ""
	}

	filter := buildSyncFilter(w.filter, cursorForSearch)

	users, err := w.client.SearchUsers(conn, filter, 500)
	if err != nil {
		w.logger.Error("LDAP sync: search failed", "error", err)
		return result, err
	}

	result.Checked = len(users)

	autoDepts := ldaputil.GetBoolConfig(ctx, w.pool, "ldap_sync_auto_create_depts")

	for _, u := range users {
		if u.Email == "" {
			continue
		}
		if err := w.upsertUser(ctx, u, autoDepts, &result); err != nil {
			result.Errors++
			w.logger.Warn("LDAP sync: upsert failed", "user", u.Email, "error", err)
		}
	}

	w.resolveManagerIDs(ctx, users)

	// Process absent-entry cursors: disable + revoke sessions for accounts this
	// engine provisioned whose directory entry is authoritatively gone. Only
	// runs on a clean full enumeration; any failure increments result.Errors so
	// the cursor and the sweep timestamp stay unadvanced and the next cycle
	// retries while absent accounts remain enabled.
	if sweepDue {
		if err := w.disableAbsentUsers(ctx, users, &result); err != nil {
			result.Errors++
			w.logger.Error("LDAP sync: absence sweep failed; absent accounts stay enabled and the sweep retries next cycle", "error", err)
		} else if err := w.recordAbsenceSweep(ctx); err != nil {
			result.Errors++
			w.logger.Error("LDAP sync: failed to record absence sweep timestamp; the sweep retries next cycle", "error", err)
		}
	}

	// Update cursor to latest modifyTimestamp
	var maxStamp string
	for _, u := range users {
		if u.ModifyStamp > maxStamp {
			maxStamp = u.ModifyStamp
		}
	}
	if maxStamp != "" && result.Errors == 0 {
		if _, err := w.pool.Exec(ctx,
			`INSERT INTO system_config (key, value, description) VALUES ('ldap_sync_last_cursor', $1, 'LDAP modifyTimestamp cursor')
			 ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now()`,
			fmt.Sprintf("%q", maxStamp),
		); err != nil {
			return result, fmt.Errorf("LDAP sync: update cursor: %w", err)
		}
	}

	details := fmt.Sprintf(`{"cursor_after":%q}`, maxStamp)
	if full {
		details = fmt.Sprintf(`{"cursor_after":%q,"full_enumeration":true}`, maxStamp)
	}

	// Log sync run
	if _, err := w.pool.Exec(ctx,
		`INSERT INTO identity_sync_log (
			source, users_checked, users_created, users_updated, users_disabled,
			fields_skipped, duration_ms, error, details
		) VALUES ($1, $2, $3, $4, $5, $6, $7, NULLIF($8, ''), $9)`,
		"ldap", result.Checked, result.Created, result.Updated, result.Disabled,
		result.Skipped, int(time.Since(start).Milliseconds()), ldaputil.SyncErrorSummary(result.Errors),
		details,
	); err != nil {
		w.logger.Warn("LDAP sync: failed to insert sync log", "error", err)
	}

	result.Duration = time.Since(start).String()
	return result, nil
}

func (w *SyncWorker) syncNormalized(ctx context.Context) (SyncResult, error) {
	return (directorysync.Engine{
		Store:       w.source,
		Connector:   normalizedConnector{client: w.client, filter: w.filter},
		SourceKey:   w.sourceKey,
		Instance:    w.instance,
		Logger:      w.logger,
		Quarantines: directorysync.PgxQuarantineStore{Pool: w.pool},
	}).Sync(ctx)
}

// upsertUser creates or updates a user from an LDAP entry.
//
// ANCHOR DISCIPLINE (LDAPSYNC-002, Astra waves12 item 1): every authorization
// decision runs through the reducer-owned authority fence
// (ldap_sync_anchor_resolve) before any mutation:
//
//   - ANCHORED: the entry's immutable subject resolves through the fence —
//     active 'legacy:ldap' source, active link with the 'provision' purpose,
//     and lifecycle authority for exactly one user. That user is the only
//     mutation target; the anchor is authoritative over any email match, so a
//     directory rename keeps updating the anchored account.
//   - MISSING / NO_SOURCE: the substrate does not know the subject (or the
//     catalog row is absent). The entry falls through to the gated email
//     path: it may only touch an account this engine provisioned itself
//     (users.sync_source = 'ldap'). An email colliding with any other account
//     (a native 'local'/'sso' account or another engine's 'ad'/'scim'
//     account) is skipped and audited as a pending sync_conflicts row.
//   - DENIED: the substrate KNOWS the subject but an authority input fails
//     (link suspended/detached, authentication-only purposes, source
//     paused/retired, lifecycle authority held elsewhere). This is
//     deliberately NOT treated as "missing": the entry does not fall back to
//     email matching — an operator who suspended the link must not be
//     re-connected to the account by directory writers. The entry is skipped
//     and audited.
//   - STALE / ERROR: a moved source generation, or a database error resolving
//     the fence, is surfaced as a sync error for retry. An unreadable
//     substrate is never "no anchor".
//
// Field protections (local_overrides + field_policy) are loaded BY USER ID
// after the target is resolved (Astra waves12 item 4), so an anchored rename
// cannot bypass the original account's overrides by presenting a new email.
//
// krb5_principal custody (D-MAILSERVER-INTERNAL-LDAPSYNC-001) is unchanged and
// owned by the always-local-only floor in ldaputil, not here.
func (w *SyncWorker) upsertUser(ctx context.Context, u LDAPUser, autoDepts bool, result *SyncResult) error {
	if u.Email == "" {
		return nil
	}
	canonEmail := identity.CanonicalizeAddress(u.Email).String()

	// Resolve department
	var deptID *int64
	if autoDepts && u.Department != "" {
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

	// Resolve the one account this entry may mutate through the reducer-owned
	// authority fence BEFORE reading or writing anything else about it.
	var existingID int64
	anchored := false
	anchorGeneration := int64(0)
	if u.ImmutableSubject != "" {
		res, err := w.resolveAnchor(ctx, u.ImmutableSubject)
		if err != nil {
			// A database error is an ERROR outcome: surface it for retry —
			// never degrade it to "no anchor".
			return fmt.Errorf("resolve anchor for %q: %w", u.ImmutableSubject, err)
		}
		anchorGeneration = res.Generation
		switch res.Resolution {
		case anchorAnchored:
			existingID = res.UserID
			anchored = true
		case anchorMissing, anchorNoSource:
			// Subject unknown to the substrate: fall through to the gated
			// email path below.
		case anchorStale:
			return fmt.Errorf("anchor %q is stale: source generation moved past %d (outcome retried next cycle)",
				u.ImmutableSubject, res.Generation)
		default: // anchorDenied
			result.Skipped++
			w.logger.Warn("LDAP sync: anchor denied lifecycle authority; entry skipped without email fallback",
				"email", canonEmail, "subject", u.ImmutableSubject,
				"reason", res.Reason, "link_state", res.LinkState,
				"source_state", res.SourceState, "account_sync_source", res.AccountSyncSource)
			if res.UserID != 0 {
				// The substrate knows which account the subject belongs to:
				// audit the collision against it for operator review.
				if _, err := w.pool.Exec(ctx,
					`INSERT INTO sync_conflicts (user_id, field, local_value, remote_value, source)
					 VALUES ($1, 'email', $2, $3, 'ldap')`,
					res.UserID, canonEmail, u.ImmutableSubject); err != nil {
					return fmt.Errorf("record denied-anchor conflict for user %d: %w", res.UserID, err)
				}
			}
			return nil
		}
	}

	if !anchored {
		var syncSource string
		err := w.pool.QueryRow(ctx,
			`SELECT id, sync_source FROM users WHERE lower(email) = $1`, canonEmail,
		).Scan(&existingID, &syncSource)

		if err != nil {
			// Create new user via the single provisioning seam. The previous
			// hand-rolled INSERT omitted the NOT NULL `username` and `domain_id`
			// columns (so it errored at runtime) and created no primary mailbox.
			// provision_account resolves the domain, derives the username, and
			// creates the primary personal mailbox.
			//
			// CANONICAL WRITE: u.Email / u.UPN route through the ONE canonicalizer.
			// ProvisionAccount's Email param is ValidatedAddress and ADUPN is
			// CanonicalAddress, so a raw u.Email / u.UPN would not compile —
			// users.email / users.ad_upn are Go-canonical by construction (the
			// precondition that lets fold_stored_address demote to a one-time backfill).
			//
			// LDAP is a TRUSTED DIRECTORY source: Email is lifted via the named
			// validation-free CanonicalAddress.AssumeValidated escape (a directory
			// `mail` value may not pass RFC-5321 — ValidateAndCanonicalizeEmail would
			// wrongly reject it), so directory sync stays validation-free —
			// EXCEPT the LDAPSYNC-006 sanity floor below: control characters
			// and non-printable ASCII never enter a provisioned identity.
			if !printableASCIIAddress(u.Email) || (u.UPN != "" && !printableASCIIAddress(u.UPN)) {
				result.Skipped++
				w.logger.Warn("LDAP sync: directory entry carries control characters in its address; refusing to provision",
					"email", canonEmail, "subject", u.ImmutableSubject)
				return nil
			}
			enabled := !u.Disabled
			// Directory mirror sync: intentionally NO welcome email. The initial mirror
			// creates every existing directory user as created=true; sending welcomes
			// here would flood the whole org (spec §7). Welcomes are interactive-only.
			out, err := identity.ProvisionAccount(ctx, w.pool, identity.ProvisionAccountParams{
				Email:        identity.CanonicalizeAddress(u.Email).AssumeValidated(),
				ADUPN:        identity.CanonicalizeAddress(u.UPN),
				DisplayName:  u.DisplayName,
				Enabled:      &enabled,
				SyncSource:   "ldap",
				FirstName:    u.FirstName,
				LastName:     u.LastName,
				JobTitle:     u.Title,
				Phone:        u.Phone,
				DepartmentID: deptID,
				// krb5_principal keeps the RAW UPN (case-sensitive Kerberos realm);
				// only the ad_upn match column is ASCII-folded.
				Krb5Principal: u.UPN,
			})
			if err != nil {
				return err
			}
			// Best-effort anchor: pin the new account to the entry's immutable
			// subject through the reducer-owned establishment fence
			// (ldap_sync_anchor_link), generation-pinned to the resolution the
			// fence just returned. Consumes (never creates) the 'legacy:ldap'
			// identity_sources row.
			if u.ImmutableSubject != "" {
				var provisioned struct {
					UserID int64 `json:"user_id"`
				}
				if json.Unmarshal(out, &provisioned) == nil && provisioned.UserID != 0 {
					w.linkProvisionedUser(ctx, provisioned.UserID, u.ImmutableSubject, anchorGeneration)
				}
			}
			result.Created++
			return nil
		}

		if syncSource != "ldap" {
			// This entry does not anchor the matched account: it is a native
			// (or foreign-source) account whose email a directory-writable
			// writer merely claimed. Never mutate it — no disable, no session
			// revocation, no profile/department/manager rewrite. Skip and
			// audit for operator review.
			result.Skipped++
			remote := u.ImmutableSubject
			if remote == "" {
				remote = canonEmail
			}
			w.logger.Warn("LDAP sync: directory entry does not anchor the matched account; skipping",
				"email", canonEmail, "subject", u.ImmutableSubject, "account_sync_source", syncSource)
			if _, err := w.pool.Exec(ctx,
				`INSERT INTO sync_conflicts (user_id, field, local_value, remote_value, source)
				 VALUES ($1, 'email', $2, $3, 'ldap')`,
				existingID, canonEmail, remote); err != nil {
				return fmt.Errorf("record unanchored directory match for user %d: %w", existingID, err)
			}
			return nil
		}
	}

	// Deprovisioning is security-relevant: the disable + its revocation run
	// atomically inside the ldap_sync_disable_user fence (Astra waves12 item
	// 3), so no committed state can strand an unfinished revocation. Errors
	// are wrapped and returned — the caller counts them as result.Errors,
	// never result.Disabled.
	if u.Disabled {
		if err := w.disableSyncUser(ctx, existingID, "directory disabled entry", anchorGeneration); err != nil {
			return err
		}
		result.Disabled++
		return nil
	}

	// Field protections load BY RESOLVED USER ID (Astra waves12 item 4): an
	// anchored rename presents a NEW email here, and the original account's
	// local-only fields and local overrides must still fence the update.
	// Both protection reads FAIL CLOSED (LDAPSYNC-005): a transient read
	// error leaves the protection state unknown, and applying directory
	// values over unknown protections could overwrite locally-locked fields.
	// The entry surfaces as a sync error and is retried next cycle instead.
	var overrides []byte
	if err := w.pool.QueryRow(ctx,
		`SELECT local_overrides::TEXT::BYTEA FROM users WHERE id = $1`, existingID,
	).Scan(&overrides); err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("load local_overrides for user %d: %w", existingID, err)
	}

	var localOverrides map[string]interface{}
	if len(overrides) > 2 {
		if err := json.Unmarshal(overrides, &localOverrides); err != nil {
			return fmt.Errorf("decode local_overrides for user %d: %w", existingID, err)
		}
	}
	localOnlyFields, err := w.getLocalOnlyFieldsByUserID(ctx, existingID)
	if err != nil {
		return fmt.Errorf("load local-only field policy for user %d: %w", existingID, err)
	}

	// LDAP carries no engine-specific extra columns (contrast AD's ad_usn_changed).
	return ldaputil.ApplyUserUpdate(ctx, w.pool, existingID, buildLDAPSyncAttrs(u),
		localOnlyFields, localOverrides, deptID, "ldap", nil, result, w.logger)
}

// printableASCIIAddress is the LDAPSYNC-006 ingress sanity floor for
// directory-derived addresses entering an identity through the
// AssumeValidated escape: every rune must be printable ASCII (0x20..0x7E),
// which rejects CR/LF, NUL, and other control or non-ASCII bytes before they
// can reach users.email, users.ad_upn, or users.krb5_principal. It is a
// floor, not RFC-5321 validation — bare UPNs stay admissible.
func printableASCIIAddress(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7E {
			return false
		}
	}
	return true
}

// Anchor resolution outcome classes returned by the reducer-owned fence// (ldap_sync_anchor_resolve). They deliberately separate "the substrate does
// not know this subject" (missing) from "the substrate knows it and refuses"
// (denied), "the authority moved" (stale) and "the substrate is unreadable"
// (Go error) — collapsing them is what let an authentication-only link
// authorize disabling a native account (Astra waves12 item 1).
const (
	anchorAnchored = "anchored"
	anchorMissing  = "missing"
	anchorDenied   = "denied"
	anchorNoSource = "no_source"
	anchorStale    = "stale"
)

// anchorResolution mirrors the JSON outcome of ldap_sync_anchor_resolve.
type anchorResolution struct {
	Resolution        string `json:"resolution"`
	UserID            int64  `json:"userId"`
	LinkID            int64  `json:"linkId"`
	SourceID          int64  `json:"sourceId"`
	Generation        int64  `json:"generation"`
	Reason            string `json:"reason"`
	SourceState       string `json:"sourceState"`
	LinkState         string `json:"linkState"`
	AccountSyncSource string `json:"accountSyncSource"`
}

// resolveAnchor runs the reducer-owned authority fence for one immutable
// subject. It returns the fence's outcome class; a database error is returned
// as an error so the caller can distinguish an unreadable substrate from a
// missing or denied anchor.
func (w *SyncWorker) resolveAnchor(ctx context.Context, subject string) (anchorResolution, error) {
	var raw []byte
	if err := w.pool.QueryRow(ctx,
		`SELECT ldap_sync_anchor_resolve($1::text, NULL::bigint)`, subject,
	).Scan(&raw); err != nil {
		return anchorResolution{}, err
	}
	var res anchorResolution
	if err := json.Unmarshal(raw, &res); err != nil {
		return anchorResolution{}, fmt.Errorf("decode anchor resolution: %w", err)
	}
	return res, nil
}

// disableSyncUser deprovisions one account through the atomic, reducer-fenced
// disable (ldap_sync_disable_user): the fence re-decides anchor/family
// lifecycle authority transactionally, and the state flip plus the complete
// revocation boundary (oauth tokens, websocket subscriptions, sessions,
// denylist row, audit, notify) commit in ONE transaction — no committed
// intermediate state can strand an unfinished revocation (Astra waves12 item
// 3). expectedGeneration > 0 pins the catalog generation for anchor-path
// callers (BZ229 on drift); 0 state-checks only.
func (w *SyncWorker) disableSyncUser(ctx context.Context, userID int64, reason string, expectedGeneration int64) error {
	var genArg interface{}
	if expectedGeneration > 0 {
		genArg = expectedGeneration
	}
	var raw []byte
	if err := w.pool.QueryRow(ctx,
		`SELECT ldap_sync_disable_user($1::bigint, $2::text, $3::bigint)`,
		userID, reason, genArg,
	).Scan(&raw); err != nil {
		return fmt.Errorf("disable user %d: %w", userID, err)
	}
	return nil
}

// linkProvisionedUser best-effort anchors a freshly provisioned account to the
// directory entry's immutable subject through the reducer-owned establishment
// fence (ldap_sync_anchor_link). It only CONSUMES the 'legacy:ldap'
// identity_sources row — creating or mutating source-catalog rows stays with
// the identity_source_upsert reducer — so when that row is absent the engine
// keeps working through the gated email path. A conflict with an existing link
// owned by a different account is left untouched, recorded as soft evidence by
// the reducer, and logged; the engine never steals an anchor.
func (w *SyncWorker) linkProvisionedUser(ctx context.Context, userID int64, subject string, expectedGeneration int64) {
	var genArg interface{}
	if expectedGeneration > 0 {
		genArg = expectedGeneration
	}
	var raw []byte
	if err := w.pool.QueryRow(ctx,
		`SELECT ldap_sync_anchor_link($1::bigint, $2::text, $3::bigint)`,
		userID, subject, genArg,
	).Scan(&raw); err != nil {
		w.logger.Warn("LDAP sync: could not anchor provisioned account to immutable subject",
			"user_id", userID, "error", err)
		return
	}
	var out struct {
		Linked bool   `json:"linked"`
		Reason string `json:"reason"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		w.logger.Warn("LDAP sync: undecodable anchor-link outcome",
			"user_id", userID, "error", err)
		return
	}
	if !out.Linked {
		w.logger.Warn("LDAP sync: immutable subject was not anchored to the provisioned account; link left unchanged",
			"user_id", userID, "subject", subject, "reason", out.Reason)
	}
}

// absenceSweepInterval reads the absent-entry deprovisioning cadence from
// system_config (hours). Default 24; a value of 0 disables sweeping entirely;
// an unset/invalid value falls back to the default.
func (w *SyncWorker) absenceSweepInterval(ctx context.Context) int {
	var raw string
	_ = w.pool.QueryRow(ctx,
		`SELECT value #>> '{}' FROM system_config WHERE key = 'ldap_sync_absence_sweep_hours'`,
	).Scan(&raw)
	hours, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil || hours < 0 {
		return defaultAbsenceSweepHours
	}
	return hours
}

// lastAbsenceSweep reads the timestamp of the last completed absence sweep. A
// missing or unparseable value returns the zero time, so the sweep is treated
// as due — an unknown sweep state must default to re-enumerating, never to
// silently skipping deprovisioning forever.
func (w *SyncWorker) lastAbsenceSweep(ctx context.Context) time.Time {
	var raw string
	_ = w.pool.QueryRow(ctx,
		`SELECT value #>> '{}' FROM system_config WHERE key = 'ldap_sync_last_absence_sweep'`,
	).Scan(&raw)
	ts, err := time.Parse(time.RFC3339, strings.TrimSpace(raw))
	if err != nil {
		return time.Time{}
	}
	return ts
}

// recordAbsenceSweep stamps the completed sweep so the next full enumeration
// waits for the configured cadence. The value is JSON-quoted like the cursor.
func (w *SyncWorker) recordAbsenceSweep(ctx context.Context) error {
	if _, err := w.pool.Exec(ctx,
		`INSERT INTO system_config (key, value, description)
		 VALUES ('ldap_sync_last_absence_sweep', $1, 'LDAP absent-entry deprovisioning sweep timestamp (RFC3339)')
		 ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now()`,
		fmt.Sprintf("%q", time.Now().UTC().Format(time.RFC3339)),
	); err != nil {
		return fmt.Errorf("LDAP sync: record absence sweep: %w", err)
	}
	return nil
}

// disableAbsentUsers is the LDAPSYNC-003 sweep, run only after a clean FULL
// enumeration: every enabled account owned by this engine whose canonical
// email is absent from the directory — and whose immutable anchor is not
// attached to any present entry (the rename case) — was authoritatively
// deleted from the directory. Disable-first policy: users.enabled flips FALSE
// and the complete revocation boundary runs in the SAME transaction via
// ldap_sync_disable_user; no mailbox or profile data is deleted. Native
// (non-'ldap') accounts are never swept.
//
// SOURCE OWNERSHIP (Astra waves12 item 2): the population is the EXACT
// source-owned set, not a discriminator-plus-heuristic guess. An account is
// sweepable only when
//
//   - it was provisioned by this engine family (users.sync_source = 'ldap')
//     AND no OTHER identity source holds lifecycle authority over it (a
//     normalized ldap:* source sharing the sync_source discriminator on a
//     shared domain is a different owner and is never swept), or
//   - the substrate actively anchors it to this source with a provision-purpose
//     link on an active 'legacy:ldap' source.
//
// RECONCILIATION AGAINST COMPLETE ENUMERATION: there is deliberately NO
// domain-observed fence. "The domains seen in this enumeration" neither
// identifies ownership (shared domains) nor bounds the source's scope (a
// successful enumeration that ends with the last user of a domain deleted, or
// an entirely emptied directory, MUST still propagate). The sweep's evidence
// budget is: a completed, error-free FULL enumeration of the source's scope.
// Anything less never reaches this function.
//
// Each per-account write re-fences authority transactionally inside
// ldap_sync_disable_user (R3: resolved-id seam). The first failure aborts the
// sweep and is surfaced by the caller (result.Errors) so absent accounts stay
// enabled and the next cycle retries with the already-disabled accounts
// excluded by the enabled predicate.
func (w *SyncWorker) disableAbsentUsers(ctx context.Context, users []LDAPUser, result *SyncResult) error {
	presentEmails := make([]string, 0, len(users))
	presentSubjects := make([]string, 0, len(users))
	for _, u := range users {
		if u.Email != "" {
			presentEmails = append(presentEmails, identity.CanonicalizeAddress(u.Email).String())
		}
		if u.ImmutableSubject != "" {
			presentSubjects = append(presentSubjects, u.ImmutableSubject)
		}
	}
	rows, err := w.pool.Query(ctx, `
		SELECT id, email FROM users
		 WHERE sync_source = 'ldap'
		   AND enabled
		   AND NOT is_guest_account(id)
		   AND lower(email) <> ALL($1::text[])
		   AND NOT EXISTS (
		       SELECT 1
		         FROM user_identity_links l
		         JOIN identity_sources s ON s.id = l.source_id
		        WHERE s.source_key = 'legacy:ldap'
		          AND l.state = 'active'
		          AND l.user_id = users.id
		          AND l.external_subject = ANY($2::text[])
		   )
		   AND NOT EXISTS (
		       SELECT 1
		         FROM user_lifecycle_authorities a
		         JOIN user_identity_links l2 ON l2.id = a.link_id
		         JOIN identity_sources s2 ON s2.id = l2.source_id
		        WHERE a.user_id = users.id
		          AND a.authority_kind = 'source'
		          AND s2.source_key <> 'legacy:ldap'
		   )`,
		presentEmails, presentSubjects,
	)
	if err != nil {
		return fmt.Errorf("absence sweep query: %w", err)
	}
	defer rows.Close()

	type absentee struct {
		id    int64
		email string
	}
	var absentees []absentee
	for rows.Next() {
		var a absentee
		if err := rows.Scan(&a.id, &a.email); err != nil {
			return fmt.Errorf("absence sweep scan: %w", err)
		}
		absentees = append(absentees, a)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("absence sweep rows: %w", err)
	}

	for _, a := range absentees {
		if err := w.disableSyncUser(ctx, a.id, "absent from full directory enumeration", 0); err != nil {
			return fmt.Errorf("absence sweep disable %q: %w", a.email, err)
		}
		result.Disabled++
		w.logger.Info("LDAP sync: disabled account absent from full directory enumeration",
			"email", a.email, "user_id", a.id)
	}
	return nil
}

// resolveManagerIDs is pass 2 of the LDAP sync: resolves each user's ManagerDN to a
// DB user_id via an in-memory DN→id map keyed by immutable subject (when the
// subject attribute is configured) and canonical email, then sets
// users.manager_id. Managers outside the sync scope are silently skipped (NULL).
//
// ONE AUTHORIZED TARGET SET (Astra waves12 item 5): clearing and assignment
// used to be gated by different predicates — clearing required
// users.sync_source = 'ldap', while assignment accepted any actively-anchored
// user — so an anchored account outside the sync_source population could be
// assigned a manager it could never have cleared. Both steps now operate on
// the SAME authorized set, computed once by authorizedManagerTargets: family
// authority (sync_source = 'ldap' with no OTHER identity source holding
// lifecycle authority) or active anchor authority (an active provision-purpose
// link on an active 'legacy:ldap' source), restricted to the present sync set.
func (w *SyncWorker) resolveManagerIDs(ctx context.Context, users []LDAPUser) {
	emails := make([]string, 0, len(users))
	subjects := make([]string, 0, len(users))
	for _, u := range users {
		if u.Email != "" {
			emails = append(emails, identity.CanonicalizeAddress(u.Email).String())
		}
		if u.ImmutableSubject != "" {
			subjects = append(subjects, u.ImmutableSubject)
		}
	}
	if len(emails) == 0 && len(subjects) == 0 {
		return
	}

	authorized, subjectToID, err := w.authorizedManagerTargets(ctx, emails, subjects)
	if err != nil {
		w.logger.Warn("LDAP sync: manager pass: failed to resolve authorized targets", "error", err)
		return
	}

	// ponytail: clears stale manager links on every re-sync — departed/out-of-scope managers become NULL.
	// The clear runs over the SAME authorized target set as assignment, so an
	// anchored account's stale manager is cleared exactly when that account is
	// also assignable (and never on accounts this pass does not own).
	if len(authorized) > 0 {
		authorizedIDs := make([]int64, 0, len(authorized))
		for id := range authorized {
			authorizedIDs = append(authorizedIDs, id)
		}
		if _, err := w.pool.Exec(ctx,
			`UPDATE users SET manager_id = NULL WHERE id = ANY($1::bigint[])`, authorizedIDs,
		); err != nil {
			w.logger.Warn("LDAP sync: manager pass: failed to clear stale manager_ids", "error", err)
			return
		}
	}

	// Batch-fetch email → DB id for the whole sync set, restricted to the
	// accounts this engine provisions and not claimed by another source.
	emailToID := make(map[string]int64, len(emails))
	rows, err := w.pool.Query(ctx,
		`SELECT email, id FROM users
		  WHERE email = ANY($1)
		    AND sync_source = 'ldap'
		    AND NOT is_guest_account(id)
		    AND NOT EXISTS (
		        SELECT 1
		          FROM user_lifecycle_authorities a
		          JOIN user_identity_links l2 ON l2.id = a.link_id
		          JOIN identity_sources s2 ON s2.id = l2.source_id
		         WHERE a.user_id = users.id
		           AND a.authority_kind = 'source'
		           AND s2.source_key <> 'legacy:ldap')`, emails)
	if err != nil {
		w.logger.Warn("LDAP sync: manager pass: failed to fetch user ids", "error", err)
		return
	}
	defer rows.Close()
	for rows.Next() {
		var email string
		var id int64
		if err := rows.Scan(&email, &id); err == nil {
			emailToID[email] = id
		}
	}
	if err := rows.Err(); err != nil {
		w.logger.Warn("LDAP sync: manager pass: row iteration error", "error", err)
		return
	}

	// resolveSelfID prefers the immutable-subject anchor over the email map: a
	// renamed anchored account is still exactly the entry's target. Either way
	// the result must be a member of the authorized target set — assignment
	// never reaches an account the clear step could not own.
	resolveSelfID := func(u LDAPUser) (int64, bool) {
		if u.ImmutableSubject != "" {
			if id, ok := subjectToID[u.ImmutableSubject]; ok && authorized[id] {
				return id, true
			}
		}
		if u.Email == "" {
			return 0, false
		}
		id, ok := emailToID[identity.CanonicalizeAddress(u.Email).String()]
		if !ok || !authorized[id] {
			return 0, false
		}
		return id, true
	}

	// Build normalized DN → user_id for manager candidates in the sync set.
	dnToID := make(map[string]int64, len(users))
	for _, u := range users {
		if u.DN == "" {
			continue
		}
		if id, ok := resolveSelfID(u); ok {
			dnToID[ldaputil.NormalizeDN(u.DN)] = id
		}
	}

	// Update manager_id for each user whose manager is in the sync set.
	for _, u := range users {
		if u.ManagerDN == "" || u.Email == "" {
			continue
		}
		selfID, ok := resolveSelfID(u)
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
			w.logger.Warn("LDAP sync: failed to update manager_id",
				"user_id", selfID, "manager_id", managerID, "error", err)
		}
	}
}

// authorizedManagerTargets resolves the ONE account set the manager pass may
// touch — the same set for clearing stale manager links and for assigning new
// ones (Astra waves12 item 5) — restricted to the present sync set (by
// canonical email or by an actively anchored present subject), plus the
// fenced subject→id map used to resolve anchored entries.
//
// An account is authorized when it is NOT a guest and either
//   - it has family authority: users.sync_source = 'ldap' and no OTHER
//     identity source holds lifecycle authority over it, or
//   - it has anchor authority: an active provision-purpose link on an active
//     'legacy:ldap' source.
func (w *SyncWorker) authorizedManagerTargets(ctx context.Context, emails, subjects []string) (map[int64]bool, map[string]int64, error) {
	authorized := make(map[int64]bool)
	rows, err := w.pool.Query(ctx, `
		SELECT u.id FROM users u
		 WHERE NOT is_guest_account(u.id)
		   AND (
		        lower(u.email) = ANY($1::text[])
		        OR EXISTS (
		            SELECT 1
		              FROM user_identity_links la
		              JOIN identity_sources sa ON sa.id = la.source_id
		             WHERE la.user_id = u.id
		               AND sa.source_key = 'legacy:ldap'
		               AND la.state = 'active'
		               AND la.external_subject = ANY($2::text[])
		        )
		   )
		   AND (
		        (
		            u.sync_source = 'ldap'
		            AND NOT EXISTS (
		                SELECT 1
		                  FROM user_lifecycle_authorities a
		                  JOIN user_identity_links l2 ON l2.id = a.link_id
		                  JOIN identity_sources s2 ON s2.id = l2.source_id
		                 WHERE a.user_id = u.id
		                   AND a.authority_kind = 'source'
		                   AND s2.source_key <> 'legacy:ldap'
		            )
		        )
		        OR EXISTS (
		            SELECT 1
		              FROM user_identity_links l
		              JOIN identity_sources s ON s.id = l.source_id
		             WHERE l.user_id = u.id
		               AND s.source_key = 'legacy:ldap'
		               AND s.state = 'active'
		               AND l.state = 'active'
		               AND 'provision' = ANY (l.purposes)
		        )
		   )`, emails, subjects)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, nil, err
		}
		authorized[id] = true
	}
	if err := rows.Err(); err != nil {
		return nil, nil, err
	}

	// Fenced subject→id resolution: only an active provision-purpose link on an
	// ACTIVE 'legacy:ldap' source resolves a subject. This is where the old
	// asymmetric gate lived — assignment used to accept ANY active link,
	// including authentication-only links on native accounts.
	subjectToID := make(map[string]int64, len(subjects))
	if len(subjects) > 0 {
		srows, err := w.pool.Query(ctx, `
			SELECT l.external_subject, l.user_id
			  FROM user_identity_links l
			  JOIN identity_sources s ON s.id = l.source_id
			  JOIN users u ON u.id = l.user_id
			 WHERE s.source_key = 'legacy:ldap'
			   AND s.state = 'active'
			   AND l.state = 'active'
			   AND 'provision' = ANY (l.purposes)
			   AND NOT is_guest_account(u.id)
			   AND l.external_subject = ANY($1::text[])`, subjects)
		if err != nil {
			return nil, nil, err
		}
		defer srows.Close()
		for srows.Next() {
			var subject string
			var id int64
			if err := srows.Scan(&subject, &id); err != nil {
				return nil, nil, err
			}
			subjectToID[subject] = id
		}
		if err := srows.Err(); err != nil {
			return nil, nil, err
		}
	}
	return authorized, subjectToID, nil
}

// getLocalOnlyFields loads the local_only field set for a user. `email` must
// be the CANONICAL address (users.email is Go-canonical by the write seam).
// Used by the read-only preview path; the mutating sync path loads protections
// by resolved user ID (getLocalOnlyFieldsByUserID). Errors are returned, never
// swallowed: an unknown protection set must fail the caller closed.
func (w *SyncWorker) getLocalOnlyFields(ctx context.Context, email string) (map[string]bool, error) {
	rows, err := w.pool.Query(ctx,
		`SELECT fp.field FROM field_policy fp
		 JOIN users u ON u.id = fp.user_id
		 WHERE u.email = $1 AND fp.policy = 'local_only'`, email)
	return w.scanLocalOnlyFields(rows, err)
}

// getLocalOnlyFieldsByUserID loads the local_only field set for an ALREADY
// RESOLVED user id (Astra waves12 item 4). The mutating sync path must load
// field protections by the anchor-resolved target, never by the incoming
// email: an anchored rename presents a new address, and matching protections
// by email would bypass the original account's local-only locks. Errors are
// returned so the mutating path can fail closed (LDAPSYNC-005).
func (w *SyncWorker) getLocalOnlyFieldsByUserID(ctx context.Context, userID int64) (map[string]bool, error) {
	rows, err := w.pool.Query(ctx,
		`SELECT fp.field FROM field_policy fp
		 WHERE fp.user_id = $1 AND fp.policy = 'local_only'`, userID)
	return w.scanLocalOnlyFields(rows, err)
}

// scanLocalOnlyFields folds a field_policy scan into the effective local-only
// set under the code-level custody floor: krb5_principal is the SSO
// authentication identity and is never sync-writable on an existing user.
// field_policy can add more local-only fields; it can never unlock this one
// (an explicit 'ad_managed' row is filtered out by the merge).
// Query and scan errors propagate to the caller instead of degrading to an
// empty (protection-free) set.
func (w *SyncWorker) scanLocalOnlyFields(rows pgx.Rows, err error) (map[string]bool, error) {
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	fields, scanErr := ldaputil.ScanFieldPolicyRows(rows)
	if scanErr != nil {
		return nil, scanErr
	}
	return ldaputil.EnforceAlwaysLocalOnly(fields), nil
}
