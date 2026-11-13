// Package ldaputil provides shared LDAP/AD utilities used by both the AD and
// generic LDAP sync engines. Extracted to eliminate copy-paste duplication.
package ldaputil

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"setjoin.com/shared/identity"
)

// FieldKrb5Principal names the users.krb5_principal column — the Kerberos/SPNEGO
// SSO identity the auth chain resolves by exact principal match to grant
// full-access authentication. Directory sync must never rewrite it.
const FieldKrb5Principal = "krb5_principal"

// alwaysLocalOnlyFields is the CODE-LEVEL floor of local-only field custody.
// These columns are never sync-writable on an existing user, regardless of
// field_policy rows: a policy row can lock MORE fields local-only, but can
// never unlock a floor field (an 'ad_managed' row for krb5_principal is
// filtered out here, and the admin SetFieldPolicy endpoint rejects it).
// Rationale: remapping krb5_principal from the directory UPN would let a
// controlled directory entry point an attacker-authenticatable principal at a
// victim account, so SPNEGO login yields the victim identity. Creation-time
// provisioning (ProvisionAccount) still writes the floor fields — the floor
// only fences the UPDATE path. The SQL side carries the matching fence:
// provision_account's existing-user UPDATE branch excludes krb5_principal from
// its SET list (so the AD unmatched-GUID → existing-email fall-through and
// scim_upsert_user cannot rewrite it either); the only sanctioned change on an
// existing user is the audited admin action (POST /admin/ad/principal).
var alwaysLocalOnlyFields = map[string]bool{FieldKrb5Principal: true}

// syncWriterAttrsKeys is the WRITER-LEVEL allowlist of attribute keys a caller
// may pass to ApplyUserUpdate in `attrs` (AD-001, r2-C3-2 "accepted input
// keys"): exactly the fixed SyncAttrs table, which is the source of truth this
// set mirrors. It splits into two roles:
//   - INPUT keys: all seven are accepted input — krb5_principal is normal
//     caller behavior (both real map builders always carry it); the
//     always-local-only floor suppresses the write and audits it.
//   - WRITABLE columns: the same set MINUS krb5_principal (never sync-writable
//     on UPDATE); local-override conflicted keys are additionally
//     skipped-with-audit as before.
//
// Anything outside this set reaching the writer is caller drift — a future key
// added to a builder's map — and is a programming error, not directory data:
// ApplyUserUpdate hard-errors with zero rows updated instead of silently
// writing a new users column.
var syncWriterAttrsKeys = map[string]bool{
	"email":            true,
	"display_name":     true,
	"first_name":       true,
	"last_name":        true,
	"job_title":        true,
	"phone":            true,
	FieldKrb5Principal: true,
}

// syncWriterExtraSetKeys is the allowlist of engine-specific extraSets keys —
// their own fixed per-engine set, never a free map (AD's uSNChanged cursor
// watermark is the only member; the LDAP engine passes none).
var syncWriterExtraSetKeys = map[string]bool{
	"ad_usn_changed": true,
}

// AcceptedSyncAttrsKeys returns a copy of the fixed accepted-input key set for
// ApplyUserUpdate's attrs (see syncWriterAttrsKeys). Exported so engine-side
// builder tests can assert their map builders stay inside the writer's
// allowlist — builder drift fails a test instead of live traffic.
func AcceptedSyncAttrsKeys() map[string]bool {
	out := make(map[string]bool, len(syncWriterAttrsKeys))
	for k := range syncWriterAttrsKeys {
		out[k] = true
	}
	return out
}

// AcceptedExtraSetKeys returns a copy of the fixed accepted-input key set for
// ApplyUserUpdate's extraSets (see syncWriterExtraSetKeys).
func AcceptedExtraSetKeys() map[string]bool {
	out := make(map[string]bool, len(syncWriterExtraSetKeys))
	for k := range syncWriterExtraSetKeys {
		out[k] = true
	}
	return out
}

// EnforceAlwaysLocalOnly merges the code-level always-local-only floor into a
// field_policy-derived set. Both sync engines apply it after loading policy
// rows, and ApplyUserUpdate re-applies it at the single UPDATE writer, so an
// explicit removal in field_policy can never re-enable a sync overwrite.
func EnforceAlwaysLocalOnly(fields map[string]bool) map[string]bool {
	merged := make(map[string]bool, len(fields)+len(alwaysLocalOnlyFields))
	for field := range fields {
		merged[field] = true
	}
	for field := range alwaysLocalOnlyFields {
		merged[field] = true
	}
	return merged
}

// SyncResult holds the outcome of a directory sync run. Shared by the AD and
// LDAP engines (each aliases it) so the identity_sync_log JSON tags stay
// identical across both.
type SyncResult struct {
	Checked  int    `json:"checked"`
	Created  int    `json:"created"`
	Updated  int    `json:"updated"`
	Disabled int    `json:"disabled"`
	Skipped  int    `json:"skipped"`
	Errors   int    `json:"errors"`
	Duration string `json:"duration"`
}

// SyncErrorSummary maps the legacy per-entry error count onto the current
// identity_sync_log error column without inventing a second count authority.
func SyncErrorSummary(count int) string {
	if count == 0 {
		return ""
	}
	return fmt.Sprintf("%d directory entries failed", count)
}

// NormalizeDN lowercases and trims whitespace for case-insensitive DN comparison.
// AD and LDAP DNs are case-insensitive per RFC 4514; lower+trim is sufficient.
func NormalizeDN(dn string) string {
	return strings.ToLower(strings.TrimSpace(dn))
}

// DisableUser deprovisions a directory-disabled user: flips users.enabled to
// FALSE and clears live sessions + websocket subscriptions. Every write's error
// is wrapped and returned — deprovisioning is security-relevant, so a DB error
// must NOT be swallowed and counted as a successful disable, or a
// directory-disabled user keeps an enabled account and/or live sessions while
// the run reports them disabled. The caller counts a returned error as
// result.Errors (never result.Disabled) so the failure surfaces and the next
// sync retries. Ownership is the resolved users.id (R3: no TOCTOU).
//
// WRITE VERIFY (LDAPSYNC-002's sibling, LDAPUTIL-002): a 0-row UPDATE is never
// reported as a successful disable. It is re-resolved: a user that vanished
// concurrently (ON DELETE CASCADE already removed its sessions) or was already
// disabled is an idempotent no-op, while a still-enabled account after a
// 0-row disable is an error — never a silent success.
func DisableUser(ctx context.Context, pool *pgxpool.Pool, userID int64) error {
	tag, err := pool.Exec(ctx, `UPDATE users SET enabled = FALSE WHERE id = $1`, userID)
	if err != nil {
		return fmt.Errorf("disable user %d: %w", userID, err)
	}
	if tag.RowsAffected() == 0 {
		var enabled bool
		scanErr := pool.QueryRow(ctx,
			`SELECT enabled FROM users WHERE id = $1`, userID,
		).Scan(&enabled)
		switch {
		case errors.Is(scanErr, pgx.ErrNoRows):
			// Deleted between resolve and disable; sessions and
			// ws_subscriptions cascaded with it. Nothing to deprovision.
			return nil
		case scanErr != nil:
			return fmt.Errorf("re-resolve user %d after 0-row disable: %w", userID, scanErr)
		case enabled:
			return fmt.Errorf("disable user %d: UPDATE matched 0 rows but the account is still enabled", userID)
		default:
			// Already disabled: idempotent no-op, still clear the seams below.
			return nil
		}
	}
	if _, err := pool.Exec(ctx, `DELETE FROM sessions WHERE user_id = $1`, userID); err != nil {
		return fmt.Errorf("delete sessions for user %d: %w", userID, err)
	}
	if _, err := pool.Exec(ctx, `DELETE FROM ws_subscriptions WHERE user_id = $1`, userID); err != nil {
		return fmt.Errorf("delete ws_subscriptions for user %d: %w", userID, err)
	}
	return nil
}

// ApplyUserUpdate applies the directory UPDATE path shared by the AD and LDAP
// sync engines: it builds a dynamic `UPDATE users SET ...` from attrs, skipping
// empty values, local_only-locked fields (counted as result.Skipped), and
// fields carrying a local override (logged to sync_conflicts as a skip). deptID,
// when non-nil and not locally overridden, updates department_id. extraSets
// carries engine-specific columns (AD's ad_usn_changed → its uSNChanged); pass
// nil for none — extraSets are written only when there is already at least one
// attr/dept change (so ad_usn_changed alone never triggers a write, matching the
// prior AD behavior). Increments result.Skipped / result.Updated in place.
//
// WRITER-LEVEL KEY ALLOWLIST (AD-001, r2-C3-2): attrs keys must be within
// AcceptedSyncAttrsKeys (the fixed SyncAttrs table — krb5_principal is accepted
// input whose write the floor suppresses with an audit) and extraSets keys
// within AcceptedExtraSetKeys. A key outside its set is caller drift reaching
// for a users column the sync contract never granted: it is a hard error with
// ZERO rows updated — never a skip, never a silent write. Both key sets are
// validated at function entry, AFTER the floor merge and BEFORE the attrs
// loop, so a forbidden key can neither escape via the empty-value continue nor
// via the no-op (len(sets)==0) return that extraSets traversal used to sit
// behind, and validation precedes every row read and statement side effect.
//
// The always-local-only floor (EnforceAlwaysLocalOnly) is re-applied here at the
// single UPDATE writer, so krb5_principal is never sync-writable even if a
// caller forgets to merge the floor into its localOnly set. When a directory
// value for krb5_principal DIFFERS from the stored principal — a would-be
// overwrite that the floor suppressed — the suppression is audited: a
// sync_conflicts row (resolution 'kept_local', same as the local-override
// conflict seam) plus a slog.Warn carrying the suppressed directory value (an
// attacker-controllable UPN — directory-mirror data, not secret material, and
// its presence in logs aids forensics).
func ApplyUserUpdate(ctx context.Context, pool *pgxpool.Pool, existingID int64,
	attrs map[string]string, localOnly map[string]bool, localOverrides map[string]interface{},
	deptID *int64, source string, extraSets map[string]interface{}, result *SyncResult,
	logger *slog.Logger) error {
	localOnly = EnforceAlwaysLocalOnly(localOnly)
	if logger == nil {
		logger = slog.Default()
	}

	// Key allowlist first — validation precedes the empty-value continue, the
	// len(sets)==0 early return, and every DB read/write below.
	for col := range attrs {
		if !syncWriterAttrsKeys[col] {
			return fmt.Errorf("apply user update: attribute key %q is not in the sync-writer allowlist; refusing the update", col)
		}
	}
	for col := range extraSets {
		if !syncWriterExtraSetKeys[col] {
			return fmt.Errorf("apply user update: extra-set key %q is not in the sync-writer allowlist; refusing the update", col)
		}
	}

	var sets []string
	var args []interface{}
	argIdx := 1

	for col, val := range attrs {
		if val == "" {
			continue
		}
		if localOnly[col] {
			if col == FieldKrb5Principal {
				if err := auditSuppressedPrincipalWrite(ctx, pool, logger,
					existingID, val, source); err != nil {
					return err
				}
			}
			result.Skipped++
			continue
		}
		if localOverrides != nil && localOverrides[col] != nil {
			// Log the conflict instead of silently skipping.
			remoteVal, _ := json.Marshal(val)
			localVal, _ := json.Marshal(localOverrides[col])
			if _, err := pool.Exec(ctx,
				`INSERT INTO sync_conflicts (user_id, field, local_value, remote_value, source)
				 VALUES ($1, $2, $3, $4, $5)`,
				existingID, col, string(localVal), string(remoteVal), source); err != nil {
				return fmt.Errorf("record sync conflict for %s: %w", col, err)
			}
			result.Skipped++
			continue
		}
		sets = append(sets, fmt.Sprintf("%s = $%d", col, argIdx))
		args = append(args, val)
		argIdx++
	}

	// department_id is a special case (handled separately from string attrs).
	if deptID != nil {
		if localOverrides == nil || localOverrides["department_id"] == nil {
			sets = append(sets, fmt.Sprintf("department_id = $%d", argIdx))
			args = append(args, *deptID)
			argIdx++
		}
	}

	if len(sets) == 0 {
		return nil
	}

	for col, val := range extraSets {
		sets = append(sets, fmt.Sprintf("%s = $%d", col, argIdx))
		args = append(args, val)
		argIdx++
	}
	args = append(args, existingID)
	if _, err := pool.Exec(ctx,
		fmt.Sprintf("UPDATE users SET %s WHERE id = $%d", strings.Join(sets, ", "), argIdx),
		args...,
	); err != nil {
		return err
	}
	result.Updated++
	return nil
}

// auditSuppressedPrincipalWrite records a sync-time krb5_principal overwrite
// that the always-local-only floor suppressed: the directory offered a
// DIFFERENT principal for an existing user. It writes a sync_conflicts row
// (the table the local-override conflict path already uses; resolution
// 'kept_local' — the stored principal won) and logs a warn carrying the
// suppressed directory value for forensics. An insert failure is returned so
// the caller counts the user as an errored sync entry rather than silently
// losing the audit trail — the suppression itself is already decided, but the
// evidence must not be.
func auditSuppressedPrincipalWrite(ctx context.Context, pool *pgxpool.Pool, logger *slog.Logger,
	existingID int64, directoryPrincipal, source string) error {
	var storedPrincipal *string
	if err := pool.QueryRow(ctx,
		`SELECT krb5_principal FROM users WHERE id = $1`, existingID,
	).Scan(&storedPrincipal); err != nil {
		return fmt.Errorf("read stored krb5_principal for user %d: %w", existingID, err)
	}
	if storedPrincipal == nil || *storedPrincipal != directoryPrincipal {
		logger.Warn("directory sync suppressed krb5_principal overwrite",
			"user_id", existingID, "source", source,
			"stored_present", storedPrincipal != nil,
			"suppressed_directory_principal", directoryPrincipal)
		if _, err := pool.Exec(ctx,
			`INSERT INTO sync_conflicts (user_id, field, local_value, remote_value, source, resolution)
			 VALUES ($1, $2, $3, $4, $5, 'kept_local')`,
			existingID, FieldKrb5Principal, storedPrincipal, directoryPrincipal, source); err != nil {
			return fmt.Errorf("record suppressed krb5_principal overwrite for user %d: %w", existingID, err)
		}
	}
	return nil
}

// DomainToBaseDN converts a DNS domain name to an LDAP base DN.
// "corp.local" → "DC=corp,DC=local"
func DomainToBaseDN(domain string) string {
	parts := strings.Split(domain, ".")
	var b strings.Builder
	for i, p := range parts {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString("DC=")
		b.WriteString(p)
	}
	return b.String()
}

// SyncAttrs returns the common attribute map for syncing a directory user to the
// local users table (the AD/LDAP UPDATE path's dynamic `UPDATE users SET …`).
// Fields map to users table columns.
//
// This fixed table is ALSO the source of the writer's accepted-input key set
// (mirrored into syncWriterAttrsKeys, validated by ApplyUserUpdate): a key
// added here must be added there, and a key a builder drifts in without
// changing SyncAttrs hard-errors at the writer instead of silently writing a
// new users column.
//
// The `email` column is an identity-address WRITE, so its parameter is
// identity.CanonicalAddress — a raw u.Email would not compile, forcing the caller
// to route through identity.CanonicalizeAddress. This closes the UPDATE-path
// writer the same way ProvisionAccount closes the create path: users.email is
// Go-canonical by construction on every sync, not just on first provision.
//
// `upn` feeds the krb5_principal column (a Kerberos principal — case-sensitive
// realm by convention), NOT the ad_upn match column, so it stays a raw string and
// is intentionally NOT ASCII-folded. (ad_upn itself is set only on the create
// path via ProvisionAccount; the UPDATE path does not rewrite it.) On the UPDATE
// path krb5_principal is fenced by the always-local-only floor — ApplyUserUpdate
// suppresses the write and audits any would-be overwrite; the attribute stays in
// the map so the suppression is visible as a result.Skipped increment.
func SyncAttrs(email identity.CanonicalAddress, displayName, firstName, lastName, title, phone, upn string) map[string]string {
	return map[string]string{
		"email":          email.String(),
		"display_name":   displayName,
		"first_name":     firstName,
		"last_name":      lastName,
		"job_title":      title,
		"phone":          phone,
		"krb5_principal": upn,
	}
}

// GetBoolConfig reads a boolean config value from system_config.
// Returns false if the key is not found or cannot be read.
func GetBoolConfig(ctx context.Context, pool *pgxpool.Pool, key string) bool {
	var val string
	if err := pool.QueryRow(ctx,
		`SELECT value #>> '{}' FROM system_config WHERE key = $1`, key,
	).Scan(&val); err != nil {
		return false
	}
	return val == "true"
}

// ScanFieldPolicyRows scans pgx Rows from a field_policy query into a set.
// The query should select a single column (field name) filtered by policy = 'local_only'.
func ScanFieldPolicyRows(rows pgx.Rows) (map[string]bool, error) {
	fields := make(map[string]bool)
	for rows.Next() {
		var f string
		if err := rows.Scan(&f); err != nil {
			return nil, err
		}
		fields[f] = true
	}
	return fields, rows.Err()
}
