package identity

import (
	"context"
	"fmt"
	"time"

	"setjoin.com/shared/validate"
)

// ProvisionAccount uses the package Querier (QueryRow → pgx.Row), satisfied by
// *pgxpool.Pool, *pgxpool.Conn, and pgx.Tx — a caller can provision on a pool or
// inside an in-flight txn.

// ProvisionAccountParams is the typed argument bundle for the ONE provisioning
// seam (provision_account). Its two identity-address columns are newtypes — NOT
// string — so a writer CANNOT bind a raw u.UPN / u.Email / operator string to
// users.email or users.ad_upn: that fails to COMPILE.
//
// The two columns carry DIFFERENT obligations, by design:
//   - Email is ValidatedAddress: canonical AND structurally-valid (passed
//     validate.ValidateEmail). It can only be minted by ValidateAndCanonicalizeEmail
//     (the validating path operator/admin input takes) or CanonicalAddress.AssumeValidated
//     (the named validation-free directory escape). So a provisioning caller MUST
//     validate the address at compile time — an unvalidated CanonicalAddress no
//     longer satisfies this field. This is the candidate-5 deepening: the
//     identity package now owns its validation boundary.
//   - ADUPN stays CanonicalAddress (canonical only, NOT validated): a UPN is a
//     directory match key that may legitimately not be an RFC-5321 email (a bare
//     `alice@corp`), so forcing validation here would reject valid directory data.
//     It is set ONLY by AD/LDAP sync, both of which canonicalize without validating.
//
// Both minters route through the one CanonicalizeAddress fold, so every value
// reaching these columns has provably passed the one canonicalizer. This is the
// compile-time enforcement that retires fold_stored_address's ongoing-twin
// contract: nothing un-canonical can reach a write.
//
// Email is required (the reducer raises BZ072 on blank). ADUPN is the zero
// CanonicalAddress ("") for non-AD/LDAP writers (admin create / CSV), which the
// reducer COALESCEs away. The non-address fields stay plain types — only the two
// address columns carry the write obligation.
type ProvisionAccountParams struct {
	Email ValidatedAddress // → p_email   (required, canonical + validated)
	ADUPN CanonicalAddress // → p_ad_upn  (canonical; "" for admin/CSV)

	DisplayName   string // → p_display_name
	PasswordHash  string // → p_password_hash ("" → SQL NULL)
	SyncSource    string // → p_sync_source ("local"/"ad"/"ldap")
	FirstName     string // → p_first_name
	LastName      string // → p_last_name
	JobTitle      string // → p_job_title
	Phone         string // → p_phone
	Krb5Principal string // → p_krb5_principal (AD/LDAP bind the UPN here too)

	IsLocalAdmin *bool   // → p_is_local_admin (nil → SQL NULL → reducer default)
	Enabled      *bool   // → p_enabled        (nil → reducer default TRUE)
	DepartmentID *int64  // → p_department_id
	QuotaBytes   *int64  // → p_quota_bytes
	ADObjectGUID *string // → p_ad_object_guid (UUID text; nil for non-AD)
	ADUSNChanged *int64  // → p_ad_usn_changed

	// Guest Accounts G0 (spec P1): guest mode — no mailbox, no domain vivify, no
	// chat autojoin; a guest_accounts satellite row insert with host_domain_id
	// resolved from InvitedBy. Zero-value (Guest=false) is byte-identical to the
	// pre-G0 call shape — every existing writer (AD/LDAP/admin create/CSV) is
	// unaffected.
	Guest          bool       // → p_guest            (default false)
	InvitedBy      *int64     // → p_invited_by       (nil for a non-guest provision)
	GuestExpiresAt *time.Time // → p_guest_expires_at (nil = no expiry)
	CreateOnly     bool       // → p_create_only (admin/CSV insert-only mode)

	// ActorID is the trusted acting-admin identity for the reducer's
	// account_provision audit row (WP3). Nil for machine flows (AD/LDAP/SCIM
	// sync): the reducer records the sync source as the system origin instead.
	ActorID *int64 // → p_actor (appended DEFAULT NULL param; nil keeps old shape)
}

// ProvisionAccount runs the provision_account reducer with the typed params and
// returns its JSONB result ({user_id, mailbox_id, domain_id, username, created}).
// This is the SINGLE Go entry to the address-write path: because its signature
// demands CanonicalAddress for the two address columns, every writer (AD create +
// UPDATE-feed, LDAP, admin create, admin CSV) must canonicalize to compile. A SQL
// NULL is produced for empty optional text via nilIfEmpty so the reducer's
// COALESCE defaults fire exactly as before this seam existed.
//
// Before the reducer call it enforces the RFC 2142 reserved-local-part gate on
// p.Email (validate.IsReservedEmailAddress). This is the one gate that also
// covers the directory-trust AssumeValidated mints (AD/LDAP mail attributes skip
// structural validation by design, but claiming a system local-part is a
// provisioning decision, not a structural property), so no ValidatedAddress
// source can provision postmaster/abuse/... — in the reducer or ahead of it.
// The rejection wraps a *validate.ValidationError (RESERVED_NAME) so HTTP
// callers that errors.As ValidationError surface a clean 400.
func ProvisionAccount(ctx context.Context, q Querier, p ProvisionAccountParams) ([]byte, error) {
	if validate.IsReservedEmailAddress(p.Email.String()) {
		return nil, fmt.Errorf("provision_account: %w",
			validate.NewValidationError("email", "email local-part is reserved (RFC 2142)", "RESERVED_NAME"))
	}
	var out []byte
	err := q.QueryRow(ctx,
		`SELECT provision_account(
		   p_email          => $1,
		   p_display_name   => $2,
		   p_password_hash  => $3,
		   p_is_local_admin => $4,
		   p_enabled        => $5,
		   p_sync_source    => $6,
		   p_first_name     => $7,
		   p_last_name      => $8,
		   p_job_title      => $9,
		   p_phone          => $10,
		   p_department_id  => $11,
		   p_quota_bytes    => $12,
		   p_ad_object_guid => $13,
		   p_ad_usn_changed => $14,
		   p_ad_upn         => $15,
		   p_krb5_principal => $16,
		   p_guest            => $17,
		   p_invited_by       => $18,
		   p_guest_expires_at => $19,
		   p_create_only      => $20,
		   p_actor            => $21)::TEXT::BYTEA`,
		p.Email.String(),
		nilIfEmpty(p.DisplayName),
		nilIfEmpty(p.PasswordHash),
		p.IsLocalAdmin,
		p.Enabled,
		nilIfEmpty(p.SyncSource),
		nilIfEmpty(p.FirstName),
		nilIfEmpty(p.LastName),
		nilIfEmpty(p.JobTitle),
		nilIfEmpty(p.Phone),
		p.DepartmentID,
		p.QuotaBytes,
		nilIfEmpty(derefOrEmpty(p.ADObjectGUID)),
		p.ADUSNChanged,
		nilIfEmpty(p.ADUPN.String()),
		nilIfEmpty(p.Krb5Principal),
		p.Guest,
		p.InvitedBy,
		p.GuestExpiresAt,
		p.CreateOnly,
		p.ActorID,
	).Scan(&out)
	return out, err
}

// nilIfEmpty maps "" → nil so an absent optional text binds as SQL NULL (the
// reducer's COALESCE then keeps the existing value on UPDATE / falls back to its
// default), preserving the exact pre-seam behavior of the hand-rolled calls.
func nilIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// derefOrEmpty returns *p or "" for a nil pointer, so an absent UUID/text pointer
// flows through nilIfEmpty to SQL NULL.
func derefOrEmpty(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}
