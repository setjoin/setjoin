package handlers

import (
	"context"
	"testing"

	"setjoin.com/shared/testsupport"
)

// ── SelectMFAMethod: the Push>TOTP>Backup accept order (Login/WebAuthn) ──────
//
// SelectMFAMethod encodes the EXISTING method-selection cascade used by the
// password Login and the WebAuthn login-finish step: push is offered when it is
// available, otherwise TOTP, otherwise no second factor. Backup codes are never
// a primary challenge (they ride as a fallback list entry), so they never win
// the selection — only the *enrolled* flags TOTP/Push drive the choice, and the
// caller passes pushAvailable = PushMFAEnrolled && pushProvider != nil.
func TestSelectMFAMethod_Ordering(t *testing.T) {
	cases := []struct {
		name          string
		creds         UserCredentials
		pushAvailable bool
		want          string
	}{
		{
			name:          "push wins when available even if totp also enrolled",
			creds:         UserCredentials{TOTPEnrolled: true, PushMFAEnrolled: true},
			pushAvailable: true,
			want:          "push",
		},
		{
			name:          "push-only enrolled and available -> push",
			creds:         UserCredentials{PushMFAEnrolled: true},
			pushAvailable: true,
			want:          "push",
		},
		{
			name:          "push enrolled but provider unavailable falls back to totp",
			creds:         UserCredentials{TOTPEnrolled: true, PushMFAEnrolled: true},
			pushAvailable: false,
			want:          "totp",
		},
		{
			name:          "push enrolled, provider unavailable, no totp -> none",
			creds:         UserCredentials{PushMFAEnrolled: true},
			pushAvailable: false,
			want:          "",
		},
		{
			name:          "totp-only -> totp regardless of pushAvailable arg",
			creds:         UserCredentials{TOTPEnrolled: true},
			pushAvailable: true,
			want:          "totp",
		},
		{
			name:          "no factors enrolled -> none",
			creds:         UserCredentials{},
			pushAvailable: true,
			want:          "",
		},
		{
			name:          "backup codes alone never become a primary challenge",
			creds:         UserCredentials{BackupCodesAvailable: true},
			pushAvailable: true,
			want:          "",
		},
		{
			name:          "webauthn enrollment does not change the second-factor choice",
			creds:         UserCredentials{TOTPEnrolled: true, WebAuthnEnrolled: true},
			pushAvailable: false,
			want:          "totp",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.creds.SelectMFAMethod(tc.pushAvailable); got != tc.want {
				t.Errorf("SelectMFAMethod(%v) = %q, want %q", tc.pushAvailable, got, tc.want)
			}
		})
	}
}

// TestUserCredentials_AnyMFAEnrolled proves the gate helper the Login/WebAuthn
// "is the user enrolled in any challengeable second factor?" check uses matches
// the legacy `TOTPEnabled || PushMFAEnabled` predicate exactly (backup/webauthn
// are not challengeable second factors on these paths, so they do not flip it).
func TestUserCredentials_AnyMFAEnrolled(t *testing.T) {
	cases := []struct {
		creds UserCredentials
		want  bool
	}{
		{UserCredentials{}, false},
		{UserCredentials{TOTPEnrolled: true}, true},
		{UserCredentials{PushMFAEnrolled: true}, true},
		{UserCredentials{TOTPEnrolled: true, PushMFAEnrolled: true}, true},
		{UserCredentials{BackupCodesAvailable: true}, false},
		{UserCredentials{WebAuthnEnrolled: true}, false},
	}
	for _, tc := range cases {
		if got := tc.creds.AnyChallengeMFAEnrolled(); got != tc.want {
			t.Errorf("AnyChallengeMFAEnrolled(%+v) = %v, want %v", tc.creds, got, tc.want)
		}
	}
}

// ── CredentialsFor / CredentialsByEmail (DB-backed edge cases) ───────────────

func TestCredentialsFor_ReadsEnrollmentFlags(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()
	store := dbCredentialStore{pool}

	const email = "credstore-flags@example.com"
	var userID int64
	err := pool.QueryRow(ctx,
		`INSERT INTO users (username, email, display_name, domain_id, sync_source, enabled,
		                    totp_enabled, push_mfa_enabled, totp_backup_codes_enc, webauthn_user_handle)
		 SELECT $1, $1, 'Cred Store', id, 'local', TRUE,
		        TRUE, TRUE, ARRAY['h1','h2']::text[], '\x0102'::bytea
		 FROM domains WHERE is_local = TRUE ORDER BY id LIMIT 1
		 RETURNING id`, email,
	).Scan(&userID)
	if err != nil {
		t.Skipf("could not seed test user (schema/domains not loaded?): %v", err)
	}
	t.Cleanup(func() {
		pool.Exec(ctx, `DELETE FROM passkey_credentials WHERE user_id = $1`, userID)
		pool.Exec(ctx, `DELETE FROM users WHERE id = $1`, userID)
	})

	// A non-revoked passkey credential => WebAuthnEnrolled true.
	if _, err := pool.Exec(ctx,
		`INSERT INTO passkey_credentials (id, user_id, public_key, attestation_type, sign_count)
		 VALUES ('\x99'::bytea, $1, '\x00'::bytea, 'none', 0)`, userID,
	); err != nil {
		t.Fatalf("seed passkey: %v", err)
	}

	creds, err := store.CredentialsFor(ctx, userID)
	if err != nil {
		t.Fatalf("CredentialsFor: %v", err)
	}
	if !creds.TOTPEnrolled || !creds.PushMFAEnrolled || !creds.BackupCodesAvailable || !creds.WebAuthnEnrolled {
		t.Errorf("CredentialsFor = %+v, want all four flags true", creds)
	}
	if creds.UserID != userID {
		t.Errorf("UserID = %d, want %d", creds.UserID, userID)
	}
	if creds.Email != email {
		t.Errorf("Email = %q, want %q", creds.Email, email)
	}

	// CredentialsByEmail must resolve the same row case-insensitively.
	byEmail, err := store.CredentialsByEmail(ctx, "CredStore-Flags@Example.com")
	if err != nil {
		t.Fatalf("CredentialsByEmail: %v", err)
	}
	if byEmail.UserID != userID {
		t.Errorf("CredentialsByEmail UserID = %d, want %d (case-insensitive lookup)", byEmail.UserID, userID)
	}
	if byEmail != creds {
		t.Errorf("CredentialsByEmail = %+v, want identical to CredentialsFor %+v", byEmail, creds)
	}
}

// TestCredentialsFor_NoEnrollments proves a user with no MFA enrollments reads
// back all-false (and that a revoked passkey does not count as enrolled).
func TestCredentialsFor_NoEnrollments(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()
	store := dbCredentialStore{pool}

	const email = "credstore-none@example.com"
	var userID int64
	err := pool.QueryRow(ctx,
		`INSERT INTO users (username, email, display_name, domain_id, sync_source, enabled)
		 SELECT $1, $1, 'Cred None', id, 'local', TRUE
		 FROM domains WHERE is_local = TRUE ORDER BY id LIMIT 1
		 RETURNING id`, email,
	).Scan(&userID)
	if err != nil {
		t.Skipf("could not seed test user: %v", err)
	}
	t.Cleanup(func() {
		pool.Exec(ctx, `DELETE FROM passkey_credentials WHERE user_id = $1`, userID)
		pool.Exec(ctx, `DELETE FROM users WHERE id = $1`, userID)
	})

	// A REVOKED passkey must not count.
	if _, err := pool.Exec(ctx,
		`INSERT INTO passkey_credentials (id, user_id, public_key, attestation_type, sign_count, revoked_at)
		 VALUES ('\x98'::bytea, $1, '\x00'::bytea, 'none', 0, now())`, userID,
	); err != nil {
		t.Fatalf("seed revoked passkey: %v", err)
	}

	creds, err := store.CredentialsFor(ctx, userID)
	if err != nil {
		t.Fatalf("CredentialsFor: %v", err)
	}
	if creds.TOTPEnrolled || creds.PushMFAEnrolled || creds.BackupCodesAvailable || creds.WebAuthnEnrolled {
		t.Errorf("CredentialsFor = %+v, want all four flags false (revoked passkey must not count)", creds)
	}
}

// TestCredentialsByEmail_DisabledUserNotFound proves a disabled account does not
// resolve (parity with verifyPassword / resolveForgotPasswordMethod, which all
// filter enabled = TRUE).
func TestCredentialsByEmail_DisabledUserNotFound(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()
	store := dbCredentialStore{pool}

	const email = "credstore-disabled@example.com"
	var userID int64
	err := pool.QueryRow(ctx,
		`INSERT INTO users (username, email, display_name, domain_id, sync_source, enabled, totp_enabled)
		 SELECT $1, $1, 'Cred Disabled', id, 'local', FALSE, TRUE
		 FROM domains WHERE is_local = TRUE ORDER BY id LIMIT 1
		 RETURNING id`, email,
	).Scan(&userID)
	if err != nil {
		t.Skipf("could not seed test user: %v", err)
	}
	t.Cleanup(func() { pool.Exec(ctx, `DELETE FROM users WHERE id = $1`, userID) })

	if _, err := store.CredentialsByEmail(ctx, email); err == nil {
		t.Error("CredentialsByEmail must not resolve a disabled account (enabled = TRUE filter)")
	}
}
