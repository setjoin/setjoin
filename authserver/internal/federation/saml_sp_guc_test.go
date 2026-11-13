package federation

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"setjoin.com/shared/testsupport"
)

// samlGUCGuardKey is a literal (not GUC-derived) pgcrypto key used to seed the
// idp_cert_enc row independent of any pool's app.encryption_key setting — so
// the seed step never depends on the very GUC these tests are attacking.
const samlGUCGuardKey = "saml-guc-guard-fixed-key-32char"

// seedSAMLGUCGuardCert inserts a committed saml_sp_registrations row whose
// idp_cert_enc is pgp_sym_encrypt'd under samlGUCGuardKey via the literal
// two-arg form, then registers cleanup. Returns the row's idp_entity_id.
func seedSAMLGUCGuardCert(t *testing.T, seedPool *pgxpool.Pool, idpCertPEM string) string {
	t.Helper()
	ctx := context.Background()
	entityID := "https://idp-guc-guard.test/" + time.Now().Format("150405.000000000")
	if _, err := seedPool.Exec(ctx,
		`INSERT INTO saml_sp_registrations
		   (idp_entity_id, idp_sso_url, idp_cert_enc, sp_entity_id, sp_acs_url, enabled)
		 VALUES ($1, 'https://idp-guc-guard.test/sso', pgp_sym_encrypt($2, $3),
		         'https://sp-guc-guard.test', 'https://sp-guc-guard.test/acs', TRUE)`,
		entityID, idpCertPEM, samlGUCGuardKey,
	); err != nil {
		t.Fatalf("seed guc-guard saml_sp_registrations row: %v", err)
	}
	t.Cleanup(func() {
		seedPool.Exec(context.Background(), `DELETE FROM saml_sp_registrations WHERE idp_entity_id = $1`, entityID)
	})
	return entityID
}

// samlDecryptIDPCert runs the EXACT idp_cert_enc decrypt expression
// loadRegistrations uses (saml_sp.go's SELECT), scoped to one row by
// idp_entity_id. This isolates the security-critical decrypt step from
// buildMiddleware's unrelated SAML-metadata-parsing requirements — a fixture
// with dummy IdP metadata errors there regardless of decrypt outcome, which
// would mask (not prove) what this file needs to show. Mirrors
// mail_decrypt_db_test.go's convention of testing the literal query directly
// rather than the full handler when the handler pulls in unrelated I/O.
func samlDecryptIDPCert(ctx context.Context, pool *pgxpool.Pool, entityID string) (string, error) {
	var certPEM string
	err := pool.QueryRow(ctx,
		`SELECT pgp_sym_decrypt(idp_cert_enc, current_setting('app.encryption_key'))
		 FROM saml_sp_registrations WHERE idp_entity_id = $1`,
		entityID,
	).Scan(&certPEM)
	return certPEM, err
}

// TestSAMLIDPCert_DBRoundTrip proves that with the GUC set correctly, the
// idp_cert_enc family's decrypt expression round-trips to the original PEM —
// the (a) case of the per-family (a)/(b)/(c) proof.
func TestSAMLIDPCert_DBRoundTrip(t *testing.T) {
	pool := testsupport.OpenTestPoolWithGUC(t, samlGUCGuardKey)
	const want = "-----BEGIN CERTIFICATE-----\nfake-idp-cert\n-----END CERTIFICATE-----"
	entityID := seedSAMLGUCGuardCert(t, pool, want)

	got, err := samlDecryptIDPCert(context.Background(), pool, entityID)
	if err != nil {
		t.Fatalf("decrypt with correct GUC must succeed: %v", err)
	}
	if got != want {
		t.Errorf("round-trip mismatch: got %q, want %q", got, want)
	}
}

// TestSAMLIDPCert_GUCMissing_FailsClosed proves the idp_cert_enc family fails
// closed — an error, never a NULL/plaintext "success" — when the AfterConnect
// hook that sets app.encryption_key is absent (a misconfigured or bypassed
// pool).
func TestSAMLIDPCert_GUCMissing_FailsClosed(t *testing.T) {
	seedPool := testsupport.OpenTestPoolWithGUC(t, samlGUCGuardKey)
	entityID := seedSAMLGUCGuardCert(t, seedPool, "dummy-idp-cert-pem")

	noGUCPool := testsupport.OpenTestPoolWithGUC(t, "") // GUC never set
	pemOut, err := samlDecryptIDPCert(context.Background(), noGUCPool, entityID)
	if err == nil {
		t.Fatalf("decrypt must error when app.encryption_key GUC is unset, not silently succeed (got %q)", pemOut)
	}
}

// TestSAMLIDPCert_WrongGUC_FailsClosed proves the same family fails loudly (an
// error, not a garbage-cert false success) when app.encryption_key is set to
// the WRONG value.
func TestSAMLIDPCert_WrongGUC_FailsClosed(t *testing.T) {
	seedPool := testsupport.OpenTestPoolWithGUC(t, samlGUCGuardKey)
	entityID := seedSAMLGUCGuardCert(t, seedPool, "dummy-idp-cert-pem")

	wrongPool := testsupport.OpenTestPoolWithGUC(t, "definitely-the-wrong-saml-key-x")
	pemOut, err := samlDecryptIDPCert(context.Background(), wrongPool, entityID)
	if err == nil {
		t.Fatalf("decrypt must error when app.encryption_key GUC is wrong, not silently succeed (got %q)", pemOut)
	}
}
