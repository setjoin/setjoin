package identity

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"
	"setjoin.com/shared/validate"
)

// med-shard2-008 (D-SHARED-VALIDATE-001): the RFC 2142 reserved-local-part gate
// must hold on the provisioning seams. NormalizeAndValidate is the single
// validated-identity seam every operator/admin write routes through
// (ValidateAndCanonicalizeEmail) AND the seam authserver's SSO JIT path wraps
// (normalizeAndValidateSSOEmail), so a reserved rejection here covers admin
// create, CSV import, guests, invites, and JIT-provisioned IdP emails alike.
func TestNormalizeAndValidateRejectsReservedLocalPart(t *testing.T) {
	inputs := []string{
		"postmaster@corp.example",
		"Postmaster@Corp.Example",
		"abuse@corp.example",
		`"abuse"@corp.example`,         // quoting cannot bypass
		"Ops <webmaster@corp.example>", // display-name decoration cannot bypass
		"NOBODY@corp.example",
	}
	for _, in := range inputs {
		canon, err := NormalizeAndValidate(in)
		if err == nil {
			t.Errorf("NormalizeAndValidate(%q) accepted reserved local-part", in)
			continue
		}
		if canon.String() != "" {
			t.Errorf("NormalizeAndValidate(%q) returned non-zero address %q on rejection", in, canon.String())
		}
		var ve *validate.ValidationError
		if !errors.As(err, &ve) || ve.Code != "RESERVED_NAME" {
			t.Errorf("NormalizeAndValidate(%q) error = %v, want wrapped RESERVED_NAME ValidationError", in, err)
		}
	}

	// Ordinary local-parts must still pass.
	canon, err := NormalizeAndValidate("Alice <alice@corp.example>")
	if err != nil {
		t.Fatalf("NormalizeAndValidate ordinary address: %v", err)
	}
	if canon.String() != "alice@corp.example" {
		t.Fatalf("canonical = %q, want alice@corp.example", canon.String())
	}
}

// recordingQuerier panics on use: ProvisionAccount's reserved gate must fire
// BEFORE any SQL is issued.
type recordingQuerier struct{ called bool }

func (r *recordingQuerier) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	r.called = true
	return failingRow{}
}

type failingRow struct{}

func (failingRow) Scan(dest ...any) error { return errors.New("querier must not be reached") }

// med-shard2-008 (D-SHARED-VALIDATE-001): ProvisionAccount is the single Go
// provisioning seam; its own reserved gate is the one that also covers the
// directory-trust AssumeValidated mints (AD/LDAP mail attributes skip
// structural validation by design). An operator-minted ValidatedAddress for a
// reserved local-part must be refused before the reducer is reached.
func TestProvisionAccountRejectsReservedLocalPartBeforeSQL(t *testing.T) {
	// AssumeValidated is the validation-free directory escape: it reaches
	// ProvisionAccount holding a reserved local-part with NO other gate fired.
	email := CanonicalizeAddress("Postmaster@corp.example").AssumeValidated()
	q := &recordingQuerier{}
	_, err := ProvisionAccount(context.Background(), q, ProvisionAccountParams{
		Email:      email,
		SyncSource: "ad",
	})
	if err == nil {
		t.Fatal("ProvisionAccount accepted reserved local-part from the directory-trust mint")
	}
	if q.called {
		t.Fatal("ProvisionAccount reached the querier with a reserved local-part")
	}
	var ve *validate.ValidationError
	if !errors.As(err, &ve) || ve.Code != "RESERVED_NAME" {
		t.Fatalf("ProvisionAccount error = %v, want wrapped RESERVED_NAME ValidationError", err)
	}

	// Quoted-local input cannot bypass (canonical form carries the same
	// local-part sequence, which net/mail unquotes for dot-atom content).
	quoted := CanonicalizeAddress(`"abuse"@corp.example`).AssumeValidated()
	if _, err := ProvisionAccount(context.Background(), &recordingQuerier{}, ProvisionAccountParams{
		Email:      quoted,
		SyncSource: "ldap",
	}); err == nil {
		t.Fatal("ProvisionAccount accepted quoted-local reserved address")
	}
}
