package carddav

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"setjoin.com/shared/testsupport"
)

// TestRenderVCards_ConcatenatesMultipleContacts is the public-interface contract for
// the new .vcf export path: each contact renders as its own BEGIN..END:VCARD block
// (via the existing contactToVCard serializer), concatenated in the given order.
func TestRenderVCards_ConcatenatesMultipleContacts(t *testing.T) {
	contacts := []*contactRow{
		{VCardUID: "uid-1", DisplayName: "Alice Smith"},
		{VCardUID: "uid-2", DisplayName: "Bob Jones"},
	}
	out := renderVCards(contacts)

	if got := strings.Count(out, "BEGIN:VCARD"); got != 2 {
		t.Fatalf("BEGIN:VCARD count = %d, want 2 (out=%q)", got, out)
	}
	if !strings.Contains(out, "FN:Alice Smith") || !strings.Contains(out, "FN:Bob Jones") {
		t.Fatalf("output missing expected FN lines: %s", out)
	}
	if strings.Index(out, "Alice") > strings.Index(out, "Bob") {
		t.Fatalf("expected Alice's block before Bob's, got: %s", out)
	}
}

// TestExportVCard_InQueryOwnershipScope pins the R4 in-query ownership scoping
// (D-MAILSERVER-INTERNAL-CARDDAV-V-003): ExportVCard/ExportVCards carry the
// contacts→addressbooks→mailboxes.user_id filter themselves, so a cross-user id
// is indistinguishable from a missing one (pgx.ErrNoRows / empty render) even
// without any caller-side gate.
func TestExportVCard_InQueryOwnershipScope(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()

	var ownerMbID int64
	if err := pool.QueryRow(ctx, `SELECT mk_account('vcf_export_owner')`).Scan(&ownerMbID); err != nil {
		t.Fatalf("mk_account (owner): %v", err)
	}
	var ownerID int64
	if err := pool.QueryRow(ctx, `SELECT user_id FROM mailboxes WHERE id=$1`, ownerMbID).Scan(&ownerID); err != nil {
		t.Fatalf("owner user_id: %v", err)
	}
	t.Cleanup(func() { teardownAccount(ctx, pool, ownerMbID, ownerID) })

	var otherMbID int64
	if err := pool.QueryRow(ctx, `SELECT mk_account('vcf_export_other')`).Scan(&otherMbID); err != nil {
		t.Fatalf("mk_account (other): %v", err)
	}
	var otherID int64
	if err := pool.QueryRow(ctx, `SELECT user_id FROM mailboxes WHERE id=$1`, otherMbID).Scan(&otherID); err != nil {
		t.Fatalf("other user_id: %v", err)
	}
	t.Cleanup(func() { teardownAccount(ctx, pool, otherMbID, otherID) })

	var abID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO addressbooks (mailbox_id, name) VALUES ($1,'VCF Export') RETURNING id`, ownerMbID,
	).Scan(&abID); err != nil {
		t.Fatalf("insert addressbook: %v", err)
	}
	var contactID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO contacts (addressbook_id, vcard_uid, display_name, etag) VALUES ($1,'vex-1','Owned Contact','et1') RETURNING id`,
		abID,
	).Scan(&contactID); err != nil {
		t.Fatalf("insert contact: %v", err)
	}

	// The owner resolves and renders the contact.
	vcard, _, err := ExportVCard(ctx, pool, contactID, ownerID)
	if err != nil {
		t.Fatalf("owner ExportVCard: %v", err)
	}
	if !strings.Contains(vcard, "Owned Contact") {
		t.Errorf("owner render missing FN line: %q", vcard)
	}
	out, err := ExportVCards(ctx, pool, abID, ownerID)
	if err != nil {
		t.Fatalf("owner ExportVCards: %v", err)
	}
	if !strings.Contains(out, "Owned Contact") {
		t.Errorf("owner bulk render missing the contact: %q", out)
	}

	// A different user gets ErrNoRows / an empty render for the SAME live ids —
	// no existence oracle, no caller-side gate required.
	if _, _, err := ExportVCard(ctx, pool, contactID, otherID); err == nil {
		t.Error("cross-user ExportVCard must return an error (pgx.ErrNoRows shape), got nil")
	} else if !errors.Is(err, pgx.ErrNoRows) {
		t.Errorf("cross-user ExportVCard error = %v, want pgx.ErrNoRows", err)
	}
	out, err = ExportVCards(ctx, pool, abID, otherID)
	if err != nil {
		t.Fatalf("cross-user ExportVCards: %v", err)
	}
	if strings.Contains(out, "Owned Contact") || out != "" {
		t.Errorf("cross-user ExportVCards must render nothing, got %q", out)
	}
}
