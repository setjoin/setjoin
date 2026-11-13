package migration

import (
	"strings"
	"testing"
)

func TestDetectMapping_Outlook(t *testing.T) {
	headers := []string{"First Name", "Last Name", "E-mail Address", "Company", "Mobile Phone"}
	m := DetectMapping(headers)
	if m.FirstName != 0 {
		t.Errorf("FirstName = %d, want 0", m.FirstName)
	}
	if m.LastName != 1 {
		t.Errorf("LastName = %d, want 1", m.LastName)
	}
	if m.Email != 2 {
		t.Errorf("Email = %d, want 2", m.Email)
	}
	if m.Company != 3 {
		t.Errorf("Company = %d, want 3", m.Company)
	}
	if m.Phone != 4 {
		t.Errorf("Phone = %d, want 4", m.Phone)
	}
}

func TestDetectMapping_Google(t *testing.T) {
	headers := []string{"Name", "Given Name", "Family Name", "E-mail 1 - Value", "Organization 1 - Name"}
	m := DetectMapping(headers)
	if m.FullName != 0 {
		t.Errorf("FullName = %d, want 0", m.FullName)
	}
	if m.FirstName != 1 {
		t.Errorf("FirstName = %d, want 1", m.FirstName)
	}
	if m.LastName != 2 {
		t.Errorf("LastName = %d, want 2", m.LastName)
	}
	if m.Email != 3 {
		t.Errorf("Email = %d, want 3", m.Email)
	}
	if m.Company != 4 {
		t.Errorf("Company = %d, want 4", m.Company)
	}
}

func TestDetectMapping_Absent(t *testing.T) {
	// A header set with no recognizable phone/notes columns leaves those at -1.
	m := DetectMapping([]string{"First Name", "Last Name", "Email"})
	if m.Phone != -1 {
		t.Errorf("Phone = %d, want -1 (absent)", m.Phone)
	}
	if m.Notes != -1 {
		t.Errorf("Notes = %d, want -1 (absent)", m.Notes)
	}
	if m.Email != 2 {
		t.Errorf("Email = %d, want 2", m.Email)
	}
}

func TestRowToVCard(t *testing.T) {
	m := Mapping{FirstName: 0, LastName: 1, Email: 2, FullName: -1, Company: -1, JobTitle: -1, Phone: -1, Notes: -1}
	vc := m.RowToVCard([]string{"Alice", "Smith", "alice@x.test"}, 42)
	if vc.FN != "Alice Smith" {
		t.Errorf("FN = %q, want \"Alice Smith\"", vc.FN)
	}
	if len(vc.Emails) != 1 {
		t.Fatalf("len(Emails) = %d, want 1", len(vc.Emails))
	}
	if vc.Emails[0].Value != "alice@x.test" {
		t.Errorf("Emails[0].Value = %q, want alice@x.test", vc.Emails[0].Value)
	}
	// D-5: the UID is DERIVED (stable, deterministic), not a random UUID.
	if vc.UID == "" {
		t.Error("UID should be derived from the row identity")
	}
	if again := m.RowToVCard([]string{"Alice", "Smith", "alice@x.test"}, 42); again.UID != vc.UID {
		t.Errorf("UID not stable across derivations: %q vs %q", vc.UID, again.UID)
	}
	if vc.N != "Smith;Alice;;;" {
		t.Errorf("N = %q, want \"Smith;Alice;;;\"", vc.N)
	}
}

func TestRowToVCard_FullNameAndExtras(t *testing.T) {
	m := Mapping{FirstName: -1, LastName: -1, FullName: 0, Email: 1, Company: 2, JobTitle: 3, Phone: 4, Notes: 5}
	vc := m.RowToVCard([]string{"Bob Lee", "bob@x.test", "Acme", "Engineer", "+1-555-0100", "vip"}, 42)
	if vc.FN != "Bob Lee" {
		t.Errorf("FN = %q, want \"Bob Lee\"", vc.FN)
	}
	if vc.ORG != "Acme" {
		t.Errorf("ORG = %q, want Acme", vc.ORG)
	}
	if vc.TITLE != "Engineer" {
		t.Errorf("TITLE = %q, want Engineer", vc.TITLE)
	}
	if vc.NOTE != "vip" {
		t.Errorf("NOTE = %q, want vip", vc.NOTE)
	}
	if len(vc.Phones) != 1 || vc.Phones[0].Value != "+1-555-0100" {
		t.Errorf("Phones = %+v, want one +1-555-0100", vc.Phones)
	}
}

func TestRowToVCard_ShortRow(t *testing.T) {
	// A row shorter than the mapped indexes must not panic; missing cells are empty.
	m := Mapping{FirstName: 0, LastName: 1, Email: 5, FullName: -1, Company: -1, JobTitle: -1, Phone: -1, Notes: -1}
	vc := m.RowToVCard([]string{"Carol"}, 42)
	if vc.FN != "Carol" {
		t.Errorf("FN = %q, want Carol", vc.FN)
	}
	if len(vc.Emails) != 0 {
		t.Errorf("len(Emails) = %d, want 0 (email cell out of range)", len(vc.Emails))
	}
	// No email cell at all → the NAME fallback identity.
	if vc.UID == "" {
		t.Error("UID = \"\", want the name-fallback identity for a row with no email cell")
	}
}

// TestRowToVCard_UnidentifiableRowSkipped pins the third branch of the D-5
// identity definition: a row with no decodable email AND no decodable name
// leaves the UID empty — importCSVInto skips it rather than minting an
// unreproducible identity.
func TestRowToVCard_UnidentifiableRowSkipped(t *testing.T) {
	m := Mapping{FirstName: -1, LastName: -1, Email: -1, FullName: -1, Company: 0, JobTitle: -1, Phone: -1, Notes: -1}
	if vc := m.RowToVCard([]string{"Acme"}, 42); vc.UID != "" {
		t.Errorf("UID = %q for a nameless, emailless row, want \"\"", vc.UID)
	}
}

// TestRowToVCard_IdentityKeyPins pins the D-5 identity key exactly:
// email-anchored (case/padding-insensitive, name-edit-immune), namespaced per
// address book, and mapping-override-sensitive.
func TestRowToVCard_IdentityKeyPins(t *testing.T) {
	base := Mapping{FullName: 0, Email: 1}

	// Email-case and padding variants are the SAME identity.
	uidA := base.RowToVCard([]string{"Alice One", "a1@example.test"}, 7).UID
	uidB := base.RowToVCard([]string{"Alice One", "  A1@Example.TEST "}, 7).UID
	if uidA != uidB {
		t.Errorf("case/padding variants diverged: %q vs %q", uidA, uidB)
	}

	// A changed NAME/notes does NOT change the identity (email-anchored).
	uidC := base.RowToVCard([]string{"Alice RENAMED", "a1@example.test"}, 7).UID
	if uidC != uidA {
		t.Errorf("name edit changed the identity: %q vs %q", uidA, uidC)
	}

	// A changed EMAIL is a different contact (a new identity, not a rename).
	uidD := base.RowToVCard([]string{"Alice One", "moved@example.test"}, 7).UID
	if uidD == uidA {
		t.Error("a different email must derive a different identity")
	}

	// Separate address books namespace the same row apart.
	uidE := base.RowToVCard([]string{"Alice One", "a1@example.test"}, 8).UID
	if uidE == uidA {
		t.Error("the same row in a different address book must derive a different UID")
	}

	// The UID is not guessable from the raw email (namespaced hash).
	if strings.Contains(uidA, "a1@example.test") || !strings.HasPrefix(uidA, "csv-") {
		t.Errorf("UID %q is not the namespaced csv-<sha256> form", uidA)
	}

	// Mapping overrides change which column anchors identity: overriding the
	// email column to a cell with a different address re-identifies the row.
	override := Mapping{FullName: 0, Email: 2}
	uidF := override.RowToVCard([]string{"Alice One", "a1@example.test", "alt@example.test"}, 7).UID
	if uidF == uidA {
		t.Error("mapping override to a different email column must change the derived identity")
	}

	// No-email-column files fall back to the name identity deterministically.
	nameOnly := Mapping{FullName: 0, Email: -1}
	uidG := nameOnly.RowToVCard([]string{"Alice One"}, 7).UID
	if uidG == "" || uidG != nameOnly.RowToVCard([]string{"ALICE ONE"}, 7).UID {
		t.Errorf("name fallback not deterministic/case-stable: %q", uidG)
	}
}
