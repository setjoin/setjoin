package migration

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	"setjoin.com/mailserver/internal/carddav"
	"setjoin.com/shared/identity"
)

// Mapping holds the column index of each contact field within a CSV row. An index
// of -1 means the field is absent from the file. The importer uses these indexes
// to project each row onto a carddav.VCard, reusing the shared insertContact path.
type Mapping struct {
	FullName  int `json:"fullName"`
	FirstName int `json:"firstName"`
	LastName  int `json:"lastName"`
	Email     int `json:"email"`
	Company   int `json:"company"`
	JobTitle  int `json:"jobTitle"`
	Phone     int `json:"phone"`
	Notes     int `json:"notes"`
}

// emptyMapping returns a Mapping with every field absent (-1).
func emptyMapping() Mapping {
	return Mapping{FullName: -1, FirstName: -1, LastName: -1, Email: -1,
		Company: -1, JobTitle: -1, Phone: -1, Notes: -1}
}

// aliases maps each target field to the lower-cased header strings that select it
// (Outlook + Google Contacts CSV conventions). The first column whose normalized
// header matches an alias wins; later duplicates are ignored.
var aliases = map[string][]string{
	"fullName":  {"name", "display name", "full name"},
	"firstName": {"first name", "given name", "firstname"},
	"lastName":  {"last name", "family name", "surname", "lastname"},
	"email":     {"e-mail address", "email", "e-mail 1 - value", "email address", "primary email", "e-mail"},
	"company":   {"company", "organization", "organization 1 - name", "organisation"},
	"jobTitle":  {"job title", "title", "organization 1 - title"},
	"phone":     {"mobile phone", "phone", "primary phone", "phone 1 - value", "telephone", "mobile"},
	"notes":     {"notes", "note"},
}

// DetectMapping inspects CSV headers and returns the best-guess column mapping.
func DetectMapping(headers []string) Mapping {
	m := emptyMapping()
	for i, h := range headers {
		norm := strings.ToLower(strings.TrimSpace(h))
		switch {
		case m.FullName < 0 && matchAlias(norm, aliases["fullName"]):
			m.FullName = i
		case m.FirstName < 0 && matchAlias(norm, aliases["firstName"]):
			m.FirstName = i
		case m.LastName < 0 && matchAlias(norm, aliases["lastName"]):
			m.LastName = i
		case m.Email < 0 && matchAlias(norm, aliases["email"]):
			m.Email = i
		case m.Company < 0 && matchAlias(norm, aliases["company"]):
			m.Company = i
		case m.JobTitle < 0 && matchAlias(norm, aliases["jobTitle"]):
			m.JobTitle = i
		case m.Phone < 0 && matchAlias(norm, aliases["phone"]):
			m.Phone = i
		case m.Notes < 0 && matchAlias(norm, aliases["notes"]):
			m.Notes = i
		}
	}
	return m
}

func matchAlias(norm string, set []string) bool {
	for _, a := range set {
		if norm == a {
			return true
		}
	}
	return false
}

// cell safely reads the column at idx from a row, returning "" when the index is
// absent (-1) or out of range (a ragged/short row).
func cell(row []string, idx int) string {
	if idx < 0 || idx >= len(row) {
		return ""
	}
	return strings.TrimSpace(row[idx])
}

// csvIdentityNamespace namespaces the derived CSV contact UIDs. Changing it
// (or the derivation below) orphans every previously derived UID, so it is
// versioned: a future identity-rule change must bump it (never silently
// rewrite identities under the same namespace).
const csvIdentityNamespace = "setjoin-csv-contact-v1"

// csvIdentityUID derives the stable per-contact vCard UID (D-5) from the
// namespaced identity key. The key is the decoded identity VALUE (see
// RowToVCard) canonicalized with the project's address canonicalizer
// (identity.CanonicalizeAddress: TrimSpace + ASCII A-Z fold, display-strip
// when the value parses as an RFC 5322 address) — NOT unicode ToLower, whose
// Turkish-İ fold is the deliberate non-goal of the shared fold. The key is
// namespaced by the derivation scheme tag, the KIND of identity field
// ("email" / "name") and the TARGET ADDRESS BOOK id, so the same row imported
// into two different books carries two distinct UIDs and re-derivation is
// deterministic across processes and imports:
//
//	UID = "csv-" ⧺ hex(sha256(csvIdentityNamespace ␀ bookID ␀ kind ␀ canonicalValue))
func csvIdentityUID(addressBookID int64, kind, value string) string {
	h := sha256.New()
	h.Write([]byte(csvIdentityNamespace))
	h.Write([]byte{0})
	h.Write([]byte(fmt.Sprintf("%d", addressBookID)))
	h.Write([]byte{0})
	h.Write([]byte(kind))
	h.Write([]byte{0})
	h.Write([]byte(value))
	return "csv-" + hex.EncodeToString(h.Sum(nil))
}

// RowToVCard projects a single CSV row onto a carddav.VCard using this mapping.
// FN is the full-name cell when present, else "First Last". N is "Last;First;;;".
// An EMAIL/TEL is appended only when its cell is non-empty.
//
// The UID is DERIVED, not minted (D-5): CSV exports carry no vCard UID, so the
// row's identity key — computed AFTER the column mapping and the import
// dialect's decoding, i.e. from exactly the values the importer stores — is
// hashed into a stable namespaced UID (csvIdentityUID). This is what makes the
// skip/overwrite duplicate strategies real across re-imports instead of the
// pre-D-5 no-ops (RowToVCard minted uuid.NewString() per row, so a re-import
// never matched an existing UID).
//
// Identity key resolution (the D-5 amendment's exact definition):
//
//   - email present after decoding (the mapped email cell is non-blank):
//     the CANONICALIZED EMAIL is the key — the email is the identity anchor,
//     so changed names/notes still resolve to the same contact, case-variant
//     or whitespace-padded emails dedupe, and a mapping override that points
//     Email elsewhere changes which column anchors identity;
//   - no email column mapped at all (mapping.Email < 0 or the cell is out of
//     range for a ragged row): the CANONICALIZED FN (display/full name) is the
//     weaker fallback key — a name edit re-identifies under this fallback
//     (inherent to name-anchored identity);
//   - neither a decodable email nor a decodable name: the UID is left empty
//     and importCSVInto SKIPS the row (an unidentifiable contact would
//     re-import as unmatchable duplicates every time).
//
// NOTE (D-5): contacts imported before this change carry random UUIDs and are
// NOT auto-reconciled — a re-import of the same people under the stable key
// cannot match the legacy rows (they skip/overwrite only their own derived
// identity); reconciling a legacy book is a separate, explicit exercise.
func (m Mapping) RowToVCard(row []string, addressBookID int64) carddav.VCard {
	first := cell(row, m.FirstName)
	last := cell(row, m.LastName)
	full := cell(row, m.FullName)

	fn := full
	if fn == "" {
		fn = strings.TrimSpace(strings.TrimSpace(first + " " + last))
	}

	vc := carddav.VCard{
		FN:    fn,
		N:     last + ";" + first + ";;;",
		ORG:   cell(row, m.Company),
		TITLE: cell(row, m.JobTitle),
		NOTE:  cell(row, m.Notes),
	}

	if email := cell(row, m.Email); email != "" {
		vc.Emails = append(vc.Emails, carddav.VCardValue{Type: "work", Value: email})
		vc.UID = csvIdentityUID(addressBookID, "email", identity.CanonicalizeAddress(email).String())
	}
	if phone := cell(row, m.Phone); phone != "" {
		vc.Phones = append(vc.Phones, carddav.VCardValue{Type: "work", Value: phone})
	}
	if vc.UID == "" {
		if key := identity.CanonicalizeAddress(fn).String(); key != "" {
			vc.UID = csvIdentityUID(addressBookID, "name", key)
		}
	}
	return vc
}
