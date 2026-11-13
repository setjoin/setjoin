package migration

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
	"setjoin.com/mailserver/internal/carddav"
)

// errAddressBookNotOwned is returned by contactStore.insert when the
// ownership-scoped INSERT..SELECT matched no address book row: the target book
// does not exist or is not owned by the verified mailbox (R3), so the contact
// is not written and the import loop records a row error instead of a silent
// no-op.
var errAddressBookNotOwned = errors.New("address book not owned by verified mailbox")

// contactStore is the statement surface shared by the CSV/VCF import loops.
// ownerMailboxID threads the authorization gate's result into EVERY statement
// (R3 — ownership predicate in the same WHERE as each mutation, no
// check-then-act on request-owned ids): when > 0, each statement re-checks
// `addressbooks.mailbox_id = ownerMailboxID` in its own WHERE, so a book that
// is re-parented or deleted mid-import can no longer receive writes. 0 is the
// residual trusted server-side form (the orchestrator's VCF upload phase passes
// a default book it resolved under the job user's own mailboxes); its ids are
// never request-owned, and the connector contact phase must NOT use it —
// CONTACTS-002 r2 moved that path to the owned store after the mailbox-id /
// book-id parameter confusion showed how a scope-0 call turns a numeric
// collision into a cross-tenant write.
type contactStore struct {
	pool           *pgxpool.Pool
	ownerMailboxID int64
}

// ImportVCF parses a multi-VCARD VCF string and imports each contact
// into the specified address book. Trusted-internal form with owner scope 0:
// callers must pass a book id that was itself resolved under an authoritative
// mailbox/user scope server-side (the migration orchestrator's VCF upload
// phase resolves the job user's default book via a user_id-joined query).
// Passing an id that was not resolved under its owning mailbox is a
// cross-tenant insert hazard — the connector contact phase moved to
// ImportVCFOwned for exactly that reason (CONTACTS-002 r2), and the
// authenticated HTTP import path has always required ImportVCFOwned.
func ImportVCF(ctx context.Context, pool *pgxpool.Pool, data string, addressBookID int64, strategy string) (imported int, skipped int, errors []string) {
	return importVCFInto(ctx, contactStore{pool: pool}, data, addressBookID, strategy)
}

// ImportVCFOwned is the owned vCard import (R3 in-statement): ownerMailboxID is
// the mailbox that a gate or server-side resolution proved owns addressBookID —
// the connector contact phase resolves the book under the job's target mailbox
// and threads that mailbox here — and every statement re-checks that pair in
// its own WHERE. A foreign or vanished book yields row errors and zero
// writes, never a cross-tenant insert.
func ImportVCFOwned(ctx context.Context, pool *pgxpool.Pool, data string, addressBookID, ownerMailboxID int64, strategy string) (imported int, skipped int, errors []string) {
	return importVCFInto(ctx, contactStore{pool: pool, ownerMailboxID: ownerMailboxID}, data, addressBookID, strategy)
}

func importVCFInto(ctx context.Context, store contactStore, data string, addressBookID int64, strategy string) (imported int, skipped int, errors []string) {
	cards, errs := splitAndParseVCF(data)
	errors = append(errors, errs...)

	for _, vc := range cards {
		select {
		case <-ctx.Done():
			return imported, skipped, errors
		default:
		}
		switch strategy {
		case "skip":
			if store.exists(ctx, addressBookID, vc.UID) {
				skipped++
				continue
			}
		case "overwrite":
			store.remove(ctx, addressBookID, vc.UID)
		case "rename":
			for store.exists(ctx, addressBookID, vc.UID) {
				vc.UID = vc.UID + "-migrated"
			}
		}

		if err := store.insert(ctx, addressBookID, &vc); err != nil {
			errors = append(errors, fmt.Sprintf("contact %s: %v", vc.UID, err))
			continue
		}
		imported++
	}

	return imported, skipped, errors
}

// splitAndParseVCF splits multi-VCARD data and parses each card.
func splitAndParseVCF(data string) ([]carddav.VCard, []string) {
	var cards []carddav.VCard
	var errs []string

	for _, block := range splitVCF(data) {
		vc, err := carddav.ParseVCard(block)
		if err != nil {
			errs = append(errs, fmt.Sprintf("vcard parse: %v", err))
			continue
		}
		cards = append(cards, vc)
	}
	return cards, errs
}

// VCardsToJSON converts connector vCard payloads into the reducer-owned JMAP
// ContactCard create shape. Parsing stays in Go; ownership, mutation, state and
// notification remain in PostgreSQL.
func VCardsToJSON(data string) ([]byte, error) {
	cards, errs := splitAndParseVCF(data)
	if len(errs) > 0 {
		return nil, fmt.Errorf("%s", errs[0])
	}
	objects := make([]map[string]any, 0, len(cards))
	for _, vc := range cards {
		var emails, phones, urls, instantMessengers, addresses any
		_ = json.Unmarshal([]byte(vcardValuesToJSON(vc.Emails, "address")), &emails)
		_ = json.Unmarshal([]byte(vcardValuesToJSON(vc.Phones, "number")), &phones)
		_ = json.Unmarshal([]byte(vcardValuesToJSON(vc.URLs, "url")), &urls)
		_ = json.Unmarshal([]byte(vcardValuesToJSON(vc.IMPPs, "value")), &instantMessengers)
		_ = json.Unmarshal([]byte(vcardAddressesToJSON(vc.Addresses)), &addresses)
		obj := map[string]any{
			"uid": vc.UID, "displayName": vc.FN, "firstName": parseFirstName(vc.N),
			"lastName": parseLastName(vc.N), "company": vc.ORG, "jobTitle": vc.TITLE,
			"emails": emails, "phones": phones, "urls": urls,
			"instantMessengers": instantMessengers, "addresses": addresses, "notes": vc.NOTE,
		}
		if vc.Birthday != nil {
			obj["birthday"] = vc.Birthday.Format("2006-01-02")
		}
		if vc.Anniversary != nil {
			obj["anniversary"] = vc.Anniversary.Format("2006-01-02")
		}
		objects = append(objects, obj)
	}
	return json.Marshal(objects)
}

// splitVCF splits raw VCF data on VCARD boundaries.
func splitVCF(data string) []string {
	var blocks []string
	var current strings.Builder
	depth := 0

	for _, line := range strings.SplitAfter(data, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(strings.ToUpper(trimmed), "BEGIN:VCARD") {
			current.Reset()
			depth++
		}
		if depth > 0 {
			current.WriteString(line)
		}
		if strings.HasPrefix(strings.ToUpper(trimmed), "END:VCARD") {
			if current.Len() > 0 {
				blocks = append(blocks, current.String())
			}
			depth--
		}
	}
	return blocks
}

// exists reports whether a contact with vcardUID is already in addressBookID.
// The addressbooks join carries the ownership scope (R3) in the same SELECT.
func (s contactStore) exists(ctx context.Context, addressBookID int64, vcardUID string) bool {
	var exists bool
	_ = s.pool.QueryRow(ctx,
		`SELECT EXISTS(
			SELECT 1 FROM contacts c
			JOIN addressbooks ab ON ab.id = c.addressbook_id
			WHERE c.addressbook_id = $1 AND c.vcard_uid = $2
			  AND ($3 <= 0 OR ab.mailbox_id = $3))`,
		addressBookID, vcardUID, s.ownerMailboxID,
	).Scan(&exists)
	return exists
}

// remove deletes a contact from addressBookID with the ownership predicate in
// the same DELETE (R3) — never a separate check-then-delete.
func (s contactStore) remove(ctx context.Context, addressBookID int64, vcardUID string) {
	_, _ = s.pool.Exec(ctx, `
		DELETE FROM contacts c
		USING addressbooks ab
		WHERE ab.id = c.addressbook_id
		  AND c.addressbook_id = $1 AND c.vcard_uid = $2
		  AND ($3 <= 0 OR ab.mailbox_id = $3)`,
		addressBookID, vcardUID, s.ownerMailboxID,
	)
}

// insert writes one contact with the ownership predicate in the same
// statement (R3/R2): the INSERT..SELECT only fires when the target book is
// owned by the verified mailbox, and zero affected rows surfaces as
// errAddressBookNotOwned instead of a silent no-op.
func (s contactStore) insert(ctx context.Context, addressBookID int64, vc *carddav.VCard) error {
	var birthday, anniversary interface{}
	if vc.Birthday != nil {
		birthday = vc.Birthday.Format("2006-01-02")
	}
	if vc.Anniversary != nil {
		anniversary = vc.Anniversary.Format("2006-01-02")
	}

	// Per-field value key — must match the native CardDAV path + export readers
	// (carddav.go: emails="address", phones="number", urls="url"); impps has no
	// canonical reader so it keeps the legacy "value". Using one key for all
	// (the pre-fix bug) blanked phone/url export.
	emails := vcardValuesToJSON(vc.Emails, "address")
	phones := vcardValuesToJSON(vc.Phones, "number")
	urls := vcardValuesToJSON(vc.URLs, "url")
	impps := vcardValuesToJSON(vc.IMPPs, "value")
	addresses := vcardAddressesToJSON(vc.Addresses)

	fn := vc.FN
	if fn == "" {
		fn = vc.N
	}

	tag, err := s.pool.Exec(ctx, `
		INSERT INTO contacts (
			addressbook_id, vcard_uid,
			display_name, first_name, last_name,
			company, job_title,
			emails, phones, urls, instant_msgs,
			addresses, notes,
			birthday, anniversary
		)
		SELECT $1,$2, $3,$4,$5, $6,$7, $8,$9,$10,$11, $12,$13, $14,$15
		WHERE EXISTS (
			SELECT 1 FROM addressbooks ab
			WHERE ab.id = $1 AND ($16 <= 0 OR ab.mailbox_id = $16))`,
		addressBookID, vc.UID,
		fn, parseFirstName(vc.N), parseLastName(vc.N),
		vc.ORG, vc.TITLE,
		emails, phones, urls, impps,
		addresses, vc.NOTE,
		birthday, anniversary,
		s.ownerMailboxID,
	)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return errAddressBookNotOwned
	}
	return err
}

// upsert writes one contact as an atomic, ownership-scoped INSERT .. ON
// CONFLICT DO UPDATE (D-5): a row with the same (addressbook_id, vcard_uid)
// updates IN PLACE — the contact id and its contact_group_members rows are
// preserved, only the payload columns refresh (updated_at bumps) — while an
// absent row inserts. The conflict target is the book-scoped unique key, so
// the updated row necessarily belongs to addressBookID, whose ownership the
// INSERT..SELECT gate re-checks in the same statement (R3): a foreign or
// vanished book inserts/updates nothing and surfaces as errAddressBookNotOwned,
// and a failure leaves the original row intact (single statement, no partial
// effect). The UPDATE arm REGENERATES the etag in the same statement (Astra
// r2): an overwrite that kept the old etag advertised a stale CardDAV
// validator, so a client's If-Match against the pre-import value still
// succeeded and could silently clobber the imported edit — the same
// regenerate-on-update contract as the reducer's jmap_contact_set_update
// (digest(vcard_uid || now(), md5)); the fresh-insert arm leaves etag at its
// empty default, which fails every If-Match closed until the row's first
// observable update. jmap_state stays untouched, matching the plain-insert
// path, whose callers bump the mailbox state via notify_contact_state. The
// column list mirrors insert — keep the two in lockstep.
func (s contactStore) upsert(ctx context.Context, addressBookID int64, vc *carddav.VCard) error {
	var birthday, anniversary interface{}
	if vc.Birthday != nil {
		birthday = vc.Birthday.Format("2006-01-02")
	}
	if vc.Anniversary != nil {
		anniversary = vc.Anniversary.Format("2006-01-02")
	}

	emails := vcardValuesToJSON(vc.Emails, "address")
	phones := vcardValuesToJSON(vc.Phones, "number")
	urls := vcardValuesToJSON(vc.URLs, "url")
	impps := vcardValuesToJSON(vc.IMPPs, "value")
	addresses := vcardAddressesToJSON(vc.Addresses)

	fn := vc.FN
	if fn == "" {
		fn = vc.N
	}

	tag, err := s.pool.Exec(ctx, `
		INSERT INTO contacts (
			addressbook_id, vcard_uid,
			display_name, first_name, last_name,
			company, job_title,
			emails, phones, urls, instant_msgs,
			addresses, notes,
			birthday, anniversary
		)
		SELECT $1,$2, $3,$4,$5, $6,$7, $8,$9,$10,$11, $12,$13, $14,$15
		WHERE EXISTS (
			SELECT 1 FROM addressbooks ab
			WHERE ab.id = $1 AND ($16 <= 0 OR ab.mailbox_id = $16))
		ON CONFLICT (addressbook_id, vcard_uid) DO UPDATE SET
			display_name = EXCLUDED.display_name,
			first_name   = EXCLUDED.first_name,
			last_name    = EXCLUDED.last_name,
			company      = EXCLUDED.company,
			job_title    = EXCLUDED.job_title,
			emails       = EXCLUDED.emails,
			phones       = EXCLUDED.phones,
			urls         = EXCLUDED.urls,
			instant_msgs = EXCLUDED.instant_msgs,
			addresses    = EXCLUDED.addresses,
			notes        = EXCLUDED.notes,
			birthday     = EXCLUDED.birthday,
			anniversary  = EXCLUDED.anniversary,
			updated_at   = now(),
			-- Validator invalidation in the SAME statement (atomic with the
			-- content write): CardDAV clients hold the old etag in If-Match,
			-- so an overwrite that kept it let stale writes succeed over the
			-- imported edit. Same regenerate form as jmap_contact_set_update.
			etag         = encode(digest(contacts.vcard_uid || now()::TEXT, 'md5'), 'hex')`,
		addressBookID, vc.UID,
		fn, parseFirstName(vc.N), parseLastName(vc.N),
		vc.ORG, vc.TITLE,
		emails, phones, urls, impps,
		addresses, vc.NOTE,
		birthday, anniversary,
		s.ownerMailboxID,
	)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return errAddressBookNotOwned
	}
	return err
}

// vcardValuesToJSON encodes a slice of VCard field values as a JSON array.
// Uses "address" as the value key to match the CardDAV native path
// (carddav.go) and the export reader (firstJSONValue(emails, "address")).
// vcardValuesToJSON serializes typed vCard values to the contacts JSONB shape
// [{"type":…,"<valueKey>":…}]. valueKey is the per-field canonical value key
// ("address" for emails, "number" for phones, "url" for urls) so imported rows
// round-trip through the native CardDAV path and the export readers.
func vcardValuesToJSON(vals []carddav.VCardValue, valueKey string) string {
	out := make([]map[string]string, len(vals))
	for i, v := range vals {
		out[i] = map[string]string{"type": v.Type, valueKey: v.Value}
	}
	b, _ := json.Marshal(out)
	return string(b)
}

func vcardAddressesToJSON(vals []carddav.VCardAddress) string {
	type entry struct {
		Type    string `json:"type"`
		Street  string `json:"street"`
		City    string `json:"city"`
		Region  string `json:"region"`
		Code    string `json:"code"`
		Country string `json:"country"`
	}
	out := make([]entry, len(vals))
	for i, v := range vals {
		out[i] = entry{
			Type:    v.Type,
			Street:  v.Street,
			City:    v.City,
			Region:  v.Region,
			Code:    v.Code,
			Country: v.Country,
		}
	}
	b, _ := json.Marshal(out)
	return string(b)
}

// parseFirstName returns the Given name from a vCard N field.
// vCard N format: "Family;Given;Additional;Prefix;Suffix" — parts[1] is Given.
func parseFirstName(n string) string {
	parts := strings.SplitN(n, ";", 3)
	if len(parts) >= 2 {
		v := strings.TrimSpace(parts[1])
		if v != "" {
			return v
		}
	}
	return ""
}

// parseLastName returns the Family name from a vCard N field.
// vCard N format: "Family;Given;Additional;Prefix;Suffix" — parts[0] is Family.
func parseLastName(n string) string {
	parts := strings.SplitN(n, ";", 2)
	if len(parts) >= 1 {
		v := strings.TrimSpace(parts[0])
		if v != "" {
			return v
		}
	}
	return ""
}
