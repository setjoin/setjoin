package carddav

import (
	"context"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// renderVCards concatenates each contact's vCard block into one document. RFC 6350
// allows multiple vCards catenated in a single .vcf file.
func renderVCards(contacts []*contactRow) string {
	var b strings.Builder
	for _, c := range contacts {
		b.WriteString(contactToVCard(c))
	}
	return b.String()
}

// ExportVCards loads a mailbox-owned address book's contacts and renders them as a
// single .vcf document, reusing contactToVCard (the same serializer CardDAV GET/
// PROPFIND use) so the export stays byte-compatible with the CardDAV surface.
//
// Ownership is enforced IN-QUERY (R1/D-MAILSERVER-INTERNAL-CARDDAV-V-003): the
// contacts→addressbooks→mailboxes join filters on mb.user_id = userID, so a
// cross-user addressBookID yields zero rows — the functions no longer trust the
// caller's pre-verification gate (which remains as the UX 403/404 layer). This
// mirrors getContactByUID/etagFromResult's in-query ownership shape.
func ExportVCards(ctx context.Context, pool *pgxpool.Pool, addressBookID, userID int64) (string, error) {
	rows, err := pool.Query(ctx, `
		SELECT c.id, c.addressbook_id, c.vcard_uid, c.display_name, c.first_name, c.last_name,
		       c.company, c.job_title, c.department, c.emails, c.phones, c.addresses, c.urls,
		       c.instant_msgs, c.notes, c.birthday, c.anniversary, c.avatar_sha256, c.categories, c.etag, c.updated_at
		FROM contacts c
		JOIN addressbooks ab ON ab.id = c.addressbook_id
		JOIN mailboxes mb ON mb.id = ab.mailbox_id
		WHERE c.addressbook_id = $1 AND mb.user_id = $2
		ORDER BY c.display_name`, addressBookID, userID)
	if err != nil {
		return "", fmt.Errorf("contacts query: %w", err)
	}
	defer rows.Close()

	var contacts []*contactRow
	for rows.Next() {
		c := &contactRow{}
		if err := scanContact(rows, c); err != nil {
			return "", fmt.Errorf("contacts scan: %w", err)
		}
		contacts = append(contacts, c)
	}
	if err := rows.Err(); err != nil {
		return "", fmt.Errorf("contacts iterate: %w", err)
	}
	return renderVCards(contacts), nil
}

// ExportVCard loads a single contact and renders it as one vCard block, reusing
// scanContact/contactToVCard (the same serializer ExportVCards/CardDAV use).
// Returns pgx.ErrNoRows when contactID doesn't exist OR is not owned by userID —
// ownership is enforced IN-QUERY (R1/D-MAILSERVER-INTERNAL-CARDDAV-V-003) via
// the contacts→addressbooks→mailboxes join on mb.user_id, so a cross-user id is
// indistinguishable from a missing one (no existence oracle); the caller's
// pre-verification gate remains as the UX 403 layer.
func ExportVCard(ctx context.Context, pool *pgxpool.Pool, contactID, userID int64) (vcard, displayName string, err error) {
	rows, err := pool.Query(ctx, `
		SELECT c.id, c.addressbook_id, c.vcard_uid, c.display_name, c.first_name, c.last_name,
		       c.company, c.job_title, c.department, c.emails, c.phones, c.addresses, c.urls,
		       c.instant_msgs, c.notes, c.birthday, c.anniversary, c.avatar_sha256, c.categories, c.etag, c.updated_at
		FROM contacts c
		JOIN addressbooks ab ON ab.id = c.addressbook_id
		JOIN mailboxes mb ON mb.id = ab.mailbox_id
		WHERE c.id = $1 AND mb.user_id = $2`, contactID, userID)
	if err != nil {
		return "", "", fmt.Errorf("contact query: %w", err)
	}
	defer rows.Close()

	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return "", "", fmt.Errorf("contact iterate: %w", err)
		}
		return "", "", pgx.ErrNoRows
	}
	c := &contactRow{}
	if err := scanContact(rows, c); err != nil {
		return "", "", fmt.Errorf("contact scan: %w", err)
	}
	return contactToVCard(c), c.DisplayName, nil
}
