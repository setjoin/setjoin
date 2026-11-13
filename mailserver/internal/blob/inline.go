package blob

import "strings"

// IsInlineMessage reports whether a raw_ref value (messages.raw_ref /
// outbound_queue.raw_ref) is the inline RFC 5322 message text itself rather
// than an object-store key. It is THE discriminator every consumer that can
// legally receive both kinds must route through (jmap sign/encrypt raw
// resolution, the SMTP outbound worker's blob load).
//
// WHY a line-break check: raw_ref carries two families of value —
//
//   - object keys / sentinels, always single-line path-ish strings: bare
//     sha256 hex (jmap sign/encrypt/attachment-assembly stores), "inbound/<hex>"
//     (SMTP MTA), "blobs/<hex>" (SMTP MSA), "dmarc/<hex>.eml", "dsn/<id>/<id>",
//     iMIP keys, "system:welcome:<uid>", "append-<uid>";
//
//   - the inline RFC 5322 message text — reducer-built drafts (jmap_email.sql
//     Email/set create builds v_raw_msg from CRLF-terminated header lines, so
//     it is always multi-line, starting "Message-ID: <...>\r\n"), which
//     send.sql passes verbatim into outbound_queue ("MinIO path or inline").
//
// A line break is the one robust discriminator: every inline message contains
// one inside its first header line, while no key producer emits one (keys here
// are hex digests and short path segments; a sha-256-shape check would instead
// misclassify the prefixed keys above). Sentinels classify as keys — correct:
// they are not deliverable text, and fetching them fails loudly as before.
func IsInlineMessage(ref string) bool {
	return strings.ContainsAny(ref, "\r\n")
}
