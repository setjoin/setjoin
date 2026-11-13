package booking

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/minio/minio-go/v7"
	"setjoin.com/mailserver/internal/notify"
)

// email.go — the two plain-text notification emails the public booking
// surface sends: the booker's verification link (double opt-in — no calendar
// event exists until this is clicked) and the owner's new-booking heads-up.
// Both go through the SAME egress the calendar iTIP invites use (build MIME
// -> content-addressed MinIO blob -> outbound_queue row) — see
// internal/jmap/calendar.go:390-397 (serializeAndEnqueueInvite), the
// established precedent for "gateway builds MIME, worker delivers it".
//
// ponytail: shared single-part quoted-printable MIME is enough here. Upgrade
// to a multipart builder if a future requirement adds HTML or attachments.

// newToken returns a fresh random token (32 bytes, base64url — RawURLEncoding
// so it's link-safe with no padding). The same string is hashed (sha256Hex)
// both when it is minted and again when the caller submits it back — the
// gateway never decodes it, so the raw bytes never need round-tripping.
func newToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand.Read failing means the OS entropy source is broken —
		// not a recoverable request-level error.
		panic("booking: crypto/rand unavailable: " + err.Error())
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func sha256Hex(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// buildPlainMIME delegates to the shared system-mail renderer.
func buildPlainMIME(fromAddr, fromName, toAddr, subject, body string) (mime, messageID string) {
	return notify.BuildSystemMIME(fromAddr, fromName, toAddr, subject, body, "booking-")
}

// enqueue stores mime as a content-addressed MinIO blob (keyPrefix + sha256)
// and inserts the outbound_queue row — identical shape to
// serializeAndEnqueueInvite's INSERT (internal/jmap/calendar.go).
func (h *PublicHandler) enqueue(ctx context.Context, keyPrefix, mime, messageID, fromAddr, toAddr string) error {
	if h.minio == nil || h.pool.Pool == nil {
		return nil // disabled in this deployment (e.g. unit tests) — best-effort
	}
	hash := sha256.Sum256([]byte(mime))
	key := keyPrefix + hex.EncodeToString(hash[:]) + ".eml"
	if _, err := h.minio.PutObject(ctx, h.bucket, key,
		strings.NewReader(mime), int64(len(mime)),
		minio.PutObjectOptions{ContentType: "message/rfc822"}); err != nil {
		return fmt.Errorf("store blob: %w", err)
	}
	if _, err := h.pool.Exec(ctx,
		`INSERT INTO outbound_queue (message_id, from_addr, rcpt_addrs, raw_ref, status)
		 VALUES ($1, $2, $3, $4, 'pending')`,
		messageID, fromAddr, []string{toAddr}, key); err != nil {
		return fmt.Errorf("enqueue: %w", err)
	}
	return nil
}

// sendVerificationEmail sends the booker their double-opt-in link. Best-effort
// (logs and returns on failure) — the booking_create row already committed;
// the booker can be re-sent the link by re-submitting the booking form.
func (h *PublicHandler) sendVerificationEmail(ctx context.Context, ownerEmail, bookerEmail, pageTitle, token string) {
	link := h.publicBaseURL + "/book/confirm?token=" + token
	body := fmt.Sprintf(
		"Please confirm your booking for %q.\n\n"+
			"Click to confirm (valid for 24 hours):\n%s\n\n"+
			"If you didn't request this, ignore this email.\n",
		pageTitle, link)
	mime, messageID := buildPlainMIME(ownerEmail, "", bookerEmail,
		"Confirm your booking: "+pageTitle, body)
	if err := h.enqueue(ctx, "booking/verify/", mime, messageID, ownerEmail, bookerEmail); err != nil {
		h.logger.Error("booking: verification email failed", "error", err)
	}
}

// sendOwnerNotification tells the page owner a booking was just confirmed.
// payload is the booking_confirm JSONB result (ownerEmail/bookerEmail/
// slotStart/slotEnd/pageTitle already on it — no second DB round trip).
func (h *PublicHandler) sendOwnerNotification(ctx context.Context, ownerEmail, bookerEmail, pageTitle, slotStart string) {
	body := fmt.Sprintf(
		"%s just booked \"%s\" with you.\n\nWhen: %s\n\nA calendar invite has been sent separately.\n",
		bookerEmail, pageTitle, slotStart)
	mime, messageID := buildPlainMIME(ownerEmail, "", ownerEmail,
		"New booking: "+pageTitle, body)
	if err := h.enqueue(ctx, "booking/notify/", mime, messageID, ownerEmail, ownerEmail); err != nil {
		h.logger.Error("booking: owner notification email failed", "error", err)
	}
}
