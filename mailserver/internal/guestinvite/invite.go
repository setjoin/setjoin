// Package guestinvite owns guest invitation credential minting and delivery.
// Raw tokens exist only in this package's short-lived Prepared value and the
// outbound email body; PostgreSQL receives only their SHA-256 digest.
package guestinvite

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/mail"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/minio/minio-go/v7"
	"setjoin.com/mailserver/internal/notify"
)

const defaultTTLDays = 7

// Prepared is an uncommitted invite credential. Keep it in memory only and
// call Send only after the transaction passed to Prepare has committed.
type Prepared struct {
	inviteID    int64
	rawToken    string
	fromAddr    string
	orgName     string
	authBaseURL string
	expiresAt   time.Time
	ttlDays     int
}

func (p Prepared) ExpiresAt() time.Time   { return p.expiresAt }
func (p Prepared) InviteID() int64        { return p.inviteID }
func (p Prepared) InviteIDString() string { return strconv.FormatInt(p.inviteID, 10) }

// Prepare mints a 256-bit opaque token and records only its SHA-256 digest via
// the authoritative guest_invite_create reducer in the caller's transaction.
func Prepare(ctx context.Context, tx pgx.Tx, creatorUserID, guestUserID int64) (Prepared, error) {
	ttlDays, err := ttlDays(ctx, tx)
	if err != nil {
		return Prepared{}, err
	}

	var hostDomainID int64
	var guestExpiresAt *time.Time
	var creatorEmail, orgName, fromAddr, authBaseURL string
	if err := tx.QueryRow(ctx,
		`SELECT ga.host_domain_id, ga.expires_at, creator.email, d.name,
		        COALESCE(NULLIF((SELECT value #>> '{}' FROM system_config WHERE key='mail.default_sender'), ''),
		                 'noreply@' || d.name),
		        COALESCE(NULLIF((SELECT value #>> '{}' FROM system_config WHERE key='authserver.public_url'), ''), '')
		   FROM guest_accounts ga
		   JOIN domains d ON d.id=ga.host_domain_id
		   JOIN users creator ON creator.id=$1
		  WHERE ga.user_id=$2`, creatorUserID, guestUserID,
	).Scan(&hostDomainID, &guestExpiresAt, &creatorEmail, &orgName, &fromAddr, &authBaseURL); err != nil {
		return Prepared{}, fmt.Errorf("resolve invite metadata: %w", err)
	}
	if addr, err := mail.ParseAddress(fromAddr); err != nil || addr.Address != fromAddr {
		return Prepared{}, errors.New("invalid guest invite sender address")
	}
	baseURL, err := url.Parse(authBaseURL)
	if err != nil || (baseURL.Scheme != "http" && baseURL.Scheme != "https") || baseURL.Host == "" {
		return Prepared{}, errors.New("invalid authserver.public_url")
	}
	if baseURL.Scheme == "http" {
		// Cleartext-credential-link posture (D-MAILSERVER-INTERNAL-GUESTINVITE-003):
		// http may be a deliberate air-gapped/TLS-terminating-elsewhere topology,
		// so it is not refused — but a bearer invite token riding an http link is
		// a recorded, operator-visible compliance warning, never a silent default.
		slog.Warn("guest invite: authserver.public_url is http:// — the invite acceptance link carries a BEARER token and will be delivered over an unencrypted link (deployment is non-compliant for guest invitations unless TLS terminates in front of this endpoint)",
			"host", baseURL.Host)
	}

	randomBytes := make([]byte, 32)
	if _, err := rand.Read(randomBytes); err != nil {
		return Prepared{}, fmt.Errorf("mint invite token: %w", err)
	}
	rawToken := base64.RawURLEncoding.EncodeToString(randomBytes)
	digest := sha256.Sum256([]byte(rawToken))
	// PostgreSQL timestamptz stores microsecond precision. Normalize before the
	// reducer call so the committed value and the API response describe exactly
	// the same instant instead of differing by discarded sub-microsecond digits.
	expiresAt := time.Now().UTC().Add(time.Duration(ttlDays) * 24 * time.Hour).Truncate(time.Microsecond)
	if guestExpiresAt != nil && guestExpiresAt.Before(expiresAt) {
		expiresAt = guestExpiresAt.UTC()
	}
	var inviteID int64
	if err := tx.QueryRow(ctx, `SELECT guest_invite_create($1,$2,$3,$4,$5,$6)`,
		creatorUserID, guestUserID, hex.EncodeToString(digest[:]), hostDomainID, creatorEmail, expiresAt).Scan(&inviteID); err != nil {
		return Prepared{}, fmt.Errorf("guest_invite_create: %w", err)
	}
	return Prepared{inviteID: inviteID, rawToken: rawToken, fromAddr: fromAddr, orgName: orgName,
		authBaseURL: authBaseURL, expiresAt: expiresAt, ttlDays: ttlDays}, nil
}

// Send constructs the sole token-bearing representation, the invitation email.
//
// Recipient binding (D-MAILSERVER-INTERNAL-GUESTINVITE-002): `to` is validated
// with mail.ParseAddress before any header is built, so an unparseable or
// header-polluting value can never ride the credential-bearing mail as a To
// recipient. The admin/invite callers resolve `to` from DB records and are
// admin-authenticated; this validation is the API-level fence for the raw
// credential delivery path.
func Send(ctx context.Context, queue notify.SystemMailQueue, mc *minio.Client, bucket string, invite Prepared, to string) error {
	if err := validateRecipient(to); err != nil {
		return err
	}
	acceptURL := strings.TrimRight(invite.authBaseURL, "/") + "/guest-invite/accept?token=" + invite.rawToken
	subject := fmt.Sprintf("You've been invited to %s", invite.orgName)
	body := fmt.Sprintf("You've been invited to join %s as an external guest.\n\n"+
		"Click the link below to set your password and activate your account:\n%s\n\n"+
		"This link expires in %d day(s).\n\n"+
		"If you did not expect this invitation, you may ignore this email.\n",
		invite.orgName, acceptURL, invite.ttlDays)
	return notify.SendSystemMail(ctx, queue, mc, bucket, "invite/", invite.fromAddr, invite.orgName, to, subject, body)
}

// validateRecipient is Send's recipient-binding fence: the address must parse
// as an RFC 5322 address with a non-empty addr-spec, so no header-polluting
// or malformed value can ride the credential-bearing invitation mail.
func validateRecipient(to string) error {
	addr, err := mail.ParseAddress(to)
	if err != nil || addr.Address == "" {
		return fmt.Errorf("guest invite: invalid recipient address %q", to)
	}
	return nil
}

func ttlDays(ctx context.Context, tx pgx.Tx) (int, error) {
	var raw string
	err := tx.QueryRow(ctx, `SELECT value #>> '{}' FROM system_config WHERE key='guest.invite_ttl_days'`).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return defaultTTLDays, nil
	}
	if err != nil {
		return 0, fmt.Errorf("read guest invite TTL: %w", err)
	}
	days, err := strconv.Atoi(raw)
	if err != nil || days <= 0 {
		return 0, fmt.Errorf("invalid guest.invite_ttl_days %q", raw)
	}
	return days, nil
}
