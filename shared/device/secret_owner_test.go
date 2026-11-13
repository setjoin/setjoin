package device

// Tests for the composed actor-binding wrapper (owner decision D1, 2026-09-14:
// DEVICE-003 / D-SHARED-DEVICE-003). GetDeviceSecretForOwner must return the
// device HMAC secret ONLY when the requesting actor owns the device
// (devices.user_id = actorUserID, enforced by the lookup predicate), and must
// fail closed with the same ErrNoSecret an unknown device produces — unknown
// device, wrong actor, and revoked device are indistinguishable (no oracle).
//
// DB-backed tests need DB_DSN (testsupport skips otherwise; REQUIRE_DB makes a
// missing DB fail instead of silently passing).

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// insertActorFixtureUser adds a second real user in the same domain as the
// device fixture's owner, so the mismatch leg proves a genuine other user
// cannot read another user's device secret (not merely that a bogus id fails).
func insertActorFixtureUser(t *testing.T, pool *pgxpool.Pool, deviceID int64, tag string) int64 {
	t.Helper()
	ctx := context.Background()

	var domainID int64
	var domainName string
	if err := pool.QueryRow(ctx,
		`SELECT u.domain_id, d2.name
		   FROM devices dev
		   JOIN users u ON u.id = dev.user_id
		   JOIN domains d2 ON d2.id = u.domain_id
		  WHERE dev.id = $1`, deviceID).Scan(&domainID, &domainName); err != nil {
		t.Fatalf("load fixture domain: %v", err)
	}

	unix := time.Now().UnixNano()
	username := tag + fmt.Sprintf("-%d", unix)
	var userID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO users (username, domain_id, email, display_name, password_hash)
		 VALUES ($1, $2, $3, 'Actor Fixture', 'x') RETURNING id`,
		username, domainID, username+"@"+domainName).Scan(&userID); err != nil {
		t.Fatalf("insert actor fixture user: %v", err)
	}
	t.Cleanup(func() {
		c := context.Background()
		_, _ = pool.Exec(c, `DELETE FROM users WHERE id = $1`, userID)
	})
	return userID
}

// deviceOwnerID loads the fixture device's owner (the only actor that may
// legitimately receive the secret).
func deviceOwnerID(t *testing.T, pool *pgxpool.Pool, deviceID int64) int64 {
	t.Helper()
	var ownerID int64
	if err := pool.QueryRow(context.Background(),
		`SELECT user_id FROM devices WHERE id = $1`, deviceID).Scan(&ownerID); err != nil {
		t.Fatalf("load device owner: %v", err)
	}
	return ownerID
}

// TestGetDeviceSecretForOwner_OwnerMatchReturnsSecret: the owner receives
// exactly the issued secret, across BOTH at-rest forms (legacy plaintext row
// and the V247 ciphertext-only envelope the lazy migration produces).
func TestGetDeviceSecretForOwner_OwnerMatchReturnsSecret(t *testing.T) {
	pool, deviceID, secret := openNonceFixture(t, "ownermatch")
	ctx := context.Background()
	ownerID := deviceOwnerID(t, pool, deviceID)

	got, err := GetDeviceSecretForOwner(ctx, pool, ownerID, deviceID, testSecretCodec)
	if err != nil {
		t.Fatalf("owner match must return the secret: %v", err)
	}
	if got != secret {
		t.Fatal("owner match must return the issued value, unmodified")
	}

	// Shape the row to the V247 ciphertext-only form and re-prove: the wrapper
	// composes through the sealed envelope exactly like GetDeviceSecret does.
	envelope, err := testSecretCodec.Seal(secret)
	if err != nil {
		t.Fatalf("seal fixture secret: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`UPDATE devices SET hmac_secret = NULL, hmac_secret_enc = $2, hmac_secret_key_id = $3
		  WHERE id = $1`, deviceID, envelope, testSecretCodec.ActiveKeyID()); err != nil {
		t.Fatalf("shape ciphertext-only row: %v", err)
	}

	got, err = GetDeviceSecretForOwner(ctx, pool, ownerID, deviceID, testSecretCodec)
	if err != nil {
		t.Fatalf("owner match on ciphertext-only row must return the secret: %v", err)
	}
	if got != secret {
		t.Fatal("owner match on ciphertext-only row must return the issued value")
	}
}

// TestGetDeviceSecretForOwner_ActorMismatchFailsClosed: a different REAL user
// (same domain) and a nonexistent actor id both fail closed with the same
// ErrNoSecret an unknown device produces — no oracle, and no secret material
// leaves the seam.
func TestGetDeviceSecretForOwner_ActorMismatchFailsClosed(t *testing.T) {
	pool, deviceID, _ := openNonceFixture(t, "ownermismatch")
	ctx := context.Background()
	otherUserID := insertActorFixtureUser(t, pool, deviceID, "otheruser")

	for _, tc := range []struct {
		name    string
		actorID int64
	}{
		{"other real user", otherUserID},
		{"nonexistent actor id", deviceOwnerID(t, pool, deviceID) + (1 << 40)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := GetDeviceSecretForOwner(ctx, pool, tc.actorID, deviceID, testSecretCodec)
			if err == nil {
				t.Fatal("actor mismatch must fail closed")
			}
			if !errors.Is(err, ErrNoSecret) {
				t.Fatalf("mismatch must collapse into ErrNoSecret (no oracle), got: %v", err)
			}
			if got != "" {
				t.Fatal("no secret material may be returned on mismatch")
			}
		})
	}
}

// TestGetDeviceSecretForOwner_UnknownDeviceFailsClosed: an unknown device id
// fails closed with ErrNoSecret even when the actor id would be valid.
func TestGetDeviceSecretForOwner_UnknownDeviceFailsClosed(t *testing.T) {
	pool, deviceID, _ := openNonceFixture(t, "ownerunknown")
	ctx := context.Background()
	ownerID := deviceOwnerID(t, pool, deviceID)

	got, err := GetDeviceSecretForOwner(ctx, pool, ownerID, deviceID+(1<<40), testSecretCodec)
	if !errors.Is(err, ErrNoSecret) {
		t.Fatalf("unknown device must fail closed with ErrNoSecret, got: %v", err)
	}
	if got != "" {
		t.Fatal("no secret material may be returned for an unknown device")
	}
}

// TestGetDeviceSecretForOwner_RevokedOwnerStillFailsClosed: the wrapper
// inherits GetDeviceSecret's revoked filter — even the legitimate owner loses
// the secret after the lifecycle reducer revokes the device.
func TestGetDeviceSecretForOwner_RevokedOwnerStillFailsClosed(t *testing.T) {
	pool, deviceID, _ := openNonceFixture(t, "ownerrevoked")
	ctx := context.Background()
	ownerID := deviceOwnerID(t, pool, deviceID)

	// Revoke through the lifecycle reducer (unenrolled -> enrolled -> revoked),
	// with the device's owner as the actor (enrolled_by FK needs a real user).
	if _, err := pool.Exec(ctx, `SELECT device_enroll_transition($1, $2, 'enrolled', 'test')`,
		ownerID, deviceID); err != nil {
		t.Fatalf("enroll: %v", err)
	}
	if _, err := pool.Exec(ctx, `SELECT device_enroll_transition($1, $2, 'revoked', 'test')`,
		ownerID, deviceID); err != nil {
		t.Fatalf("revoke: %v", err)
	}

	got, err := GetDeviceSecretForOwner(ctx, pool, ownerID, deviceID, testSecretCodec)
	if !errors.Is(err, ErrNoSecret) {
		t.Fatalf("revoked device must fail closed with ErrNoSecret even for its owner, got: %v", err)
	}
	if got != "" {
		t.Fatal("no secret material may be returned for a revoked device")
	}
}

// TestGetDeviceSecretForOwner_NilCodecFailsClosed: composition preserves
// GetDeviceSecret's nil-codec contract — the ownership predicate passing must
// not open a plaintext fallback path.
func TestGetDeviceSecretForOwner_NilCodecFailsClosed(t *testing.T) {
	pool, deviceID, _ := openNonceFixture(t, "ownernilcodec")
	ctx := context.Background()
	ownerID := deviceOwnerID(t, pool, deviceID)

	if _, err := GetDeviceSecretForOwner(ctx, pool, ownerID, deviceID, nil); err == nil {
		t.Fatal("nil codec must fail closed even on an owner match")
	}
}
