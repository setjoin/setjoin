package ad

// Regression test for D-MAILSERVER-INTERNAL-AD-002 (ad-deprovision-completeness):
// the empty-email guard used to precede the deprovision branch, so a
// directory-disabled entry whose mail attribute was CLEARED kept an enabled
// local account with live sessions — silently, with no Disabled increment and
// no cursor stall. The guard is now provision-only: the disable arm runs keyed
// on ad_object_guid even without an email.

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"testing"

	"github.com/jackc/pgx/v5"
)

func TestDeprovisionRunsForEmptyEmailDisabledEntry(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	suffix := randSuffix(t)
	domain := "adtest-deprov-" + suffix + ".local"

	var domainID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO domains (name, is_local) VALUES ($1, TRUE) RETURNING id`, domain,
	).Scan(&domainID); err != nil {
		t.Fatalf("insert domain: %v", err)
	}

	var objectGUID string
	if err := pool.QueryRow(ctx, `SELECT gen_random_uuid()::TEXT`).Scan(&objectGUID); err != nil {
		t.Fatalf("gen uuid: %v", err)
	}

	email := "ad-deprov-" + suffix + "@" + domain

	t.Cleanup(func() {
		c := context.Background()
		pool.Exec(c, `DELETE FROM sync_conflicts WHERE user_id IN (SELECT id FROM users WHERE ad_object_guid::TEXT = $1)`, objectGUID)
		pool.Exec(c, `DELETE FROM field_policy WHERE user_id IN (SELECT id FROM users WHERE ad_object_guid::TEXT = $1)`, objectGUID)
		pool.Exec(c, `DELETE FROM mailboxes WHERE user_id IN (SELECT id FROM users WHERE ad_object_guid::TEXT = $1)`, objectGUID)
		pool.Exec(c, `DELETE FROM users WHERE ad_object_guid::TEXT = $1`, objectGUID)
		pool.Exec(c, `DELETE FROM domains WHERE id = $1`, domainID)
	})

	var logs bytes.Buffer
	w := &SyncWorker{pool: pool, logger: slog.New(slog.NewTextHandler(&logs, nil))}

	// Previously-synced, ENABLED user with a mail attribute.
	created := SyncResult{}
	if err := w.upsertUser(ctx, ADUser{
		ObjectGUID: objectGUID, Email: email, DisplayName: "Deprov Test",
		UPN: email, USNChanged: 1,
	}, false, false, &created); err != nil {
		t.Fatalf("create upsert: %v", err)
	}
	if created.Created != 1 {
		t.Fatalf("create result = %+v, want Created=1", created)
	}

	// Directory clears mail AND disables the account (userAccountControl & 2).
	disabled := SyncResult{}
	if err := w.upsertUser(ctx, ADUser{
		ObjectGUID: objectGUID, Email: "", Disabled: true, USNChanged: 2,
	}, false, false, &disabled); err != nil {
		t.Fatalf("disabled empty-email upsert: %v", err)
	}
	if disabled.Disabled != 1 {
		t.Fatalf("disabled result = %+v, want Disabled=1 (empty-email entry must still deprovision)", disabled)
	}

	var userID int64
	if err := pool.QueryRow(ctx,
		`SELECT id FROM users WHERE ad_object_guid::TEXT = $1`, objectGUID,
	).Scan(&userID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			t.Fatal("user vanished after disable arm — unexpected")
		}
		t.Fatalf("read user: %v", err)
	}
	var enabled bool
	if err := pool.QueryRow(ctx, `SELECT enabled FROM users WHERE id = $1`, userID).Scan(&enabled); err != nil {
		t.Fatalf("read enabled: %v", err)
	}
	if enabled {
		t.Fatal("user still enabled after directory-disabled empty-email sync")
	}
}
