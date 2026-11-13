package mdm

// Device-event persistence tests (branch completion for events.go):
// LogDeviceEvent validation, zero-OccurredAt defaulting, scope-arm insertion
// (in-scope write, out-of-scope ErrDeviceOutOfScope), full-authority insert,
// and GetDeviceEvents reads with limit defaulting, empty-history, scoped, and
// JSON details round-trip.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"setjoin.com/shared/testsupport"
)

const w5MdmDomainID = 98400
const w5MdmUserID = 98401
const w5MdmMailboxID = 98411
const w5MdmDeviceID = 98421

// seedW5MdmFixture creates a domain, user, primary mailbox, and one enrolled
// device so device_events rows have their FK chain. Child-first teardown.
func seedW5MdmFixture(t *testing.T) *pgxpool.Pool {
	t.Helper()
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, sql, args...); err != nil {
			t.Fatalf("seed %q: %v", sql, err)
		}
	}
	exec(`INSERT INTO domains (id, name, is_local) OVERRIDING SYSTEM VALUE VALUES ($1, 'mdm-w5.test', TRUE) ON CONFLICT DO NOTHING`, w5MdmDomainID)
	exec(`INSERT INTO users (id, username, domain_id, email, display_name, enabled) OVERRIDING SYSTEM VALUE VALUES
		($1, 'mdm_w5_owner', $2, 'owner@mdm-w5.test', 'MDM W5 Owner', TRUE) ON CONFLICT DO NOTHING`, w5MdmUserID, w5MdmDomainID)
	exec(`INSERT INTO mailboxes (id, user_id, domain_id, email, display_name, type, is_primary) OVERRIDING SYSTEM VALUE VALUES
		($1, $2, $3, 'owner@mdm-w5.test', 'MDM W5 Owner', 'personal', TRUE) ON CONFLICT DO NOTHING`, w5MdmMailboxID, w5MdmUserID, w5MdmDomainID)
	exec(`INSERT INTO devices (id, user_id, device_name, platform, fingerprint, hmac_secret) OVERRIDING SYSTEM VALUE VALUES
		($1, $2, 'w5-device', 'macos', 'w5-fingerprint', 'w5-hmac-secret') ON CONFLICT DO NOTHING`, w5MdmDeviceID, w5MdmUserID)

	t.Cleanup(func() {
		c := context.Background()
		pool.Exec(c, `DELETE FROM device_events WHERE device_id = $1`, w5MdmDeviceID)            //nolint:errcheck
		pool.Exec(c, `DELETE FROM devices WHERE id = $1`, w5MdmDeviceID)                         //nolint:errcheck
		pool.Exec(c, `DELETE FROM mailbox_address_claims WHERE mailbox_id = $1`, w5MdmMailboxID) //nolint:errcheck
		pool.Exec(c, `DELETE FROM mailbox_lifecycle WHERE mailbox_id = $1`, w5MdmMailboxID)      //nolint:errcheck
		pool.Exec(c, `DELETE FROM folders WHERE mailbox_id = $1`, w5MdmMailboxID)                //nolint:errcheck
		pool.Exec(c, `DELETE FROM mailboxes WHERE id = $1`, w5MdmMailboxID)                      //nolint:errcheck
		pool.Exec(c, `DELETE FROM users WHERE id = $1`, w5MdmUserID)                             //nolint:errcheck
		pool.Exec(c, `DELETE FROM domains WHERE id = $1`, w5MdmDomainID)                         //nolint:errcheck
	})
	return pool
}

func w5ValidEvent() *DeviceEvent {
	return &DeviceEvent{
		DeviceID:  w5MdmDeviceID,
		EventType: "policy_applied",
		Severity:  SeverityInfo,
		Details:   map[string]interface{}{"source": "w5-test"},
	}
}

func TestLogDeviceEvent_ValidationAndInsert(t *testing.T) {
	pool := seedW5MdmFixture(t)
	ctx := context.Background()

	t.Run("invalid events rejected before any write", func(t *testing.T) {
		bad := []DeviceEvent{
			{DeviceID: 0, EventType: "policy_applied", Severity: SeverityInfo},
			{DeviceID: w5MdmDeviceID, EventType: "not_a_type", Severity: SeverityInfo},
			{DeviceID: w5MdmDeviceID, EventType: "policy_applied", Severity: "loud"},
		}
		for i := range bad {
			if err := LogDeviceEvent(ctx, pool, &bad[i], 0); err == nil {
				t.Errorf("case %d must be rejected", i)
			}
		}
		if got := countW5(t, pool, `SELECT COUNT(*) FROM device_events WHERE device_id=$1`, w5MdmDeviceID); got != 0 {
			t.Fatalf("rejected events must not persist, got %d", got)
		}
	})

	t.Run("full-authority insert defaults OccurredAt", func(t *testing.T) {
		ev := w5ValidEvent()
		ev.OccurredAt = time.Time{} // zero: LogDeviceEvent must default it
		if err := LogDeviceEvent(ctx, pool, ev, 0); err != nil {
			t.Fatalf("insert: %v", err)
		}
		var n int
		if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM device_events WHERE device_id=$1 AND event_type='policy_applied'`, w5MdmDeviceID).Scan(&n); err != nil {
			t.Fatalf("count: %v", err)
		}
		if n != 1 {
			t.Fatalf("event must persist, got %d", n)
		}
	})

	t.Run("scoped insert in domain succeeds", func(t *testing.T) {
		ev := w5ValidEvent()
		ev.EventType = "policy_violation"
		if err := LogDeviceEvent(ctx, pool, ev, w5MdmDomainID); err != nil {
			t.Fatalf("scoped insert: %v", err)
		}
	})

	t.Run("scoped insert out of domain fails closed", func(t *testing.T) {
		ev := w5ValidEvent()
		ev.EventType = "wipe_requested"
		err := LogDeviceEvent(ctx, pool, ev, w5MdmDomainID+999999)
		if !errors.Is(err, ErrDeviceOutOfScope) {
			t.Fatalf("out-of-scope insert = %v, want ErrDeviceOutOfScope", err)
		}
	})
}

func TestGetDeviceEvents_Branches(t *testing.T) {
	pool := seedW5MdmFixture(t)
	ctx := context.Background()

	if err := LogDeviceEvent(ctx, pool, w5ValidEvent(), 0); err != nil {
		t.Fatalf("seed event: %v", err)
	}

	t.Run("read returns persisted event with details", func(t *testing.T) {
		events, err := GetDeviceEvents(ctx, pool, w5MdmDeviceID, 10, 0)
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		if len(events) != 1 {
			t.Fatalf("events = %d, want 1", len(events))
		}
		if events[0].Details["source"] != "w5-test" {
			t.Errorf("details round-trip = %+v", events[0].Details)
		}
	})

	t.Run("non-positive limit defaults to 50", func(t *testing.T) {
		events, err := GetDeviceEvents(ctx, pool, w5MdmDeviceID, -3, 0)
		if err != nil || len(events) != 1 {
			t.Fatalf("default-limit read: %v %d", err, len(events))
		}
	})

	t.Run("scoped read returns rows in domain", func(t *testing.T) {
		events, err := GetDeviceEvents(ctx, pool, w5MdmDeviceID, 10, w5MdmDomainID)
		if err != nil || len(events) != 1 {
			t.Fatalf("scoped read: %v %d", err, len(events))
		}
	})

	t.Run("scoped read out of domain is empty", func(t *testing.T) {
		events, err := GetDeviceEvents(ctx, pool, w5MdmDeviceID, 10, w5MdmDomainID+999999)
		if err != nil {
			t.Fatalf("out-of-scope read: %v", err)
		}
		if len(events) != 0 {
			t.Fatalf("out-of-scope read must be empty, got %d", len(events))
		}
	})

	t.Run("zero rows is an empty history, not nil", func(t *testing.T) {
		events, err := GetDeviceEvents(ctx, pool, w5MdmDeviceID+1, 10, 0)
		if err != nil {
			t.Fatalf("empty read: %v", err)
		}
		if events == nil || len(events) != 0 {
			t.Fatalf("empty history must be non-nil empty slice, got %#v", events)
		}
	})
}

func countW5(t *testing.T, pool *pgxpool.Pool, sql string, args ...any) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(context.Background(), sql, args...).Scan(&n); err != nil {
		t.Fatalf("count %q: %v", sql, err)
	}
	return n
}
