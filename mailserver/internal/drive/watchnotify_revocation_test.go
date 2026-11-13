package drive

// D-MAILSERVER-INTERNAL-DRIVE-R-001 — the live-push half of the watch
// revocation fix. watchersOf must re-derive the watcher's current
// read_metadata capability on the event node per event: on legacy-mode spaces
// drive_member_revoke prunes drive_watches only via the acl-mode
// drive_acl_bump (cutover) path, so a removed member's watch row survives and
// would otherwise keep receiving drive-watch:<uid> pushes indefinitely. The
// unit tripwire runs everywhere; the end-to-end assertions skip without
// DB_DSN (the live_helpers_test.go genre).

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// sqlCapturingPool implements driveWatchRows, recording the non-drive_changes
// (watcher-resolution) SQL and answering every query with zero rows.
type sqlCapturingPool struct{ watcherSQL string }

func (p *sqlCapturingPool) Query(_ context.Context, sql string, _ ...any) (pgx.Rows, error) {
	if !strings.Contains(sql, "drive_changes") {
		p.watcherSQL = sql
	}
	return &fakeRows{}, nil
}

// TestWatchNotifier_WatcherQueryReDerivesCapabilityPerEvent pins the
// revocation posture at the query seam: watcher resolution must carry the
// same drive_runtime_has_node_capability authority drive_watch_set gates
// watch creation with and drive_acl_revoke_bound_artifacts prunes stale
// watches with.
func TestWatchNotifier_WatcherQueryReDerivesCapabilityPerEvent(t *testing.T) {
	pool := &sqlCapturingPool{}
	wn := NewWatchNotifier(pool, func(context.Context, string, string) error { return nil }, discardLogger())
	wn.Handle(context.Background(), `{"spaceId":2,"kind":"lock","nodeId":99}`)
	if !strings.Contains(pool.watcherSQL, "drive_runtime_has_node_capability") {
		t.Fatal("watcher resolution must re-derive drive_runtime_has_node_capability per event; a bare drive_watches read keeps pushing to removed members")
	}
	if !strings.Contains(pool.watcherSQL, "read_metadata") {
		t.Fatal("watcher re-derivation must gate on read_metadata — the same capability drive_watch_set requires to arm a watch")
	}
}

// TestWatchNotifier_RemovedMemberGetsNoPushAfterMemberRevoke_Live is the
// end-to-end binding test: after a legacy member_revoke (which does NOT prune
// the watch row), the removed member's channel stays silent while the active
// watcher's pushes are unchanged.
func TestWatchNotifier_RemovedMemberGetsNoPushAfterMemberRevoke_Live(t *testing.T) {
	pool := driveLivePool(t) // skips without DB_DSN; Close is registered before fixture cleanups
	ctx := t.Context()

	owner := driveLiveUser(t, pool, "wnro")
	removed := driveLiveUser(t, pool, "wnrr")
	active := driveLiveUser(t, pool, "wnra")

	var spaceID int64
	if err := pool.QueryRow(ctx, `SELECT drive_space_create($1, 'wnr', 'regular')`, owner).Scan(&spaceID); err != nil {
		t.Fatalf("drive_space_create: %v", err)
	}
	for _, member := range []int64{removed, active} {
		if _, err := pool.Exec(ctx, `SELECT drive_member_grant($1, $2, $3, 'editor')`, owner, spaceID, member); err != nil {
			t.Fatalf("drive_member_grant(%d): %v", member, err)
		}
	}
	var fileID int64
	if err := pool.QueryRow(ctx, `SELECT drive_node_create($1, $2, NULL, 'file', 'wnr.docx')`, owner, spaceID).Scan(&fileID); err != nil {
		t.Fatalf("drive_node_create: %v", err)
	}
	if _, err := pool.Exec(ctx, `SELECT drive_watch_set($1, $2, NULL)`, removed, fileID); err != nil {
		t.Fatalf("drive_watch_set(removed): %v", err)
	}
	if _, err := pool.Exec(ctx, `SELECT drive_watch_set($1, $2, NULL)`, active, fileID); err != nil {
		t.Fatalf("drive_watch_set(active): %v", err)
	}

	// One cleanup covering every fixture, in FK-safe order (runs LIFO, before
	// pool.Close); the mailboxes leg is the admin_users_test.go DISABLE-TRIGGER
	// genre — mk_account's primary-mailbox trigger blocks plain deletes.
	t.Cleanup(func() {
		if err := deleteWatchRevocationFixture(context.Background(), pool, spaceID, []int64{owner, removed, active}); err != nil {
			t.Errorf("fixture cleanup: %v", err)
		}
	})

	var mu sync.Mutex
	sentTo := map[int64]int{}
	notify := func(_ context.Context, channel, _ string) error {
		uid, err := strconv.ParseInt(strings.TrimPrefix(channel, "drive-watch:"), 10, 64)
		if err != nil {
			t.Errorf("unexpected channel %q", channel)
			return nil
		}
		mu.Lock()
		defer mu.Unlock()
		sentTo[uid]++
		return nil
	}
	wn := NewWatchNotifier(pool, notify, discardLogger())

	// Event 1 — both watchers are still members: both channels get the push.
	var seq int64
	if err := pool.QueryRow(ctx, `SELECT drive_notify_change($1, $2, 'update')`, spaceID, fileID).Scan(&seq); err != nil {
		t.Fatalf("drive_notify_change: %v", err)
	}
	wn.Handle(ctx, fmt.Sprintf(`{"spaceId":%d,"seq":%d}`, spaceID, seq))
	if got := sentTo[removed]; got != 1 {
		t.Fatalf("removed-to-be user should receive exactly 1 push while still a member, got %d (all: %v)", got, sentTo)
	}
	if got := sentTo[active]; got != 1 {
		t.Fatalf("active watcher should receive exactly 1 push, got %d (all: %v)", got, sentTo)
	}

	// Legacy member_revoke does NOT prune the watch row (drive_acl_bump only
	// runs in acl mode) — the premise that makes fan-out re-derivation
	// load-bearing.
	if _, err := pool.Exec(ctx, `SELECT drive_member_revoke($1, $2, $3)`, owner, spaceID, removed); err != nil {
		t.Fatalf("drive_member_revoke: %v", err)
	}
	var watchRows int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM drive_watches WHERE user_id = $1 AND node_id = $2`, removed, fileID).Scan(&watchRows); err != nil {
		t.Fatalf("watch count: %v", err)
	}
	if watchRows != 1 {
		t.Fatalf("premise: legacy member_revoke must leave the watch row in place (the fix is at fan-out), got %d rows", watchRows)
	}

	// Event 2 — a fresh (node,op) dedupe key: the removed member's channel
	// stays silent; the active watcher's push is unchanged.
	var seq2 int64
	if err := pool.QueryRow(ctx, `SELECT drive_notify_change($1, $2, 'rename')`, spaceID, fileID).Scan(&seq2); err != nil {
		t.Fatalf("drive_notify_change(2): %v", err)
	}
	wn.Handle(ctx, fmt.Sprintf(`{"spaceId":%d,"seq":%d}`, spaceID, seq2))
	if got := sentTo[removed]; got != 1 {
		t.Errorf("removed member received %d pushes total, want 1 (pre-revocation only)", got)
	}
	if got := sentTo[active]; got != 2 {
		t.Errorf("active watcher received %d pushes total, want 2 (unchanged by the other member's removal)", got)
	}
}

// deleteWatchRevocationFixture removes the live revocation test's whole
// fixture in ONE transaction (Astra waves12 finding 1: the former autocommit
// DISABLE/ENABLE TRIGGER ALL with ignored errors could strand the mailboxes
// triggers globally disabled on the shared test database, and the blanket
// ENABLE did not preserve a deliberately-disabled trigger's prior state).
// The trigger disable/restore and every delete commit or roll back
// atomically, so a mid-cleanup failure can never leave the shared schema with
// triggers off — and after the blanket ENABLE (which also re-arms the
// internal FK triggers) each user trigger captured with non-default
// pg_trigger.tgenabled is put back EXACTLY ('D' disabled, 'R' replica,
// 'A' always). Drive rows go first in FK-safe order; mailbox_address_claims
// and mailbox_lifecycle would block the mailbox/user deletes (the
// ldap/jmap fixture teardowns clear the same legs). Every error is wrapped
// and returned — none are ignored. lock_timeout bounds the wait so cleanup
// cannot hang behind a concurrent writer holding locks on mailboxes.
func deleteWatchRevocationFixture(ctx context.Context, pool *pgxpool.Pool, spaceID int64, uids []int64) error {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin: %w", err)
	}
	// No-op after a successful Commit; on any earlier return below it undoes
	// the trigger disable together with every delete.
	defer tx.Rollback(ctx) //nolint:errcheck // no-op after commit
	if _, err := tx.Exec(ctx, `SET LOCAL lock_timeout = '500ms'`); err != nil {
		return fmt.Errorf("set lock_timeout: %w", err)
	}

	for _, stmt := range []struct{ what, query string }{
		{"drive_watches", `DELETE FROM drive_watches WHERE node_id IN (SELECT id FROM drive_nodes WHERE space_id = $1)`},
		{"drive_node_closure", `DELETE FROM drive_node_closure WHERE space_id = $1`},
		{"drive_files", `DELETE FROM drive_files WHERE space_id = $1`},
		{"drive_nodes", `DELETE FROM drive_nodes WHERE space_id = $1`},
		{"drive_space_members", `DELETE FROM drive_space_members WHERE space_id = $1`},
		{"drive_changes", `DELETE FROM drive_changes WHERE space_id = $1`},
	} {
		if _, err := tx.Exec(ctx, stmt.query, spaceID); err != nil {
			return fmt.Errorf("delete %s: %w", stmt.what, err)
		}
	}

	// The space's audit chain is append-only (BZ145 blocks DELETE even for a
	// superuser — trg_drive_audit_immutable), so the fixture's own chain is
	// removed under a transactional disable of that one guard, the same
	// atomic-window genre as the mailboxes dance below: any later failure
	// rolls the guard state AND the audit rows back together. Scoped to this
	// fixture's space; the guard is back on before the space row goes.
	if _, err := tx.Exec(ctx, `ALTER TABLE drive_audit_log DISABLE TRIGGER trg_drive_audit_immutable`); err != nil {
		return fmt.Errorf("disable drive audit guard: %w", err)
	}
	if _, err := tx.Exec(ctx, `DELETE FROM drive_audit_log WHERE space_id = $1`, spaceID); err != nil {
		return fmt.Errorf("delete drive_audit_log: %w", err)
	}
	if _, err := tx.Exec(ctx, `ALTER TABLE drive_audit_log ENABLE TRIGGER trg_drive_audit_immutable`); err != nil {
		return fmt.Errorf("re-enable drive audit guard: %w", err)
	}
	if _, err := tx.Exec(ctx, `DELETE FROM drive_spaces WHERE id = $1`, spaceID); err != nil {
		return fmt.Errorf("delete drive_spaces: %w", err)
	}

	for _, uid := range uids {
		for _, stmt := range []struct{ what, query string }{
			{"mailbox_address_claims", `DELETE FROM mailbox_address_claims WHERE mailbox_id IN (SELECT id FROM mailboxes WHERE user_id = $1)`},
			{"mailbox_lifecycle", `DELETE FROM mailbox_lifecycle WHERE bound_user_id = $1`},
		} {
			if _, err := tx.Exec(ctx, stmt.query, uid); err != nil {
				return fmt.Errorf("delete %s (user %d): %w", stmt.what, uid, err)
			}
		}
	}

	// Capture the prior non-internal trigger state so the disable can be
	// undone EXACTLY, not just blanket-ENABLEd.
	var prior []mailboxesTriggerState
	rows, err := tx.Query(ctx,
		`SELECT tgname, tgenabled FROM pg_trigger
		   WHERE tgrelid = 'public.mailboxes'::regclass AND NOT tgisinternal
		   ORDER BY tgname`)
	if err != nil {
		return fmt.Errorf("read mailboxes trigger state: %w", err)
	}
	for rows.Next() {
		var g mailboxesTriggerState
		var en string
		if err := rows.Scan(&g.name, &en); err != nil {
			rows.Close()
			return fmt.Errorf("scan mailboxes trigger state: %w", err)
		}
		g.enabled = en[0]
		prior = append(prior, g)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return fmt.Errorf("iterate mailboxes trigger state: %w", err)
	}
	rows.Close()

	if _, err := tx.Exec(ctx, `ALTER TABLE mailboxes DISABLE TRIGGER ALL`); err != nil {
		return fmt.Errorf("disable mailboxes triggers: %w", err)
	}
	for _, uid := range uids {
		if _, err := tx.Exec(ctx, `DELETE FROM mailboxes WHERE user_id = $1`, uid); err != nil {
			return fmt.Errorf("delete mailboxes (user %d): %w", uid, err)
		}
	}
	// ENABLE ALL first (re-arms the internal FK triggers the blanket disable
	// took down), then restore each user trigger's captured state.
	if _, err := tx.Exec(ctx, `ALTER TABLE mailboxes ENABLE TRIGGER ALL`); err != nil {
		return fmt.Errorf("re-enable mailboxes triggers: %w", err)
	}
	for _, g := range prior {
		action, ok := triggerStateAction(g.enabled)
		if !ok {
			continue // default state — ENABLE ALL already restored it
		}
		qname := `"` + strings.ReplaceAll(g.name, `"`, `""`) + `"`
		if _, err := tx.Exec(ctx, `ALTER TABLE mailboxes `+action+` TRIGGER `+qname); err != nil {
			return fmt.Errorf("restore mailboxes trigger %s state: %w", g.name, err)
		}
	}

	for _, uid := range uids {
		if _, err := tx.Exec(ctx, `DELETE FROM users WHERE id = $1`, uid); err != nil {
			return fmt.Errorf("delete user %d: %w", uid, err)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit: %w", err)
	}
	return nil
}

// triggerStateAction maps a pg_trigger.tgenabled byte to the ALTER TABLE
// action that restores it; ok=false means the default origin state the
// blanket ENABLE ALL already put back.
func triggerStateAction(enabled byte) (action string, ok bool) {
	switch enabled {
	case 'O':
		return "", false
	case 'D':
		return "DISABLE", true
	case 'R':
		return "ENABLE REPLICA", true
	case 'A':
		return "ENABLE ALWAYS", true
	default:
		return "DISABLE", true
	}
}

// mailboxesTriggerState is one non-internal mailboxes trigger's pg_trigger
// row: its name and tgenabled state ('O' origin, 'D' disabled, 'R' replica,
// 'A' always).
type mailboxesTriggerState = struct {
	name    string
	enabled byte
}

// mailboxesTriggerStates lists every non-internal mailboxes trigger's
// tgenabled in tgname order — the exact-state baseline the rollback proof
// compares against.
func mailboxesTriggerStates(t *testing.T, pool *pgxpool.Pool) []mailboxesTriggerState {
	t.Helper()
	rows, err := pool.Query(context.Background(),
		`SELECT tgname, tgenabled FROM pg_trigger
		   WHERE tgrelid = 'public.mailboxes'::regclass AND NOT tgisinternal
		   ORDER BY tgname`)
	if err != nil {
		t.Fatalf("read mailboxes trigger states: %v", err)
	}
	defer rows.Close()
	var states []mailboxesTriggerState
	for rows.Next() {
		var g mailboxesTriggerState
		var en string
		if err := rows.Scan(&g.name, &en); err != nil {
			t.Fatalf("scan mailboxes trigger state: %v", err)
		}
		g.enabled = en[0]
		states = append(states, g)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate mailboxes trigger states: %v", err)
	}
	return states
}

// setMailboxesTriggerState drives one mailboxes trigger to an exact
// tgenabled state (autocommit; used by the rollback proof to plant and to
// undo a non-default probe state).
func setMailboxesTriggerState(t *testing.T, pool *pgxpool.Pool, name string, enabled byte) {
	t.Helper()
	action, ok := triggerStateAction(enabled)
	if !ok {
		action = "ENABLE"
	}
	qname := `"` + strings.ReplaceAll(name, `"`, `""`) + `"`
	if _, err := pool.Exec(context.Background(), `ALTER TABLE mailboxes `+action+` TRIGGER `+qname); err != nil {
		t.Fatalf("set mailboxes trigger %s to %q: %v", name, enabled, err)
	}
}

// TestWatchRevocationCleanup_RollbackSurvivesTriggerState_Live pins the
// cleanup's failure posture (Astra waves12 finding 1): a mid-transaction
// error — here the users delete blocked by a planted field_policy.set_by FK,
// which carries no ON DELETE action — must surface to the caller AND roll the
// whole teardown back: the mailboxes trigger states survive EXACTLY as
// captured (no stranded global disable, the deliberately-disabled probe
// trigger is not blanket-enabled away) and the in-transaction deletes are
// undone. Once the blocking row is gone, the same teardown succeeds.
func TestWatchRevocationCleanup_RollbackSurvivesTriggerState_Live(t *testing.T) {
	pool := driveLivePool(t) // skips without DB_DSN
	ctx := context.Background()

	uid := driveLiveUser(t, pool, "wnrb")

	pristine := mailboxesTriggerStates(t, pool)
	if len(pristine) == 0 {
		t.Fatal("premise: mailboxes must carry non-internal triggers (the mk_account primary-mailbox genre the cleanup snapshots)")
	}
	// Deliberately put the first trigger (tgname order) into a non-default
	// state: a correct cleanup preserves it across both failure and success
	// instead of blanket-enabling the table. Restored to its exact pre-test
	// state at the end (t.Cleanup is LIFO; driveLivePool's Close still runs
	// last).
	probe := pristine[0].name
	setMailboxesTriggerState(t, pool, probe, 'D')
	t.Cleanup(func() { setMailboxesTriggerState(t, pool, probe, pristine[0].enabled) })

	// The state the teardown must preserve EXACTLY: everything as captured,
	// with the probe deliberately non-default.
	planted := mailboxesTriggerStates(t, pool)

	// The FK plant that blocks the teardown's users delete.
	if _, err := pool.Exec(ctx,
		`INSERT INTO field_policy (user_id, field, policy, set_by) VALUES ($1, 'wnr-rollback-probe', 'local_only', $1)`, uid); err != nil {
		t.Fatalf("plant field_policy probe: %v", err)
	}

	err := deleteWatchRevocationFixture(ctx, pool, 0 /* no space fixture */, []int64{uid})
	if err == nil {
		t.Fatal("fixture cleanup must surface the planted users-delete FK failure, got nil error")
	}

	after := mailboxesTriggerStates(t, pool)
	if len(planted) != len(after) {
		t.Fatalf("mailboxes trigger set changed across a failed cleanup: before %d triggers, after %d", len(planted), len(after))
	}
	for i := range planted {
		if planted[i] != after[i] {
			t.Errorf("trigger %s state = %q after failed cleanup, want exactly %q (rollback must survive the prior state)", after[i].name, after[i].enabled, planted[i].enabled)
		}
	}

	// The in-transaction deletes rolled back too: the mailbox is back.
	var mailboxes int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM mailboxes WHERE user_id = $1`, uid).Scan(&mailboxes); err != nil {
		t.Fatalf("count rolled-back mailboxes: %v", err)
	}
	if mailboxes != 1 {
		t.Fatalf("failed cleanup must roll back to the full fixture, got %d mailboxes for user %d", mailboxes, uid)
	}

	if _, err := pool.Exec(ctx, `DELETE FROM field_policy WHERE user_id = $1 AND field = 'wnr-rollback-probe'`, uid); err != nil {
		t.Fatalf("remove field_policy probe: %v", err)
	}
	if err := deleteWatchRevocationFixture(ctx, pool, 0, []int64{uid}); err != nil {
		t.Fatalf("fixture cleanup must succeed once the blocking FK row is gone: %v", err)
	}
	// The success path must also restore the probe trigger's disabled state.
	restored := mailboxesTriggerStates(t, pool)
	if len(restored) != len(planted) {
		t.Fatalf("mailboxes trigger set changed across the successful cleanup: before %d triggers, after %d", len(planted), len(restored))
	}
	for i := range planted {
		if restored[i] != planted[i] {
			t.Errorf("trigger %s state = %q after successful cleanup, want exactly %q", restored[i].name, restored[i].enabled, planted[i].enabled)
		}
	}
}
