package toggle

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"setjoin.com/shared/pgnotify"
)

type notificationTestListener struct {
	mu                  sync.Mutex
	handler             pgnotify.NotifyHandler
	reconnect           func(context.Context) error
	subscribeErr        error
	unsubscribed        []int
	reconnectRegistered bool
	reconnectRemoved    bool
}

func (l *notificationTestListener) RegisterReconnect(fn func(context.Context) error) func() {
	l.mu.Lock()
	l.reconnect = fn
	l.reconnectRegistered = true
	l.mu.Unlock()
	return func() {
		l.mu.Lock()
		l.reconnectRemoved = true
		l.mu.Unlock()
	}
}

func (l *notificationTestListener) SubscribeDurable(
	_ context.Context,
	channel string,
	handler pgnotify.NotifyHandler,
) (int, error) {
	if channel != ConfigChangedChannel {
		panic("unexpected channel " + channel)
	}
	l.mu.Lock()
	l.handler = handler
	l.mu.Unlock()
	return 41, l.subscribeErr
}

func (l *notificationTestListener) Unsubscribe(_ string, id int) {
	l.mu.Lock()
	l.unsubscribed = append(l.unsubscribed, id)
	l.mu.Unlock()
}

func (l *notificationTestListener) snapshot() (pgnotify.NotifyHandler, func(context.Context) error, []int, bool, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.handler, l.reconnect, append([]int(nil), l.unsubscribed...), l.reconnectRegistered, l.reconnectRemoved
}

// notificationTestFlags is the authoritative-snapshot double. It deliberately
// exposes no point-mutation entry point: after the reload-only propagation
// change, the notificationFlags interface offers the listener no way to write
// payload content into the runtime snapshot, so a forged key/enabled pair has
// no sink to reach.
type notificationTestFlags struct {
	mu          sync.Mutex
	reloads     int
	reloadError error
}

func (f *notificationTestFlags) Reload(context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reloads++
	return f.reloadError
}

func (f *notificationTestFlags) snapshot() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.reloads
}

func withDebounceInterval(t *testing.T, d time.Duration) {
	t.Helper()
	previous := reloadDebounceInterval
	reloadDebounceInterval = d
	t.Cleanup(func() { reloadDebounceInterval = previous })
}

func waitForReloads(t *testing.T, flags *notificationTestFlags, want int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		if got := flags.snapshot(); got == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("reloads=%d, want %d", flags.snapshot(), want)
		}
		time.Sleep(time.Millisecond)
	}
}

// TestBindNotificationsReloadOnlyPropagation replaces the historical
// point-update semantics: a config_changed notification carrying key/enabled
// content is at most a debounced reload hint. The runtime snapshot changes
// only through flags.Reload re-reading feature_toggles, so payload content
// never produces a value and observers fire only after the snapshot has been
// authoritatively reconciled.
func TestBindNotificationsReloadOnlyPropagation(t *testing.T) {
	withDebounceInterval(t, 5*time.Millisecond)
	listener := &notificationTestListener{}
	flags := &notificationTestFlags{}
	var observedMu sync.Mutex
	var observed []Notification
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	if err := BindNotifications(t.Context(), listener, flags, ObserverFunc(func(_ context.Context, n Notification) {
		observedMu.Lock()
		observed = append(observed, n)
		observedMu.Unlock()
	}), logger); err != nil {
		t.Fatal(err)
	}
	handler, reconnect, _, registered, _ := listener.snapshot()
	if handler == nil || reconnect == nil || !registered {
		t.Fatalf("handler=%v reconnect=%v registered=%v", handler != nil, reconnect != nil, registered)
	}
	if reloads := flags.snapshot(); reloads != 1 {
		t.Fatalf("post-LISTEN reloads=%d, want 1", reloads)
	}
	observedMu.Lock()
	if len(observed) != 1 || !observed[0].Reload {
		observedMu.Unlock()
		t.Fatalf("startup observations=%+v", observed)
	}
	observedMu.Unlock()

	// A point payload and a reload payload inside one debounce window coalesce
	// into a single authoritative reload; neither applies content.
	handler(&pgconn.Notification{Channel: ConfigChangedChannel, Payload: `{"key":"feature.captcha","enabled":true}`})
	handler(&pgconn.Notification{Channel: ConfigChangedChannel, Payload: `{"reload":true}`})
	if reloads := flags.snapshot(); reloads != 1 {
		t.Fatalf("reload ran synchronously at delivery: reloads=%d", reloads)
	}
	waitForReloads(t, flags, 2)

	observedMu.Lock()
	got := append([]Notification(nil), observed...)
	observedMu.Unlock()
	if len(got) != 2 {
		t.Fatalf("observations=%+v, want startup plus one coalesced reload", got)
	}
	if !got[1].Reload {
		t.Fatalf("coalesced notification=%+v, want the reload hint (last pending wins)", got[1])
	}
}

// TestBindNotificationsForgedPayloadIsReloadHintOnly pins the med
// med-toggle-notify-auth-001 remediation at the protocol level: forged
// higher-version, protected-key, and unauthenticated payloads are consumed as
// reload hints. notificationTestFlags has no point-write entry point, so the
// compiler proves the listener cannot materialize payload content as a flag
// value; the database-backed arm in
// TestBindNotificationsReloadOnlyMatchesFeatureToggles proves the resulting
// values match feature_toggles.
func TestBindNotificationsForgedPayloadIsReloadHintOnly(t *testing.T) {
	withDebounceInterval(t, 5*time.Millisecond)
	listener := &notificationTestListener{}
	flags := &notificationTestFlags{}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	if err := BindNotifications(t.Context(), listener, flags, nil, logger); err != nil {
		t.Fatal(err)
	}
	handler, _, _, _, _ := listener.snapshot()

	handler(&pgconn.Notification{Channel: ConfigChangedChannel,
		Payload: `{"key":"dengbao.sod_mode","enabled":true,"version":999}`})
	handler(&pgconn.Notification{Channel: ConfigChangedChannel,
		Payload: `{"key":"feature.assist","enabled":true,"version":2147483647}`})
	handler(&pgconn.Notification{Channel: ConfigChangedChannel,
		Payload: `not-json-at-all`})

	// One startup reload plus exactly one debounced reload for the whole
	// forged burst; no other effect is reachable.
	waitForReloads(t, flags, 2)
	if reloads := flags.snapshot(); reloads != 2 {
		t.Fatalf("reloads=%d, want 2", reloads)
	}
}

func TestBindNotificationsDebounceCoalescesBursts(t *testing.T) {
	withDebounceInterval(t, 5*time.Millisecond)
	listener := &notificationTestListener{}
	flags := &notificationTestFlags{}
	var observedMu sync.Mutex
	var observed []Notification
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	if err := BindNotifications(t.Context(), listener, flags, ObserverFunc(func(_ context.Context, n Notification) {
		observedMu.Lock()
		observed = append(observed, n)
		observedMu.Unlock()
	}), logger); err != nil {
		t.Fatal(err)
	}
	handler, _, _, _, _ := listener.snapshot()
	for i := range 5 {
		handler(&pgconn.Notification{Channel: ConfigChangedChannel,
			Payload: fmt.Sprintf(`{"key":"feature.probe_%d","enabled":true}`, i)})
	}
	waitForReloads(t, flags, 2)

	observedMu.Lock()
	got := append([]Notification(nil), observed...)
	observedMu.Unlock()
	if len(got) != 2 {
		t.Fatalf("observations=%+v, want startup plus one coalesced reload", got)
	}
	if got[1].Key != "feature.probe_4" {
		t.Fatalf("coalesced pending=%+v, want last notification of the burst", got[1])
	}
}

func TestBindNotificationsReconcilesMalformedAndEmptyKeys(t *testing.T) {
	withDebounceInterval(t, 5*time.Millisecond)
	listener := &notificationTestListener{}
	flags := &notificationTestFlags{}
	if err := BindNotifications(t.Context(), listener, flags, nil, slog.New(slog.NewTextHandler(io.Discard, nil))); err != nil {
		t.Fatal(err)
	}
	handler, _, _, _, _ := listener.snapshot()
	handler(&pgconn.Notification{Payload: `{`})
	handler(&pgconn.Notification{Payload: `{"key":""}`})
	waitForReloads(t, flags, 2)
}

func TestBindNotificationsFailsClosedAndCleansUpSetup(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	t.Run("subscribe", func(t *testing.T) {
		want := errors.New("LISTEN refused")
		listener := &notificationTestListener{subscribeErr: want}
		flags := &notificationTestFlags{}
		if err := BindNotifications(t.Context(), listener, flags, nil, logger); !errors.Is(err, want) {
			t.Fatalf("err=%v, want %v", err, want)
		}
		_, _, unsubscribed, _, reconnectRemoved := listener.snapshot()
		if !reflect.DeepEqual(unsubscribed, []int{41}) || !reconnectRemoved {
			t.Fatalf("unsubscribed=%v reconnectRemoved=%v", unsubscribed, reconnectRemoved)
		}
		if reloads := flags.snapshot(); reloads != 0 {
			t.Fatalf("reloads=%d, want 0", reloads)
		}
	})
	t.Run("post-listen-reload", func(t *testing.T) {
		want := errors.New("authoritative snapshot unavailable")
		listener := &notificationTestListener{}
		flags := &notificationTestFlags{reloadError: want}
		if err := BindNotifications(t.Context(), listener, flags, nil, logger); !errors.Is(err, want) {
			t.Fatalf("err=%v, want %v", err, want)
		}
		_, _, unsubscribed, _, reconnectRemoved := listener.snapshot()
		if !reflect.DeepEqual(unsubscribed, []int{41}) || !reconnectRemoved {
			t.Fatalf("unsubscribed=%v reconnectRemoved=%v", unsubscribed, reconnectRemoved)
		}
	})
}

func TestBindNotificationsReconnectAndCancellation(t *testing.T) {
	withDebounceInterval(t, 5*time.Millisecond)
	ctx, cancel := context.WithCancel(t.Context())
	listener := &notificationTestListener{}
	flags := &notificationTestFlags{}
	var observedMu sync.Mutex
	observed := 0
	if err := BindNotifications(ctx, listener, flags, ObserverFunc(func(context.Context, Notification) {
		observedMu.Lock()
		observed++
		observedMu.Unlock()
	}), slog.New(slog.NewTextHandler(io.Discard, nil))); err != nil {
		t.Fatal(err)
	}
	handler, reconnect, _, _, _ := listener.snapshot()
	if err := reconnect(t.Context()); err != nil {
		t.Fatal(err)
	}
	if reloads := flags.snapshot(); reloads != 2 {
		t.Fatalf("reloads=%d after reconnect", reloads)
	}

	cancel()
	deadline := time.Now().Add(time.Second)
	for {
		_, _, unsubscribed, _, removed := listener.snapshot()
		if len(unsubscribed) == 1 && removed {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("binding was not unregistered: unsubscribed=%v removed=%v", unsubscribed, removed)
		}
		time.Sleep(time.Millisecond)
	}
	handler(&pgconn.Notification{Payload: `{"key":"feature.captcha","enabled":true}`})
	if err := reconnect(t.Context()); err != nil {
		t.Fatal(err)
	}
	reloads := flags.snapshot()
	observedMu.Lock()
	gotObserved := observed
	observedMu.Unlock()
	if reloads != 2 || gotObserved != 2 {
		t.Fatalf("after cancel reloads=%d observed=%d", reloads, gotObserved)
	}
}

// assertSnapshotMatchesFeatureToggles compares one key's runtime resolution
// against the authoritative feature_toggles row: an absent/NULL row resolves
// to the registry default, a present row to the database value.
func assertSnapshotMatchesFeatureToggles(
	t *testing.T,
	ctx context.Context,
	pool *pgxpool.Pool,
	flags *FeatureFlags,
	key string,
) {
	t.Helper()
	var enabled *bool
	err := pool.QueryRow(ctx, `SELECT enabled FROM feature_toggles WHERE key=$1`, key).Scan(&enabled)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("read %s: %v", key, err)
	}
	want, wantSource := flags.Resolve(key)
	if enabled == nil {
		defaultEnabled, ok := Lookup(key)
		if !ok {
			t.Fatalf("%s is not registered", key)
		}
		if want != defaultEnabled.Default || wantSource != SourceDefault {
			t.Fatalf("%s resolved (%v,%s) with no authoritative row, want (%v,default)",
				key, want, wantSource, defaultEnabled.Default)
		}
		return
	}
	if want != *enabled || wantSource != SourceDatabase {
		t.Fatalf("%s resolved (%v,%s), authoritative row is (%v,database)", key, want, wantSource, *enabled)
	}
}

// TestBindNotificationsReloadOnlyMatchesFeatureToggles is the database-backed
// arm of the med-toggle-notify-auth-001 proposed tests: a forged protected-key
// payload never materializes a transient unauthorized value, flag values after
// any notification match feature_toggles, and a legitimate reducer-emitted
// change propagates promptly through the reload path.
func TestBindNotificationsReloadOnlyMatchesFeatureToggles(t *testing.T) {
	dsn := os.Getenv("DB_DSN")
	if dsn == "" {
		t.Skip("DB_DSN not set")
	}
	withDebounceInterval(t, 10*time.Millisecond)
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}

	const probe = FeatureStaleNudges
	var probeOriginal bool
	if err := pool.QueryRow(ctx, `SELECT enabled FROM feature_toggles WHERE key=$1`, probe).Scan(&probeOriginal); err != nil {
		t.Fatalf("probe row %s must be seeded by the baseline: %v", probe, err)
	}
	// Cleanup is LIFO: the probe restore runs before the pool closes.
	t.Cleanup(pool.Close)
	t.Cleanup(func() {
		restoreCtx, restoreCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer restoreCancel()
		if _, err := pool.Exec(restoreCtx,
			`SELECT feature_toggle_set($1,$2,1,'127.0.0.1','reload-only propagation test cleanup')`,
			probe, probeOriginal); err != nil {
			t.Errorf("restore %s: %v", probe, err)
		}
	})

	flags, err := New(ctx, pool, nil)
	if err != nil {
		t.Fatal(err)
	}
	listener := &notificationTestListener{}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	if err := BindNotifications(ctx, listener, flags, nil, logger); err != nil {
		t.Fatal(err)
	}
	handler, _, _, _, _ := listener.snapshot()

	// Forged protected-key payload: dengbao.sod_mode enabled=true with a
	// higher version. From delivery, through the debounced reload window, and
	// for a safety margin beyond it, the forged value must never be
	// observable and the snapshot must keep matching feature_toggles.
	handler(&pgconn.Notification{Channel: ConfigChangedChannel,
		Payload: `{"key":"dengbao.sod_mode","enabled":true,"version":999}`})
	forgedDeadline := time.Now().Add(300 * time.Millisecond)
	for time.Now().Before(forgedDeadline) {
		if flags.IsEnabled(FeatureDengbaoSodMode) {
			t.Fatal("forged protected-key payload materialized a transient unauthorized value")
		}
		assertSnapshotMatchesFeatureToggles(t, ctx, pool, flags, FeatureDengbaoSodMode)
		time.Sleep(time.Millisecond)
	}
	assertSnapshotMatchesFeatureToggles(t, ctx, pool, flags, FeatureDengbaoSodMode)

	// Legitimate reducer-emitted change propagates promptly through the
	// debounced reload path.
	if _, err := pool.Exec(ctx,
		`SELECT feature_toggle_set($1,true,1,'127.0.0.1','reload-only propagation test')`, probe); err != nil {
		t.Fatal(err)
	}
	handler(&pgconn.Notification{Channel: ConfigChangedChannel,
		Payload: fmt.Sprintf(`{"key":%q,"enabled":true}`, probe)})
	propagationDeadline := time.Now().Add(2 * time.Second)
	for !flags.IsEnabled(probe) {
		if time.Now().After(propagationDeadline) {
			t.Fatalf("reducer change to %s did not propagate through the reload path within 2s", probe)
		}
		time.Sleep(time.Millisecond)
	}
	assertSnapshotMatchesFeatureToggles(t, ctx, pool, flags, probe)
}
