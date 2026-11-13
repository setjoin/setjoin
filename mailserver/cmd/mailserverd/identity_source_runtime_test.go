package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"

	"setjoin.com/mailserver/internal/admin"
	"setjoin.com/mailserver/internal/identitysource"
	"setjoin.com/shared/cryptokey"
	"setjoin.com/shared/testsupport"
)

type fakeIdentityRuntimeCatalog struct {
	mu            sync.Mutex
	entries       []identitySourceRuntimeEntry
	loads         int
	err           error
	invalid       []error
	masterEnabled bool
}

func (c *fakeIdentityRuntimeCatalog) LoadActive(
	context.Context,
) (identitySourceRuntimeSnapshot, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.loads++
	return identitySourceRuntimeSnapshot{
		entries:       append([]identitySourceRuntimeEntry(nil), c.entries...),
		invalid:       append([]error(nil), c.invalid...),
		authoritative: true,
		masterEnabled: c.masterEnabled,
	}, c.err
}

func (c *fakeIdentityRuntimeCatalog) set(entries ...identitySourceRuntimeEntry) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries = append([]identitySourceRuntimeEntry(nil), entries...)
}

type identityRuntimeEvent struct {
	action     string
	sourceID   int64
	generation int64
}

type fakeIdentityRuntimeBuilder struct {
	events chan<- identityRuntimeEvent
}

func (b fakeIdentityRuntimeBuilder) Build(
	entry identitySourceRuntimeEntry,
) (identitysource.Runnable, error) {
	return fakeIdentityRuntimeWorker{entry: entry, events: b.events}, nil
}

type fakeIdentityRuntimeWorker struct {
	entry  identitySourceRuntimeEntry
	events chan<- identityRuntimeEvent
}

func (w fakeIdentityRuntimeWorker) Run(ctx context.Context) {
	w.events <- identityRuntimeEvent{
		action: "start", sourceID: w.entry.spec.SourceID, generation: w.entry.spec.Generation,
	}
	<-ctx.Done()
	w.events <- identityRuntimeEvent{
		action: "stop", sourceID: w.entry.spec.SourceID, generation: w.entry.spec.Generation,
	}
}

func runtimeEntry(id, generation int64) identitySourceRuntimeEntry {
	return identitySourceRuntimeEntry{
		spec: identitysource.Spec{SourceID: id, Generation: generation},
		key:  fmt.Sprintf("source-%d", id),
		config: admin.IdentitySourceRuntimeConfig{
			SourceKey: fmt.Sprintf("source-%d", id),
			Kind:      "ldap",
		},
	}
}

func awaitIdentityRuntimeEvent(
	t *testing.T,
	events <-chan identityRuntimeEvent,
	action string,
	id int64,
	generation int64,
) {
	t.Helper()
	select {
	case got := <-events:
		if got.action != action || got.sourceID != id || got.generation != generation {
			t.Fatalf("event = %+v, want %s %d/%d", got, action, id, generation)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for %s %d/%d", action, id, generation)
	}
}

func TestIdentitySourceRuntimeManagerMasterGateAndLiveReconcile(t *testing.T) {
	t.Parallel()
	catalog := &fakeIdentityRuntimeCatalog{entries: []identitySourceRuntimeEntry{runtimeEntry(1, 1)}}
	events := make(chan identityRuntimeEvent, 8)
	var enabled atomic.Bool
	manager := newIdentitySourceRuntimeManager(
		catalog,
		fakeIdentityRuntimeBuilder{events: events},
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		enabled.Load,
	)
	manager.pollEvery = time.Hour
	if err := manager.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(manager.Stop)
	if manager.supervisor.Count() != 0 {
		t.Fatal("worker started while the identity master feature was disabled")
	}
	catalog.mu.Lock()
	catalog.masterEnabled = true
	catalog.mu.Unlock()
	enabled.Store(true)
	manager.Notify(`{"key":"feature.identity_model_v2","enabled":true}`)
	awaitIdentityRuntimeEvent(t, events, "start", 1, 1)

	catalog.set(runtimeEntry(1, 2), runtimeEntry(2, 1))
	manager.Notify(`{"key":"identity.source.1","generation":2}`)
	awaitIdentityRuntimeEvent(t, events, "stop", 1, 1)
	started := map[int64]int64{}
	for len(started) < 2 {
		select {
		case got := <-events:
			if got.action != "start" {
				t.Fatalf("unexpected replacement event: %+v", got)
			}
			started[got.sourceID] = got.generation
		case <-time.After(2 * time.Second):
			t.Fatal("timed out waiting for replacement workers")
		}
	}
	if started[1] != 2 || started[2] != 1 {
		t.Fatalf("replacement generations = %#v", started)
	}

	enabled.Store(false)
	manager.Notify(`{"key":"feature.identity_model_v2","enabled":false}`)
	seen := map[int64]bool{}
	for len(seen) < 2 {
		select {
		case got := <-events:
			if got.action != "stop" || got.generation != map[int64]int64{1: 2, 2: 1}[got.sourceID] {
				t.Fatalf("unexpected disable event: %+v", got)
			}
			seen[got.sourceID] = true
		case <-time.After(2 * time.Second):
			t.Fatal("timed out waiting for master-gate worker shutdown")
		}
	}
}

func TestIdentitySourceRuntimeManagerPollRepairsLostNotify(t *testing.T) {
	t.Parallel()
	catalog := &fakeIdentityRuntimeCatalog{
		entries: []identitySourceRuntimeEntry{runtimeEntry(7, 1)}, masterEnabled: true,
	}
	events := make(chan identityRuntimeEvent, 8)
	manager := newIdentitySourceRuntimeManager(
		catalog,
		fakeIdentityRuntimeBuilder{events: events},
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		func() bool { return true },
	)
	manager.pollEvery = 10 * time.Millisecond
	if err := manager.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(manager.Stop)
	awaitIdentityRuntimeEvent(t, events, "start", 7, 1)

	catalog.set(runtimeEntry(7, 2))
	awaitIdentityRuntimeEvent(t, events, "stop", 7, 1)
	awaitIdentityRuntimeEvent(t, events, "start", 7, 2)
}

func TestIdentitySourceRuntimeManagerPollStopsWorkersAfterMissedMasterDisable(t *testing.T) {
	t.Parallel()
	catalog := &fakeIdentityRuntimeCatalog{
		entries: []identitySourceRuntimeEntry{runtimeEntry(9, 1)}, masterEnabled: true,
	}
	events := make(chan identityRuntimeEvent, 4)
	manager := newIdentitySourceRuntimeManager(
		catalog,
		fakeIdentityRuntimeBuilder{events: events},
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		func() bool { return true }, // deliberately stale process-local cache
	)
	manager.pollEvery = 10 * time.Millisecond
	if err := manager.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(manager.Stop)
	awaitIdentityRuntimeEvent(t, events, "start", 9, 1)

	catalog.mu.Lock()
	catalog.masterEnabled = false
	catalog.mu.Unlock()
	awaitIdentityRuntimeEvent(t, events, "stop", 9, 1)
}

func TestIdentitySourceRuntimeManagerIsolatesInvalidSourceAndStartsHealthySource(t *testing.T) {
	t.Parallel()
	events := make(chan identityRuntimeEvent, 2)
	var logs strings.Builder
	manager := newIdentitySourceRuntimeManager(
		&fakeIdentityRuntimeCatalog{
			entries:       []identitySourceRuntimeEntry{runtimeEntry(11, 1)},
			invalid:       []error{errors.New("legacy AD envelope unavailable")},
			masterEnabled: true,
		},
		fakeIdentityRuntimeBuilder{events: events},
		slog.New(slog.NewTextHandler(&logs, nil)),
		func() bool { return true },
	)
	manager.pollEvery = time.Hour
	if err := manager.Start(context.Background()); err != nil {
		t.Fatalf("partial source failure stopped healthy runtime: %v", err)
	}
	t.Cleanup(manager.Stop)
	awaitIdentityRuntimeEvent(t, events, "start", 11, 1)
	if got := logs.String(); !strings.Contains(got, "source isolated") ||
		!strings.Contains(got, "legacy AD envelope unavailable") {
		t.Fatalf("isolated source diagnostic missing: %q", got)
	}
}

func TestValidIdentitySourceNotificationKey(t *testing.T) {
	t.Parallel()
	for _, key := range []string{"identity.source.1", "identity.source.9223372036854775807"} {
		if !validIdentitySourceNotificationKey(key) {
			t.Fatalf("valid key rejected: %q", key)
		}
	}
	for _, key := range []string{
		"", "identity.source.", "identity.source.0", "identity.source.-1",
		"identity.source.1.extra", "feature.identity_model_v2",
	} {
		if validIdentitySourceNotificationKey(key) {
			t.Fatalf("invalid key accepted: %q", key)
		}
	}
}

func TestDatabaseIdentitySourceRuntimeCatalogFiltersAndFailsClosed(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()
	testsupport.SetFeatureToggleForTest(t, pool, "feature.identity_model_v2", true)
	codec, err := admin.NewConfigSecretCodec(admin.ConfigSecretKeyring{
		DeploymentID:  "identity-runtime-catalog-test",
		ActiveVersion: 1,
		ActiveKey:     []byte("0123456789abcdef0123456789abcdef"),
		ActiveProfile: cryptokey.ProfileStandard,
	})
	if err != nil {
		t.Fatal(err)
	}
	goodKey := "runtime-ad-" + uuid.NewString()
	invalidKey := "runtime-invalid-" + uuid.NewString()
	pausedKey := "runtime-paused-" + uuid.NewString()
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(),
			`DELETE FROM identity_sources WHERE source_key=ANY($1::text[])`,
			[]string{goodKey, invalidKey, pausedKey},
		)
	})

	runtimeEnvelope := func(key string) []byte {
		t.Helper()
		document := json.RawMessage(fmt.Sprintf(
			`{"apiVersion":"setjoin.io/v1","kind":"IdentitySource",`+
				`"metadata":{"sourceKey":%q,"displayName":"Runtime AD"},`+
				`"spec":{"type":"ad","endpoint":{"host":"dc.example.test","port":636,"tls":"ldaps"},`+
				`"subjectAttribute":"objectGUID","baseDN":"dc=example,dc=test"}}`,
			key,
		))
		plain, marshalErr := json.Marshal(map[string]any{
			"document": document,
			"secrets": map[string]string{
				"bindPassword": base64.StdEncoding.EncodeToString([]byte("catalog-secret")),
			},
		})
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		envelope, encryptErr := codec.Encrypt("identity_source."+key, plain)
		if encryptErr != nil {
			t.Fatal(encryptErr)
		}
		return envelope
	}
	for _, row := range []struct {
		key      string
		state    string
		envelope []byte
	}{
		{goodKey, "active", runtimeEnvelope(goodKey)},
		{invalidKey, "active", []byte("not-an-envelope")},
		{pausedKey, "paused", runtimeEnvelope(pausedKey)},
	} {
		if _, err := pool.Exec(ctx, `
			INSERT INTO identity_sources(
				source_key,display_name,kind,capabilities,state,
				generation,config_envelope,config_key_version
			) VALUES($1,'Runtime test','ad','{"provisionLifecycle":true}'::jsonb,$2,7,$3,1)`,
			row.key, row.state, row.envelope,
		); err != nil {
			t.Fatalf("insert %s: %v", row.key, err)
		}
	}

	snapshot, loadErr := (databaseIdentitySourceRuntimeCatalog{
		pool: pool, codec: codec,
	}).LoadActive(ctx)
	if !snapshot.authoritative {
		t.Fatal("successful catalog scan was not authoritative")
	}
	if !snapshot.masterEnabled {
		t.Fatal("enabled identity master toggle was not included in catalog snapshot")
	}
	if len(snapshot.entries) != 1 || snapshot.entries[0].key != goodKey ||
		snapshot.entries[0].spec.Generation != 7 {
		t.Fatalf("active runnable entries = %+v", snapshot.entries)
	}
	if got := snapshot.entries[0].config.BindPassword(); got != "catalog-secret" {
		t.Fatal("active source secret was not decrypted for the worker builder")
	}
	if loadErr != nil {
		t.Fatalf("one invalid source made the catalog non-authoritative: %v", loadErr)
	}
	var invalidSourceErr error
	for _, candidate := range snapshot.invalid {
		if strings.Contains(candidate.Error(), invalidKey) {
			invalidSourceErr = candidate
			break
		}
	}
	if invalidSourceErr == nil {
		t.Fatalf("invalid active source was not isolated: %v", snapshot.invalid)
	}
	if strings.Contains(invalidSourceErr.Error(), "catalog-secret") {
		t.Fatal("catalog diagnostic exposed connector secret material")
	}
}

func TestIdentitySourceRuntimeWorkerBuilderSupportsOnlyBoundedConnectors(t *testing.T) {
	t.Parallel()
	builder := identitySourceWorkerBuilder{
		logger:          slog.New(slog.NewTextHandler(io.Discard, nil)),
		adIntervalMin:   15,
		ldapIntervalMin: 15,
	}
	base := identitySourceRuntimeEntry{
		spec: identitysource.Spec{SourceID: 7, Generation: 2},
		key:  "corp-directory",
		config: admin.IdentitySourceRuntimeConfig{
			SourceKey:  "corp-directory",
			Host:       "directory.example.test",
			Port:       636,
			Transport:  "ldaps",
			BaseDN:     "dc=example,dc=test",
			BindDN:     "cn=service,dc=example,dc=test",
			UserFilter: "(objectClass=person)",
		},
	}
	for _, connector := range []struct {
		name             string
		kind             string
		subjectAttribute string
	}{
		{name: "ad", kind: "ad", subjectAttribute: "objectGUID"},
		{name: "ldap", kind: "ldap", subjectAttribute: "entryUUID"},
	} {
		t.Run(connector.name, func(t *testing.T) {
			entry := base
			entry.config.Kind = connector.kind
			entry.config.SubjectAttribute = connector.subjectAttribute
			worker, err := builder.Build(entry)
			if err != nil || worker == nil {
				t.Fatalf("build %s worker = %T / %v", connector.kind, worker, err)
			}
		})
	}
	for _, invalid := range []struct {
		name   string
		mutate func(*identitySourceRuntimeEntry)
	}{
		{"unknown-kind", func(entry *identitySourceRuntimeEntry) {
			entry.config.Kind = "scim"
		}},
		{"ad-endpoint", func(entry *identitySourceRuntimeEntry) {
			entry.config.Kind = "ad"
			entry.config.SubjectAttribute = "objectGUID"
			entry.config.Port = 0
		}},
		{"ldap-endpoint", func(entry *identitySourceRuntimeEntry) {
			entry.config.Kind = "ldap"
			entry.config.SubjectAttribute = "entryUUID"
			entry.config.Host = ""
		}},
		{"ldap-anchor", func(entry *identitySourceRuntimeEntry) {
			entry.config.Kind = "ldap"
			entry.config.SubjectAttribute = "not an attribute"
		}},
		{"ldap-filter", func(entry *identitySourceRuntimeEntry) {
			entry.config.Kind = "ldap"
			entry.config.SubjectAttribute = "entryUUID"
			entry.config.UserFilter = "("
		}},
	} {
		t.Run(invalid.name, func(t *testing.T) {
			entry := base
			invalid.mutate(&entry)
			if worker, err := builder.Build(entry); err == nil || worker != nil {
				t.Fatalf("invalid runtime connector built as %T / %v", worker, err)
			}
		})
	}
}

func TestIdentitySourceRuntimeManagerFailsClosedAndRejectsDoubleStart(t *testing.T) {
	t.Parallel()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	catalog := &fakeIdentityRuntimeCatalog{
		masterEnabled: true,
		err:           fmt.Errorf("catalog unavailable"),
	}
	manager := newIdentitySourceRuntimeManager(
		catalog,
		fakeIdentityRuntimeBuilder{events: make(chan identityRuntimeEvent, 1)},
		logger,
		func() bool { return true },
	)
	if err := manager.Start(context.Background()); err == nil {
		t.Fatal("initial catalog failure did not fail closed")
	}
	manager.Stop()

	catalog.err = nil
	if err := manager.Start(context.Background()); err != nil {
		t.Fatalf("start after corrected catalog: %v", err)
	}
	if err := manager.Start(context.Background()); err == nil {
		t.Fatal("double-started identity runtime manager")
	}
	manager.Notify(`not-json`)
	manager.Notify(`{"key":"unrelated"}`)
	manager.Stop()
	manager.Stop()
}
