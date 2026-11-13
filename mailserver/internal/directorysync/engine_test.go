package directorysync

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
	"setjoin.com/mailserver/internal/identitysource"
	"setjoin.com/mailserver/internal/ldaputil"
)

type testCursor string

func (c testCursor) Encode() (json.RawMessage, error) {
	return json.Marshal(map[string]string{"cursor": string(c)})
}

type fakeConnector struct {
	label       string
	before      Cursor
	objects     []Object
	after       Cursor
	preflight   error
	decodeErr   error
	fetchErr    error
	rejectDupes bool
}

func (c *fakeConnector) Label() string    { return c.label }
func (c *fakeConnector) Preflight() error { return c.preflight }
func (c *fakeConnector) DecodeCursor(json.RawMessage) (Cursor, error) {
	if c.decodeErr != nil {
		return nil, c.decodeErr
	}
	return c.before, nil
}
func (c *fakeConnector) Fetch(context.Context, Cursor) ([]Object, Cursor, error) {
	return c.objects, c.after, c.fetchErr
}
func (c *fakeConnector) ValidateObject(_ Object, seen bool) error {
	if seen && c.rejectDupes {
		return errors.New("duplicate subject")
	}
	return nil
}

type fakeStore struct {
	source       identitysource.Source
	acquired     bool
	acquireErr   error
	recovery     identitysource.RecoveryResult
	recoveryErr  error
	pages        []identitysource.Page
	releaseCalls int
}

func (s *fakeStore) SourceByKey(context.Context, string) (identitysource.Source, error) {
	return s.source, nil
}
func (s *fakeStore) AcquireLease(context.Context, identitysource.Source, uuid.UUID) (bool, error) {
	return s.acquired, s.acquireErr
}
func (s *fakeStore) ReleaseLease(context.Context, identitysource.Source, uuid.UUID) error {
	s.releaseCalls++
	return nil
}
func (s *fakeStore) ResumeUnfinished(context.Context, identitysource.Source, uuid.UUID) (identitysource.RecoveryResult, error) {
	return s.recovery, s.recoveryErr
}
func (s *fakeStore) ApplyPage(_ context.Context, _ identitysource.Source, page identitysource.Page, _ uuid.UUID) (identitysource.FinishResult, error) {
	s.pages = append(s.pages, page)
	// Truthful store behavior: every staged entry of the page applied, none
	// quarantined (D-MAILSERVER-INTERNAL-DIRECTORYSYNC-004 — Sync maps the
	// store's real per-page outcomes onto SyncResult instead of assuming the
	// staged count applied).
	return identitysource.FinishResult{
		State:          "completed",
		CursorAdvanced: true,
		Applied:        len(page.Entries),
	}, nil
}

func TestSyncPageBoundariesAndTerminalCursor(t *testing.T) {
	for _, count := range []int{0, 1, identitysource.MaxEntries, identitysource.MaxEntries + 1} {
		t.Run(fmt.Sprintf("%d_objects", count), func(t *testing.T) {
			objects := make([]Object, count)
			for i := range objects {
				objects[i] = Object{Subject: uuid.NewString(), Email: "USER@EXAMPLE.COM"}
			}
			store := &fakeStore{source: identitysource.Source{Cursor: json.RawMessage(`{"cursor":"before"}`)}, acquired: true}
			connector := &fakeConnector{label: "TEST", before: testCursor("before"), after: testCursor("after"), objects: objects}
			result, err := (Engine{Store: store, Connector: connector, Instance: uuid.New()}).Sync(context.Background())
			if err != nil {
				t.Fatalf("Sync: %v", err)
			}
			if result.Checked != count || result.Updated != count {
				t.Fatalf("result=%+v count=%d", result, count)
			}
			wantPages := 1
			if count > identitysource.MaxEntries {
				wantPages = 4
			}
			if len(store.pages) != wantPages {
				t.Fatalf("pages=%d want=%d", len(store.pages), wantPages)
			}
			seenBatchIDs := make(map[uuid.UUID]struct{}, len(store.pages))
			for i, page := range store.pages {
				if page.BatchID == uuid.Nil {
					t.Fatalf("page %d has nil batch id", i)
				}
				if _, exists := seenBatchIDs[page.BatchID]; exists {
					t.Fatalf("page %d reused batch id", i)
				}
				seenBatchIDs[page.BatchID] = struct{}{}
				wantCursor := `{"cursor":"before"}`
				if i == len(store.pages)-1 {
					wantCursor = `{"cursor":"after"}`
				}
				if string(page.Cursor) != wantCursor {
					t.Fatalf("page %d cursor=%s want=%s", i, page.Cursor, wantCursor)
				}
			}
		})
	}
}

func TestSyncManagerFallbackAndAuthoritativeSubject(t *testing.T) {
	store := &fakeStore{acquired: true}
	connector := &fakeConnector{
		label:  "TEST",
		before: testCursor(""),
		after:  testCursor("1"),
		objects: []Object{
			{Subject: "manager", RelationKey: "manager-key", Email: "manager@example.com"},
			{Subject: "fallback", ManagerRelationKey: "manager-key", Email: "fallback@example.com"},
			{Subject: "explicit", ManagerRelationKey: "manager-key", ManagerSubject: "other", Email: "explicit@example.com"},
		},
	}
	if _, err := (Engine{Store: store, Connector: connector, Instance: uuid.New()}).Sync(context.Background()); err != nil {
		t.Fatalf("Sync: %v", err)
	}
	var fallback, explicit map[string]any
	if err := json.Unmarshal(store.pages[0].Entries[1].Payload, &fallback); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(store.pages[0].Entries[2].Payload, &explicit); err != nil {
		t.Fatal(err)
	}
	if fallback["managerSubject"] != "manager" || explicit["managerSubject"] != "other" {
		t.Fatalf("manager subjects fallback=%v explicit=%v", fallback["managerSubject"], explicit["managerSubject"])
	}
}

func TestSyncLeaseRecoveryAndValidationFailures(t *testing.T) {
	t.Run("lease not acquired", func(t *testing.T) {
		store := &fakeStore{}
		result, err := (Engine{
			Store: store, Connector: &fakeConnector{label: "TEST"}, Instance: uuid.New(),
		}).Sync(context.Background())
		if err != nil || result.Skipped != 1 || len(store.pages) != 0 {
			t.Fatalf("result=%+v err=%v pages=%d", result, err, len(store.pages))
		}
	})
	t.Run("recovery", func(t *testing.T) {
		store := &fakeStore{acquired: true, recovery: identitysource.RecoveryResult{
			Found: true, EntryCount: 3, Finish: identitysource.FinishResult{Applied: 2, Quarantined: 1},
		}}
		result, err := (Engine{
			Store: store, Connector: &fakeConnector{label: "TEST"}, Instance: uuid.New(),
		}).Sync(context.Background())
		if err != nil || result.Checked != 3 || result.Updated != 2 || result.Skipped != 1 {
			t.Fatalf("result=%+v err=%v", result, err)
		}
	})
	t.Run("decode label", func(t *testing.T) {
		store := &fakeStore{acquired: true}
		_, err := (Engine{
			Store:     store,
			Connector: &fakeConnector{label: "TEST", decodeErr: errors.New("bad cursor")},
			Instance:  uuid.New(),
		}).Sync(context.Background())
		if err == nil || !strings.Contains(err.Error(), "decode TEST committed cursor") {
			t.Fatalf("err=%v", err)
		}
	})
	t.Run("duplicate validation", func(t *testing.T) {
		store := &fakeStore{acquired: true}
		_, err := (Engine{
			Store: store,
			Connector: &fakeConnector{
				label: "TEST", before: testCursor(""), after: testCursor(""),
				objects: []Object{{Subject: "same"}, {Subject: "same"}}, rejectDupes: true,
			},
			Instance: uuid.New(),
		}).Sync(context.Background())
		if err == nil || err.Error() != "duplicate subject" {
			t.Fatalf("err=%v", err)
		}
	})
}

func TestEngineHasNoLDAPDependency(t *testing.T) {
	source, err := os.ReadFile("engine.go")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(source), "go-ldap") {
		t.Fatal("engine.go must not import an LDAP package")
	}
}

// TestEntries_InvalidSubjectQuarantinedPerObject pins the per-object subject
// disposition (D-MAILSERVER-INTERNAL-DIRECTORYSYNC-003): an oversized,
// untrimmed or control-character subject no longer fails whole-page validation
// pre-staging (wedging the source cursor every cycle) — the object is skipped
// and durably quarantined while the healthy rest of the page still stages.
func TestEntries_InvalidSubjectQuarantinedPerObject(t *testing.T) {
	good := Object{Subject: "good-subject", Email: "good@example.com"}
	oversized := Object{Subject: strings.Repeat("x", 513), Email: "big@example.com"}
	untrimmed := Object{Subject: " padded-subject ", Email: "pad@example.com"}
	ctl := Object{Subject: "subj\nect", Email: "ctl@example.com"}

	e := Engine{Connector: &fakeConnector{label: "TEST"}}
	var result ldaputil.SyncResult
	entries, quarantined, err := e.entries(
		[]Object{good, oversized, untrimmed, ctl}, "TEST", &result)
	if err != nil {
		t.Fatalf("entries: %v", err)
	}
	if len(entries) != 1 || entries[0].ImmutableSubject != "good-subject" {
		t.Fatalf("only the healthy object must stage, got %d entries", len(entries))
	}
	if len(quarantined) != 3 {
		t.Fatalf("three invalid subjects must quarantine, got %d: %+v", len(quarantined), quarantined)
	}
	for _, rec := range quarantined {
		if rec.ReasonCode != QuarantineInvalidSubject {
			t.Errorf("reason code = %q, want %q", rec.ReasonCode, QuarantineInvalidSubject)
		}
	}
	if result.Skipped != 3 {
		t.Errorf("result.Skipped = %d, want 3", result.Skipped)
	}
}

// TestSync_MapsRealFinishResults pins the SyncResult mapping
// (D-MAILSERVER-INTERNAL-DIRECTORYSYNC-004): Updated reports the store's real
// per-page Applied (not the staged count), reducer-side quarantines land in
// Skipped, and staged disable entries of fully-applied pages count as
// Disabled — the fresh path aligns with the recovery path's semantics.
func TestSync_MapsRealFinishResults(t *testing.T) {
	applied := 0
	store := &countingStore{
		fakeStore: fakeStore{
			source:   identitysource.Source{Cursor: json.RawMessage(`{"cursor":"before"}`)},
			acquired: true,
		},
		onApply: func(page identitysource.Page) identitysource.FinishResult {
			applied += len(page.Entries)
			// Last chunk quarantined one entry reducer-side.
			return identitysource.FinishResult{
				State:          "completed",
				CursorAdvanced: true,
				Applied:        len(page.Entries) - 1,
				Quarantined:    1,
			}
		},
	}
	objects := []Object{
		{Subject: "s1", Email: "s1@example.com"},
		{Subject: "s2", Email: "s2@example.com", Disabled: true},
	}
	result, err := (Engine{Store: store, Connector: &fakeConnector{label: "TEST", before: testCursor("before"), after: testCursor("after"), objects: objects}, Instance: uuid.New()}).
		Sync(context.Background())
	if err != nil {
		t.Fatalf("Sync: %v", err)
	}
	_ = applied
	if result.Updated != 1 {
		t.Errorf("Updated = %d, want 1 (two staged entries, one quarantined reducer-side)", result.Updated)
	}
	if result.Skipped != 1 {
		t.Errorf("Skipped = %d, want 1 (reducer-side quarantine)", result.Skipped)
	}
	if result.Disabled != 0 {
		t.Errorf("Disabled = %d, want 0 — a partially-applied page cannot attribute individual applies (lower-bound rule)", result.Disabled)
	}
}

// countingStore is a fakeStore whose ApplyPage outcome is caller-controlled.
type countingStore struct {
	fakeStore
	onApply func(identitysource.Page) identitysource.FinishResult
}

func (s *countingStore) ApplyPage(ctx context.Context, src identitysource.Source, page identitysource.Page, inst uuid.UUID) (identitysource.FinishResult, error) {
	return s.onApply(page), nil
}
