package directorysync

// Durable quarantine-before-cursor acceptance tests (med-shard2-012, Astra
// waves34 HOLD 1). Skip-and-quarantine decisions are persisted to the
// Quarantines store BEFORE the page cursor is acknowledged, so cursor
// advancement and restarts can never silently drop the only durable evidence
// of an owed review. A quarantine-accounting failure must leave the
// committed cursor untouched.

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"
	"setjoin.com/mailserver/internal/identitysource"
)

// recordingQuarantines captures the exact sequence position of each durable
// accounting call relative to ApplyPage calls, so the test can prove
// quarantine evidence lands before cursor acknowledgment rather than after.
type recordingQuarantines struct {
	fail    error
	records []QuarantineRecord
	order   []string // "quarantine" | "apply" in call order
	source  identitysource.Source
}

func (q *recordingQuarantines) RecordQuarantines(
	_ context.Context, source identitysource.Source, _ uuid.UUID, records []QuarantineRecord,
) error {
	q.order = append(q.order, "quarantine")
	q.source = source
	q.records = append(q.records, records...)
	return q.fail
}

// quarantinesEnabledStore is a fakeStore that reports ApplyPage calls to the
// shared order log.
type quarantinesEnabledStore struct {
	fakeStore
	order *[]string
}

func (s *quarantinesEnabledStore) ApplyPage(
	_ context.Context, _ identitysource.Source, page identitysource.Page, _ uuid.UUID,
) (identitysource.FinishResult, error) {
	*s.order = append(*s.order, "apply")
	return s.fakeStore.ApplyPage(context.Background(), s.source, page, uuid.New())
}

// Both skip classes (missing immutable subject; mail-less in-scope upsert)
// are durably recorded, exactly once per distinct (object key, reason) pair,
// and the durable accounting call strictly precedes any page application —
// i.e. it precedes cursor acknowledgment. Non-quarantined objects still
// stage, and the tombstone path never quarantines.
func TestSyncRecordsQuarantineBeforeCursorAcknowledgment(t *testing.T) {
	order := []string{}
	quarantines := &recordingQuarantines{}
	store := &quarantinesEnabledStore{
		fakeStore: fakeStore{
			source:   identitysource.Source{ID: 42, Generation: 7, Cursor: json.RawMessage(`{"cursor":"before"}`)},
			acquired: true,
		},
		order: &order,
	}
	connector := &fakeConnector{
		label:  "TEST",
		before: testCursor("before"),
		after:  testCursor("after"),
		objects: []Object{
			{Subject: "", RelationKey: "ghost-dn", Email: "ghost@example.com"},
			{Subject: "mail-less", DisplayName: "No Mail Attribute"},
			{Subject: "live", Email: "live@example.com"},
			{Subject: "deleted", Tombstone: true},
		},
	}
	result, err := (Engine{
		Store: store, Connector: connector, Quarantines: quarantines,
		Instance: uuid.New(),
	}).Sync(context.Background())
	if err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if result.Skipped != 2 || result.Updated != 2 {
		t.Fatalf("result=%+v want Skipped=2 Updated=2", result)
	}
	if len(quarantines.order) != 1 || len(order) < 1 {
		t.Fatalf("order=%v quarantine calls=%d", order, len(quarantines.order))
	}
	if quarantines.order[0] != "quarantine" {
		t.Fatalf("durable accounting must precede cursor acknowledgment, order=%v", order)
	}
	if quarantines.source.ID != 42 || quarantines.source.Generation != 7 {
		t.Fatalf("accounting must be source-scoped, got %+v", quarantines.source)
	}
	if len(quarantines.records) != 2 {
		t.Fatalf("records=%+v want exactly the two skip classes", quarantines.records)
	}
	byKey := make(map[string]QuarantineRecord, len(quarantines.records))
	for _, record := range quarantines.records {
		byKey[record.ReasonCode+"\x00"+record.ObjectKey] = record
	}
	missing, ok := byKey[QuarantineMissingSubject+"\x00ghost-dn"]
	if !ok {
		t.Fatalf("missing-subject skip not recorded durably: %+v", quarantines.records)
	}
	if missing.SubjectDigest == "" {
		t.Fatal("missing-subject record must carry a subject digest for redacted correlation")
	}
	if _, ok := byKey[QuarantineNoUsableMail+"\x00mail-less"]; !ok {
		t.Fatalf("mail-less skip not recorded durably: %+v", quarantines.records)
	}
	for _, record := range quarantines.records {
		if len(record.ObjectKey) > quarantineMaxObjectKey {
			t.Fatalf("record key %q exceeds ledger bounds", record.ObjectKey)
		}
	}
	if len(store.pages) != 1 || len(store.pages[0].Entries) != 2 {
		t.Fatalf("non-quarantined objects must still stage: %+v", store.pages)
	}
}

// A mail-less object with neither subject nor relation key still produces a
// bounded digest-form ledger key, and two identical malformed objects in one
// page collapse into one record per (key, reason) pair.
func TestSyncQuarantineKeyFallbackAndPageDedup(t *testing.T) {
	quarantines := &recordingQuarantines{}
	store := &fakeStore{source: identitysource.Source{Cursor: json.RawMessage(`{"cursor":"before"}`)}, acquired: true}
	connector := &fakeConnector{
		label:  "TEST",
		before: testCursor("before"),
		after:  testCursor("after"),
		objects: []Object{
			{Subject: "", DisplayName: "no key at all"},
			{Subject: "", DisplayName: "no key at all, again"},
		},
	}
	if _, err := (Engine{
		Store: store, Connector: connector, Quarantines: quarantines, Instance: uuid.New(),
	}).Sync(context.Background()); err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if len(quarantines.records) != 1 {
		t.Fatalf("records=%+v want one collapsed record", quarantines.records)
	}
	key := quarantines.records[0].ObjectKey
	if len(key) > quarantineMaxObjectKey || key == "" {
		t.Fatalf("fallback key %q must be non-empty and bounded", key)
	}
}

// A quarantine-accounting failure must fail the cycle BEFORE any page is
// applied: the committed cursor stays untouched so the next cycle
// re-traverses and re-accounts idempotently.
func TestSyncQuarantineFailureBlocksCursorAcknowledgment(t *testing.T) {
	order := []string{}
	quarantines := &recordingQuarantines{fail: errors.New("ledger unavailable")}
	store := &quarantinesEnabledStore{
		fakeStore: fakeStore{
			source:   identitysource.Source{Cursor: json.RawMessage(`{"cursor":"before"}`)},
			acquired: true,
		},
		order: &order,
	}
	connector := &fakeConnector{
		label:  "TEST",
		before: testCursor("before"),
		after:  testCursor("after"),
		objects: []Object{
			{Subject: "mail-less", DisplayName: "No Mail Attribute"},
			{Subject: "live", Email: "live@example.com"},
		},
	}
	result, err := (Engine{
		Store: store, Connector: connector, Quarantines: quarantines, Instance: uuid.New(),
	}).Sync(context.Background())
	if err == nil || !strings.Contains(err.Error(), "record TEST quarantine accounting") {
		t.Fatalf("quarantine failure must fail the sync, got err=%v", err)
	}
	if result.Errors != 1 {
		t.Fatalf("result=%+v want Errors=1", result)
	}
	if len(store.pages) != 0 {
		t.Fatalf("cursor must not be acknowledged while accounting failed, pages=%d", len(store.pages))
	}
}

// Without a Quarantines store the engine keeps its historical log-only
// behavior (used while production workers are being wired): pages apply and
// skips are counted, never silently dropped from the loud log path.
func TestSyncNilQuarantinesKeepsLogOnlyBehavior(t *testing.T) {
	store := &fakeStore{source: identitysource.Source{Cursor: json.RawMessage(`{"cursor":"before"}`)}, acquired: true}
	connector := &fakeConnector{
		label:  "TEST",
		before: testCursor("before"),
		after:  testCursor("after"),
		objects: []Object{
			{Subject: "mail-less", DisplayName: "No Mail Attribute"},
		},
	}
	result, err := (Engine{Store: store, Connector: connector, Instance: uuid.New()}).Sync(context.Background())
	if err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if result.Skipped != 1 || len(store.pages) != 1 {
		t.Fatalf("result=%+v pages=%d want Skipped=1 pages=1", result, len(store.pages))
	}
}
