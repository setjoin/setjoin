package spam

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"
)

func TestBatchCollector_Dedup(t *testing.T) {
	b := newBatchCollector(1 * time.Second)

	// Same message moved to Junk then back to Inbox within the batch window.
	b.add(trainEvent{UserID: 7, MessageID: 123, IsSpam: true})  // spam
	b.add(trainEvent{UserID: 7, MessageID: 123, IsSpam: false}) // not spam (moved back)

	events := b.flush()
	if len(events) != 0 {
		t.Fatalf("expected 0 events after dedup, got %d", len(events))
	}
}

func TestBatchCollector_MaxBatchSize(t *testing.T) {
	b := newBatchCollector(1 * time.Second)

	// Bulk move: 500 messages to Junk.
	for i := 0; i < 500; i++ {
		b.add(trainEvent{UserID: 1, MessageID: int64(i), IsSpam: true})
	}

	events := b.flush()
	if len(events) > 100 {
		t.Fatalf("expected max 100 events, got %d", len(events))
	}
}

// TestBatchCollector_OverflowCarriesToNextFlush is the regression for the
// silent-drop bug: flush() used to reset b.pending unconditionally, discarding
// any event beyond maxBatch instead of carrying it to the next flush window.
// A bulk Junk-move of 500 messages must eventually train all 500, across
// however many flush calls it takes, not just the first 100.
func TestBatchCollector_OverflowCarriesToNextFlush(t *testing.T) {
	b := newBatchCollector(1 * time.Second)

	for i := 0; i < 500; i++ {
		b.add(trainEvent{UserID: 1, MessageID: int64(i), IsSpam: true})
	}

	seen := make(map[int64]bool)
	total := 0
	for i := 0; i < 10 && len(b.pending) > 0; i++ { // guard against infinite loop on regression
		events := b.flush()
		for _, ev := range events {
			if seen[ev.MessageID] {
				t.Fatalf("duplicate MessageID %d across flushes", ev.MessageID)
			}
			seen[ev.MessageID] = true
		}
		total += len(events)
	}

	if total != 500 {
		t.Fatalf("expected all 500 events retained across flushes, got %d", total)
	}
	for i := 0; i < 500; i++ {
		if !seen[int64(i)] {
			t.Fatalf("MessageID %d was lost", i)
		}
	}
}

func TestBatchCollector_LastWriteWins(t *testing.T) {
	b := newBatchCollector(1 * time.Second)

	b.add(trainEvent{UserID: 1, MessageID: 1, IsSpam: true}) // spam
	time.Sleep(10 * time.Millisecond)
	b.add(trainEvent{UserID: 1, MessageID: 1, IsSpam: true}) // spam again (no-op, same label)
	b.add(trainEvent{UserID: 1, MessageID: 2, IsSpam: true}) // spam

	events := b.flush()
	if len(events) != 2 {
		t.Fatalf("expected 2 events, got %d: %v", len(events), events)
	}
}

// TestBatchCollector_PreservesUserID is the regression for the dropped-UserID
// bug: the collector must carry UserID through to flush so flushAndTrain can
// group by real user. The old add(messageID, isSpam) discarded UserID, so every
// event was attributed to user 0.
func TestBatchCollector_PreservesUserID(t *testing.T) {
	b := newBatchCollector(1 * time.Second)
	b.add(trainEvent{UserID: 42, MessageID: 999, IsSpam: true})

	events := b.flush()
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	if events[0].UserID != 42 {
		t.Fatalf("UserID must survive add->flush; got %d, want 42", events[0].UserID)
	}
}

// TestParseNotifyPayload_NumericIDs is the regression for the JSON-contract bug:
// spam_train_notify() emits user_id/message_id as unquoted JSON numbers (BIGINT
// via json_build_object). A `string` MessageID made json.Unmarshal reject EVERY
// payload, silently killing auto-training. The payload below mirrors the trigger.
func TestParseNotifyPayload_NumericIDs(t *testing.T) {
	ev, err := ParseNotifyPayload(`{"user_id":7,"message_id":12345,"is_spam":true}`)
	if err != nil {
		t.Fatalf("numeric message_id must parse (trigger emits a JSON number); got err=%v", err)
	}
	if ev.UserID != 7 || ev.MessageID != 12345 || !ev.IsSpam {
		t.Fatalf("unexpected event: %+v", ev)
	}
}

// fakeModelStore is an in-memory ModelStore that reproduces the persistence
// fence semantics of PGModelStore.SaveModel so trainer reactions to fenced and
// faulted saves are covered deterministically (no goroutine timing): the
// afterLoad hook models the admin/competing-writer action landing inside the
// trainer's load→train→save window.
type fakeModelStore struct {
	msgs     map[int64][]byte
	// row state
	rowExists   bool
	rowDisabled bool
	rowBytes    []byte
	// load results
	loadModel *Model
	loadErr   error
	// hook runs at the start of SaveModel — the deterministic race point.
	afterLoad func(s *fakeModelStore)
	// saveErr, when set, makes every save fail with a DB fault.
	saveErr error
	// observation
	loadCalls, fetchCalls, saveCalls int
	savedBytes                       []byte
	logs                             *bytes.Buffer
}

func newFakeModelStore(t *testing.T) *fakeModelStore {
	return &fakeModelStore{msgs: make(map[int64][]byte), logs: &bytes.Buffer{}}
}

func (f *fakeModelStore) LoadModelForTraining(ctx context.Context, userID int64) (*Model, []byte, error) {
	f.loadCalls++
	if f.loadErr != nil {
		return nil, nil, f.loadErr
	}
	if f.loadModel == nil {
		f.loadModel = NewModel(DefaultFeatureSize)
	}
	if f.rowExists && !f.rowDisabled && len(f.rowBytes) > 0 {
		return f.loadModel, f.rowBytes, nil
	}
	return f.loadModel, nil, nil
}

func (f *fakeModelStore) SaveModel(ctx context.Context, userID int64, data []byte, expect []byte) error {
	f.saveCalls++
	if f.saveErr != nil {
		return f.saveErr
	}
	if f.afterLoad != nil {
		f.afterLoad(f)
		f.afterLoad = nil
	}
	if f.rowDisabled {
		return ErrSaveFenced
	}
	if len(expect) > 0 {
		if !f.rowExists || !bytes.Equal(f.rowBytes, expect) {
			return ErrSaveFenced
		}
	} else if f.rowExists && len(f.rowBytes) > 0 {
		// Cold-start save may only overtake an empty placeholder row.
		return ErrSaveFenced
	}
	f.rowExists = true
	f.rowBytes = append([]byte(nil), data...)
	f.savedBytes = f.rowBytes
	return nil
}

func (f *fakeModelStore) FetchMessage(ctx context.Context, userID int64, messageID int64) ([]byte, error) {
	f.fetchCalls++
	if raw, ok := f.msgs[messageID]; ok {
		return raw, nil
	}
	return nil, errors.New("no such message")
}

func newFakeTrainer(t *testing.T, store *fakeModelStore) *Trainer {
	t.Helper()
	return NewTrainer(store, slog.New(slog.NewTextHandler(store.logs, nil)))
}

// TestTrainer_ResetDuringTrainingFencesSave is the deterministic race coverage
// for the reset half of the persistence fence: admin ResetModel lands between
// the trainer's load and save. SaveModel must refuse (ErrSaveFenced), the
// pre-reset-derived weights must never be reinserted, and the drop must be
// logged.
func TestTrainer_ResetDuringTrainingFencesSave(t *testing.T) {
	store := newFakeModelStore(t)
	store.msgs[1] = []byte("From: bulk@evil.example\r\nSubject: zorphblat\r\n\r\nzorphblat body")
	store.rowExists = true
	store.rowBytes = []byte("PERSISTED-PRE-RESET-WEIGHTS")

	trainer := newFakeTrainer(t, store)
	trainer.collector.add(trainEvent{UserID: 7, MessageID: 1, IsSpam: true})
	store.afterLoad = func(s *fakeModelStore) {
		// Admin ResetModel's destructive wipe lands mid-batch.
		s.rowExists = false
		s.rowBytes = nil
	}
	trainer.flushAndTrain(context.Background())

	if store.saveCalls != 1 {
		t.Fatalf("SaveModel calls = %d, want 1 (save attempted then fenced)", store.saveCalls)
	}
	if store.savedBytes != nil {
		t.Fatalf("fenced save must not persist: row state %+v", store)
	}
	if !strings.Contains(store.logs.String(), "batch dropped (fenced)") {
		t.Fatalf("fence drop not logged; logs:\n%s", store.logs.String())
	}
}

// TestTrainer_DisableDuringTrainingFencesSave is the deterministic race
// coverage for the disable half: DisableModel lands between load and save.
// The newly disabled model must stay untouched.
func TestTrainer_DisableDuringTrainingFencesSave(t *testing.T) {
	store := newFakeModelStore(t)
	store.msgs[1] = []byte("From: bulk@evil.example\r\nSubject: zorphblat\r\n\r\nzorphblat body")
	store.rowExists = true
	store.rowBytes = []byte("PERSISTED-WEIGHTS")

	trainer := newFakeTrainer(t, store)
	trainer.collector.add(trainEvent{UserID: 7, MessageID: 1, IsSpam: true})
	store.afterLoad = func(s *fakeModelStore) {
		// Admin DisableModel lands mid-batch.
		s.rowDisabled = true
	}
	trainer.flushAndTrain(context.Background())

	if store.savedBytes != nil || !bytes.Equal(store.rowBytes, []byte("PERSISTED-WEIGHTS")) {
		t.Fatalf("newly disabled model was overwritten: %q", store.rowBytes)
	}
	if !strings.Contains(store.logs.String(), "batch dropped (fenced)") {
		t.Fatalf("fence drop not logged; logs:\n%s", store.logs.String())
	}
}

// TestTrainer_LoadFaultRefusesOverwrite pins the fault branch: a load fault or
// corrupt blob (surfaced as a load error) must stop the whole user pipeline —
// no fetch, no train, no save — and be logged, never silently collapsing into
// a fresh-model overwrite.
func TestTrainer_LoadFaultRefusesOverwrite(t *testing.T) {
	store := newFakeModelStore(t)
	store.msgs[1] = []byte("raw")
	store.loadErr = errors.New("corrupt spam model for user 7: invalid")
	store.rowExists = true
	store.rowBytes = []byte("PERSISTED-WEIGHTS")

	trainer := newFakeTrainer(t, store)
	trainer.collector.add(trainEvent{UserID: 7, MessageID: 1, IsSpam: true})
	trainer.flushAndTrain(context.Background())

	if store.fetchCalls != 0 || store.saveCalls != 0 {
		t.Fatalf("faulted load must refuse the pipeline: fetch=%d save=%d", store.fetchCalls, store.saveCalls)
	}
	if !bytes.Equal(store.rowBytes, []byte("PERSISTED-WEIGHTS")) {
		t.Fatalf("persisted blob was not preserved: %q", store.rowBytes)
	}
	if !strings.Contains(store.logs.String(), "load model failed") {
		t.Fatalf("load fault not logged; logs:\n%s", store.logs.String())
	}
}

// TestTrainer_SaveFaultSurfaced pins the save-fault branch: a DB fault during
// persistence must surface (logged), keep the old blob, and not be retried
// inside the same window.
func TestTrainer_SaveFaultSurfaced(t *testing.T) {
	store := newFakeModelStore(t)
	store.msgs[1] = []byte("raw")
	store.rowExists = true
	store.rowBytes = []byte("OLD-BLOB")

	trainer := newFakeTrainer(t, store)
	trainer.collector.add(trainEvent{UserID: 7, MessageID: 1, IsSpam: true})
	store.saveErr = errors.New("db connection reset")
	trainer.flushAndTrain(context.Background())

	if !bytes.Equal(store.rowBytes, []byte("OLD-BLOB")) {
		t.Fatalf("persisted blob changed despite save fault: %q", store.rowBytes)
	}
	if !strings.Contains(store.logs.String(), "persist model failed") {
		t.Fatalf("save fault not logged; logs:\n%s", store.logs.String())
	}
}

// TestTrainer_DisabledUserSkippedFake pins the trainer-gating branch against a
// disabled model at the unit level: the disabled user is skipped (no fetch,
// no save, explicit skip log) instead of rebuilt.
func TestTrainer_DisabledUserSkippedFake(t *testing.T) {
	store := newFakeModelStore(t)
	store.msgs[1] = []byte("raw1")
	store.loadErr = ErrModelDisabled

	trainer := newFakeTrainer(t, store)
	trainer.collector.add(trainEvent{UserID: 7, MessageID: 1, IsSpam: true})
	trainer.flushAndTrain(context.Background())

	if store.fetchCalls != 0 || store.saveCalls != 0 {
		t.Fatalf("disabled user must be refused entirely: fetch=%d save=%d", store.fetchCalls, store.saveCalls)
	}
	if !strings.Contains(store.logs.String(), "model disabled, skipping user") {
		t.Fatalf("opt-out gating branch not taken; logs:\n%s", store.logs.String())
	}
}
