package migration

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
)

var (
	_ SourceSession = (*IMAPConnector)(nil)
	_ SourceSession = (*EWSConnector)(nil)
	_ SourceSession = (*M365Connector)(nil)
)

func TestIMAPSourceSessionRestoresDurableStateAndCapturesAcknowledgedItems(t *testing.T) {
	session := NewIMAPConnector(IMAPConfig{})
	if err := session.RestoreSourceState(SourceResumeState{
		LegacyUIDs: map[string]int{"Inbox": 2},
		Durable: []SourceCheckpointCandidate{{
			Scope: "Inbox", Kind: "imap_uid",
			Value: json.RawMessage(`{"uid":7,"uidValidity":99}`),
		}},
	}); err != nil {
		t.Fatal(err)
	}
	if got := session.resumeCursor["Inbox"]; got != 7 {
		t.Fatalf("restored uid = %d, want 7", got)
	}
	if got := session.checkpointUIDValidities["Inbox"]; got != 99 {
		t.Fatalf("restored uid validity = %d, want 99", got)
	}

	snapshot := imapBatchSnapshot("Inbox", 8, 99)
	if len(snapshot.Candidates) != 1 {
		t.Fatalf("candidate count = %d, want 1", len(snapshot.Candidates))
	}
	checkpoint, err := decodeIMAPCheckpoint(snapshot.Candidates[0].Value)
	if err != nil {
		t.Fatal(err)
	}
	if checkpoint.UID != 8 || checkpoint.UIDValidity != 99 {
		t.Fatalf("captured checkpoint = %+v", checkpoint)
	}
	if got := snapshot.LegacyPatch["cursor_uids"]; !reflect.DeepEqual(got, map[string]int{"Inbox": 8}) {
		t.Fatalf("legacy uids = %#v", got)
	}
}

func TestProviderSourceSessionsOwnCheckpointKinds(t *testing.T) {
	tests := []struct {
		name      string
		session   SourceSession
		kind      string
		value     string
		wantPatch map[string]any
		snapshot  SourceCheckpointSnapshot
	}{
		{
			name: "ews", session: &EWSConnector{}, kind: "ews_sync_state", value: "sync-2",
			wantPatch: map[string]any{"delta": map[string]string{"folder-id": "sync-2"}},
			snapshot:  ewsBatchSnapshot("folder-id", "sync-2"),
		},
		{
			name: "m365", session: &M365Connector{}, kind: "m365_delta_link", value: "https://graph.test/delta/2",
			wantPatch: map[string]any{"delta": map[string]string{"mail": "https://graph.test/delta/2"}},
			snapshot:  m365BatchSnapshot("mail", "https://graph.test/delta/2"),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			scope := "Inbox"
			if test.name == "m365" {
				scope = "mail"
			}
			if err := test.session.RestoreSourceState(SourceResumeState{Durable: []SourceCheckpointCandidate{{
				Scope: scope, Kind: test.kind, Value: jsonMarshal(test.value),
			}}}); err != nil {
				t.Fatal(err)
			}
			snapshot := test.snapshot
			if len(snapshot.Candidates) != 1 || snapshot.Candidates[0].Kind != test.kind {
				t.Fatalf("candidates = %#v", snapshot.Candidates)
			}
			if !reflect.DeepEqual(snapshot.LegacyPatch, test.wantPatch) {
				t.Fatalf("legacy patch = %#v, want %#v", snapshot.LegacyPatch, test.wantPatch)
			}
		})
	}
}

func TestSourceSessionRejectsAnotherProvidersCheckpoint(t *testing.T) {
	for name, session := range map[string]SourceSession{
		"imap": NewIMAPConnector(IMAPConfig{}),
		"ews":  &EWSConnector{},
		"m365": &M365Connector{},
	} {
		t.Run(name, func(t *testing.T) {
			err := session.RestoreSourceState(SourceResumeState{Durable: []SourceCheckpointCandidate{{
				Scope: "scope", Kind: "foreign_kind", Value: json.RawMessage(`"cursor"`),
			}}})
			if err == nil {
				t.Fatal("foreign checkpoint kind accepted")
			}
		})
	}
}

func TestSourceSessionInterfaceKeepsPersistenceOutsideAdapter(t *testing.T) {
	var session SourceSession = NewIMAPConnector(IMAPConfig{})
	if _, ok := any(session).(interface {
		CommitCheckpoint(context.Context, SourceCheckpointCandidate) error
	}); ok {
		t.Fatal("source session must not persist its own checkpoint")
	}
}

// These two characterization guards deliberately describe the R3 exit gate,
// not the current implementation. They must fail until iteration exposes a
// closed batch and the orchestrator drops whole-mailbox retention.
func TestSourceSessionIterationExposesOneClosedBatch(t *testing.T) {
	method, ok := reflect.TypeOf((*SourceSession)(nil)).Elem().MethodByName("IterateSource")
	if !ok {
		t.Fatal("SourceSession omitted iteration")
	}
	if method.Type.NumOut() != 1 {
		t.Fatalf("IterateSource returns %d values; want one closed batch stream", method.Type.NumOut())
	}
}

func TestConnectorPhaseDoesNotRetainWholeMailboxDedup(t *testing.T) {
	raw, err := os.ReadFile("orchestrator.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"seenObjects := make(map[string]bool)", "dedup := make(map[string]map[uint32]bool)"} {
		if strings.Contains(string(raw), forbidden) {
			t.Fatalf("connector phase still retains whole-mailbox state: %s", forbidden)
		}
	}
}

func testSourceBatch(index int) SourceBatch {
	return SourceBatch{
		Items: []SourceItem{{
			Type: ItemMail, Change: SourceUpsert,
			SourceObjectID: fmt.Sprintf("object-%d", index), SourceVersion: "v1",
		}},
		Candidate: m365BatchSnapshot("messages", fmt.Sprintf("cursor-%d", index)),
	}
}

func TestSourceBatchCrashMatrixKeepsOnlyAcknowledgedCandidate(t *testing.T) {
	tests := []struct {
		name         string
		handle       func(SourceBatch, *int, *int) error
		wantApplied  int
		wantCommit   int
		wantProgress int
	}{
		{name: "crash before apply", handle: func(SourceBatch, *int, *int) error {
			return errors.New("crash before apply")
		}},
		{name: "crash after apply before checkpoint", handle: func(_ SourceBatch, applied, _ *int) error {
			*applied++
			return errors.New("crash before checkpoint")
		}, wantApplied: 1},
		{name: "crash after checkpoint before progress", handle: func(_ SourceBatch, applied, committed *int) error {
			*applied++
			*committed++
			return errors.New("crash before progress")
		}, wantApplied: 1, wantCommit: 1},
		{name: "success", handle: func(_ SourceBatch, applied, committed *int) error {
			*applied++
			*committed++
			return nil
		}, wantApplied: 1, wantCommit: 1, wantProgress: 1},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var producerAcknowledged atomic.Int64
			stream := newSourceBatchStream(t.Context(), func(_ context.Context, emit sourceBatchEmitter) error {
				if err := emit(testSourceBatch(1)); err != nil {
					return err
				}
				producerAcknowledged.Add(1)
				return nil
			})
			applied, committed, progress := 0, 0, 0
			err := consumeSourceBatches(t.Context(), stream, func(_ context.Context, batch SourceBatch) error {
				err := test.handle(batch, &applied, &committed)
				if err == nil {
					progress++
				}
				return err
			})
			if test.name == "success" && err != nil {
				t.Fatal(err)
			}
			if test.name != "success" && err == nil {
				t.Fatal("injected crash returned nil")
			}
			if applied != test.wantApplied || committed != test.wantCommit || progress != test.wantProgress {
				t.Fatalf("applied/committed/progress = %d/%d/%d, want %d/%d/%d",
					applied, committed, progress, test.wantApplied, test.wantCommit, test.wantProgress)
			}
			wantAck := int64(0)
			if test.name == "success" {
				wantAck = 1
			}
			if got := producerAcknowledged.Load(); got != wantAck {
				t.Fatalf("producer acknowledgements = %d, want %d", got, wantAck)
			}
		})
	}
}

func TestSourceBatchCancellationStopsProducerAndJoins(t *testing.T) {
	producerDone := make(chan struct{})
	stream := newSourceBatchStream(t.Context(), func(_ context.Context, emit sourceBatchEmitter) error {
		defer close(producerDone)
		return emit(testSourceBatch(1))
	})
	ctx, cancel := context.WithCancel(t.Context())
	err := consumeSourceBatches(ctx, stream, func(context.Context, SourceBatch) error {
		cancel()
		return context.Canceled
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("consume error = %v, want cancellation", err)
	}
	select {
	case <-producerDone:
	default:
		t.Fatal("producer was not joined before cancellation returned")
	}
}

func TestSourceBatchBackpressureAllowsOneProviderReadInFlight(t *testing.T) {
	var reads atomic.Int64
	stream := newSourceBatchStream(t.Context(), func(_ context.Context, emit sourceBatchEmitter) error {
		for index := 1; index <= 3; index++ {
			reads.Add(1)
			if err := emit(testSourceBatch(index)); err != nil {
				return err
			}
		}
		return nil
	})
	handled := 0
	err := consumeSourceBatches(t.Context(), stream, func(context.Context, SourceBatch) error {
		handled++
		if got := reads.Load(); got != int64(handled) {
			return fmt.Errorf("provider read ahead to %d while handling batch %d", got, handled)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if handled != 3 {
		t.Fatalf("handled batches = %d, want 3", handled)
	}
}

func TestSourceBatchCancellationInterruptsBlockedProviderRead(t *testing.T) {
	readStarted := make(chan struct{})
	readStopped := make(chan struct{})
	stream := newSourceBatchStream(t.Context(), func(ctx context.Context, _ sourceBatchEmitter) error {
		close(readStarted)
		<-ctx.Done()
		close(readStopped)
		return ctx.Err()
	})
	ctx, cancel := context.WithCancel(t.Context())
	<-readStarted
	cancel()
	if err := consumeSourceBatches(ctx, stream, func(context.Context, SourceBatch) error { return nil }); !errors.Is(err, context.Canceled) {
		t.Fatalf("consume error = %v, want cancellation", err)
	}
	select {
	case <-readStopped:
	default:
		t.Fatal("blocked provider read was not interrupted and joined")
	}
}

func TestMillionObjectSourceStateRemainsWindowBounded(t *testing.T) {
	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)
	const totalObjects = 1_000_000
	maxInput, maxOutput := 0, 0
	for base := 0; base < totalObjects; base += sourceBatchSize {
		items := make([]SourceItem, sourceBatchSize)
		for index := range items {
			items[index] = SourceItem{Type: ItemMail, Change: SourceUpsert,
				SourceObjectID: fmt.Sprintf("object-%d", base+index), SourceVersion: "v1",
				SourceFolderID: "Inbox", SourceUID: uint32(index + 1)}
		}
		// Include one duplicate to prove both maps are discarded with this page.
		items[len(items)-1] = items[0]
		deduped := dedupeSourceBatch(items)
		if len(items) > maxInput {
			maxInput = len(items)
		}
		if len(deduped) > maxOutput {
			maxOutput = len(deduped)
		}
	}
	runtime.GC()
	var after runtime.MemStats
	runtime.ReadMemStats(&after)
	if maxInput > sourceBatchSize || maxOutput > sourceBatchSize {
		t.Fatalf("retained source window input/output = %d/%d, limit %d", maxInput, maxOutput, sourceBatchSize)
	}
	const retainedHeapBudget = 16 << 20
	if after.HeapAlloc > before.HeapAlloc+retainedHeapBudget {
		t.Fatalf("retained heap grew by %d bytes after one million objects; budget %d",
			after.HeapAlloc-before.HeapAlloc, retainedHeapBudget)
	}
}
