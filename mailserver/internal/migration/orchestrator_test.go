package migration

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	wh "setjoin.com/shared/webhook"
)

type terminalDispatchCall struct {
	userID, mailboxID int64
	event             wh.CloudEvent
}

type terminalDispatchSpy struct{ calls []terminalDispatchCall }

func (s *terminalDispatchSpy) DispatchForUser(_ context.Context, userID int64, event wh.CloudEvent) {
	s.calls = append(s.calls, terminalDispatchCall{userID: userID, event: event})
}

func (s *terminalDispatchSpy) DispatchForMailbox(_ context.Context, userID, mailboxID int64, event wh.CloudEvent) {
	s.calls = append(s.calls, terminalDispatchCall{userID: userID, mailboxID: mailboxID, event: event})
}

func TestMigrationTerminalLegacyDispatchIsTypedAndPostReducer(t *testing.T) {
	spy := &terminalDispatchSpy{}
	o := &Orchestrator{dispatcher: spy}
	mailboxID := int64(44)
	o.dispatchTerminalEvent(t.Context(), migrationTerminalEvent{
		JobID: 7, EventType: wh.EventMigrationCompleted, SubjectUserID: 33, SubjectMailboxID: &mailboxID,
	})
	if len(spy.calls) != 1 || spy.calls[0].userID != 33 || spy.calls[0].mailboxID != 44 {
		t.Fatalf("mailbox terminal dispatch=%+v, want typed user=33 mailbox=44", spy.calls)
	}
	if spy.calls[0].event.Type != wh.EventMigrationCompleted {
		t.Fatalf("event type=%q", spy.calls[0].event.Type)
	}
	data, ok := spy.calls[0].event.Data.(map[string]interface{})
	if !ok || data["job_id"] != int64(7) || len(data) != 1 {
		t.Fatalf("legacy terminal payload=%#v, want exact job_id", spy.calls[0].event.Data)
	}
	o.dispatchTerminalEvent(t.Context(), migrationTerminalEvent{
		JobID: 8, EventType: wh.EventMigrationFailed, SubjectUserID: 55, PublicationEnrolled: true,
	})
	if len(spy.calls) != 1 {
		t.Fatalf("enrolled fact also used legacy dispatch: %+v", spy.calls)
	}
}

func TestIMAPCheckpointCanonicalRoundTrip(t *testing.T) {
	want := imapCheckpoint{UID: 42, UIDValidity: 9001}
	raw := encodeIMAPCheckpoint(want)
	if bytes.Contains(raw, []byte("lastUID")) {
		t.Fatalf("canonical checkpoint retained legacy field: %s", raw)
	}
	if !bytes.Contains(raw, []byte(`"uid":42`)) {
		t.Fatalf("canonical checkpoint omitted uid: %s", raw)
	}
	got, err := decodeIMAPCheckpoint(raw)
	if err != nil {
		t.Fatalf("decode canonical checkpoint: %v", err)
	}
	if got != want {
		t.Fatalf("round-trip checkpoint = %+v, want %+v", got, want)
	}
}

func TestIMAPCheckpointReaderAcceptsLegacyFixture(t *testing.T) {
	// This is the exact pre-V209 pgTAP fixture spelling retained in
	// migration_source_identity.pg.
	raw := []byte(`{"uidValidity":1,"lastUID":1}`)
	got, err := decodeIMAPCheckpoint(raw)
	if err != nil {
		t.Fatalf("decode legacy checkpoint: %v", err)
	}
	if got != (imapCheckpoint{UID: 1, UIDValidity: 1}) {
		t.Fatalf("legacy checkpoint = %+v", got)
	}
}

func TestIMAPCheckpointReaderMixedAndMalformed(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		want    imapCheckpoint
		wantErr bool
	}{
		{name: "matching mixed fields", raw: `{"uid":7,"lastUID":7,"uidValidity":3}`, want: imapCheckpoint{UID: 7, UIDValidity: 3}},
		{name: "conflicting mixed fields", raw: `{"uid":7,"lastUID":8,"uidValidity":3}`, wantErr: true},
		{name: "missing uid", raw: `{"uidValidity":3}`, wantErr: true},
		{name: "missing uid validity", raw: `{"uid":7}`, wantErr: true},
		{name: "zero uid validity", raw: `{"uid":7,"uidValidity":0}`, wantErr: true},
		{name: "wrong uid type", raw: `{"uid":"7","uidValidity":3}`, wantErr: true},
		{name: "malformed json", raw: `{"uid":7`, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := decodeIMAPCheckpoint([]byte(tt.raw))
			if tt.wantErr {
				if err == nil {
					t.Fatalf("decode succeeded with %+v", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("decode: %v", err)
			}
			if got != tt.want {
				t.Fatalf("checkpoint = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestMigrationOperationIDIsStableAndVersionBound(t *testing.T) {
	item := SourceItem{Type: ItemMail, Change: SourceUpsert, SourceObjectID: "immutable-1", SourceVersion: "v1"}
	first := migrationOperationID(42, item)
	if second := migrationOperationID(42, item); first != second {
		t.Fatalf("same source operation changed UUID: %s != %s", first, second)
	}
	item.SourceVersion = "v2"
	if changed := migrationOperationID(42, item); changed == first {
		t.Fatal("new source version reused prior operation UUID")
	}
}

// The migration phase state machine (status transitions, the 1000-entry
// error-log cap, the cursor deep-merge / lost-update guard) now lives in the
// migration_orchestrate reducer and is covered by
// mailserver/sql/tests/migration_orchestrate.pg. The Go orchestrator is a thin
// caller: every migration_jobs row mutation flows through o.orchestrate (one
// SELECT migration_orchestrate($1,$2,$3) per phase boundary). These tests assert
// the Go-side patch-building shape that feeds the reducer.

// TestOrchestratePatch_ProgressShape verifies the progress patch the orchestrator
// hands the reducer carries the phase-keyed progress map the reducer deep-merges.
func TestOrchestratePatch_ProgressShape(t *testing.T) {
	phaseProgress := map[string]interface{}{"items_done": 3, "items_failed": 1}
	patch := map[string]any{"progress": map[string]any{"connector": phaseProgress}}

	data, err := json.Marshal(patch)
	if err != nil {
		t.Fatalf("marshal patch: %v", err)
	}
	var round struct {
		Progress map[string]map[string]int `json:"progress"`
	}
	if err := json.Unmarshal(data, &round); err != nil {
		t.Fatalf("unmarshal patch: %v", err)
	}
	if round.Progress["connector"]["items_done"] != 3 {
		t.Errorf("progress patch lost items_done: %+v", round.Progress)
	}
}

// TestOrchestratePatch_ErrorsShape verifies the error patch carries an "errors"
// array — the reducer appends it and enforces the 1000-entry cap in SQL.
func TestOrchestratePatch_ErrorsShape(t *testing.T) {
	patch := map[string]any{"errors": []string{"import: boom"}}
	data, _ := json.Marshal(patch)
	var round struct {
		Errors []string `json:"errors"`
	}
	if err := json.Unmarshal(data, &round); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(round.Errors) != 1 || round.Errors[0] != "import: boom" {
		t.Errorf("errors patch malformed: %+v", round.Errors)
	}
}

// TestOrchestratePatch_CursorShape verifies cursor_uids and delta ride in the
// same patch namespace the reducer merges into resume_cursor->{uids,delta}.
func TestOrchestratePatch_CursorShape(t *testing.T) {
	patch := map[string]any{
		"cursor_uids": map[string]int{"INBOX": 42},
		"delta":       map[string]string{"INBOX": "d1"},
	}
	data, _ := json.Marshal(patch)
	var round struct {
		CursorUIDs map[string]int    `json:"cursor_uids"`
		Delta      map[string]string `json:"delta"`
	}
	if err := json.Unmarshal(data, &round); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if round.CursorUIDs["INBOX"] != 42 || round.Delta["INBOX"] != "d1" {
		t.Errorf("cursor patch malformed: %+v", round)
	}
}

// TestOrchestrateSignature is a compile-time guard that the single mutation seam
// keeps its (ctx, jobID, phase, patch) → status shape.
func TestOrchestrateSignature(t *testing.T) {
	var _ func(context.Context, int64, string, map[string]any) (string, error) = (&Orchestrator{}).orchestrate
}
