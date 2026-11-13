package migration

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"

	"setjoin.com/shared/testsupport"
)

type scriptedSourceSession struct {
	identity    SourceIdentity
	identityErr error
	restoreErr  error
	restored    SourceResumeState
	batches     []SourceBatch
}

func (s *scriptedSourceSession) TestConnection(context.Context) error { return nil }

func (s *scriptedSourceSession) FetchItems(context.Context, func(int, int)) (<-chan SourceItem, <-chan error) {
	items := make(chan SourceItem)
	errs := make(chan error)
	close(items)
	close(errs)
	return items, errs
}

func (s *scriptedSourceSession) FetchItemsCursor(context.Context, map[string]int) (<-chan SourceItem, <-chan error) {
	return s.FetchItems(context.Background(), nil)
}

func (s *scriptedSourceSession) ResolveSourceIdentity(context.Context) (SourceIdentity, error) {
	return s.identity, s.identityErr
}

func (s *scriptedSourceSession) RestoreSourceState(state SourceResumeState) error {
	s.restored = state
	return s.restoreErr
}

func (s *scriptedSourceSession) IterateSource(ctx context.Context) *SourceBatchStream {
	return newSourceBatchStream(ctx, func(_ context.Context, emit sourceBatchEmitter) error {
		for _, batch := range s.batches {
			if err := emit(batch); err != nil {
				return err
			}
		}
		return nil
	})
}

func TestOrchestratorSourceSessionCommitsOnlyClosedProviderPage(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	testsupport.SetFeatureToggleForTest(t, pool, "feature.mail_migration_source_identity", true)
	userID, _, mailboxID := adminStartFixture(t, pool)
	ctx := t.Context()
	var jobID int64
	if err := pool.QueryRow(ctx, `
		INSERT INTO migration_jobs(user_id,source_type,source_config_enc,target_mailbox_id,status,resume_cursor)
		VALUES($1,'ews',$2,$3,'pending',$4) RETURNING id`,
		userID, []byte("encrypted-fixture"), mailboxID,
		`{"uids":{"Inbox":2},"delta":{"folder-old":"state-old"}}`,
	).Scan(&jobID); err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	dispatch := &terminalDispatchSpy{}
	orchestrator := NewOrchestrator(pool, nil, "", "coverage-root", logger, ctx, dispatch)
	status, err := orchestrator.orchestrate(ctx, jobID, "start", nil)
	if err != nil || status != "fetching" {
		t.Fatalf("start status=%q err=%v", status, err)
	}
	job, err := orchestrator.loadJob(ctx, jobID)
	if err != nil || job.ID != jobID || job.UserID != userID {
		t.Fatalf("job=%+v err=%v", job, err)
	}
	resume := orchestrator.loadLegacySourceResume(ctx, jobID)
	if resume.LegacyUIDs["Inbox"] != 2 || resume.LegacyDelta["folder-old"] != "state-old" {
		t.Fatalf("resume=%+v", resume)
	}

	identity := SourceIdentity{
		SourceType: "ews", MailboxKey: "ews:coverage-mailbox",
		SelectorDigest: strings.Repeat("a", 64), SourceGeneration: 1,
	}
	session := &scriptedSourceSession{identity: identity, batches: []SourceBatch{{
		Candidate: SourceCheckpointSnapshot{Candidates: []SourceCheckpointCandidate{{
			Scope: "folder-id", LegacyScope: "Projects", Kind: "ews_sync_state", Value: jsonMarshal("state-2"),
		}}},
	}}}
	js := &jobState{pauseCh: make(chan struct{}, 1), pauseAck: make(chan struct{}, 1), resumeCh: make(chan struct{}, 1)}
	if err := orchestrator.runConnectorPhase(ctx, jobID, session, resume, js); err != nil {
		t.Fatal(err)
	}
	if len(session.restored.Durable) != 0 || session.restored.LegacyUIDs["Inbox"] != 2 {
		t.Fatalf("restored=%+v", session.restored)
	}
	checkpoints := orchestrator.loadSourceCheckpoints(ctx, jobID, 1)
	if len(checkpoints) != 1 || checkpoints[0].Scope != "folder-id" || checkpoints[0].Kind != "ews_sync_state" {
		t.Fatalf("checkpoints=%+v", checkpoints)
	}
	projected := orchestrator.loadLegacySourceResume(ctx, jobID)
	if projected.LegacyDelta["Projects"] != "state-2" {
		t.Fatalf("projected resume=%+v", projected)
	}

	if err := orchestrator.runThreadReconcile(ctx, jobID); err != nil {
		t.Fatal(err)
	}
	for _, snapshot := range []SourceCheckpointSnapshot{
		{},
		{Candidates: []SourceCheckpointCandidate{{Scope: "", LegacyScope: "Projects", Kind: "ews_sync_state", Value: jsonMarshal("bad")}}},
	} {
		if err := orchestrator.commitCheckpointSnapshot(ctx, jobID, snapshot, 1, 0, true); err == nil {
			t.Fatalf("invalid checkpoint accepted: %+v", snapshot)
		}
	}

	missingID := &scriptedSourceSession{identity: identity, batches: []SourceBatch{{
		Items: []SourceItem{{Type: ItemMail, Change: SourceUpsert}},
		Candidate: SourceCheckpointSnapshot{Candidates: []SourceCheckpointCandidate{{
			Scope: "folder-id", LegacyScope: "Projects", Kind: "ews_sync_state", Value: jsonMarshal("state-3"),
		}}},
	}}}
	if err := orchestrator.runConnectorPhase(ctx, jobID, missingID, projected, js); err == nil || !strings.Contains(err.Error(), "immutable source id") {
		t.Fatalf("missing-id error=%v", err)
	}
	applyDeletes := &scriptedSourceSession{identity: identity, batches: []SourceBatch{{
		Items: []SourceItem{
			{Type: ItemMail, Change: SourceDelete, SourceObjectID: "mail-gone", SourceVersion: "v1", SourceFolderID: "inbox"},
			{Type: ItemCalendar, Change: SourceDelete, SourceObjectID: "event-gone", SourceVersion: "v1", SourceFolderID: "calendar"},
			{Type: ItemContact, Change: SourceDelete, SourceObjectID: "contact-gone", SourceVersion: "v1", SourceFolderID: "contacts"},
		},
		Candidate: SourceCheckpointSnapshot{Candidates: []SourceCheckpointCandidate{{
			Scope: "folder-ops", LegacyScope: "folder-ops", Kind: "ews_sync_state", Value: jsonMarshal("state-ops"),
		}}},
	}}}
	if err := orchestrator.runConnectorPhase(ctx, jobID, applyDeletes, projected, js); err != nil {
		t.Fatal(err)
	}
	pauseJS := &jobState{pauseCh: make(chan struct{}, 1), pauseAck: make(chan struct{}, 1), resumeCh: make(chan struct{}, 1)}
	pauseJS.pauseCh <- struct{}{}
	pauseJS.resumeCh <- struct{}{}
	if err := orchestrator.runConnectorPhase(ctx, jobID, applyDeletes, projected, pauseJS); err != nil {
		t.Fatal(err)
	}
	if len(pauseJS.pauseAck) != 1 {
		t.Fatal("pause/resume handshake did not acknowledge the held provider page")
	}
	shouldPause := &jobState{
		pauseCh: make(chan struct{}, 1), pauseAck: make(chan struct{}, 1),
		resumeCh: make(chan struct{}, 1), shouldPause: true,
	}
	if err := orchestrator.runConnectorPhase(ctx, jobID, applyDeletes, projected, shouldPause); !errors.Is(err, context.Canceled) {
		t.Fatalf("graceful pause error=%v", err)
	}
	if status, err := orchestrator.orchestrate(ctx, jobID, "resume", nil); err != nil || status != "fetching" {
		t.Fatalf("resume after graceful pause status=%q err=%v", status, err)
	}
	waitCtx, waitCancel := context.WithCancel(ctx)
	waitJS := &jobState{pauseCh: make(chan struct{}, 1), pauseAck: make(chan struct{}, 1), resumeCh: make(chan struct{})}
	waitJS.pauseCh <- struct{}{}
	waitDone := make(chan error, 1)
	go func() { waitDone <- orchestrator.runConnectorPhase(waitCtx, jobID, applyDeletes, projected, waitJS) }()
	<-waitJS.pauseAck
	waitCancel()
	if err := <-waitDone; !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel while paused error=%v", err)
	}
	restoreFailure := &scriptedSourceSession{identity: identity, restoreErr: errors.New("checkpoint rejected")}
	if err := orchestrator.runConnectorPhase(ctx, jobID, restoreFailure, projected, js); err == nil || !strings.Contains(err.Error(), "checkpoint rejected") {
		t.Fatalf("restore error=%v", err)
	}

	if err := orchestrator.runConnectorPhase(ctx, jobID+9_000_000, session, resume, js); err == nil {
		t.Fatal("missing target mailbox accepted")
	}
	identityFailure := &scriptedSourceSession{identityErr: errors.New("selector unavailable")}
	if err := orchestrator.runConnectorPhase(ctx, jobID, identityFailure, resume, js); err == nil || !strings.Contains(err.Error(), "resolve source mailbox") {
		t.Fatalf("identity error=%v", err)
	}
	if _, err := pool.Exec(ctx, `UPDATE feature_toggles SET enabled=false WHERE key='feature.mail_migration_source_identity'`); err != nil {
		t.Fatal(err)
	}
	if err := orchestrator.commitCheckpointSnapshot(ctx, jobID, SourceCheckpointSnapshot{
		LegacyPatch: map[string]any{"delta": map[string]string{"legacy": "state-legacy"}},
	}, 1, 0, false); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE migration_jobs SET resume_cursor='{"Inbox":9}' WHERE id=$1`, jobID); err != nil {
		t.Fatal(err)
	}
	if flat := orchestrator.loadLegacySourceResume(ctx, jobID); flat.LegacyUIDs["Inbox"] != 9 {
		t.Fatalf("flat resume=%+v", flat)
	}

	status, err = orchestrator.orchestrate(ctx, jobID, "fail", map[string]any{"errors": []string{"coverage failure"}})
	if err != nil || status != "failed" {
		t.Fatalf("fail status=%q err=%v", status, err)
	}
}

func TestOrchestratorLifecycleControlsAreIdempotentAndBounded(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	orchestrator := NewOrchestrator(nil, nil, "", "coverage-root", logger, t.Context(), nil)
	var cancelled int
	state := &jobState{
		cancel: func() { cancelled++ }, pauseCh: make(chan struct{}, 1),
		pauseAck: make(chan struct{}, 1), resumeCh: make(chan struct{}, 1),
	}
	orchestrator.activeJobs[7] = state
	if !orchestrator.IsRunning(7) || orchestrator.IsRunning(8) {
		t.Fatal("active job inventory is inconsistent")
	}
	if err := orchestrator.PauseJob(7); err != nil {
		t.Fatal(err)
	}
	if err := orchestrator.PauseJob(7); err != nil {
		t.Fatal(err)
	}
	if len(state.pauseCh) != 1 {
		t.Fatalf("pause signals=%d, want one coalesced signal", len(state.pauseCh))
	}
	if err := orchestrator.ResumeJob(7); err != nil {
		t.Fatal(err)
	}
	if err := orchestrator.ResumeJob(7); err != nil {
		t.Fatal(err)
	}
	if len(state.resumeCh) != 1 {
		t.Fatalf("resume signals=%d, want one coalesced signal", len(state.resumeCh))
	}
	if err := orchestrator.CancelJob(7); err != nil || cancelled != 1 {
		t.Fatalf("cancelled=%d err=%v", cancelled, err)
	}
	if err := orchestrator.CancelJob(8); err == nil {
		t.Fatal("missing cancel accepted")
	}
	if err := orchestrator.PauseJob(8); err == nil {
		t.Fatal("missing pause accepted")
	}
	<-state.pauseCh
	orchestrator.Shutdown()
	if !orchestrator.stopping || len(state.pauseCh) != 1 {
		t.Fatalf("shutdown stopping=%v pause=%d", orchestrator.stopping, len(state.pauseCh))
	}
}
