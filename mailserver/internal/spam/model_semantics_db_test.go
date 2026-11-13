// model_semantics_db_test.go — pins the three user_spam_model semantics that
// med-shard3-016 requires to stay separate:
//
//  1. Scoring opt-out: user_spam_model.disabled is actually consumed —
//     LoadModel refuses with ErrModelDisabled (the FTRL scoring caller in
//     internal/smtp/inbound.go skips model.Score on any LoadModel error), the
//     trained weights stay persisted, and re-enabling restores the same model.
//  2. Trainer gating: a disabled model is neither scored nor rebuilt — the
//     trainer skips the user without touching the disabled row, while an
//     enabled user in the same batch still trains (proves the skip is the
//     opt-out gating, not a dead trainer).
//  3. Model reset: an explicit reset (admin ResetModel's DELETE) is a
//     destructive wipe the trainer must not silently undo — post-reset
//     training rebuilds a FRESH model (sample_count restarts, poisoned
//     pre-reset weights are gone, bit-identical to a never-trained reference).
//
// Needs DB_DSN (testsupport.OpenTestPool skips locally / fails in CI per the
// fail-closed policy — see shared/testsupport/pool.go).
package spam

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"setjoin.com/shared/pgxutil"
	"setjoin.com/shared/testsupport"
)

// insertSpamModelRow persists a trained model row for userID, mirroring what
// SaveModel's INSERT branch leaves behind. sampleCount pins the counter.
func insertSpamModelRow(t *testing.T, pool *pgxpool.Pool, userID int64, modelBytes []byte, sampleCount int, disabled bool) {
	t.Helper()
	ctx := context.Background()
	if _, err := pool.Exec(ctx,
		`INSERT INTO user_spam_model (user_id, model_bytes, sample_count, disabled)
		 VALUES ($1, $2, $3, $4)`,
		userID, modelBytes, sampleCount, disabled,
	); err != nil {
		t.Fatalf("insert user_spam_model row: %v", err)
	}
}

// insertSpamInlineMessage inserts a message whose raw_ref is the inline RFC
// 5322 text itself (the W5 inline convention — blob.IsInlineMessage matches on
// the newline), so FetchMessage returns the bytes with no object store.
// Cleanup is registered AFTER the user fixture cleanup so LIFO deletes the
// message before the mailbox it references.
func insertSpamInlineMessage(t *testing.T, pool *pgxpool.Pool, mailboxID int64, msgIDKey, raw string) (messageID int64) {
	t.Helper()
	ctx := context.Background()
	if err := pool.QueryRow(ctx,
		`INSERT INTO messages
		   (mailbox_id, folder_id, message_id, subject, from_addr, to_addrs,
		    cc_addrs, bcc_addrs, thread_id, raw_ref, received_at)
		 VALUES
		   ($1, 1, $2, $3, $4, '[]'::jsonb, '[]'::jsonb, '[]'::jsonb, $5, $6, now())
		 RETURNING id`,
		mailboxID, msgIDKey+"@spam-semantics.example.com", msgIDKey,
		"sender@spam-semantics.example.com", "thread-"+msgIDKey, raw,
	).Scan(&messageID); err != nil {
		t.Fatalf("insert test message: %v", err)
	}
	t.Cleanup(func() {
		pool.Exec(context.Background(), `DELETE FROM messages WHERE id = $1`, messageID) //nolint:errcheck
	})
	return messageID
}

// spamModelRowState snapshots the columns the trainer must not touch on a
// disabled row.
type spamModelRowState struct {
	modelBytes  []byte
	sampleCount int
	trainedAt   time.Time
}

func spamModelRowSnapshot(t *testing.T, pool *pgxpool.Pool, userID int64) spamModelRowState {
	t.Helper()
	var s spamModelRowState
	if err := pool.QueryRow(context.Background(),
		`SELECT model_bytes, sample_count, trained_at FROM user_spam_model WHERE user_id = $1`, userID,
	).Scan(&s.modelBytes, &s.sampleCount, &s.trainedAt); err != nil {
		t.Fatalf("snapshot user_spam_model row: %v", err)
	}
	return s
}

// TestLoadModel_DisabledScoringOptOut pins scoring opt-out: the disabled flag
// is consumed by LoadModel (refusal with ErrModelDisabled — the contract the
// scoring caller's error branch turns into "no FTRL scoring"), while the
// trained weights are retained (opt-out is not a reset) and re-enabling
// restores the exact same model.
func TestLoadModel_DisabledScoringOptOut(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()

	userID, _ := insertSpamTestUserWithMailbox(t, pool, "smoptx")

	spamRaw := []byte("From: spammer@evil.example.com\r\nSubject: WINNER zorphblatquix prize\r\n\r\nhttp://evil.example.com/prize you won a million")
	m := newUserModel(userID)
	for i := 0; i < 10; i++ {
		m.Train(spamRaw, true)
	}
	data, err := m.Save()
	if err != nil {
		t.Fatalf("Save: %v", err)
	}
	insertSpamModelRow(t, pool, userID, sealModelBlob(userID, data), 10, false)

	store := NewPGModelStore(pgxutil.WorkerPool{Pool: pool}, nil, "unused-bucket")

	// Control: enabled row loads and scores.
	loaded, err := store.LoadModel(ctx, userID)
	if err != nil || loaded == nil {
		t.Fatalf("enabled LoadModel: err=%v, model=%v", err, loaded)
	}
	if loaded.Score(spamRaw) != m.Score(spamRaw) {
		t.Fatalf("enabled model diverges from trained reference: %.6f vs %.6f",
			loaded.Score(spamRaw), m.Score(spamRaw))
	}

	// Disable (admin DisableModel UPDATE path).
	if _, err := pool.Exec(ctx, `UPDATE user_spam_model SET disabled = TRUE WHERE user_id = $1`, userID); err != nil {
		t.Fatalf("disable exec: %v", err)
	}

	disabledModel, err := store.LoadModel(ctx, userID)
	if !errors.Is(err, ErrModelDisabled) {
		t.Fatalf("disabled LoadModel err = %v, want ErrModelDisabled", err)
	}
	if disabledModel != nil {
		t.Fatalf("disabled LoadModel must not return a usable model, got non-nil")
	}

	// Opt-out is not a reset: weights stay persisted.
	if _, err := pool.Exec(ctx, `UPDATE user_spam_model SET disabled = FALSE WHERE user_id = $1`, userID); err != nil {
		t.Fatalf("enable exec: %v", err)
	}
	reenabled, err := store.LoadModel(ctx, userID)
	if err != nil {
		t.Fatalf("re-enabled LoadModel: %v", err)
	}
	if reenabled.Score(spamRaw) != m.Score(spamRaw) {
		t.Fatalf("weights did not survive the opt-out cycle: %.6f vs trained %.6f",
			reenabled.Score(spamRaw), m.Score(spamRaw))
	}
}

// TestTrainer_DisabledModelNotRebuilt pins trainer gating: a disabled model is
// neither scored nor rebuilt. The trainer must skip the disabled user without
// touching the row (no weight overwrite, no counter bump, no trained_at bump)
// while an enabled user in the SAME batch trains — proving the untouched row
// is the opt-out gating and not a dead trainer.
func TestTrainer_DisabledModelNotRebuilt(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()

	disabledUserID, disabledMailboxID := insertSpamTestUserWithMailbox(t, pool, "smgate")
	enabledUserID, enabledMailboxID := insertSpamTestUserWithMailbox(t, pool, "smgok")

	// Exactly what admin DisableModel writes for a never-trained user.
	insertSpamModelRow(t, pool, disabledUserID, []byte{}, 0, true)
	before := spamModelRowSnapshot(t, pool, disabledUserID)

	disabledMsgID := insertSpamInlineMessage(t, pool, disabledMailboxID, "smgate-msg",
		"From: bulk@evil.example.com\r\nSubject: zorphblatquix offer\r\n\r\nzorphblatquix click here now")
	enabledMsgID := insertSpamInlineMessage(t, pool, enabledMailboxID, "smgok-msg",
		"From: bulk@evil.example.com\r\nSubject: zorphblatquix offer\r\n\r\nzorphblatquix click here now")

	logBuf := &bytes.Buffer{}
	trainer := NewTrainer(NewPGModelStore(pgxutil.WorkerPool{Pool: pool}, nil, "unused-bucket"),
		slog.New(slog.NewTextHandler(logBuf, nil)))
	trainer.collector.add(trainEvent{UserID: disabledUserID, MessageID: disabledMsgID, IsSpam: true})
	trainer.collector.add(trainEvent{UserID: enabledUserID, MessageID: enabledMsgID, IsSpam: true})
	trainer.flushAndTrain(ctx)

	// Disabled user: row byte-identical — neither rebuilt nor counter-bumped.
	after := spamModelRowSnapshot(t, pool, disabledUserID)
	if !bytes.Equal(after.modelBytes, before.modelBytes) {
		t.Fatalf("disabled model was rebuilt: model_bytes changed (got %d bytes, want %d)",
			len(after.modelBytes), len(before.modelBytes))
	}
	if after.sampleCount != before.sampleCount {
		t.Fatalf("disabled sample_count = %d, want unchanged %d", after.sampleCount, before.sampleCount)
	}
	if !after.trainedAt.Equal(before.trainedAt) {
		t.Fatalf("disabled trained_at moved (%v -> %v): disabled row was upserted", before.trainedAt, after.trainedAt)
	}
	if !strings.Contains(logBuf.String(), "model disabled, skipping user") {
		t.Fatalf("trainer did not take the opt-out gating branch; logs:\n%s", logBuf.String())
	}

	// Control: the enabled user in the same flush trained and persisted.
	enabled := spamModelRowSnapshot(t, pool, enabledUserID)
	if enabled.sampleCount != 1 {
		t.Fatalf("enabled control user sample_count = %d, want 1 (trainer must be live)", enabled.sampleCount)
	}
}

// TestTrainer_ResetNotSilentlyUndone pins reset semantics: admin ResetModel's
// DELETE is a destructive wipe, and subsequent training must not resurrect the
// wiped state. The post-reset rebuild is a FRESH model: sample_count restarts
// and the trained weights are bit-identical to a never-trained reference model
// trained once on the single post-reset event — no pre-reset residue.
func TestTrainer_ResetNotSilentlyUndone(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()

	userID, mailboxID := insertSpamTestUserWithMailbox(t, pool, "smreset")

	poisonRaw := []byte("From: bulk@evil.example.com\r\nSubject: zorphblatquix winner\r\n\r\nzorphblatquix click here to claim your prize")
	poisonMsgID := insertSpamInlineMessage(t, pool, mailboxID, "smreset-msg", string(poisonRaw))

	logBuf := &bytes.Buffer{}
	trainer := NewTrainer(NewPGModelStore(pgxutil.WorkerPool{Pool: pool}, nil, "unused-bucket"),
		slog.New(slog.NewTextHandler(logBuf, nil)))

	// Poison the persisted model through the real trainer path.
	for i := 0; i < 10; i++ {
		trainer.collector.add(trainEvent{UserID: userID, MessageID: poisonMsgID, IsSpam: true})
		trainer.flushAndTrain(ctx)
	}
	preReset, err := NewPGModelStore(pgxutil.WorkerPool{Pool: pool}, nil, "unused-bucket").LoadModel(ctx, userID)
	if err != nil {
		t.Fatalf("pre-reset LoadModel: %v", err)
	}
	if got := preReset.Score(poisonRaw); got <= 0.7 {
		t.Fatalf("pre-setup invalid: poisoned score = %.4f, want > 0.7", got)
	}
	if got := spamModelRowSnapshot(t, pool, userID).sampleCount; got != 10 {
		t.Fatalf("pre-setup invalid: sample_count = %d, want 10", got)
	}

	// Explicit reset — exactly admin ResetModel's destructive wipe.
	if _, err := pool.Exec(ctx, `DELETE FROM user_spam_model WHERE user_id = $1`, userID); err != nil {
		t.Fatalf("reset exec: %v", err)
	}

	// Post-reset: one fresh ham event trains the rebuilt model.
	hamRaw := []byte("From: colleague@setjoin.example.com\r\nSubject: zorphblatquix lunch plans\r\nMessage-Id: <ham@setjoin.example.com>\r\nDate: Mon, 1 Jun 2026\r\nContent-Type: text/plain\r\n\r\nzorphblatquix lunch at noon as usual, please confirm")
	hamMsgID := insertSpamInlineMessage(t, pool, mailboxID, "smreset-ham", string(hamRaw))
	trainer.collector.add(trainEvent{UserID: userID, MessageID: hamMsgID, IsSpam: false})
	trainer.flushAndTrain(ctx)

	// The wipe was not undone: sample_count restarted (no accumulation onto a
	// surviving row) and the rebuilt model carries none of the poisoned
	// weights — it is bit-identical to a fresh model trained once on the
	// post-reset event.
	rebuilt, err := NewPGModelStore(pgxutil.WorkerPool{Pool: pool}, nil, "unused-bucket").LoadModel(ctx, userID)
	if err != nil {
		t.Fatalf("post-reset LoadModel: %v", err)
	}
	if got := spamModelRowSnapshot(t, pool, userID).sampleCount; got != 1 {
		t.Fatalf("post-reset sample_count = %d, want 1 (reset must wipe counters; trainer must not accumulate over a wiped row)", got)
	}
	reference := newUserModel(userID)
	reference.Train(hamRaw, false) // the only post-reset signal
	if got, want := rebuilt.Score(poisonRaw), reference.Score(poisonRaw); got != want {
		t.Fatalf("post-reset model diverges from fresh reference: %.6f vs %.6f (wiped state leaked back)", got, want)
	}
	if got := rebuilt.Score(poisonRaw); got >= 0.7 {
		t.Fatalf("post-reset poisoned score = %.4f, want < 0.7 — reset was silently undone", got)
	}
	if !strings.Contains(logBuf.String(), "spam trainer: model updated") {
		t.Fatalf("post-reset rebuild was silent; logs:\n%s", logBuf.String())
	}
}

// spamModelRowExists reports whether a user_spam_model row exists for userID.
func spamModelRowExists(t *testing.T, pool *pgxpool.Pool, userID int64) bool {
	t.Helper()
	var exists bool
	if err := pool.QueryRow(context.Background(),
		`SELECT EXISTS(SELECT 1 FROM user_spam_model WHERE user_id = $1)`, userID,
	).Scan(&exists); err != nil {
		t.Fatalf("row existence probe: %v", err)
	}
	return exists
}

// trainedUserModel is a small trained model used as realistic save payload.
func trainedUserModel(t *testing.T, userID int64, raw []byte) []byte {
	t.Helper()
	m := newUserModel(userID)
	for i := 0; i < 5; i++ {
		m.Train(raw, true)
	}
	data, err := m.Save()
	if err != nil {
		t.Fatalf("Save: %v", err)
	}
	return data
}

const fenceMsgRaw = "From: bulk@evil.example.com\r\nSubject: zorphblatquix winner\r\n\r\nzorphblatquix click here to claim your prize"

// TestSaveModel_FencedAgainstResetReinsertion is the core persistence-fence
// race test: the trainer loads a row, admin ResetModel DELETEs it mid-batch,
// and the trainer's save must be REFUSED — the pre-reset-derived weights must
// not be reinserted through the INSERT arm.
func TestSaveModel_FencedAgainstResetReinsertion(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()

	userID, _ := insertSpamTestUserWithMailbox(t, pool, "smfnc1")
	insertSpamModelRow(t, pool, userID, sealModelBlob(userID, trainedUserModel(t, userID, []byte(fenceMsgRaw))), 5, false)

	store := NewPGModelStore(pgxutil.WorkerPool{Pool: pool}, nil, "unused-bucket")
	model, expect, err := store.LoadModelForTraining(ctx, userID)
	if err != nil || model == nil || expect == nil {
		t.Fatalf("warm LoadModelForTraining: model=%v expect=%v err=%v", model, expect, err)
	}

	// Admin ResetModel's destructive wipe lands mid-batch.
	if _, err := pool.Exec(ctx, `DELETE FROM user_spam_model WHERE user_id = $1`, userID); err != nil {
		t.Fatalf("reset exec: %v", err)
	}

	model.Train([]byte(fenceMsgRaw), true)
	data, err := model.Save()
	if err != nil {
		t.Fatalf("Save: %v", err)
	}
	if err := store.SaveModel(ctx, userID, data, expect); !errors.Is(err, ErrSaveFenced) {
		t.Fatalf("save after interleaved reset err = %v, want ErrSaveFenced", err)
	}
	if spamModelRowExists(t, pool, userID) {
		t.Fatal("fenced save reinserted a row after reset — pre-reset weights resurrected")
	}
}

// TestSaveModel_FencedAgainstDisableOverwrite pins the disable half of the
// fence: a save whose load raced with DisableModel must be refused and the
// newly disabled row must stay byte-identical.
func TestSaveModel_FencedAgainstDisableOverwrite(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()

	userID, _ := insertSpamTestUserWithMailbox(t, pool, "smfnc2")
	blob := sealModelBlob(userID, trainedUserModel(t, userID, []byte(fenceMsgRaw)))
	insertSpamModelRow(t, pool, userID, blob, 5, false)
	before := spamModelRowSnapshot(t, pool, userID)

	store := NewPGModelStore(pgxutil.WorkerPool{Pool: pool}, nil, "unused-bucket")
	model, expect, err := store.LoadModelForTraining(ctx, userID)
	if err != nil || expect == nil {
		t.Fatalf("warm LoadModelForTraining: err=%v", err)
	}

	// Admin DisableModel lands mid-batch.
	if _, err := pool.Exec(ctx, `UPDATE user_spam_model SET disabled = TRUE WHERE user_id = $1`, userID); err != nil {
		t.Fatalf("disable exec: %v", err)
	}

	model.Train([]byte(fenceMsgRaw), true)
	data, err := model.Save()
	if err != nil {
		t.Fatalf("Save: %v", err)
	}
	if err := store.SaveModel(ctx, userID, data, expect); !errors.Is(err, ErrSaveFenced) {
		t.Fatalf("save after interleaved disable err = %v, want ErrSaveFenced", err)
	}
	after := spamModelRowSnapshot(t, pool, userID)
	if !bytes.Equal(after.modelBytes, before.modelBytes) || after.sampleCount != before.sampleCount || !after.trainedAt.Equal(before.trainedAt) {
		t.Fatalf("newly disabled model was overwritten: %+v -> %+v", before, after)
	}
}

// TestSaveModel_FencedAgainstCompetingSave pins the competing-writer half: if
// the row's bytes changed after the trainer's load, the stale save is refused
// instead of clobbering newer weights.
func TestSaveModel_FencedAgainstCompetingSave(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()

	userID, _ := insertSpamTestUserWithMailbox(t, pool, "smfnc3")
	insertSpamModelRow(t, pool, userID, sealModelBlob(userID, trainedUserModel(t, userID, []byte(fenceMsgRaw))), 5, false)

	store := NewPGModelStore(pgxutil.WorkerPool{Pool: pool}, nil, "unused-bucket")
	model, expect, err := store.LoadModelForTraining(ctx, userID)
	if err != nil || expect == nil {
		t.Fatalf("warm LoadModelForTraining: err=%v", err)
	}

	// A competing save replaces the row mid-batch.
	fresher := sealModelBlob(userID, trainedUserModel(t, userID, []byte("From: other@x.example\r\nSubject: fresher\r\n\r\nfresher body")))
	if _, err := pool.Exec(ctx, `UPDATE user_spam_model SET model_bytes = $2, sample_count = sample_count + 1 WHERE user_id = $1`, userID, fresher); err != nil {
		t.Fatalf("competing save exec: %v", err)
	}

	model.Train([]byte(fenceMsgRaw), true)
	data, err := model.Save()
	if err != nil {
		t.Fatalf("Save: %v", err)
	}
	if err := store.SaveModel(ctx, userID, data, expect); !errors.Is(err, ErrSaveFenced) {
		t.Fatalf("stale save over competing write err = %v, want ErrSaveFenced", err)
	}
	if after := spamModelRowSnapshot(t, pool, userID); !bytes.Equal(after.modelBytes, fresher) {
		t.Fatal("competing writer's row was clobbered by the fenced save")
	}
}

// TestSaveModel_ColdStartFencedByDisablePlaceholder pins the cold-start arm:
// DisableModel of a never-trained user inserts a '\x' placeholder mid-batch;
// the trainer's cold save must not overtake the disabled row.
func TestSaveModel_ColdStartFencedByDisablePlaceholder(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()

	userID, _ := insertSpamTestUserWithMailbox(t, pool, "smfnc4")

	store := NewPGModelStore(pgxutil.WorkerPool{Pool: pool}, nil, "unused-bucket")
	model, expect, err := store.LoadModelForTraining(ctx, userID)
	if err != nil || model == nil || expect != nil {
		t.Fatalf("cold LoadModelForTraining: model=%v expect=%v err=%v", model, expect, err)
	}

	// Admin DisableModel inserts the placeholder mid-batch (never-trained user).
	if _, err := pool.Exec(ctx,
		`INSERT INTO user_spam_model (user_id, model_bytes, sample_count, disabled) VALUES ($1, '\x', 0, TRUE)`, userID,
	); err != nil {
		t.Fatalf("placeholder insert: %v", err)
	}

	model.Train([]byte(fenceMsgRaw), true)
	data, err := model.Save()
	if err != nil {
		t.Fatalf("Save: %v", err)
	}
	if err := store.SaveModel(ctx, userID, data, expect); !errors.Is(err, ErrSaveFenced) {
		t.Fatalf("cold save over disabled placeholder err = %v, want ErrSaveFenced", err)
	}
	after := spamModelRowSnapshot(t, pool, userID)
	if len(after.modelBytes) != 0 || after.sampleCount != 0 {
		t.Fatalf("disabled placeholder was overwritten: %d bytes, sample_count %d", len(after.modelBytes), after.sampleCount)
	}
}

// TestSaveModel_ColdStartOvertakesEmptyEnabledPlaceholderOnly pins the one
// legal cold-start overtake: an ENABLED, empty placeholder row (never-trained
// user re-enabled, first training event) is overtaken with sample_count
// restarting at 1; a row carrying real weights the trainer never saw is not.
func TestSaveModel_ColdStartOvertakesEmptyEnabledPlaceholderOnly(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()

	userID, _ := insertSpamTestUserWithMailbox(t, pool, "smfnc5")
	// Exactly what DisableModel leaves for a never-trained user, re-enabled.
	insertSpamModelRow(t, pool, userID, []byte{}, 0, false)

	store := NewPGModelStore(pgxutil.WorkerPool{Pool: pool}, nil, "unused-bucket")
	model, expect, err := store.LoadModelForTraining(ctx, userID)
	if err != nil || model == nil || expect != nil {
		t.Fatalf("cold-over-placeholder LoadModelForTraining: model=%v expect=%v err=%v", model, expect, err)
	}
	model.Train([]byte(fenceMsgRaw), true)
	data, err := model.Save()
	if err != nil {
		t.Fatalf("Save: %v", err)
	}
	if err := store.SaveModel(ctx, userID, data, expect); err != nil {
		t.Fatalf("cold save over enabled placeholder: %v", err)
	}
	after := spamModelRowSnapshot(t, pool, userID)
	if len(after.modelBytes) == 0 || after.sampleCount != 1 {
		t.Fatalf("cold overtake wrong: %d bytes, sample_count %d, want data + sample_count 1", len(after.modelBytes), after.sampleCount)
	}

	// Control: the same cold save against a row with REAL weights is fenced.
	userID2, _ := insertSpamTestUserWithMailbox(t, pool, "smfnc6")
	insertSpamModelRow(t, pool, userID2, sealModelBlob(userID2, trainedUserModel(t, userID2, []byte(fenceMsgRaw))), 3, false)
	freshModel := newUserModel(userID2)
	freshModel.Train([]byte(fenceMsgRaw), true)
	freshData, err := freshModel.Save()
	if err != nil {
		t.Fatalf("Save: %v", err)
	}
	if err := store.SaveModel(ctx, userID2, freshData, nil); !errors.Is(err, ErrSaveFenced) {
		t.Fatalf("cold save over unseen real weights err = %v, want ErrSaveFenced", err)
	}
}

// TestTrainer_CorruptBlobRefusedAndPreserved pins the corrupt-blob half of the
// preservation requirement: a row whose bytes are not a valid sealed model
// must surface as a load error, make the trainer refuse the batch, and the
// corrupt bytes must be preserved — never silently replaced by a fresh model.
func TestTrainer_CorruptBlobRefusedAndPreserved(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()

	userID, mailboxID := insertSpamTestUserWithMailbox(t, pool, "smfnc7")
	corrupt := []byte("definitely not a model blob")
	insertSpamModelRow(t, pool, userID, corrupt, 4, false)
	before := spamModelRowSnapshot(t, pool, userID)

	msgID := insertSpamInlineMessage(t, pool, mailboxID, "smfnc7-msg", fenceMsgRaw)

	logBuf := &bytes.Buffer{}
	trainer := NewTrainer(NewPGModelStore(pgxutil.WorkerPool{Pool: pool}, nil, "unused-bucket"),
		slog.New(slog.NewTextHandler(logBuf, nil)))
	trainer.collector.add(trainEvent{UserID: userID, MessageID: msgID, IsSpam: true})
	trainer.flushAndTrain(ctx)

	if _, err := NewPGModelStore(pgxutil.WorkerPool{Pool: pool}, nil, "unused-bucket").LoadModel(ctx, userID); err == nil {
		t.Fatal("corrupt blob loads without error — corrupt state was silently replaced by a fresh model")
	}
	after := spamModelRowSnapshot(t, pool, userID)
	if !bytes.Equal(after.modelBytes, before.modelBytes) || after.sampleCount != before.sampleCount || !after.trainedAt.Equal(before.trainedAt) {
		t.Fatalf("corrupt blob was overwritten instead of preserved: %+v -> %+v", before, after)
	}
	if !strings.Contains(logBuf.String(), "load model failed") {
		t.Fatalf("corrupt-blob load fault not logged; logs:\n%s", logBuf.String())
	}
}

// TestSaveModel_SaveFaultPreservesBlob is the fault-injection preservation
// test: a DB fault at persistence time must surface as an error and leave the
// previously persisted blob byte-identical (no silent reset of the row).
func TestSaveModel_SaveFaultPreservesBlob(t *testing.T) {
	pool := testsupport.OpenTestPool(t)

	userID, _ := insertSpamTestUserWithMailbox(t, pool, "smfnc8")
	blob := sealModelBlob(userID, trainedUserModel(t, userID, []byte(fenceMsgRaw)))
	insertSpamModelRow(t, pool, userID, blob, 5, false)

	store := NewPGModelStore(pgxutil.WorkerPool{Pool: pool}, nil, "unused-bucket")
	model, expect, err := store.LoadModelForTraining(context.Background(), userID)
	if err != nil || expect == nil {
		t.Fatalf("warm LoadModelForTraining: err=%v", err)
	}
	model.Train([]byte(fenceMsgRaw), true)
	data, err := model.Save()
	if err != nil {
		t.Fatalf("Save: %v", err)
	}

	// Deterministic DB fault: a canceled context fails the statement.
	faultedCtx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := store.SaveModel(faultedCtx, userID, data, expect); err == nil {
		t.Fatal("save with faulted DB context returned nil — fault not surfaced")
	}
	after := spamModelRowSnapshot(t, pool, userID)
	if !bytes.Equal(after.modelBytes, blob) || after.sampleCount != 5 {
		t.Fatalf("faulted save mutated the persisted blob: %d bytes, sample_count %d", len(after.modelBytes), after.sampleCount)
	}

	// Control: the honest save over the intact snapshot succeeds and runs the
	// caller's success branch (destructive overwrite is logged by the trainer).
	if err := store.SaveModel(context.Background(), userID, data, expect); err != nil {
		t.Fatalf("honest save after fault: %v", err)
	}
}

// TestLoadModel_RejectsForeignUserBlob pins the seal's user binding: a blob
// copied from another user's row must surface as a load error (never decoded
// as the victim's weights).
func TestLoadModel_RejectsForeignUserBlob(t *testing.T) {
	pool := testsupport.OpenTestPool(t)

	victim, _ := insertSpamTestUserWithMailbox(t, pool, "smfnc9")
	attacker, _ := insertSpamTestUserWithMailbox(t, pool, "smfnc10")

	foreign := sealModelBlob(attacker, trainedUserModel(t, attacker, []byte(fenceMsgRaw)))
	insertSpamModelRow(t, pool, victim, foreign, 9, false)

	store := NewPGModelStore(pgxutil.WorkerPool{Pool: pool}, nil, "unused-bucket")
	if _, err := store.LoadModel(context.Background(), victim); err == nil {
		t.Fatal("blob sealed for another user loaded as the victim's model")
	}
}
