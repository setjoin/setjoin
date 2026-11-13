package spam

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync/atomic"

	"github.com/jackc/pgx/v5"
	"github.com/minio/minio-go/v7"
	"setjoin.com/mailserver/internal/blob"
	"setjoin.com/shared/pgxutil"
)

// ErrModelDisabled is returned by LoadModel when the user's model row carries
// user_spam_model.disabled = TRUE (admin_spam DisableModel). It is the
// machine-readable scoring opt-out: the FTRL scoring caller in
// internal/smtp/inbound.go skips model.Score on any LoadModel error, so this
// sentinel is what actually consumes the disabled flag, and the trainer
// special-cases it to refuse rebuilding a disabled model. It is NOT a model
// reset (the row and its trained weights are retained) and NOT user training
// consent (see trainer.go — that remains an open product decision).
var ErrModelDisabled = errors.New("spam model disabled for user (scoring opt-out)")

// ErrSaveFenced is returned by SaveModel when the optimistic persistence
// fence refuses the write: the model state the trainer trained from no longer
// matches the row (admin ResetModel deleted it, DisableModel disabled it, or
// another save replaced the bytes). Persisting anyway would reinsert
// pre-reset weights or overwrite a newly disabled model — the exact
// transitions med-shard3-016 fences. The trainer drops the batch; the next
// window reloads fresh state.
var ErrSaveFenced = errors.New("spam model changed during training; save fenced")

// modelBlobMagic seals every persisted model blob. Layout:
//
//	"SPM1" | LE32(PerUserFeatureKey(userID)) | FTR2 blob
//
// The seal makes the per-user keying change detectable and binding:
//
//   - A blob persisted before per-user keying (bare FTR2 bytes) fails the
//     prefix check and surfaces as a load error instead of silently decoding
//     trained weights under the new keyed bucket mapping (fail-closed, same
//     convention as the FTRL→FTR2 magic bump: such models are cleared by an
//     admin reset and retrain). FeatureMLSpam is toggle-gated OFF, so no
//     serving path depends on pre-keying blobs.
//   - A row copied between users fails the key check — a blob only loads for
//     the user whose feature space its weights were trained in.
const modelBlobMagic = "SPM1"

// sealModelBlob binds ftrl bytes to userID's feature-space key.
func sealModelBlob(userID int64, ftrl []byte) []byte {
	out := make([]byte, 0, 8+len(ftrl))
	out = append(out, modelBlobMagic...)
	var kb [4]byte
	binary.LittleEndian.PutUint32(kb[:], PerUserFeatureKey(userID))
	out = append(out, kb[:]...)
	return append(out, ftrl...)
}

// openModelBlob verifies the seal against userID and returns the inner FTRL
// bytes. Legacy (unsealed) and cross-user blobs are refused, never silently
// decoded.
func openModelBlob(userID int64, blobBytes []byte) ([]byte, error) {
	if len(blobBytes) < 8 || string(blobBytes[:4]) != modelBlobMagic {
		return nil, fmt.Errorf("model blob predates per-user feature keying (reset the model to retrain)")
	}
	if binary.LittleEndian.Uint32(blobBytes[4:8]) != PerUserFeatureKey(userID) {
		return nil, fmt.Errorf("model blob feature key does not match user")
	}
	return blobBytes[8:], nil
}

// newUserModel builds the keyed model for userID: the fixed DefaultFeatureSize
// FTRL table with the user's per-user feature-space key as the extract key
// (see ExtractFeatures). Direct NewModel callers get table==key at the default
// size; only the store needs the keyed split.
func newUserModel(userID int64) *Model {
	return &Model{
		ftrl:     NewFTRL(DefaultFeatureSize, DefaultFTRLParams()),
		featSize: PerUserFeatureKey(userID),
	}
}

// PGModelStore implements ModelStore using PostgreSQL.
type PGModelStore struct {
	pool   pgxutil.WorkerPool
	minio  *minio.Client
	bucket string

	// Batch-load observability (feature.spam_model_batch_load, owner decision
	// A6): process-wide gauges/totals every BatchScorer wired to this store
	// feeds. ResidentModels/ResidentBytes are the live memory footprint of
	// models held across delivery-scoring batches (the quantity the toggle's
	// memory-footprint warning declares); Loads/Hits are lifetime counters.
	// Surfaced via BatchLoadStats for the admin spam dashboard.
	batchLoadsTotal     atomic.Int64
	batchHitsTotal      atomic.Int64
	batchResidentModels atomic.Int64
	batchResidentBytes  atomic.Int64
}

// NewPGModelStore creates a new PostgreSQL-backed model store. minioClient +
// bucket are used by FetchMessage to read raw message bytes directly from object
// storage (the trainer is a trusted background worker, so it reads the blob
// itself instead of going over the JWT-gated HTTP download endpoint).
func NewPGModelStore(pool pgxutil.WorkerPool, minioClient *minio.Client, bucket string) *PGModelStore {
	return &PGModelStore{pool: pool, minio: minioClient, bucket: bucket}
}

// loadModelRow is the single load path behind LoadModel and
// LoadModelForTraining. It returns the parsed model, the raw persisted column
// bytes (nil for a cold start: no row, or the '\x' placeholder row), and
// whether a non-placeholder row existed.
func (s *PGModelStore) loadModelRow(ctx context.Context, userID int64) (*Model, []byte, bool, error) {
	var (
		data     []byte
		disabled bool
	)
	err := s.pool.QueryRow(ctx,
		`SELECT model_bytes, disabled FROM user_spam_model WHERE user_id = $1`, userID,
	).Scan(&data, &disabled)
	if errors.Is(err, pgx.ErrNoRows) {
		// Cold start: no model has ever been persisted (or it was pruned or
		// explicitly reset — see the reset policy in trainer.go).
		return newUserModel(userID), nil, false, nil
	}
	if err != nil {
		return nil, nil, false, fmt.Errorf("load spam model for user %d: %w", userID, err)
	}
	if disabled {
		return nil, nil, false, ErrModelDisabled
	}
	if len(data) == 0 {
		// DisableModel's placeholder row (model_bytes '\x', sample_count 0)
		// re-enabled without any training since: nothing persisted to load.
		// Saves against it take the cold-start arm (overtake-empty-only).
		return newUserModel(userID), nil, false, nil
	}
	inner, err := openModelBlob(userID, data)
	if err != nil {
		return nil, nil, false, fmt.Errorf("corrupt spam model for user %d: %w", userID, err)
	}
	m := newUserModel(userID)
	if err := m.Load(inner); err != nil {
		return nil, nil, false, fmt.Errorf("corrupt spam model for user %d: %w", userID, err)
	}
	return m, data, true, nil
}

// LoadModel loads the FTRL model for a user from PostgreSQL.
//
// Outcome contract (faults, cold start, and opt-out are deliberately distinct —
// callers must never be handed an unverified fresh model as a silent fallback):
//
//   - No row (never trained, pruned by prune_spam, or explicitly reset via
//     admin ResetModel's DELETE), or the empty '\x' placeholder row: cold
//     start — returns a fresh untrained model with a nil error. This is the
//     documented rebuild path (prune_spam.sql: "a stale model ... is rebuilt
//     on the user's next training event").
//   - disabled = TRUE: returns (nil, ErrModelDisabled). Scoring is opted out
//     and the trained weights stay persisted for a later EnableModel.
//   - Any other query fault, a blob persisted before per-user keying, a blob
//     sealed for a different user, or an unparsable blob: returns (nil, err).
//     The error is surfaced so the callers' existing error branches run:
//     scoring skips FTRL, and the trainer refuses to train — persisting a
//     batch onto a silently-fresh model would be an unlogged destructive
//     overwrite of the persisted weights (the exact fail-open collapse this
//     contract replaces).
func (s *PGModelStore) LoadModel(ctx context.Context, userID int64) (*Model, error) {
	m, _, _, err := s.loadModelRow(ctx, userID)
	return m, err
}

// LoadModelForTraining is the trainer's load path: it additionally returns the
// optimistic-concurrency snapshot for SaveModel's persistence fence. A nil
// expect means the trainer started from a cold start (no row or the empty
// placeholder); a non-nil expect is the exact model_bytes the row must still
// carry when the trained batch is saved — any interleaved reset, disable, or
// competing save makes SaveModel refuse with ErrSaveFenced.
func (s *PGModelStore) LoadModelForTraining(ctx context.Context, userID int64) (*Model, []byte, error) {
	m, data, found, err := s.loadModelRow(ctx, userID)
	if err != nil {
		return nil, nil, err
	}
	if found && data != nil {
		return m, data, nil
	}
	return m, nil, nil
}

// SaveModel persists trained model bytes under the optimistic persistence
// fence (med-shard3-016). expect is the snapshot returned by
// LoadModelForTraining:
//
//   - expect non-nil (warm start): CAS UPDATE — the row is overwritten only
//     while it still carries exactly the bytes the trainer trained from and
//     disabled = FALSE. An interleaved ResetModel (row gone), DisableModel,
//     or competing save yields 0 affected rows → ErrSaveFenced; pre-reset
//     weights can never be reinserted through the INSERT arm because a reset
//     can only interleave after an existing row was loaded.
//   - expect nil (cold start): INSERT ... ON CONFLICT DO UPDATE, where the
//     update arm only overtakes an EMPTY, non-disabled row (DisableModel's
//     '\x' placeholder, sample_count restarts at 1). A placeholder inserted
//     between load and save (DisableModel of a never-trained user) is
//     disabled → fenced; a row with real weights the trainer never saw →
//     fenced. A cold-start save after a reset can carry no pre-reset
//     knowledge: the trainer had no row to train from.
//
// Rows are written with the per-user seal (sealModelBlob), so a blob only
// loads back for the user it was trained for. 0 affected rows is always
// ErrSaveFenced; query faults surface as errors — never a silent overwrite.
func (s *PGModelStore) SaveModel(ctx context.Context, userID int64, data []byte, expect []byte) error {
	sealed := sealModelBlob(userID, data)
	if len(expect) > 0 {
		tag, err := s.pool.Exec(ctx,
			`UPDATE user_spam_model
			    SET model_bytes = $2, sample_count = sample_count + 1, trained_at = now()
			  WHERE user_id = $1 AND disabled = FALSE AND model_bytes = $3`,
			userID, sealed, expect,
		)
		if err != nil {
			return fmt.Errorf("persist spam model for user %d: %w", userID, err)
		}
		if tag.RowsAffected() == 0 {
			return ErrSaveFenced
		}
		return nil
	}
	tag, err := s.pool.Exec(ctx,
		`INSERT INTO user_spam_model (user_id, model_bytes, sample_count, trained_at)
		 VALUES ($1, $2, 1, now())
		 ON CONFLICT (user_id) DO UPDATE SET
		   model_bytes = EXCLUDED.model_bytes,
		   sample_count = EXCLUDED.sample_count,
		   trained_at = now()
		 WHERE user_spam_model.disabled = FALSE
		   AND octet_length(user_spam_model.model_bytes) = 0`,
		userID, sealed,
	)
	if err != nil {
		return fmt.Errorf("persist spam model for user %d: %w", userID, err)
	}
	if tag.RowsAffected() == 0 {
		return ErrSaveFenced
	}
	return nil
}

// maxScanMessageBytes caps the raw bytes the trainer/scorer will read for one
// message (D-MAILSERVER-INTERNAL-SPAM-006, spam-scan-resource-limits). It
// matches the SMTP ingress ceiling, so with today's producers it never binds;
// a future producer storing larger blobs is bounded here instead of pulling
// the full object into memory. Train and score both read through FetchMessage,
// so a deterministic truncation keeps the two inputs identical.
const maxScanMessageBytes = 150 << 20

// FetchMessage retrieves the raw RFC822 content for a message.
// messages.raw_ref is EITHER an object-store key ("inbound/<sha>" for received
// mail, "blobs/<sha>" for MSA submissions, bare sha for assembled drafts) OR
// the inline RFC 5322 text itself (reducer-built drafts / sent copies) — the
// W5 raw_ref convention, discriminated by blob.IsInlineMessage.
func (s *PGModelStore) FetchMessage(ctx context.Context, userID int64, messageID int64) ([]byte, error) {
	// Resolve the message's blob ref (sha256). messages has NO user_id column —
	// ownership is the mailbox→user join. Runs on the BYPASSRLS pool: the spam
	// trainer is a background batch worker that trains models across all users
	// (cross-tenant by nature); the per-user scope is the mb.user_id predicate.
	var rawRef string
	err := s.pool.QueryRow(ctx,
		`SELECT m.raw_ref
		 FROM messages m
		 JOIN mailboxes mb ON mb.id = m.mailbox_id
		 WHERE m.id = $1 AND mb.user_id = $2`,
		messageID, userID,
	).Scan(&rawRef)
	if err != nil {
		return nil, fmt.Errorf("fetch message %d: %w", messageID, err)
	}
	// Inline raw_ref (webmail-sent copies a user may mark as spam/ham): the text
	// IS the message — a GetObject on it would be a guaranteed NoSuchKey.
	if blob.IsInlineMessage(rawRef) {
		return []byte(rawRef), nil
	}
	// Read the blob directly from object storage (raw_ref is the object key),
	// exactly as the outbound worker does. The trainer is a trusted in-process
	// worker, so it must NOT round-trip through the JWT-gated /jmap/download HTTP
	// endpoint (it has no inbound request whose Authorization header it could
	// forward — that path always 401'd, and the hardcoded :80 / no-timeout client
	// were further dead ends).
	if s.minio == nil {
		return nil, fmt.Errorf("download blob %s: no object store configured", rawRef)
	}
	obj, err := s.minio.GetObject(ctx, s.bucket, rawRef, minio.GetObjectOptions{})
	if err != nil {
		return nil, fmt.Errorf("download blob %s: %w", rawRef, err)
	}
	defer func() { _ = obj.Close() }()
	// Resource bound (D-MAILSERVER-INTERNAL-SPAM-006): never read beyond the
	// scan cap; the read is deterministically truncated for train and score
	// alike, so both paths always see the same bytes.
	return io.ReadAll(io.LimitReader(obj, maxScanMessageBytes))
}
