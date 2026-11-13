package spam

import (
	"bytes"
	"context"
	"log/slog"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"setjoin.com/shared/pgxutil"
	"setjoin.com/shared/testsupport"
)

// Edge-branch coverage: parseMessage's mixed-EOL header/body separator, the
// non-email From feature, the all-caps subject feature, batch-scorer sink
// wiring, and the model store's fault branches.

// containsFeature reports whether the extracted index table contains the
// bucket for token.
func containsFeature(feats []uint32, size uint32, token string) bool {
	idx := featureIndex(size, token)
	for _, f := range feats {
		if f == idx {
			return true
		}
	}
	return false
}

// TestExtractFeaturesMixedEOLSeparatorPinned pins parseMessage's EARLIEST
// double-EOL rule: whichever header/body separator ("\r\n\r\n" vs "\n\n")
// comes first wins, so an LF-only blank line inside a CRLF body (or the
// reverse) can't move the header/body boundary.
func TestExtractFeaturesMixedEOLSeparatorPinned(t *testing.T) {
	const size = DefaultFeatureSize

	// CRLF separator first: the LF blank line inside the body belongs to it.
	crlfFirst := []byte("From: a@x.test\r\nSubject: hi\r\n\r\nbody one\n\nmore words\r\n")
	feats := ExtractFeatures(crlfFirst, size)
	if !containsFeature(feats, size, "w:more") {
		t.Fatalf("CRLF-first body split early; 'more' missing from %v", feats)
	}

	// LF separator first: the CRLF blank line inside the body belongs to it.
	lfFirst := []byte("From: a@x.test\nSubject: hi\n\nbody two\r\n\r\nmore words\n")
	feats = ExtractFeatures(lfFirst, size)
	if !containsFeature(feats, size, "w:more") {
		t.Fatalf("LF-first body split early; 'more' missing from %v", feats)
	}
}

// TestExtractFeaturesNonEmailFromUsesAddrToken pins the from:addr fallback: a
// From header with NO email-shaped substring is hashed as from:addr:<value>.
func TestExtractFeaturesNonEmailFromUsesAddrToken(t *testing.T) {
	const size = DefaultFeatureSize
	raw := []byte("From: MAILER-DAEMON\nSubject: bounce\n\nbody\n")
	feats := ExtractFeatures(raw, size)
	if !containsFeature(feats, size, "from:addr:mailer-daemon") {
		t.Fatalf("from:addr token missing from %v", feats)
	}
}

// TestExtractFeaturesAllCapsSubject pins the all-caps subject penalty.
func TestExtractFeaturesAllCapsSubject(t *testing.T) {
	const size = DefaultFeatureSize
	upper := ExtractFeatures([]byte("From: a@x.test\nSubject: URGENT WINNER NOW\n\nbody\n"), size)
	if !containsFeature(upper, size, "allcaps") {
		t.Fatalf("allcaps missing for shouting subject: %v", upper)
	}
	lower := ExtractFeatures([]byte("From: a@x.test\nSubject: quiet meeting notes\n\nbody\n"), size)
	if containsFeature(lower, size, "allcaps") {
		t.Fatalf("allcaps fired for a quiet subject: %v", lower)
	}
}

// sinkRecordingSource is a ModelSource that also implements BatchStatsSink —
// the production PGModelStore shape whose gauge wiring NewBatchScorer must
// detect.
type sinkRecordingSource struct {
	ModelSource
	releases int64
	loads    int64
}

func (s *sinkRecordingSource) recordBatchLoad(int64)    { s.loads++ }
func (s *sinkRecordingSource) recordBatchRelease(int64) { s.releases++ }

// TestNewBatchScorerWiresStatsSink pins the optional-sink detection: a source
// implementing BatchStatsSink becomes the scorer's gauge sink.
func TestNewBatchScorerWiresStatsSink(t *testing.T) {
	src := &sinkRecordingSource{}
	b := NewBatchScorer(src, 4)
	if b.sink == nil {
		t.Fatal("NewBatchScorer did not wire a BatchStatsSink-capable source")
	}
	if b.sink != src {
		t.Fatal("sink must be the source itself")
	}
	// A plain ModelSource without the sink interface wires nothing (compile-
	// time: interface conversion path differs).
	b2 := NewBatchScorer(struct{ ModelSource }{}, 4)
	if b2.sink != nil {
		t.Fatalf("plain source must not be used as sink, got %v", b2.sink)
	}
}

// TestLogBatchLoadPostureNilLogger pins the nil-logger default: both postures
// log through slog.Default() instead of panicking.
func TestLogBatchLoadPostureNilLogger(t *testing.T) {
	LogBatchLoadPosture(nil, true)
	LogBatchLoadPosture(nil, false)
	LogBatchLoadPosture(slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)), true)
}

// TestLoadModel_DBErrorSurfaces pins the generic load error branch: an
// unreachable database is an error, never a silent cold start.
func TestLoadModel_DBErrorSurfaces(t *testing.T) {
	pool, err := pgxpool.New(context.Background(),
		"postgres://spamtest@127.0.0.1:1/noSuchDB?sslmode=disable&connect_timeout=1")
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	store := NewPGModelStore(pgxutil.WorkerPool{Pool: pool}, nil, "bucket")
	if _, err := store.LoadModel(context.Background(), 1); err == nil {
		t.Fatal("LoadModel on broken pool: want error")
	}
	if _, _, err := store.LoadModelForTraining(context.Background(), 1); err == nil {
		t.Fatal("LoadModelForTraining on broken pool: want error")
	}
	if err := store.SaveModel(context.Background(), 1, []byte("model"), nil); err == nil {
		t.Fatal("SaveModel on broken pool: want error")
	}
}

// cleanSpamFixture deletes any leaked fixture rows for one fixed label,
// dependents first (the shared fixture's own cleanup can strand them).
func cleanSpamFixture(t *testing.T, pool *pgxpool.Pool, label string) {
	t.Helper()
	ctx := context.Background()
	dom := "spam-test-" + label + ".example.com"
	_, _ = pool.Exec(ctx, `DELETE FROM user_spam_model WHERE user_id IN (SELECT id FROM users WHERE domain_id IN (SELECT id FROM domains WHERE name=$1))`, dom)
	_, _ = pool.Exec(ctx, `DELETE FROM messages WHERE mailbox_id IN (SELECT id FROM mailboxes WHERE domain_id IN (SELECT id FROM domains WHERE name=$1))`, dom)
	_, _ = pool.Exec(ctx, `DELETE FROM mailboxes WHERE domain_id IN (SELECT id FROM domains WHERE name=$1)`, dom)
	_, _ = pool.Exec(ctx, `DELETE FROM users WHERE domain_id IN (SELECT id FROM domains WHERE name=$1)`, dom)
	_, _ = pool.Exec(ctx, `DELETE FROM domains WHERE name=$1`, dom)
}

// TestLoadModel_CorruptBlobSurfaces pins the corruption branch: a row whose
// blob does not open (wrong seal / truncated) returns a wrapped corruption
// error instead of a zero model.
func TestLoadModel_CorruptBlobSurfaces(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()
	// Cleanup-first: the shared fixture's fixed domain name leaks when a prior
	// run's cleanup trips the mailboxes shared_not_primary constraint.
	cleanSpamFixture(t, pool, "corrupt")
	userID, _ := insertSpamTestUserWithMailbox(t, pool, "corrupt")
	t.Cleanup(func() {
		cleanSpamFixture(t, pool, "corrupt")
	})
	// Sealed envelope (opens cleanly) whose payload is not a valid FTRL model
	// — the m.Load arm of the corruption check.
	insertSpamModelRow(t, pool, userID, sealModelBlob(userID, []byte("not-an-ftrl-model")), 3, false)

	store := NewPGModelStore(pgxutil.WorkerPool{Pool: pool}, nil, "bucket")
	if _, err := store.LoadModel(ctx, userID); err == nil {
		t.Fatal("LoadModel with corrupt blob: want error")
	} else if !bytes.Contains([]byte(err.Error()), []byte("corrupt spam model")) {
		t.Fatalf("err = %v, want corruption complaint", err)
	}
}
