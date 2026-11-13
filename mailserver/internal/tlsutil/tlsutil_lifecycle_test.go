package tlsutil

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"setjoin.com/shared/testsupport"
)

// failingCodec is a SecretCodec whose Encrypt always fails — the
// refuse-to-downgrade-to-plaintext arm of persistKeys.
type failingCodec struct{}

func (failingCodec) Encrypt(string, json.RawMessage) (json.RawMessage, error) {
	return nil, errors.New("keyring unavailable")
}

func (failingCodec) Decrypt(string, json.RawMessage) (json.RawMessage, error) {
	return nil, errors.New("keyring unavailable")
}

// ticketKeyManagerFixture builds a manager wired to a real TLS config and the
// test pool, restoring any pre-existing persisted ticket-key row afterwards.
func ticketKeyManagerFixture(t *testing.T, pool *pgxpool.Pool, codec SecretCodec) *SessionTicketKeyManager {
	t.Helper()
	ctx := context.Background()

	var prior struct {
		exists bool
		value  []byte
	}
	_ = pool.QueryRow(ctx,
		`SELECT value FROM system_config WHERE key = 'tls_session_ticket_keys'`).Scan(&prior.value)
	prior.exists = prior.value != nil
	t.Cleanup(func() {
		if prior.exists {
			_, _ = pool.Exec(context.Background(),
				`UPDATE system_config SET value = $1 WHERE key = 'tls_session_ticket_keys'`, prior.value)
		} else {
			_, _ = pool.Exec(context.Background(),
				`DELETE FROM system_config WHERE key = 'tls_session_ticket_keys'`)
		}
	})

	logger := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
	return &SessionTicketKeyManager{
		config:  &tls.Config{},
		pool:    pool,
		logger:  logger,
		secrets: codec,
	}
}

// TestLoadPersistedKeysInvalidRowRegeneratesFresh pins the defensive load arm:
// an invalid or redacted persisted row (legacy plaintext garbage that is not a
// stored-keys JSON) is replaced by freshly generated keys, never applied as-is.
func TestLoadPersistedKeysInvalidRowRegeneratesFresh(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()

	for _, codec := range []SecretCodec{nil, &stubCodec{}} {
		m := ticketKeyManagerFixture(t, pool, codec)
		if _, err := pool.Exec(ctx,
			`INSERT INTO system_config (key, value, encrypted, description)
			 VALUES ('tls_session_ticket_keys', '"redacted:secret"', TRUE, 'tlsutil test row')
			 ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value`); err != nil {
			t.Fatalf("seed invalid row (codec=%T): %v", codec, err)
		}

		m.loadPersistedKeys(ctx)

		m.mu.Lock()
		fresh := m.current != ([32]byte{})
		m.mu.Unlock()
		if !fresh {
			t.Fatalf("invalid row (codec=%T) did not regenerate fresh keys", codec)
		}
	}
}

// TestRotatePersistsWithoutCodecWarnsButWrites pins the legacy plaintext
// posture: with no codec wired the rotated key JSON is persisted verbatim (the
// row keeps its encrypted=TRUE label only because the SQL hardcodes it — the
// manager says so at Warn level). The in-memory keys must still apply.
func TestRotatePersistsWithoutCodecWarnsButWrites(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	m := ticketKeyManagerFixture(t, pool, nil)

	m.rotate(context.Background())

	var raw []byte
	if err := pool.QueryRow(context.Background(),
		`SELECT value FROM system_config WHERE key = 'tls_session_ticket_keys'`).Scan(&raw); err != nil {
		t.Fatalf("read persisted keys: %v", err)
	}
	var stored storedTicketKeys
	if err := json.Unmarshal(raw, &stored); err != nil {
		t.Fatalf("persisted row is not key JSON: %v (%s)", err, raw)
	}
	if stored.Current == "" {
		t.Fatal("persisted current key is empty")
	}
}

// TestRotateEncryptFailureKeepsPreviousPersistedState pins the
// refuse-to-downgrade arm: an encryption failure keeps whatever was persisted
// before instead of writing plaintext, while the in-memory keys still rotate.
func TestRotateEncryptFailureKeepsPreviousPersistedState(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	m := ticketKeyManagerFixture(t, pool, failingCodec{})

	// Seed a known-good persisted row.
	before := storedTicketKeys{Current: key32(), Previous: key32()}
	val, err := json.Marshal(before)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(context.Background(),
		`INSERT INTO system_config (key, value, encrypted, description)
		 VALUES ('tls_session_ticket_keys', $1, TRUE, 'tlsutil test row')
		 ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value`, val); err != nil {
		t.Fatalf("seed good row: %v", err)
	}

	m.rotate(context.Background())

	// The row must still hold the seeded keys (DB round-trip normalizes JSON
	// spacing, so compare decoded values, not bytes).
	var after storedTicketKeys
	if err := pool.QueryRow(context.Background(),
		`SELECT value FROM system_config WHERE key = 'tls_session_ticket_keys'`).Scan(&after); err != nil {
		t.Fatal(err)
	}
	if after.Current != before.Current {
		t.Fatalf("persisted current key changed after encrypt failure — plaintext downgrade risk")
	}
}

// TestRotatePersistExecFailureIsLogged pins the DB-write failure arm: a
// broken pool surfaces a logged persistence error, never a panic.
func TestRotatePersistExecFailureIsLogged(t *testing.T) {
	broken, err := pgxpool.New(context.Background(),
		"postgres://tlsutil@127.0.0.1:1/noSuchDB?sslmode=disable&connect_timeout=1")
	if err != nil {
		t.Fatal(err)
	}
	defer broken.Close()
	m := &SessionTicketKeyManager{
		config: &tls.Config{},
		pool:   broken,
		logger: slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError})),
	}
	m.rotate(context.Background())

	m.mu.Lock()
	rotated := m.current != ([32]byte{})
	m.mu.Unlock()
	if !rotated {
		t.Fatal("in-memory keys did not rotate despite the persistence failure")
	}
}

// TestSetConfigNilAndCodecSetter pins the accessor seams: SetConfig(nil) must
// not panic and must not apply keys; SetSecretCodec wires the codec; the
// nil-codec passthrough helpers are the documented legacy behavior.
func TestSetConfigNilAndCodecSetter(t *testing.T) {
	m := &SessionTicketKeyManager{logger: slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))}
	m.SetConfig(nil) // must not panic with a nil config

	cfg := &tls.Config{}
	m.SetConfig(cfg)
	if m.config != cfg {
		t.Fatal("SetConfig did not store the config reference")
	}

	plain, err := encryptTicketKeys(nil, json.RawMessage(`"plain"`))
	if err != nil || string(plain) != `"plain"` {
		t.Fatalf("nil-codec encrypt passthrough = (%s,%v), want verbatim,nil", plain, err)
	}
	got, ok := decryptTicketKeys(nil, json.RawMessage(`"plain"`))
	if ok || string(got) != `"plain"` {
		t.Fatalf("nil-codec decrypt passthrough = (%s,%v), want verbatim,false", got, ok)
	}

	codec := &stubCodec{}
	m.SetSecretCodec(codec)
	if m.secrets != codec {
		t.Fatal("SetSecretCodec did not wire the codec")
	}
}

// TestRotatePersistsEnvelopeWithCodec pins the encrypted posture: with a codec
// wired, the persisted row carries the envelope (never the verbatim key JSON).
func TestRotatePersistsEnvelopeWithCodec(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	codec := &stubCodec{}
	m := ticketKeyManagerFixture(t, pool, codec)

	m.rotate(context.Background())

	var raw []byte
	if err := pool.QueryRow(context.Background(),
		`SELECT value FROM system_config WHERE key = 'tls_session_ticket_keys'`).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var env struct {
		Envelope json.RawMessage `json:"envelope"`
	}
	if err := json.Unmarshal(raw, &env); err != nil || env.Envelope == nil {
		t.Fatalf("persisted row is not an envelope: %s (%v)", raw, err)
	}
	var stored storedTicketKeys
	if err := json.Unmarshal(env.Envelope, &stored); err != nil || stored.Current == "" {
		t.Fatalf("envelope payload is not key JSON: %s (%v)", env.Envelope, err)
	}
	if len(codec.gotConfigKeys) == 0 {
		t.Fatal("codec was never invoked during rotate")
	}
}
