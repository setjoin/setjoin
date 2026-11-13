package tlsutil

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"
)

func key32() string {
	var b [32]byte
	_, _ = rand.Read(b[:])
	return base64.StdEncoding.EncodeToString(b[:])
}

func TestParseStoredKeys(t *testing.T) {
	cur := key32()
	prev := key32()

	tests := []struct {
		name   string
		raw    string
		wantOK bool
	}{
		{"valid current+previous", `{"current":"` + cur + `","previous":"` + prev + `"}`, true},
		{"valid current only", `{"current":"` + cur + `"}`, true},
		{"redaction sentinel current", `{"current":"[ENCRYPTED]","previous":"[ENCRYPTED]"}`, false},
		{"malformed json", `"[ENCRYPTED]"`, false},
		{"short current key", `{"current":"` + base64.StdEncoding.EncodeToString([]byte("tooshort")) + `"}`, false},
		{"non-base64 current", `{"current":"not!base64!"}`, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotCur, _, ok := parseStoredKeys(json.RawMessage(tt.raw))
			if ok != tt.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tt.wantOK)
			}
			if ok && gotCur == ([32]byte{}) {
				t.Errorf("ok=true but current key is zero")
			}
		})
	}
}

// stubCodec is a minimal SecretCodec double: it "envelopes" with a marker so
// tests can observe what the ticket-key manager would persist, and asserts the
// AAD-bound config key the real codec will bind ciphertext with.
type stubCodec struct {
	gotConfigKeys []string
}

func (s *stubCodec) Encrypt(configKey string, plaintext json.RawMessage) (json.RawMessage, error) {
	s.gotConfigKeys = append(s.gotConfigKeys, configKey)
	wrapped := append([]byte(`{"envelope":`), plaintext...)
	return append(wrapped, '}'), nil
}

func (s *stubCodec) Decrypt(configKey string, stored json.RawMessage) (json.RawMessage, error) {
	var env struct {
		Envelope json.RawMessage `json:"envelope"`
	}
	if err := json.Unmarshal(stored, &env); err != nil || env.Envelope == nil {
		return nil, errNotEnvelope
	}
	return env.Envelope, nil
}

// errNotEnvelope marks a non-envelope payload so the caller's legacy fallback
// path is exercised.
var errNotEnvelope = errors.New("stub: not an envelope")

// TestTicketKeyEnvelopeSealing proves the TLSUTIL-001 fix at the manager seam:
// with a codec wired, persistable ticket-key JSON is enveloped (never passed
// through verbatim), the codec is invoked with the ticket-key config key (the
// real codec's AAD binding), decryption round-trips, and a legacy plaintext
// row still falls through to the plain parser.
func TestTicketKeyEnvelopeSealing(t *testing.T) {
	codec := &stubCodec{}
	keys := storedTicketKeys{Current: key32(), Previous: key32()}
	val, err := json.Marshal(keys)
	if err != nil {
		t.Fatal(err)
	}

	env, err := encryptTicketKeys(codec, val)
	if err != nil {
		t.Fatalf("encryptTicketKeys: %v", err)
	}
	if string(env) == string(val) {
		t.Fatal("envelope equals plaintext — nothing was sealed")
	}
	if len(codec.gotConfigKeys) != 1 || codec.gotConfigKeys[0] != ticketKeysConfigKey {
		t.Fatalf("codec called with config keys %v, want [%s]", codec.gotConfigKeys, ticketKeysConfigKey)
	}
	got, ok := decryptTicketKeys(codec, env)
	if !ok || string(got) != string(val) {
		t.Fatalf("decryptTicketKeys = %s, %v; want %s, true", got, ok, val)
	}

	// Legacy plaintext row: decryption fails, caller falls back to raw.
	fallback, ok := decryptTicketKeys(codec, val)
	if ok {
		t.Fatal("plaintext row misdetected as envelope")
	}
	if string(fallback) != string(val) {
		t.Fatal("fallback payload altered")
	}
	if _, _, pok := parseStoredKeys(fallback); !pok {
		t.Fatal("legacy plaintext row no longer parses after codec wired")
	}
}
