package authn

import (
	"encoding/json"
	"testing"

	"github.com/go-webauthn/webauthn/webauthn"
)

// newTestPasskeyProvider builds a PasskeyProvider with a real go-webauthn engine
// but no DB pool. The decoy login path does not touch the pool, so this is
// sufficient to exercise the enumeration-hardening logic.
func newTestPasskeyProvider(t *testing.T) *PasskeyProvider {
	t.Helper()
	p, err := NewPasskeyProvider(nil, "localhost", "SetJoin", "http://localhost:8080")
	if err != nil {
		t.Fatalf("NewPasskeyProvider: %v", err)
	}
	return p
}

// realAssertionShape returns the JSON keys of an assertion produced for a
// genuine user that has a registered credential — the baseline a decoy must
// match so the two are indistinguishable on the wire.
func realAssertionShape(t *testing.T, p *PasskeyProvider) (optKeys, sessKeys map[string]struct{}) {
	t.Helper()
	wu := &passkeyUser{
		id:          7,
		email:       "real@example.com",
		displayName: "real@example.com",
		userHandle:  []byte("0123456789abcdef0123456789abcdef"),
		credentials: []webauthn.Credential{{
			ID:              []byte("real-credential-id-bytes-32-long"),
			AttestationType: "none",
		}},
	}
	opt, sd, err := p.wauth.BeginLogin(wu)
	if err != nil {
		t.Fatalf("real BeginLogin: %v", err)
	}
	optJSON, _ := json.Marshal(opt)
	sessJSON, _ := json.Marshal(sd)
	return keysOf(t, optJSON), keysOf(t, sessJSON)
}

func keysOf(t *testing.T, b []byte) map[string]struct{} {
	t.Helper()
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("unmarshal: %v (%s)", err, b)
	}
	out := make(map[string]struct{}, len(m))
	for k := range m {
		out[k] = struct{}{}
	}
	return out
}

// TestBeginDecoyLogin_ReturnsPlausibleAssertion is the core enumeration-hardening
// proof. Against the OLD code, an unknown account produced an error from
// BeginLogin (HTTP 404/400) while a known account produced 200 + options — a
// trivial enumeration oracle. The decoy path must instead yield a real,
// well-formed assertion with userID 0.
func TestBeginDecoyLogin_ReturnsPlausibleAssertion(t *testing.T) {
	p := newTestPasskeyProvider(t)

	uid, optJSON, sessJSON, err := p.beginDecoyLogin("ghost@example.com")
	if err != nil {
		t.Fatalf("beginDecoyLogin returned error (re-introduces enumeration oracle): %v", err)
	}
	if uid != 0 {
		t.Errorf("decoy userID = %d, want 0", uid)
	}
	if len(optJSON) == 0 || len(sessJSON) == 0 {
		t.Fatalf("decoy produced empty assertion/session: opt=%q sess=%q", optJSON, sessJSON)
	}

	// The decoy assertion JSON must have the same top-level shape as a real one.
	gotOptKeys := keysOf(t, optJSON)
	gotSessKeys := keysOf(t, sessJSON)
	wantOptKeys, wantSessKeys := realAssertionShape(t, p)

	for k := range wantOptKeys {
		if _, ok := gotOptKeys[k]; !ok {
			t.Errorf("decoy assertion missing key %q present in real assertion", k)
		}
	}
	for k := range gotOptKeys {
		if _, ok := wantOptKeys[k]; !ok {
			t.Errorf("decoy assertion has extra key %q not in real assertion", k)
		}
	}
	for k := range wantSessKeys {
		if _, ok := gotSessKeys[k]; !ok {
			t.Errorf("decoy session missing key %q present in real session", k)
		}
	}

	// A real challenge must be present (>= 16 bytes, base64url) so the client
	// cannot detect a decoy by an empty/short challenge.
	var opt struct {
		PublicKey struct {
			Challenge          string `json:"challenge"`
			AllowedCredentials []struct {
				ID string `json:"id"`
			} `json:"allowCredentials"`
		} `json:"publicKey"`
	}
	if err := json.Unmarshal(optJSON, &opt); err != nil {
		t.Fatalf("unmarshal decoy assertion: %v", err)
	}
	if len(opt.PublicKey.Challenge) == 0 {
		t.Error("decoy assertion has empty challenge")
	}
	if len(opt.PublicKey.AllowedCredentials) == 0 {
		t.Error("decoy assertion exposes empty allowCredentials — distinguishable from a real assertion")
	}
}

// TestBeginDecoyLogin_DeterministicPerEmail proves repeated probes for the same
// non-existent email yield a stable allowCredentials set, so an attacker cannot
// detect a decoy by observing a changing credential ID across requests, while
// different emails get different credential IDs.
func TestBeginDecoyLogin_DeterministicPerEmail(t *testing.T) {
	p := newTestPasskeyProvider(t)

	credA1 := decoyCredIDs(t, p, "alice@example.com")
	credA2 := decoyCredIDs(t, p, "alice@example.com")
	credB := decoyCredIDs(t, p, "bob@example.com")

	if len(credA1) == 0 {
		t.Fatal("no decoy credentials returned")
	}
	if !equalStrSlice(credA1, credA2) {
		t.Errorf("decoy credential IDs not stable for same email: %v vs %v", credA1, credA2)
	}
	if equalStrSlice(credA1, credB) {
		t.Errorf("decoy credential IDs collide across different emails: %v", credA1)
	}
}

// TestBeginDecoyLogin_ChallengeIsFresh ensures the random challenge differs per
// call (only the credential ID set is deterministic), matching a real login.
func TestBeginDecoyLogin_ChallengeIsFresh(t *testing.T) {
	p := newTestPasskeyProvider(t)
	c1 := decoyChallenge(t, p, "carol@example.com")
	c2 := decoyChallenge(t, p, "carol@example.com")
	if c1 == "" || c2 == "" {
		t.Fatal("empty challenge")
	}
	if c1 == c2 {
		t.Error("decoy challenge is static across calls — must be a fresh random value")
	}
}

func decoyCredIDs(t *testing.T, p *PasskeyProvider, email string) []string {
	t.Helper()
	_, optJSON, _, err := p.beginDecoyLogin(email)
	if err != nil {
		t.Fatalf("beginDecoyLogin(%q): %v", email, err)
	}
	var opt struct {
		PublicKey struct {
			AllowedCredentials []struct {
				ID string `json:"id"`
			} `json:"allowCredentials"`
		} `json:"publicKey"`
	}
	if err := json.Unmarshal(optJSON, &opt); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	ids := make([]string, 0, len(opt.PublicKey.AllowedCredentials))
	for _, c := range opt.PublicKey.AllowedCredentials {
		ids = append(ids, c.ID)
	}
	return ids
}

func decoyChallenge(t *testing.T, p *PasskeyProvider, email string) string {
	t.Helper()
	_, optJSON, _, err := p.beginDecoyLogin(email)
	if err != nil {
		t.Fatalf("beginDecoyLogin(%q): %v", email, err)
	}
	var opt struct {
		PublicKey struct {
			Challenge string `json:"challenge"`
		} `json:"publicKey"`
	}
	if err := json.Unmarshal(optJSON, &opt); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	return opt.PublicKey.Challenge
}

func equalStrSlice(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
