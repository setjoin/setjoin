package contractvectors

import (
	"setjoin.com/shared/pwhash"
	"testing"
)

// Fixed salts make the stored hash input reproducible. The outcomes come from
// the production verifier, including the legacy rehash decision.
func TestRecordPwhash(t *testing.T) {
	const normal = "$2b$10$PedblkiwaUbDsqqrryOt7uRJMFhmX80v9hermz7rZrMshnM9m1FAy"
	const legacy = "$2b$04$A5ox0PnnBJzfk5U44aU2f.rG2Qap1gfazGCHrnK/6M21ieIW2Ty8G"
	const sm3 = "$sm3$1000$Zml4ZWQtc2FsdC0xMjM0NQ$ww77uFYw3ESURuYwecIlu0i0cfw+QRw3mtrnxOswjC4"
	inputs := []struct{ name, hash, password string }{
		{"bcrypt", normal, "fixture-password"},
		{"legacy_bcrypt_cost", legacy, "fixture-password"},
		{"legacy_sm3_iterations", sm3, "fixture-password"},
		{"wrong_password", normal, "wrong"},
		{"malformed_hash", "not-a-hash", "fixture-password"},
		{"zero_sm3_iterations", "$sm3$0$YQ$YQ", "fixture-password"},
		{"empty_sm3_salt", "$sm3$1000$$YQ", "fixture-password"},
	}
	var cases []vectorCase
	for _, in := range inputs {
		cases = append(cases, vectorCase{Name: in.name,
			Input:  map[string]any{"hash": in.hash, "password": in.password},
			Output: map[string]any{"password_valid": pwhash.VerifyPasswordHash(in.hash, in.password) == nil, "credential_valid": pwhash.VerifyCredentialHash(in.hash, in.password) == nil, "needs_rehash": pwhash.NeedsRehash(in.hash)},
		})
	}
	writeVectors(t, "pwhash", cases)
}
