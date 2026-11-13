package pwhash

import (
	"errors"
	"strings"
	"testing"

	"setjoin.com/shared/cryptokey"

	"golang.org/x/crypto/bcrypt"
)

func TestSetCryptoProfile(t *testing.T) {
	if activeProfile != cryptokey.ProfileStandard {
		t.Errorf("default activeProfile = %q, want %q", activeProfile, cryptokey.ProfileStandard)
	}

	SetCryptoProfile(cryptokey.ProfileSMx)
	if activeProfile != cryptokey.ProfileSMx {
		t.Errorf("after SetCryptoProfile(smx): %q, want %q", activeProfile, cryptokey.ProfileSMx)
	}

	SetCryptoProfile(cryptokey.ProfileHybrid)
	if activeProfile != cryptokey.ProfileHybrid {
		t.Errorf("after SetCryptoProfile(hybrid): %q, want %q", activeProfile, cryptokey.ProfileHybrid)
	}

	SetCryptoProfile(cryptokey.ProfileStandard)
}

func TestPasswordMaxBytesMatchesBcryptBoundary(t *testing.T) {
	if PasswordMaxBytes != 72 {
		t.Fatalf("PasswordMaxBytes = %d, want bcrypt's 72-byte boundary", PasswordMaxBytes)
	}
	if _, err := HashPassword(strings.Repeat("a", PasswordMaxBytes)); err != nil {
		t.Fatalf("hash at boundary: %v", err)
	}
	if _, err := HashPassword(strings.Repeat("a", PasswordMaxBytes+1)); err == nil {
		t.Fatal("hash above boundary unexpectedly succeeded")
	}
}

func TestHashPasswordWithProfileRejectsOverByteLimit(t *testing.T) {
	tooLong := strings.Repeat("界", PasswordMaxBytes/3+1)
	if got := len([]byte(tooLong)); got <= PasswordMaxBytes {
		t.Fatalf("test password is %d bytes, want more than %d", got, PasswordMaxBytes)
	}

	for _, profile := range []cryptokey.CryptoProfile{
		cryptokey.ProfileStandard,
		cryptokey.ProfileSMx,
	} {
		t.Run(string(profile), func(t *testing.T) {
			SetCryptoProfile(profile)
			if _, err := HashPasswordWithProfile(tooLong); !errors.Is(err, bcrypt.ErrPasswordTooLong) {
				t.Fatalf("HashPasswordWithProfile error = %v, want bcrypt.ErrPasswordTooLong", err)
			}
		})
	}
	SetCryptoProfile(cryptokey.ProfileStandard)
}

func TestVerifyPasswordHashDispatchesStoredFormat(t *testing.T) {
	bcryptHash, err := HashPassword("password123")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	sm3Hash, err := HashPasswordSM3("password123")
	if err != nil {
		t.Fatalf("HashPasswordSM3: %v", err)
	}

	for name, hash := range map[string]string{
		"bcrypt": bcryptHash,
		"sm3":    sm3Hash,
	} {
		t.Run(name+" accepts matching password", func(t *testing.T) {
			if err := VerifyPasswordHash(hash, "password123"); err != nil {
				t.Fatalf("VerifyPasswordHash: %v", err)
			}
		})
		t.Run(name+" rejects wrong password", func(t *testing.T) {
			if err := VerifyPasswordHash(hash, "wrong-password"); err == nil {
				t.Fatal("VerifyPasswordHash accepted a wrong password")
			}
		})
	}
}

func TestHashPasswordWithProfile_Standard(t *testing.T) {
	SetCryptoProfile(cryptokey.ProfileStandard)
	hash, err := HashPasswordWithProfile("password123")
	if err != nil {
		t.Fatalf("HashPasswordWithProfile (standard): %v", err)
	}
	if !strings.HasPrefix(hash, "$2a$") {
		t.Errorf("standard profile should produce bcrypt hash: got %q", hash)
	}
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte("password123")); err != nil {
		t.Errorf("bcrypt verify failed: %v", err)
	}
}

func TestHashPasswordWithProfile_SMx(t *testing.T) {
	SetCryptoProfile(cryptokey.ProfileSMx)
	hash, err := HashPasswordWithProfile("password123")
	if err != nil {
		t.Fatalf("HashPasswordWithProfile (smx): %v", err)
	}
	if !strings.HasPrefix(hash, "$sm3$") {
		t.Errorf("smx profile should produce SM3 hash: got %q", hash)
	}
	if err := VerifyPasswordSM3(hash, "password123"); err != nil {
		t.Errorf("SM3 verify failed: %v", err)
	}
	SetCryptoProfile(cryptokey.ProfileStandard)
}

func TestHashPasswordWithProfile_Hybrid(t *testing.T) {
	SetCryptoProfile(cryptokey.ProfileHybrid)
	hash, err := HashPasswordWithProfile("password123")
	if err != nil {
		t.Fatalf("HashPasswordWithProfile (hybrid): %v", err)
	}
	if !strings.HasPrefix(hash, "$sm3$") {
		t.Errorf("hybrid profile should produce SM3 hash: got %q", hash)
	}
	SetCryptoProfile(cryptokey.ProfileStandard)
}

func TestBcryptAndSM3_Coexist(t *testing.T) {
	// SM3 hash can coexist with bcrypt. Can verify both formats.
	sm3Hash, _ := HashPasswordSM3("password")
	if err := VerifyPasswordSM3(sm3Hash, "password"); err != nil {
		t.Errorf("SM3 verify should work: %v", err)
	}

	bcryptHash, _ := HashPassword("password")
	if err := bcrypt.CompareHashAndPassword([]byte(bcryptHash), []byte("password")); err != nil {
		t.Errorf("bcrypt verify should work: %v", err)
	}

	// Cross-format verification should fail
	if IsSM3Hash(sm3Hash) && !IsSM3Hash(bcryptHash) {
		// Can't verify SM3 hash with bcrypt
		if err := bcrypt.CompareHashAndPassword([]byte(sm3Hash), []byte("password")); err == nil {
			t.Error("bcrypt should not verify SM3 hash")
		}
	}
}
