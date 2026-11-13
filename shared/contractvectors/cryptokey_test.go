package contractvectors

import (
	"encoding/hex"
	"testing"

	"setjoin.com/shared/cryptokey"
)

func TestRecordCryptokey(t *testing.T) {
	secret := []byte("fixture-master-secret")
	nonce := []byte("fixed-nonce!")
	plaintext := []byte("stored signing key")
	aad := []byte("user:42")
	var cases []vectorCase
	for _, item := range []struct {
		name    string
		profile cryptokey.CryptoProfile
		algo    cryptokey.AlgorithmTag
	}{
		{"aes_column_envelope", cryptokey.ProfileStandard, cryptokey.AlgoAES256GCM},
		{"sm4_column_envelope", cryptokey.ProfileSMx, cryptokey.AlgoSM4GCM},
	} {
		key := cryptokey.DeriveDBEncryptionKey(secret, item.profile)
		envelope, err := cryptokey.SealEnvelopeDeterministic(item.algo, key, nonce, plaintext, aad)
		if err != nil {
			t.Fatal(err)
		}
		opened, openErr := cryptokey.DecryptColumnWithAAD(envelope, secret, aad)
		cases = append(cases, vectorCase{Name: item.name, Input: map[string]any{"master_secret_hex": hex.EncodeToString(secret), "nonce_hex": hex.EncodeToString(nonce), "plaintext_hex": hex.EncodeToString(plaintext), "aad_hex": hex.EncodeToString(aad), "profile": item.profile}, Output: map[string]any{"key_hex": hex.EncodeToString(key), "envelope_hex": hex.EncodeToString(envelope), "opened_hex": hex.EncodeToString(opened), "error": vectorCryptoError(openErr)}})
		_, wrongAAD := cryptokey.DecryptColumnWithAAD(envelope, secret, []byte("other"))
		cases = append(cases, vectorCase{Name: item.name + "_wrong_aad", Input: map[string]any{"master_secret_hex": hex.EncodeToString(secret), "envelope_hex": hex.EncodeToString(envelope), "aad_hex": hex.EncodeToString([]byte("other"))}, Output: map[string]any{"error": vectorCryptoError(wrongAAD)}})
	}
	_, bad := cryptokey.DecryptColumn([]byte("bad"), secret)
	cases = append(cases, vectorCase{Name: "truncated_column", Input: map[string]any{"master_secret_hex": hex.EncodeToString(secret), "envelope_hex": "626164"}, Output: map[string]any{"error": vectorCryptoError(bad)}})
	cases = append(cases, vectorCase{Name: "domain_keys", Input: map[string]any{"secret_hex": hex.EncodeToString(secret)}, Output: map[string]any{"cookie_hex": hex.EncodeToString(cryptokey.DeriveCookieKey(secret)), "oidc_hex": hex.EncodeToString(cryptokey.DeriveOIDCCryptoKey(secret)), "attachment_hex": hex.EncodeToString(cryptokey.DeriveMailAttachmentTokenKey(secret))}})
	writeVectors(t, "cryptokey", cases)
}

func vectorCryptoError(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
