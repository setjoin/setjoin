package cryptokey

import (
	"crypto/cipher"

	"github.com/emmansun/gmsm/sm4"
)

// SM4Vector is one SM4-GCM at-rest interop vector. gmsm is the canonical
// external oracle the offline-core SQLCipher SM4 page cipher MUST reproduce
// byte-for-byte (verify-crypto-with-an-external-oracle). Deterministic nonce
// so the golden is stable.
type SM4Vector struct {
	Key           []byte
	Nonce         []byte
	Plaintext     []byte
	AAD           []byte
	CiphertextTag []byte // gcm.Seal output (ciphertext || 16-byte tag), nonce NOT prepended
}

func sm4SealDeterministic(key, nonce, pt, aad []byte) []byte {
	block, err := sm4.NewCipher(key)
	if err != nil {
		panic("sm4_vectors: " + err.Error())
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic("sm4_vectors: " + err.Error())
	}
	return gcm.Seal(nil, nonce, pt, aad)
}

// SM4Vectors returns the canonical at-rest SM4-GCM interop vectors.
// The gmsm oracle seals each case deterministically so Rust can reproduce
// the exact bytes (verify-crypto-with-an-external-oracle).
func SM4Vectors() []SM4Vector {
	cases := []struct {
		key, nonce, pt, aad []byte
	}{
		{makeN(0x01, 16), makeN(0x00, 12), []byte("hello sm4"), nil},
		{makeN(0xA5, 16), makeN(0x11, 12), []byte{}, []byte("aad-bytes")},
		{makeN(0x7F, 16), makeN(0xAB, 12), []byte("国密 SM4 at-rest"), []byte("hdr")},
	}
	out := make([]SM4Vector, 0, len(cases))
	for _, c := range cases {
		out = append(out, SM4Vector{
			Key: c.key, Nonce: c.nonce, Plaintext: c.pt, AAD: c.aad,
			CiphertextTag: sm4SealDeterministic(c.key, c.nonce, c.pt, c.aad),
		})
	}
	return out
}

// makeN returns a byte slice of length n filled with b.
// ponytail: package-private helper for test-vector construction; not exported.
func makeN(b byte, n int) []byte {
	s := make([]byte, n)
	for i := range s {
		s[i] = b
	}
	return s
}
