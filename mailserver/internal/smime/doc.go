// Package smime implements S/MIME for setjoin mail.
//
// Inbound verification (the badge path): VerifyDetached grades a detached CMS
// signature as valid/invalid/untrusted by parsing + chain-verifying via
// github.com/github/smimesign/ietf-cms against a trust pool (LoadBundledRoots —
// the embedded Mozilla CA bundle; Phase B adds admin-imported private-CA roots),
// requiring an Email-Protection EKU, a valid validity window, and a From-match
// (any cert SAN email equals the header From). A "valid" verdict is the only one
// that lights the green "verified sender" shield.
//
// Verify is the legacy detached-CMS verifier kept for the iMIP (calendar) path;
// it is hardened to require a content-binding messageDigest and to not panic on
// non-RSA keys, but it is not on the badge path.
//
// Sign/Encrypt/Decrypt are the hand-rolled outbound primitives. Sign() emits
// RFC 5652-conformant CMS (D4 fixed 5 interop bugs: FullBytes embedding for
// cert/issuer/attribute values, correct IssuerAndSerialNumber structure, RFC 5652
// §5.4 DER SET encoding for the signed-attrs digest). Verified by the openssl
// canonicalization oracle in sign_canonical_test.go.
//
// Encrypt() emits RFC 5652/3565 EnvelopedData decryptable by openssl and external
// MUAs (E1 fixed 2 interop bugs the self round-trip test hid: the RecipientInfo
// RecipientIdentifier is an UNTAGGED IssuerAndSerialNumber SEQUENCE — the prior
// [0] tag selected the wrong CHOICE alternative; and the AES-CBC IV lives in the
// contentEncryptionAlgorithm parameters as an OCTET STRING, not prepended to the
// encrypted content). Verified by the openssl decrypt oracle in
// encrypt_canonical_test.go.
//
// Since owner decision A5 (S/MIME 4.0 / RFC 8551) the outbound DEFAULT is
// AES-256-GCM wrapped as CMS AuthEnvelopedData (RFC 5083; encrypt.go): the
// ciphertext rides in authEncryptedContentInfo.encryptedContent, the 16-octet
// GCM tag in the dedicated mac field (GCMParameters aes-ICVlen=16 explicit,
// 12-octet nonce, no authAttrs ⇒ empty AAD). EncryptWithAlgorithm and the
// smime.encrypt_algorithm config key (SMIME_ENCRYPT_ALGORITHM) select the
// S/MIME 3.2 AES-256-CBC EnvelopedData fallback for deployments that need it.
// RECEIVE is content-type agnostic and always accepts BOTH forms
// (parseEnvelopedAny in decrypt_authenveloped.go) — the backward-compat
// mandate: legacy CBC mail stays readable forever, and the RSA session-key
// unwrap (with its Bleichenbacher padding-oracle collapse) is shared by both.
// GCM interop is oracle-verified against openssl cms both directions
// (TestEncrypt_GCM_OpensslDecrypts, TestReverseOracle_OpensslGCMEncryptThenOurDecrypt).
//
// DecryptMulti() (decrypt_multi.go) is the SP1 Phase-5 read-side primitive: it
// tries EACH of the reader's keystore keypairs ([]DecryptKey) against the
// EnvelopedData's RecipientInfos and returns the cleartext from the first
// serial-match that fully decrypts — covering key rollover and encrypt-to-self,
// where the reader holds several certs. ErrNoMatchingKey is returned otherwise
// (the webmail "wrong/rotated key" read-state); it is DISTINCT only from a
// malformed-CMS parse error returned before the match loop, so callers tell "you
// don't hold the key" from "the blob is corrupt". To deny a Bleichenbacher PKCS#1
// v1.5 padding oracle, the session-key unwrap uses rsa.DecryptPKCS1v15SessionKey
// with a random fixed-length fallback (NOT rsa.DecryptPKCS1v15, whose error leaks
// padding validity), and a matched-but-failing unwrap/body is collapsed into
// ErrNoMatchingKey so invalid-padding and wrong-key are indistinguishable to the
// caller (TestDecryptMulti_NoPaddingOracle). The single-key Decrypt() got the same
// fix — both share the extracted decryptBody().
// DecodeEnvelopedDER() normalizes either the application/pkcs7-mime MIME/base64
// wire form OR bare DER (e.g. `openssl cms -encrypt -outform DER`) into the
// EnvelopedData DER these consume. The REVERSE openssl oracle
// (TestReverseOracle_OpensslEncryptThenOurDecrypt) proves the inverse of E1: an
// EnvelopedData produced by an external sender's openssl opens via DecryptMulti —
// the property hosted decrypt-on-read depends on.
//
// NOTE: Sign() output is NOT round-trippable through VerifyDetached/ietf-cms —
// outbound only, verified externally via openssl/external MUAs, never through
// our own VerifyDetached.
package smime
