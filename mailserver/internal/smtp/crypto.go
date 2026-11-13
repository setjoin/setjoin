package smtp

import (
	"strings"
)

// CryptoType indicates what kind of cryptographic envelope a message has.
type CryptoType string

const (
	CryptoNone           CryptoType = "none"
	CryptoSMIMESigned    CryptoType = "smime-signed"
	CryptoSMIMEEncrypted CryptoType = "smime-encrypted"
	CryptoPGPSigned      CryptoType = "pgp-signed"
	CryptoPGPEncrypted   CryptoType = "pgp-encrypted"
)

// DetectCrypto inspects Content-Type headers to determine if a message
// uses S/MIME or PGP.
func DetectCrypto(msg string) CryptoType {
	ct := strings.ToLower(extractHeader(msg, "Content-Type"))

	if strings.Contains(ct, "application/pkcs7-mime") {
		if strings.Contains(ct, "smime-type=signed-data") {
			return CryptoSMIMESigned
		}
		return CryptoSMIMEEncrypted
	}
	if strings.Contains(ct, "application/pkcs7-signature") {
		return CryptoSMIMESigned
	}
	if strings.Contains(ct, "multipart/signed") && strings.Contains(ct, "protocol=\"application/pkcs7-signature\"") {
		return CryptoSMIMESigned
	}

	if strings.Contains(ct, "application/pgp-encrypted") {
		return CryptoPGPEncrypted
	}
	if strings.Contains(ct, "application/pgp-signature") {
		return CryptoPGPSigned
	}
	if strings.Contains(ct, "multipart/encrypted") && strings.Contains(ct, "protocol=\"application/pgp-encrypted\"") {
		return CryptoPGPEncrypted
	}
	if strings.Contains(ct, "multipart/signed") && strings.Contains(ct, "protocol=\"application/pgp-signature\"") {
		return CryptoPGPSigned
	}

	return CryptoNone
}
