package jmap

import (
	"crypto/x509"
	"fmt"

	"setjoin.com/mailserver/internal/smime"
)

// buildSMIMEWire is the ONE owner of the outbound submission byte-pipeline order
// for a single draft: assemble (multipart/mixed when the draft carries attachment
// parts) → sign (inner, S/MIME) → encrypt (outer envelope). signOneSubmission,
// poolEncryptOps.SignAndEncrypt and the plain-attachment assembler all express
// their byte handling through this composition, so the assemble-then-sign
// ordering cannot silently diverge per caller again (the W0/#4 data-loss bug:
// sign/encrypt used to process the body-only draft and the attachment assembler
// skipped already-processed creations — a signed/encrypted send with attachments
// shipped without them).
//
// draftRaw is the draft's raw RFC 5322 bytes (inline text for reducer-built
// drafts). parts are the draft's attachments (nil/empty = none). candidates +
// fromAddr drive the inner sign (sign=false skips it); encryptCerts non-empty
// applies the outer CMS envelope.
//
// Returns (wire, "", nil) on success; ("", reason, nil) for a sign-resolution
// failure (one of smime.Reason*); ("", "", err) for an assembly/crypto error.
func buildSMIMEWire(
	draftRaw []byte,
	parts []attachmentPart,
	candidates []smime.SignCandidate,
	fromAddr string,
	sign bool,
	encryptCerts []*x509.Certificate,
) (wire []byte, reason string, err error) {
	content := draftRaw

	// 1) ASSEMBLE first (W0/#4 assemble-then-sign): the multipart/mixed wire is
	// built BEFORE any signing/encryption so the crypto always covers the
	// attachments. When the result will be signed, the sign input is laid out as
	// top-headers + blank line + ENTITY (the multipart/mixed Content-Type header
	// + body): ResolveAndSign strips everything before the first blank line, so
	// the content headers ride INSIDE the signed part and SignMessage's re-wrap
	// preserves the inner multipart/mixed Content-Type — the receiver can parse
	// the attachments out of the verified content.
	if len(parts) > 0 {
		top, entity, aerr := assembleMixedParts(string(draftRaw), parts)
		if aerr != nil {
			return nil, "", fmt.Errorf("assemble mime: %w", aerr)
		}
		if sign {
			content = []byte(top + "\r\n" + entity)
		} else {
			content = []byte(top + "MIME-Version: 1.0\r\n" + entity)
		}
	}

	// 2) SIGN (inner).
	if sign {
		signed, sreason := smime.ResolveAndSign(candidates, fromAddr, content)
		if sreason != "" {
			return nil, sreason, nil
		}
		content = signed
	}

	// 3) ENCRYPT (outer envelope).
	if len(encryptCerts) > 0 {
		enc, eerr := smime.Encrypt(content, encryptCerts)
		if eerr != nil {
			return nil, "", eerr
		}
		content = enc
	}

	return content, "", nil
}
