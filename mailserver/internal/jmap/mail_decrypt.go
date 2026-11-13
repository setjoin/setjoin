package jmap

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"strconv"

	"setjoin.com/mailserver/internal/smime"
)

// mail_decrypt.go — SP1 Phase 5: decrypt-on-read for the webmail/JMAP read path.
//
// Encrypted mail is stored encrypted-at-rest (Phase 3/4): the messages row has
// crypto_type='smime-encrypted', body_text/body_html=NULL, and raw_ref points at
// the EnvelopedData blob in S3. IMAP serves that blob VERBATIM (the client's own
// key decrypts it — see internal/imap). The webmail/JMAP path instead does hosted
// decrypt-on-read here: after Email/get returns, for each encrypted email we load
// the READER's keystore keys, fetch the raw_ref blob, smime.DecryptMulti it (try
// ALL the reader's keys — key rollover + encrypt-to-self), and inject TRANSIENT
// cleartext into the response. Plaintext is NEVER persisted; a failed decrypt is a
// calm read-state (no_key / wrong_key / error), never a 5xx. Each successful
// decrypt is audited (email_decrypt_read) and the whole pass is cost-bounded.

// decryptState values are the stable strings the webmail D-F1 read-states key on.
const (
	decryptStateDecrypted = "decrypted" // body injected; show the "Encrypted" indicator
	decryptStateNoKey     = "no_key"    // reader has no keystore key → "open in your client"
	decryptStateWrongKey  = "wrong_key" // rotated/foreign cert → "no longer have"
	decryptStateError     = "error"     // malformed CMS / cost-bound / blob fetch → calm generic
)

const cryptoTypeSMIMEEncrypted = "smime-encrypted"

// decryptAllowed gates one decrypt-on-read op for a user against the per-user cost
// bound. Returns false when the budget is exhausted (the caller then serves the
// encrypted read-state, NOT an error — fail-closed-to-ciphertext, never plaintext).
// A nil limiter allows (unit-test / unconfigured).
func (h *JMAPHandler) decryptAllowed(userID int64) bool {
	if h.decryptLimiter == nil {
		return true
	}
	return h.decryptLimiter.Allow("decrypt:" + strconv.FormatInt(userID, 10))
}

// parseDecryptCandidate turns a (certPEM, keyPEM) pair into a smime.DecryptKey.
// It is pure (no I/O) so the skip rules are unit-testable without a DB: an
// unparseable cert PEM, an unparseable key PEM, or a non-RSA key all yield
// ok=false (never a usable candidate). The key is parsed as PKCS#1 then PKCS#8.
func parseDecryptCandidate(certPEM, keyPEM string) (smime.DecryptKey, bool) {
	if certPEM == "" || keyPEM == "" {
		return smime.DecryptKey{}, false
	}
	cert, err := smime.ParseCert([]byte(certPEM))
	if err != nil {
		return smime.DecryptKey{}, false
	}
	keyAny, err := smime.ParsePrivateKey([]byte(keyPEM))
	if err != nil {
		return smime.DecryptKey{}, false
	}
	rsaKey, ok := keyAny.(*rsa.PrivateKey)
	if !ok {
		return smime.DecryptKey{}, false
	}
	return smime.DecryptKey{Cert: cert, Key: rsaKey}, true
}

// loadDecryptKeys returns the reading user's keystore keypairs (parsed cert +
// decrypted RSA key) for decrypt-on-read. R1-scoped by user_id. The pgp_sym_decrypt
// of the private key relies on the app.encryption_key GUC carried on h.pool (same
// as loadSignCandidates). Rows with a NULL/empty key, an unparseable PEM, or a
// non-RSA key are skipped via parseDecryptCandidate (never a usable candidate).
// With a nil pool (unit-test mode) it returns no keys, no error.
func (h *JMAPHandler) loadDecryptKeys(ctx context.Context, userID int64) ([]smime.DecryptKey, error) {
	if h.pool == nil {
		return nil, nil
	}
	// private_key_enc is a TEXT column holding the bytea-hex of pgp_sym_encrypt's
	// output (the admin/self-service write stores the bytea result into text). The
	// ::bytea cast is REQUIRED: pgp_sym_decrypt has no (text, text) overload, so an
	// uncast text arg raises "function pgp_sym_decrypt(text, text) does not exist".
	rows, err := h.pool.Query(ctx,
		`SELECT cert_pem,
		        pgp_sym_decrypt(private_key_enc::bytea, current_setting('app.encryption_key'))
		 FROM user_smime_certs
		 WHERE user_id = $1 AND private_key_enc IS NOT NULL`,
		userID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []smime.DecryptKey
	for rows.Next() {
		var certPEM, keyPEM string
		if err := rows.Scan(&certPEM, &keyPEM); err != nil {
			return nil, err
		}
		if dk, ok := parseDecryptCandidate(certPEM, keyPEM); ok {
			out = append(out, dk)
		}
	}
	return out, rows.Err()
}

// decryptEmailResult rewrites the Email/get JSON in place: for each email with
// cryptoType=="smime-encrypted" it performs decrypt-on-read and sets a
// "decryptState" field (plus transient bodyText/bodyHTML/preview on success). It
// NEVER persists plaintext and NEVER returns an error to the caller — a failed
// decrypt is a read-state, not a 5xx. On any structural parse failure it returns
// the input unchanged (fail to the reducer's authoritative response).
//
// The per-email decrypt is gated by decryptAllowed; a denied op yields the calm
// "error" state (fail-closed-to-ciphertext). Each successful decrypt is audited
// against mailboxID — the caller's authenticated PRIMARY mailbox (the reducer is
// scoped to that account), which is a genuine mailboxes(id) the audit FK accepts.
func (h *JMAPHandler) decryptEmailResult(ctx context.Context, userID, mailboxID int64, result json.RawMessage) json.RawMessage {
	var resp map[string]json.RawMessage
	if err := json.Unmarshal(result, &resp); err != nil {
		return result
	}
	listRaw, ok := resp["list"]
	if !ok || len(listRaw) == 0 {
		return result
	}
	var list []map[string]json.RawMessage
	if err := json.Unmarshal(listRaw, &list); err != nil {
		return result
	}

	// Load the reader's keystore keys ONCE for the whole batch (not per email).
	// A nil/empty set means every encrypted email resolves to no_key.
	var keys []smime.DecryptKey
	keysLoaded := false

	changed := false
	for _, email := range list {
		ct := jsonString(email["cryptoType"])
		if ct != cryptoTypeSMIMEEncrypted {
			continue // not encrypted: leave entirely untouched
		}
		changed = true

		// Cost bound: a denied op serves the encrypted read-state, never plaintext.
		if !h.decryptAllowed(userID) {
			setDecryptState(email, decryptStateError)
			continue
		}

		if !keysLoaded {
			loaded, err := h.loadDecryptKeys(ctx, userID)
			if err != nil {
				h.logger.Error("smime: decrypt-on-read key load failed", "user_id", userID, "error", err)
				keys = nil // fall through to no_key/error states; never leak plaintext
			} else {
				keys = loaded
			}
			keysLoaded = true
		}
		if len(keys) == 0 {
			setDecryptState(email, decryptStateNoKey)
			continue
		}

		blobID := jsonString(email["blobId"])
		state := h.decryptOneEmail(ctx, userID, mailboxID, email, blobID, keys)
		setDecryptState(email, state)
	}

	if !changed {
		return result // byte-identical when nothing was encrypted
	}

	newList, err := json.Marshal(list)
	if err != nil {
		return result
	}
	resp["list"] = newList
	out, err := json.Marshal(resp)
	if err != nil {
		return result
	}
	return out
}

// decryptOneEmail fetches the EnvelopedData blob and tries the reader's keys.
// It mutates email in place with the transient cleartext on success and returns
// the decryptState. It NEVER persists plaintext. keys is guaranteed non-empty.
// mailboxID is the caller's authenticated mailbox — the audit row's mailbox_id.
func (h *JMAPHandler) decryptOneEmail(
	ctx context.Context,
	userID, mailboxID int64,
	email map[string]json.RawMessage,
	blobID string,
	keys []smime.DecryptKey,
) string {
	if blobID == "" || h.minio == nil {
		// No blob to fetch (or no S3 in unit-test mode): can't decrypt → calm error.
		return decryptStateError
	}

	artifact, err := h.fetchBlob(ctx, blobID)
	if err != nil {
		h.logger.Error("smime: decrypt-on-read blob fetch failed", "blob_id", blobID, "error", err)
		return decryptStateError
	}
	der, err := smime.DecodeEnvelopedDER(artifact)
	if err != nil {
		h.logger.Warn("smime: decrypt-on-read blob is not a valid EnvelopedData artifact", "blob_id", blobID, "error", err)
		return decryptStateError
	}

	plaintext, err := smime.DecryptMulti(der, keys)
	switch {
	case err == nil:
		injectCleartext(email, plaintext)
		// Audit the successful server-side decrypt (action keyed by the message id).
		// mailboxID is the caller's authenticated PRIMARY mailbox — a real
		// mailboxes(id) the audit FK accepts (NOT the tag_id-keyed mailboxIds).
		if id, ok := parseInt64(jsonString(email["id"])); ok {
			h.auditMailbox(ctx, userID, mailboxID, "email_decrypt_read", &id)
		} else {
			h.auditMailbox(ctx, userID, mailboxID, "email_decrypt_read", nil)
		}
		return decryptStateDecrypted
	case isNoMatchingKey(err):
		return decryptStateWrongKey
	default:
		h.logger.Warn("smime: decrypt-on-read failed", "blob_id", blobID, "error", err)
		return decryptStateError
	}
}

// isNoMatchingKey reports whether err is smime.ErrNoMatchingKey.
func isNoMatchingKey(err error) bool {
	return errors.Is(err, smime.ErrNoMatchingKey)
}

// --- small JSON helpers ---

// jsonString decodes a JSON string value, returning "" for null/absent/non-string.
func jsonString(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return ""
	}
	return s
}

func parseInt64(s string) (int64, bool) {
	if s == "" {
		return 0, false
	}
	v, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0, false
	}
	return v, true
}

func setDecryptState(email map[string]json.RawMessage, state string) {
	b, _ := json.Marshal(state)
	email["decryptState"] = b
}

// injectCleartext writes the transient decrypted body into the email's bodyText
// (and a short preview). It does NOT touch the DB — this is response-only. The
// decrypted bytes are the inner (possibly signed) MIME message; we expose them as
// bodyText so the webmail can render them. We deliberately do NOT set bodyHTML:
// the cleartext may be a full MIME part, and rendering it as raw HTML in the
// reading pane is unsafe; bodyText keeps the existing iframe-sandbox barrier the
// primary defense. The preview is a short, escaped-by-JSON snippet.
func injectCleartext(email map[string]json.RawMessage, plaintext []byte) {
	bt, _ := json.Marshal(string(plaintext))
	email["bodyText"] = bt
	prev := plaintext
	if len(prev) > 256 {
		prev = prev[:256]
	}
	pv, _ := json.Marshal(string(prev))
	email["preview"] = pv
}
