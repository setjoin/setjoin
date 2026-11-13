package jmap

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/minio/minio-go/v7"

	"setjoin.com/mailserver/internal/blob"
	"setjoin.com/mailserver/internal/smime"
)

// mail_smime.go — Phase D: outbound S/MIME signing at submission time.
//
// EmailSubmission/set previously deferred signing to the SMTP OutboundWorker.
// Phase D re-homes it here: for each creation that requested signSMIME, the
// handler resolves the user's signing cert by From↔SAN match, fetches the draft
// blob, signs it (reusing smime.ResolveAndSign — the SAME byte-handling as the
// worker so external MUAs still accept the signature), stores the signed blob,
// and feeds the new blob key to the p_processed_raw_ref swap seam on the reducer
// (renamed from p_signed_raw_ref in V027; mail_encrypt.go also threads p_is_encrypted).
//
// signSMIME is STRIPPED from every creation before the reducer call so the
// (still-present, now dormant) worker signing path never double-signs. The worker
// code + reducer plumbing are removed in Task D3, not here.
//
// Sign failures become per-creationId notCreated[*].{type,description} entries
// built Go-side (the reducer can't see them — signing happens before the call)
// and merged into the reducer's returned SetResponse.

// maxSignSize caps the draft blob we will pull into memory to sign. A draft over
// this is left unsigned (smime_sign_failed) rather than risk an OOM on the request
// path. 50 MiB comfortably exceeds any reasonable mail size.
const maxSignSize = 50 << 20

// signSubmissionTimeout bounds the S3 fetch + sign + store per creation so a slow
// object store can't pin a request thread.
const signSubmissionTimeout = 10 * time.Second

// smimeNotCreatedDescription maps a smime reason marker to a human one-liner for
// the notCreated entry's description.
func smimeNotCreatedDescription(reason string) string {
	switch reason {
	case smime.ReasonNoCert:
		return "S/MIME signing was requested but you have no usable signing certificate."
	case smime.ReasonNoMatchingCert:
		return "S/MIME signing was requested but none of your certificates matches the From address."
	case smime.ReasonSignFailed:
		return "S/MIME signing was requested but the message could not be signed."
	case smime.ReasonEncryptNoCert:
		return "Encryption was requested but no usable certificate is available for one or more recipients."
	case smime.ReasonEncryptNoSenderCert:
		return "Encryption was requested but you have no usable encryption certificate (needed so you can read your own sent copy)."
	case smime.ReasonEncryptNoJournalCert:
		return "Encryption was requested but no journal certificate is configured, and this domain requires journaling."
	default:
		return "S/MIME signing failed."
	}
}

// stripSignSMIME returns a copy of a creation's JSON object with the "signSMIME"
// key removed, so the dormant worker path never re-signs. It is a pure function:
// no I/O. On any unmarshal error it returns the input unchanged (the reducer will
// reject malformed input on its own terms).
func stripSignSMIME(creation json.RawMessage) json.RawMessage {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(creation, &obj); err != nil {
		return creation
	}
	if _, ok := obj["signSMIME"]; !ok {
		return creation
	}
	delete(obj, "signSMIME")
	out, err := json.Marshal(obj)
	if err != nil {
		return creation
	}
	return out
}

// mergeNotCreated merges Go-side notCreated entries (keyed by creationId, each a
// {type, description} object) into the reducer's SetResponse JSON, returning the
// re-marshaled result. It is a pure function. When goNotCreated is empty it returns
// result unchanged. On any parse failure it returns result unchanged (fail-open to
// the reducer's authoritative response rather than dropping it).
func mergeNotCreated(result json.RawMessage, goNotCreated map[string]json.RawMessage) json.RawMessage {
	if len(goNotCreated) == 0 {
		return result
	}
	var resp map[string]json.RawMessage
	if err := json.Unmarshal(result, &resp); err != nil {
		return result
	}
	existing := map[string]json.RawMessage{}
	if raw, ok := resp["notCreated"]; ok && len(raw) > 0 {
		// Ignore a non-object notCreated (e.g. null) — start from empty.
		_ = json.Unmarshal(raw, &existing)
	}
	for id, entry := range goNotCreated {
		existing[id] = entry
	}
	merged, err := json.Marshal(existing)
	if err != nil {
		return result
	}
	resp["notCreated"] = merged
	out, err := json.Marshal(resp)
	if err != nil {
		return result
	}
	return out
}

// signSubmissions performs the Phase-D signing pass over a parsed create map.
// For every creation with signSMIME==true it resolves+signs+stores and records a
// signedRef (creationId→signed-blob-key); failures are recorded in notCreated and
// the creation is DROPPED from the returned create map (so it is not submitted).
// signSMIME is stripped from every surviving creation.
//
// It returns the (possibly trimmed) create map, the signedRefs map, and the
// Go-side notCreated map. The infra (h.pool, h.minio) is required: if either is
// nil it strips signSMIME from all creations and returns no signedRefs (the
// unit-test / no-infra shape — signing is simply not performed).
func (h *JMAPHandler) signSubmissions(
	ctx context.Context,
	userID int64,
	accountID int64,
	create map[string]json.RawMessage,
) (modified map[string]json.RawMessage, signedRefs map[string]string, notCreated map[string]json.RawMessage) {
	modified = make(map[string]json.RawMessage, len(create))
	signedRefs = map[string]string{}
	notCreated = map[string]json.RawMessage{}

	for creationID, raw := range create {
		var sub struct {
			SignSMIME bool   `json:"signSMIME"`
			EmailID   string `json:"emailId"`
		}
		// A malformed creation is left for the reducer to reject; pass it through.
		if err := json.Unmarshal(raw, &sub); err != nil {
			modified[creationID] = raw
			continue
		}
		if !sub.SignSMIME {
			modified[creationID] = raw
			continue
		}

		// signSMIME requested. Without infra we cannot sign — strip the flag so
		// the dormant worker path doesn't fire, and leave the draft unsigned.
		if h.pool == nil || h.minio == nil {
			modified[creationID] = stripSignSMIME(raw)
			continue
		}

		key, reason := h.signOneSubmission(ctx, userID, accountID, sub.EmailID)
		switch {
		case reason != "":
			// Sign failure: surface notCreated and DROP this creation entirely.
			entry, _ := json.Marshal(map[string]string{
				"type":        reason,
				"description": smimeNotCreatedDescription(reason),
			})
			notCreated[creationID] = entry
			// dropped: not added to modified
		case key == "":
			// Nothing to sign (draft not found, or already signed): pass through
			// with signSMIME stripped so the reducer/worker handle it unsigned.
			modified[creationID] = stripSignSMIME(raw)
		default:
			// Signed and stored: record the swap ref, strip the flag.
			signedRefs[creationID] = key
			modified[creationID] = stripSignSMIME(raw)
		}
	}
	return modified, signedRefs, notCreated
}

// classifyDraftLoadErr decides what a draft-load query error means for signing.
// It is a pure function (no I/O) so the fail-closed decision is unit-testable
// without a DB:
//   - pgx.ErrNoRows → ("", "") — the draft genuinely isn't there / isn't owned;
//     leave it for the reducer to emit notFound. There is simply nothing to sign.
//   - any other error (transient connection blip, context-cancel, ...) →
//     ("", smime.ReasonSignFailed) — MUST fail CLOSED. The user requested a
//     signature; sending unsigned because the load hiccuped is a trust bug.
func classifyDraftLoadErr(err error) (signedRef string, reason string) {
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ""
	}
	return "", smime.ReasonSignFailed
}

// signOneSubmission loads the draft + the user's cert candidates, fetches the draft
// blob, signs it, and stores the signed blob. It returns (blobKey, "") on success;
// ("", "") when there is nothing to sign (draft not found, or the draft is already
// S/MIME-signed); and ("", reason) on a sign failure (one of smime.Reason*).
//
// Security: both queries are R1-scoped — the draft by (id, mailbox_id=accountID)
// and the certs by user_id — never by req.* or by the users.email=From join. The
// app.encryption_key GUC needed by pgp_sym_decrypt is carried by h.workerPool's
// AfterConnect hook (same db pool builder as h.pool). Messages queries run on
// h.workerPool (BYPASSRLS) to survive the W6 FORCE flip; inline R1 scoping retained.
func (h *JMAPHandler) signOneSubmission(
	ctx context.Context,
	userID int64,
	accountID int64,
	emailID string,
) (blobKey, reason string) {
	if emailID == "" {
		return "", "" // nothing to load; reducer will reject if required
	}

	// Load the draft (From + raw_ref + attachment flag), R1-scoped by mailbox. On
	// workerPool (BYPASSRLS) so the inline mailbox_id predicate survives the W6
	// FORCE flip without a GUC.
	var fromAddr, rawRef string
	var receivedAt time.Time
	var hasAttach bool
	err := h.workerPool.QueryRow(ctx,
		`SELECT from_addr, raw_ref, received_at, has_attachments FROM messages WHERE id = $1 AND mailbox_id = $2`,
		emailID, accountID,
	).Scan(&fromAddr, &rawRef, &receivedAt, &hasAttach)
	if err != nil {
		ref, reason := classifyDraftLoadErr(err)
		if reason != "" {
			// A transient/connection error (NOT a clean not-found) must fail
			// CLOSED: the user asked to sign, so dropping signSMIME and sending
			// unsigned would be a fail-open trust bug.
			h.logger.Error("smime: draft load failed", "email_id", emailID, "error", err)
		}
		return ref, reason
	}

	// Load the user's signing-cert candidates, R1-scoped by user_id. Decrypt the
	// private key with the app.encryption_key GUC carried on this pool connection.
	candidates, err := h.loadSignCandidates(ctx, userID)
	if err != nil {
		h.logger.Error("smime: candidate cert load failed", "user_id", userID, "error", err)
		return "", smime.ReasonSignFailed
	}

	// Bound the S3 fetch + sign + store so a slow store can't pin the request.
	ctx2, cancel := context.WithTimeout(ctx, signSubmissionTimeout)
	defer cancel()

	// W0/#4 assemble-then-sign: a draft WITH attachments is signed over its
	// ASSEMBLED multipart/mixed wire — never over the body-only draft (which
	// silently shipped without the attachments). Any attachment-load failure
	// fails CLOSED: never sign-and-send a message missing its attachments.
	var parts []attachmentPart
	if hasAttach {
		parts, err = h.loadDraftAttachmentParts(ctx2, emailID, receivedAt)
		if err != nil {
			h.logger.Error("smime: attachment load for sign failed", "email_id", emailID, "error", err)
			return "", smime.ReasonSignFailed
		}
	}
	// W5 raw_ref convention: the draft raw is resolved by what the ref IS
	// (inline RFC 5322 text vs MinIO key — blob.IsInlineMessage), never by
	// whether attachments happen to exist. Pre-fix, no-attachment reducer
	// drafts (inline refs) were GetObject'ed and every sign failed.
	raw, err := h.rawFromRef(ctx2, rawRef)
	if err != nil {
		h.logger.Error("smime: draft blob fetch failed", "raw_ref", rawRef, "error", err)
		return "", smime.ReasonSignFailed
	}
	if len(raw) > maxSignSize {
		h.logger.Warn("smime: draft over sign size cap, leaving unsigned", "size", len(raw))
		return "", smime.ReasonSignFailed
	}
	// Idempotency: a no-attachment draft that is already S/MIME-signed is left
	// as-is (with parts the wire is assembled fresh, as before).
	if len(parts) == 0 && smime.IsSignedMessage(raw) {
		return "", ""
	}

	signed, reason, err := buildSMIMEWire(raw, parts, candidates, fromAddr, true, nil)
	if err != nil {
		h.logger.Error("smime: sign wire build failed", "email_id", emailID, "error", err)
		return "", smime.ReasonSignFailed
	}
	if reason != "" {
		return "", reason
	}

	// Store the signed blob under its content hash (the messages.raw_ref
	// convention: raw_ref IS the sha256 hex of the blob — see spam/store.go,
	// blob upload, admin import/export).
	sum := sha256.Sum256(signed)
	key := hex.EncodeToString(sum[:])
	if _, err := h.minio.PutObject(ctx2, h.bucket, key,
		bytes.NewReader(signed), int64(len(signed)),
		minio.PutObjectOptions{ContentType: "message/rfc822"}); err != nil {
		h.logger.Error("smime: signed blob store failed", "error", err)
		return "", smime.ReasonSignFailed
	}
	return key, ""
}

// loadSignCandidates returns the user's S/MIME signing certs (cleartext cert PEM +
// decrypted key PEM). R1-scoped by user_id. The decrypt relies on the
// app.encryption_key GUC on the pool connection (set by the db pool AfterConnect
// hook). Rows with a NULL/empty decrypted key are skipped (never returns a NULL
// decrypt as a usable candidate).
func (h *JMAPHandler) loadSignCandidates(ctx context.Context, userID int64) ([]smime.SignCandidate, error) {
	// private_key_enc is a TEXT column holding the bytea-hex of pgp_sym_encrypt's
	// output; the ::bytea cast is REQUIRED (pgp_sym_decrypt has no (text, text)
	// overload — without it the query raises "function pgp_sym_decrypt(text, text)
	// does not exist" and ALL signing fails). Matches every other decrypt site in
	// the codebase (authserver totp.go/push.go) and the P5 loadDecryptKeys.
	rows, err := h.pool.Query(ctx,
		`SELECT cert_pem,
		        pgp_sym_decrypt(private_key_enc::bytea, current_setting('app.encryption_key')),
		        is_default
		 FROM user_smime_certs
		 WHERE user_id = $1 AND private_key_enc IS NOT NULL`,
		userID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []smime.SignCandidate
	for rows.Next() {
		var certPEM, keyPEM string
		var isDefault bool
		if err := rows.Scan(&certPEM, &keyPEM, &isDefault); err != nil {
			return nil, err
		}
		if certPEM == "" || keyPEM == "" {
			continue
		}
		out = append(out, smime.SignCandidate{
			CertPEM:   []byte(certPEM),
			KeyPEM:    []byte(keyPEM),
			IsDefault: isDefault,
		})
	}
	return out, rows.Err()
}

// rawFromRef resolves the RFC 5322 bytes a draft's raw_ref denotes: the ref
// itself when it is the inline message text (reducer-built drafts store the
// full message in messages.raw_ref — see blob.IsInlineMessage for the producer
// map + why a line break is the discriminator), else the MinIO blob it keys.
// The single raw-resolution seam for the sign AND encrypt paths.
func (h *JMAPHandler) rawFromRef(ctx context.Context, rawRef string) ([]byte, error) {
	if blob.IsInlineMessage(rawRef) {
		return []byte(rawRef), nil
	}
	return h.fetchBlob(ctx, rawRef)
}

// fetchBlob reads an object from the configured bucket into memory. The read is
// BOUNDED at maxSignSize+1 bytes (via io.LimitReader, the auth/jwks.go pattern):
// the caller's len(raw) > maxSignSize guard then rejects an oversized blob —
// but the whole (possibly huge) object is never pulled into RAM first.
func (h *JMAPHandler) fetchBlob(ctx context.Context, key string) ([]byte, error) {
	obj, err := h.minio.GetObject(ctx, h.bucket, key, minio.GetObjectOptions{})
	if err != nil {
		return nil, err
	}
	defer obj.Close()
	return io.ReadAll(io.LimitReader(obj, maxSignSize+1))
}
