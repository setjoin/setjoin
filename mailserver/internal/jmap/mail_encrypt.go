package jmap

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/minio/minio-go/v7"

	"setjoin.com/mailserver/internal/smime"
)

// mail_encrypt.go — SP1 Phase 3: outbound S/MIME ENCRYPTION at submission time.
//
// Phase D re-homed SIGNING to EmailSubmission/set; this extends that into a
// combined processSubmissions pass: after the (optional) inner SIGN, when
// encryptSMIME is requested, the handler resolves every recipient cert + the
// sender's own cert (encrypt-to-self) + (when journaling is required for the
// sender's domain) the journal cert, builds the dedup'd cert set, encrypts the
// signed-or-draft blob to it (outer), stores the ciphertext, and feeds the
// reducer processedRefs + isEncrypted. DLP/rules still scan the cleartext inside
// send()/deliver() (the reducer is handed the cleartext bodies; it stores NULL).
//
// FAIL-CLOSED: encrypt requested + ANY recipient/sender/journal cert missing →
// per-creationId notCreated, the creation is DROPPED, nothing is sent, never
// plaintext. Encrypt-step errors are treated the same (fail closed).

// smimeEncryptOps is the I/O seam the encrypt path needs: cert resolution, the
// draft envelope, the journal lookups, and the sign+encrypt+store blob op. The
// production impl (poolEncryptOps) wraps h.pool / h.minio / smime.*; tests stub
// it so processSubmissions' fail-closed decision tree runs with no DB / no S3.
type smimeEncryptOps interface {
	// ResolveEncryptCert resolves the cert to encrypt TO for one address, scoped
	// to the sender. ok=false (fail-closed) when none qualifies. The SAME shared
	// predicate (smime.IsEncryptionCapable) the submission check uses.
	ResolveEncryptCert(ctx context.Context, senderUserID int64, email string) (*x509.Certificate, bool)
	// SenderInfo returns the draft's From address, the sender's domain id, and the
	// flat recipient list (to+cc+bcc). ok=false when the draft can't be loaded.
	SenderInfo(ctx context.Context, accountID int64, emailID string) (fromAddr string, domainID int64, recipients []string, ok bool)
	// JournalingRequired reports whether the sender's domain requires journaling.
	JournalingRequired(ctx context.Context, domainID int64) (bool, error)
	// JournalCert returns the domain's journal cert: (cert, configured, err).
	// configured=false means journaling is required but no cert is set → fail closed.
	JournalCert(ctx context.Context, domainID int64) (*x509.Certificate, bool, error)
	// SignAndEncrypt loads the draft blob, signs it (inner) when signRequested,
	// encrypts it (outer) to certs, stores the ciphertext content-addressed, and
	// returns the blob key. Any error → fail closed. accountID R1-scopes the draft
	// load (mailbox_id) per DATABASE_SECURITY.md.
	SignAndEncrypt(ctx context.Context, accountID int64, emailID string, certs []*x509.Certificate, signRequested bool) (string, error)
}

// buildEncryptCertSet unions the recipient certs with the sender's own cert
// (encrypt-to-self) and the journal cert (when non-nil), de-duplicated by SHA-256
// fingerprint. A nil sender / journal is omitted. Order is deterministic (sorted
// by fingerprint) so the same inputs always produce the same RecipientInfos set.
func buildEncryptCertSet(recipientCerts []*x509.Certificate, senderCert, journalCert *x509.Certificate) []*x509.Certificate {
	seen := map[string]struct{}{}
	var out []*x509.Certificate
	add := func(c *x509.Certificate) {
		if c == nil {
			return
		}
		fp := sha256.Sum256(c.Raw)
		k := hex.EncodeToString(fp[:])
		if _, dup := seen[k]; dup {
			return
		}
		seen[k] = struct{}{}
		out = append(out, c)
	}
	for _, c := range recipientCerts {
		add(c)
	}
	add(senderCert)
	add(journalCert)
	sort.Slice(out, func(i, j int) bool {
		fi := sha256.Sum256(out[i].Raw)
		fj := sha256.Sum256(out[j].Raw)
		return bytes.Compare(fi[:], fj[:]) < 0
	})
	return out
}

// stripSMIMEFlags removes BOTH signSMIME and encryptSMIME from a creation object
// so the dormant worker path never re-processes. Pure; returns input unchanged on
// any unmarshal error.
func stripSMIMEFlags(creation json.RawMessage) json.RawMessage {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(creation, &obj); err != nil {
		return creation
	}
	if _, a := obj["signSMIME"]; !a {
		if _, b := obj["encryptSMIME"]; !b {
			return creation
		}
	}
	delete(obj, "signSMIME")
	delete(obj, "encryptSMIME")
	out, err := json.Marshal(obj)
	if err != nil {
		return creation
	}
	return out
}

// processSubmissions is the combined sign+encrypt pass. Creations that do NOT
// request encryptSMIME are handled by the existing sign-only pass (signSubmissions:
// sign or passthrough, isEncrypted=false). Creations that DO request encryptSMIME
// run the fail-closed encrypt path here.
//
// Returns the (possibly trimmed) create map, processedRefs (creationId→final-blob
// key), isEncrypted (creationId→bool), and the Go-side notCreated map.
func (h *JMAPHandler) processSubmissions(
	ctx context.Context,
	userID int64,
	accountID int64,
	create map[string]json.RawMessage,
) (modified map[string]json.RawMessage, processedRefs map[string]string, isEncrypted map[string]bool, notCreated map[string]json.RawMessage) {
	processedRefs = map[string]string{}
	isEncrypted = map[string]bool{}
	notCreated = map[string]json.RawMessage{}

	// Split the encrypt-requested creations out; the rest go through the unchanged
	// sign-only pass so the Phase-D behavior (and its tests) are untouched.
	nonEncrypt := make(map[string]json.RawMessage, len(create))
	encrypt := make(map[string]json.RawMessage)
	for id, raw := range create {
		var probe struct {
			EncryptSMIME bool `json:"encryptSMIME"`
		}
		if err := json.Unmarshal(raw, &probe); err == nil && probe.EncryptSMIME {
			encrypt[id] = raw
			continue
		}
		nonEncrypt[id] = raw
	}

	modified = make(map[string]json.RawMessage, len(create))

	// Sign-only / no-S-MIME creations: existing pass. isEncrypted defaults false.
	if len(nonEncrypt) > 0 {
		signedMod, signedRefs, signNotCreated := h.signSubmissions(ctx, userID, accountID, nonEncrypt)
		for id, raw := range signedMod {
			modified[id] = raw
			isEncrypted[id] = false
		}
		for id, ref := range signedRefs {
			processedRefs[id] = ref
		}
		for id, nc := range signNotCreated {
			notCreated[id] = nc
		}
	}

	// Encrypt-requested creations: fail-closed encrypt (with optional inner sign).
	for id, raw := range encrypt {
		var sub struct {
			SignSMIME bool   `json:"signSMIME"`
			EmailID   string `json:"emailId"`
			Envelope  *struct {
				RcptTo []struct {
					Email string `json:"email"`
				} `json:"rcptTo"`
			} `json:"envelope"`
		}
		if err := json.Unmarshal(raw, &sub); err != nil {
			// Malformed: leave for the reducer to reject; don't encrypt.
			modified[id] = raw
			isEncrypted[id] = false
			continue
		}

		// Without the encrypt seam (nil ops / nil infra) we cannot encrypt. Fail
		// CLOSED: the user asked for confidentiality — drop, never send plaintext.
		if h.encryptOps == nil {
			notCreated[id] = h.encryptNotCreated(smime.ReasonEncryptNoCert, nil)
			continue
		}

		// An explicit SMTP envelope (rcptTo) is the AUTHORITATIVE delivery set:
		// jmap_email_submission_set delivers to envelope.rcptTo over the draft
		// to/cc/bcc headers. Encrypt to the SAME set so the recipient certs match
		// who actually receives the mail — otherwise an envelope-only recipient
		// gets ciphertext with no RecipientInfo (undecryptable), and a draft-only
		// header that isn't delivered could wrongly fail the send closed.
		var envelopeRcpts []string
		if sub.Envelope != nil {
			for _, r := range sub.Envelope.RcptTo {
				if r.Email != "" {
					envelopeRcpts = append(envelopeRcpts, r.Email)
				}
			}
		}

		ref, reason, noCertAddrs := h.encryptOneSubmission(ctx, userID, accountID, sub.EmailID, sub.SignSMIME, envelopeRcpts)
		if reason != "" {
			notCreated[id] = h.encryptNotCreated(reason, noCertAddrs)
			continue // DROPPED — not added to modified
		}
		processedRefs[id] = ref
		isEncrypted[id] = true
		modified[id] = stripSMIMEFlags(raw)
	}

	// Attachment assembly: any surviving creation NOT already processed by sign/encrypt
	// whose draft carries attachments gets its multipart/mixed wire blob assembled in Go
	// (the bytes only exist in MinIO) and swapped in via processedRefs. A failure drops
	// the creation into notCreated — never send a message missing its attachments.
	// (S/MIME + attachments: the sign/encrypt paths assemble the multipart/mixed wire
	// THEMSELVES before signing/enveloping — buildSMIMEWire's assemble-then-sign order,
	// W0/#4 — so a processedRef from those paths already carries the attachments and
	// this loop correctly skips it.)
	if h.pool != nil && h.minio != nil {
		for id, raw := range modified {
			if _, done := processedRefs[id]; done {
				continue
			}
			var sub struct {
				EmailID string `json:"emailId"`
			}
			if err := json.Unmarshal(raw, &sub); err != nil {
				continue
			}
			key, err := h.assembleAttachmentSubmission(ctx, accountID, sub.EmailID)
			if err != nil {
				h.logger.Error("attachment assembly failed", "creation", id, "email_id", sub.EmailID, "error", err)
				delete(modified, id)
				notCreated[id] = json.RawMessage(`{"type":"serverFail","description":"failed to assemble attachments"}`)
				continue
			}
			if key != "" {
				processedRefs[id] = key
			}
		}
	}

	return modified, processedRefs, isEncrypted, notCreated
}

// encryptNotCreated builds a per-creationId notCreated entry for an encrypt
// failure. addresses names the offending recipients for the no-cert marker so the
// (Phase 4) compose UX can list EVERY gap up front (D-F2 "names ALL recipients");
// the sender/journal markers carry no list (their copy is about the user's own
// cert / the admin, not a recipient roster) and pass addresses=nil. The compose
// UX MUST switch on the stable type, never render description (API/logs only).
func (h *JMAPHandler) encryptNotCreated(reason string, addresses []string) json.RawMessage {
	type entry struct {
		Type        string   `json:"type"`
		Description string   `json:"description"`
		Addresses   []string `json:"addresses,omitempty"`
	}
	e := entry{
		Type:        reason,
		Description: smimeNotCreatedDescription(reason),
		Addresses:   addresses,
	}
	raw, _ := json.Marshal(e)
	return raw
}

// encryptOneSubmission runs the fail-closed encrypt decision for one creation:
// resolve sender cert (encrypt-to-self), every recipient cert, and — when the
// domain requires journaling — the journal cert; then encrypt the signed-or-draft
// blob to the union set and store it. Returns (blobKey, "", nil) on success, or
// ("", reason, noCertAddrs) on any missing cert / encrypt failure (reason is one
// of smime.ReasonEncrypt*). noCertAddrs lists EVERY recipient that did not resolve
// when reason is ReasonEncryptNoCert (so the compose UX can name all gaps); it is
// nil for the sender / journal markers.
func (h *JMAPHandler) encryptOneSubmission(
	ctx context.Context,
	userID, accountID int64,
	emailID string,
	signRequested bool,
	envelopeRcpts []string,
) (blobKey, reason string, noCertAddrs []string) {
	ops := h.encryptOps

	fromAddr, domainID, recipients, ok := ops.SenderInfo(ctx, accountID, emailID)
	if !ok {
		// Draft not loadable → nothing to encrypt; fail closed (the reducer would
		// emit notFound, but the user requested encryption, so surface it as such).
		return "", smime.ReasonEncryptNoCert, nil
	}

	// Prefer the explicit SMTP envelope recipients (the delivery set) over the
	// draft to/cc/bcc headers — see the caller. fromAddr/domainID still come from
	// SenderInfo (encrypt-to-self + journaling are sender-scoped, not per-recipient).
	if len(envelopeRcpts) > 0 {
		recipients = envelopeRcpts
	}

	// Sender's own encrypt-to-self cert (so the Sent copy is readable).
	senderCert, ok := ops.ResolveEncryptCert(ctx, userID, smimeCanon(fromAddr))
	if !ok {
		return "", smime.ReasonEncryptNoSenderCert, nil
	}

	// Every recipient must resolve. Collect ALL missing before failing so the
	// (Phase 4) compose copy can list every gap, but ANY miss fails closed.
	var recipientCerts []*x509.Certificate
	var missing []string
	for _, r := range recipients {
		canon := smimeCanon(r)
		if canon == "" {
			continue
		}
		c, ok := ops.ResolveEncryptCert(ctx, userID, canon)
		if !ok {
			missing = append(missing, canon)
			continue
		}
		recipientCerts = append(recipientCerts, c)
	}
	if len(missing) > 0 {
		return "", smime.ReasonEncryptNoCert, missing
	}

	// Journal: when required for the domain, the journal cert MUST be configured
	// (encrypt-to-journal) or we fail closed (no plaintext archive).
	var journalCert *x509.Certificate
	required, err := ops.JournalingRequired(ctx, domainID)
	if err != nil {
		h.logger.Error("smime: journaling-required check failed", "domain_id", domainID, "error", err)
		return "", smime.ReasonEncryptNoCert, nil // fail closed on the gate query
	}
	if required {
		jc, configured, jerr := ops.JournalCert(ctx, domainID)
		if jerr != nil {
			h.logger.Error("smime: journal cert lookup failed", "domain_id", domainID, "error", jerr)
			return "", smime.ReasonEncryptNoCert, nil
		}
		if !configured {
			return "", smime.ReasonEncryptNoJournalCert, nil
		}
		// Run the journal cert through the SAME shared encryption-capable predicate
		// as recipient/sender certs. A signing-only / non-RSA journal cert would
		// otherwise pass here, fail later inside smime.Encrypt, and surface as the
		// user-facing ReasonEncryptNoCert (empty recipient list — blaming the
		// sender for an admin misconfiguration). Route it to the admin marker.
		if !smime.IsEncryptionCapable(jc) {
			return "", smime.ReasonEncryptNoJournalCert, nil
		}
		journalCert = jc
	}

	certs := buildEncryptCertSet(recipientCerts, senderCert, journalCert)
	if len(certs) == 0 {
		return "", smime.ReasonEncryptNoCert, nil
	}

	key, err := ops.SignAndEncrypt(ctx, accountID, emailID, certs, signRequested)
	if err != nil {
		h.logger.Error("smime: sign+encrypt+store failed", "email_id", emailID, "error", err)
		return "", smime.ReasonEncryptNoCert, nil // encrypt failure = fail closed
	}
	return key, "", nil
}

// smimeCanon canonicalizes an address WITHOUT a DB (lowercase + trim of a bare
// <a@b> form). The full alias-resolving canonicalization happens DB-side in the
// pool-backed ResolveEncryptCert; this is the no-DB normalization that keys the
// stub resolver and strips obvious display-name/angle-bracket noise.
func smimeCanon(addr string) string {
	s := strings.TrimSpace(addr)
	if i := strings.LastIndex(s, "<"); i >= 0 {
		if j := strings.Index(s[i:], ">"); j >= 0 {
			s = s[i+1 : i+j]
		}
	}
	return strings.ToLower(strings.TrimSpace(s))
}

// ── production seam: poolEncryptOps ─────────────────────────────────────────

// poolEncryptOps is the DB/S3-backed smimeEncryptOps. It is constructed lazily on
// the handler (h.encryptOps) when the infra is present.
type poolEncryptOps struct {
	h *JMAPHandler
}

func (p *poolEncryptOps) ResolveEncryptCert(ctx context.Context, senderUserID int64, email string) (*x509.Certificate, bool) {
	// The pool satisfies smime.Querier (QueryRow). ResolveRecipientCert applies the
	// shared encryption-capable predicate + alias canonicalization + the settled
	// revocation policy (admin blocklist; CRL source stays unwired → fail-open)
	// itself.
	return smime.ResolveRecipientCert(ctx, p.h.pool, senderUserID, email, &smime.RevocationOptions{
		MaxStaleness: smime.DefaultMaxCRLStaleness,
		Blocklist:    smime.BlocklistCheckFunc(p.h.pool),
	})
}

func (p *poolEncryptOps) SenderInfo(ctx context.Context, accountID int64, emailID string) (string, int64, []string, bool) {
	if emailID == "" {
		return "", 0, nil, false
	}
	var fromAddr string
	var domainID int64
	var toAddrs, ccAddrs, bccAddrs []byte
	// R1-scoped by mailbox. domain_id comes from the sending mailbox. On workerPool
	// (BYPASSRLS) so inline mailbox_id predicate survives the W6 FORCE flip.
	err := p.h.workerPool.QueryRow(ctx,
		`SELECT m.from_addr, mb.domain_id, m.to_addrs, m.cc_addrs, m.bcc_addrs
		   FROM messages m JOIN mailboxes mb ON mb.id = m.mailbox_id
		  WHERE m.id = $1 AND m.mailbox_id = $2`,
		emailID, accountID,
	).Scan(&fromAddr, &domainID, &toAddrs, &ccAddrs, &bccAddrs)
	if err != nil {
		return "", 0, nil, false
	}
	rcpts := append(extractEmails(toAddrs), extractEmails(ccAddrs)...)
	rcpts = append(rcpts, extractEmails(bccAddrs)...)
	return fromAddr, domainID, rcpts, true
}

func (p *poolEncryptOps) JournalingRequired(ctx context.Context, domainID int64) (bool, error) {
	var required bool
	err := p.h.pool.QueryRow(ctx,
		`SELECT journaling_required_for_domain($1)`, domainID).Scan(&required)
	return required, err
}

func (p *poolEncryptOps) JournalCert(ctx context.Context, domainID int64) (*x509.Certificate, bool, error) {
	var pem *string
	if err := p.h.pool.QueryRow(ctx,
		`SELECT journal_cert_pem_for_domain($1)`, domainID).Scan(&pem); err != nil {
		return nil, false, err
	}
	if pem == nil || *pem == "" {
		return nil, false, nil // required-but-unconfigured → caller fails closed
	}
	cert, err := smime.ParseCert([]byte(*pem))
	if err != nil {
		return nil, false, fmt.Errorf("smime: journal cert PEM unparseable: %w", err)
	}
	return cert, true, nil
}

func (p *poolEncryptOps) SignAndEncrypt(ctx context.Context, accountID int64, emailID string, certs []*x509.Certificate, signRequested bool) (string, error) {
	h := p.h

	// Load the draft (From + raw_ref + attachment flag), R1-scoped by mailbox. On
	// workerPool (BYPASSRLS) so inline mailbox_id predicate survives the W6 FORCE
	// flip without a GUC.
	var fromAddr, rawRef string
	var receivedAt time.Time
	var hasAttach bool
	if err := h.workerPool.QueryRow(ctx,
		`SELECT from_addr, raw_ref, received_at, has_attachments FROM messages WHERE id = $1 AND mailbox_id = $2`,
		emailID, accountID,
	).Scan(&fromAddr, &rawRef, &receivedAt, &hasAttach); err != nil {
		return "", fmt.Errorf("smime: draft load for encrypt failed: %w", err)
	}

	ctx2, cancel := context.WithTimeout(ctx, signSubmissionTimeout)
	defer cancel()

	// W0/#4 assemble-then-sign(-then-encrypt): a draft WITH attachments is
	// enveloped over its ASSEMBLED multipart/mixed wire — never the body-only
	// draft. Attachment-load failure fails CLOSED (never encrypt-and-send a
	// message missing its attachments).
	var parts []attachmentPart
	if hasAttach {
		var perr error
		parts, perr = h.loadDraftAttachmentParts(ctx2, emailID, receivedAt)
		if perr != nil {
			return "", fmt.Errorf("smime: attachment load for encrypt failed: %w", perr)
		}
	}
	// W5 raw_ref convention: resolve by what the ref IS (inline RFC 5322 text
	// vs MinIO key — the shared rawFromRef seam), never by attachment presence.
	// Pre-fix, no-attachment reducer drafts (inline refs) were GetObject'ed and
	// every encrypt failed closed with a misleading no-recipient-cert reason.
	raw, ferr := h.rawFromRef(ctx2, rawRef)
	if ferr != nil {
		return "", fmt.Errorf("smime: draft blob fetch for encrypt failed: %w", ferr)
	}
	if len(raw) > maxSignSize {
		return "", fmt.Errorf("smime: draft over size cap for encrypt: %d", len(raw))
	}

	// Inner SIGN (if requested) + outer ENCRYPT, through the single pipeline owner
	// (buildSMIMEWire: assemble → sign-inner → encrypt-outer).
	var candidates []smime.SignCandidate
	if signRequested {
		var cerr error
		candidates, cerr = h.loadSignCandidates(ctx2, mustUserOfMailbox(ctx2, h, accountID, emailID))
		if cerr != nil {
			return "", fmt.Errorf("smime: cert candidates for inner sign failed: %w", cerr)
		}
	}
	enc, reason, err := buildSMIMEWire(raw, parts, candidates, fromAddr, signRequested, certs)
	if reason != "" {
		return "", fmt.Errorf("smime: inner sign failed: %s", reason)
	}
	if err != nil {
		return "", fmt.Errorf("smime: encrypt failed: %w", err)
	}

	// Store the ciphertext content-addressed (raw_ref convention: sha256 hex).
	sum := sha256.Sum256(enc)
	key := hex.EncodeToString(sum[:])
	if _, err := h.minio.PutObject(ctx2, h.bucket, key,
		bytes.NewReader(enc), int64(len(enc)),
		minio.PutObjectOptions{ContentType: "message/rfc822"}); err != nil {
		return "", fmt.Errorf("smime: encrypted blob store failed: %w", err)
	}

	// SP1 Task 7.5 (quota-on-encrypted-size): the stored draft's size_bytes still
	// reflects the CLEARTEXT body it was created with; the wire/at-rest artifact is
	// now the (larger) CMS EnvelopedData blob. Update the draft size in-place to
	// len(enc) so jmap_email_submission_set's fresh v_msg.size_bytes SELECT (it runs
	// AFTER this Go pass) charges quota — and records size_bytes on the Sent /
	// recipient copies — against the encrypted artifact, never the cleartext.
	// R3: ownership (mailbox_id) in the same WHERE. On workerPool (BYPASSRLS).
	if _, err := h.workerPool.Exec(ctx2,
		`UPDATE messages SET size_bytes = $1 WHERE id = $2 AND mailbox_id = $3`,
		int64(len(enc)), emailID, accountID); err != nil {
		return "", fmt.Errorf("smime: encrypted draft size update failed: %w", err)
	}
	return key, nil
}

// extractEmails pulls the "email" field out of a JSONB recipient array column.
func extractEmails(addrsJSON []byte) []string {
	if len(addrsJSON) == 0 {
		return nil
	}
	var arr []struct {
		Email string `json:"email"`
	}
	if err := json.Unmarshal(addrsJSON, &arr); err != nil {
		return nil
	}
	out := make([]string, 0, len(arr))
	for _, a := range arr {
		if a.Email != "" {
			out = append(out, a.Email)
		}
	}
	return out
}

// mustUserOfMailbox resolves the owning user id for the mailbox that owns emailID
// so the inner sign can load that user's signing certs. R1-scoped by accountID
// (mailbox_id) per DATABASE_SECURITY.md. On any error it returns 0
// (loadSignCandidates then finds no candidates → ResolveAndSign fails → fail closed).
// On workerPool (BYPASSRLS) so the inline predicate survives the W6 FORCE flip.
func mustUserOfMailbox(ctx context.Context, h *JMAPHandler, accountID int64, emailID string) int64 {
	var uid int64
	if err := h.workerPool.QueryRow(ctx,
		`SELECT mb.user_id FROM messages m JOIN mailboxes mb ON mb.id = m.mailbox_id WHERE m.id = $1 AND m.mailbox_id = $2`,
		emailID, accountID,
	).Scan(&uid); err != nil {
		return 0
	}
	return uid
}
