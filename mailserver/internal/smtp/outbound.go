package smtp

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/textproto"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/minio/minio-go/v7"
	"setjoin.com/mailserver/internal/blob"
	"setjoin.com/mailserver/internal/linkprotect"
	"setjoin.com/mailserver/internal/tlsutil"
	"setjoin.com/shared/pgxutil"
	"setjoin.com/shared/toggle"
)

// OutboundWorker polls the outbound_queue and delivers pending messages
// to external SMTP servers. Runs as a background goroutine started from main.go.
type OutboundWorker struct {
	pool          *pgxpool.Pool
	logger        *slog.Logger
	interval      time.Duration
	bucket        string
	minio         *minio.Client
	toggles       *toggle.FeatureFlags
	sem           chan struct{}
	connPool      *mxConnPool
	tlsPolicy     *tlsPolicyState
	tlsPolicyNext time.Time // next refresh of TLS policy from DB
	// linkProtectKeys verifies link-protect tokens on the egress un-rewrite for
	// forwarded copies (forward_unwrap_links). An empty Secret disables it.
	linkProtectKeys linkprotect.TokenKeys
	// lookupMXFn and dialMX are seams for tests. In production they default to
	// the package lookupMX / net.DialTimeout. Tests inject scripted MX servers
	// (net.Pipe) to exercise the per-recipient outcome accumulation without a
	// live MX. They are NEVER set on the live path.
	lookupMXFn func(domain string) ([]*net.MX, error)
	dialMX     func(addr string) (net.Conn, error)
	// commandTimeout bounds SMTP command/reply phases. dataTimeout separately
	// bounds the potentially larger message body transfer. Every live or reused
	// connection is also closed when the worker context is cancelled.
	commandTimeout time.Duration
	dataTimeout    time.Duration
	// loadRawFn is the blob-load seam for tests. In production it defaults to
	// loadRawForDelivery (the UPDATE…RETURNING raw_ref + MinIO fetch head of
	// deliverOne). DB tests inject a stub returning a canned raw message so they
	// drive the REAL deliverOne without a live MinIO. NEVER set on the live path.
	loadRawFn func(ctx context.Context, item queueItem) (string, bool)
}

func NewOutboundWorker(pool pgxutil.WorkerPool, logger *slog.Logger, bucket string, minioClient *minio.Client, toggles *toggle.FeatureFlags) *OutboundWorker {
	w := &OutboundWorker{
		pool:       pool.Pool,
		logger:     logger,
		interval:   10 * time.Second,
		bucket:     bucket,
		minio:      minioClient,
		toggles:    toggles,
		sem:        make(chan struct{}, 20),
		connPool:   &mxConnPool{conns: make(map[string][]*pooledConn), max: 5, idle: 60 * time.Second},
		tlsPolicy:  &tlsPolicyState{},
		lookupMXFn: lookupMX,
		dialMX: func(addr string) (net.Conn, error) {
			return net.DialTimeout("tcp", addr, 30*time.Second)
		},
		commandTimeout: 5 * time.Minute,
		dataTimeout:    10 * time.Minute,
	}
	w.loadRawFn = w.loadRawForDelivery
	return w
}

// SetLinkProtectKeys supplies the versioned key set used to verify + decode
// link-protect tokens when un-rewriting forwarded copies (LINK-PROTECT egress
// rail, Track A2; MAILSERVERD-004 dual-key overlap rotation). It must be the
// SAME configured set the inbound rewriter and the click handler use: tokens
// delivered under either generation — current, or the retiring key during the
// overlap window — then verify on egress, so a rotation never leaves rotated
// protected links stranded in forwarded messages.
func (w *OutboundWorker) SetLinkProtectKeys(keys linkprotect.TokenKeys) {
	w.linkProtectKeys = keys
}

// SetLinkProtectSecret is the pre-rotation single-secret form of
// SetLinkProtectKeys: it installs the VERSION-1 key set of secret. Mirrors the
// inbound server's SetLinkProtect secret (cfg.JWTSecret) so tokens this server
// signed verify on egress.
func (w *OutboundWorker) SetLinkProtectSecret(secret []byte) {
	w.SetLinkProtectKeys(linkprotect.TokenKeys{Secret: secret})
}

// mxConnPool caches established SMTP connections per MX host for reuse.
type mxConnPool struct {
	mu    sync.Mutex
	conns map[string][]*pooledConn
	max   int
	idle  time.Duration
}

type pooledConn struct {
	tp   *textproto.Conn
	conn net.Conn
	used time.Time
	host string
	// tls records whether this session was upgraded to TLS when established.
	// The reuse path re-evaluates the current delivery's TLS policy against it:
	// a pooled PLAINTEXT session must never carry mail whose policy requires
	// TLS, and the reused-delivery result reports this flag (never a hard-coded
	// false) so tls:false cannot mask a TLS session or tls:true a plaintext one.
	tls bool
	// dane records whether this session's certificate was DANE-validated at
	// establishment. A session established WITHOUT DANE validation (toggles
	// off, or no records published then) must never carry a delivery for which
	// DANE is required NOW: TLSA records can appear and toggles can flip while
	// a session sits in the pool — the DANE decision is re-evaluated per
	// delivery, never inherited from the pooled session's era.
	dane bool
}

func (p *mxConnPool) get(host string) *pooledConn {
	p.mu.Lock()
	defer p.mu.Unlock()
	pool := p.conns[host]
	if len(pool) == 0 {
		return nil
	}
	pc := pool[len(pool)-1]
	p.conns[host] = pool[:len(pool)-1]
	if time.Since(pc.used) < p.idle {
		return pc
	}
	// TODO(perf): If SMTP retry rate exceeds 5%, add a NOOP health check before reusing connections:
	//   if err := pc.tp.Cmd("NOOP; expect=250"); err != nil { pc.tp.Close(); pc.conn.Close(); return nil }
	pc.tp.Close()
	pc.conn.Close()
	return nil
}

func (p *mxConnPool) put(pc *pooledConn) {
	p.mu.Lock()
	defer p.mu.Unlock()
	pc.used = time.Now()
	pool := p.conns[pc.host]
	if len(pool) >= p.max {
		pc.tp.Close()
		pc.conn.Close()
		return
	}
	p.conns[pc.host] = append(pool, pc)
}

func (p *mxConnPool) remove(host string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.conns, host)
}

// Run starts the delivery loop. Blocks until ctx is cancelled.
func (w *OutboundWorker) Run(ctx context.Context) {
	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()

	w.logger.Info("SMTP outbound worker started", "interval", w.interval)

	for {
		select {
		case <-ctx.Done():
			w.logger.Info("SMTP outbound worker stopped")
			return
		case <-ticker.C:
			w.processBatch(ctx)
		}
	}
}

// queueItem represents a single outbound queue row.
type queueItem struct {
	id           int
	messageID    string
	fromAddr     string
	recipients   []string
	rawRef       string
	attemptCount int
	mailboxID    *int64
	// messagePK is the surrogate id of the Sent messages row (outbound_queue.message_pk,
	// set by send.sql). Links delivery_attempts without the non-unique RFC message_id.
	// NULL for legacy/DMARC/system rows → per-recipient delivery_attempts logging is skipped.
	messagePK *int64
	// receivedAt is messages.received_at for messagePK (the partition key that, with
	// messagePK, resolves the (id, received_at) PK). NULL when messagePK is NULL.
	receivedAt *time.Time
	// forwardUnwrap is set for forwarded copies whose body must have its
	// link-protect redirects un-rewritten before egress (LINK-PROTECT rail).
	forwardUnwrap bool
}

// Delivery outcome discriminators. These map to the delivery_attempts.outcome
// CHECK enum (accepted|deferred|rejected|error) — an out-of-set value is rejected
// by the DB. They drive the per-recipient delivery_attempts rows. message_trace
// stays MESSAGE-level (one 'delivered' per delivered message; one 'bounced' only
// at the queue-bounce moment) so admin_reports' TotalSent/TotalBounced counts
// (computed directly over message_trace) match the OLD invariant.
const (
	outcomeAccepted = "accepted"
	outcomeDeferred = "deferred"
	outcomeRejected = "rejected"
	outcomeError    = "error"
)

// recipientResult is the per-recipient outcome of one delivery pass. Accumulated
// in deliverOne, then drives the per-recipient delivery_attempts log and the
// message-level message_trace 'delivered' row (its rcpt_addr names a delivered
// recipient + carries delivered/total counts).
type recipientResult struct {
	rcpt     string
	mxHost   string
	smtpText string
	smtpCode int
	tls      bool
	outcome  string
}

// mxResult carries the SMTP outcome of a single deliverToMX call out to the
// per-recipient accumulator: the remote reply code+text from the command that
// actually failed (RCPT or DATA) or the final 250, whether STARTTLS was used,
// and the delivery error (nil on success). Returning a struct keeps the
// per-recipient threading readable vs. multiplying return values.
type mxResult struct {
	code int
	text string
	tls  bool
	err  error
}

// outcomeForCode maps an SMTP reply code to the delivery_attempts outcome enum.
// 2xx→accepted, 4xx→deferred (transient, retried), 5xx→rejected (permanent),
// and any lookup/connection/no-code failure (code 0)→error.
func outcomeForCode(code int, err error) string {
	switch {
	case err == nil:
		return outcomeAccepted
	case code >= 200 && code < 300:
		return outcomeAccepted
	case code >= 400 && code < 500:
		return outcomeDeferred
	case code >= 500 && code < 600:
		return outcomeRejected
	default:
		// 0 or unparseable: a connection/lookup/protocol failure with no usable
		// SMTP code. Not in the 2/4/5xx ranges → error.
		return outcomeError
	}
}

// parseSMTPCode extracts the leading 3-digit reply code from an SMTP response
// line, DEFENSIVELY: a short or garbage line yields 0 (never a panic — the
// worker has no recover() and runs on the live delivery path).
func parseSMTPCode(line string) int {
	if len(line) < 3 {
		return 0
	}
	c0, c1, c2 := line[0], line[1], line[2]
	if c0 < '0' || c0 > '9' || c1 < '0' || c1 > '9' || c2 < '0' || c2 > '9' {
		return 0
	}
	return int(c0-'0')*100 + int(c1-'0')*10 + int(c2-'0')
}

func (w *OutboundWorker) processBatch(ctx context.Context) {
	// Refresh TLS policy from DB every 5 minutes
	if time.Now().After(w.tlsPolicyNext) {
		if err := w.tlsPolicy.load(ctx, w.pool); err != nil {
			w.logger.Warn("outbound: failed to reload TLS policy", "error", err)
		}
		w.tlsPolicyNext = time.Now().Add(5 * time.Minute)
	}

	// Queue depth alert: log and notify if backlog exceeds threshold
	var queueDepth int
	w.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM outbound_queue WHERE status IN ('pending','deferred')`,
	).Scan(&queueDepth)
	if queueDepth > 1000 {
		w.logger.Warn("outbound queue backlog", "depth", queueDepth)
		w.pool.Exec(ctx, `SELECT pg_notify('admin:alert', json_build_object('type','queue_backlog','depth',$1)::TEXT)`, queueDepth)
	}

	// Fetch up to 10 pending items. LEFT JOIN messages for received_at (the
	// partition key that resolves the (id, received_at) PK alongside message_pk);
	// a NULL message_pk (legacy/DMARC/system rows) yields a NULL received_at and
	// skips delivery_attempts logging in deliverOne.
	rows, err := w.pool.Query(ctx,
		`SELECT q.id, q.message_id, q.from_addr, q.rcpt_addrs, q.raw_ref, q.attempt_count,
		        q.mailbox_id, q.forward_unwrap_links, q.message_pk, m.received_at
		 FROM outbound_queue q
		 LEFT JOIN messages m ON m.id = q.message_pk
		 WHERE q.status IN ('pending', 'deferred') AND q.next_attempt_at <= now()
		 ORDER BY q.queued_at ASC
		 LIMIT 10`)
	if err != nil {
		w.logger.Error("outbound worker: failed to query queue", "error", err)
		return
	}
	defer rows.Close()

	var items []queueItem
	for rows.Next() {
		var item queueItem
		if err := rows.Scan(&item.id, &item.messageID, &item.fromAddr, &item.recipients, &item.rawRef, &item.attemptCount, &item.mailboxID, &item.forwardUnwrap, &item.messagePK, &item.receivedAt); err != nil {
			continue
		}
		items = append(items, item)
	}

	for _, item := range items {
		select {
		case w.sem <- struct{}{}:
			// Per-delivery goroutine — uses worker ctx with semaphore for concurrency control.
			go func(it queueItem) {
				defer func() { <-w.sem }()
				w.deliverOne(ctx, it)
			}(item)
		case <-ctx.Done():
			return
		}
	}
}

// loadRawForDelivery is the blob-load head of deliverOne, extracted behind the
// loadRawFn seam: it marks the queue row 'sending' + reads raw_ref in one round
// trip, then fetches the blob from MinIO. On success it returns (rawMsg, true);
// on any failure it calls markFailed with the SAME message as before and returns
// ("", false). This is a pure extraction — the default loadRawFn runs it verbatim,
// so the live path is unchanged; tests inject a stub so they drive the real
// deliverOne without a live MinIO.
func (w *OutboundWorker) loadRawForDelivery(ctx context.Context, item queueItem) (string, bool) {
	// Mark as sending and fetch raw_ref in one round trip
	var rawRef string
	err := w.pool.QueryRow(ctx,
		`UPDATE outbound_queue SET status = 'sending' WHERE id = $1
		 RETURNING COALESCE(raw_ref, '')`, item.id,
	).Scan(&rawRef)
	if err != nil {
		w.markFailed(ctx, item, "failed to read raw_ref: "+err.Error())
		return "", false
	}
	if rawRef == "" {
		// Separate branch from the query error above: the old combined guard
		// dereferenced a nil err here and panicked the delivery goroutine.
		w.markFailed(ctx, item, "failed to read raw_ref: empty raw_ref")
		return "", false
	}

	// W5 raw_ref convention: reducer-built drafts enqueue raw_ref as the inline
	// RFC 5322 text itself (jmap_email.sql create → send.sql passes it verbatim
	// — "MinIO path or inline"); only Go-side producers store an object first.
	// Deliver inline text directly; pre-fix it was GetObject'ed and every
	// inline-draft external send deferred until it bounced.
	if blob.IsInlineMessage(rawRef) {
		return rawRef, true
	}

	obj, err := w.minio.GetObject(ctx, w.bucket, rawRef, minio.GetObjectOptions{})
	if err != nil {
		w.markFailed(ctx, item, "failed to fetch blob from MinIO: "+err.Error())
		return "", false
	}
	rawBytes, err := io.ReadAll(obj)
	obj.Close()
	if err != nil {
		w.markFailed(ctx, item, "failed to read blob content: "+err.Error())
		return "", false
	}
	return string(rawBytes), true
}

// unwrapForwardLinks is the egress un-rewrite head of deliverOne (LINK-PROTECT
// rail, Track A2), extracted behind a testable seam: it verifies + decodes the
// message's /link-protect?token=… redirects against the worker's configured
// key set (MAILSERVERD-004: current key first, retiring key during the overlap
// window) and splices the original URLs back per output context. Returns the
// possibly-rewritten message and the number of redirects removed. With no key
// set wired (or an empty Secret) the message is returned unchanged; on a
// rewrite ERROR the original is sent unchanged — our redirects are
// self-verifying and inert, the fail-safe direction.
func (w *OutboundWorker) unwrapForwardLinks(item queueItem, rawMsg string) (string, int) {
	if len(w.linkProtectKeys.Secret) == 0 {
		return rawMsg, 0
	}
	unwrapped, n, err := linkprotect.UnwrapMessageBodyN([]byte(rawMsg), w.linkProtectKeys)
	if err != nil {
		w.logger.Warn("outbound: link-protect un-rewrite failed; sending original", "msg_id", item.messageID, "error", err)
		return rawMsg, 0
	}
	if n == 0 {
		return rawMsg, 0
	}
	return string(unwrapped), n
}

func (w *OutboundWorker) deliverOne(ctx context.Context, item queueItem) {
	rawMsg, ok := w.loadRawFn(ctx, item)
	if !ok {
		return
	}

	// LINK-PROTECT egress rail (Track A2): a forwarded copy carries the inbound
	// message's stored body, whose external URLs were rewritten to THIS server's
	// /link-protect?token=… redirects. Those redirects are broken for the forward
	// target and leak the recipient mailbox_id + message_id in the token. Un-rewrite
	// them back to the original URLs before signing so the forwarded copy is clean.
	// Done before DKIM so the signature covers the final, un-rewritten body.
	if item.forwardUnwrap {
		if unwrapped, n := w.unwrapForwardLinks(item, rawMsg); n > 0 {
			rawMsg = unwrapped
			w.logger.Info("outbound: un-rewrote link-protect URLs on forward", "msg_id", item.messageID, "count", n)
		}
	}

	// Attempt DKIM signing if a signing key exists for the sender domain.
	rawMsg = w.signDKIM(ctx, item, rawMsg)

	// S/MIME signing AND encryption both happen at submission now (Phase D + SP1
	// Phase 3 — the EmailSubmission/set handler signs/encrypts the draft and swaps
	// raw_ref to the final blob). The worker relays that blob VERBATIM; it no longer
	// signs or encrypts. The submission-time check is the single fail-closed gate.

	// Resolve MX + deliver per recipient, accumulating one outcome each (never
	// collapsed to recipients[0]). lastErr is the original human-readable last
	// failure string preserved for markFailed's outbound_queue.last_error.
	results, lastErr := w.deliverRecipients(ctx, item, rawMsg)

	// Best-effort per-recipient delivery_attempts log (outside any txn, errors
	// ignored). Never affects delivery; skipped when the row has no surrogate link.
	for _, rr := range results {
		w.logDeliveryAttempt(ctx, item, rr)
	}

	// Derive the failed set from the results to drive the queue status decision
	// (unchanged: all-fail → markFailed, partial/any-success → delivered).
	var failed []string
	for _, rr := range results {
		if rr.outcome != outcomeAccepted {
			failed = append(failed, rr.rcpt)
		}
	}

	if len(failed) == len(item.recipients) {
		// All recipients failed. markFailed owns the queue status/backoff AND
		// (only at the 20-attempt bounce threshold) the single message-level
		// 'bounced' message_trace row. No per-recipient or per-retry trace here —
		// message_trace cardinality must stay message-level (admin_reports counts
		// TotalSent/TotalBounced directly over it). The per-recipient detail lives
		// in delivery_attempts (logged above).
		w.markFailed(ctx, item, "all recipients failed: "+lastErr)
		return
	}
	if len(failed) > 0 {
		w.logger.Warn("outbound: partial delivery failure",
			"msg_id", item.messageID,
			"failed", strings.Join(failed, ", "))
	}

	// Mark as delivered (source of truth: outbound_queue). At least one
	// recipient was accepted (partial delivery still marks the message delivered).
	w.pool.Exec(ctx,
		`UPDATE outbound_queue SET status = 'delivered', delivered_at = now(), attempt_count = attempt_count + 1 WHERE id = $1`,
		item.id,
	)
	w.logger.Info("outbound message delivered", "msg_id", item.messageID)

	// Exactly ONE message-level 'delivered' message_trace row (the OLD invariant
	// admin_reports relies on), naming a DELIVERED recipient — never recipients[0]
	// blindly (which could name a failed one). Per-recipient detail is in
	// delivery_attempts; this row carries the delivered/total counts.
	w.writeDeliveredTrace(ctx, item, results)
}

// deliverRecipients resolves MX and delivers rawMsg to each recipient,
// returning one recipientResult per recipient (success or final failure). It
// preserves the original per-recipient delivery decisions exactly (MTA-STS
// enforce skip, admin TLS policy, MX fallback loop, TLS-RPT recording); it only
// additionally captures the per-recipient SMTP code/text/tls into the result.
// Extracted from deliverOne so the per-recipient outcome→rows mapping is unit
// testable (the MX seam — lookupMXFn/dialMX — is injected in tests).
func (w *OutboundWorker) deliverRecipients(ctx context.Context, item queueItem, rawMsg string) ([]recipientResult, string) {
	results := make([]recipientResult, 0, len(item.recipients))
	var lastErr string
	for _, rcpt := range item.recipients {
		domain := extractDomain(rcpt)
		if domain == "" {
			lastErr = "invalid recipient address: " + rcpt
			results = append(results, recipientResult{rcpt: rcpt, smtpText: lastErr, outcome: outcomeError})
			continue
		}

		mxRecords, err := w.lookupMXFn(domain)
		if err != nil || len(mxRecords) == 0 {
			lastErr = "MX lookup failed for " + domain
			results = append(results, recipientResult{rcpt: rcpt, smtpText: lastErr, outcome: outcomeError})
			continue
		}

		// Check MTA-STS policy for this domain (if enabled)
		var mtaPolicy *MTASTSPolicy
		var tlsReportURI string
		if w.toggles.IsEnabled(toggle.FeatureMTASTS) {
			mtaPolicy = LookupMTASTS(domain)
		}
		if w.toggles.IsEnabled(toggle.FeatureTlsRpt) {
			tlsReportURI = DiscoverTLSReportURI(domain)
		}

		var delivered bool
		var lastMX mxResult
		var lastMXHost string
		for _, mx := range mxRecords {
			// MTA-STS enforcement: skip MX hosts not in policy
			if mtaPolicy != nil && mtaPolicy.Mode == "enforce" && !mtaPolicy.MXMatches(mx.Host) {
				lastErr = fmt.Sprintf("MTA-STS enforce: MX %s not in policy for %s", mx.Host, domain)
				lastMXHost = mx.Host
				lastMX = mxResult{err: fmt.Errorf("%s", lastErr)}
				continue
			}
			// Combine MTA-STS + admin TLS policy: requireTLS (enforce wins) and
			// skipTLS (admin opts this domain out of STARTTLS, e.g. a partner MX
			// with a broken cert that would otherwise hard-fail opportunistic TLS).
			mtaSTSRequire := mtaPolicy != nil && mtaPolicy.Mode == "enforce"
			enforceDomains, skipDomains, globalEnforce := w.tlsPolicy.get()
			adminRequire, adminSkip := resolveTLSPolicy(domain, enforceDomains, skipDomains, globalEnforce)
			requireTLS := mtaSTSRequire || adminRequire

			res := w.deliverToMX(ctx, mx.Host, rcpt, item.fromAddr, rawMsg, requireTLS, adminSkip)
			lastMX = res
			lastMXHost = mx.Host
			err = res.err
			if err == nil {
				delivered = true
				if w.toggles.IsEnabled(toggle.FeatureTlsRpt) {
					RecordTLSSession(ctx, w.pool, domain, mx.Host, "", "success", "", tlsReportURI)
				}
				break
			}
			// Record failure for TLS-RPT
			if w.toggles.IsEnabled(toggle.FeatureTlsRpt) {
				result := classifyTLSError(err)
				RecordTLSSession(ctx, w.pool, domain, mx.Host, "", result, err.Error(), tlsReportURI)
			}
			lastErr = fmt.Sprintf("delivery to %s failed: %s", rcpt, err.Error())
		}

		// One result per recipient: success → accepted (the 250 from the last
		// MX tried); failure → the outcome derived from the last MX's reply code
		// (the command that actually failed, RCPT or DATA, populated by deliverToMX).
		rr := recipientResult{
			rcpt:     rcpt,
			mxHost:   lastMXHost,
			smtpCode: lastMX.code,
			smtpText: lastMX.text,
			tls:      lastMX.tls,
		}
		if delivered {
			rr.outcome = outcomeAccepted
		} else {
			rr.outcome = outcomeForCode(lastMX.code, lastMX.err)
			if rr.smtpText == "" && lastMX.err != nil {
				rr.smtpText = lastMX.err.Error()
			}
		}
		results = append(results, rr)
	}
	return results, lastErr
}

// writeDeliveredTrace emits EXACTLY ONE message-level 'delivered' message_trace
// row for a delivered (incl. partial) message — the message-level replacement
// for the old per-recipient delivered loop. This preserves the OLD invariant of
// one 'delivered' row per delivered message that admin_reports.TotalSent counts
// directly over message_trace. rcpt_addr is the first ACCEPTED recipient in
// results (a delivered recipient — never recipients[0] blindly, which could name
// a failed one). details carries delivered/total counts. The per-recipient
// breakdown lives in delivery_attempts. Best-effort: errors ignored, outside any
// txn, mirroring the fire-and-forget trace writes.
func (w *OutboundWorker) writeDeliveredTrace(ctx context.Context, item queueItem, results []recipientResult) {
	delivered := 0
	rcptAddr := ""
	var remoteHost string
	for _, rr := range results {
		if rr.outcome == outcomeAccepted {
			delivered++
			if rcptAddr == "" {
				rcptAddr = rr.rcpt
				remoteHost = rr.mxHost
			}
		}
	}
	if rcptAddr == "" {
		// No accepted recipient — should not happen on the delivered path (it's
		// only reached when at least one recipient was accepted). Guard anyway so
		// rcpt_addr (NOT NULL) is never empty.
		return
	}
	details, err := json.Marshal(map[string]any{
		"delivered": delivered,
		"total":     len(results),
	})
	if err != nil {
		details = []byte("{}")
	}
	w.pool.Exec(ctx,
		`INSERT INTO message_trace (message_id, event, from_addr, rcpt_addr, remote_host, details)
		 VALUES ($1, 'delivered', $2, $3, $4, $5)`,
		item.messageID, item.fromAddr, rcptAddr, remoteHost, string(details),
	)
}

// logDeliveryAttempt records one per-recipient delivery outcome into the
// delivery_attempts side-log. Best-effort: the write runs OUTSIDE any delivery
// transaction and its error is IGNORED — a failed/slow insert must NEVER affect
// delivery (outbound_queue stays the source of truth). Skipped entirely for rows
// with no surrogate link (legacy/DMARC/system sends): a NULL message_pk,
// received_at, or mailbox_id would violate the NOT NULL columns.
func (w *OutboundWorker) logDeliveryAttempt(ctx context.Context, item queueItem, r recipientResult) {
	if item.messagePK == nil || *item.messagePK == 0 || item.receivedAt == nil || item.mailboxID == nil {
		return
	}
	// Per-pass attempt number (shared across this send's recipients), from the
	// value already in hand — NOT a MAX(attempt_number)+1 subselect (which would
	// add a per-recipient read-then-write race on an append-only log).
	attemptNumber := item.attemptCount + 1
	var mxHost *string
	if r.mxHost != "" {
		mxHost = &r.mxHost
	}
	var smtpCode *int
	if r.smtpCode != 0 {
		smtpCode = &r.smtpCode
	}
	var smtpText *string
	if r.smtpText != "" {
		smtpText = &r.smtpText
	}
	w.pool.Exec(ctx,
		`INSERT INTO delivery_attempts
		   (message_pk, received_at, mailbox_id, recipient_email, mx_host,
		    attempt_number, smtp_code, smtp_text, outcome, tls)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
		*item.messagePK, *item.receivedAt, *item.mailboxID, r.rcpt, mxHost,
		attemptNumber, smtpCode, smtpText, r.outcome, r.tls,
	)
}

// daneEnabled reports whether the DANE rails are on (both the DNSSEC and DANE
// toggles). Every DANE decision on the outbound path — the precheck, pooled-
// reuse gating and post-handshake validation — sits behind this pair.
func (w *OutboundWorker) daneEnabled() bool {
	return w.toggles != nil &&
		w.toggles.IsEnabled(toggle.FeatureDNSSEC) &&
		w.toggles.IsEnabled(toggle.FeatureDANE)
}

func (w *OutboundWorker) deliverToMX(ctx context.Context, mxHost, rcpt, from, rawMsg string, requireTLS, skipTLS bool) mxResult {
	// DANE precheck (RFC 7672 §2.2): evaluate the COMPLETE outcome before any
	// delivery path — pooled or fresh — and before any MAIL/DATA command. A
	// failed lookup defers (server unreachable; never plaintext); an
	// authenticated RRset makes TLS mandatory for this attempt regardless of
	// admin skipTLS; absence preserves opportunistic delivery. This replaces
	// the former IsDANEAvailable boolean, whose collapsed "false" let
	// STARTTLS-stripping and skipTLS deliveries proceed over cleartext.
	daneOn := w.daneEnabled()
	daneRequired := false
	if daneOn {
		switch DANEPrecheckMX(mxHost) {
		case DANEPrecheckUnavailable:
			w.logger.Warn("DANE: TLSA lookup failed — server unreachable per RFC 7672 §2.1; delivery deferred", "mx_host", mxHost)
			return mxResult{err: fmt.Errorf("DANE: server %s unreachable — TLSA lookup failed per RFC 7672 §2.1", mxHost)}
		case DANEPrecheckRequired:
			daneRequired = true
		}
	}

	// Try connection pool first — but only reuse a pooled session whose TLS
	// state satisfies THIS delivery's policy. The pool is keyed by MX host, so
	// policy-differing recipient domains sharing an MX host can otherwise hand
	// an enforce-listed delivery a pooled PLAINTEXT session and report a
	// tls:false success over cleartext. The DANE decision is likewise made NOW
	// (against current records), never inherited from when the session was
	// pooled.
	if pc := w.connPool.get(mxHost); pc != nil {
		reuseOK := pc.tls || !requireTLS
		if daneRequired && !(pc.tls && pc.dane) {
			// DANE is required NOW: a pooled plaintext session obviously
			// cannot serve it, and neither can a TLS session whose
			// certificate was never DANE-validated at establishment.
			reuseOK = false
		}
		if !reuseOK {
			// The pooled session cannot satisfy this delivery's policy (TLS
			// required by MTA-STS/admin policy or by DANE, or the session was
			// never DANE-validated when DANE now applies): drop it so it can
			// keep serving only policy-free deliveries, and fall through to a
			// fresh connection that either upgrades to TLS or fails closed
			// below.
			pc.tp.Close()
			pc.conn.Close()
			w.connPool.remove(mxHost)
		} else {
			release, err := w.armSMTPConnection(ctx, pc.conn)
			if err != nil {
				pc.tp.Close()
				pc.conn.Close()
				w.connPool.remove(mxHost)
			} else {
				// Reset connection state with RSET
				if err := w.cmd(pc.tp, "RSET"); err != nil {
					release(false)
					// Discard the session; Close errors cannot affect the
					// RSET failure already surfaced via mxResult.
					_ = pc.tp.Close()
					_ = pc.conn.Close()
					w.connPool.remove(mxHost)
				} else {
					code, text, err := w.sendEnvelope(pc.tp, from, rcpt)
					if err == nil {
						w.setSMTPDeadline(ctx, pc.conn, w.smtpDataTimeout())
						code, text, err = w.sendData(pc.tp, rawMsg)
					}
					if err != nil {
						release(false)
						w.connPool.remove(mxHost)
						pc.tp.Close()
						pc.conn.Close()
						// Fall through to fresh connection
					} else {
						if !release(true) {
							return mxResult{code: code, text: text, tls: pc.tls, err: ctx.Err()}
						}
						w.connPool.put(pc)
						// Reused conn: report the session's recorded TLS state —
						// never a hard-coded false that could mask cleartext
						// delivery (or hide a TLS session) in delivery_attempts.
						return mxResult{code: code, text: text, tls: pc.tls, err: nil}
					}
				}
			}
		}
	}

	addr := strings.TrimSuffix(mxHost, ".") + ":25"
	conn, err := w.dialMX(addr)
	if err != nil {
		return mxResult{err: fmt.Errorf("connect: %w", err)}
	}
	release, err := w.armSMTPConnection(ctx, conn)
	if err != nil {
		conn.Close()
		return mxResult{err: fmt.Errorf("connection deadline: %w", err)}
	}

	tp, hasTLS, err := w.dialAndEHLO(conn, mxHost)
	if err != nil {
		release(false)
		conn.Close()
		return mxResult{err: err}
	}

	usedTLS := false
	if hasTLS && (!skipTLS || daneRequired) {
		// A DANE-required delivery attempts STARTTLS even when admin policy
		// skips TLS for this domain: the host publishes authenticated records
		// precisely so it can be reached over authenticated TLS, and skipping
		// here would downgrade a DANE-protected delivery to plaintext. The
		// post-handshake validation (upgradeToTLS) is what decides acceptance.
		tp, err = w.upgradeToTLS(tp, conn, mxHost)
		if err != nil {
			release(false)
			return mxResult{err: err}
		}
		usedTLS = true
	} else if requireTLS || daneRequired {
		// STARTTLS not offered (stripping) or explicitly skipped, and this
		// delivery requires TLS (MTA-STS/admin policy or DANE) — fail closed;
		// never a plaintext fallback.
		release(false)
		tp.Close()
		return mxResult{err: fmt.Errorf("TLS required but not offered by %s (MTA-STS enforce or DANE policy)", mxHost)}
	}
	code, text, err := w.sendEnvelope(tp, from, rcpt)
	if err != nil {
		release(false)
		tp.Close()
		return mxResult{code: code, text: text, tls: usedTLS, err: err}
	}
	w.setSMTPDeadline(ctx, conn, w.smtpDataTimeout())
	code, text, err = w.sendData(tp, rawMsg)
	if err != nil {
		release(false)
		tp.Close()
		return mxResult{code: code, text: text, tls: usedTLS, err: err}
	}

	// Pool the connection for reuse (with its recorded TLS + DANE state —
	// dane marks that this session's certificate WAS DANE-validated at
	// establishment, so a future DANE-required delivery may reuse it).
	if !release(true) {
		return mxResult{code: code, text: text, tls: usedTLS, err: ctx.Err()}
	}
	w.connPool.put(&pooledConn{tp: tp, conn: conn, host: mxHost, tls: usedTLS, dane: usedTLS && daneOn})
	return mxResult{code: code, text: text, tls: usedTLS, err: nil}
}

func (w *OutboundWorker) smtpCommandTimeout() time.Duration {
	if w.commandTimeout > 0 {
		return w.commandTimeout
	}
	return 5 * time.Minute
}

func (w *OutboundWorker) smtpDataTimeout() time.Duration {
	if w.dataTimeout > 0 {
		return w.dataTimeout
	}
	return 10 * time.Minute
}

func (w *OutboundWorker) setSMTPDeadline(ctx context.Context, conn net.Conn, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	return conn.SetDeadline(deadline)
}

// armSMTPConnection bounds all protocol I/O and makes worker shutdown close a
// blocked socket immediately. The returned release function must be called
// exactly once. Passing reusable=true clears the deadline before pooling; it
// returns false if cancellation raced with release, in which case the socket
// has been closed and must not be pooled.
func (w *OutboundWorker) armSMTPConnection(ctx context.Context, conn net.Conn) (func(bool) bool, error) {
	if err := w.setSMTPDeadline(ctx, conn, w.smtpCommandTimeout()); err != nil {
		return nil, err
	}
	stopCancel := context.AfterFunc(ctx, func() {
		_ = conn.Close()
	})
	return func(reusable bool) bool {
		stopped := stopCancel()
		if !reusable || !stopped || ctx.Err() != nil {
			_ = conn.Close()
			return false
		}
		if err := conn.SetDeadline(time.Time{}); err != nil {
			_ = conn.Close()
			return false
		}
		return true
	}, nil
}

func commandLine(tp *textproto.Conn, format string, args ...any) (string, error) {
	id, err := tp.Cmd(format, args...)
	if err != nil {
		return "", err
	}
	tp.StartResponse(id)
	defer tp.EndResponse(id)
	return tp.ReadLine()
}

// cmd sends a single SMTP command and reads the response.
func (w *OutboundWorker) cmd(tp *textproto.Conn, command string) error {
	line, err := commandLine(tp, "%s", command)
	if err != nil {
		return err
	}
	if !strings.HasPrefix(line, "2") {
		return fmt.Errorf("unexpected response: %s", line)
	}
	return nil
}

// dialAndEHLO reads the greeting, sends EHLO, and parses capabilities. TLS
// requirements (MTA-STS/admin policy, DANE) and DANE lookup outcomes are
// evaluated by deliverToMX via DANEPrecheckMX BEFORE this exchange and again
// at the STARTTLS decision — this function only parses what the server
// advertised, it never decides whether plaintext is acceptable.
func (w *OutboundWorker) dialAndEHLO(conn net.Conn, mxHost string) (*textproto.Conn, bool, error) {
	tp := textproto.NewConn(conn)

	line, err := tp.ReadLine()
	if err != nil {
		return nil, false, fmt.Errorf("greeting: %w", err)
	}
	if !strings.HasPrefix(line, "220") {
		return nil, false, fmt.Errorf("unexpected greeting: %s", line)
	}

	hostname, _ := getLocalHostname()
	id, err := tp.Cmd("EHLO %s", hostname)
	if err != nil {
		return nil, false, fmt.Errorf("ehlo: %w", err)
	}

	hasStartTLS := false
	tp.StartResponse(id)
	defer tp.EndResponse(id)
	for {
		line, err := tp.ReadLine()
		if err != nil {
			return nil, false, fmt.Errorf("ehlo response: %w", err)
		}
		if strings.HasPrefix(strings.ToUpper(line), "250-STARTTLS") {
			hasStartTLS = true
		}
		if strings.HasPrefix(line, "250 ") {
			break
		}
	}

	return tp, hasStartTLS, nil
}

// upgradeToTLS performs STARTTLS, DANE validation, and re-EHLO.
func (w *OutboundWorker) upgradeToTLS(tp *textproto.Conn, conn net.Conn, mxHost string) (*textproto.Conn, error) {
	id, err := tp.Cmd("STARTTLS")
	if err != nil {
		return nil, fmt.Errorf("starttls: %w", err)
	}
	tp.StartResponse(id)
	line, readErr := tp.ReadLine()
	tp.EndResponse(id)
	if readErr != nil {
		return nil, fmt.Errorf("starttls response: %w", readErr)
	}
	if !strings.HasPrefix(line, "220") {
		return nil, fmt.Errorf("starttls rejected: %s", line)
	}

	tlsConn := tls.Client(conn, &tls.Config{
		ServerName:       strings.TrimSuffix(mxHost, "."),
		MinVersion:       tls.VersionTLS12,
		CipherSuites:     tlsutil.DefaultCipherSuites,
		CurvePreferences: tlsutil.DefaultCurves,
	})
	if err := tlsConn.Handshake(); err != nil {
		return nil, fmt.Errorf("tls handshake: %w", err)
	}
	if w.daneEnabled() {
		if err := w.applyDANEVerdict(ValidateDANEConnection(tlsConn.ConnectionState(), mxHost, w.logger), mxHost); err != nil {
			return nil, err
		}
	}
	tp = textproto.NewConn(tlsConn)
	if err := w.ehloAfterTLS(tp); err != nil {
		return nil, err
	}
	return tp, nil
}

// applyDANEVerdict maps a DANE verification result to the delivery decision
// after a successful STARTTLS upgrade. nil = proceed with this (already-TLS)
// connection; non-nil = fail the delivery attempt (the caller tries the next
// MX and otherwise defers with retry — never a plaintext fallback, because the
// connection is already inside the TLS layer). Extracted from upgradeToTLS so
// the acceptance matrix is table-testable without a live TLS handshake.
func (w *OutboundWorker) applyDANEVerdict(result DANEResult, mxHost string) error {
	switch result {
	case DANESecure:
		// DANE authenticated — proceed with delivery.
		return nil
	case DANESecureUnusable:
		// "Secure" RRset with no USABLE records — TLS is active but DANE
		// authentication is not possible; proceed but log (RFC 7672 §2.2).
		w.logger.Warn("DANE: TLSA records exist but none are usable — per RFC 7672 §2.2, TLS is active but authentication not required",
			"mx_host", mxHost)
		return nil
	case DANEInsecure:
		// No TLSA records (NODATA/NXDOMAIN) — legitimate non-DANE delivery:
		// keep the already-upgraded opportunistic TLS; absence never defers
		// or rejects.
		return nil
	case DANECertMismatch:
		// Authenticated TLSA records exist and the presented certificate
		// matches none of them — reject the delivery even against a CA-valid
		// certificate (RFC 7672 §2.2: server treated as unreachable).
		return fmt.Errorf("DANE: certificate does not match the authenticated TLSA records for %s — delivery rejected per RFC 7672 §2.2", mxHost)
	case DANELookupFailed:
		// SERVFAIL/timeout/bogus DNSSEC — defer with retry; never degrade to
		// plaintext, never masquerade as absence (RFC 7672 §2.1).
		return fmt.Errorf("DANE: server %s unreachable — TLSA lookup failed per RFC 7672 §2.1", mxHost)
	default:
		// Unknown verdict — fail closed.
		return fmt.Errorf("DANE: unknown verification result %d for %s", result, mxHost)
	}
}

func (w *OutboundWorker) ehloAfterTLS(tp *textproto.Conn) error {
	hostname, _ := getLocalHostname()
	id, err := tp.Cmd("EHLO %s", hostname)
	if err != nil {
		return fmt.Errorf("ehlo after tls: %w", err)
	}
	tp.StartResponse(id)
	defer tp.EndResponse(id)
	for {
		line, err := tp.ReadLine()
		if err != nil {
			return fmt.Errorf("ehlo after tls: %w", err)
		}
		if strings.HasPrefix(line, "250 ") {
			break
		}
	}
	return nil
}

// rejectEnvelopeAddr returns an error if addr contains any ASCII control
// character (0x00–0x1F or 0x7F). A CR, LF, or NUL in an envelope address
// could inject extra SMTP commands on the wire; rejecting all C0 controls +
// DEL is the conservative, correct posture (ponytail: broader than strictly
// required, but a valid address never contains them).
func rejectEnvelopeAddr(addr string) error {
	for i := 0; i < len(addr); i++ {
		c := addr[i]
		if c < 0x20 || c == 0x7F {
			return fmt.Errorf("smtp: envelope address contains invalid character 0x%02X", c)
		}
	}
	return nil
}

// sendEnvelope issues MAIL FROM and RCPT TO. It returns the SMTP reply code and
// first-line text of the command that decided the outcome (the rejecting reply
// on failure, the RCPT 250 on success) ALONGSIDE the error. The err decision is
// byte-for-byte the original strings.HasPrefix(line,"250") gate — (code, text)
// are derived in parallel from the same line, never substituted for the gate.
func (w *OutboundWorker) sendEnvelope(tp *textproto.Conn, from, rcpt string) (int, string, error) {
	if err := rejectEnvelopeAddr(from); err != nil {
		return 0, "", err
	}
	if err := rejectEnvelopeAddr(rcpt); err != nil {
		return 0, "", err
	}
	line, err := commandLine(tp, "MAIL FROM:<%s>", from)
	if err != nil || !strings.HasPrefix(line, "250") {
		return parseSMTPCode(line), line, fmt.Errorf("mail from rejected: %s", line)
	}
	line, err = commandLine(tp, "RCPT TO:<%s>", rcpt)
	if err != nil || !strings.HasPrefix(line, "250") {
		return parseSMTPCode(line), line, fmt.Errorf("rcpt to rejected: %s", line)
	}
	return parseSMTPCode(line), line, nil
}

// sendData issues DATA, sends the dot-stuffed body, and validates the final
// response. It intentionally leaves the SMTP session open so deliverToMX can
// return it to the connection pool; RSET starts the next transaction.
// It returns the SMTP reply code and first-line text of the DATA-phase command
// that decided the outcome (the rejecting reply, or the final 250) alongside the
// error. The "354" / "250" HasPrefix gates are the original err decisions,
func (w *OutboundWorker) sendData(tp *textproto.Conn, rawMsg string) (int, string, error) {
	id, err := tp.Cmd("DATA")
	if err != nil {
		return 0, "", fmt.Errorf("data: %w", err)
	}
	tp.StartResponse(id)
	defer tp.EndResponse(id)
	line, err := tp.ReadLine()
	if err != nil || !strings.HasPrefix(line, "354") {
		return parseSMTPCode(line), line, fmt.Errorf("data rejected: %s", line)
	}

	stuffed := dotStuff(rawMsg)
	if _, err := fmt.Fprintf(tp.W, "%s\r\n.\r\n", stuffed); err != nil {
		return 0, "", fmt.Errorf("write message body: %w", err)
	}
	if err := tp.W.Flush(); err != nil {
		return 0, "", fmt.Errorf("flush message body: %w", err)
	}

	line, err = tp.ReadLine()
	if err != nil || !strings.HasPrefix(line, "250") {
		return parseSMTPCode(line), line, fmt.Errorf("delivery rejected: %s", line)
	}
	return parseSMTPCode(line), line, nil
}
func (w *OutboundWorker) markFailed(ctx context.Context, item queueItem, errMsg string) {
	newAttempts := item.attemptCount + 1
	status := "deferred"
	if newAttempts >= 20 {
		status = "bounced"
	}

	backoffMinutes := 1
	switch {
	case newAttempts >= 10:
		backoffMinutes = 1440 // 24 hours
	case newAttempts >= 5:
		backoffMinutes = 240 // 4 hours
	case newAttempts >= 2:
		backoffMinutes = 15
	}

	w.pool.Exec(ctx,
		`UPDATE outbound_queue SET
			status = $1, attempt_count = $2, last_error = $3,
			next_attempt_at = now() + make_interval(mins => $4)
		 WHERE id = $5`,
		status, newAttempts, errMsg, backoffMinutes, item.id,
	)

	if status == "bounced" {
		// Exactly ONE message-level 'bounced' message_trace row, only at the
		// queue-bounce moment (newAttempts >= 20) — NOT per-retry, NOT per-recipient
		// (restores the OLD invariant admin_reports.TotalBounced counts over
		// message_trace; a deferred <20 all-fail writes none). emitBounceTrace is the
		// one canonical writer (also used by bouncePermanent); see it for the
		// json.Marshal + recipients[0] guard.
		w.emitBounceTrace(ctx, item, errMsg)
	} else {
		w.logger.Info("outbound delivery deferred", "msg_id", item.messageID, "attempt", newAttempts)
	}
}

// emitBounceTrace logs and records the message_trace row that marks a permanent
// bounce. markFailed calls this on reaching the retry limit so the NDR trace is
// never silently dropped.
func (w *OutboundWorker) emitBounceTrace(ctx context.Context, item queueItem, errMsg string) {
	w.logger.Warn("outbound message bounced", "msg_id", item.messageID, "error", errMsg)
	// details via json.Marshal (NOT fmt.Sprintf — an error string with a quote/brace
	// would otherwise produce invalid JSON). recipients[0] is guarded: at an
	// all-failed bounce it legitimately names a failed recipient, but bouncePermanent
	// can also reach here, so never index an empty slice. Best-effort, errors ignored.
	details, jerr := json.Marshal(map[string]any{"error": errMsg})
	if jerr != nil {
		details = []byte("{}")
	}
	rcptAddr := ""
	if len(item.recipients) > 0 {
		rcptAddr = item.recipients[0]
	}
	if rcptAddr == "" {
		return
	}
	w.pool.Exec(ctx,
		`INSERT INTO message_trace (message_id, event, from_addr, rcpt_addr, details)
		 VALUES ($1, 'bounced', $2, $3, $4)`,
		item.messageID, item.fromAddr, rcptAddr, string(details),
	)
}

// (bouncePermanent was removed with the worker-side S/MIME encryption pass in SP1
// Phase 3: its only caller was the encrypt-no-cert immediate bounce. Encryption now
// fails closed at submission — the worker has no encrypt-specific permanent-bounce
// path. Real-delivery permanent failures still flow through markFailed → emitBounceTrace.)

func extractDomain(email string) string {
	if idx := strings.LastIndex(email, "@"); idx >= 0 {
		return email[idx+1:]
	}
	return ""
}

func getLocalHostname() (string, error) {
	h, err := net.LookupHost("localhost")
	if err != nil || len(h) == 0 {
		return "mailserver.local", nil
	}
	hn, err := net.LookupAddr(h[0])
	if err != nil || len(hn) == 0 {
		return "mailserver.local", nil
	}
	return strings.TrimSuffix(hn[0], "."), nil
}

func (w *OutboundWorker) signDKIM(ctx context.Context, item queueItem, rawMsg string) string {
	domain := extractDomain(item.fromAddr)
	if domain == "" {
		return rawMsg
	}

	var privKeyPEM string
	err := w.pool.QueryRow(ctx,
		`SELECT private_key FROM domain_signing_keys WHERE domain = $1 AND enabled = TRUE LIMIT 1`,
		domain,
	).Scan(&privKeyPEM)
	if err != nil {
		return rawMsg // no signing key configured, send unsigned
	}

	block, _ := pem.Decode([]byte(privKeyPEM))
	if block == nil {
		w.logger.Warn("dkim: failed to decode PEM for domain", "domain", domain)
		return rawMsg
	}

	privKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		w.logger.Warn("dkim: failed to parse private key", "domain", domain, "error", err)
		return rawMsg
	}

	dkimHeader, err := SignDKIM([]byte(rawMsg), "default", domain, privKey)
	if err != nil {
		w.logger.Warn("dkim: signing failed", "domain", domain, "error", err)
		return rawMsg
	}

	return dkimHeader + "\r\n" + rawMsg
}
