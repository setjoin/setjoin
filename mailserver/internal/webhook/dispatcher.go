package webhook

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"setjoin.com/shared/ssrf"
	wh "setjoin.com/shared/webhook"
)

// deliveryTimeout bounds a single delivery attempt (HTTP + log write).
// retryTickInterval is deliberately > deliveryTimeout so a retry's deliverOne
// always finishes before the next tick fires: otherwise a row whose delivery is
// still in-flight (status still 'failed', completed_at stale) gets re-selected
// and a second concurrent POST is sent to the subscriber. Keep this invariant.
const (
	deliveryTimeout   = 30 * time.Second
	deliveryLeaseTime = 45 * time.Second
	settlementTimeout = 5 * time.Second
	retryTickInterval = 2 * deliveryTimeout
	deliveryBatchSize = 100
	deliveryWorkers   = 8
	deliveryQueueSize = deliveryWorkers
)

// Dispatcher delivers CloudEvents to registered webhook subscriptions.
type Dispatcher struct {
	pool       *pgxpool.Pool
	httpClient *http.Client
	logger     *slog.Logger
	// secretCodec opens the at-rest signing-secret envelopes
	// (webhook_subscriptions.secret_enc; D6/DBSCHEMA-005, the V247 device
	// pattern). Required in production (WithSecretCodec): the loader fails
	// closed without it — on envelope rows AND legacy rows alike — so
	// delivery never rides on encryption being unavailable.
	secretCodec *wh.SecretCodec
	mu          sync.Mutex
	breakers    map[int64]*circuitBreaker
	executor    sync.Once
	started     atomic.Bool
	stopping    atomic.Bool
	tasks       chan deliveryTask
	admission   chan struct{}
	submitMu    sync.RWMutex
	executorWG  sync.WaitGroup
	workerID    uuid.UUID
}

// Option configures optional Dispatcher seams at construction.
type Option func(*Dispatcher)

// WithSecretCodec threads the process secret codec that opens the at-rest
// webhook signing-secret envelopes (D6/DBSCHEMA-005). Production must always
// wire it; without it every secret read fails closed (no plaintext fallback).
func WithSecretCodec(codec *wh.SecretCodec) Option {
	return func(d *Dispatcher) { d.secretCodec = codec }
}

// NewDispatcher creates a webhook dispatcher.
func NewDispatcher(pool *pgxpool.Pool, logger *slog.Logger, opts ...Option) *Dispatcher {
	d := &Dispatcher{
		pool: pool,
		// SSRF guard: refuses to dial loopback/private/link-local/unspecified
		// addresses (incl. 169.254.169.254 metadata), enforced at connect time
		// so it also defeats DNS rebinding. See shared/ssrf.
		httpClient: ssrf.SafeHTTPClient(deliveryTimeout),
		logger:     logger,
		breakers:   make(map[int64]*circuitBreaker),
		workerID:   uuid.New(),
	}
	for _, opt := range opts {
		if opt != nil {
			opt(d)
		}
	}
	return d
}

// Dispatch sends a CloudEvent to all matching active subscriptions.
func (d *Dispatcher) Dispatch(ctx context.Context, event wh.CloudEvent) {
	d.dispatch(ctx, event, nil, nil)
}

// DispatchForUser is the explicit legacy compatibility seam for a user-scoped
// event. It never guesses a subject from arbitrary payload JSON: SQL matches an
// organization subscription or the exact self owner in one predicate.
func (d *Dispatcher) DispatchForUser(ctx context.Context, subjectUserID int64, event wh.CloudEvent) {
	d.dispatch(ctx, event, &subjectUserID, nil)
}

// DispatchForMailbox is the legacy compatibility seam for a mailbox-scoped
// persistent event. SQL proves the mailbox belongs to the supplied subject user;
// a mismatched pair fails closed instead of broadening delivery.
func (d *Dispatcher) DispatchForMailbox(ctx context.Context, subjectUserID, subjectMailboxID int64, event wh.CloudEvent) {
	d.dispatch(ctx, event, &subjectUserID, &subjectMailboxID)
}

func (d *Dispatcher) dispatch(ctx context.Context, event wh.CloudEvent, subjectUserID, subjectMailboxID *int64) {
	body, err := event.Marshal()
	if err != nil {
		d.logger.Error("webhook marshal failed", "event_type", event.Type, "error", err)
		return
	}

	eventJSON, err := json.Marshal([]string{event.Type})
	if err != nil {
		d.logger.Error("webhook event type marshal failed", "event_type", event.Type, "error", err)
		return
	}

	query := `SELECT id,url FROM webhook_subscriptions
		 WHERE is_active=TRUE AND event_types @> $1::jsonb`
	args := []any{string(eventJSON)}
	if subjectMailboxID != nil {
		query += ` AND EXISTS (SELECT 1 FROM mailboxes WHERE id=$3 AND user_id=$2)
			AND (scope='organization' OR (scope='self' AND user_id=$2))`
		args = append(args, *subjectUserID, *subjectMailboxID)
	} else if subjectUserID != nil {
		query += ` AND (scope='organization' OR (scope='self' AND user_id=$2))`
		args = append(args, *subjectUserID)
	} else {
		// A generic event has no authenticated subject axis. Only an explicitly
		// organization-scoped subscription may receive it; default-self legacy
		// rows fail closed instead of silently retaining broad delivery.
		query += ` AND scope='organization'`
	}
	query += ` ORDER BY id`
	rows, err := d.pool.Query(ctx, query, args...)
	if err != nil {
		d.logger.Error("webhook query failed", "error", err)
		return
	}
	defer rows.Close()

	type sub struct {
		id  int64
		url string
	}
	var subs []sub
	for rows.Next() {
		var s sub
		if rows.Scan(&s.id, &s.url) == nil {
			subs = append(subs, s)
		}
	}

	pending := make([]deliveryTask, 0, len(subs))
	for _, s := range subs {
		// The signing secret never rides the fan-out query: it is loaded (and
		// a legacy plaintext row lazily re-sealed) per subscription through the
		// at-rest codec seam. A subscription whose secret cannot be opened
		// (unknown key id, codec missing) is SKIPPED — fail closed: never send
		// a delivery an attacker could forge (D6/DBSCHEMA-005).
		secret, err := wh.LoadSubscriptionSecret(ctx, d.pool, d.secretCodec, s.id)
		if err != nil {
			d.logger.Error("webhook dispatch: signing secret unavailable — skipping subscription (fail-closed)",
				"subscription_id", s.id, "error", err)
			continue
		}
		pending = append(pending, deliveryTask{subID: s.id, url: s.url, secret: secret,
			event: event, body: body, attempt: 1})
	}
	d.submit(context.WithoutCancel(ctx), pending, false)
}

// EnqueueDurable records one pending delivery per matching subscription before
// returning. A stable event ID therefore turns lifecycle-worker replay into a
// no-op at the subscriber boundary, while the retry worker can recover a crash
// between the database hand-off and the first HTTP attempt.
func (d *Dispatcher) EnqueueDurable(ctx context.Context, event wh.CloudEvent) error {
	body, err := event.Marshal()
	if err != nil {
		return err
	}
	eventJSON, err := json.Marshal([]string{event.Type})
	if err != nil {
		return err
	}
	rows, err := d.pool.Query(ctx, `
		SELECT id FROM webhook_subscriptions
		 WHERE is_active=TRUE AND scope='organization' AND event_types @> $1::jsonb
		 ORDER BY id`, string(eventJSON))
	if err != nil {
		return err
	}
	type subscription struct{ id int64 }
	subs := make([]subscription, 0)
	for rows.Next() {
		var sub subscription
		if err := rows.Scan(&sub.id); err != nil {
			rows.Close()
			return err
		}
		subs = append(subs, sub)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()

	for _, sub := range subs {
		var status string
		var attempt int
		err := d.pool.QueryRow(ctx, `
			INSERT INTO webhook_deliveries(
			  subscription_id,event_id,event_type,request_body,attempt,status)
			VALUES($1,$2,$3,$4,0,'pending')
			ON CONFLICT(subscription_id,event_id) DO UPDATE
			  SET event_type=webhook_deliveries.event_type
			RETURNING status,attempt`, sub.id, event.ID, event.Type, body,
		).Scan(&status, &attempt)
		if err != nil {
			return err
		}
		_ = status
		_ = attempt
	}
	d.claimDurable(context.WithoutCancel(ctx), event.ID)
	return nil
}

type deliveryTask struct {
	subID      int64
	url        string
	secret     string
	event      wh.CloudEvent
	body       []byte
	attempt    int
	durable    bool
	deliveryID int64
	leaseOwner uuid.UUID
}

func (d *Dispatcher) startExecutor(ctx context.Context) {
	d.executor.Do(func() {
		d.tasks = make(chan deliveryTask, deliveryQueueSize)
		d.admission = make(chan struct{}, deliveryWorkers+deliveryQueueSize)
		if d.workerID == uuid.Nil {
			d.workerID = uuid.New()
		}
		for i := 0; i < deliveryWorkers; i++ {
			d.executorWG.Add(1)
			go func() {
				defer d.executorWG.Done()
				for task := range d.tasks {
					attemptCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), deliveryTimeout)
					d.deliverTask(attemptCtx, task)
					cancel()
					<-d.admission
				}
			}()
		}
		d.started.Store(true)
		go func() {
			<-ctx.Done()
			d.submitMu.Lock()
			d.stopping.Store(true)
			close(d.tasks)
			d.submitMu.Unlock()
			d.executorWG.Wait()
		}()
	})
}

func (d *Dispatcher) submit(ctx context.Context, tasks []deliveryTask, durable bool) int {
	if len(tasks) == 0 {
		return 0
	}
	if !d.started.Load() {
		if d.logger != nil {
			d.logger.Warn("webhook delivery executor not started", "durable", durable)
		}
		return 0
	}
	d.submitMu.RLock()
	defer d.submitMu.RUnlock()
	if d.stopping.Load() {
		return 0
	}
	accepted := 0
	for _, task := range tasks {
		select {
		case d.admission <- struct{}{}:
		default:
			if d.logger != nil {
				d.logger.Warn("webhook delivery executor saturated",
					"durable", durable, "event_id", task.event.ID)
			}
			continue
		}
		select {
		case d.tasks <- task:
			accepted++
		default:
			<-d.admission
			if d.logger != nil {
				d.logger.Warn("webhook delivery executor saturated",
					"durable", durable, "event_id", task.event.ID)
			}
		}
	}
	return accepted
}

type deliveryClaim struct {
	ID             int64           `json:"id"`
	SubscriptionID int64           `json:"subscription_id"`
	EventID        string          `json:"event_id"`
	EventType      string          `json:"event_type"`
	RequestBody    json.RawMessage `json:"request_body"`
	Attempt        int             `json:"attempt"`
	URL            string          `json:"url"`
	// Deliberately NO secret cell: the signing secret is not copied into the
	// claim envelope. It is loaded per claim through the at-rest codec seam
	// (LoadSubscriptionSecret) so the plaintext exists only in the worker's
	// memory for the duration of one signing operation (D6/DBSCHEMA-005).
}

// claimDurable reserves only as many rows as the fixed executor can admit.
// The lease and attempt increment happen atomically under SKIP LOCKED before
// any task enters memory, so saturation cannot repeatedly select a hot prefix.
func (d *Dispatcher) claimDurable(ctx context.Context, eventID string) int {
	if !d.started.Load() || d.pool == nil {
		return 0
	}
	d.submitMu.RLock()
	defer d.submitMu.RUnlock()
	if d.stopping.Load() {
		return 0
	}
	reserved := 0
	for reserved < deliveryBatchSize {
		select {
		case d.admission <- struct{}{}:
			reserved++
		default:
			goto reservedDone
		}
	}
reservedDone:
	if reserved == 0 {
		return 0
	}
	var raw []byte
	var eventFilter any
	if eventID != "" {
		eventFilter = eventID
	}
	if err := d.pool.QueryRow(ctx, `SELECT webhook_delivery_claim($1,$2,$3)`,
		d.workerID, reserved, eventFilter).Scan(&raw); err != nil {
		for i := 0; i < reserved; i++ {
			<-d.admission
		}
		if d.logger != nil && ctx.Err() == nil {
			d.logger.Warn("webhook delivery claim failed", "error", err)
		}
		return 0
	}
	var claims []deliveryClaim
	if err := json.Unmarshal(raw, &claims); err != nil {
		for i := 0; i < reserved; i++ {
			<-d.admission
		}
		if d.logger != nil {
			d.logger.Warn("webhook delivery claim decode failed", "error", err)
		}
		return 0
	}
	for i := len(claims); i < reserved; i++ {
		<-d.admission
	}
	accepted := 0
	for _, claim := range claims {
		var event wh.CloudEvent
		if claim.ID <= 0 || claim.SubscriptionID <= 0 || claim.Attempt < 1 ||
			json.Unmarshal(claim.RequestBody, &event) != nil {
			d.completeDurable(ctx, claim.ID, d.workerID, false, false, 0, "", 0,
				"invalid durable delivery claim")
			<-d.admission
			continue
		}
		// Signing secret loaded per claim through the at-rest codec seam
		// (lazy migration included). A secret that cannot be opened (unknown
		// key id, row without any secret) fails the delivery closed — exactly
		// the below-minimum-secret defect class deliverTask refuses — instead
		// of sending a message an attacker could forge.
		//
		// The failure settles RETRYABLE (Astra D6 impl-r2 finding 4): a
		// transient read error (database hiccup, briefly unavailable key
		// configuration) must not permanently exhaust a durable delivery
		// through webhook_delivery_complete's terminal branch. No HTTP is
		// attempted — the claim is settled unmet and the row returns to the
		// backoff queue; only a subscription-configuration fault that outlives
		// max_retries ends exhausted. A nil codec (misconfiguration) fails the
		// same way: deliveries stall visibly instead of draining as exhausted.
		secret, err := wh.LoadSubscriptionSecret(ctx, d.pool, d.secretCodec, claim.SubscriptionID)
		if err != nil {
			if d.logger != nil {
				d.logger.Error("webhook delivery: signing secret unavailable — failing delivery retryable (fail-closed, no HTTP)",
					"subscription_id", claim.SubscriptionID, "delivery_id", claim.ID, "error", err)
			}
			d.completeDurable(ctx, claim.ID, d.workerID, false, true, 0, "", 0,
				"signing secret unavailable: "+err.Error())
			<-d.admission
			continue
		}
		task := deliveryTask{subID: claim.SubscriptionID, url: claim.URL, secret: secret,
			event: event, body: claim.RequestBody, attempt: claim.Attempt, durable: true,
			deliveryID: claim.ID, leaseOwner: d.workerID}
		// Admission tokens count running+queued work, so a reserved task always
		// has a queue slot even while all fixed workers are busy.
		d.tasks <- task
		accepted++
	}
	return accepted
}

func (d *Dispatcher) deliverTask(ctx context.Context, task deliveryTask) {
	subID, url, secret := task.subID, task.url, task.secret
	event, body, attempt := task.event, task.body, task.attempt
	d.mu.Lock()
	cb, ok := d.breakers[subID]
	if !ok {
		cb = &circuitBreaker{}
		d.breakers[subID] = cb
	}
	d.mu.Unlock()

	if cb.isOpen() {
		if d.logger != nil {
			d.logger.Warn("circuit breaker open, skipping delivery", "subscription_id", subID)
		}
		if task.durable {
			d.completeDurable(ctx, task.deliveryID, task.leaseOwner, false, true,
				0, "", 0, "circuit breaker open")
		}
		return
	}

	sigHeader, err := wh.Sign(body, secret)
	if err != nil {
		// A below-minimum signing secret is a subscription-configuration
		// defect (D-SHARED-WEBHOOK-002: both minting paths generate 32-byte
		// secrets; this guard catches hand-edited rows). Fail the delivery
		// loudly instead of sending a message an attacker could forge.
		if d.logger != nil {
			d.logger.Error("webhook delivery: signing secret rejected — failing delivery (fail-closed)",
				"subscription_id", subID, "error", err)
		}
		if task.durable {
			d.completeDurable(ctx, task.deliveryID, task.leaseOwner, false, false,
				0, "", 0, err.Error())
		}
		return
	}
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
	if err != nil {
		if task.durable {
			d.completeDurable(ctx, task.deliveryID, task.leaseOwner, false, false,
				0, "", 0, err.Error())
		}
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Webhook-Signature", sigHeader)

	start := time.Now()
	resp, err := d.httpClient.Do(req)
	latency := int(time.Since(start).Milliseconds())

	deliveryStatus := "success"
	var respCode int
	var respBody string
	var errMsg string

	if err != nil {
		deliveryStatus = "failed"
		errMsg = err.Error()
	} else {
		respCode = resp.StatusCode
		buf := make([]byte, 1024)
		n, _ := resp.Body.Read(buf)
		respBody = string(buf[:n])
		resp.Body.Close()

		if respCode >= 500 || respCode == 429 {
			deliveryStatus = "failed"
		} else if respCode >= 400 {
			deliveryStatus = "exhausted" // permanent 4xx failure
		}
	}

	if task.durable {
		d.completeDurable(ctx, task.deliveryID, task.leaseOwner,
			deliveryStatus == "success", deliveryStatus == "failed",
			respCode, respBody, latency, errMsg)
	} else if d.pool != nil {
		// Legacy best-effort attempts keep the historical upsert behavior.
		_, logErr := d.pool.Exec(ctx,
			`INSERT INTO webhook_deliveries (subscription_id, event_id, event_type, request_body, response_code, response_body, latency_ms, attempt, status, error_message, completed_at)
			 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,now())
			 ON CONFLICT (subscription_id,event_id) DO UPDATE SET
			   attempt=EXCLUDED.attempt,status=EXCLUDED.status,response_code=EXCLUDED.response_code,
			   response_body=EXCLUDED.response_body,latency_ms=EXCLUDED.latency_ms,
			   error_message=EXCLUDED.error_message,completed_at=EXCLUDED.completed_at
			 WHERE webhook_deliveries.status IN ('pending','failed')
			   AND webhook_deliveries.attempt<EXCLUDED.attempt`,
			subID, event.ID, event.Type, string(body), respCode, respBody, latency,
			attempt, deliveryStatus, errMsg)
		if logErr != nil && d.logger != nil {
			d.logger.Warn("webhook delivery log write failed", "sub_id", subID, "event_id", event.ID, "error", logErr)
		}
	}

	if deliveryStatus == "success" {
		cb.onSuccess()
	} else {
		cb.onFailure()
	}
}

func (d *Dispatcher) completeDurable(ctx context.Context, deliveryID int64, workerID uuid.UUID,
	succeeded, retryable bool, responseCode int, responseBody string, latencyMS int, errorMessage string,
) {
	if d.pool == nil || deliveryID <= 0 || workerID == uuid.Nil {
		return
	}
	settleCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), settlementTimeout)
	defer cancel()
	var completed bool
	err := d.pool.QueryRow(settleCtx,
		`SELECT webhook_delivery_complete($1,$2,$3,$4,$5,$6,$7,$8)`,
		deliveryID, workerID, succeeded, retryable, responseCode, responseBody,
		latencyMS, errorMessage).Scan(&completed)
	if (err != nil || !completed) && d.logger != nil {
		d.logger.Warn("webhook durable delivery settlement failed", "delivery_id", deliveryID,
			"completed", completed, "error", err)
	}
}

// StartRetryWorker runs a background goroutine that re-delivers 'failed'
// deliveries up to max_retries (honouring retry_enabled and exponential
// backoff). It ticks every retryTickInterval and exits when ctx is cancelled.
//
// Call this once after creating the Dispatcher; it must receive a lifecycle
// context (not a request context) so retries outlive individual requests.
func (d *Dispatcher) StartRetryWorker(ctx context.Context) {
	// This lifecycle call is the single executor owner. It must run before any
	// request handler can submit, so workers always terminate with lifecycle ctx.
	d.startExecutor(ctx)
	// Complete the first residue claim before callers can submit. Running this
	// inside the goroutine would transiently reserve every admission token and
	// could make the first request observe false saturation.
	d.retryPending(ctx)
	go func() {
		tick := time.NewTicker(retryTickInterval)
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
				d.retryPending(ctx)
			}
		}
	}()
}

// retryPending atomically admits only rows the fixed executor can accept.
// Backoff and subscription retry policy are re-checked by the claim reducer.
func (d *Dispatcher) retryPending(ctx context.Context) {
	d.claimDurable(ctx, "")
}

// DeliverPendingEvent performs the bounded immediate handoff after a publication
// fact has durably fanned out. Rows left by a crash are independently recovered
// by retryPending, so this latency optimization is never the durability owner.
func (d *Dispatcher) DeliverPendingEvent(ctx context.Context, eventID string) {
	d.claimDurable(ctx, eventID)
}

// circuitBreaker implements a simple failure-counting circuit breaker.
type circuitBreaker struct {
	mu            sync.Mutex
	failures      int
	lastFailureAt time.Time
	isOpenState   bool
}

func (cb *circuitBreaker) onSuccess() {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	cb.failures = 0
	cb.isOpenState = false
}

func (cb *circuitBreaker) onFailure() {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	cb.failures++
	cb.lastFailureAt = time.Now()
	if cb.failures >= 10 {
		cb.isOpenState = true
	}
}

func (cb *circuitBreaker) isOpen() bool {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	if !cb.isOpenState {
		return false
	}
	if time.Since(cb.lastFailureAt) > 2*time.Minute {
		cb.isOpenState = false
		cb.failures = 0
		return false
	}
	return true
}
