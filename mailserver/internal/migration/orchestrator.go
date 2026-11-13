package migration

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/minio/minio-go/v7"
	"setjoin.com/mailserver/internal/mimeutil"
	"setjoin.com/shared/envutil"
	wh "setjoin.com/shared/webhook"
)

// UploadData holds uploaded ICS/VCF file contents for a migration job.
type UploadData struct {
	ICS []byte
	VCF []byte
}

// Orchestrator manages the lifecycle of migration jobs.
type Orchestrator struct {
	pool           *pgxpool.Pool
	minio          *minio.Client
	bucket         string
	logger         *slog.Logger
	encryptionKey  []byte // HKDF-derived key for migration config encryption
	systemKey      []byte // HKDF-derived key for system_config secrets
	encryptionRoot string // raw DB_ENCRYPTION_KEY for deriving purpose keys
	dispatcher     terminalEventDispatcher
	activeJobs     map[int64]*jobState
	mu             sync.Mutex
	stopping       bool
	ctx            context.Context // lifecycle context for background job operations
}

type terminalEventDispatcher interface {
	DispatchForUser(context.Context, int64, wh.CloudEvent)
	DispatchForMailbox(context.Context, int64, int64, wh.CloudEvent)
}

const uploadPrefix = "migration/upload/" // MinIO key prefix for uploaded ICS/VCF blobs

type jobState struct {
	cancel      context.CancelFunc
	pauseCh     chan struct{}
	pauseAck    chan struct{}
	resumeCh    chan struct{}
	shouldPause bool
}

// NewOrchestrator creates a new migration orchestrator.
func NewOrchestrator(pool *pgxpool.Pool, minioClient *minio.Client, bucket string, encryptionRoot string, logger *slog.Logger, ctx context.Context, dispatcher terminalEventDispatcher) *Orchestrator {
	migrationKey, _ := DeriveKey(encryptionRoot, "migration")
	systemKey, _ := DeriveKey(encryptionRoot, "system")
	return &Orchestrator{
		pool:           pool,
		minio:          minioClient,
		bucket:         bucket,
		logger:         logger,
		encryptionKey:  migrationKey,
		systemKey:      systemKey,
		encryptionRoot: encryptionRoot,
		dispatcher:     dispatcher,
		activeJobs:     make(map[int64]*jobState),
		ctx:            ctx,
	}
}

// StoreUpload saves ICS or VCF upload data to MinIO.
func (o *Orchestrator) StoreUpload(ctx context.Context, jobID int64, data *UploadData) error {
	if len(data.ICS) > 0 {
		key := fmt.Sprintf("%s%d/ics", uploadPrefix, jobID)
		if _, err := o.minio.PutObject(ctx, o.bucket, key, bytes.NewReader(data.ICS), int64(len(data.ICS)), minio.PutObjectOptions{}); err != nil {
			return fmt.Errorf("store ics upload: %w", err)
		}
	}
	if len(data.VCF) > 0 {
		key := fmt.Sprintf("%s%d/vcf", uploadPrefix, jobID)
		if _, err := o.minio.PutObject(ctx, o.bucket, key, bytes.NewReader(data.VCF), int64(len(data.VCF)), minio.PutObjectOptions{}); err != nil {
			return fmt.Errorf("store vcf upload: %w", err)
		}
	}
	return nil
}

func (o *Orchestrator) loadUpload(ctx context.Context, jobID int64, suffix string) ([]byte, error) {
	key := fmt.Sprintf("%s%d/%s", uploadPrefix, jobID, suffix)
	obj, err := o.minio.GetObject(ctx, o.bucket, key, minio.GetObjectOptions{})
	if err != nil {
		return nil, err
	}
	defer obj.Close()
	return io.ReadAll(obj)
}

// EncryptionKey returns the orchestrator's migration-purpose AES encryption key.
func (o *Orchestrator) EncryptionKey() []byte {
	return o.encryptionKey
}

// EncryptionRoot returns the raw DB_ENCRYPTION_KEY for deriving purpose keys.
func (o *Orchestrator) EncryptionRoot() string {
	return o.encryptionRoot
}

// StartJob begins executing a migration job in a background goroutine.
func (o *Orchestrator) StartJob(ctx context.Context, jobID int64) error {
	o.mu.Lock()
	if _, exists := o.activeJobs[jobID]; exists {
		o.mu.Unlock()
		return fmt.Errorf("job %d is already running", jobID)
	}
	js := &jobState{
		pauseCh:  make(chan struct{}, 1),
		pauseAck: make(chan struct{}),
		resumeCh: make(chan struct{}, 1),
	}
	// State-machine race fix (D-MAILSERVER-INTERNAL-MIGRATION-F-003): the
	// job's context is created and its cancel stored INSIDE the mutex, so a
	// CancelJob that lands after the map insertion observes the REAL cancel —
	// never the do-nothing placeholder that made a cancel of a just-started
	// job succeed while stopping nothing. The happens-before edge is the
	// mutex itself: every js.cancel read in CancelJob/PauseJob/ResumeJob is
	// also under o.mu.
	jobCtx, cancel := context.WithCancel(o.ctx)
	js.cancel = cancel
	o.activeJobs[jobID] = js
	o.mu.Unlock()

	go o.runJob(jobCtx, jobID, js)
	return nil
}

// CancelJob cancels a running migration job.
func (o *Orchestrator) CancelJob(jobID int64) error {
	o.mu.Lock()
	js, exists := o.activeJobs[jobID]
	o.mu.Unlock()
	if !exists {
		return fmt.Errorf("job %d is not running", jobID)
	}
	js.cancel()
	return nil
}

// PauseJob triggers a graceful pause on a running migration job.
func (o *Orchestrator) PauseJob(jobID int64) error {
	o.mu.Lock()
	js, exists := o.activeJobs[jobID]
	o.mu.Unlock()
	if !exists {
		return fmt.Errorf("job %d is not running", jobID)
	}
	select {
	case js.pauseCh <- struct{}{}:
	default:
	}
	return nil
}

// ResumeJob resumes a paused migration job.
func (o *Orchestrator) ResumeJob(jobID int64) error {
	o.mu.Lock()
	js, exists := o.activeJobs[jobID]
	o.mu.Unlock()
	if !exists {
		// Job was paused and goroutine returned — restart
		return o.StartJob(o.ctx, jobID)
	}
	select {
	case js.resumeCh <- struct{}{}:
	default:
	}
	return nil
}

// IsRunning returns true if a job is running or paused (active goroutine).
func (o *Orchestrator) IsRunning(jobID int64) bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	_, exists := o.activeJobs[jobID]
	return exists
}

// orchestrate is the single seam through which every migration_jobs row mutation
// flows. It calls the migration_orchestrate reducer, which performs the whole
// phase transition (status + cursor/delta/progress merge + error-log append +
// terminal NULLing) atomically in one transaction. patch may be nil. Returns the
// new status. The connector/MinIO I/O and webhook dispatch stay in Go.
func (o *Orchestrator) orchestrate(ctx context.Context, jobID int64, phase string, patch map[string]any) (string, error) {
	var out []byte
	if err := o.pool.QueryRow(ctx,
		`SELECT migration_orchestrate($1,$2,$3)`,
		jobID, phase, jsonMarshal(patch),
	).Scan(&out); err != nil {
		o.logger.Error("migration: orchestrate failed", "job_id", jobID, "phase", phase, "error", err)
		return "", err
	}
	var r struct {
		Status              string `json:"status"`
		EventType           string `json:"event_type"`
		SubjectUserID       int64  `json:"subject_user_id"`
		SubjectMailboxID    *int64 `json:"subject_mailbox_id"`
		PublicationEnrolled bool   `json:"publication_enrolled"`
	}
	_ = json.Unmarshal(out, &r)
	o.dispatchTerminalEvent(ctx, migrationTerminalEvent{
		JobID: jobID, EventType: r.EventType, SubjectUserID: r.SubjectUserID,
		SubjectMailboxID: r.SubjectMailboxID, PublicationEnrolled: r.PublicationEnrolled,
	})
	return r.Status, nil
}

type migrationTerminalEvent struct {
	JobID               int64  `json:"job_id"`
	EventType           string `json:"event_type"`
	SubjectUserID       int64  `json:"subject_user_id"`
	SubjectMailboxID    *int64 `json:"subject_mailbox_id"`
	PublicationEnrolled bool   `json:"publication_enrolled"`
}

func (o *Orchestrator) dispatchTerminalEvent(ctx context.Context, e migrationTerminalEvent) {
	if e.PublicationEnrolled || e.EventType == "" || e.SubjectUserID == 0 || o.dispatcher == nil {
		return
	}
	event := wh.NewCloudEvent("mailserver/gateway", e.EventType, map[string]interface{}{"job_id": e.JobID})
	if e.SubjectMailboxID != nil {
		o.dispatcher.DispatchForMailbox(ctx, e.SubjectUserID, *e.SubjectMailboxID, event)
		return
	}
	o.dispatcher.DispatchForUser(ctx, e.SubjectUserID, event)
}

// RecoverStuckJobs finds jobs stuck in non-terminal states from a previous run
// and marks them failed via the migration_recover_stuck reducer (atomic bulk
// UPDATE), then dispatches migration.failed webhooks for each affected job.
func (o *Orchestrator) RecoverStuckJobs(ctx context.Context) {
	var out []byte
	if err := o.pool.QueryRow(ctx, `SELECT migration_recover_stuck()`).Scan(&out); err != nil {
		o.logger.Error("migration recovery: recover_stuck failed", "error", err)
		return
	}
	var r struct {
		IDs            []int64                  `json:"ids"`
		TerminalEvents []migrationTerminalEvent `json:"terminal_events"`
	}
	_ = json.Unmarshal(out, &r)
	if len(r.IDs) == 0 {
		return
	}

	o.logger.Info("migration recovery: marked stuck jobs as failed", "count", len(r.IDs))
	for _, event := range r.TerminalEvents {
		o.dispatchTerminalEvent(ctx, event)
	}
}

// Shutdown gracefully stops all running jobs (saves cursor, marks paused).
func (o *Orchestrator) Shutdown() {
	o.mu.Lock()
	o.stopping = true
	jobs := make([]*jobState, 0, len(o.activeJobs))
	for _, js := range o.activeJobs {
		jobs = append(jobs, js)
	}
	o.mu.Unlock()

	o.logger.Info("migration: shutting down", "active_jobs", len(jobs))
	for _, js := range jobs {
		select {
		case js.pauseCh <- struct{}{}:
		default:
		}
	}
}

// --- Internal ---

func (o *Orchestrator) runJob(ctx context.Context, jobID int64, js *jobState) {
	defer func() {
		o.mu.Lock()
		delete(o.activeJobs, jobID)
		o.mu.Unlock()
	}()

	job, err := o.loadJob(ctx, jobID)
	if err != nil {
		o.logger.Error("migration: load job failed", "job_id", jobID, "error", err)
		return
	}

	// Retained binaries and feature-OFF jobs still resume from the legacy
	// projection; the source session owns interpreting it.
	resume := o.loadLegacySourceResume(ctx, jobID)

	// Mark as started or resumed (atomic phase transition via the reducer).
	if job.Status == "paused" {
		_, _ = o.orchestrate(ctx, jobID, "resume", nil)
	} else {
		_, _ = o.orchestrate(ctx, jobID, "start", nil)
	}

	// Phase 1 — connector-based import (IMAP, EWS, or M365)
	if job.SourceType == "imap" || job.SourceType == "ews" || job.SourceType == "m365" {
		conn, err := o.createConnector(ctx, jobID, job.SourceType, job.SourceConfigEnc)
		if err != nil {
			o.logger.Error("migration: create connector failed", "job_id", jobID, "error", err)
			_, _ = o.orchestrate(ctx, jobID, "fail",
				map[string]any{"errors": []string{fmt.Sprintf("connector: %v", err)}})
			return
		}
		if err := o.runConnectorPhase(ctx, jobID, conn, resume, js); err != nil {
			if ctx.Err() != nil {
				o.finalizePauseOrCancel(jobID, js)
				return
			}
			_, _ = o.orchestrate(o.ctx, jobID, "fail", map[string]any{"errors": []string{err.Error()}})
			return
		}
		if ctx.Err() != nil {
			o.finalizePauseOrCancel(jobID, js)
			return
		}
	}

	// Legacy: pipe-delimited source_type with "imap" substring (e.g. "imap|ics").
	// Routes through the same IMAP factory + connector phase as a plain "imap"
	// job so the dedup/progress/pause loop is single-sourced.
	if ContainsSourceType(job.SourceType, "imap") && job.SourceType != "imap" {
		conn, err := o.createConnector(ctx, jobID, "imap", job.SourceConfigEnc)
		if err != nil {
			o.logger.Error("migration: create connector failed", "job_id", jobID, "error", err)
			_, _ = o.orchestrate(ctx, jobID, "fail",
				map[string]any{"errors": []string{fmt.Sprintf("connector: %v", err)}})
			return
		}
		if err := o.runConnectorPhase(ctx, jobID, conn, resume, js); err != nil {
			if ctx.Err() != nil {
				o.finalizePauseOrCancel(jobID, js)
				return
			}
			_, _ = o.orchestrate(o.ctx, jobID, "fail", map[string]any{"errors": []string{err.Error()}})
			return
		}
		if ctx.Err() != nil {
			o.finalizePauseOrCancel(jobID, js)
			return
		}
	}

	// Phase 2 — ICS calendar import
	if ContainsSourceType(job.SourceType, "ics") {
		o.runICSPhase(ctx, jobID, job)
		if ctx.Err() != nil {
			o.finalizePauseOrCancel(jobID, js)
			return
		}
	}

	// Phase 3 — VCF contacts import
	if ContainsSourceType(job.SourceType, "vcf") {
		o.runVCFPhase(ctx, jobID, job)
		if ctx.Err() != nil {
			o.finalizePauseOrCancel(jobID, js)
			return
		}
	}

	// Mark completed — the reducer NULLs credentials + cursor and stamps completed_at.
	_, _ = o.orchestrate(o.ctx, jobID, "complete", nil)
	o.logger.Info("migration: job completed", "job_id", jobID)
}

// finalizePauseOrCancel routes a context-cancelled phase exit to the right
// terminal transition: a graceful pause (shouldPause) → 'pause', otherwise a
// cancel → 'cancel'. Both go through the atomic reducer.
func (o *Orchestrator) finalizePauseOrCancel(jobID int64, js *jobState) {
	if js.shouldPause {
		_, _ = o.orchestrate(o.ctx, jobID, "pause", nil)
		o.logger.Info("migration: job paused", "job_id", jobID)
	} else {
		_, _ = o.orchestrate(o.ctx, jobID, "cancel", nil)
		o.logger.Info("migration: job cancelled", "job_id", jobID)
	}
}

// createConnector returns the appropriate Connector for the given source type by
// dispatching through the per-source ConnectorFactory table. Each factory owns
// its own config-merge (global defaults ⊕ per-job overrides), decrypt, and auth
// strategy. Any source type not in the table falls back to the IMAP factory,
// preserving the prior switch-default behavior. useGlobalAuth is read from the
// job config so the factory can skip the global merge when the job carries its
// own credentials.
func (o *Orchestrator) createConnector(ctx context.Context, jobID int64, sourceType string, configEnc []byte) (SourceSession, error) {
	var jobCfg MigrationJobConfig
	if err := DecryptConfigAny(configEnc, o.encryptionKey, &jobCfg); err != nil {
		return nil, fmt.Errorf("decrypt job config: %w", err)
	}

	factories := o.connectorFactories()
	factory, ok := factories[sourceType]
	if !ok {
		factory = imapFactory{o}
	}
	return factory.Create(ctx, jobID, configEnc, jobCfg.UseGlobalAuth)
}

// runConnectorPhase runs the connector-based migration phase (IMAP, EWS, or M365).
func (o *Orchestrator) runConnectorPhase(ctx context.Context, jobID int64, session SourceSession, resume SourceResumeState, js *jobState) error {
	mailboxID := o.getMailboxID(ctx, jobID)
	if mailboxID == 0 {
		return fmt.Errorf("migration target mailbox is missing")
	}
	// CONTACTS-002 r2 (Astra HOLD finding 1): the feature-OFF contact branch
	// used to pass mailboxID into ImportVCF's addressBookID parameter, so a
	// mailbox id numerically matching another tenant's address-book id made the
	// owner-scope-0 legacy wrapper insert cross-tenant. The target book is now
	// resolved UNDER the target mailbox (same mailbox_id-scoped shape the VCF
	// upload phase uses via getDefaultAddressBookID) and the import goes through
	// ImportVCFOwned with that mailbox as the verified owner — the same owner
	// scope the authenticated HTTP path threads. Resolution happens lazily on
	// the first contact item so mail-only connector jobs neither require nor
	// touch an address book; a resolution failure is an explicit phase error,
	// never a silent fallback to the unscoped wrapper.
	var (
		migrationBookID  int64
		migrationBookSet bool
	)
	resolveMigrationBook := func(resolveCtx context.Context) (int64, error) {
		if migrationBookSet {
			return migrationBookID, nil
		}
		id, err := o.defaultAddressBookIDForMailbox(resolveCtx, mailboxID)
		if err != nil {
			return 0, fmt.Errorf("resolve default address book for mailbox %d: %w", mailboxID, err)
		}
		if id == 0 {
			return 0, fmt.Errorf("migration target mailbox %d has no default address book", mailboxID)
		}
		migrationBookID, migrationBookSet = id, true
		return migrationBookID, nil
	}
	phaseCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	identity, err := session.ResolveSourceIdentity(phaseCtx)
	if err != nil {
		return fmt.Errorf("resolve source mailbox: %w", err)
	}
	useSourceIdentity := o.featureEnabled(phaseCtx, "feature.mail_migration_source_identity")
	var sourceGeneration int64 = 1
	if useSourceIdentity {
		var err error
		sourceGeneration, err = o.bindSourceIdentity(phaseCtx, jobID, identity)
		if err != nil {
			return err
		}
		// Resolve twice around connector construction/preflight. A selector that
		// changes between authentication and enumeration must fail before the first
		// source item is projected.
		revalidated, err := session.ResolveSourceIdentity(phaseCtx)
		if err != nil {
			return fmt.Errorf("revalidate source mailbox: %w", err)
		}
		if revalidated.SourceType != identity.SourceType ||
			revalidated.MailboxKey != identity.MailboxKey ||
			revalidated.SelectorDigest != identity.SelectorDigest {
			return fmt.Errorf("source mailbox changed between preflight and enumeration")
		}
		resume.Durable = o.loadSourceCheckpoints(phaseCtx, jobID, sourceGeneration)
	}
	if err := session.RestoreSourceState(resume); err != nil {
		return err
	}

	phaseProgress := map[string]interface{}{
		"items_done":   0,
		"items_failed": 0,
		"imported":     0,
		"updated":      0,
		"moved":        0,
		"deleted":      0,
		"unchanged":    0,
		"replayed":     0,
	}
	lastSave := time.Now()
	currentFolder := ""
	stream := session.IterateSource(phaseCtx)
	err = consumeSourceBatches(ctx, stream, func(batchCtx context.Context, batch SourceBatch) error {
		// Dedupe is intentionally scoped to one closed provider page. Stable
		// operation IDs in the reducers own all cross-page/crash replay.
		for _, item := range dedupeSourceBatch(batch.Items) {
			select {
			case <-batchCtx.Done():
				return batchCtx.Err()
			case <-js.pauseCh:
				js.pauseAck <- struct{}{}
				o.updateProgress(batchCtx, jobID, "connector", phaseProgress)
				select {
				case <-js.resumeCh:
				case <-batchCtx.Done():
					return batchCtx.Err()
				}
			default:
			}

			if js.shouldPause {
				o.updateProgress(batchCtx, jobID, "connector", phaseProgress)
				_, _ = o.orchestrate(o.ctx, jobID, "pause", nil)
				return context.Canceled
			}
			if item.Change == "" {
				item.Change = SourceUpsert
			}
			if item.SourceObjectID == "" {
				return fmt.Errorf("connector returned %s object without immutable source id", item.Type)
			}
			if item.Change == SourceDelete && !useSourceIdentity {
				// Tombstones require the durable source-object map. While the cutover
				// flag is OFF, retain the legacy append-only projection.
				continue
			}
			folderKey := strings.Join(item.FolderPath, "/")

			// Track current folder for progress reporting
			if folderKey != currentFolder {
				currentFolder = folderKey
				phaseProgress["current_folder"] = currentFolder
			}

			switch item.Type {
			case ItemMail:
				outcome, err := o.importMailItem(batchCtx, jobID, mailboxID, item, useSourceIdentity)
				if err != nil {
					phaseProgress["items_failed"] = phaseProgress["items_failed"].(int) + 1
					return fmt.Errorf("import source object %q: %w", item.SourceObjectID, err)
				}
				incrementMigrationOutcome(phaseProgress, outcome)
			case ItemCalendar:
				if useSourceIdentity {
					outcome, err := o.importAuxItem(batchCtx, jobID, mailboxID, item)
					if err != nil {
						phaseProgress["items_failed"] = phaseProgress["items_failed"].(int) + 1
						return fmt.Errorf("import source event %q: %w", item.SourceObjectID, err)
					}
					incrementMigrationOutcome(phaseProgress, outcome)
					break
				}
				imported, _, importErrs := ImportICS(batchCtx, o.pool, item.RawICS, mailboxID, "", "skip")
				if len(importErrs) > 0 {
					phaseProgress["items_failed"] = phaseProgress["items_failed"].(int) + 1
					return fmt.Errorf("import source event %q: %s", item.SourceObjectID, importErrs[0])
				}
				_ = imported
			case ItemContact:
				if useSourceIdentity {
					outcome, err := o.importAuxItem(batchCtx, jobID, mailboxID, item)
					if err != nil {
						phaseProgress["items_failed"] = phaseProgress["items_failed"].(int) + 1
						return fmt.Errorf("import source contact %q: %w", item.SourceObjectID, err)
					}
					incrementMigrationOutcome(phaseProgress, outcome)
					break
				}
				bookID, bookErr := resolveMigrationBook(batchCtx)
				if bookErr != nil {
					phaseProgress["items_failed"] = phaseProgress["items_failed"].(int) + 1
					return fmt.Errorf("import source contact %q: %w", item.SourceObjectID, bookErr)
				}
				imported, _, importErrs := ImportVCFOwned(batchCtx, o.pool, item.RawVCF, bookID, mailboxID, "skip")
				if len(importErrs) > 0 {
					phaseProgress["items_failed"] = phaseProgress["items_failed"].(int) + 1
					return fmt.Errorf("import source contact %q: %s", item.SourceObjectID, importErrs[0])
				}
				_ = imported
			}
			phaseProgress["items_done"] = phaseProgress["items_done"].(int) + 1
		}
		if err := o.commitCheckpointSnapshot(batchCtx, jobID, batch.Candidate, sourceGeneration,
			phaseProgress["items_done"].(int), useSourceIdentity); err != nil {
			return err
		}
		// Progress may lag a committed checkpoint after a crash, but source data
		// cannot be lost: reducer operation IDs already made every covered apply
		// durable before the candidate was committed.
		if time.Since(lastSave) > 10*time.Second {
			o.updateProgress(batchCtx, jobID, "connector", phaseProgress)
			lastSave = time.Now()
		}
		return nil
	})
	if err != nil {
		drainCtx, drainCancel := context.WithTimeout(context.WithoutCancel(ctx), sourceStreamJoinTimeout)
		o.updateProgress(drainCtx, jobID, "connector", phaseProgress)
		drainCancel()
		return err
	}
	o.updateProgress(ctx, jobID, "connector", phaseProgress)
	if useSourceIdentity {
		if err := o.runThreadReconcile(ctx, jobID); err != nil {
			return err
		}
	}
	return nil
}

// defaultAddressBookIDForMailbox resolves the target mailbox's default address
// book scoped by the mailbox id itself (CONTACTS-002 r2): the connector contact
// import must land in a book provably under the job's target mailbox, never in
// a numerically colliding book of another tenant. Unlike the upload phase's
// user-scoped getDefaultAddressBookID, this variant takes no detour through the
// user's other mailboxes. Returns (0, nil) when the mailbox has no default
// book; callers turn that into an explicit phase error.
func (o *Orchestrator) defaultAddressBookIDForMailbox(ctx context.Context, mailboxID int64) (int64, error) {
	var id int64
	err := o.pool.QueryRow(ctx,
		`SELECT id FROM addressbooks WHERE mailbox_id = $1 AND is_default = TRUE LIMIT 1`,
		mailboxID,
	).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	return id, nil
}

func (o *Orchestrator) runThreadReconcile(ctx context.Context, jobID int64) error {
	var start []byte
	if err := o.pool.QueryRow(ctx, `SELECT migration_thread_reconcile_start($1)`, jobID).Scan(&start); err != nil {
		return fmt.Errorf("start thread reconciliation: %w", err)
	}
	for {
		var raw []byte
		if err := o.pool.QueryRow(ctx, `SELECT migration_thread_reconcile_batch($1,1000)`, jobID).Scan(&raw); err != nil {
			return fmt.Errorf("reconcile imported threads: %w", err)
		}
		var result struct {
			Processed int64 `json:"processed"`
			Remaining int64 `json:"remaining"`
		}
		if err := json.Unmarshal(raw, &result); err != nil {
			return fmt.Errorf("decode thread reconciliation receipt: %w", err)
		}
		o.updateProgress(ctx, jobID, "thread_reconcile", map[string]interface{}{
			"processed": result.Processed, "remaining": result.Remaining,
		})
		if result.Remaining == 0 {
			return nil
		}
		if result.Processed == 0 {
			return fmt.Errorf("thread reconciliation made no progress with %d remaining", result.Remaining)
		}
	}
}

// commitCheckpointSnapshot persists one closed provider page only after every
// target apply in that page succeeded. The adapter owns serialization; the
// orchestrator owns the durable commit decision.
func (o *Orchestrator) commitCheckpointSnapshot(ctx context.Context, jobID int64, snapshot SourceCheckpointSnapshot,
	sourceGeneration int64, committedCount int, useSourceIdentity bool,
) error {
	if useSourceIdentity {
		if len(snapshot.Candidates) != 1 {
			return fmt.Errorf("source batch returned %d checkpoint candidates; want exactly one", len(snapshot.Candidates))
		}
		for _, candidate := range snapshot.Candidates {
			if candidate.Scope == "" || candidate.LegacyScope == "" || candidate.Kind == "" || len(candidate.Value) == 0 {
				return fmt.Errorf("source session returned an incomplete checkpoint candidate")
			}
			if _, err := o.pool.Exec(ctx, `SELECT migration_checkpoint_commit_v2($1,$2,$3,$4,$5,$6,$7)`,
				jobID, candidate.Scope, candidate.LegacyScope, candidate.Kind, candidate.Value, sourceGeneration, committedCount); err != nil {
				return fmt.Errorf("commit %s checkpoint %q: %w", candidate.Kind, candidate.Scope, err)
			}
		}
		return nil
	}
	if len(snapshot.LegacyPatch) > 0 {
		_, _ = o.orchestrate(ctx, jobID, "progress", snapshot.LegacyPatch)
	}
	return nil
}

type imapCheckpoint struct {
	UID         uint32 `json:"uid"`
	UIDValidity uint32 `json:"uidValidity"`
}

// encodeIMAPCheckpoint defines the canonical durable wire shape. Readers stay
// tolerant of the pre-V209 lastUID spelling, but every current binary writes
// uid so the compatibility surface converges instead of expanding.
func encodeIMAPCheckpoint(checkpoint imapCheckpoint) []byte {
	return jsonMarshal(checkpoint)
}

func decodeIMAPCheckpoint(raw []byte) (imapCheckpoint, error) {
	var wire struct {
		UID         *uint32 `json:"uid"`
		LastUID     *uint32 `json:"lastUID"`
		UIDValidity *uint32 `json:"uidValidity"`
	}
	if err := json.Unmarshal(raw, &wire); err != nil {
		return imapCheckpoint{}, fmt.Errorf("decode IMAP checkpoint: %w", err)
	}
	if wire.UIDValidity == nil || *wire.UIDValidity == 0 {
		return imapCheckpoint{}, fmt.Errorf("decode IMAP checkpoint: missing uidValidity")
	}
	if wire.UID == nil && wire.LastUID == nil {
		return imapCheckpoint{}, fmt.Errorf("decode IMAP checkpoint: missing uid")
	}
	if wire.UID != nil && wire.LastUID != nil && *wire.UID != *wire.LastUID {
		return imapCheckpoint{}, fmt.Errorf("decode IMAP checkpoint: conflicting uid and lastUID")
	}
	uid := wire.LastUID
	if wire.UID != nil {
		uid = wire.UID
	}
	return imapCheckpoint{UID: *uid, UIDValidity: *wire.UIDValidity}, nil
}

func (o *Orchestrator) loadSourceCheckpoints(ctx context.Context, jobID, sourceGeneration int64) []SourceCheckpointCandidate {
	rows, err := o.pool.Query(ctx, `
		SELECT scope_key, cursor_kind, cursor_value
		  FROM migration_checkpoints
		 WHERE job_id=$1 AND source_generation=$2
		 ORDER BY scope_key, cursor_kind`,
		jobID, sourceGeneration)
	if err != nil {
		return nil
	}
	defer rows.Close()
	checkpoints := make([]SourceCheckpointCandidate, 0)
	for rows.Next() {
		var scope, kind string
		var raw []byte
		if rows.Scan(&scope, &kind, &raw) != nil {
			continue
		}
		checkpoints = append(checkpoints, SourceCheckpointCandidate{Scope: scope, Kind: kind, Value: raw})
	}
	return checkpoints
}

func (o *Orchestrator) runICSPhase(ctx context.Context, jobID int64, job migrationJobRow) {
	icsData, err := o.loadUpload(ctx, jobID, "ics")
	if err != nil || len(icsData) == 0 {
		o.appendError(ctx, jobID, "ics: no uploaded ICS data")
		return
	}

	calendarID := o.getDefaultCalendarID(ctx, job.UserID)
	if calendarID == 0 {
		o.appendError(ctx, jobID, "ics: no calendar found for user")
		return
	}

	userEmail := o.getUserEmail(ctx, job.UserID)
	imported, skipped, errs := ImportICS(ctx, o.pool, string(icsData), calendarID, userEmail, job.ConflictStrategy)
	for _, e := range errs {
		o.appendError(ctx, jobID, e)
	}
	o.updateProgress(ctx, jobID, "ics", map[string]interface{}{"imported": imported, "skipped": skipped})
}

func (o *Orchestrator) runVCFPhase(ctx context.Context, jobID int64, job migrationJobRow) {
	vcfData, err := o.loadUpload(ctx, jobID, "vcf")
	if err != nil || len(vcfData) == 0 {
		o.appendError(ctx, jobID, "vcf: no uploaded VCF data")
		return
	}

	addressBookID := o.getDefaultAddressBookID(ctx, job.UserID)
	if addressBookID == 0 {
		o.appendError(ctx, jobID, "vcf: no address book found for user")
		return
	}

	imported, skipped, errs := ImportVCF(ctx, o.pool, string(vcfData), addressBookID, job.ConflictStrategy)
	for _, e := range errs {
		o.appendError(ctx, jobID, e)
	}
	o.updateProgress(ctx, jobID, "vcf", map[string]interface{}{"imported": imported, "skipped": skipped})
}

func (o *Orchestrator) importMailItem(ctx context.Context, jobID, mailboxID int64, item SourceItem, useSourceIdentity bool) (string, error) {
	operationID := migrationOperationID(jobID, item)
	if item.Change == SourceDelete {
		var result []byte
		err := o.pool.QueryRow(ctx, `SELECT migration_apply_mail_object(
			$1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24)`,
			jobID, operationID, item.SourceObjectID, item.SourceVersion,
			item.SourceFolderID, string(item.Change), nil, nil, nil, nil, nil, nil,
			[]string{}, []string{}, []string{}, nil, nil, nil, nil, 0, false, false, nil, nil,
		).Scan(&result)
		return migrationOutcome(result, err)
	}
	rawStr := string(item.RawMIME)

	msgID := mimeutil.ExtractHeader(rawStr, "Message-ID")
	if msgID == "" {
		msgID = fmt.Sprintf("<imported-%s@migration>", envutil.RandomID())
	}
	subject := mimeutil.ExtractHeader(rawStr, "Subject")
	fromAddr, fromName := mimeutil.ParseFrom(mimeutil.ExtractHeader(rawStr, "From"))
	toAddrs := mimeutil.ParseAddressList(mimeutil.ExtractHeader(rawStr, "To"))
	ccAddrs := mimeutil.ParseAddressList(mimeutil.ExtractHeader(rawStr, "Cc"))
	bccAddrs := mimeutil.ParseAddressList(mimeutil.ExtractHeader(rawStr, "Bcc"))
	inReplyTo := mimeutil.ExtractHeader(rawStr, "In-Reply-To")
	references := mimeutil.ExtractHeader(rawStr, "References")
	bodyText := mimeutil.ExtractBodyText(rawStr)
	bodyHTML := mimeutil.ExtractBodyHTML(rawStr)

	hash := sha256.Sum256(item.RawMIME)
	ref := hex.EncodeToString(hash[:])

	_, err := o.minio.PutObject(ctx, o.bucket, ref, bytes.NewReader(item.RawMIME), int64(len(item.RawMIME)), minio.PutObjectOptions{
		ContentType: "message/rfc822",
	})
	if err != nil {
		return "", fmt.Errorf("minio upload: %w", err)
	}

	var tagID *int64
	if len(item.Tags) > 0 {
		tagName := item.Tags[0]
		var tid int64
		err := o.pool.QueryRow(ctx,
			`SELECT id FROM tags WHERE mailbox_id = $1 AND name = $2 LIMIT 1`,
			mailboxID, tagName,
		).Scan(&tid)
		if err == nil {
			tagID = &tid
		} else if len(item.FolderPath) > 0 {
			// Tag doesn't exist - create the full folder path as user tags
			tid, err := o.ensureTagPath(ctx, mailboxID, item.FolderPath)
			if err != nil {
				o.logger.Warn("migration: failed to create tag path", "path", item.FolderPath, "error", err)
			} else {
				tagID = &tid
			}
		}
	}

	if useSourceIdentity {
		var result []byte
		err := o.pool.QueryRow(ctx, `SELECT migration_apply_mail_object(
			$1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24)`,
			jobID, operationID, item.SourceObjectID, item.SourceVersion,
			item.SourceFolderID, string(item.Change), ref, tagID, msgID, subject, fromAddr, fromName,
			toAddrs, ccAddrs, bccAddrs, inReplyTo, references, bodyText, bodyHTML,
			len(item.RawMIME), false, false, ref, nil,
		).Scan(&result)
		return migrationOutcome(result, err)
	}
	// Round 4 (Astra r13): import_message has ONE unified signature with an
	// authorization tail (p_actor_id/p_domain_scope). This is the SYSTEM
	// migration path — no human actor — so the tail is passed as explicit NULLs
	// by name: p_actor_id IS NULL selects the reducer's no-actor arm that skips
	// the statement-level authorization predicate, and named notation pins the
	// tail (it can never drift into the vestigial p_user_id/p_list_id params or
	// resolve against a stale overload).
	_, err = o.pool.Exec(ctx,
		`SELECT import_message($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,
			p_actor_id => NULL, p_domain_scope => NULL)`,
		mailboxID, tagID, msgID, subject, fromAddr, fromName, toAddrs, ccAddrs, bccAddrs,
		inReplyTo, references, bodyText, bodyHTML, len(item.RawMIME), false, false, ref, nil)
	return "imported", err
}

func migrationOutcome(raw []byte, err error) (string, error) {
	if err != nil {
		return "", err
	}
	var result struct {
		Outcome string `json:"outcome"`
	}
	if err := json.Unmarshal(raw, &result); err != nil {
		return "", err
	}
	if result.Outcome == "" {
		return "", fmt.Errorf("migration reducer omitted outcome")
	}
	return result.Outcome, nil
}

func incrementMigrationOutcome(progress map[string]interface{}, outcome string) {
	if current, ok := progress[outcome].(int); ok {
		progress[outcome] = current + 1
	}
}

func migrationOperationID(jobID int64, item SourceItem) uuid.UUID {
	key := fmt.Sprintf("%d\x00%s\x00%s\x00%s\x00%s", jobID, item.Type,
		item.SourceObjectID, item.SourceVersion, item.Change)
	return uuid.NewSHA1(uuid.NameSpaceOID, []byte(key))
}

func (o *Orchestrator) importAuxItem(ctx context.Context, jobID, mailboxID int64, item SourceItem) (string, error) {
	operationID := migrationOperationID(jobID, item)
	payload := []byte(item.RawICS)
	objectType, targetKind := "calendar", "calendar_event"
	if item.Type == ItemContact {
		payload = []byte(item.RawVCF)
		objectType, targetKind = "contact", "contact"
	}
	var contentHash any
	if item.Change != SourceDelete {
		hash := sha256.Sum256(payload)
		contentHash = hex.EncodeToString(hash[:])
	}

	tx, err := o.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return "", err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var raw []byte
	if err := tx.QueryRow(ctx, `SELECT migration_aux_object_begin($1,$2,$3,$4,$5,$6,$7,$8)`,
		jobID, operationID, objectType, item.SourceObjectID, item.SourceVersion,
		item.SourceFolderID, string(item.Change), contentHash).Scan(&raw); err != nil {
		return "", err
	}
	var decision struct {
		Action     string `json:"action"`
		TargetKind string `json:"targetKind"`
		TargetID   *int64 `json:"targetId"`
	}
	if err := json.Unmarshal(raw, &decision); err != nil {
		return "", fmt.Errorf("decode source-object decision: %w", err)
	}
	if decision.Action == "replay" || decision.Action == "unchanged" {
		return decision.Action, tx.Commit(ctx)
	}
	if decision.TargetID != nil {
		if err := destroyAuxProjection(ctx, tx, mailboxID, decision.TargetKind, *decision.TargetID); err != nil {
			return "", err
		}
	}
	if item.Change == SourceDelete {
		if err := tx.QueryRow(ctx, `SELECT migration_aux_object_complete($1,$2,'tombstoned',NULL,NULL)`,
			jobID, operationID).Scan(&raw); err != nil {
			return "", err
		}
		return "deleted", tx.Commit(ctx)
	}

	targetID, err := createAuxProjection(ctx, tx, jobID, mailboxID, item)
	if err != nil {
		return "", err
	}
	if err := tx.QueryRow(ctx, `SELECT migration_aux_object_complete($1,$2,'applied',$3,$4)`,
		jobID, operationID, targetKind, targetID).Scan(&raw); err != nil {
		return "", err
	}
	outcome := "imported"
	if decision.TargetID != nil {
		if item.Change == SourceMove {
			outcome = "moved"
		} else {
			outcome = "updated"
		}
	}
	return outcome, tx.Commit(ctx)
}

func destroyAuxProjection(ctx context.Context, tx pgx.Tx, mailboxID int64, targetKind string, targetID int64) error {
	var raw []byte
	var err error
	switch targetKind {
	case "calendar_event":
		err = tx.QueryRow(ctx, `SELECT jmap_calendar_event_set_destroy($1,$2)`,
			mailboxID, []int64{targetID}).Scan(&raw)
	case "contact":
		err = tx.QueryRow(ctx, `SELECT jmap_contact_set_destroy($1,$2)`,
			mailboxID, []int64{targetID}).Scan(&raw)
	case "":
		return nil
	default:
		return fmt.Errorf("unsupported migration target kind %q", targetKind)
	}
	return err
}

func createAuxProjection(ctx context.Context, tx pgx.Tx, jobID, mailboxID int64, item SourceItem) (int64, error) {
	var raw []byte
	switch item.Type {
	case ItemCalendar:
		events, _, parseErrs := SplitAndParseICS(item.RawICS)
		if len(parseErrs) > 0 || len(events) != 1 {
			return 0, fmt.Errorf("calendar source object must contain exactly one valid event")
		}
		eventJSON, err := EventsToJSON(events)
		if err != nil {
			return 0, err
		}
		var userID, calendarID int64
		var actorEmail string
		if err := tx.QueryRow(ctx, `SELECT j.user_id,u.email,c.id
			FROM migration_jobs j JOIN users u ON u.id=j.user_id
			JOIN calendars c ON c.mailbox_id=j.target_mailbox_id AND c.is_default
			WHERE j.id=$1 AND j.target_mailbox_id=$2 LIMIT 1`, jobID, mailboxID).
			Scan(&userID, &actorEmail, &calendarID); err != nil {
			return 0, fmt.Errorf("resolve migration calendar target: %w", err)
		}
		if err := tx.QueryRow(ctx, `SELECT calendar_import_ics($1,$2,$3,$4,$5,'skip')`,
			mailboxID, userID, actorEmail, calendarID, eventJSON).Scan(&raw); err != nil {
			return 0, err
		}
	case ItemContact:
		objectsJSON, err := VCardsToJSON(item.RawVCF)
		if err != nil {
			return 0, err
		}
		var objects []map[string]any
		if err := json.Unmarshal(objectsJSON, &objects); err != nil || len(objects) != 1 {
			return 0, fmt.Errorf("contact source object must contain exactly one valid vCard")
		}
		creates := map[string]any{"source": objects[0]}
		if err := tx.QueryRow(ctx, `SELECT jmap_contact_set_create($1,$2)`,
			mailboxID, jsonMarshal(creates)).Scan(&raw); err != nil {
			return 0, err
		}
	default:
		return 0, fmt.Errorf("unsupported auxiliary object type %q", item.Type)
	}
	return createdProjectionID(raw)
}

func createdProjectionID(raw []byte) (int64, error) {
	var result struct {
		Created map[string]struct {
			ID string `json:"id"`
		} `json:"created"`
	}
	if err := json.Unmarshal(raw, &result); err != nil {
		return 0, err
	}
	for _, created := range result.Created {
		id, err := strconv.ParseInt(created.ID, 10, 64)
		if err == nil && id > 0 {
			return id, nil
		}
	}
	return 0, fmt.Errorf("projection reducer did not create an object")
}

func (o *Orchestrator) bindSourceIdentity(ctx context.Context, jobID int64, identity SourceIdentity) (int64, error) {
	var instanceID uuid.UUID
	if err := o.pool.QueryRow(ctx, `SELECT migration_source_bind($1,$2,$3,$4)`,
		jobID, identity.SourceType, identity.MailboxKey, identity.SelectorDigest,
	).Scan(&instanceID); err != nil {
		return 0, fmt.Errorf("bind source mailbox: %w", err)
	}
	var generation int64
	if err := o.pool.QueryRow(ctx,
		`SELECT generation FROM migration_source_instances WHERE id=$1`, instanceID,
	).Scan(&generation); err != nil {
		return 0, fmt.Errorf("read source generation: %w", err)
	}
	return generation, nil
}

func (o *Orchestrator) featureEnabled(ctx context.Context, key string) bool {
	var enabled bool
	if err := o.pool.QueryRow(ctx, `SELECT enabled FROM feature_toggles WHERE key=$1`, key).Scan(&enabled); err != nil {
		return false
	}
	return enabled
}

// --- DB helpers ---

type migrationJobRow struct {
	ID               int64
	UserID           int64
	SourceType       string
	SourceConfigEnc  []byte
	Status           string
	ConflictStrategy string
}

func (o *Orchestrator) loadJob(ctx context.Context, jobID int64) (migrationJobRow, error) {
	var row migrationJobRow
	err := o.pool.QueryRow(ctx,
		`SELECT id, user_id, source_type, source_config_enc, status, conflict_strategy
		 FROM migration_jobs WHERE id = $1`, jobID,
	).Scan(&row.ID, &row.UserID, &row.SourceType, &row.SourceConfigEnc, &row.Status, &row.ConflictStrategy)
	return row, err
}

func (o *Orchestrator) loadLegacySourceResume(ctx context.Context, jobID int64) SourceResumeState {
	var raw string
	o.pool.QueryRow(ctx,
		`SELECT COALESCE(resume_cursor, '{}') FROM migration_jobs WHERE id = $1`, jobID,
	).Scan(&raw)

	// Try new structured format first: {"uids": {...}, "delta": {...}}
	var structured struct {
		UIDs  map[string]int    `json:"uids"`
		Delta map[string]string `json:"delta"`
	}
	if err := json.Unmarshal([]byte(raw), &structured); err == nil && (len(structured.UIDs) > 0 || len(structured.Delta) > 0) {
		return SourceResumeState{LegacyUIDs: structured.UIDs, LegacyDelta: structured.Delta}
	}

	// Fall back to legacy flat format: {"folder": 123, ...}
	cursor := make(map[string]int)
	json.Unmarshal([]byte(raw), &cursor)
	return SourceResumeState{LegacyUIDs: cursor}
}

func (o *Orchestrator) getMailboxID(ctx context.Context, jobID int64) int64 {
	var id int64
	_ = o.pool.QueryRow(ctx,
		`SELECT target_mailbox_id FROM migration_jobs WHERE id = $1`, jobID,
	).Scan(&id)
	return id
}

func (o *Orchestrator) getDefaultCalendarID(ctx context.Context, userID int64) int64 {
	var id int64
	_ = o.pool.QueryRow(ctx,
		`SELECT c.id FROM calendars c
		 JOIN mailboxes m ON c.mailbox_id = m.id
		 WHERE m.user_id = $1 AND c.is_default = TRUE LIMIT 1`, userID,
	).Scan(&id)
	return id
}

func (o *Orchestrator) getDefaultAddressBookID(ctx context.Context, userID int64) int64 {
	var id int64
	_ = o.pool.QueryRow(ctx,
		`SELECT a.id FROM addressbooks a
		 JOIN mailboxes m ON a.mailbox_id = m.id
		 WHERE m.user_id = $1 AND a.is_default = TRUE LIMIT 1`, userID,
	).Scan(&id)
	return id
}

func (o *Orchestrator) getUserEmail(ctx context.Context, userID int64) string {
	var email string
	_ = o.pool.QueryRow(ctx,
		`SELECT email FROM users WHERE id = $1`, userID,
	).Scan(&email)
	return email
}

func (o *Orchestrator) appendError(ctx context.Context, jobID int64, msg string) {
	// The reducer appends to error_log and caps it at 1000 entries in-SQL.
	_, _ = o.orchestrate(ctx, jobID, "progress", map[string]any{"errors": []string{msg}})
}

func (o *Orchestrator) updateProgress(ctx context.Context, jobID int64, phase string, data map[string]interface{}) {
	// The reducer deep-merges progress->phase into the progress jsonb (no status change).
	_, _ = o.orchestrate(ctx, jobID, "progress", map[string]any{"progress": map[string]any{phase: data}})
}

// --- helpers ---

func ContainsSourceType(sourceType, target string) bool {
	types := splitPipeDelimited(sourceType)
	for _, t := range types {
		if t == target {
			return true
		}
	}
	return false
}

func splitPipeDelimited(s string) []string {
	if s == "" {
		return nil
	}
	var parts []string
	for _, p := range bytes.Split([]byte(s), []byte("|")) {
		if len(p) > 0 {
			parts = append(parts, string(p))
		}
	}
	return parts
}

func jsonMarshal(v interface{}) []byte {
	b, _ := json.Marshal(v)
	return b
}

// hashColor generates a deterministic hex color from a tag name string.
func hashColor(name string) string {
	h := sha256.Sum256([]byte(name))
	return "#" + hex.EncodeToString(h[0:3])
}

// ensureTagPath makes sure a tag exists for each segment in the folder path,
// creating user tags with parent_id chains as needed. Returns the leaf tag ID.
//
// Example: ["工作", "项目"] creates tag "工作" (parent=null) then "项目" (parent="工作").
// Returns the ID of the leaf tag "项目".
func (o *Orchestrator) ensureTagPath(ctx context.Context, mailboxID int64, path []string) (int64, error) {
	if len(path) == 0 {
		return 0, fmt.Errorf("empty tag path")
	}

	var parentID *int64
	var leafID int64

	for _, segment := range path {
		if segment == "" {
			continue
		}

		var existingID int64
		err := o.pool.QueryRow(ctx,
			`SELECT id FROM tags WHERE mailbox_id = $1 AND name = $2 LIMIT 1`,
			mailboxID, segment,
		).Scan(&existingID)
		if err == nil {
			parentID = &existingID
			leafID = existingID
			continue
		}

		err = o.pool.QueryRow(ctx, `
			INSERT INTO tags (mailbox_id, name, tag_type, parent_id, color, sort_order)
			VALUES ($1, $2, 'user', $3, $4, $5)
			ON CONFLICT (mailbox_id, name) DO UPDATE
			    SET parent_id = COALESCE(tags.parent_id, EXCLUDED.parent_id)
			RETURNING id`,
			mailboxID, segment, parentID,
			hashColor(segment),
			len(path)*10,
		).Scan(&leafID)
		if err != nil {
			return 0, fmt.Errorf("ensure tag %q: %w", segment, err)
		}
		parentID = &leafID
	}

	return leafID, nil
}
