package directorysync

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"
	"unicode"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"setjoin.com/mailserver/internal/identitysource"
	"setjoin.com/mailserver/internal/ldaputil"
	"setjoin.com/shared/identity"
)

// Durable engine-side quarantine reason codes. They are recorded in the
// identity_source_quarantines ledger through the
// identity_source_quarantine_record reducer and must match its
// ^[A-Z0-9_.:-]{1,64}$ reason-code constraint.
const (
	QuarantineMissingSubject  = "MISSING_IMMUTABLE_SUBJECT"
	QuarantineNoUsableMail    = "NO_USABLE_MAIL_ATTRIBUTE"
	QuarantineInvalidSubject  = "INVALID_IMMUTABLE_SUBJECT"
	quarantineMaxRecords      = 500
	quarantineMaxObjectKey    = 512
	quarantineDigestKeyPrefix = "digest:"
)

// QuarantineRecord is one durable skip-and-quarantine fact for an object the
// engine did NOT stage. ObjectKey is a stable, bounded, control-free key for
// the offending object; SubjectDigest is the hex SHA-256 of the immutable
// subject (of the empty string when the object has none) so ledger evidence
// correlates with the redacted digests already used across the identity
// substrate without widening subject plaintext exposure.
type QuarantineRecord struct {
	ObjectKey     string
	SubjectDigest string
	ReasonCode    string
}

// QuarantineStore persists quarantine accounting durably, scoped to one
// identity source, BEFORE the engine acknowledges a page cursor. Production
// uses PgxQuarantineStore against the same worker pool as the PageStore.
type QuarantineStore interface {
	RecordQuarantines(
		ctx context.Context,
		source identitysource.Source,
		instance uuid.UUID,
		records []QuarantineRecord,
	) error
}

// PgxQuarantineStore records quarantine accounting through the
// identity_source_quarantine_record reducer, so the ledger's authorization,
// generation/lease fencing, and accumulation semantics stay reducer-owned
// business authority. It carries no business decisions of its own.
type PgxQuarantineStore struct {
	Pool *pgxpool.Pool
}

// RecordQuarantines calls the durable quarantine ledger reducer once for the
// whole page. Any reducer failure is returned so the engine can refuse to
// acknowledge the page cursor.
func (s PgxQuarantineStore) RecordQuarantines(
	ctx context.Context,
	source identitysource.Source,
	instance uuid.UUID,
	records []QuarantineRecord,
) error {
	if s.Pool == nil {
		return errors.New("quarantine store has no database pool")
	}
	if len(records) == 0 {
		return nil
	}
	payload := make([]map[string]string, 0, len(records))
	for _, record := range records {
		payload = append(payload, map[string]string{
			"objectKey":     record.ObjectKey,
			"subjectDigest": record.SubjectDigest,
			"reasonCode":    record.ReasonCode,
		})
	}
	blob, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal quarantine records: %w", err)
	}
	var recorded int
	if err := s.Pool.QueryRow(ctx,
		`SELECT identity_source_quarantine_record($1,$2,$3,$4::jsonb)`,
		source.ID, source.Generation, instance, blob,
	).Scan(&recorded); err != nil {
		return err
	}
	if recorded != len(records) {
		return fmt.Errorf("quarantine ledger recorded %d of %d records", recorded, len(records))
	}
	return nil
}

// Engine runs the database-normalized directory synchronization pipeline.
type Engine struct {
	Store     PageStore
	Connector Connector
	SourceKey string
	Instance  uuid.UUID
	Logger    *slog.Logger
	// Quarantines durably records skip-and-quarantine accounting before any
	// cursor acknowledgment. When nil, the engine falls back to its
	// historical loud log-only behavior; production sync workers must wire
	// PgxQuarantineStore so quarantine evidence survives cursor advancement
	// and process restarts.
	Quarantines QuarantineStore
}

// Sync fetches one connector batch and applies it through the identity-source
// inbox. It deliberately owns no transport or cursor-specific logic.
//
// AUTHORITATIVE RECONCILIATION CONTRACT: revocation/deletion is derived only
// from an authoritative source — an explicit upstream tombstone the connector
// attests (Object.Tombstone). Absence of an object from a fetched page is
// never deletion evidence: an incremental (cursor-filtered) page, a filtered
// scope, or a failed/partial scan must never deprovision, and a failed scan
// leaves both the staged data and the committed cursor untouched so the next
// cycle retries. The engine implements no absence janitor of its own: the
// alternative deletion authority, a completed full-reconciliation pass, would
// need the store-owned local anchor set to diff against, which the PageStore
// surface does not expose. Until that seam exists, absence-derived deletion
// stays fail-closed OFF.
//
// Durable quarantine-before-cursor contract: malformed objects and mail-less
// in-scope upserts (the deterministic BZ228 block class) are skipped and
// quarantined with loud accounting instead of being staged into a block that
// would wedge the source cursor every cycle. Both skip classes are persisted
// to the identity_source_quarantines ledger through the
// identity_source_quarantine_record reducer BEFORE the page cursor is
// acknowledged: a failed accounting call fails the whole cycle and leaves the
// committed cursor untouched, and a crash between accounting and apply is
// recovered by idempotent re-accounting on the next traversal. Once the
// accounting is durable, later incremental pages need not repeat the
// quarantined object — the ledger row survives cursor advancement and
// process restarts until an operator resolves the source condition. Only
// provably non-revocable objects are skipped this way, and every other entry
// in the page — in particular every tombstone/disable — still stages before
// the page cursor commits, so advancing past a quarantined object never
// skips owed revocation work for already-traversed objects.
func (e Engine) Sync(ctx context.Context) (ldaputil.SyncResult, error) {
	started := time.Now()
	var result ldaputil.SyncResult
	if e.Store == nil || e.Connector == nil {
		return result, errors.New("directory sync engine is not configured")
	}
	if err := e.Connector.Preflight(); err != nil {
		return result, err
	}
	label := e.Connector.Label()
	source, err := e.Store.SourceByKey(ctx, e.SourceKey)
	if err != nil {
		return result, fmt.Errorf("load %s identity source: %w", label, err)
	}
	acquired, err := e.Store.AcquireLease(ctx, source, e.Instance)
	if err != nil {
		return result, fmt.Errorf("acquire %s identity source lease: %w", label, err)
	}
	if !acquired {
		result.Skipped = 1
		return result, nil
	}
	defer e.releaseLease(ctx, source, label)

	recovery, err := e.Store.ResumeUnfinished(ctx, source, e.Instance)
	if err != nil {
		result.Errors = 1
		return result, fmt.Errorf("resume %s identity source batch: %w", label, err)
	}
	if recovery.Found {
		result.Checked = recovery.EntryCount
		result.Updated = recovery.Finish.Applied
		result.Skipped = recovery.Finish.Quarantined
		result.Duration = time.Since(started).String()
		return result, nil
	}

	before, err := e.Connector.DecodeCursor(source.Cursor)
	if err != nil {
		return result, fmt.Errorf("decode %s committed cursor: %w", label, err)
	}
	objects, after, err := e.Connector.Fetch(ctx, before)
	if err != nil {
		return result, err
	}
	result.Checked = len(objects)

	entries, quarantined, err := e.entries(objects, label, &result)
	if err != nil {
		return result, err
	}
	// Quarantine accounting is durable BEFORE the cursor moves: a failure
	// here fails the cycle with the committed cursor untouched, so the next
	// cycle re-traverses the same page and re-accounts idempotently.
	if err := e.recordQuarantines(ctx, source, label, quarantined); err != nil {
		result.Errors = 1
		return result, err
	}
	beforeJSON, err := before.Encode()
	if err != nil {
		return result, err
	}
	afterJSON, err := after.Encode()
	if err != nil {
		return result, err
	}
	finishes, err := e.applyPages(ctx, source, entries, beforeJSON, afterJSON)
	if err != nil {
		result.Errors = 1
		return result, err
	}
	// Map the store's per-page FinishResults onto SyncResult so the fresh path
	// reports what ACTUALLY happened, aligned with the recovery path above
	// (D-MAILSERVER-INTERNAL-DIRECTORYSYNC-004): Updated = applies (not the
	// staged count), Skipped = engine skips + reducer-side quarantines, and
	// Disabled counts staged disable entries of fully-applied pages (partial
	// pages cannot attribute individual applies, so they contribute no
	// Disabled claim — a lower bound, never an overcount).
	for _, finish := range finishes {
		result.Updated += finish.Applied
		result.Skipped += finish.Quarantined
		if finish.Quarantined == 0 && finish.Applied == finish.entries {
			result.Disabled += finish.disables
		}
	}
	result.Duration = time.Since(started).String()
	return result, nil
}

func (e Engine) releaseLease(ctx context.Context, source identitysource.Source, label string) {
	releaseCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	if err := e.Store.ReleaseLease(releaseCtx, source, e.Instance); err != nil && e.Logger != nil {
		e.Logger.Warn(label+" sync: release identity source lease", "error", err)
	}
}

// entries converts fetched objects into inbox entries under the
// authoritative reconciliation contract:
//
//   - Tombstoned objects propagate as disable-first revocation (operation
//     "disable"): the reducer-owned disable path revokes live sessions,
//     OAuth tokens, and websocket subscriptions without destroying mailbox
//     or profile data, which is the strongest propagation the upsert/disable
//     inbox vocabulary offers. A tombstone is never expressed as data
//     destruction, and it propagates even when upstream deletion scrubbed
//     the mail attribute.
//
//   - Malformed objects (missing immutable subject) and mail-less in-scope
//     upserts are skipped and quarantined with loud accounting instead of
//     being staged. Staging either class deterministically blocks the batch
//     (empty subject has no identity anchor; a mail-less upsert is the
//     reducer's BZ228 block class) and wedges the source cursor every
//     cycle. Neither class carries revocation potential of its own, so the
//     page cursor may advance past them — but only after the skip is
//     persisted to the durable quarantine ledger (see recordQuarantines);
//     a mail-less DISABLED object and a tombstone still propagate, because
//     dropping their disable would regress revocation completeness (an
//     unknown disable subject remains the reducer's deliberate
//     operator-review block, not an engine skip).
//
//     Nothing absent from the page is acted on: the engine never
//     synthesizes entries for subjects the connector did not return, so an
//     incremental page can never drop an enabled anchor.
//
// Connector-owned validation (including duplicate-subject policy) stays
// page-fatal by contract and runs before any quarantine skip. One page
// yields at most one ledger record per distinct (object key, reason) pair.
func (e Engine) entries(objects []Object, label string, result *ldaputil.SyncResult) ([]identitysource.Entry, []QuarantineRecord, error) {
	relationSubjects := make(map[string]string, len(objects))
	for _, object := range objects {
		if object.RelationKey != "" && object.Subject != "" {
			relationSubjects[object.RelationKey] = object.Subject
		}
	}
	seen := make(map[string]struct{}, len(objects))
	quarantined := make(map[string]struct{}, len(objects))
	records := make([]QuarantineRecord, 0, len(objects))
	entries := make([]identitysource.Entry, 0, len(objects))
	for _, object := range objects {
		if object.Subject == "" {
			result.Skipped++
			e.quarantineRecord(label, QuarantineMissingSubject,
				"object missing configured immutable subject", object, quarantined, &records)
			continue
		}
		// Per-object subject-bounds disposition (D-MAILSERVER-INTERNAL-
		// DIRECTORYSYNC-003): the inbox pipeline's per-entry validation
		// (identitysource.Entry.Validate / boundedText) rejects an oversized,
		// untrimmed or control-character subject — the old flow let ONE such
		// object fail whole-page validation pre-staging every cycle, wedging
		// the source with no durable failure evidence. The object is now
		// skipped and quarantined like the other deterministic block classes:
		// the evidence lands in the ledger before the cursor advances, and the
		// rest of the page still stages.
		if !subjectWithinBounds(object.Subject) {
			result.Skipped++
			e.quarantineRecord(label, QuarantineInvalidSubject,
				"object subject violates the inbox entry bounds (trimmed, control-free, <=512 bytes)",
				object, quarantined, &records)
			continue
		}
		_, duplicate := seen[object.Subject]
		if err := e.Connector.ValidateObject(object, duplicate); err != nil {
			return nil, nil, err
		}
		seen[object.Subject] = struct{}{}
		email := identity.CanonicalizeAddress(object.Email).String()
		// Exact mirror of the inbox's deterministic BZ228 upsert gate for
		// engine-sourced entries (empty address, or no @ in the stored
		// canonical form): such an entry could never apply, only block the
		// batch and wedge the cursor.
		if (email == "" || !strings.Contains(email, "@")) && !object.Tombstone && !object.Disabled {
			result.Skipped++
			e.quarantineRecord(label, QuarantineNoUsableMail,
				"in-scope object has no usable mail attribute for upsert", object, quarantined, &records)
			continue
		}
		managerSubject := object.ManagerSubject
		if managerSubject == "" {
			managerSubject = relationSubjects[object.ManagerRelationKey]
		}
		operation := "upsert"
		if object.Disabled || object.Tombstone {
			operation = "disable"
		}
		payload, err := json.Marshal(map[string]any{
			"operation":      operation,
			"email":          email,
			"displayName":    object.DisplayName,
			"firstName":      object.FirstName,
			"lastName":       object.LastName,
			"jobTitle":       object.JobTitle,
			"phone":          object.Phone,
			"department":     object.Department,
			"upn":            object.UPN,
			"enabled":        !(object.Disabled || object.Tombstone),
			"cursorValue":    object.CursorValue,
			"managerSubject": managerSubject,
		})
		if err != nil {
			return nil, nil, err
		}
		entries = append(entries, identitysource.Entry{
			ObjectKey: object.Subject, ImmutableSubject: object.Subject, Payload: payload,
		})
	}
	return entries, records, nil
}

// quarantineRecord logs the skip loudly and collects one durable ledger
// record per distinct (object key, reason) pair for the page. The record is
// persisted by recordQuarantines before the page cursor is acknowledged;
// duplicates within one page collapse so a repeated skip still accounts
// exactly one occurrence per traversal.
func (e Engine) quarantineRecord(
	label, reasonCode, reason string,
	object Object,
	seen map[string]struct{},
	records *[]QuarantineRecord,
) {
	e.quarantineLog(label, reason, object)
	key := quarantineObjectKey(object)
	dedup := reasonCode + "\x00" + key
	if _, duplicate := seen[dedup]; duplicate {
		return
	}
	seen[dedup] = struct{}{}
	*records = append(*records, QuarantineRecord{
		ObjectKey:     key,
		SubjectDigest: sha256Hex([]byte(object.Subject)),
		ReasonCode:    reasonCode,
	})
}

// quarantineObjectKey derives a stable, bounded, control-free ledger key for
// a skipped object: the immutable subject when present, else the relation
// key, else (or when unsafe for the ledger's CHECK constraints) a SHA-256
// digest form that always satisfies the object-key bounds.
func quarantineObjectKey(object Object) string {
	key := object.Subject
	if key == "" {
		key = object.RelationKey
	}
	if key == "" || len(key) > quarantineMaxObjectKey || hasControlChar(key) {
		return quarantineDigestKeyPrefix + sha256Hex([]byte(key))
	}
	return key
}

func hasControlChar(value string) bool {
	for _, r := range value {
		if unicode.IsControl(r) {
			return true
		}
	}
	return false
}

// subjectWithinBounds mirrors the inbox pipeline's per-entry ObjectKey bound
// (identitysource.MaxObjectKey + boundedText semantics: trimmed, non-empty,
// control-free) for the engine-side immutable subject. Subjects are used as
// BOTH the entry's ObjectKey (≤512) and ImmutableSubject (≤2048), so the
// stricter ObjectKey bound governs (D-MAILSERVER-INTERNAL-DIRECTORYSYNC-003).
func subjectWithinBounds(subject string) bool {
	if subject == "" || strings.TrimSpace(subject) != subject || len(subject) > identitysource.MaxObjectKey {
		return false
	}
	return !hasControlChar(subject)
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// recordQuarantines persists skip-and-quarantine accounting through the
// durable quarantine ledger BEFORE the page cursor is acknowledged. A
// failure here fails the whole cycle: the committed cursor stays put and the
// next cycle re-traverses the same page and re-accounts idempotently, so
// advancing past a quarantined object can never silently drop the only
// durable evidence of the skip. Without a configured Quarantines store the
// engine retains the historical loud log-only behavior.
func (e Engine) recordQuarantines(
	ctx context.Context,
	source identitysource.Source,
	label string,
	records []QuarantineRecord,
) error {
	if e.Quarantines == nil || len(records) == 0 {
		return nil
	}
	if len(records) > quarantineMaxRecords {
		return fmt.Errorf("%s sync produced %d quarantine records; maximum is %d",
			label, len(records), quarantineMaxRecords)
	}
	if err := e.Quarantines.RecordQuarantines(ctx, source, e.Instance, records); err != nil {
		return fmt.Errorf("record %s quarantine accounting: %w", label, err)
	}
	return nil
}

// quarantineLog records a skip-and-quarantine decision at Error level. The
// log is the loud, per-traversal signal; the durable per-object evidence is
// the identity_source_quarantines ledger row written through
// recordQuarantines (plus the reducer-side identity_link_events entry), which
// the engine never rewrites or clears.
func (e Engine) quarantineLog(label, reason string, object Object) {
	if e.Logger == nil {
		return
	}
	e.Logger.Error(label+" sync: directory object skipped and quarantined; re-accounted on every traversal until the source is corrected",
		"reason", reason,
		"subject", object.Subject,
		"relationKey", object.RelationKey,
		"email", object.Email)
}

// pageFinish carries one chunk's staged disable count alongside the store's
// FinishResult so Sync can map real outcomes onto SyncResult.
type pageFinish struct {
	identitysource.FinishResult
	entries  int // staged entries in the chunk
	disables int // staged entries with operation == "disable"
}

func (e Engine) applyPages(
	ctx context.Context,
	source identitysource.Source,
	entries []identitysource.Entry,
	before, after json.RawMessage,
) ([]pageFinish, error) {
	chunks := (len(entries) + identitysource.MaxEntries - 1) / identitysource.MaxEntries
	if chunks == 0 {
		chunks = 1
	}
	passes := 1
	if chunks > 1 {
		passes = 2
	}
	finishes := make([]pageFinish, 0, chunks)
	for pass := 0; pass < passes; pass++ {
		for chunk := 0; chunk < chunks; chunk++ {
			start := chunk * identitysource.MaxEntries
			end := min(start+identitysource.MaxEntries, len(entries))
			cursor := before
			if pass == passes-1 && chunk == chunks-1 {
				cursor = after
			}
			pageEntries := entries[start:end]
			finish, err := e.Store.ApplyPage(ctx, source, identitysource.Page{
				BatchID: uuid.New(),
				Cursor:  cursor,
				Entries: pageEntries,
			}, e.Instance)
			if err != nil {
				return nil, err
			}
			// Only the FINAL pass's outcomes are terminal: earlier passes stage
			// the same entries with the pre-page cursor and are re-applied by
			// the last pass, so counting them would double-report.
			if pass == passes-1 {
				finishes = append(finishes, pageFinish{
					FinishResult: finish,
					entries:      len(pageEntries),
					disables:     countDisableEntries(pageEntries),
				})
			}
		}
	}
	return finishes, nil
}

// countDisableEntries counts staged entries whose payload operation is
// "disable" — the disable-first revocation vocabulary entries() emits for
// Disabled/Tombstoned objects.
func countDisableEntries(entries []identitysource.Entry) int {
	disables := 0
	for _, entry := range entries {
		var payload struct {
			Operation string `json:"operation"`
		}
		if err := json.Unmarshal(entry.Payload, &payload); err == nil && payload.Operation == "disable" {
			disables++
		}
	}
	return disables
}
