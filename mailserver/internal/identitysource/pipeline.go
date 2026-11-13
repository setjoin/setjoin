// Package identitysource is the typed connector transport shared by AD, LDAP,
// and SCIM. It stages bounded, sanitized entries in PostgreSQL; reducers remain
// the authority for identity matching, lifecycle, and cursor advancement.
package identitysource

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	MaxEntries      = 500
	MaxObjectKey    = 512
	MaxSubject      = 2048
	MaxPayloadBytes = 64 << 10
	// MaxCursorBytes bounds the directory-derived sync cursor. The cursor is
	// the one page field persisted up to ~502 times per page (batch row, one
	// inbox row per entry, pending/committed source columns), so an unbounded
	// rogue 'ldap' directory could amplify WAL and disk per cycle. Both
	// connector decoders treat a pruned cursor as a full resync. The bound is
	// mirrored by identity_source_batch_begin and by V236 CHECK constraints.
	MaxCursorBytes   = 4096
	defaultLeaseSecs = 45
)

var allowedPayloadKeys = map[string]struct{}{
	"operation": {}, "email": {}, "displayName": {}, "firstName": {},
	"lastName": {}, "jobTitle": {}, "phone": {}, "department": {},
	"upn": {}, "enabled": {}, "cursorValue": {}, "managerSubject": {},
}

// Entry contains only connector-neutral, bounded values. ImmutableSubject must
// be a protocol-defined immutable anchor; email and profile values are payload
// evidence and never identity keys.
type Entry struct {
	ObjectKey        string          `json:"objectKey"`
	ImmutableSubject string          `json:"immutableSubject"`
	Payload          json.RawMessage `json:"payload"`
}

func (e Entry) Validate() error {
	if err := boundedText("objectKey", e.ObjectKey, MaxObjectKey); err != nil {
		return err
	}
	if err := boundedText("immutableSubject", e.ImmutableSubject, MaxSubject); err != nil {
		return err
	}
	if len(e.Payload) == 0 || len(e.Payload) > MaxPayloadBytes || !json.Valid(e.Payload) {
		return fmt.Errorf("payload must be valid JSON and at most %d bytes", MaxPayloadBytes)
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(e.Payload, &object); err != nil || object == nil {
		return errors.New("payload must be a JSON object")
	}
	for key := range object {
		if _, ok := allowedPayloadKeys[key]; !ok {
			return fmt.Errorf("payload contains unsupported field %q", key)
		}
	}
	return nil
}

func boundedText(name, value string, limit int) error {
	if strings.TrimSpace(value) != value || value == "" || len(value) > limit {
		return fmt.Errorf("%s must be trimmed and contain 1..%d bytes", name, limit)
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			return fmt.Errorf("%s contains a control character", name)
		}
	}
	return nil
}

// Page is one remote page and its post-page cursor. An empty page is legal.
type Page struct {
	BatchID uuid.UUID
	Cursor  json.RawMessage
	Entries []Entry
}

func (p *Page) Validate() error {
	if p.BatchID == uuid.Nil {
		p.BatchID = uuid.New()
	}
	if len(p.Entries) > MaxEntries {
		return fmt.Errorf("page has %d entries; maximum is %d", len(p.Entries), MaxEntries)
	}
	if len(p.Cursor) == 0 || len(p.Cursor) > MaxCursorBytes {
		return fmt.Errorf("cursor must contain 1..%d bytes", MaxCursorBytes)
	}
	if !json.Valid(p.Cursor) {
		return errors.New("cursor must be valid JSON")
	}
	var cursor any
	if err := json.Unmarshal(p.Cursor, &cursor); err != nil || cursor == nil {
		return errors.New("cursor must be non-null JSON")
	}
	for i := range p.Entries {
		if err := p.Entries[i].Validate(); err != nil {
			return fmt.Errorf("entry %d: %w", i, err)
		}
	}
	return nil
}

type Store struct {
	pool *pgxpool.Pool
}

func NewStore(pool *pgxpool.Pool) *Store { return &Store{pool: pool} }

type Source struct {
	ID         int64
	Generation int64
	Key        string
	Kind       string
	State      string
	Cursor     json.RawMessage
}

func (s *Store) SourceByKey(ctx context.Context, key string) (Source, error) {
	var out Source
	var cursor []byte
	err := s.pool.QueryRow(ctx, `
		SELECT id,generation,source_key,kind,state,committed_cursor
		  FROM identity_sources WHERE source_key=$1`, key,
	).Scan(&out.ID, &out.Generation, &out.Key, &out.Kind, &out.State, &cursor)
	if len(cursor) != 0 {
		out.Cursor = bytes.Clone(cursor)
	}
	return out, err
}

func (s *Store) AcquireLease(ctx context.Context, source Source, instance uuid.UUID) (bool, error) {
	var acquired bool
	err := s.pool.QueryRow(ctx,
		`SELECT identity_source_lease_acquire($1,$2,$3,$4)`,
		source.ID, source.Generation, instance, defaultLeaseSecs,
	).Scan(&acquired)
	return acquired, err
}

func (s *Store) ReleaseLease(ctx context.Context, source Source, instance uuid.UUID) error {
	_, err := s.pool.Exec(ctx,
		`SELECT identity_source_lease_release($1,$2,$3)`,
		source.ID, source.Generation, instance,
	)
	return err
}

func (s *Store) Begin(ctx context.Context, source Source, page Page, instance uuid.UUID) error {
	if err := page.Validate(); err != nil {
		return err
	}
	entries, err := json.Marshal(page.Entries)
	if err != nil {
		return fmt.Errorf("marshal identity source page: %w", err)
	}
	_, err = s.pool.Exec(ctx,
		`SELECT identity_source_batch_begin($1,$2,$3,$4::jsonb,$5::jsonb,$6)`,
		source.ID, source.Generation, page.BatchID, []byte(page.Cursor), entries, instance,
	)
	return err
}

type ApplyResult struct {
	State    string `json:"state"`
	Code     string `json:"code,omitempty"`
	UserID   string `json:"userId,omitempty"`
	LinkID   string `json:"linkId,omitempty"`
	Replayed bool   `json:"replayed,omitempty"`
}

func (s *Store) Apply(ctx context.Context, source Source, batchID uuid.UUID, objectKey string) (ApplyResult, error) {
	var raw []byte
	err := s.pool.QueryRow(ctx,
		`SELECT identity_source_entry_apply($1,$2,$3,$4)`,
		source.ID, source.Generation, batchID, objectKey,
	).Scan(&raw)
	if err != nil {
		code := "INTERNAL"
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) {
			code = pgErr.Code
		}
		_, recordErr := s.pool.Exec(ctx,
			`SELECT identity_source_entry_fail($1,$2,$3,$4,$5)`,
			source.ID, source.Generation, batchID, objectKey, code,
		)
		if recordErr != nil {
			return ApplyResult{}, errors.Join(err, fmt.Errorf("record connector failure: %w", recordErr))
		}
		return ApplyResult{}, err
	}
	var out ApplyResult
	if err := json.Unmarshal(raw, &out); err != nil {
		return ApplyResult{}, fmt.Errorf("decode identity source apply result: %w", err)
	}
	return out, nil
}

type FinishResult struct {
	State          string          `json:"state"`
	CursorAdvanced bool            `json:"cursorAdvanced"`
	Pending        int             `json:"pending,omitempty"`
	Cursor         json.RawMessage `json:"cursor,omitempty"`
	Applied        int             `json:"applied,omitempty"`
	Quarantined    int             `json:"quarantined,omitempty"`
}

func (s *Store) Finish(ctx context.Context, source Source, page Page, duration time.Duration, instance uuid.UUID) (FinishResult, error) {
	var raw []byte
	seconds := int(duration.Round(time.Second) / time.Second)
	if seconds < 0 {
		seconds = 0
	}
	err := s.pool.QueryRow(ctx,
		`SELECT identity_source_batch_finish($1,$2,$3,$4,$5)`,
		source.ID, source.Generation, page.BatchID, seconds, instance,
	).Scan(&raw)
	if err != nil {
		return FinishResult{}, err
	}
	var out FinishResult
	if err := json.Unmarshal(raw, &out); err != nil {
		return FinishResult{}, fmt.Errorf("decode identity source finish result: %w", err)
	}
	return out, nil
}

// RecoveryResult describes a durable batch found and drained before any new
// remote discovery. Found=false means the source has no unfinished batch.
type RecoveryResult struct {
	Found      bool
	BatchID    uuid.UUID
	EntryCount int
	Finish     FinishResult
}

// ResumeUnfinished drains the source's one durable open batch. Callers invoke
// this immediately after acquiring the source lease and before contacting the
// directory. That ordering makes process restarts replay the accepted batch ID
// instead of discovering the same page under a fresh UUID and hitting BZ240.
func (s *Store) ResumeUnfinished(
	ctx context.Context,
	source Source,
	instance uuid.UUID,
) (RecoveryResult, error) {
	var raw []byte
	err := s.pool.QueryRow(ctx,
		`SELECT identity_source_batch_resume($1,$2,$3)`,
		source.ID, source.Generation, instance,
	).Scan(&raw)
	if err != nil {
		return RecoveryResult{}, fmt.Errorf("load unfinished identity source batch: %w", err)
	}
	var batch struct {
		Found      bool      `json:"found"`
		BatchID    uuid.UUID `json:"batchId"`
		Generation string    `json:"generation"`
		EntryCount int       `json:"entryCount"`
		ObjectKeys []string  `json:"objectKeys"`
	}
	if err := json.Unmarshal(raw, &batch); err != nil {
		return RecoveryResult{}, fmt.Errorf("decode unfinished identity source batch: %w", err)
	}
	if !batch.Found {
		return RecoveryResult{}, nil
	}
	if batch.BatchID == uuid.Nil || batch.Generation == "" {
		return RecoveryResult{}, errors.New("unfinished identity source batch response is incomplete")
	}

	finish, drainErr := s.drainBatch(
		ctx, source, batch.BatchID, batch.ObjectKeys, batch.EntryCount, time.Now(), instance,
	)
	return RecoveryResult{
		Found: true, BatchID: batch.BatchID, EntryCount: batch.EntryCount, Finish: finish,
	}, drainErr
}

// ApplyPage stages first, applies every object independently, and attempts the
// terminal cursor commit. A blocked result is not hidden as success.
func (s *Store) ApplyPage(ctx context.Context, source Source, page Page, instance uuid.UUID) (FinishResult, error) {
	start := time.Now()
	// Validate in this frame so an omitted batch ID is generated once and the
	// exact same ID is used by staging, entry application, and cursor commit.
	// Begin also validates defensively for direct callers.
	if err := page.Validate(); err != nil {
		return FinishResult{}, err
	}
	acquired, err := s.AcquireLease(ctx, source, instance)
	if err != nil {
		return FinishResult{}, fmt.Errorf("renew identity source lease: %w", err)
	}
	if !acquired {
		return FinishResult{}, errors.New("identity source lease was lost before staging")
	}
	if err := s.Begin(ctx, source, page, instance); err != nil {
		return FinishResult{}, err
	}
	objectKeys := make([]string, 0, len(page.Entries))
	for _, entry := range page.Entries {
		objectKeys = append(objectKeys, entry.ObjectKey)
	}
	return s.drainBatch(
		ctx, source, page.BatchID, objectKeys, len(page.Entries), start, instance,
	)
}

func (s *Store) drainBatch(
	ctx context.Context,
	source Source,
	batchID uuid.UUID,
	objectKeys []string,
	entryCount int,
	start time.Time,
	instance uuid.UUID,
) (FinishResult, error) {
	var applyErr error
	lastHeartbeat := time.Now()
	for _, objectKey := range objectKeys {
		if time.Since(lastHeartbeat) >= defaultLeaseSecs*time.Second/3 {
			acquired, err := s.AcquireLease(ctx, source, instance)
			if err != nil {
				return FinishResult{}, errors.Join(applyErr,
					fmt.Errorf("renew identity source lease while applying: %w", err))
			}
			if !acquired {
				return FinishResult{}, errors.Join(applyErr,
					errors.New("identity source lease was lost while applying"))
			}
			lastHeartbeat = time.Now()
		}
		result, err := s.Apply(ctx, source, batchID, objectKey)
		if err != nil {
			applyErr = errors.Join(applyErr, err)
			continue
		}
		if result.State == "blocked" {
			applyErr = errors.Join(applyErr,
				fmt.Errorf("entry %s blocked (%s)", objectKey, result.Code))
		}
	}
	acquired, err := s.AcquireLease(ctx, source, instance)
	if err != nil {
		return FinishResult{}, errors.Join(applyErr,
			fmt.Errorf("renew identity source lease before cursor commit: %w", err))
	}
	if !acquired {
		return FinishResult{}, errors.Join(applyErr,
			errors.New("identity source lease was lost before cursor commit"))
	}
	finish, finishErr := s.Finish(
		ctx, source, Page{BatchID: batchID}, time.Since(start), instance,
	)
	if finishErr != nil {
		return finish, errors.Join(applyErr, finishErr)
	}
	if !finish.CursorAdvanced {
		applyErr = errors.Join(applyErr,
			fmt.Errorf("identity source batch %s remains blocked with %d pending entries",
				batchID, finish.Pending))
	}
	if finish.State == "completed" &&
		finish.Applied+finish.Quarantined != entryCount {
		applyErr = errors.Join(applyErr,
			fmt.Errorf(
				"identity source batch %s completed with %d terminal entries, expected %d",
				batchID, finish.Applied+finish.Quarantined, entryCount,
			))
	}
	return finish, applyErr
}
