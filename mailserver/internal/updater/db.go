package updater

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

var (
	ErrControlPlaneUnavailable = errors.New("upgrade control plane unavailable")
	ErrInstallationLocked      = errors.New("another updater holds the installation advisory lock")
)

// Intent is the minimum authoritative state needed by the host executor.
type Intent struct {
	ID                string
	ReleaseID         string
	ManifestDigest    string
	RecoverySetID     string
	RecoverySetDigest string
	State             State
	StateGeneration   int64
	ExecutorID        string
	LeaseID           string
}

type ControlPlane interface {
	TryInstallationLock(context.Context) error
	ReadLatest(context.Context) (*Intent, error)
	Claim(context.Context, *Intent, string, string) (*Intent, error)
	Progress(context.Context, Event, State, json.RawMessage) (int64, bool, error)
	Complete(context.Context, Event, State, json.RawMessage) (int64, bool, error)
}

type RecoveryControlPlane interface {
	TryInstallationLock(context.Context) error
	ReadLatest(context.Context) (*Intent, error)
	Recover(context.Context, Event, json.RawMessage) (int64, bool, error)
}

// PGControlPlane owns one direct session so the PostgreSQL advisory lock lives
// exactly as long as the updater process. Its credential is setjoin_updater,
// never the schema owner.
type PGControlPlane struct {
	conn   *pgx.Conn
	locked bool
}

func OpenPGControlPlane(ctx context.Context, dsn string) (*PGControlPlane, error) {
	conn, err := pgx.Connect(ctx, strings.TrimSpace(dsn))
	if err != nil {
		return nil, fmt.Errorf("%w: connect: %v", ErrControlPlaneUnavailable, err)
	}
	return &PGControlPlane{conn: conn}, nil
}

func ValidateDistinctDatabaseCredentials(controlDSN, ownerDSN string) error {
	control, err := pgx.ParseConfig(strings.TrimSpace(controlDSN))
	if err != nil {
		return fmt.Errorf("parse updater control credential: %w", err)
	}
	owner, err := pgx.ParseConfig(strings.TrimSpace(ownerDSN))
	if err != nil {
		return fmt.Errorf("parse migration-owner credential: %w", err)
	}
	if control.User != "setjoin_updater" {
		return fmt.Errorf("updater control credential must use setjoin_updater, got %q", control.User)
	}
	if owner.User == "" || owner.User == control.User || strings.TrimSpace(controlDSN) == strings.TrimSpace(ownerDSN) {
		return errors.New("migration-owner credential must be distinct from setjoin_updater")
	}
	return nil
}

func (db *PGControlPlane) Close(ctx context.Context) error {
	if db == nil || db.conn == nil {
		return nil
	}
	return db.conn.Close(ctx)
}

func (db *PGControlPlane) TryInstallationLock(ctx context.Context) error {
	if db.locked {
		return nil
	}
	var acquired bool
	if err := db.conn.QueryRow(ctx, `SELECT pg_try_advisory_lock(21322, 21840)`).Scan(&acquired); err != nil {
		return fmt.Errorf("%w: advisory lock: %v", ErrControlPlaneUnavailable, err)
	}
	if !acquired {
		return ErrInstallationLocked
	}
	db.locked = true
	return nil
}

func (db *PGControlPlane) ReadLatest(ctx context.Context) (*Intent, error) {
	var raw []byte
	if err := db.conn.QueryRow(ctx, `SELECT upgrade_intent_read(NULL)`).Scan(&raw); err != nil {
		return nil, fmt.Errorf("%w: read intent: %v", ErrControlPlaneUnavailable, err)
	}
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) || len(raw) == 0 {
		return nil, nil
	}
	return parseIntent(raw)
}

func (db *PGControlPlane) RecoveryIdentity(ctx context.Context) (RecoveryIdentity, error) {
	var raw []byte
	if err := db.conn.QueryRow(ctx, `SELECT upgrade_recovery_identity_read()`).Scan(&raw); err != nil {
		return RecoveryIdentity{}, fmt.Errorf("%w: read recovery identity: %v", ErrControlPlaneUnavailable, err)
	}
	var wire struct {
		InstallationID string `json:"installationId"`
		TimelineID     string `json:"timelineId"`
	}
	if err := strictJSON(raw, &wire); err != nil {
		return RecoveryIdentity{}, fmt.Errorf("decode recovery identity: %w", err)
	}
	installation, installErr := uuid.Parse(wire.InstallationID)
	timeline, timelineErr := uuid.Parse(wire.TimelineID)
	if installErr != nil || timelineErr != nil || installation == uuid.Nil || timeline == uuid.Nil {
		return RecoveryIdentity{}, errors.New("database returned invalid recovery identity")
	}
	return RecoveryIdentity{InstallationID: installation.String(), TimelineID: timeline.String()}, nil
}

func (db *PGControlPlane) Claim(ctx context.Context, intent *Intent, executorID, leaseID string) (*Intent, error) {
	if intent == nil || !journalIdentifierExpr.MatchString(intent.ReleaseID) ||
		!journalDigestExpr.MatchString(intent.ManifestDigest) ||
		!canonicalUUIDString(intent.RecoverySetID) ||
		!journalDigestExpr.MatchString(intent.RecoverySetDigest) ||
		!journalIdentifierExpr.MatchString(executorID) {
		return nil, errors.New("invalid upgrade claim authority")
	}
	id, err := positiveInt64(intent.ID)
	if err != nil {
		return nil, err
	}
	lease, err := uuid.Parse(leaseID)
	if err != nil {
		return nil, fmt.Errorf("invalid lease ID: %w", err)
	}
	var raw []byte
	if err := db.conn.QueryRow(ctx, `SELECT upgrade_intent_claim($1,$2,$3,$4)`,
		id, intent.StateGeneration, executorID, lease).Scan(&raw); err != nil {
		return nil, err
	}
	claimed, err := parseIntent(raw)
	if err != nil {
		return nil, err
	}
	if claimed.ReleaseID != intent.ReleaseID || claimed.ManifestDigest != intent.ManifestDigest ||
		claimed.RecoverySetID != intent.RecoverySetID || claimed.RecoverySetDigest != intent.RecoverySetDigest ||
		claimed.LeaseID != lease.String() {
		return nil, errors.New("database claim response differs from the requested authority")
	}
	claimed.ExecutorID = executorID
	return claimed, nil
}

func (db *PGControlPlane) Progress(ctx context.Context, event Event, target State, evidence json.RawMessage) (int64, bool, error) {
	return db.mutate(ctx, `SELECT upgrade_intent_progress($1,$2,$3,$4,$5,$6,$7)`, event, target, evidence)
}

func (db *PGControlPlane) Complete(ctx context.Context, event Event, target State, result json.RawMessage) (int64, bool, error) {
	return db.mutate(ctx, `SELECT upgrade_intent_complete($1,$2,$3,$4,$5,$6,$7)`, event, target, result)
}

func (db *PGControlPlane) Recover(ctx context.Context, event Event, result json.RawMessage) (int64, bool, error) {
	id, err := positiveInt64(event.IntentID)
	if err != nil {
		return 0, false, err
	}
	lease, err := uuid.Parse(event.LeaseID)
	if err != nil {
		return 0, false, fmt.Errorf("invalid lease ID: %w", err)
	}
	current, err := generationForDatabase(event.StateGeneration)
	if err != nil || current <= 1 {
		return 0, false, fmt.Errorf("invalid state generation %d", event.StateGeneration)
	}
	expected := current - 1
	var raw []byte
	if err := db.conn.QueryRow(ctx, `SELECT upgrade_intent_recover($1,$2,$3,$4,$5,$6)`,
		id, expected, event.ExecutorID, lease, event.Hash, result).Scan(&raw); err != nil {
		return 0, false, err
	}
	var response struct {
		IntentID        string `json:"intentId"`
		State           State  `json:"state"`
		StateGeneration string `json:"stateGeneration"`
		Replayed        bool   `json:"replayed"`
	}
	if err := strictJSON(raw, &response); err != nil {
		return 0, false, fmt.Errorf("decode recovery reducer response: %w", err)
	}
	if response.State != StateRolledBack || response.IntentID != event.IntentID {
		return 0, false, fmt.Errorf("recovery reducer response identity differs")
	}
	generation, err := positiveInt64(response.StateGeneration)
	if err != nil {
		return 0, false, err
	}
	return generation, response.Replayed, nil
}

func (db *PGControlPlane) mutate(ctx context.Context, query string, event Event, target State, evidence json.RawMessage) (int64, bool, error) {
	id, err := positiveInt64(event.IntentID)
	if err != nil {
		return 0, false, err
	}
	lease, err := uuid.Parse(event.LeaseID)
	if err != nil {
		return 0, false, fmt.Errorf("invalid lease ID: %w", err)
	}
	var raw []byte
	current, err := generationForDatabase(event.StateGeneration)
	if err != nil || current <= 1 {
		return 0, false, fmt.Errorf("invalid state generation %d", event.StateGeneration)
	}
	expected := current - 1
	if err := db.conn.QueryRow(ctx, query, id, expected, event.ExecutorID,
		lease, target, event.Hash, evidence).Scan(&raw); err != nil {
		return 0, false, err
	}
	var response struct {
		IntentID        string `json:"intentId"`
		State           State  `json:"state"`
		StateGeneration string `json:"stateGeneration"`
		Replayed        bool   `json:"replayed"`
	}
	if err := strictJSON(raw, &response); err != nil {
		return 0, false, fmt.Errorf("decode reducer response: %w", err)
	}
	generation, err := positiveInt64(response.StateGeneration)
	if err != nil {
		return 0, false, err
	}
	return generation, response.Replayed, nil
}

func parseIntent(raw []byte) (*Intent, error) {
	var wire struct {
		IntentID          string  `json:"intentId"`
		ReleaseID         string  `json:"releaseId"`
		ManifestDigest    string  `json:"manifestDigest"`
		RecoverySetID     string  `json:"recoverySetId"`
		RecoverySetDigest string  `json:"recoverySetDigest"`
		State             State   `json:"state"`
		StateGeneration   string  `json:"stateGeneration"`
		ExecutorID        string  `json:"executorId"`
		LeaseID           string  `json:"leaseId"`
		Replayed          bool    `json:"replayed"`
		InstallationID    string  `json:"installationId"`
		RequestedByUserID string  `json:"requestedByUserId"`
		ApprovedByUserID  *string `json:"approvedByUserId"`
		ApprovalRequestID *string `json:"approvalRequestId"`
		Reason            string  `json:"reason"`
		ScheduleAt        any     `json:"scheduleAt"`
		ExpiresAt         any     `json:"expiresAt"`
		ClaimedAt         any     `json:"claimedAt"`
		CancelRequestedAt any     `json:"cancelRequestedAt"`
		CompletedAt       any     `json:"completedAt"`
		Result            any     `json:"result"`
		CreatedAt         any     `json:"createdAt"`
		UpdatedAt         any     `json:"updatedAt"`
		Events            any     `json:"events"`
	}
	if err := strictJSON(raw, &wire); err != nil {
		return nil, fmt.Errorf("decode upgrade intent: %w", err)
	}
	if _, err := positiveInt64(wire.IntentID); err != nil {
		return nil, err
	}
	generation, err := positiveInt64(wire.StateGeneration)
	if err != nil {
		return nil, err
	}
	if !wire.State.Valid() {
		return nil, fmt.Errorf("unknown upgrade intent state %q", wire.State)
	}
	if wire.ReleaseID != "" && !journalIdentifierExpr.MatchString(wire.ReleaseID) {
		return nil, errors.New("database returned invalid release ID")
	}
	if wire.ManifestDigest != "" && !journalDigestExpr.MatchString(wire.ManifestDigest) {
		return nil, errors.New("database returned invalid manifest digest")
	}
	if (wire.RecoverySetID == "") != (wire.RecoverySetDigest == "") ||
		(wire.RecoverySetID != "" && (!canonicalUUIDString(wire.RecoverySetID) ||
			!journalDigestExpr.MatchString(wire.RecoverySetDigest))) {
		return nil, errors.New("database returned invalid recovery-set authority")
	}
	if wire.LeaseID != "" && !canonicalUUIDString(wire.LeaseID) {
		return nil, errors.New("database returned invalid lease ID")
	}
	return &Intent{ID: wire.IntentID, ReleaseID: wire.ReleaseID,
		ManifestDigest: wire.ManifestDigest, State: wire.State,
		RecoverySetID: wire.RecoverySetID, RecoverySetDigest: wire.RecoverySetDigest,
		StateGeneration: generation, ExecutorID: wire.ExecutorID, LeaseID: wire.LeaseID}, nil
}

func canonicalUUIDString(value string) bool {
	parsed, err := uuid.Parse(value)
	return err == nil && parsed != uuid.Nil && parsed.String() == value
}

func positiveInt64(value string) (int64, error) {
	parsed, err := strconv.ParseInt(value, 10, 64)
	if err != nil || parsed <= 0 || strconv.FormatInt(parsed, 10) != value {
		return 0, fmt.Errorf("invalid decimal identifier %q", value)
	}
	return parsed, nil
}

func generationFromDatabase(value int64) (uint64, error) {
	if value <= 0 {
		return 0, fmt.Errorf("invalid database state generation %d", value)
	}
	//nolint:gosec // G115: the positive int64 domain is fully representable by uint64.
	return uint64(value), nil
}

func generationForDatabase(value uint64) (int64, error) {
	if value == 0 || value > maxStateGeneration {
		return 0, fmt.Errorf("invalid journal state generation %d", value)
	}
	//nolint:gosec // G115: maxStateGeneration is exactly math.MaxInt64.
	return int64(value), nil
}

// ReadCredentialFile reads a systemd LoadCredential file without accepting a
// secret from argv or the process environment.
func ReadCredentialFile(path string) (string, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return "", fmt.Errorf("stat credential: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() <= 0 || info.Size() > 16<<10 || info.Mode().Perm()&0o077 != 0 {
		return "", fmt.Errorf("credential must be a non-empty private regular file")
	}
	// The root-only CLI selects this path, and the file was just checked as a
	// bounded private regular file with no symlink or group/world access.
	//nolint:gosec // G304: the value is an operator-selected credential file, not request input.
	file, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("open credential: %w", err)
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, (16<<10)+1))
	if err != nil {
		return "", fmt.Errorf("read credential: %w", err)
	}
	if len(data) > 16<<10 {
		return "", fmt.Errorf("credential exceeds 16 KiB")
	}
	value := strings.TrimSpace(string(data))
	if value == "" || strings.ContainsAny(value, "\r\n\x00") {
		return "", fmt.Errorf("credential contains invalid whitespace or control bytes")
	}
	return value, nil
}

// ReadPrivateKeyFile reads opaque private key material without trimming or
// otherwise normalizing bytes. This must stay byte-for-byte aligned with the
// recovery-set creator: a trailing newline written by an operator tool is part
// of the HMAC key, not presentation whitespace.
func ReadPrivateKeyFile(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("stat private key: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 ||
		info.Mode().Perm()&0o077 != 0 || info.Size() < 32 || info.Size() > 16<<10 {
		return nil, fmt.Errorf("private key must be a regular non-symlink 0600 file of 32-16384 bytes")
	}
	// The root-owned service selects one fixed LoadCredential path and the file
	// was just bounded and lstat-checked.
	//nolint:gosec // G304: fixed service credential path, not request input.
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open private key: %w", err)
	}
	data, readErr := io.ReadAll(io.LimitReader(file, (16<<10)+1))
	closeErr := file.Close()
	if err := errors.Join(readErr, closeErr); err != nil {
		return nil, fmt.Errorf("read private key: %w", err)
	}
	if len(data) > 16<<10 {
		return nil, fmt.Errorf("private key exceeds 16 KiB")
	}
	return data, nil
}
