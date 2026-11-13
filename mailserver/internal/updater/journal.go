package updater

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const (
	JournalVersion   = 1
	maxJournalBytes  = 64 << 20
	maxJournalRecord = 1 << 20
	journalFileName  = "events.jsonl"
	snapshotFileName = "snapshot.json"
	// One fixed archive preserves the immediately previous reconciled terminal
	// tip while keeping host-local evidence bounded. PostgreSQL retains the
	// complete durable upgrade history.
	terminalArchiveFileName = "last-terminal.json"
	journalDirMode          = 0o700
	journalFileMode         = 0o600
	maxStateGeneration      = uint64(1<<63 - 1)
)

var (
	ErrJournalTornWrite   = errors.New("upgrade journal has a torn write")
	ErrJournalChecksum    = errors.New("upgrade journal checksum mismatch")
	ErrJournalSequence    = errors.New("upgrade journal sequence mismatch")
	ErrJournalVersion     = errors.New("unsupported upgrade journal version")
	journalIdentifierExpr = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	journalDigestExpr     = regexp.MustCompile(`^[a-f0-9]{64}$`)
	journalLeaseExpr      = regexp.MustCompile(`^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$`)
)

// Event is one completed durable boundary. Hash authenticates all preceding
// fields and PreviousHash makes deletion, insertion, and reordering visible.
type Event struct {
	Version           int             `json:"version"`
	Sequence          uint64          `json:"sequence"`
	OccurredAt        string          `json:"occurred_at"`
	IntentID          string          `json:"intent_id"`
	ReleaseID         string          `json:"release_id"`
	ManifestDigest    string          `json:"manifest_digest"`
	RecoverySetID     string          `json:"recovery_set_id,omitempty"`
	RecoverySetDigest string          `json:"recovery_set_digest,omitempty"`
	LeaseID           string          `json:"lease_id"`
	ExecutorID        string          `json:"executor_id"`
	StateGeneration   uint64          `json:"state_generation"`
	State             State           `json:"state"`
	Step              string          `json:"step"`
	Evidence          json.RawMessage `json:"evidence"`
	PreviousHash      string          `json:"previous_hash,omitempty"`
	Hash              string          `json:"hash"`
}

type eventPayload struct {
	Version           int             `json:"version"`
	Sequence          uint64          `json:"sequence"`
	OccurredAt        string          `json:"occurred_at"`
	IntentID          string          `json:"intent_id"`
	ReleaseID         string          `json:"release_id"`
	ManifestDigest    string          `json:"manifest_digest"`
	RecoverySetID     string          `json:"recovery_set_id,omitempty"`
	RecoverySetDigest string          `json:"recovery_set_digest,omitempty"`
	LeaseID           string          `json:"lease_id"`
	ExecutorID        string          `json:"executor_id"`
	StateGeneration   uint64          `json:"state_generation"`
	State             State           `json:"state"`
	Step              string          `json:"step"`
	Evidence          json.RawMessage `json:"evidence"`
	PreviousHash      string          `json:"previous_hash,omitempty"`
}

type journalSnapshot struct {
	Version    int   `json:"version"`
	Last       Event `json:"last"`
	Reconciled bool  `json:"reconciled"`
}

// JournalState is the verified durable tip. Events contains the full log when
// uncompacted, or the compacted tip followed by any later entries.
type JournalState struct {
	Events     []Event
	Reconciled bool
}

func (s JournalState) Last() (Event, bool) {
	if len(s.Events) == 0 {
		return Event{}, false
	}
	return s.Events[len(s.Events)-1], true
}

// Journal is a root-owned, host-local append log. Its sync hooks are injectable
// only through package tests; the production constructor always uses fsync.
type Journal struct {
	dir      string
	now      func() time.Time
	syncFile func(*os.File) error
	syncDir  func(string) error
}

func OpenJournal(dir string) (*Journal, error) {
	if strings.TrimSpace(dir) == "" || !filepath.IsAbs(dir) {
		return nil, fmt.Errorf("journal directory must be absolute")
	}
	if err := os.MkdirAll(dir, journalDirMode); err != nil {
		return nil, fmt.Errorf("create journal directory: %w", err)
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return nil, fmt.Errorf("stat journal directory: %w", err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("journal path must be a real directory")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("journal directory permissions must not grant group or world access")
	}
	return &Journal{
		dir:      dir,
		now:      func() time.Time { return time.Now().UTC().Truncate(time.Second) },
		syncFile: func(file *os.File) error { return file.Sync() },
		syncDir:  syncDirectory,
	}, nil
}

func (j *Journal) Load() (JournalState, error) {
	var state JournalState
	var baseline *Event
	snapshotPath := filepath.Join(j.dir, snapshotFileName)
	if data, err := readBounded(snapshotPath, maxJournalRecord); err == nil {
		var snapshot journalSnapshot
		if err := strictJSON(data, &snapshot); err != nil {
			return state, fmt.Errorf("decode journal snapshot: %w", err)
		}
		if snapshot.Version != JournalVersion {
			return state, fmt.Errorf("%w: snapshot version %d", ErrJournalVersion, snapshot.Version)
		}
		if err := verifyEvent(snapshot.Last, "", false); err != nil {
			return state, fmt.Errorf("verify journal snapshot: %w", err)
		}
		copy := snapshot.Last
		baseline = &copy
		state.Events = append(state.Events, copy)
		state.Reconciled = snapshot.Reconciled
	} else if !errors.Is(err, os.ErrNotExist) {
		return state, fmt.Errorf("read journal snapshot: %w", err)
	}

	logPath := filepath.Join(j.dir, journalFileName)
	data, err := readBounded(logPath, maxJournalBytes)
	if errors.Is(err, os.ErrNotExist) {
		return state, nil
	}
	if err != nil {
		return state, fmt.Errorf("read journal: %w", err)
	}
	if len(data) == 0 {
		return state, nil
	}
	if data[len(data)-1] != '\n' {
		return state, ErrJournalTornWrite
	}

	previousSequence := uint64(0)
	previousGeneration := uint64(0)
	previousHash := ""
	if baseline != nil {
		previousSequence = baseline.Sequence
		previousGeneration = baseline.StateGeneration
		previousHash = baseline.Hash
	}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 4096), maxJournalRecord)
	compactedSequence := uint64(0)
	compactedHash := ""
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(bytes.TrimSpace(line)) == 0 {
			return state, fmt.Errorf("%w: empty record", ErrJournalSequence)
		}
		var event Event
		if err := strictJSON(line, &event); err != nil {
			return state, fmt.Errorf("decode journal event: %w", err)
		}
		if baseline != nil && event.Sequence <= baseline.Sequence {
			if event.Sequence != compactedSequence+1 {
				return state, fmt.Errorf("%w: compacted log got %d after %d", ErrJournalSequence, event.Sequence, compactedSequence)
			}
			if err := verifyEvent(event, compactedHash, true); err != nil {
				return state, err
			}
			compactedSequence = event.Sequence
			compactedHash = event.Hash
			if event.Sequence == baseline.Sequence && event.Hash != baseline.Hash {
				return state, fmt.Errorf("%w: snapshot/log tip differs", ErrJournalChecksum)
			}
			continue
		}
		if event.Sequence != previousSequence+1 {
			return state, fmt.Errorf("%w: got %d after %d", ErrJournalSequence, event.Sequence, previousSequence)
		}
		if previousSequence > 0 && event.StateGeneration != previousGeneration+1 {
			return state, fmt.Errorf("%w: state generation got %d after %d", ErrJournalSequence, event.StateGeneration, previousGeneration)
		}
		if err := verifyEvent(event, previousHash, true); err != nil {
			return state, err
		}
		state.Events = append(state.Events, event)
		state.Reconciled = false
		previousSequence = event.Sequence
		previousGeneration = event.StateGeneration
		previousHash = event.Hash
	}
	if err := scanner.Err(); err != nil {
		return state, fmt.Errorf("scan journal: %w", err)
	}
	return state, nil
}

// Append records a completed boundary and fsyncs it before returning.
func (j *Journal) Append(event Event) (Event, error) {
	state, err := j.Load()
	if err != nil {
		return Event{}, err
	}
	last, ok := state.Last()
	if ok {
		if event.StateGeneration != last.StateGeneration+1 {
			return Event{}, fmt.Errorf("journal state generation changed from %d to %d", last.StateGeneration, event.StateGeneration)
		}
		event.Sequence = last.Sequence + 1
		event.PreviousHash = last.Hash
		if event.IntentID != last.IntentID || event.ReleaseID != last.ReleaseID ||
			event.ManifestDigest != last.ManifestDigest || event.LeaseID != last.LeaseID ||
			event.RecoverySetID != last.RecoverySetID || event.RecoverySetDigest != last.RecoverySetDigest ||
			event.ExecutorID != last.ExecutorID {
			return Event{}, fmt.Errorf("journal transaction identity changed")
		}
	} else {
		if event.StateGeneration == 0 {
			return Event{}, fmt.Errorf("journal state generation must be positive")
		}
		event.Sequence = 1
		event.PreviousHash = ""
	}
	event.Version = JournalVersion
	event.OccurredAt = j.now().Format(time.RFC3339)
	if len(event.Evidence) == 0 {
		event.Evidence = json.RawMessage(`{}`)
	}
	hash, err := eventHash(event)
	if err != nil {
		return Event{}, err
	}
	event.Hash = hash
	if err := verifyEvent(event, event.PreviousHash, false); err != nil {
		return Event{}, err
	}
	line, err := json.Marshal(event)
	if err != nil {
		return Event{}, fmt.Errorf("encode journal event: %w", err)
	}
	line = append(line, '\n')
	path := filepath.Join(j.dir, journalFileName)
	// j.dir was opened as a private real directory and journalFileName is fixed.
	//nolint:gosec // G304: no caller-controlled filename is opened.
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, journalFileMode)
	if err != nil {
		return Event{}, fmt.Errorf("open journal: %w", err)
	}
	if _, err := file.Write(line); err != nil {
		_ = file.Close()
		return Event{}, fmt.Errorf("append journal: %w", err)
	}
	if err := j.syncFile(file); err != nil {
		_ = file.Close()
		return Event{}, fmt.Errorf("sync journal: %w", err)
	}
	if err := file.Close(); err != nil {
		return Event{}, fmt.Errorf("close journal: %w", err)
	}
	return event, nil
}

// Compact writes a verified terminal tip atomically, then truncates the append
// log. It is forbidden until PostgreSQL reconciliation is confirmed.
func (j *Journal) Compact(reconciled bool) error {
	state, err := j.Load()
	if err != nil {
		return err
	}
	last, ok := state.Last()
	if !ok || !last.State.Terminal() || !reconciled {
		return fmt.Errorf("journal compaction requires a reconciled terminal transaction")
	}
	snapshot := journalSnapshot{Version: JournalVersion, Last: last, Reconciled: true}
	data, err := json.Marshal(snapshot)
	if err != nil {
		return fmt.Errorf("encode journal snapshot: %w", err)
	}
	if err := j.atomicWrite(snapshotFileName, append(data, '\n')); err != nil {
		return err
	}
	log, err := os.OpenFile(filepath.Join(j.dir, journalFileName), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, journalFileMode)
	if err != nil {
		return fmt.Errorf("truncate journal: %w", err)
	}
	if err := j.syncFile(log); err != nil {
		_ = log.Close()
		return fmt.Errorf("sync compacted journal: %w", err)
	}
	if err := log.Close(); err != nil {
		return fmt.Errorf("close compacted journal: %w", err)
	}
	return j.syncDir(j.dir)
}

// ArchiveReconciledTerminal moves a compacted terminal snapshot out of the
// active-journal namespace before a later approved intent starts a fresh hash
// chain. In-flight or unreconciled transactions can never be rotated.
func (j *Journal) ArchiveReconciledTerminal() error {
	state, err := j.Load()
	if err != nil {
		return err
	}
	last, ok := state.Last()
	if !ok || !last.State.Terminal() || !state.Reconciled {
		return fmt.Errorf("journal rotation requires a reconciled terminal transaction")
	}
	logInfo, err := os.Stat(filepath.Join(j.dir, journalFileName))
	if err != nil || !logInfo.Mode().IsRegular() || logInfo.Size() != 0 {
		return fmt.Errorf("journal rotation requires an empty compacted append log")
	}
	snapshotPath := filepath.Join(j.dir, snapshotFileName)
	raw, err := readBounded(snapshotPath, maxJournalRecord)
	if err != nil {
		return fmt.Errorf("read terminal journal snapshot: %w", err)
	}
	// Persist and fsync the archive before removing the active snapshot. If the
	// final directory sync fails, a reboot may resurrect the active snapshot,
	// which safely delays the next transaction rather than losing evidence.
	if err := j.atomicWrite(terminalArchiveFileName, raw); err != nil {
		return fmt.Errorf("archive terminal journal snapshot: %w", err)
	}
	if err := os.Remove(snapshotPath); err != nil {
		return fmt.Errorf("retire active terminal journal snapshot: %w", err)
	}
	return j.syncDir(j.dir)
}

func (j *Journal) atomicWrite(name string, data []byte) error {
	tmp, err := os.CreateTemp(j.dir, "."+name+".*.tmp")
	if err != nil {
		return fmt.Errorf("create snapshot temp file: %w", err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	if err := tmp.Chmod(journalFileMode); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("chmod snapshot: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write snapshot: %w", err)
	}
	if err := j.syncFile(tmp); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("sync snapshot: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close snapshot: %w", err)
	}
	if err := os.Rename(tmpName, filepath.Join(j.dir, name)); err != nil {
		return fmt.Errorf("rename snapshot: %w", err)
	}
	return j.syncDir(j.dir)
}

func verifyEvent(event Event, expectedPrevious string, enforcePrevious bool) error {
	if event.Version != JournalVersion {
		return fmt.Errorf("%w: event version %d", ErrJournalVersion, event.Version)
	}
	if event.Sequence == 0 || !journalIdentifierExpr.MatchString(event.IntentID) ||
		!journalIdentifierExpr.MatchString(event.ReleaseID) || !journalLeaseExpr.MatchString(event.LeaseID) ||
		!journalDigestExpr.MatchString(event.ManifestDigest) || !event.State.Valid() ||
		!journalIdentifierExpr.MatchString(event.ExecutorID) || event.StateGeneration == 0 || event.StateGeneration > maxStateGeneration ||
		!journalIdentifierExpr.MatchString(event.Step) {
		return fmt.Errorf("invalid upgrade journal event")
	}
	if (event.RecoverySetID == "") != (event.RecoverySetDigest == "") ||
		(event.RecoverySetID != "" && (!journalLeaseExpr.MatchString(event.RecoverySetID) ||
			!journalDigestExpr.MatchString(event.RecoverySetDigest))) {
		return fmt.Errorf("invalid recovery-set journal binding")
	}
	if _, err := time.Parse(time.RFC3339, event.OccurredAt); err != nil {
		return fmt.Errorf("invalid journal timestamp: %w", err)
	}
	if len(event.Evidence) == 0 || len(event.Evidence) > maxJournalRecord ||
		!json.Valid(event.Evidence) || bytes.TrimSpace(event.Evidence)[0] != '{' {
		return fmt.Errorf("invalid journal evidence")
	}
	if enforcePrevious && event.PreviousHash != expectedPrevious {
		return fmt.Errorf("%w: previous hash differs", ErrJournalChecksum)
	}
	if event.PreviousHash != "" && !journalDigestExpr.MatchString(event.PreviousHash) {
		return fmt.Errorf("invalid previous journal hash")
	}
	if !journalDigestExpr.MatchString(event.Hash) {
		return fmt.Errorf("invalid journal hash")
	}
	want, err := eventHash(event)
	if err != nil {
		return err
	}
	if event.Hash != want {
		return ErrJournalChecksum
	}
	return nil
}

func eventHash(event Event) (string, error) {
	payload := eventPayload{
		Version: event.Version, Sequence: event.Sequence, OccurredAt: event.OccurredAt,
		IntentID: event.IntentID, ReleaseID: event.ReleaseID,
		ManifestDigest: event.ManifestDigest, LeaseID: event.LeaseID, ExecutorID: event.ExecutorID,
		RecoverySetID: event.RecoverySetID, RecoverySetDigest: event.RecoverySetDigest,
		StateGeneration: event.StateGeneration, State: event.State, Step: event.Step,
		Evidence: event.Evidence, PreviousHash: event.PreviousHash,
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("encode journal checksum payload: %w", err)
	}
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:]), nil
}

func strictJSON(data []byte, dst any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return fmt.Errorf("multiple JSON values")
		}
		return err
	}
	return nil
}

func readBounded(path string, maximum int64) ([]byte, error) {
	// Callers pass only fixed snapshot/journal filenames below the validated
	// private journal directory; the opened descriptor is then re-stat'd.
	//nolint:gosec // G304: no request-controlled path reaches this helper.
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > maximum {
		return nil, fmt.Errorf("file is not regular or exceeds %d bytes", maximum)
	}
	return io.ReadAll(io.LimitReader(file, maximum+1))
}

func syncDirectory(dir string) error {
	// Callers pass only validated install, journal, quarantine, or evidence roots.
	//nolint:gosec // G304: no request-controlled path reaches this helper.
	file, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer file.Close()
	return file.Sync()
}
