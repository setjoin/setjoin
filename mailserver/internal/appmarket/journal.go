package appmarket

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"setjoin.com/mailserver/internal/updater"
)

const (
	maxAppJournalRecord = 256 << 10
	maxAppJournalSize   = 64 << 20
)

var (
	ErrAppJournalChecksum = errors.New("managed app journal checksum mismatch")
	ErrAppJournalTorn     = errors.New("managed app journal torn write")
)

type JournalRecord struct {
	Version         int             `json:"version"`
	Sequence        uint64          `json:"sequence"`
	OccurredAt      string          `json:"occurredAt"`
	OperationID     string          `json:"operationId"`
	LeaseID         string          `json:"leaseId"`
	ExecutorID      string          `json:"executorId"`
	StateGeneration int64           `json:"stateGeneration"`
	State           string          `json:"state"`
	Step            string          `json:"step"`
	Evidence        json.RawMessage `json:"evidence"`
	PreviousHash    string          `json:"previousHash,omitempty"`
	Hash            string          `json:"hash"`
}

type AppJournal struct {
	dir string
	mu  sync.Mutex
}

func OpenAppJournal(dir string) (*AppJournal, error) {
	if !filepath.IsAbs(dir) || strings.TrimSpace(dir) == "" {
		return nil, errors.New("managed app journal directory must be absolute")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create managed app journal: %w", err)
	}
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("managed app journal must be an owner-only real directory")
	}
	j := &AppJournal{dir: dir}
	if _, err := j.Load(); err != nil {
		return nil, err
	}
	return j, nil
}

func (j *AppJournal) AcquireLock() (*updater.LocalLock, error) {
	return updater.AcquireLocalLock(j.dir)
}

func (j *AppJournal) Load() ([]JournalRecord, error) {
	path := filepath.Join(j.dir, "events.jsonl")
	raw, err := os.ReadFile(path) //nolint:gosec // root-owned fixed path
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read managed app journal: %w", err)
	}
	if len(raw) > maxAppJournalSize {
		return nil, errors.New("managed app journal exceeds the bounded size")
	}
	if len(raw) > 0 && raw[len(raw)-1] != '\n' {
		return nil, ErrAppJournalTorn
	}
	var out []JournalRecord
	previous := ""
	scanner := bufio.NewScanner(strings.NewReader(string(raw)))
	scanner.Buffer(make([]byte, 4096), maxAppJournalRecord)
	for scanner.Scan() {
		var record JournalRecord
		if err := json.Unmarshal(scanner.Bytes(), &record); err != nil {
			return nil, fmt.Errorf("decode managed app journal: %w", err)
		}
		if record.Version != 1 || record.Sequence != uint64(len(out)+1) || record.PreviousHash != previous || record.Hash != recordHash(record) {
			return nil, ErrAppJournalChecksum
		}
		previous = record.Hash
		out = append(out, record)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan managed app journal: %w", err)
	}
	return out, nil
}

func (j *AppJournal) Append(op *Operation, step string, evidence any) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	records, err := j.Load()
	if err != nil {
		return err
	}
	evidenceRaw, err := json.Marshal(evidence)
	if err != nil {
		return fmt.Errorf("encode managed app journal evidence: %w", err)
	}
	record := JournalRecord{Version: 1, Sequence: uint64(len(records) + 1),
		OccurredAt:  time.Now().UTC().Truncate(time.Second).Format(time.RFC3339),
		OperationID: op.OperationID.String(), LeaseID: op.LeaseID.String(), ExecutorID: op.ExecutorID,
		StateGeneration: op.StateGeneration, State: op.State, Step: step, Evidence: evidenceRaw}
	if len(records) > 0 {
		record.PreviousHash = records[len(records)-1].Hash
	}
	record.Hash = recordHash(record)
	line, err := json.Marshal(record)
	if err != nil {
		return err
	}
	file, err := os.OpenFile(filepath.Join(j.dir, "events.jsonl"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600) //nolint:gosec
	if err != nil {
		return fmt.Errorf("open managed app journal: %w", err)
	}
	defer file.Close()
	if _, err := file.Write(append(line, '\n')); err != nil {
		return fmt.Errorf("append managed app journal: %w", err)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync managed app journal: %w", err)
	}
	return nil
}

func recordHash(record JournalRecord) string {
	record.Hash = ""
	raw, _ := json.Marshal(record)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}
