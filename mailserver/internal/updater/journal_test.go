package updater

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testJournal(t *testing.T) *Journal {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "journal")
	journal, err := OpenJournal(dir)
	if err != nil {
		t.Fatal(err)
	}
	journal.now = func() time.Time { return time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC) }
	return journal
}

func testEvent(state State, step string) Event {
	return Event{
		IntentID: "42", ReleaseID: "release-1",
		ManifestDigest:  strings.Repeat("a", 64),
		LeaseID:         "11111111-1111-4111-8111-111111111111",
		ExecutorID:      "updater-test",
		StateGeneration: 2,
		State:           state, Step: step, Evidence: json.RawMessage(`{"ok":true}`),
	}
}

func TestJournalAppendLoadAndReplay(t *testing.T) {
	t.Parallel()
	journal := testJournal(t)
	first, err := journal.Append(testEvent(StateClaimed, "claimed"))
	if err != nil {
		t.Fatal(err)
	}
	secondEvent := testEvent(StatePreflight, "preflight")
	secondEvent.StateGeneration = 3
	second, err := journal.Append(secondEvent)
	if err != nil {
		t.Fatal(err)
	}
	if first.Sequence != 1 || second.Sequence != 2 || second.PreviousHash != first.Hash {
		t.Fatalf("unexpected hash chain: %#v %#v", first, second)
	}
	state, err := journal.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(state.Events) != 2 || state.Events[1].Hash != second.Hash {
		t.Fatalf("unexpected replay: %#v", state)
	}
}

func TestJournalRejectsTornChecksumAndUnknownVersion(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		edit func([]byte) []byte
		want error
	}{
		{name: "torn", edit: func(data []byte) []byte { return data[:len(data)-1] }, want: ErrJournalTornWrite},
		{name: "checksum", edit: func(data []byte) []byte {
			return []byte(strings.Replace(string(data), `"state":"claimed"`, `"state":"preflight"`, 1))
		}, want: ErrJournalChecksum},
		{name: "version", edit: func(data []byte) []byte {
			return []byte(strings.Replace(string(data), `"version":1`, `"version":2`, 1))
		}, want: ErrJournalVersion},
	} {
		t.Run(tc.name, func(t *testing.T) {
			journal := testJournal(t)
			if _, err := journal.Append(testEvent(StateClaimed, "claimed")); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(journal.dir, journalFileName)
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, tc.edit(data), journalFileMode); err != nil {
				t.Fatal(err)
			}
			if _, err := journal.Load(); !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}
}

func TestJournalRejectsDuplicateOrOutOfOrderSequence(t *testing.T) {
	t.Parallel()
	journal := testJournal(t)
	first, err := journal.Append(testEvent(StateClaimed, "claimed"))
	if err != nil {
		t.Fatal(err)
	}
	line, err := json.Marshal(first)
	if err != nil {
		t.Fatal(err)
	}
	file, err := os.OpenFile(filepath.Join(journal.dir, journalFileName), os.O_APPEND|os.O_WRONLY, journalFileMode)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write(append(line, '\n')); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := journal.Load(); !errors.Is(err, ErrJournalSequence) {
		t.Fatalf("got %v, want sequence error", err)
	}
}

func TestJournalSyncFailureIsReportedAndValidWriteCanResume(t *testing.T) {
	t.Parallel()
	journal := testJournal(t)
	journal.syncFile = func(*os.File) error { return errors.New("EIO") }
	if _, err := journal.Append(testEvent(StateClaimed, "claimed")); err == nil || !strings.Contains(err.Error(), "EIO") {
		t.Fatalf("expected sync error, got %v", err)
	}
	journal.syncFile = func(file *os.File) error { return file.Sync() }
	state, err := journal.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(state.Events) != 1 {
		t.Fatalf("a complete write before failed fsync must be replayable, got %d", len(state.Events))
	}
}

func TestJournalCompactionRequiresReconciledTerminalState(t *testing.T) {
	t.Parallel()
	journal := testJournal(t)
	if _, err := journal.Append(testEvent(StateClaimed, "claimed")); err != nil {
		t.Fatal(err)
	}
	if err := journal.Compact(true); err == nil {
		t.Fatal("non-terminal journal compacted")
	}
	failed := testEvent(StateFailed, "failed")
	failed.StateGeneration = 3
	if _, err := journal.Append(failed); err != nil {
		t.Fatal(err)
	}
	if err := journal.Compact(false); err == nil {
		t.Fatal("unreconciled journal compacted")
	}
	if err := journal.Compact(true); err != nil {
		t.Fatal(err)
	}
	state, err := journal.Load()
	if err != nil {
		t.Fatal(err)
	}
	last, ok := state.Last()
	if !ok || last.State != StateFailed || !state.Reconciled || len(state.Events) != 1 {
		t.Fatalf("unexpected compacted state: %#v", state)
	}
}

func TestJournalArchivesOneReconciledTerminalBeforeNextTransaction(t *testing.T) {
	journal := testJournal(t)
	if err := journal.ArchiveReconciledTerminal(); err == nil {
		t.Fatal("empty journal rotated")
	}
	if _, err := journal.Append(testEvent(StateFailed, "failed")); err != nil {
		t.Fatal(err)
	}
	if err := journal.ArchiveReconciledTerminal(); err == nil {
		t.Fatal("uncompacted terminal journal rotated")
	}
	if err := journal.Compact(true); err != nil {
		t.Fatal(err)
	}
	if err := journal.ArchiveReconciledTerminal(); err != nil {
		t.Fatal(err)
	}
	state, err := journal.Load()
	if err != nil || len(state.Events) != 0 || state.Reconciled {
		t.Fatalf("active journal=%#v err=%v", state, err)
	}
	archive, err := readBounded(filepath.Join(journal.dir, terminalArchiveFileName), maxJournalRecord)
	if err != nil || !bytes.Contains(archive, []byte(`"state":"failed"`)) {
		t.Fatalf("terminal archive=%q err=%v", archive, err)
	}
	next := testEvent(StateApproved, "claim_prepared")
	next.IntentID = "43"
	next.StateGeneration = 1
	if _, err := journal.Append(next); err != nil {
		t.Fatalf("fresh transaction after terminal archive: %v", err)
	}
}

func TestOpenJournalRejectsRelativeAndLoosePermissions(t *testing.T) {
	t.Parallel()
	if _, err := OpenJournal("relative"); err == nil {
		t.Fatal("relative journal directory accepted")
	}
	dir := filepath.Join(t.TempDir(), "loose")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenJournal(dir); err == nil {
		t.Fatal("group/world-readable journal accepted")
	}
}

func TestOpenJournalAndBoundedIORejectIndirectOrOversizedPaths(t *testing.T) {
	t.Parallel()
	base := t.TempDir()
	file := filepath.Join(base, "file")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenJournal(file); err == nil {
		t.Fatal("file journal accepted")
	}
	link := filepath.Join(base, "link")
	if err := os.Symlink(base, link); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenJournal(link); err == nil {
		t.Fatal("symlink journal accepted")
	}
	if _, err := readBounded(filepath.Join(base, "missing"), 1); err == nil {
		t.Fatal("missing bounded file accepted")
	}
	if _, err := readBounded(base, 1); err == nil {
		t.Fatal("directory accepted as bounded file")
	}
	large := filepath.Join(base, "large")
	if err := os.WriteFile(large, []byte("ab"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readBounded(large, 1); err == nil {
		t.Fatal("oversized bounded file accepted")
	}
	if err := syncDirectory(filepath.Join(base, "missing")); err == nil {
		t.Fatal("missing directory synced")
	}
}

func TestJournalAppendRejectsGenerationIdentityAndInvalidEvidence(t *testing.T) {
	t.Parallel()
	journal := testJournal(t)
	zero := testEvent(StateClaimed, "claimed")
	zero.StateGeneration = 0
	if _, err := journal.Append(zero); err == nil {
		t.Fatal("zero generation accepted")
	}
	first, err := journal.Append(testEvent(StateClaimed, "claimed"))
	if err != nil {
		t.Fatal(err)
	}
	wrongGeneration := testEvent(StatePreflight, "preflight")
	wrongGeneration.StateGeneration = first.StateGeneration + 2
	if _, err := journal.Append(wrongGeneration); err == nil {
		t.Fatal("generation gap accepted")
	}
	for _, mutate := range []func(*Event){
		func(e *Event) { e.IntentID = "other" }, func(e *Event) { e.ReleaseID = "other" },
		func(e *Event) { e.ManifestDigest = strings.Repeat("b", 64) }, func(e *Event) { e.LeaseID = "22222222-2222-4222-8222-222222222222" },
		func(e *Event) { e.ExecutorID = "other" },
	} {
		event := testEvent(StatePreflight, "preflight")
		event.StateGeneration = first.StateGeneration + 1
		mutate(&event)
		if _, err := journal.Append(event); err == nil {
			t.Fatal("transaction identity drift accepted")
		}
	}
	invalid := testEvent(StatePreflight, "preflight")
	invalid.StateGeneration = first.StateGeneration + 1
	invalid.Evidence = json.RawMessage(`[]`)
	if _, err := journal.Append(invalid); err == nil {
		t.Fatal("non-object evidence accepted")
	}
	valid := testEvent(StatePreflight, "preflight")
	valid.StateGeneration = first.StateGeneration + 1
	valid.Evidence = nil
	if appended, err := journal.Append(valid); err != nil || string(appended.Evidence) != `{}` {
		t.Fatalf("default evidence=%s err=%v", appended.Evidence, err)
	}
}

func TestVerifyEventRejectsEveryEnvelopeBoundary(t *testing.T) {
	t.Parallel()
	journal := testJournal(t)
	valid, err := journal.Append(testEvent(StateClaimed, "claimed"))
	if err != nil {
		t.Fatal(err)
	}
	cases := []func(*Event){
		func(e *Event) { e.Version = 2 }, func(e *Event) { e.Sequence = 0 },
		func(e *Event) { e.IntentID = "/" }, func(e *Event) { e.ReleaseID = "/" },
		func(e *Event) { e.LeaseID = "bad" }, func(e *Event) { e.ManifestDigest = "bad" },
		func(e *Event) { e.State = "future" }, func(e *Event) { e.ExecutorID = "/" },
		func(e *Event) { e.StateGeneration = 0 }, func(e *Event) { e.StateGeneration = maxStateGeneration + 1 },
		func(e *Event) { e.Step = "/" }, func(e *Event) { e.OccurredAt = "bad" },
		func(e *Event) { e.Evidence = nil }, func(e *Event) { e.Evidence = json.RawMessage(`[]`) },
		func(e *Event) { e.Evidence = bytes.Repeat([]byte("x"), maxJournalRecord+1) },
		func(e *Event) { e.RecoverySetID = "11111111-1111-4111-8111-111111111111" },
		func(e *Event) { e.RecoverySetID, e.RecoverySetDigest = "bad", strings.Repeat("a", 64) },
		func(e *Event) { e.PreviousHash = "bad" }, func(e *Event) { e.Hash = "bad" },
		func(e *Event) { e.Hash = strings.Repeat("0", 64) },
	}
	for i, mutate := range cases {
		event := valid
		mutate(&event)
		if err := verifyEvent(event, event.PreviousHash, false); err == nil {
			t.Fatalf("invalid envelope %d accepted", i)
		}
	}
	if err := verifyEvent(valid, strings.Repeat("f", 64), true); !errors.Is(err, ErrJournalChecksum) {
		t.Fatalf("previous mismatch=%v", err)
	}
}

func TestJournalLoadRejectsMalformedSnapshotAndLogForms(t *testing.T) {
	t.Parallel()
	for name, write := range map[string]func(*Journal){
		"snapshot malformed": func(j *Journal) {
			_ = os.WriteFile(filepath.Join(j.dir, snapshotFileName), []byte(`{`), journalFileMode)
		},
		"snapshot oversized": func(j *Journal) {
			_ = os.WriteFile(filepath.Join(j.dir, snapshotFileName), bytes.Repeat([]byte("x"), maxJournalRecord+1), journalFileMode)
		},
		"log oversized": func(j *Journal) {
			_ = os.WriteFile(filepath.Join(j.dir, journalFileName), bytes.Repeat([]byte("x"), maxJournalBytes+1), journalFileMode)
		},
		"log empty record": func(j *Journal) {
			_ = os.WriteFile(filepath.Join(j.dir, journalFileName), []byte("\n"), journalFileMode)
		},
		"log invalid json": func(j *Journal) {
			_ = os.WriteFile(filepath.Join(j.dir, journalFileName), []byte("{\n"), journalFileMode)
		},
	} {
		t.Run(name, func(t *testing.T) {
			j := testJournal(t)
			write(j)
			if _, err := j.Load(); err == nil {
				t.Fatal("malformed journal accepted")
			}
		})
	}
	for name, replace := range map[string]func([]byte) []byte{
		"snapshot version": func(raw []byte) []byte { return bytes.Replace(raw, []byte(`"version":1`), []byte(`"version":2`), 1) },
		"snapshot event": func(raw []byte) []byte {
			return bytes.Replace(raw, []byte(`"state":"failed"`), []byte(`"state":"future"`), 1)
		},
	} {
		t.Run(name, func(t *testing.T) {
			j := testJournal(t)
			if _, err := j.Append(testEvent(StateFailed, "failed")); err != nil {
				t.Fatal(err)
			}
			if err := j.Compact(true); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(j.dir, snapshotFileName)
			raw, _ := os.ReadFile(path)
			if err := os.WriteFile(path, replace(raw), journalFileMode); err != nil {
				t.Fatal(err)
			}
			if _, err := j.Load(); err == nil {
				t.Fatal("tampered snapshot accepted")
			}
		})
	}
}

func TestJournalCompactionReportsFsyncAndDirectoryFailures(t *testing.T) {
	t.Parallel()
	for name, configure := range map[string]func(*Journal){
		"snapshot fsync":  func(j *Journal) { j.syncFile = func(*os.File) error { return errors.New("snapshot fsync") } },
		"directory fsync": func(j *Journal) { j.syncDir = func(string) error { return errors.New("directory fsync") } },
		"log fsync": func(j *Journal) {
			calls := 0
			j.syncFile = func(file *os.File) error {
				calls++
				if calls == 2 {
					return errors.New("log fsync")
				}
				return file.Sync()
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			j := testJournal(t)
			if _, err := j.Append(testEvent(StateFailed, "failed")); err != nil {
				t.Fatal(err)
			}
			configure(j)
			if err := j.Compact(true); err == nil {
				t.Fatal("compaction failure hidden")
			}
		})
	}
	missing := testJournal(t)
	if _, err := missing.Append(testEvent(StateClaimed, "claimed")); err != nil {
		t.Fatal(err)
	}
	missing.dir = filepath.Join(t.TempDir(), "missing")
	if _, err := missing.Append(testEvent(StatePreflight, "preflight")); err == nil {
		t.Fatal("missing journal directory accepted")
	}
}

func TestStrictJSONRejectsTrailingAndUnknownData(t *testing.T) {
	t.Parallel()
	var value struct {
		Value int `json:"value"`
	}
	if err := strictJSON([]byte(`{"value":1}`), &value); err != nil || value.Value != 1 {
		t.Fatalf("value=%d err=%v", value.Value, err)
	}
	for _, raw := range []string{`{`, `{"value":1,"unknown":2}`, `{"value":1} {"value":2}`} {
		if err := strictJSON([]byte(raw), &value); err == nil {
			t.Fatalf("invalid JSON %s accepted", raw)
		}
	}
}

func TestJournalLoadsCompactedLogReplayAndRejectsDivergentTip(t *testing.T) {
	build := func(t *testing.T, secondEvidence string) (*Journal, []byte) {
		t.Helper()
		journal := testJournal(t)
		first, err := journal.Append(testEvent(StateClaimed, "claimed"))
		if err != nil {
			t.Fatal(err)
		}
		second := testEvent(StateFailed, "failed")
		second.StateGeneration = first.StateGeneration + 1
		second.Evidence = json.RawMessage(secondEvidence)
		if _, err := journal.Append(second); err != nil {
			t.Fatal(err)
		}
		raw, err := os.ReadFile(filepath.Join(journal.dir, journalFileName))
		if err != nil {
			t.Fatal(err)
		}
		return journal, raw
	}

	journal, raw := build(t, `{"result":"one"}`)
	if err := journal.Compact(true); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(journal.dir, journalFileName), raw, journalFileMode); err != nil {
		t.Fatal(err)
	}
	state, err := journal.Load()
	if err != nil || !state.Reconciled || len(state.Events) != 1 {
		t.Fatalf("compacted replay state=%#v err=%v", state, err)
	}

	other, otherRaw := build(t, `{"result":"two"}`)
	_ = other
	if err := os.WriteFile(filepath.Join(journal.dir, journalFileName), otherRaw, journalFileMode); err != nil {
		t.Fatal(err)
	}
	if _, err := journal.Load(); !errors.Is(err, ErrJournalChecksum) {
		t.Fatalf("divergent compacted tip error=%v", err)
	}

	lines := bytes.Split(bytes.TrimSpace(raw), []byte("\n"))
	if len(lines) != 2 {
		t.Fatalf("log lines=%d", len(lines))
	}
	if err := os.WriteFile(filepath.Join(journal.dir, journalFileName), append(lines[1], '\n'), journalFileMode); err != nil {
		t.Fatal(err)
	}
	if _, err := journal.Load(); !errors.Is(err, ErrJournalSequence) {
		t.Fatalf("compacted sequence error=%v", err)
	}
}

func TestJournalRejectsGenerationDriftAndPropagatesInternalFailures(t *testing.T) {
	journal := testJournal(t)
	first, err := journal.Append(testEvent(StateClaimed, "claimed"))
	if err != nil {
		t.Fatal(err)
	}
	second := testEvent(StatePreflight, "preflight")
	second.Version = JournalVersion
	second.Sequence = first.Sequence + 1
	second.StateGeneration = first.StateGeneration + 2
	second.PreviousHash = first.Hash
	second.OccurredAt = time.Date(2026, 8, 1, 0, 0, 1, 0, time.UTC).Format(time.RFC3339)
	second.Hash, err = eventHash(second)
	if err != nil {
		t.Fatal(err)
	}
	line, err := json.Marshal(second)
	if err != nil {
		t.Fatal(err)
	}
	file, err := os.OpenFile(filepath.Join(journal.dir, journalFileName), os.O_APPEND|os.O_WRONLY, journalFileMode)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write(append(line, '\n')); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := journal.Load(); !errors.Is(err, ErrJournalSequence) {
		t.Fatalf("generation drift error=%v", err)
	}
	if _, err := journal.Append(testEvent(StatePreflight, "another")); !errors.Is(err, ErrJournalSequence) {
		t.Fatalf("append load error=%v", err)
	}
	if err := journal.Compact(true); !errors.Is(err, ErrJournalSequence) {
		t.Fatalf("compact load error=%v", err)
	}
	invalid := testEvent(StateClaimed, "claimed")
	invalid.Version, invalid.Sequence, invalid.OccurredAt = JournalVersion, 1, time.Now().UTC().Format(time.RFC3339)
	invalid.Evidence = json.RawMessage(`{`)
	if _, err := eventHash(invalid); err == nil {
		t.Fatal("invalid JSON checksum payload encoded")
	}
	missing := testJournal(t)
	missing.dir = filepath.Join(t.TempDir(), "missing")
	if err := missing.atomicWrite(snapshotFileName, []byte("{}\n")); err == nil {
		t.Fatal("snapshot written in missing directory")
	}
}
