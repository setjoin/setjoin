package backup

import (
	"fmt"
	"testing"
)

// fakeRows is a fake rowScanner for exercising the scan helpers' error handling
// without a live cursor — the cursor-error path (rows.Err()) is otherwise
// untestable, which is exactly how the silent-truncation bug slipped in.
type fakeRows struct {
	rows      [][]any
	idx       int
	scanErrAt int   // return a Scan error at this 0-based row index (-1 = never)
	errResult error // what Err() returns after iteration
}

func (f *fakeRows) Next() bool { f.idx++; return f.idx <= len(f.rows) }

func (f *fakeRows) Scan(dest ...any) error {
	i := f.idx - 1
	if i == f.scanErrAt {
		return fmt.Errorf("scan boom at row %d", i)
	}
	row := f.rows[i]
	for j, d := range dest {
		switch p := d.(type) {
		case *string:
			*p = row[j].(string)
		case *int64:
			*p = row[j].(int64)
		case *bool:
			*p = row[j].(bool)
		}
	}
	return nil
}

func (f *fakeRows) Err() error { return f.errResult }

func TestScanBlobRefs_ReturnsAllRows(t *testing.T) {
	rows := &fakeRows{rows: [][]any{{"h1", int64(10)}, {"h2", int64(20)}}, scanErrAt: -1}
	got, err := scanBlobRefs(rows)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 2 || got[0].Hash != "h1" || got[1].Size != 20 {
		t.Errorf("got %+v, want [{h1 10} {h2 20}]", got)
	}
}

// TestScanBlobRefs_ScanErrorIsFatal: a per-row Scan failure must abort the whole
// snapshot (return error), NOT silently drop that blob — a dropped blob is
// undetectable data loss in a DR backup.
func TestScanBlobRefs_ScanErrorIsFatal(t *testing.T) {
	rows := &fakeRows{rows: [][]any{{"h1", int64(10)}, {"h2", int64(20)}}, scanErrAt: 1}
	if _, err := scanBlobRefs(rows); err == nil {
		t.Fatal("a Scan error must be fatal to the snapshot, not silently skipped")
	}
}

// TestScanBlobRefs_CursorErrorIsFatal: a mid-iteration cursor error (rows.Err())
// must surface — without this check a truncated read looks like a clean finish.
func TestScanBlobRefs_CursorErrorIsFatal(t *testing.T) {
	rows := &fakeRows{rows: [][]any{{"h1", int64(10)}}, scanErrAt: -1, errResult: fmt.Errorf("connection reset")}
	if _, err := scanBlobRefs(rows); err == nil {
		t.Fatal("a cursor error (rows.Err()) must be returned, not swallowed")
	}
}

func TestScanConfigEntries_CursorErrorIsFatal(t *testing.T) {
	rows := &fakeRows{rows: [][]any{{"k1", "v1", false}}, scanErrAt: -1, errResult: fmt.Errorf("connection reset")}
	if _, err := scanConfigEntries(rows); err == nil {
		t.Fatal("a cursor error in config export must be returned, not swallowed")
	}
}

// TestScanConfigEntries_CarriesEncrypted: the export must capture the encrypted
// flag (dropping it corrupts encrypted DR credentials on restore).
func TestScanConfigEntries_CarriesEncrypted(t *testing.T) {
	rows := &fakeRows{rows: [][]any{{"plain", "v", false}, {"secret", `{"_enc":"x"}`, true}}, scanErrAt: -1}
	got, err := scanConfigEntries(rows)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !got["secret"].Encrypted {
		t.Error("encrypted flag for 'secret' must survive the export")
	}
	if got["plain"].Encrypted {
		t.Error("'plain' should be encrypted=false")
	}
	if got["secret"].Value != `{"_enc":"x"}` {
		t.Errorf("value = %q", got["secret"].Value)
	}
}
