package admin

import (
	"errors"
	"testing"
	"time"
)

type migrationReadCursor struct {
	next        int
	count       int
	scanErrorAt int
	scanError   error
	finalError  error
}

func (r *migrationReadCursor) Next() bool { r.next++; return r.next <= r.count }
func (r *migrationReadCursor) Err() error { return r.finalError }
func (r *migrationReadCursor) Scan(dest ...any) error {
	*dest[0].(*int64) = int64(r.next)
	if r.next == r.scanErrorAt {
		return r.scanError
	}
	*dest[1].(*string) = "s3"
	*dest[2].(*string) = "posix"
	*dest[3].(*string) = "completed"
	*dest[4].(*int64) = 4
	*dest[5].(*int64) = 1
	*dest[6].(*any) = time.Unix(1, 0)
	*dest[7].(*any) = time.Unix(2, 0)
	return nil
}

func TestReadStorageMigrationRowsRefusesPartialData(t *testing.T) {
	marker := errors.New("private database failure")
	for _, tc := range []struct {
		name   string
		cursor migrationReadCursor
	}{
		{"partial row", migrationReadCursor{count: 2, scanErrorAt: 2, scanError: marker}},
		{"after rows", migrationReadCursor{count: 2, finalError: marker}},
		{"before rows", migrationReadCursor{finalError: marker}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result, err := readStorageMigrationRows(&tc.cursor)
			if !errors.Is(err, marker) || result != nil {
				t.Fatalf("partial result escaped: %v %v", result, err)
			}
		})
	}
	result, err := readStorageMigrationRows(&migrationReadCursor{count: 2})
	if err != nil || len(result) != 2 || result[1]["id"] != int64(2) || result[1]["progress_pct"] != float64(25) || result[1]["completed"] == nil {
		t.Fatalf("complete projection: %v %v", result, err)
	}
	empty, err := readStorageMigrationRows(&migrationReadCursor{})
	if err != nil || empty == nil || len(empty) != 0 {
		t.Fatalf("empty projection must remain []: %v %v", empty, err)
	}
}
