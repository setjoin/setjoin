package admin

import (
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

type failingMailboxImportReader struct{}

func (failingMailboxImportReader) Read([]byte) (int, error) { return 0, errors.New("read failed") }

type erroringReadCloser struct{ err error }

func (r erroringReadCloser) Read([]byte) (int, error) { return 0, r.err }
func (r erroringReadCloser) Close() error             { return nil }

func zipBytesForTest(t *testing.T, entries map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, body := range entries {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func zipFilesForTest(t *testing.T, entries map[string]string) []*zip.File {
	t.Helper()
	raw := zipBytesForTest(t, entries)
	zr, err := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		t.Fatal(err)
	}
	return zr.File
}

func TestImportZIPStagesValidatesAndSkipsNonMessages(t *testing.T) {
	raw := zipBytesForTest(t, map[string]string{"readme.txt": "not a message"})
	h := &ImportExportHandler{}
	imported, failed := h.importZIP(context.Background(), 1, nil, bytes.NewReader(raw))
	if imported != 0 || len(failed) != 0 {
		t.Fatalf("imported=%d failed=%v", imported, failed)
	}
}

func TestImportZIPHonorsCancellationBeforeEntryWork(t *testing.T) {
	raw := zipBytesForTest(t, map[string]string{"one.eml": "Subject: one\r\n\r\nbody"})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	h := &ImportExportHandler{}
	imported, failed := h.importZIP(ctx, 1, nil, bytes.NewReader(raw))
	if imported != 0 || len(failed) != 1 || failed[0]["error"] != "Import cancelled before completion." {
		t.Fatalf("imported=%d failed=%v", imported, failed)
	}
}

func TestImportZIPRejectsMalformedArchive(t *testing.T) {
	h := &ImportExportHandler{}
	imported, failed := h.importZIP(context.Background(), 1, nil, strings.NewReader("not-a-zip"))
	if imported != 0 || len(failed) != 1 || failed[0]["error"] != "Invalid ZIP file. The file may be corrupted." {
		t.Fatalf("imported=%d failed=%v", imported, failed)
	}
}

func TestImportZIPReportsStagingFailures(t *testing.T) {
	originalCreate := createMailboxImportTemp
	originalChmod := chmodMailboxImportTemp
	originalSync := syncMailboxImportTemp
	t.Cleanup(func() {
		createMailboxImportTemp = originalCreate
		chmodMailboxImportTemp = originalChmod
		syncMailboxImportTemp = originalSync
	})
	h := &ImportExportHandler{}
	createMailboxImportTemp = func(string, string) (*os.File, error) { return nil, errors.New("create failed") }
	if _, failed := h.importZIP(context.Background(), 1, nil, strings.NewReader("x")); len(failed) != 1 || failed[0]["error"] != "Failed to stage the import file." {
		t.Fatalf("create failure = %v", failed)
	}
	createMailboxImportTemp = originalCreate
	chmodMailboxImportTemp = func(*os.File) error { return errors.New("chmod failed") }
	if _, failed := h.importZIP(context.Background(), 1, nil, strings.NewReader("x")); len(failed) != 1 || failed[0]["error"] != "Failed to stage the import file." {
		t.Fatalf("chmod failure = %v", failed)
	}
	chmodMailboxImportTemp = originalChmod
	if _, failed := h.importZIP(context.Background(), 1, nil, failingMailboxImportReader{}); len(failed) != 1 || failed[0]["error"] != "ZIP file exceeds the safe import limits." {
		t.Fatalf("copy failure = %v", failed)
	}
	syncMailboxImportTemp = func(*os.File) error { return errors.New("sync failed") }
	if _, failed := h.importZIP(context.Background(), 1, nil, strings.NewReader("x")); len(failed) != 1 || failed[0]["error"] != "Failed to stage the import file." {
		t.Fatalf("sync failure = %v", failed)
	}
}

func TestImportZIPRejectsArchiveDuringIntegratedValidation(t *testing.T) {
	raw := zipBytesForTest(t, map[string]string{"bomb.eml": strings.Repeat("A", 1<<20)})
	h := &ImportExportHandler{logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	if _, failed := h.importZIP(context.Background(), 1, nil, bytes.NewReader(raw)); len(failed) != 1 || failed[0]["error"] != "ZIP file exceeds the safe import limits." {
		t.Fatalf("integrated validation failure = %v", failed)
	}
}

func TestReadMailboxZIPEntryRejectsRuntimeExpansionAndReadFailure(t *testing.T) {
	raw, err := readMailboxZIPEntry(io.NopCloser(strings.NewReader("four")), 3)
	if err == nil || string(raw) != "four" {
		t.Fatalf("runtime expansion raw=%q err=%v", raw, err)
	}
	if _, err := readMailboxZIPEntry(erroringReadCloser{err: errors.New("read failed")}, 3); err == nil {
		t.Fatal("entry read failure ignored")
	}
}

func TestImportZIPReadsEMLEntryAndReportsStorageFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
	}))
	t.Cleanup(server.Close)
	client, err := minio.New(strings.TrimPrefix(server.URL, "http://"), &minio.Options{
		Creds: credentials.NewStaticV4("test", "test-secret", ""), Region: "us-east-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	raw := zipBytesForTest(t, map[string]string{"one.eml": "Subject: one\r\nFrom: a@example.test\r\n\r\nbody"})
	h := &ImportExportHandler{minio: client, bucket: "mail", logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	imported, failed := h.importZIP(context.Background(), 1, nil, bytes.NewReader(raw))
	if imported != 0 || len(failed) != 1 || failed[0]["file"] != "one.eml" {
		t.Fatalf("imported=%d failed=%v", imported, failed)
	}
}

func TestValidateMailboxZIPAcceptsOrdinaryArchive(t *testing.T) {
	files := zipFilesForTest(t, map[string]string{"one.eml": "Subject: one\r\n\r\nbody"})
	if err := validateMailboxZIP(files); err != nil {
		t.Fatalf("ordinary archive rejected: %v", err)
	}
}

func TestValidateMailboxZIPRejectsHighExpansionRatio(t *testing.T) {
	files := zipFilesForTest(t, map[string]string{"bomb.eml": strings.Repeat("A", 1<<20)})
	if err := validateMailboxZIP(files); err == nil {
		t.Fatal("high-ratio archive accepted")
	}
}

func TestValidateMailboxZIPRejectsEntryCount(t *testing.T) {
	files := make([]*zip.File, mailboxZIPMaxEntries+1)
	for i := range files {
		files[i] = &zip.File{}
	}
	if err := validateMailboxZIP(files); err == nil {
		t.Fatal("over-entry-count archive accepted")
	}
}

func TestValidateMailboxZIPRejectsDeclaredEntryAndTotalSizes(t *testing.T) {
	tooLarge := &zip.File{FileHeader: zip.FileHeader{Name: "large.eml", UncompressedSize64: uint64(mailboxZIPMaxEntryBytes + 1), CompressedSize64: uint64(mailboxZIPMaxEntryBytes + 1)}}
	if err := validateMailboxZIP([]*zip.File{tooLarge}); err == nil {
		t.Fatal("oversized declared entry accepted")
	}
	partSize := uint64(mailboxZIPMaxEntryBytes)
	parts := make([]*zip.File, mailboxZIPMaxExpandedBytes/mailboxZIPMaxEntryBytes+1)
	for i := range parts {
		parts[i] = &zip.File{FileHeader: zip.FileHeader{Name: fmt.Sprintf("%d.eml", i), UncompressedSize64: partSize, CompressedSize64: partSize}}
	}
	if err := validateMailboxZIP(parts); err == nil {
		t.Fatal("oversized declared archive accepted")
	}
}
