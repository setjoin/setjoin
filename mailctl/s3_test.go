package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestUploadAndDownloadFileRoundTripAgainstS3ProtocolFixture(t *testing.T) {
	objects := map[string][]byte{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := strings.TrimPrefix(r.URL.Path, "/bucket/")
		switch r.Method {
		case http.MethodHead:
			if r.URL.Path == "/bucket/" || r.URL.Path == "/bucket" {
				w.WriteHeader(http.StatusOK)
				return
			}
			raw, ok := objects[key]
			if !ok {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("Content-Length", strconv.Itoa(len(raw)))
			w.Header().Set("ETag", `"fixture-etag"`)
			w.Header().Set("Last-Modified", "Sat, 01 Aug 2026 00:00:00 GMT")
			w.WriteHeader(http.StatusOK)
		case http.MethodPut:
			raw, err := io.ReadAll(r.Body)
			if err != nil {
				t.Fatal(err)
			}
			if r.Header.Get("Content-Encoding") == "aws-chunked" || bytes.Contains(raw, []byte(";chunk-signature=")) {
				raw, err = decodeAWSChunkedFixture(raw)
				if err != nil {
					http.Error(w, err.Error(), http.StatusBadRequest)
					return
				}
			}
			objects[key] = raw
			w.Header().Set("ETag", `"fixture-etag"`)
			w.WriteHeader(http.StatusOK)
		case http.MethodGet:
			if _, ok := r.URL.Query()["location"]; ok {
				w.Header().Set("Content-Type", "application/xml")
				_, _ = io.WriteString(w, `<LocationConstraint xmlns="http://s3.amazonaws.com/doc/2006-03-01/"></LocationConstraint>`)
				return
			}
			raw, ok := objects[key]
			if !ok {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("Content-Length", strconv.Itoa(len(raw)))
			w.Header().Set("Last-Modified", "Sat, 01 Aug 2026 00:00:00 GMT")
			_, _ = w.Write(raw)
		default:
			http.Error(w, "unsupported", http.StatusMethodNotAllowed)
		}
	}))
	defer server.Close()
	config := s3Config{Endpoint: server.URL, Bucket: "bucket", AccessKey: "access", SecretKey: "secret"}
	source := filepath.Join(t.TempDir(), "source")
	if err := os.WriteFile(source, []byte("payload"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := uploadFile(context.Background(), config, source, "db.dump"); err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(t.TempDir(), "destination")
	if err := os.WriteFile(destination, []byte("old-longer-payload"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := downloadFile(context.Background(), config, "db.dump", destination); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(destination)
	if err != nil || string(raw) != "payload" {
		t.Fatalf("raw=%q err=%v", raw, err)
	}
}

func decodeAWSChunkedFixture(raw []byte) ([]byte, error) {
	var decoded bytes.Buffer
	for len(raw) > 0 {
		lineEnd := bytes.Index(raw, []byte("\r\n"))
		if lineEnd < 0 {
			return nil, fmt.Errorf("missing chunk header terminator")
		}
		header := raw[:lineEnd]
		if semi := bytes.IndexByte(header, ';'); semi >= 0 {
			header = header[:semi]
		}
		size, err := strconv.ParseUint(string(header), 16, 64)
		if err != nil {
			return nil, fmt.Errorf("parse chunk size: %w", err)
		}
		raw = raw[lineEnd+2:]
		if size == 0 {
			return decoded.Bytes(), nil
		}
		if uint64(len(raw)) < size+2 || !bytes.Equal(raw[size:size+2], []byte("\r\n")) {
			return nil, fmt.Errorf("truncated signed chunk")
		}
		_, _ = decoded.Write(raw[:size])
		raw = raw[size+2:]
	}
	return nil, fmt.Errorf("missing final chunk")
}

func TestS3FileHelpersRejectInvalidEndpointAndLocalPaths(t *testing.T) {
	invalid := s3Config{Endpoint: "://bad", Bucket: "bucket", AccessKey: "access", SecretKey: "secret"}
	if err := uploadFile(context.Background(), invalid, "/missing", "key"); err == nil {
		t.Fatal("invalid upload endpoint accepted")
	}
	if err := downloadFile(context.Background(), invalid, "key", "/missing"); err == nil {
		t.Fatal("invalid download endpoint accepted")
	}
	valid := s3Config{Endpoint: "http://127.0.0.1:1", Bucket: "bucket", AccessKey: "access", SecretKey: "secret"}
	if err := uploadFile(context.Background(), valid, filepath.Join(t.TempDir(), "missing"), "key"); err == nil {
		t.Fatal("missing upload input accepted")
	}
}

func TestDownloadFileRejectsTruncatedRemoteObject(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Has("location") {
			w.Header().Set("Content-Type", "application/xml")
			_, _ = io.WriteString(w, `<LocationConstraint xmlns="http://s3.amazonaws.com/doc/2006-03-01/"></LocationConstraint>`)
			return
		}
		w.Header().Set("Content-Length", "100")
		w.Header().Set("Last-Modified", "Sat, 01 Aug 2026 00:00:00 GMT")
		_, _ = io.WriteString(w, "short")
	}))
	defer server.Close()
	destination := filepath.Join(t.TempDir(), "destination")
	if err := os.WriteFile(destination, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	config := s3Config{Endpoint: server.URL, Bucket: "bucket", AccessKey: "access", SecretKey: "secret"}
	if err := downloadFile(context.Background(), config, "truncated", destination); err == nil {
		t.Fatal("truncated remote object accepted")
	}
}
