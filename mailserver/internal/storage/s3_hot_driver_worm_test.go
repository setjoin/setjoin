package storage

import (
	"context"
	"encoding/xml"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

// TestS3HotDriverPutObjectRetentionUppercasesMode is the B1 regression test:
// minio-go's RetentionMode is only valid as "GOVERNANCE"/"COMPLIANCE"
// (api-object-lock.go RetentionMode.IsValid()). The driver's domain
// vocabulary is lowercase ("governance"/"compliance", per worm.go's
// validWORMModes). Passing the lowercase value straight through makes
// minio-go reject it client-side in newObjectRetention() before any I/O —
// PutObjectRetention becomes a silent no-op and the compliance-vault
// Object-Lock never applies. The driver must map to uppercase at the
// boundary.
func TestS3HotDriverPutObjectRetentionUppercasesMode(t *testing.T) {
	var gotMode string
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := r.URL.Query()["retention"]; ok {
			gotPath = r.URL.Path
			body := struct {
				XMLName xml.Name `xml:"Retention"`
				Mode    string   `xml:"Mode"`
			}{}
			_ = xml.NewDecoder(r.Body).Decode(&body)
			gotMode = body.Mode
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	host := strings.TrimPrefix(srv.URL, "http://")
	client, err := minio.New(host, &minio.Options{
		Creds:  credentials.NewStaticV4("k", "s", ""),
		Secure: false,
		Region: "us-east-1", // avoid a GetBucketLocation round-trip against the stub
	})
	if err != nil {
		t.Fatalf("minio.New: %v", err)
	}
	d := &s3HotDriver{client: client, bucket: "test-bucket"}

	err = d.PutObjectRetention(context.Background(), "test-key", "governance", time.Now().Add(24*time.Hour))
	if err != nil {
		t.Fatalf("PutObjectRetention returned an error — the lowercase domain mode never reached minio-go as a valid retention mode: %v", err)
	}

	wantPath := "/test-bucket/test-key"
	if u, uerr := url.PathUnescape(gotPath); uerr == nil {
		gotPath = u
	}
	if gotPath != wantPath {
		t.Fatalf("stub never received the retention request (path=%q) — PutObjectRetention rejected the mode client-side", gotPath)
	}
	if gotMode != "GOVERNANCE" {
		t.Errorf("mode reaching minio = %q, want uppercase %q", gotMode, "GOVERNANCE")
	}
}

// TestS3HotDriverEnsureBucketObjectLockUppercasesMode covers the sibling
// write path (bucket-level default retention): the same lowercase-vs-
// minio-go-uppercase mismatch as PutObjectRetention, at the B1 boundary.
func TestS3HotDriverEnsureBucketObjectLockUppercasesMode(t *testing.T) {
	var gotMode string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := r.URL.Query()["object-lock"]; ok {
			body := struct {
				XMLName xml.Name `xml:"ObjectLockConfiguration"`
				Rule    struct {
					DefaultRetention struct {
						Mode string `xml:"Mode"`
					} `xml:"DefaultRetention"`
				} `xml:"Rule"`
			}{}
			_ = xml.NewDecoder(r.Body).Decode(&body)
			gotMode = body.Rule.DefaultRetention.Mode
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	host := strings.TrimPrefix(srv.URL, "http://")
	client, err := minio.New(host, &minio.Options{
		Creds:  credentials.NewStaticV4("k", "s", ""),
		Secure: false,
		Region: "us-east-1",
	})
	if err != nil {
		t.Fatalf("minio.New: %v", err)
	}
	d := &s3HotDriver{client: client, bucket: "test-bucket"}

	if err := d.EnsureBucketObjectLock(context.Background(), "compliance", 2557); err != nil {
		t.Fatalf("EnsureBucketObjectLock returned an error — the lowercase domain mode never reached minio-go as a valid retention mode: %v", err)
	}
	if gotMode != "COMPLIANCE" {
		t.Errorf("mode reaching minio = %q, want uppercase %q", gotMode, "COMPLIANCE")
	}
}

// TestS3HotDriverEnsureBucketObjectLockPassesValidityUnit is a bug found
// while verifying B1: EnsureBucketObjectLock always passes a nil
// ValidityUnit to minio-go's SetObjectLockConfig. minio-go's
// newObjectLockConfig requires mode, validity, AND unit to be all-nil or
// all-set (api-object-lock.go) — with unit always nil but mode/validity
// set, every call falls through to "all of retention mode, validity and
// validity unit must be passed", so the bucket-level Object Lock default
// can never be configured at startup (internal/startup/worm.go calls this
// unconditionally when an S3 WORM mode is configured). Uses an
// already-uppercase mode so this test isolates the unit bug from the B1
// mode-casing bug (fixed separately).
func TestS3HotDriverEnsureBucketObjectLockPassesValidityUnit(t *testing.T) {
	var gotMode string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := r.URL.Query()["object-lock"]; ok {
			body := struct {
				XMLName xml.Name `xml:"ObjectLockConfiguration"`
				Rule    struct {
					DefaultRetention struct {
						Mode string `xml:"Mode"`
					} `xml:"DefaultRetention"`
				} `xml:"Rule"`
			}{}
			_ = xml.NewDecoder(r.Body).Decode(&body)
			gotMode = body.Rule.DefaultRetention.Mode
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	host := strings.TrimPrefix(srv.URL, "http://")
	client, err := minio.New(host, &minio.Options{
		Creds:  credentials.NewStaticV4("k", "s", ""),
		Secure: false,
		Region: "us-east-1", // avoid a GetBucketLocation round-trip against the stub
	})
	if err != nil {
		t.Fatalf("minio.New: %v", err)
	}
	d := &s3HotDriver{client: client, bucket: "test-bucket"}

	if err := d.EnsureBucketObjectLock(context.Background(), "COMPLIANCE", 2557); err != nil {
		t.Fatalf("EnsureBucketObjectLock returned an error — the nil ValidityUnit made minio-go reject mode+validity as incomplete: %v", err)
	}
	if gotMode != "COMPLIANCE" {
		t.Errorf("mode reaching minio = %q, want %q", gotMode, "COMPLIANCE")
	}
}
