//go:build gofree_record

package threat

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"github.com/jackc/pgx/v5/pgxpool"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type authrtTransport struct {
	url      string
	requests *[]string
}

func (r authrtTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	*r.requests = append(*r.requests, req.Method+" "+req.URL.String())
	req = req.Clone(req.Context())
	u, _ := http.NewRequest(req.Method, r.url, nil)
	req.URL = u.URL
	return http.DefaultTransport.RoundTrip(req)
}
func TestRecordAuthRuntimeFeed(t *testing.T) {
	dir := os.Getenv("AUTHRT_ORACLE_DIR")
	if dir == "" {
		t.Fatal("AUTHRT_ORACLE_DIR required")
	}
	path := filepath.Join(dir, "feed-go.json")
	if _, e := os.Stat(path); e == nil {
		t.Fatal("refuse overwrite")
	}
	ctx := context.Background()
	db, e := pgxpool.New(ctx, os.Getenv("TEST_DB_DSN"))
	if e != nil {
		t.Fatal(e)
	}
	defer db.Close()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	requests := []string{}
	body := "; comment\n198.51.100.0/24 ; SBL1\n2001:db8::/32 other\n198.51.100.0/24 ; duplicate\nnot-a-cidr\n"
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, body) }))
	defer peer.Close()
	old := feedHTTPClient
	feedHTTPClient = &http.Client{Timeout: time.Second, Transport: authrtTransport{peer.URL, &requests}}
	defer func() { feedHTTPClient = old }()
	// This recorder owns the complete threat table of the assigned disposable DB.
	_, e = db.Exec(ctx, "DELETE FROM threat_feed_blocks")
	if e != nil {
		t.Fatal(e)
	}
	defer db.Exec(ctx, "DELETE FROM threat_feed_blocks")
	snapshots := [][]string{}
	for _, text := range []string{body, "; empty feed leaves previous snapshot\n"} {
		body = text
		if e = refreshOnce(ctx, db, logger); e != nil {
			t.Fatal(e)
		}
		rows, e := db.Query(ctx, "SELECT cidr::text||'|'||source FROM threat_feed_blocks ORDER BY cidr::text")
		if e != nil {
			t.Fatal(e)
		}
		out := []string{}
		for rows.Next() {
			var s string
			if e = rows.Scan(&s); e != nil {
				t.Fatal(e)
			}
			out = append(out, s)
		}
		rows.Close()
		snapshots = append(snapshots, out)
	}
	out := map[string]any{"requests": requests, "snapshots": snapshots}
	b, _ := json.MarshalIndent(out, "", "  ")
	if e = os.WriteFile(path, append(b, '\n'), 0644); e != nil {
		t.Fatal(e)
	}
}

// A normal Go transport requests/decompresses gzip and sends its standard UA.
func TestRecordAuthRuntimeFeedTransport(t *testing.T) {
	dir := os.Getenv("AUTHRT_ORACLE_DIR")
	if dir == "" {
		t.Fatal("AUTHRT_ORACLE_DIR required")
	}
	path := filepath.Join(dir, "feed-transport-go.json")
	if _, e := os.Stat(path); e == nil {
		t.Fatal("refuse overwrite")
	}
	ctx := context.Background()
	db, e := pgxpool.New(ctx, os.Getenv("TEST_DB_DSN"))
	if e != nil {
		t.Fatal(e)
	}
	defer db.Close()
	facts := make(chan map[string]any, 1)
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		facts <- map[string]any{"request_line": r.Method + " " + r.URL.Path, "user_agent": r.UserAgent(), "accept_encoding": r.Header.Get("Accept-Encoding")}
		w.Header().Set("Content-Encoding", "gzip")
		z := gzip.NewWriter(w)
		fmt.Fprint(z, "198.51.100.0/24 ; SBL1\n")
		z.Close()
	}))
	defer peer.Close()
	old := feedHTTPClient
	requests := []string{}
	feedHTTPClient = &http.Client{Timeout: time.Second, Transport: authrtTransport{peer.URL + "/drop/drop.txt", &requests}}
	defer func() { feedHTTPClient = old }()
	if _, e = db.Exec(ctx, "DELETE FROM threat_feed_blocks"); e != nil {
		t.Fatal(e)
	}
	defer db.Exec(ctx, "DELETE FROM threat_feed_blocks")
	if e = refreshOnce(ctx, db, slog.New(slog.NewTextHandler(io.Discard, nil))); e != nil {
		t.Fatal(e)
	}
	rows, e := db.Query(ctx, "SELECT cidr::text||'|'||source FROM threat_feed_blocks ORDER BY cidr::text")
	if e != nil {
		t.Fatal(e)
	}
	blocks := []string{}
	for rows.Next() {
		var s string
		rows.Scan(&s)
		blocks = append(blocks, s)
	}
	rows.Close()
	out := <-facts
	out["blocks"] = blocks
	b, _ := json.MarshalIndent(out, "", "  ")
	if e = os.WriteFile(path, append(b, '\n'), 0644); e != nil {
		t.Fatal(e)
	}
}
