package health

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestHealthRowJSON(t *testing.T) {
	v := 42.0
	th := 100.0
	row := Row{
		CheckName: "db_ping",
		Status:    "ok",
		Value:     &v,
		Threshold: &th,
		Details:   "reachable",
		CheckedAt: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
	}
	b, err := json.Marshal(row)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}
	var parsed map[string]any
	if err := json.Unmarshal(b, &parsed); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if parsed["check_name"] != "db_ping" {
		t.Errorf("check_name = %v, want db_ping", parsed["check_name"])
	}
	if parsed["status"] != "ok" {
		t.Errorf("status = %v, want ok", parsed["status"])
	}
	if parsed["details"] != "reachable" {
		t.Errorf("details = %v, want reachable", parsed["details"])
	}
}

func TestHealthRowNullValue(t *testing.T) {
	row := Row{
		CheckName: "minio_connectivity",
		Status:    "error",
		Value:     nil,
		Threshold: nil,
		Details:   "connection refused",
		CheckedAt: time.Now(),
	}
	b, err := json.Marshal(row)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}
	var parsed map[string]any
	if err := json.Unmarshal(b, &parsed); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if _, ok := parsed["value"]; ok {
		t.Error("null value should be omitted from JSON")
	}
}

// TestRegisterProbe pins the three RegisterProbe/probeRows contracts a live
// component check (Meet B1's SFU leg) depends on: a skipped probe (e.g. the
// owning feature toggled off) produces NO row, a healthy probe produces an
// "ok" row, and a failing probe produces an "error" row carrying the error
// text — all without a DB pool, since probeRows never touches h.pool.
func TestRegisterProbe(t *testing.T) {
	h := &Handler{prevStatus: make(map[string]string)}
	h.RegisterProbe("skipped", func(context.Context) (bool, error) { return true, nil })
	h.RegisterProbe("ok", func(context.Context) (bool, error) { return false, nil })
	h.RegisterProbe("down", func(context.Context) (bool, error) { return false, errors.New("dial tcp: refused") })

	rows := h.probeRows(context.Background())
	if len(rows) != 2 {
		t.Fatalf("want 2 rows (skipped omitted), got %d: %+v", len(rows), rows)
	}
	byName := map[string]Row{}
	for _, r := range rows {
		byName[r.CheckName] = r
	}
	if _, ok := byName["skipped"]; ok {
		t.Error("skipped probe produced a row, want it omitted entirely")
	}
	if got := byName["ok"].Status; got != "ok" {
		t.Errorf("ok probe status = %q, want ok", got)
	}
	if got := byName["down"].Status; got != "error" {
		t.Errorf("down probe status = %q, want error", got)
	}
	if got := byName["down"].Details; got != "dial tcp: refused" {
		t.Errorf("down probe details = %q, want the error text", got)
	}
}

func TestHealthOverallPriority(t *testing.T) {
	cases := []struct {
		statuses []string
		want     string
	}{
		{[]string{"ok", "ok"}, "ok"},
		{[]string{"ok", "warn"}, "warn"},
		{[]string{"warn", "ok"}, "warn"},
		{[]string{"ok", "error"}, "error"},
		{[]string{"error", "warn"}, "error"},
		{[]string{"warn", "error"}, "error"},
		{[]string{}, "ok"},
	}
	for _, tc := range cases {
		overall := "ok"
		for _, s := range tc.statuses {
			if s == "error" {
				overall = "error"
			} else if s == "warn" && overall != "error" {
				overall = "warn"
			}
		}
		if overall != tc.want {
			t.Errorf("statuses=%v got=%q want=%q", tc.statuses, overall, tc.want)
		}
	}
}

func TestWritePublicHealthResponseRedactsDetails(t *testing.T) {
	rr := httptest.NewRecorder()
	writePublicHealthResponse(rr, http.StatusServiceUnavailable, []byte(`{
		"status":"error",
		"checks":[{"check_name":"database_size_gb","details":"internal endpoint","value":42}]
	}`))
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d want %d", rr.Code, http.StatusServiceUnavailable)
	}
	if got := rr.Body.String(); got != "{\"status\":\"error\"}\n" {
		t.Fatalf("public health body=%q, want aggregate status only", got)
	}
	if strings.Contains(rr.Body.String(), "database") || strings.Contains(rr.Body.String(), "checks") {
		t.Fatal("public health response leaked detailed check data")
	}
}

func TestWritePublicHealthResponseFailsClosedOnMalformedDetail(t *testing.T) {
	rr := httptest.NewRecorder()
	writePublicHealthResponse(rr, http.StatusOK, []byte(`not-json`))
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d want %d", rr.Code, http.StatusInternalServerError)
	}
}

func TestCapturedResponseImplementsStatusHeaderAndBody(t *testing.T) {
	captured := newCapturedResponse()
	captured.Header().Set("X-Test", "yes")
	captured.WriteHeader(http.StatusTeapot)
	if _, err := captured.Write([]byte("body")); err != nil {
		t.Fatal(err)
	}
	if captured.status != http.StatusTeapot || captured.header.Get("X-Test") != "yes" || captured.body.String() != "body" {
		t.Fatalf("captured response = status:%d header:%v body:%q", captured.status, captured.header, captured.body.String())
	}
}

func TestPublicCheckFailsClosedWhenDetailedCheckCannotRun(t *testing.T) {
	pool, err := pgxpool.New(context.Background(), "postgres://127.0.0.1:1/missing?connect_timeout=1")
	if err != nil {
		t.Fatal(err)
	}
	pool.Close()
	h := NewHandler(pool, slog.Default(), nil)
	rec := httptest.NewRecorder()
	h.PublicCheck(rec, httptest.NewRequest(http.MethodGet, "/health", nil))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%q, want fail-closed 500", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "health_history") {
		t.Fatalf("public health leaked internal detail: %q", rec.Body.String())
	}
}
