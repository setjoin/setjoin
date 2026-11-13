package carddav

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"setjoin.com/mailserver/internal/auth"
)

func TestDAVHandlersRejectOversizedBodiesBeforeDatabaseWork(t *testing.T) {
	h := &Handler{logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	for _, tc := range []struct {
		name string
		path string
		size int64
		call func(http.ResponseWriter, *http.Request)
	}{
		{"propfind", "/carddav/1/", davXMLBodyMaxBytes, h.handlePropfind},
		{"report", "/carddav/1/", davXMLBodyMaxBytes, h.handleReport},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, tc.path, strings.NewReader(strings.Repeat("x", int(tc.size+1))))
			req = req.WithContext(auth.ContextWithUser(context.Background(), &auth.Claims{UserID: 1}))
			rec := httptest.NewRecorder()
			tc.call(rec, req)
			if rec.Code != http.StatusRequestEntityTooLarge {
				t.Fatalf("status=%d, want 413", rec.Code)
			}
		})
	}
}

func TestDAVReportParsersRejectMalformedXMLBeforeDatabaseWork(t *testing.T) {
	h := &Handler{logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	req := httptest.NewRequest("REPORT", "/carddav/1/", strings.NewReader(`<addressbook-query`))
	req = req.WithContext(auth.ContextWithUser(context.Background(), &auth.Claims{UserID: 1}))
	rec := httptest.NewRecorder()
	h.handleReport(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("query status=%d, want 400", rec.Code)
	}

	req = httptest.NewRequest("REPORT", "/carddav/1/", nil)
	rec = httptest.NewRecorder()
	h.handleMultiget(rec, req, []byte(`<broken`), 1)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("multiget status=%d, want 400", rec.Code)
	}
}
