package caldav

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
		{"propfind", "/caldav/1/", davXMLBodyMaxBytes, h.handlePropfind},
		{"report", "/caldav/1/", davXMLBodyMaxBytes, h.handleReport},
		{"mkcalendar", "/caldav/1/new/", davXMLBodyMaxBytes, h.handleMkcalendar},
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
	for _, call := range []func(http.ResponseWriter, *http.Request){
		h.handleReport,
		func(w http.ResponseWriter, r *http.Request) { h.handleFreeBusyQuery(w, r, []byte(`<broken`)) },
	} {
		req := httptest.NewRequest("REPORT", "/caldav/1/", strings.NewReader(`<calendar-query`))
		req = req.WithContext(auth.ContextWithUser(context.Background(), &auth.Claims{UserID: 1}))
		rec := httptest.NewRecorder()
		call(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status=%d, want 400", rec.Code)
		}
	}
}
