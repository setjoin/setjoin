package middleware

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// hijackableRecorder is a ResponseRecorder that also implements http.Hijacker,
// mirroring the real server's writer so the wrapper's Hijack delegation has a
// live path to exercise.
type hijackableRecorder struct {
	*httptest.ResponseRecorder
	hijacked bool
}

func (h *hijackableRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	h.hijacked = true
	return nil, nil, http.ErrNotSupported // the assertion is on delegation, not a real hijack
}

// readerFromRecorder reports whether ReadFrom was delegated to it.
type readerFromRecorder struct {
	*httptest.ResponseRecorder
	got []byte
}

func (r *readerFromRecorder) ReadFrom(src io.Reader) (int64, error) {
	b, err := io.ReadAll(src)
	r.got = b
	return int64(len(b)), err
}

func TestCacheControl_HijackDelegatesToCapableWriter(t *testing.T) {
	rec := &hijackableRecorder{ResponseRecorder: httptest.NewRecorder()}
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hj, ok := w.(http.Hijacker)
		if !ok {
			t.Fatal("Hijacker capability lost through the wrapper")
		}
		if _, _, err := hj.Hijack(); err == nil {
			t.Error("expected the recorder's sentinel error through delegation")
		}
		w.WriteHeader(http.StatusOK)
	})
	CacheControl(handler).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/ws/socket", nil))
	if !rec.hijacked {
		t.Fatal("wrapper did not delegate Hijack to the underlying writer")
	}
	if got := rec.Header().Get("Cache-Control"); got != noStore {
		t.Fatalf("unregistered route Cache-Control = %q, want no-store", got)
	}
}

func TestCacheControl_HijackUnsupportedReportsErrNotSupported(t *testing.T) {
	var rw http.ResponseWriter = httptest.NewRecorder()
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hj, ok := w.(http.Hijacker)
		if !ok {
			t.Fatal("wrapper must still satisfy http.Hijacker when the underlying writer does not")
		}
		if _, _, err := hj.Hijack(); err != http.ErrNotSupported {
			t.Fatalf("Hijack without an underlying Hijacker = %v, want http.ErrNotSupported", err)
		}
		w.WriteHeader(http.StatusOK)
	})
	CacheControl(handler).ServeHTTP(rw, httptest.NewRequest(http.MethodGet, "/plain", nil))
}

func TestCacheControl_ReadFromDelegatesAndStamps(t *testing.T) {
	rec := &readerFromRecorder{ResponseRecorder: httptest.NewRecorder()}
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// ServeContent-style: io.Copy must consult the wrapper's ReadFrom.
		// (A strings.Reader implements WriterTo and would bypass it — use a
		// plain reader.)
		src := struct{ io.Reader }{strings.NewReader("static-bytes")}
		if _, err := io.Copy(w, src); err != nil {
			t.Fatalf("copy through the wrapper: %v", err)
		}
	})
	CacheControl(handler).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/favicon.ico", nil))
	if string(rec.got) != "static-bytes" {
		t.Fatalf("ReadFrom delegation lost the payload: %q", rec.got)
	}
	if got := rec.Header().Get("Cache-Control"); got != "public, max-age=604800, immutable" {
		t.Fatalf("stamped at first write through ReadFrom: %q", got)
	}
}

func TestCacheControl_ReadFromFallsBackToCopy(t *testing.T) {
	rec := httptest.NewRecorder()
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if _, err := io.Copy(w, strings.NewReader("plain")); err != nil {
			t.Fatalf("copy: %v", err)
		}
	})
	CacheControl(handler).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/downloads", nil))
	if rec.Body.String() != "plain" {
		t.Fatalf("fallback copy lost the body: %q", rec.Body.String())
	}
	if got := rec.Header().Get("Cache-Control"); got != "public, max-age=3600" {
		t.Fatalf("downloads value = %q", got)
	}
}
