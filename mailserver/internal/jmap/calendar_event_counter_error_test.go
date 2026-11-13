package jmap

import (
	"encoding/json"
	"io"
	"log/slog"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
)

// TestCalendarA3Error_CounterBZ001Forbidden guards the fix for audit #32: the
// CalendarEvent/counter handler must route its reducer error through
// calendarA3Error (BZ001 -> forbidden), not the generic mapReducerErr
// (BZ001 -> serverFail). This test exercises the shared interceptor directly
// with a synthetic BZ001 PgError, matching what jmap_calendar_event_counter
// raises for a foreign/stale eventId.
func TestCalendarA3Error_CounterBZ001Forbidden(t *testing.T) {
	h := &JMAPHandler{logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	err := &pgconn.PgError{Code: "BZ001", Message: "not authorized for this calendar"}

	raw := calendarA3Error(err, h, "CalendarEvent/counter")

	var got Error
	if uerr := json.Unmarshal(raw, &got); uerr != nil {
		t.Fatalf("unmarshal error response: %v", uerr)
	}
	if got.Type != "forbidden" {
		t.Fatalf("Type = %q, want %q", got.Type, "forbidden")
	}
}
