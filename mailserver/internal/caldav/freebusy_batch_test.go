package caldav

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func noopLogger() *slog.Logger { return slog.New(slog.DiscardHandler) }

func TestFreeBusyBatchRequestParsing(t *testing.T) {
	// Test that the batch request body parses correctly.
	tests := []struct {
		name    string
		body    interface{}
		wantErr bool
	}{
		{
			name: "valid request",
			body: FreeBusyBatchRequest{
				UserIDs: []int64{1, 2, 3},
				RoomIDs: []int64{10},
				Start:   "2026-06-01T08:00:00Z",
				End:     "2026-06-01T18:00:00Z",
			},
			wantErr: false,
		},
		{
			name: "empty user_ids and room_ids",
			body: FreeBusyBatchRequest{
				UserIDs: []int64{},
				RoomIDs: []int64{},
				Start:   "2026-06-01T08:00:00Z",
				End:     "2026-06-01T18:00:00Z",
			},
			wantErr: true,
		},
		{
			name: "missing start",
			body: FreeBusyBatchRequest{
				UserIDs: []int64{1},
				RoomIDs: []int64{},
				Start:   "",
				End:     "2026-06-01T18:00:00Z",
			},
			wantErr: true,
		},
		{
			name: "missing end",
			body: FreeBusyBatchRequest{
				UserIDs: []int64{1},
				RoomIDs: []int64{},
				Start:   "2026-06-01T08:00:00Z",
				End:     "",
			},
			wantErr: true,
		},
		{
			name: "start after end",
			body: FreeBusyBatchRequest{
				UserIDs: []int64{1},
				RoomIDs: []int64{},
				Start:   "2026-06-02T08:00:00Z",
				End:     "2026-06-01T08:00:00Z",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body, _ := json.Marshal(tt.body)
			var req FreeBusyBatchRequest
			err := json.Unmarshal(body, &req)
			if err != nil {
				t.Fatalf("json unmarshal failed: %v", err)
			}

			err = req.Validate()
			if tt.wantErr && err == nil {
				t.Error("expected validation error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("unexpected validation error: %v", err)
			}
		})
	}
}

func TestFreeBusyBatchResponseJSON(t *testing.T) {
	// Test that the response type marshals correctly.
	resp := FreeBusyBatchResponse{
		Results: []FreeBusyEntityResult{
			{
				EntityID: "1",
				Email:    "alice@test.local",
				Type:     "user",
				Intervals: []BusyInterval{
					{Start: time.Date(2026, 6, 1, 9, 0, 0, 0, time.UTC), End: time.Date(2026, 6, 1, 10, 0, 0, 0, time.UTC), Status: "busy"},
				},
			},
			{
				EntityID: "10",
				Email:    "room-board@resources",
				Type:     "room",
				Intervals: []BusyInterval{
					{Start: time.Date(2026, 6, 1, 14, 0, 0, 0, time.UTC), End: time.Date(2026, 6, 1, 15, 0, 0, 0, time.UTC), Status: "busy"},
				},
			},
		},
	}

	b, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("json marshal failed: %v", err)
	}

	var parsed FreeBusyBatchResponse
	if err := json.Unmarshal(b, &parsed); err != nil {
		t.Fatalf("json unmarshal failed: %v", err)
	}

	if len(parsed.Results) != 2 {
		t.Errorf("expected 2 results, got %d", len(parsed.Results))
	}
	if parsed.Results[0].Email != "alice@test.local" {
		t.Errorf("expected alice@test.local, got %s", parsed.Results[0].Email)
	}
	if parsed.Results[0].Type != "user" {
		t.Errorf("expected user type, got %s", parsed.Results[0].Type)
	}
	if len(parsed.Results[0].Intervals) != 1 {
		t.Errorf("expected 1 interval, got %d", len(parsed.Results[0].Intervals))
	}
}

func TestFreeBusyBatchHandler_NoAuth(t *testing.T) {
	// Handler without DB pool: should return 401 when no auth context.
	h := &Handler{pool: nil, logger: noopLogger()}
	req := httptest.NewRequest(http.MethodPost, "/caldav/freebusy/batch", nil)
	rec := httptest.NewRecorder()

	h.FreeBusy(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rec.Code)
	}
}

func TestFreeBusyBatchHandler_MethodNotAllowed(t *testing.T) {
	// Only POST is allowed.
	h := &Handler{pool: nil, logger: noopLogger()}

	tests := []struct {
		method string
		want   int
	}{
		{"GET", http.StatusMethodNotAllowed},
		{"PUT", http.StatusMethodNotAllowed},
		{"DELETE", http.StatusMethodNotAllowed},
	}

	for _, tt := range tests {
		t.Run(tt.method, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, "/caldav/freebusy/batch", nil)
			rec := httptest.NewRecorder()
			h.FreeBusy(rec, req)
			if rec.Code != tt.want {
				t.Errorf("expected %d, got %d", tt.want, rec.Code)
			}
		})
	}
}
