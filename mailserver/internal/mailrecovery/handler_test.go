package mailrecovery

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"setjoin.com/mailserver/internal/auth"
	servercontinuity "setjoin.com/mailserver/internal/continuity"
	"setjoin.com/shared/jwtutil"
	"setjoin.com/shared/toggle"
)

type recoveryHandlerRow struct{ raw json.RawMessage }

func (row recoveryHandlerRow) Scan(dest ...any) error {
	*(dest[0].(*json.RawMessage)) = append(json.RawMessage(nil), row.raw...)
	return nil
}

type recoveryHandlerDB struct {
	queryCount int
	queries    []string
	lastQuery  string
	lastArgs   []any
}

func (db *recoveryHandlerDB) QueryRow(_ context.Context, query string, args ...any) pgx.Row {
	db.queryCount++
	db.queries = append(db.queries, query)
	db.lastQuery = query
	db.lastArgs = append([]any(nil), args...)
	return recoveryHandlerRow{raw: json.RawMessage(`{"id":"11111111-1111-4111-8111-111111111111","status":"open"}`)}
}

func TestAdminIncidentMutationsUseFixedReducerQueries(t *testing.T) {
	now := time.Date(2026, 8, 3, 0, 0, 0, 0, time.UTC)
	tests := []struct {
		name      string
		invoke    func(*Handler, http.ResponseWriter, *http.Request)
		wantQuery string
	}{
		{name: "approve", invoke: (*Handler).AdminApprove, wantQuery: `SELECT mail_recovery_incident_approve($1,$2,$3)`},
		{name: "close", invoke: (*Handler).AdminClose, wantQuery: `SELECT mail_recovery_incident_close($1,$2,$3)`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db := &recoveryHandlerDB{}
			handler := &Handler{
				db:         db,
				store:      recoveryHandlerStore{},
				continuity: &servercontinuity.Service{},
				toggles:    toggle.NewTestFlags(map[string]bool{toggle.FeatureUpgradeRecoveryIntake: true}),
				logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
				now:        func() time.Time { return now },
			}
			request := httptest.NewRequest(http.MethodPost, "/admin/system/recovery/incidents/11111111-1111-4111-8111-111111111111/"+tt.name,
				strings.NewReader(`{"reason":"Reviewed recovery evidence"}`))
			request.SetPathValue("id", "11111111-1111-4111-8111-111111111111")
			request.Header.Set("X-Audit-Reason", "Reviewed recovery evidence")
			request = request.WithContext(auth.ContextWithUser(request.Context(), &jwtutil.Claims{UserID: 7}))
			recorder := httptest.NewRecorder()

			tt.invoke(handler, recorder, request)

			if recorder.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200; body=%s", recorder.Code, recorder.Body.String())
			}
			if db.lastQuery != tt.wantQuery {
				t.Fatalf("query = %q, want %q", db.lastQuery, tt.wantQuery)
			}
			if len(db.lastArgs) != 3 || db.lastArgs[0] != int64(7) || db.lastArgs[2] != "Reviewed recovery evidence" {
				t.Fatalf("args = %#v", db.lastArgs)
			}
		})
	}
}

func (*recoveryHandlerDB) Query(context.Context, string, ...any) (pgx.Rows, error) {
	return nil, errors.New("unexpected query")
}

type recoveryHandlerStore struct{}

func (recoveryHandlerStore) Put(context.Context, string, io.Reader, int64, string) error { return nil }
func (recoveryHandlerStore) Get(context.Context, string) (io.ReadCloser, error) {
	return nil, errors.New("unexpected get")
}
func (recoveryHandlerStore) Remove(context.Context, string) error { return nil }

func TestValidIncidentEvidenceMatchesExactMailboxScope(t *testing.T) {
	digest := strings.Repeat("a", 64)
	tests := []struct {
		name      string
		evidence  map[string]string
		mailboxes []int64
		want      bool
	}{
		{name: "exact", evidence: map[string]string{"42": digest, "43": strings.Repeat("b", 64)}, mailboxes: []int64{42, 43}, want: true},
		{name: "empty", evidence: map[string]string{}, mailboxes: []int64{42}},
		{name: "missing mailbox", evidence: map[string]string{"42": digest}, mailboxes: []int64{42, 43}},
		{name: "extra mailbox", evidence: map[string]string{"42": digest, "43": digest}, mailboxes: []int64{42}},
		{name: "duplicate mailbox scope", evidence: map[string]string{"42": digest, "43": digest}, mailboxes: []int64{42, 42}},
		{name: "uppercase", evidence: map[string]string{"42": strings.Repeat("A", 64)}, mailboxes: []int64{42}},
		{name: "not hex", evidence: map[string]string{"42": strings.Repeat("g", 64)}, mailboxes: []int64{42}},
		{name: "wrong length", evidence: map[string]string{"42": strings.Repeat("a", 62)}, mailboxes: []int64{42}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := validIncidentEvidence(tt.evidence, tt.mailboxes); got != tt.want {
				t.Fatalf("validIncidentEvidence() = %v, want %v", got, tt.want)
			}
		})
	}

	evidence := make(map[string]string, 101)
	mailboxes := make([]int64, 0, 101)
	for id := int64(1); id <= 101; id++ {
		evidence[strconv.FormatInt(id, 10)] = digest
		mailboxes = append(mailboxes, id)
	}
	if validIncidentEvidence(evidence, mailboxes) {
		t.Fatal("101 evidence entries accepted")
	}
}

func TestAdminOpenWiresEvidenceAndExpiryValidationBeforeReducer(t *testing.T) {
	now := time.Date(2026, 8, 2, 0, 0, 0, 0, time.UTC)
	digest := strings.Repeat("a", 64)
	tests := []struct {
		name      string
		mailboxes []string
		evidence  map[string]string
		expiresAt time.Time
		wantCode  int
		wantQuery int
	}{
		{name: "valid", mailboxes: []string{"42"}, evidence: map[string]string{"42": digest}, expiresAt: now.Add(24 * time.Hour), wantCode: http.StatusCreated, wantQuery: 1},
		{name: "duplicate scope with extra evidence", mailboxes: []string{"42", "42"}, evidence: map[string]string{"42": digest, "43": digest}, expiresAt: now.Add(24 * time.Hour), wantCode: http.StatusBadRequest},
		{name: "uppercase digest", mailboxes: []string{"42"}, evidence: map[string]string{"42": strings.Repeat("A", 64)}, expiresAt: now.Add(24 * time.Hour), wantCode: http.StatusBadRequest},
		{name: "expiry beyond seven days", mailboxes: []string{"42"}, evidence: map[string]string{"42": digest}, expiresAt: now.Add(7*24*time.Hour + time.Nanosecond), wantCode: http.StatusBadRequest},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db := &recoveryHandlerDB{}
			handler := &Handler{
				db: db, store: recoveryHandlerStore{}, continuity: &servercontinuity.Service{},
				toggles: toggle.NewTestFlags(map[string]bool{toggle.FeatureUpgradeRecoveryIntake: true}),
				logger:  slog.New(slog.NewTextHandler(io.Discard, nil)), now: func() time.Time { return now },
			}
			body, err := json.Marshal(map[string]any{
				"incidentId": "11111111-1111-4111-8111-111111111111", "mailboxIds": tt.mailboxes,
				"evidence": tt.evidence, "minimumTimeline": "11", "maximumTimeline": "12",
				"expiresAt": tt.expiresAt, "reason": "Verified recovery evidence", "approvalRequired": true,
				"idempotencyKey": "22222222-2222-4222-8222-222222222222",
			})
			if err != nil {
				t.Fatal(err)
			}
			request := httptest.NewRequest(http.MethodPost, "/admin/system/recovery/incidents", strings.NewReader(string(body)))
			request.Header.Set("X-Audit-Reason", "Verified recovery evidence")
			request.Header.Set("Idempotency-Key", "22222222-2222-4222-8222-222222222222")
			claims := &jwtutil.Claims{UserID: 7, JTI: "recovery-test-session", ACR: jwtutil.ACRAAL2,
				AMR: []string{jwtutil.AMRPassword, jwtutil.AMROTP, jwtutil.AMRMultiFactor}}
			claims.IssuedAt = jwtutil.NewNumericDate(now.Add(-time.Minute))
			request = request.WithContext(auth.ContextWithUser(request.Context(), claims))
			recorder := httptest.NewRecorder()
			handler.AdminOpen(recorder, request)
			if recorder.Code != tt.wantCode || db.queryCount != tt.wantQuery {
				t.Fatalf("status/query count = %d/%d, want %d/%d; body=%s", recorder.Code, db.queryCount, tt.wantCode, tt.wantQuery, recorder.Body.String())
			}
		})
	}
}

func TestValidIncidentExpiryIsFutureAndAtMostSevenDays(t *testing.T) {
	now := time.Date(2026, 8, 2, 0, 0, 0, 0, time.UTC)
	tests := []struct {
		name      string
		expiresAt time.Time
		want      bool
	}{
		{name: "zero"},
		{name: "past", expiresAt: now.Add(-time.Second)},
		{name: "now", expiresAt: now},
		{name: "future", expiresAt: now.Add(time.Second), want: true},
		{name: "seven days", expiresAt: now.Add(7 * 24 * time.Hour), want: true},
		{name: "over seven days", expiresAt: now.Add(7*24*time.Hour + time.Nanosecond)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := validIncidentExpiry(now, tt.expiresAt); got != tt.want {
				t.Fatalf("validIncidentExpiry() = %v, want %v", got, tt.want)
			}
		})
	}
}
