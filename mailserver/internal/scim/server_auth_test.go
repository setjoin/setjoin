package scim

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"golang.org/x/crypto/bcrypt"

	"setjoin.com/shared/pgxutil"
)

func TestAuthenticateBindsActiveSCIMSourceMetadata(t *testing.T) {
	pool := scimTestPool(t)
	ctx := context.Background()
	suffix := scimRandomSuffix(t)
	rawToken := "scim-test-token-" + suffix
	hash, err := bcrypt.GenerateFromPassword([]byte(rawToken), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("hash SCIM token: %v", err)
	}
	var sourceID, generation int64
	if err := pool.QueryRow(ctx, `
		INSERT INTO identity_sources(source_key,display_name,kind,capabilities,state)
		VALUES($1,$2,'scim','{"provision_lifecycle":true,"stable_immutable_subject":true}'::jsonb,'active')
		RETURNING id,generation`,
		"scim:auth-"+suffix, "SCIM auth "+suffix,
	).Scan(&sourceID, &generation); err != nil {
		t.Fatalf("create SCIM source: %v", err)
	}
	var tokenID int64
	if err := pool.QueryRow(ctx, `
		INSERT INTO scim_tokens(name,token_hash,deletion_policy,attribute_mapping,source_id)
		VALUES($1,$2,'soft','{"department":"department"}'::jsonb,$3)
		RETURNING id`,
		"SCIM auth "+suffix, string(hash), sourceID,
	).Scan(&tokenID); err != nil {
		t.Fatalf("create SCIM token: %v", err)
	}

	s := NewServer(pool, pgxutil.WorkerPool{Pool: pool}, scimTestLogger(), "", "")
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Context().Value(ctxTokenID) != tokenID ||
			r.Context().Value(ctxSourceID) != sourceID ||
			r.Context().Value(ctxSourceGeneration) != generation {
			t.Fatalf("SCIM metadata was not bound to request context")
		}
		w.WriteHeader(http.StatusNoContent)
	})
	req := httptest.NewRequest(http.MethodGet, "/scim/v2/Users", nil)
	req.Header.Set("Authorization", "Bearer "+rawToken)
	rec := httptest.NewRecorder()
	s.Authenticate(next).ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("SCIM authentication status=%d body=%s", rec.Code, rec.Body.String())
	}
}
