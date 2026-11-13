package jmap

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/jwtutil"
	"setjoin.com/shared/pgxutil"
	"setjoin.com/shared/toggle"
)

func attachmentRequestWithClaims(method, target, body string, claims *auth.Claims) *http.Request {
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	return req.WithContext(auth.ContextWithUser(context.Background(), claims))
}

func TestDecodeAttachmentTokenRequestStrictBoundary(t *testing.T) {
	sha := strings.Repeat("a", 64)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/mail/attachment-transfer-token",
		strings.NewReader(`{"accountId":"42","sha256":"`+sha+`"}`))
	got, err := decodeAttachmentTokenRequest(rec, req)
	if err != nil || got.AccountID != "42" || got.SHA256 != sha {
		t.Fatalf("decode = %+v, %v", got, err)
	}

	for name, body := range map[string]string{
		"unknown key":     `{"accountId":"42","sha256":"` + sha + `","token":"secret"}`,
		"numeric account": `{"accountId":42,"sha256":"` + sha + `"}`,
		"leading zero":    `{"accountId":"042","sha256":"` + sha + `"}`,
		"uppercase hash":  `{"accountId":"42","sha256":"` + strings.ToUpper(sha) + `"}`,
		"short hash":      `{"accountId":"42","sha256":"abcd"}`,
		"two objects":     `{"accountId":"42","sha256":"` + sha + `"}{}`,
	} {
		t.Run(name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/api/mail/attachment-transfer-token", strings.NewReader(body))
			if _, err := decodeAttachmentTokenRequest(rec, req); err == nil {
				t.Fatal("invalid request accepted")
			}
		})
	}
}

func TestValidBlobSHA256ExactLowercaseHex(t *testing.T) {
	if !validBlobSHA256(strings.Repeat("0", 64)) || !validBlobSHA256(strings.Repeat("f", 64)) {
		t.Fatal("canonical lowercase hash rejected")
	}
	for _, value := range []string{"", strings.Repeat("a", 63), strings.Repeat("A", 64), strings.Repeat("g", 64)} {
		if validBlobSHA256(value) {
			t.Fatalf("invalid sha accepted: %q", value)
		}
	}
}

func TestAttachmentTransferHandlersFailClosedBeforeDatabaseAccess(t *testing.T) {
	sha := strings.Repeat("a", 64)
	body := `{"accountId":"42","sha256":"` + sha + `"}`
	normal := &auth.Claims{
		UserID: 42,
		Type:   auth.TypeAccess,
		Device: &jwtutil.DeviceClaim{ID: "device", Platform: "desktop"},
	}

	t.Run("mint feature off is hidden", func(t *testing.T) {
		h := &JMAPHandler{toggles: toggle.NewTestFlags(map[string]bool{})}
		rec := httptest.NewRecorder()
		h.MintAttachmentTransfer(rec, attachmentRequestWithClaims(http.MethodPost, "/api/mail/attachment-transfer-token", body, normal))
		if rec.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404", rec.Code)
		}
	})

	on := toggle.NewTestFlags(map[string]bool{
		toggle.FeatureOfflineMail:           true,
		toggle.FeatureConnectivityAwareSync: true,
	})
	for name, claims := range map[string]*auth.Claims{
		"guest": {
			UserID: 42, Type: auth.TypeAccess, AccountType: jwtutil.AccountTypeGuest,
			Device: &jwtutil.DeviceClaim{ID: "device", Platform: "desktop"},
		},
		"scoped token": {
			UserID: 42, Type: auth.TypeAccess, Scp: "mail-attachment",
			Device: &jwtutil.DeviceClaim{ID: "device", Platform: "desktop"},
		},
		"derived claim": {
			UserID: 42, Type: auth.TypeAccess, Attachment: &jwtutil.AttachmentTransferClaim{},
			Device: &jwtutil.DeviceClaim{ID: "device", Platform: "desktop"},
		},
		"missing device": {UserID: 42, Type: auth.TypeAccess},
	} {
		t.Run("mint rejects "+name, func(t *testing.T) {
			h := &JMAPHandler{toggles: on}
			rec := httptest.NewRecorder()
			h.MintAttachmentTransfer(rec, attachmentRequestWithClaims(http.MethodPost, "/api/mail/attachment-transfer-token", body, claims))
			if rec.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want 403", rec.Code)
			}
		})
	}

	t.Run("download path mismatch is unauthorized", func(t *testing.T) {
		h := &JMAPHandler{toggles: on}
		claims := &auth.Claims{Attachment: &jwtutil.AttachmentTransferClaim{SHA256: sha}}
		req := attachmentRequestWithClaims(http.MethodGet, "/mail-attachment/"+strings.Repeat("b", 64), "", claims)
		req.SetPathValue("sha256", strings.Repeat("b", 64))
		rec := httptest.NewRecorder()
		h.DownloadAttachmentTransfer(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", rec.Code)
		}
	})
}

func TestAttachmentPolicyModeOffIsHidden(t *testing.T) {
	var policy effectiveTransferPolicy
	policy.SyncQoS.Mode = "off"
	if !attachmentPolicyModeHidden(policy) {
		t.Fatal("winning mode off must hide mint and download routes")
	}
	policy.SyncQoS.Mode = "observe"
	if attachmentPolicyModeHidden(policy) {
		t.Fatal("only winning mode off has the route-hiding contract")
	}
}

func TestOriginSessionActiveRevocationScopes(t *testing.T) {
	pool := testPoolDB(t)
	h := NewJMAPHandler(pool, pgxutil.WorkerPool{Pool: pool}, "localhost", nil, "test-bucket", 10_000_000, testLoggerDB(t))
	_, userID, _ := insertTestUserWithMailbox(t, pool, false)
	claims := &auth.Claims{
		UserID:   userID,
		JTI:      "derived-jti",
		FamilyID: "family-1",
		Attachment: &jwtutil.AttachmentTransferClaim{
			OriginJTI:      "origin-jti",
			OriginIssuedAt: time.Now().Add(-time.Minute).Unix(),
		},
	}
	if !h.originSessionActive(context.Background(), claims) {
		t.Fatal("unrevoked origin session reported inactive")
	}

	for _, tc := range []struct {
		name, scope, jti, family string
	}{
		{"jti", "jti", "origin-jti", ""},
		{"family", "family", "", "family-1"},
		{"all", "all", "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var id int64
			if err := pool.QueryRow(context.Background(), `
				INSERT INTO session_revocations(user_id,scope,jti,family_id,reason,expires_at)
				VALUES ($1,$2,NULLIF($3,''),NULLIF($4,''),'e3-test',now()+interval '1 hour')
				RETURNING id`, userID, tc.scope, tc.jti, tc.family).Scan(&id); err != nil {
				t.Fatalf("insert revocation: %v", err)
			}
			if h.originSessionActive(context.Background(), claims) {
				t.Fatalf("%s revocation did not invalidate origin session", tc.scope)
			}
			if _, err := pool.Exec(context.Background(), `DELETE FROM session_revocations WHERE id=$1`, id); err != nil {
				t.Fatalf("delete revocation: %v", err)
			}
		})
	}
}
