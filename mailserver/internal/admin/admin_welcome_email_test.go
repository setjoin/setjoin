package admin

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/mailserver/internal/notify"
	"setjoin.com/shared/testsupport"
)

func validCfg() notify.WelcomeEmailConfig {
	return notify.WelcomeEmailConfig{
		Enabled:       true,
		DefaultLocale: "en",
		Locales: map[string]notify.WelcomeLocale{
			"en": {Subject: "Hi", BodyText: "Welcome", BodyHTML: ""},
		},
	}
}

func TestValidateWelcomeConfig(t *testing.T) {
	if err := validateWelcomeConfig(validCfg()); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}

	// default_locale must be one of en/zh/de.
	bad := validCfg()
	bad.DefaultLocale = "fr"
	if err := validateWelcomeConfig(bad); err == nil {
		t.Error("expected error for unknown default_locale")
	}

	// en locale must exist with a non-empty subject + body_text.
	noEn := validCfg()
	noEn.Locales = map[string]notify.WelcomeLocale{"zh": {Subject: "x", BodyText: "y"}}
	if err := validateWelcomeConfig(noEn); err == nil {
		t.Error("expected error when en locale missing")
	}

	emptyBody := validCfg()
	emptyBody.Locales["en"] = notify.WelcomeLocale{Subject: "x", BodyText: ""}
	if err := validateWelcomeConfig(emptyBody); err == nil {
		t.Error("expected error for empty en body_text")
	}

	// an unknown locale key is rejected (only en/zh/de allowed).
	extra := validCfg()
	extra.Locales["fr"] = notify.WelcomeLocale{Subject: "x", BodyText: "y"}
	if err := validateWelcomeConfig(extra); err == nil {
		t.Error("expected error for unknown locale key")
	}
}

// TestWelcomeHandler_GetPut exercises the Get/Put HTTP handlers against the test
// DB (A4): GET returns the seeded config; a valid PUT persists and is reflected
// by get_system_config; an invalid PUT is rejected with 400.
func TestWelcomeHandler_GetPut(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()
	h := NewWelcomeEmailHandler(pool, testsupport.TestLogger())

	// Snapshot + restore the seeded config so the test does not leak edits.
	var prev []byte
	if err := pool.QueryRow(ctx, `SELECT get_system_config('welcome_email')`).Scan(&prev); err != nil {
		t.Fatalf("snapshot config: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `SELECT set_system_config('welcome_email', $1::jsonb, false, NULL)`, prev)
	})

	actorID := seedUser(t, pool)

	// GET returns the seeded config (enabled=true).
	getReq := httptest.NewRequest("GET", "/admin/system/welcome-email", nil)
	getW := httptest.NewRecorder()
	h.Get(getW, getReq)
	if getW.Code != http.StatusOK {
		t.Fatalf("GET status = %d, want 200: %s", getW.Code, getW.Body.String())
	}
	var got notify.WelcomeEmailConfig
	if err := json.Unmarshal(getW.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode GET body: %v", err)
	}
	if !got.Enabled {
		t.Errorf("GET config enabled = false, want true (seeded)")
	}

	// PUT a valid config: flip enabled to false.
	cfg := got
	cfg.Enabled = false
	body, _ := json.Marshal(cfg)
	putReq := httptest.NewRequest("PUT", "/admin/system/welcome-email", strings.NewReader(string(body)))
	putReq = putReq.WithContext(auth.ContextWithUser(putReq.Context(), &auth.Claims{UserID: actorID, Email: "admin@x.com", IsAdmin: true}))
	putW := httptest.NewRecorder()
	h.Put(putW, putReq)
	if putW.Code != http.StatusNoContent {
		t.Fatalf("PUT status = %d, want 204: %s", putW.Code, putW.Body.String())
	}
	var enabled bool
	if err := pool.QueryRow(ctx, `SELECT (get_system_config('welcome_email')->>'enabled')::boolean`).Scan(&enabled); err != nil {
		t.Fatalf("read back: %v", err)
	}
	if enabled {
		t.Errorf("after PUT, enabled = true, want false")
	}

	// PUT an invalid config (bad default_locale) → 400.
	bad := got
	bad.DefaultLocale = "fr"
	badBody, _ := json.Marshal(bad)
	badReq := httptest.NewRequest("PUT", "/admin/system/welcome-email", strings.NewReader(string(badBody)))
	badReq = badReq.WithContext(auth.ContextWithUser(badReq.Context(), &auth.Claims{UserID: actorID, Email: "admin@x.com", IsAdmin: true}))
	badW := httptest.NewRecorder()
	h.Put(badW, badReq)
	if badW.Code != http.StatusBadRequest {
		t.Fatalf("invalid PUT status = %d, want 400: %s", badW.Code, badW.Body.String())
	}
}

func TestWelcomeTestSendRequest_Decode(t *testing.T) {
	body := `{"locale":"en","subject":"Hi {{DisplayName}}","body_text":"Welcome {{Email}}","body_html":""}`
	var req welcomeTestSendRequest
	if err := json.NewDecoder(strings.NewReader(body)).Decode(&req); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if req.Locale != "en" || req.Subject != "Hi {{DisplayName}}" || req.BodyText != "Welcome {{Email}}" {
		t.Errorf("decoded wrong: %+v", req)
	}
	if tmpl := req.template(); tmpl.Subject != req.Subject || tmpl.BodyText != req.BodyText {
		t.Errorf("template() lost content: %+v", tmpl)
	}
}

// TestWelcomeHandler_TestSend exercises the TestSend handler against the test DB
// (A4): a POST delivers a substituted message into the calling admin's own
// mailbox. The admin is provisioned with a real primary mailbox so the
// recipient resolver succeeds.
func TestWelcomeHandler_TestSend(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()
	h := NewWelcomeEmailHandler(pool, testsupport.TestLogger())

	// Provision an admin with a real primary mailbox.
	var adminID int64
	if err := pool.QueryRow(ctx,
		`SELECT (provision_account('ts-admin@welcome.test', 'Test Send Admin')->>'user_id')::bigint`).Scan(&adminID); err != nil {
		t.Fatalf("provision admin: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM users WHERE id = $1`, adminID) })

	body := `{"locale":"en","subject":"Preview for {{DisplayName}}","body_text":"Hi {{Email}}","body_html":""}`
	req := httptest.NewRequest("POST", "/admin/system/welcome-email/test", strings.NewReader(body))
	req = req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{UserID: adminID, Email: "ts-admin@welcome.test", IsAdmin: true}))
	w := httptest.NewRecorder()
	h.TestSend(w, req)
	if w.Code != http.StatusAccepted {
		t.Fatalf("TestSend status = %d, want 202: %s", w.Code, w.Body.String())
	}

	// The substituted message landed in the admin's mailbox (sentinel + subject).
	var subject string
	err := pool.QueryRow(ctx,
		`SELECT m.subject FROM messages m JOIN mailboxes mb ON mb.id = m.mailbox_id
		  WHERE mb.user_id = $1 AND m.raw_ref = $2 ORDER BY m.id DESC LIMIT 1`,
		adminID, "system:welcome:"+strconv.FormatInt(adminID, 10)).Scan(&subject)
	if err != nil {
		t.Fatalf("read delivered message: %v", err)
	}
	if subject != "Preview for Test Send Admin" {
		t.Errorf("subject = %q, want substituted", subject)
	}
}
