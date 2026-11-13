package user

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"setjoin.com/mailserver/internal/auth"
)

func TestNotificationPrefsHandler_GetUnauthenticated(t *testing.T) {
	pool := testPool(t)
	h := NewNotificationPrefsHandler(pool)

	req := httptest.NewRequest("GET", "/user/notification-preferences", nil)
	w := httptest.NewRecorder()
	h.GetPrefs(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestNotificationPrefsHandler_GetAuthenticatedEmpty(t *testing.T) {
	pool := testPool(t)
	h := NewNotificationPrefsHandler(pool)

	req := httptest.NewRequest("GET", "/user/notification-preferences", nil)
	ctx := auth.ContextWithUser(req.Context(), &auth.Claims{UserID: 999999})
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()
	h.GetPrefs(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d — body: %s", w.Code, w.Body.String())
	}
}

func TestNotificationPrefsHandler_PutUnauthenticated(t *testing.T) {
	pool := testPool(t)
	h := NewNotificationPrefsHandler(pool)

	req := httptest.NewRequest("PUT", "/user/notification-preferences", nil)
	w := httptest.NewRecorder()
	h.SetPrefs(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestNotificationPrefsHandler_PutInvalidJSON(t *testing.T) {
	pool := testPool(t)
	h := NewNotificationPrefsHandler(pool)

	req := httptest.NewRequest("PUT", "/user/notification-preferences", bytes.NewReader([]byte("not json")))
	ctx := auth.ContextWithUser(req.Context(), &auth.Claims{UserID: 999999})
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()
	h.SetPrefs(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d — body: %s", w.Code, w.Body.String())
	}
}

func TestNotificationPrefsHandler_VipSendersGetUnauthenticated(t *testing.T) {
	pool := testPool(t)
	h := NewNotificationPrefsHandler(pool)

	req := httptest.NewRequest("GET", "/user/vip-senders", nil)
	w := httptest.NewRecorder()
	h.GetVipSenders(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestNotificationPrefsHandler_VipSendersSetUnauthenticated(t *testing.T) {
	pool := testPool(t)
	h := NewNotificationPrefsHandler(pool)

	req := httptest.NewRequest("PUT", "/user/vip-senders", nil)
	w := httptest.NewRecorder()
	h.SetVipSender(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestNotificationPrefsHandler_VipSendersSetInvalidJSON(t *testing.T) {
	pool := testPool(t)
	h := NewNotificationPrefsHandler(pool)

	req := httptest.NewRequest("PUT", "/user/vip-senders", bytes.NewReader([]byte("not json")))
	ctx := auth.ContextWithUser(req.Context(), &auth.Claims{UserID: 999999})
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()
	h.SetVipSender(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d — body: %s", w.Code, w.Body.String())
	}
}

func TestNotificationPrefsHandler_VipSendersSetEmptyEmail(t *testing.T) {
	pool := testPool(t)
	h := NewNotificationPrefsHandler(pool)

	body := map[string]interface{}{"email": "  ", "vip": true}
	b, _ := json.Marshal(body)
	req := httptest.NewRequest("PUT", "/user/vip-senders", bytes.NewReader(b))
	ctx := auth.ContextWithUser(req.Context(), &auth.Claims{UserID: 999999})
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()
	h.SetVipSender(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for blank email, got %d — body: %s", w.Code, w.Body.String())
	}
}

func TestNotificationPrefsHandler_PutInvalidFingerprint(t *testing.T) {
	pool := testPool(t)
	h := NewNotificationPrefsHandler(pool)

	body := map[string]interface{}{
		"device_fingerprint": "not-a-uuid",
		"preferences": map[string]interface{}{
			"push_enabled": true,
		},
	}
	b, _ := json.Marshal(body)
	req := httptest.NewRequest("PUT", "/user/notification-preferences", bytes.NewReader(b))
	ctx := auth.ContextWithUser(req.Context(), &auth.Claims{UserID: 999999})
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()
	h.SetPrefs(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d — body: %s", w.Code, w.Body.String())
	}
}

func TestNotificationPrefsHandler_StructInitialization(t *testing.T) {
	pool := testPool(t)
	h := NewNotificationPrefsHandler(pool)
	if h.pool != pool {
		t.Error("pool not set correctly")
	}
}

func TestNotificationPrefsHandler_RoundTrip(t *testing.T) {
	pool := testPool(t)
	userID := createTestUser(t, pool)
	h := NewNotificationPrefsHandler(pool)

	// PUT global preferences
	prefs := map[string]interface{}{
		"device_fingerprint": nil,
		"preferences": map[string]interface{}{
			"push_enabled":                  true,
			"push_sound":                    "chime",
			"stop_push_when_desktop_online": false,
			"mail_notifications":            "all",
			"calendar_reminders":            true,
			"task_reminders":                true,
			"dnd_days":                      127,
		},
	}
	b, _ := json.Marshal(prefs)
	req := httptest.NewRequest("PUT", "/user/notification-preferences", bytes.NewReader(b))
	ctx := auth.ContextWithUser(req.Context(), &auth.Claims{UserID: userID})
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()
	h.SetPrefs(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("PUT expected 200, got %d — body: %s", w.Code, w.Body.String())
	}

	// GET should return the saved preferences
	req2 := httptest.NewRequest("GET", "/user/notification-preferences", nil)
	req2 = req2.WithContext(ctx)

	w2 := httptest.NewRecorder()
	h.GetPrefs(w2, req2)
	if w2.Code != http.StatusOK {
		t.Fatalf("GET expected 200, got %d", w2.Code)
	}

	var resp struct {
		Preferences []NotificationPrefs `json:"preferences"`
	}
	if err := json.Unmarshal(w2.Body.Bytes(), &resp); err != nil {
		t.Fatalf("json decode: %v", err)
	}
	if len(resp.Preferences) == 0 {
		t.Fatal("expected at least one preference after PUT")
	}
	p := resp.Preferences[0]
	if p.PushSound != "chime" {
		t.Errorf("push_sound = %q, want chime", p.PushSound)
	}
	if p.PushEnabled != true {
		t.Errorf("push_enabled = %v, want true", p.PushEnabled)
	}
	if p.MailNotifications != "all" {
		t.Errorf("mail_notifications = %q, want all", p.MailNotifications)
	}
	// The PUT above omitted read_receipt_policy, so the INSERT must default it to "ask"
	// (privacy-safe default — never silently opt the recipient into sending receipts).
	if p.ReadReceiptPolicy != "ask" {
		t.Errorf("read_receipt_policy = %q, want ask (default on insert)", p.ReadReceiptPolicy)
	}

	// "always" and "never" must round-trip through PUT → GET. The global preference row
	// keys on (user_id, device_fingerprint) where device_fingerprint IS NULL; because NULLs
	// are distinct in that unique constraint, we clear the user's rows before each PUT so
	// the GET reads exactly the row we just wrote (a single, unambiguous global row).
	for _, want := range []string{"always", "never"} {
		if _, err := pool.Exec(req.Context(),
			`DELETE FROM user_notification_prefs WHERE user_id = $1`, userID); err != nil {
			t.Fatalf("clear prefs: %v", err)
		}
		putPrefs := map[string]interface{}{
			"device_fingerprint": nil,
			"preferences": map[string]interface{}{
				"push_enabled":        true,
				"mail_notifications":  "all",
				"read_receipt_policy": want,
			},
		}
		pb, _ := json.Marshal(putPrefs)
		preq := httptest.NewRequest("PUT", "/user/notification-preferences", bytes.NewReader(pb))
		preq = preq.WithContext(ctx)
		pw := httptest.NewRecorder()
		h.SetPrefs(pw, preq)
		if pw.Code != http.StatusOK {
			t.Fatalf("PUT read_receipt_policy=%q expected 200, got %d — body: %s", want, pw.Code, pw.Body.String())
		}

		greq := httptest.NewRequest("GET", "/user/notification-preferences", nil)
		greq = greq.WithContext(ctx)
		gw := httptest.NewRecorder()
		h.GetPrefs(gw, greq)
		if gw.Code != http.StatusOK {
			t.Fatalf("GET expected 200, got %d", gw.Code)
		}
		var gresp struct {
			Preferences []NotificationPrefs `json:"preferences"`
		}
		if err := json.Unmarshal(gw.Body.Bytes(), &gresp); err != nil {
			t.Fatalf("json decode: %v", err)
		}
		if len(gresp.Preferences) == 0 {
			t.Fatal("expected at least one preference")
		}
		if got := gresp.Preferences[0].ReadReceiptPolicy; got != want {
			t.Errorf("read_receipt_policy = %q, want %q (round-trip)", got, want)
		}
	}
}

// TestNotificationPrefsHandler_GlobalPrefsPutTwiceUpdatesInPlace is a
// regression test for a pre-existing bug found while verifying Chat A3 QoL
// Task 7's "prefs round-trip" requirement: user_notification_prefs'
// UNIQUE(user_id, device_fingerprint) constraint was a PLAIN unique
// constraint, and Postgres treats every NULL as distinct from every other
// NULL under a plain UNIQUE — so ON CONFLICT (user_id, device_fingerprint)
// DO UPDATE (SetPrefs' only write path) never actually conflicts for the
// GLOBAL preference row (device_fingerprint IS NULL, the common case for
// every plain Settings > Notifications save). Two back-to-back global PUTs
// silently created TWO rows instead of updating one, and GetPrefs's `ORDER
// BY device_fingerprint NULLS FIRST` (no secondary sort key) then returned
// an ARBITRARY tie — a user saving notification prefs twice could see stale
// settings. Fixed by V123 (NULLS NOT DISTINCT, the same fix already used at
// V015/V041/V109).
func TestNotificationPrefsHandler_GlobalPrefsPutTwiceUpdatesInPlace(t *testing.T) {
	pool := testPool(t)
	userID := createTestUser(t, pool)
	h := NewNotificationPrefsHandler(pool)
	ctx := auth.ContextWithUser(context.Background(), &auth.Claims{UserID: userID})

	first := map[string]interface{}{
		"device_fingerprint": nil,
		"preferences": map[string]interface{}{
			"push_enabled":        true,
			"mail_notifications":  "all",
			"read_receipt_policy": "never",
		},
	}
	fb, _ := json.Marshal(first)
	freq := httptest.NewRequest("PUT", "/user/notification-preferences", bytes.NewReader(fb)).WithContext(ctx)
	fw := httptest.NewRecorder()
	h.SetPrefs(fw, freq)
	if fw.Code != http.StatusOK {
		t.Fatalf("first PUT expected 200, got %d — body: %s", fw.Code, fw.Body.String())
	}

	// A SECOND global PUT changing an unrelated field, with read_receipt_policy
	// omitted, must UPDATE the same row in place — never insert a duplicate,
	// and never reset read_receipt_policy back to its "ask" default.
	second := map[string]interface{}{
		"device_fingerprint": nil,
		"preferences": map[string]interface{}{
			"push_enabled":       false,
			"mail_notifications": "important",
		},
	}
	sb, _ := json.Marshal(second)
	sreq := httptest.NewRequest("PUT", "/user/notification-preferences", bytes.NewReader(sb)).WithContext(ctx)
	sw := httptest.NewRecorder()
	h.SetPrefs(sw, sreq)
	if sw.Code != http.StatusOK {
		t.Fatalf("second PUT expected 200, got %d — body: %s", sw.Code, sw.Body.String())
	}

	var rowCount int
	if err := pool.QueryRow(context.Background(),
		`SELECT count(*) FROM user_notification_prefs WHERE user_id = $1`, userID).Scan(&rowCount); err != nil {
		t.Fatalf("count rows: %v", err)
	}
	if rowCount != 1 {
		t.Fatalf("row count after two global PUTs = %d, want 1 (the second PUT must UPDATE, not duplicate)", rowCount)
	}

	greq := httptest.NewRequest("GET", "/user/notification-preferences", nil).WithContext(ctx)
	gw := httptest.NewRecorder()
	h.GetPrefs(gw, greq)
	var gresp struct {
		Preferences []NotificationPrefs `json:"preferences"`
	}
	if err := json.Unmarshal(gw.Body.Bytes(), &gresp); err != nil {
		t.Fatalf("json decode: %v", err)
	}
	if len(gresp.Preferences) != 1 {
		t.Fatalf("GET returned %d preference rows, want exactly 1", len(gresp.Preferences))
	}
	p := gresp.Preferences[0]
	if p.MailNotifications != "important" {
		t.Errorf("mail_notifications = %q, want important (the second PUT's value)", p.MailNotifications)
	}
	if p.ReadReceiptPolicy != "never" {
		t.Errorf("read_receipt_policy = %q, want never preserved (the second PUT omitted it)", p.ReadReceiptPolicy)
	}
}

// TestNotificationPrefsHandler_ChatNotificationsRoundTrip verifies the global
// chat_notifications preference (Chat A3 QoL Task 7) round-trips through
// PUT -> GET, defaults to "all" on first insert, and survives an UNRELATED
// subsequent PUT rather than being silently reset — values are a DIFFERENT
// vocabulary from the per-channel chat_channel_members.notif_level
// ("all"/"mentions"/"none", chat_member_set_notif) — don't cross the two.
func TestNotificationPrefsHandler_ChatNotificationsRoundTrip(t *testing.T) {
	pool := testPool(t)
	userID := createTestUser(t, pool)
	h := NewNotificationPrefsHandler(pool)
	ctx := auth.ContextWithUser(context.Background(), &auth.Claims{UserID: userID})

	put := func(prefs map[string]interface{}) {
		t.Helper()
		body := map[string]interface{}{"device_fingerprint": nil, "preferences": prefs}
		b, _ := json.Marshal(body)
		req := httptest.NewRequest("PUT", "/user/notification-preferences", bytes.NewReader(b)).WithContext(ctx)
		w := httptest.NewRecorder()
		h.SetPrefs(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("PUT expected 200, got %d — body: %s", w.Code, w.Body.String())
		}
	}
	get := func() NotificationPrefs {
		t.Helper()
		req := httptest.NewRequest("GET", "/user/notification-preferences", nil).WithContext(ctx)
		w := httptest.NewRecorder()
		h.GetPrefs(w, req)
		var resp struct {
			Preferences []NotificationPrefs `json:"preferences"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("json decode: %v", err)
		}
		if len(resp.Preferences) != 1 {
			t.Fatalf("GET returned %d preference rows, want exactly 1", len(resp.Preferences))
		}
		return resp.Preferences[0]
	}

	// Omitting chat_notifications on first insert defaults to "all".
	put(map[string]interface{}{"push_enabled": true, "mail_notifications": "all"})
	if got := get().ChatNotifications; got != "all" {
		t.Errorf("chat_notifications = %q, want all (default on insert)", got)
	}

	// "mentions" and "off" round-trip through PUT -> GET (update-in-place,
	// per the V123 dedup fix above).
	for _, want := range []string{"mentions", "off"} {
		put(map[string]interface{}{"push_enabled": true, "mail_notifications": "all", "chat_notifications": want})
		if got := get().ChatNotifications; got != want {
			t.Errorf("chat_notifications = %q, want %q (round-trip)", got, want)
		}
	}

	// Saving unrelated prefs afterward must NOT reset chat_notifications back to "all".
	put(map[string]interface{}{"push_enabled": false, "mail_notifications": "all"})
	if got := get().ChatNotifications; got != "off" {
		t.Errorf("chat_notifications = %q, want off preserved (unrelated PUT must not reset it)", got)
	}
}

// TestNotificationPrefsHandler_PutInvalidChatNotifications verifies that an unaccepted
// chat_notifications value is rejected at the handler with HTTP 400 before it ever
// reaches the row.
func TestNotificationPrefsHandler_PutInvalidChatNotifications(t *testing.T) {
	pool := testPool(t)
	h := NewNotificationPrefsHandler(pool)

	body := map[string]interface{}{
		"device_fingerprint": nil,
		"preferences": map[string]interface{}{
			"push_enabled":       true,
			"chat_notifications": "bogus",
		},
	}
	b, _ := json.Marshal(body)
	req := httptest.NewRequest("PUT", "/user/notification-preferences", bytes.NewReader(b))
	ctx2 := auth.ContextWithUser(req.Context(), &auth.Claims{UserID: 999999})
	req = req.WithContext(ctx2)

	w := httptest.NewRecorder()
	h.SetPrefs(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid chat_notifications, got %d — body: %s", w.Code, w.Body.String())
	}
}

// TestNotificationPrefsHandler_PutInvalidReadReceiptPolicy verifies that an unaccepted
// read_receipt_policy value (one the DB CHECK / validReadReceiptPolicy would refuse) is
// rejected at the handler with HTTP 400 before it ever reaches the row.
func TestNotificationPrefsHandler_PutInvalidReadReceiptPolicy(t *testing.T) {
	pool := testPool(t)
	h := NewNotificationPrefsHandler(pool)

	body := map[string]interface{}{
		"device_fingerprint": nil,
		"preferences": map[string]interface{}{
			"push_enabled":        true,
			"read_receipt_policy": "bogus",
		},
	}
	b, _ := json.Marshal(body)
	req := httptest.NewRequest("PUT", "/user/notification-preferences", bytes.NewReader(b))
	ctx := auth.ContextWithUser(req.Context(), &auth.Claims{UserID: 999999})
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()
	h.SetPrefs(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid read_receipt_policy, got %d — body: %s", w.Code, w.Body.String())
	}
}
