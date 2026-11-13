// translate_test.go — Chat A3 QoL Task 5: POST /chat/messages/{id}/translate
// as a real HTTP round trip (chatDSN/chatTestPool/chatTestUser/chatDo, the
// tracer_integration_test.go genre). Membership + message-body fetch reuse
// chat_thread_list (already covered at the reducer layer by
// mailserver/sql/tests/chat_message.pg) — this file proves the Go route
// wires claims.UserID through to it correctly, gates on feature.assist, and
// emits the egress-observability audit line, not the reducer logic itself.
package chat_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"setjoin.com/mailserver/internal/admin"
	"setjoin.com/mailserver/internal/chat"
	"setjoin.com/shared/cryptokey"
	"setjoin.com/shared/toggle"
)

func TestTranslateRouteNonMember403(t *testing.T) {
	dsn := chatDSN(t)
	pool := chatTestPool(t, dsn)
	h := chat.NewHandler(pool, toggle.NewTestFlags(map[string]bool{"feature.chat": true, "feature.assist": true}), slog.Default())

	owner := chatTestUser(t, pool, "a3xlateOwner")
	outsider := chatTestUser(t, pool, "a3xlateOutsider")

	var channelID int64
	if err := pool.QueryRow(context.Background(), `SELECT chat_channel_create($1, $2)`, owner, "a3-xlate-chan").Scan(&channelID); err != nil {
		t.Fatalf("chat_channel_create: %v", err)
	}
	sendRR := chatDo(t, h, owner, "POST", fmt.Sprintf("/chat/channels/%d/messages", channelID), `{"body":"hello there"}`)
	if sendRR.Code != http.StatusCreated {
		t.Fatalf("send: want 201, got %d: %s", sendRR.Code, sendRR.Body.String())
	}
	var sent struct {
		MessageID int64 `json:"messageId"`
	}
	if err := json.Unmarshal(sendRR.Body.Bytes(), &sent); err != nil {
		t.Fatalf("decode send: %v", err)
	}

	rr := chatDo(t, h, outsider, "POST", fmt.Sprintf("/chat/messages/%d/translate", sent.MessageID), `{"targetLocale":"zh"}`)
	if rr.Code != http.StatusForbidden {
		t.Errorf("non-member translate: want 403 (BZ163), got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestTranslateRouteAssistOff503(t *testing.T) {
	dsn := chatDSN(t)
	pool := chatTestPool(t, dsn)
	h := chat.NewHandler(pool, toggle.NewTestFlags(map[string]bool{"feature.chat": true, "feature.assist": false}), slog.Default())

	owner := chatTestUser(t, pool, "a3xlateOffOwner")

	var channelID int64
	if err := pool.QueryRow(context.Background(), `SELECT chat_channel_create($1, $2)`, owner, "a3-xlate-off-chan").Scan(&channelID); err != nil {
		t.Fatalf("chat_channel_create: %v", err)
	}
	sendRR := chatDo(t, h, owner, "POST", fmt.Sprintf("/chat/channels/%d/messages", channelID), `{"body":"hello there"}`)
	if sendRR.Code != http.StatusCreated {
		t.Fatalf("send: want 201, got %d: %s", sendRR.Code, sendRR.Body.String())
	}
	var sent struct {
		MessageID int64 `json:"messageId"`
	}
	if err := json.Unmarshal(sendRR.Body.Bytes(), &sent); err != nil {
		t.Fatalf("decode send: %v", err)
	}

	rr := chatDo(t, h, owner, "POST", fmt.Sprintf("/chat/messages/%d/translate", sent.MessageID), `{"targetLocale":"zh"}`)
	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("feature.assist off: want 503, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestTranslateRouteHappyPathAndAuditLine(t *testing.T) {
	dsn := chatDSN(t)
	pool := chatTestPool(t, dsn)

	// Stub OpenAI-compatible upstream — the same genre as
	// shared/assist/openai_test.go's canned-response server.
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"你好"}}]}`))
	}))
	defer upstream.Close()

	ctx := context.Background()
	if _, err := pool.Exec(ctx, `SELECT set_system_config('assist.provider_url', to_jsonb($1::text))`, upstream.URL); err != nil {
		t.Fatalf("set assist.provider_url: %v", err)
	}
	if _, err := pool.Exec(ctx, `SELECT set_system_config('assist.model', to_jsonb('test-model'::text))`); err != nil {
		t.Fatalf("set assist.model: %v", err)
	}

	var logBuf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logBuf, nil))
	h := chat.NewHandler(pool, toggle.NewTestFlags(map[string]bool{"feature.chat": true, "feature.assist": true}), logger)

	owner := chatTestUser(t, pool, "a3xlateHappyOwner")

	var channelID int64
	if err := pool.QueryRow(ctx, `SELECT chat_channel_create($1, $2)`, owner, "a3-xlate-happy-chan").Scan(&channelID); err != nil {
		t.Fatalf("chat_channel_create: %v", err)
	}
	sendRR := chatDo(t, h, owner, "POST", fmt.Sprintf("/chat/channels/%d/messages", channelID), `{"body":"hello there"}`)
	if sendRR.Code != http.StatusCreated {
		t.Fatalf("send: want 201, got %d: %s", sendRR.Code, sendRR.Body.String())
	}
	var sent struct {
		MessageID int64 `json:"messageId"`
	}
	if err := json.Unmarshal(sendRR.Body.Bytes(), &sent); err != nil {
		t.Fatalf("decode send: %v", err)
	}

	rr := chatDo(t, h, owner, "POST", fmt.Sprintf("/chat/messages/%d/translate", sent.MessageID), `{"targetLocale":"zh"}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("translate: want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var resp struct {
		Translated string `json:"translated"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode translate response: %v", err)
	}
	if resp.Translated != "你好" {
		t.Errorf("translated = %q, want %q", resp.Translated, "你好")
	}

	logged := logBuf.String()
	for _, want := range []string{
		fmt.Sprintf("messageId=%d", sent.MessageID),
		fmt.Sprintf("userId=%d", owner),
		"targetLocale=zh",
		"provider=test-model",
	} {
		if !strings.Contains(logged, want) {
			t.Errorf("audit log missing %q; got: %s", want, logged)
		}
	}

	// A4a Task 3: with feature.chat_compliance OFF (not set in this test's
	// flag map, default-false per shared/toggle registryDefaults), the
	// translate.egress act is never written — the pre-existing slog line
	// above is the only observability, exactly as it was before A4a.
	var chainCount int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM chat_audit_log WHERE channel_id = $1 AND action = 'translate.egress'`,
		channelID).Scan(&chainCount); err != nil {
		t.Fatalf("count chat_audit_log: %v", err)
	}
	if chainCount != 0 {
		t.Errorf("translate.egress chain rows with compliance OFF = %d, want 0", chainCount)
	}
}

// TestTranslateRouteAuditChainOn is Task 3's chain-wiring proof: with
// feature.chat_compliance ON, a successful translate writes ONE
// translate.egress act on the channel's chain carrying {targetLocale,
// provider} in after_state, before the (stubbed) provider call ever runs.
func TestTranslateRouteAuditChainOn(t *testing.T) {
	dsn := chatDSN(t)
	pool := chatTestPool(t, dsn)

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"你好"}}]}`))
	}))
	defer upstream.Close()

	ctx := context.Background()
	if _, err := pool.Exec(ctx, `SELECT set_system_config('assist.provider_url', to_jsonb($1::text))`, upstream.URL); err != nil {
		t.Fatalf("set assist.provider_url: %v", err)
	}
	if _, err := pool.Exec(ctx, `SELECT set_system_config('assist.model', to_jsonb('test-model'::text))`); err != nil {
		t.Fatalf("set assist.model: %v", err)
	}
	if _, err := pool.Exec(ctx, `UPDATE feature_toggles SET enabled = TRUE WHERE key = 'feature.chat_compliance'`); err != nil {
		t.Fatalf("enable feature.chat_compliance: %v", err)
	}
	defer func() {
		_, _ = pool.Exec(context.Background(), `UPDATE feature_toggles SET enabled = FALSE WHERE key = 'feature.chat_compliance'`)
	}()

	h := chat.NewHandler(pool, toggle.NewTestFlags(map[string]bool{
		"feature.chat": true, "feature.assist": true, "feature.chat_compliance": true,
	}), slog.Default())

	owner := chatTestUser(t, pool, "a4aXlateChainOwner")

	var channelID int64
	if err := pool.QueryRow(ctx, `SELECT chat_channel_create($1, $2)`, owner, "a4a-xlate-chain-chan").Scan(&channelID); err != nil {
		t.Fatalf("chat_channel_create: %v", err)
	}
	sendRR := chatDo(t, h, owner, "POST", fmt.Sprintf("/chat/channels/%d/messages", channelID), `{"body":"hello there"}`)
	if sendRR.Code != http.StatusCreated {
		t.Fatalf("send: want 201, got %d: %s", sendRR.Code, sendRR.Body.String())
	}
	var sent struct {
		MessageID int64 `json:"messageId"`
	}
	if err := json.Unmarshal(sendRR.Body.Bytes(), &sent); err != nil {
		t.Fatalf("decode send: %v", err)
	}

	rr := chatDo(t, h, owner, "POST", fmt.Sprintf("/chat/messages/%d/translate", sent.MessageID), `{"targetLocale":"zh"}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("translate: want 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var action string
	var after []byte
	if err := pool.QueryRow(ctx,
		`SELECT action, after_state FROM chat_audit_log WHERE channel_id = $1 AND action = 'translate.egress'`,
		channelID).Scan(&action, &after); err != nil {
		t.Fatalf("query chat_audit_log: %v", err)
	}
	var afterJSON map[string]string
	if err := json.Unmarshal(after, &afterJSON); err != nil {
		t.Fatalf("decode after_state: %v", err)
	}
	if afterJSON["targetLocale"] != "zh" {
		t.Errorf("after_state.targetLocale = %q, want %q", afterJSON["targetLocale"], "zh")
	}
	if afterJSON["provider"] != "test-model" {
		t.Errorf("after_state.provider = %q, want %q", afterJSON["provider"], "test-model")
	}

	var chainCount int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM chat_audit_log WHERE channel_id = $1 AND action = 'translate.egress'`,
		channelID).Scan(&chainCount); err != nil {
		t.Fatalf("count chat_audit_log: %v", err)
	}
	if chainCount != 1 {
		t.Errorf("translate.egress chain rows = %d, want 1 (risk-4: one act write, not a per-send hot path)", chainCount)
	}
}

// ER5 occ_130c4ed3dfc8ef275164387e follow-up: after the startup upgrade
// rewrites a legacy plaintext assist.api_key into a setjoin-config-secret
// envelope, the translate lane reads it through the same codec — an envelope
// without the codec fails closed (503, the pre-upgrade posture) and with the
// codec decrypts transparently (availability restored, never ciphertext
// upstream). Both arms over the real HTTP route with a real envelope in
// system_config, matching how the ConfigStore writes the key.
func TestTranslateRouteEncryptedAPIKeyCodecArms(t *testing.T) {
	dsn := chatDSN(t)
	pool := chatTestPool(t, dsn)
	ctx := context.Background()

	codec, err := admin.NewConfigSecretCodec(admin.ConfigSecretKeyring{
		DeploymentID:  "chat-translate-codec-arm",
		ActiveVersion: 1,
		ActiveKey:     []byte("chat-translate-test-master-key-32byt"),
		ActiveProfile: cryptokey.ProfileStandard,
	})
	if err != nil {
		t.Fatalf("codec: %v", err)
	}
	sealed, err := codec.Encrypt("assist.api_key", json.RawMessage(`"sk-test-envelope-key"`))
	if err != nil {
		t.Fatalf("seal assist.api_key: %v", err)
	}

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The provider request must carry the DECRYPTED key as Bearer — a
		// raw envelope reaching here is the ciphertext-leak failure mode.
		auth := r.Header.Get("Authorization")
		if auth != "Bearer sk-test-envelope-key" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"你好"}}]}`))
	}))
	defer upstream.Close()

	if _, err := pool.Exec(ctx, `SELECT set_system_config('assist.provider_url', to_jsonb($1::text))`, upstream.URL); err != nil {
		t.Fatalf("set assist.provider_url: %v", err)
	}
	if _, err := pool.Exec(ctx, `SELECT set_system_config('assist.model', to_jsonb('test-model'::text))`); err != nil {
		t.Fatalf("set assist.model: %v", err)
	}
	if _, err := pool.Exec(ctx, `SELECT set_system_config('assist.api_key', $1::jsonb)`, string(sealed)); err != nil {
		t.Fatalf("set encrypted assist.api_key: %v", err)
	}

	owner := chatTestUser(t, pool, "a3xlateEnvOwner")
	var channelID int64
	if err := pool.QueryRow(ctx, `SELECT chat_channel_create($1, $2)`, owner, "a3-xlate-env-chan").Scan(&channelID); err != nil {
		t.Fatalf("chat_channel_create: %v", err)
	}
	send := chatDo(t, chat.NewHandler(pool, toggle.NewTestFlags(map[string]bool{"feature.chat": true, "feature.assist": true}), slog.Default()), owner, "POST", fmt.Sprintf("/chat/channels/%d/messages", channelID), `{"body":"hello there"}`)
	if send.Code != http.StatusCreated {
		t.Fatalf("send: want 201, got %d: %s", send.Code, send.Body.String())
	}
	var sent struct {
		MessageID int64 `json:"messageId"`
	}
	if err := json.Unmarshal(send.Body.Bytes(), &sent); err != nil {
		t.Fatalf("decode send: %v", err)
	}

	// Arm 1 — no codec wired: the envelope fails closed as 503 (never sent
	// upstream as a Bearer token).
	hNoCodec := chat.NewHandler(pool, toggle.NewTestFlags(map[string]bool{"feature.chat": true, "feature.assist": true}), slog.Default())
	rrNoCodec := chatDo(t, hNoCodec, owner, "POST", fmt.Sprintf("/chat/messages/%d/translate", sent.MessageID), `{"targetLocale":"zh"}`)
	if rrNoCodec.Code != http.StatusServiceUnavailable {
		t.Fatalf("envelope without codec: want 503 fail-closed, got %d: %s", rrNoCodec.Code, rrNoCodec.Body.String())
	}

	// Arm 2 — codec wired (the main.go posture): the envelope decrypts and
	// translate completes against the stub provider with the PLAINTEXT key.
	hWithCodec := chat.NewHandler(pool, toggle.NewTestFlags(map[string]bool{"feature.chat": true, "feature.assist": true}), slog.Default())
	hWithCodec.SetConfigSecretCodec(codec)
	rr := chatDo(t, hWithCodec, owner, "POST", fmt.Sprintf("/chat/messages/%d/translate", sent.MessageID), `{"targetLocale":"zh"}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("envelope with codec: want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var resp struct {
		Translated string `json:"translated"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode translate response: %v", err)
	}
	if resp.Translated != "你好" {
		t.Errorf("translated = %q, want %q", resp.Translated, "你好")
	}
}
