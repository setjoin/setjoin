// attachments_route_test.go — Chat A2 Task 5: the ensure-space route, the
// attachments[] pass-through on send, the route-layer feature.drive gate on
// "the two attachment surfaces", and the conversations route's spaceId/
// attachmentsEnabled contract. DB-gated (chatDSN/chatTestPool/chatTestUser/
// chatDo, the tracer_integration_test.go genre).
package chat_test

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/mailserver/internal/chat"
	"setjoin.com/shared/jwtutil"
	"setjoin.com/shared/toggle"
)

func TestEnsureSpaceRoute(t *testing.T) {
	dsn := chatDSN(t)
	pool := chatTestPool(t, dsn)
	h := chat.NewHandler(pool, toggle.NewTestFlags(map[string]bool{"feature.chat": true, "feature.drive": true}), slog.Default())

	member := chatTestUser(t, pool, "a2ensureA")
	outsider := chatTestUser(t, pool, "a2ensureB")

	var channelID int64
	if err := pool.QueryRow(context.Background(), `SELECT chat_channel_create($1, $2)`, member, "a2-ensure-chan").Scan(&channelID); err != nil {
		t.Fatalf("chat_channel_create: %v", err)
	}

	rr := chatDo(t, h, member, "POST", fmt.Sprintf("/chat/channels/%d/space", channelID), "")
	if rr.Code != http.StatusOK {
		t.Fatalf("ensure space: want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var out struct {
		SpaceID int64 `json:"spaceId"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out.SpaceID == 0 {
		t.Fatal("ensure space: want a non-zero spaceId")
	}

	// A second ensure by the same member returns the SAME space id.
	rr2 := chatDo(t, h, member, "POST", fmt.Sprintf("/chat/channels/%d/space", channelID), "")
	if rr2.Code != http.StatusOK {
		t.Fatalf("second ensure: want 200, got %d: %s", rr2.Code, rr2.Body.String())
	}
	var out2 struct {
		SpaceID int64 `json:"spaceId"`
	}
	if err := json.Unmarshal(rr2.Body.Bytes(), &out2); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out2.SpaceID != out.SpaceID {
		t.Errorf("second ensure returned a different space id: %d, want %d", out2.SpaceID, out.SpaceID)
	}

	// A non-member is rejected (BZ163 -> forbidden) BEFORE any space work.
	rrForbidden := chatDo(t, h, outsider, "POST", fmt.Sprintf("/chat/channels/%d/space", channelID), "")
	if rrForbidden.Code != http.StatusForbidden {
		t.Errorf("non-member ensure: want 403, got %d: %s", rrForbidden.Code, rrForbidden.Body.String())
	}
}

func TestSendMessageAttachmentsPassThrough(t *testing.T) {
	dsn := chatDSN(t)
	pool := chatTestPool(t, dsn)
	ctx := context.Background()

	// chat_message_send's own BZ173 reducer-defense reads the DB row
	// directly — flip it for this test, restore after.
	var prevEnabled bool
	if err := pool.QueryRow(ctx, `SELECT enabled FROM feature_toggles WHERE key = 'feature.drive'`).Scan(&prevEnabled); err != nil {
		t.Fatalf("read feature.drive toggle: %v", err)
	}
	if _, err := pool.Exec(ctx, `UPDATE feature_toggles SET enabled = true WHERE key = 'feature.drive'`); err != nil {
		t.Fatalf("enable feature.drive: %v", err)
	}
	t.Cleanup(func() {
		pool.Exec(context.Background(), `UPDATE feature_toggles SET enabled = $1 WHERE key = 'feature.drive'`, prevEnabled) //nolint:errcheck
	})

	h := chat.NewHandler(pool, toggle.NewTestFlags(map[string]bool{"feature.chat": true, "feature.drive": true}), slog.Default())
	author := chatTestUser(t, pool, "a2sendattA")

	var channelID int64
	if err := pool.QueryRow(ctx, `SELECT chat_channel_create($1, $2)`, author, "a2-send-attach").Scan(&channelID); err != nil {
		t.Fatalf("chat_channel_create: %v", err)
	}

	// Register a real chunk claim (proof-of-possession) exactly the way a
	// real chunk PUT does under the hood — drive_chunk_register is the same
	// reducer chat_attachments.pg's own pgTAP fixture uses, not a bypass.
	sha := "aa11223344556677889900112233445566778899001122334455667788990011"
	var spaceIDForClaim int64
	if err := pool.QueryRow(ctx, `SELECT chat_space_ensure($1, $2)`, author, channelID).Scan(&spaceIDForClaim); err != nil {
		t.Fatalf("chat_space_ensure (pre-provision for the claim): %v", err)
	}
	if _, err := pool.Exec(ctx, `SELECT drive_chunk_register($1, $2, $3, $4)`, author, spaceIDForClaim, sha, 11); err != nil {
		t.Fatalf("drive_chunk_register: %v", err)
	}

	body := fmt.Sprintf(`{"body":"see attached","attachments":[{"sha256":%q,"size":11,"name":"hello.txt","contentType":"text/plain","manifest":[{"sha256":%q,"size":11}]}]}`, sha, sha)
	rr := chatDo(t, h, author, "POST", fmt.Sprintf("/chat/channels/%d/messages", channelID), body)
	if rr.Code != http.StatusCreated {
		t.Fatalf("send with attachment: want 201, got %d: %s", rr.Code, rr.Body.String())
	}
	var sent struct {
		MessageID int64 `json:"messageId"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &sent); err != nil {
		t.Fatalf("decode send: %v", err)
	}

	var filename string
	var sizeBytes int64
	if err := pool.QueryRow(ctx, `SELECT filename, size_bytes FROM chat_message_attachments WHERE message_id = $1`, sent.MessageID).
		Scan(&filename, &sizeBytes); err != nil {
		t.Fatalf("attachments[] did not reach the reducer (no chat_message_attachments row): %v", err)
	}
	if filename != "hello.txt" || sizeBytes != 11 {
		t.Errorf("attachment row = (%q, %d), want (\"hello.txt\", 11)", filename, sizeBytes)
	}
}

// TestAttachmentSurfacesDriveOff404 pins Task 5's route gate: the two
// attachment surfaces (ensure-space, an attachments-bearing send) 404 while
// feature.drive is off; plain messaging is completely unaffected, and the
// conversations route reports attachmentsEnabled:false.
func TestAttachmentSurfacesDriveOff404(t *testing.T) {
	dsn := chatDSN(t)
	pool := chatTestPool(t, dsn)
	h := chat.NewHandler(pool, toggle.NewTestFlags(map[string]bool{"feature.chat": true, "feature.drive": false}), slog.Default())

	author := chatTestUser(t, pool, "a2offA")
	var channelID int64
	if err := pool.QueryRow(context.Background(), `SELECT chat_channel_create($1, $2)`, author, "a2-off-chan").Scan(&channelID); err != nil {
		t.Fatalf("chat_channel_create: %v", err)
	}

	rrSpace := chatDo(t, h, author, "POST", fmt.Sprintf("/chat/channels/%d/space", channelID), "")
	if rrSpace.Code != http.StatusNotFound {
		t.Errorf("ensure-space with feature.drive off: want 404, got %d", rrSpace.Code)
	}

	rrAttach := chatDo(t, h, author, "POST", fmt.Sprintf("/chat/channels/%d/messages", channelID),
		`{"body":"x","attachments":[{"sha256":"deadbeef","size":1,"name":"a","manifest":[]}]}`)
	if rrAttach.Code != http.StatusNotFound {
		t.Errorf("attachments-bearing send with feature.drive off: want 404, got %d: %s", rrAttach.Code, rrAttach.Body.String())
	}

	// Plain messaging (no attachments) is unaffected by the drive gate.
	rrPlain := chatDo(t, h, author, "POST", fmt.Sprintf("/chat/channels/%d/messages", channelID), `{"body":"plain text still works"}`)
	if rrPlain.Code != http.StatusCreated {
		t.Errorf("plain send with feature.drive off: want 201 (chat itself unaffected), got %d: %s", rrPlain.Code, rrPlain.Body.String())
	}

	rrConv := chatDo(t, h, author, "GET", "/chat/conversations", "")
	if rrConv.Code != http.StatusOK {
		t.Fatalf("GET conversations: want 200, got %d", rrConv.Code)
	}
	var conv struct {
		AttachmentsEnabled bool `json:"attachmentsEnabled"`
	}
	if err := json.Unmarshal(rrConv.Body.Bytes(), &conv); err != nil {
		t.Fatalf("decode conversations: %v", err)
	}
	if conv.AttachmentsEnabled {
		t.Error("attachmentsEnabled: want false with feature.drive off")
	}
}

// TestSendMessageNullAndEmptyAttachmentsAreNotAttachmentsBearing pins the
// null-vs-[] handler bug class (root AGENTS.md): explicit JSON
// `"attachments": null` and `"attachments": []` must both be treated as
// PLAIN messages, not "attachments-bearing" — with feature.drive OFF they
// must NOT 404 (the raw bytes `null`/`[]` are non-zero-length RawMessage, so
// a bare len==0 check misreads them), and with feature.drive ON they must
// not reach chat_message_send as anything jsonb_array_length can choke on.
func TestSendMessageNullAndEmptyAttachmentsAreNotAttachmentsBearing(t *testing.T) {
	dsn := chatDSN(t)
	pool := chatTestPool(t, dsn)

	author := chatTestUser(t, pool, "a2nullattA")
	var channelID int64
	if err := pool.QueryRow(context.Background(), `SELECT chat_channel_create($1, $2)`, author, "a2-nullattach-chan").Scan(&channelID); err != nil {
		t.Fatalf("chat_channel_create: %v", err)
	}

	for _, drive := range []bool{false, true} {
		h := chat.NewHandler(pool, toggle.NewTestFlags(map[string]bool{"feature.chat": true, "feature.drive": drive}), slog.Default())
		for _, body := range []string{
			`{"body":"plain via null","attachments":null}`,
			`{"body":"plain via empty array","attachments":[]}`,
		} {
			rr := chatDo(t, h, author, "POST", fmt.Sprintf("/chat/channels/%d/messages", channelID), body)
			if rr.Code != http.StatusCreated {
				t.Errorf("feature.drive=%v body=%s: want 201, got %d: %s", drive, body, rr.Code, rr.Body.String())
			}
		}
	}
}

// TestConversationsAttachmentsEnabledTrueAndSpaceId pins the happy-path
// contract: attachmentsEnabled:true with both toggles on, and spaceId rides
// through per-conversation (NULL until ensured, then sticky).
func TestConversationsAttachmentsEnabledTrueAndSpaceId(t *testing.T) {
	dsn := chatDSN(t)
	pool := chatTestPool(t, dsn)
	h := chat.NewHandler(pool, toggle.NewTestFlags(map[string]bool{"feature.chat": true, "feature.drive": true}), slog.Default())

	member := chatTestUser(t, pool, "a2convA")
	var channelID int64
	if err := pool.QueryRow(context.Background(), `SELECT chat_channel_create($1, $2)`, member, "a2-conv-chan").Scan(&channelID); err != nil {
		t.Fatalf("chat_channel_create: %v", err)
	}

	rr := chatDo(t, h, member, "GET", "/chat/conversations", "")
	if rr.Code != http.StatusOK {
		t.Fatalf("GET conversations: want 200, got %d", rr.Code)
	}
	var conv struct {
		AttachmentsEnabled bool             `json:"attachmentsEnabled"`
		Conversations      []map[string]any `json:"conversations"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &conv); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !conv.AttachmentsEnabled {
		t.Error("attachmentsEnabled: want true with both toggles on")
	}
	var found map[string]any
	for _, c := range conv.Conversations {
		if int64(c["channelId"].(float64)) == channelID {
			found = c
		}
	}
	if found == nil {
		t.Fatal("channel missing from conversations list")
	}
	if found["spaceId"] != nil {
		t.Errorf("spaceId = %v, want nil before any ensure", found["spaceId"])
	}

	ensureRR := chatDo(t, h, member, "POST", fmt.Sprintf("/chat/channels/%d/space", channelID), "")
	if ensureRR.Code != http.StatusOK {
		t.Fatalf("ensure space: want 200, got %d", ensureRR.Code)
	}
	var ensured struct {
		SpaceID int64 `json:"spaceId"`
	}
	if err := json.Unmarshal(ensureRR.Body.Bytes(), &ensured); err != nil {
		t.Fatalf("decode ensure: %v", err)
	}

	rr2 := chatDo(t, h, member, "GET", "/chat/conversations", "")
	var conv2 struct {
		Conversations []map[string]any `json:"conversations"`
	}
	if err := json.Unmarshal(rr2.Body.Bytes(), &conv2); err != nil {
		t.Fatalf("decode: %v", err)
	}
	for _, c := range conv2.Conversations {
		if int64(c["channelId"].(float64)) == channelID {
			if int64(c["spaceId"].(float64)) != ensured.SpaceID {
				t.Errorf("spaceId = %v, want %d after ensure", c["spaceId"], ensured.SpaceID)
			}
		}
	}
}

func TestConversationsAttachmentsDisabledForGuestViewer(t *testing.T) {
	dsn := chatDSN(t)
	pool := chatTestPool(t, dsn)
	h := chat.NewHandler(pool, toggle.NewTestFlags(map[string]bool{"feature.chat": true, "feature.drive": true}), slog.Default())

	member := chatTestUser(t, pool, "g4convguest")
	req := httptest.NewRequest(http.MethodGet, "/chat/conversations", nil)
	req = req.WithContext(auth.ContextWithUser(req.Context(), &jwtutil.Claims{
		UserID: member, AccountType: jwtutil.AccountTypeGuest,
	}))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("GET conversations as guest claim: want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var out struct {
		AttachmentsEnabled bool `json:"attachmentsEnabled"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode conversations: %v", err)
	}
	if out.AttachmentsEnabled {
		t.Fatal("attachmentsEnabled: want false for a G4 guest viewer even with Chat and Drive toggles on")
	}
}
