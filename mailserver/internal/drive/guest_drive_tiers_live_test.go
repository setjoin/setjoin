package drive

// Guest G4's DB-gated route proof: the same live Chat attachment is
// previewable through its office rendition while original bytes are denied;
// enabling the profile flag restores raw content, and soft-delete revokes
// both routes through the shared attachment-liveness predicate.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strconv"
	"testing"
	"time"

	"setjoin.com/shared/toggle"
)

func TestGuestDriveTiers_PreviewYesRawNo_Live(t *testing.T) {
	pool := driveLivePool(t)
	ctx := context.Background()
	for _, key := range []string{"feature.guest_accounts", "feature.drive", "feature.chat"} {
		withFeatureToggleEnabled(t, pool, key)
	}

	hostID := driveLiveUser(t, pool, "g4drivehost")
	suffix := strconv.FormatInt(time.Now().UnixNano(), 10)
	var hostDomainID int64
	if err := pool.QueryRow(ctx, `SELECT domain_id FROM users WHERE id=$1`, hostID).Scan(&hostDomainID); err != nil {
		t.Fatalf("resolve host domain: %v", err)
	}
	var guestID int64
	if err := pool.QueryRow(ctx, `
		INSERT INTO users(username, domain_id, email, display_name, enabled)
		SELECT $1, d.id, $2, 'G4 Drive External', TRUE
		  FROM domains d WHERE d.name='guest.invalid'
		RETURNING id`, "g4driveguest-"+suffix, "g4driveguest-"+suffix+"@external.example").Scan(&guestID); err != nil {
		t.Fatalf("create guest user: %v", err)
	}
	var profileID int64
	if err := pool.QueryRow(ctx, `
		INSERT INTO guest_profiles(host_domain_id, name, allow_download, apps)
		VALUES ($1, $2, false, ARRAY['chat','drive']::text[])
		RETURNING id`, hostDomainID, "g4-drive-view-"+suffix).Scan(&profileID); err != nil {
		t.Fatalf("create guest profile: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO guest_accounts
		       (user_id, invited_email, invited_by, invited_by_email, host_domain_id, profile_id, status, expires_at)
		SELECT $1, u.email, $2, inviter.email, $3, $4, 'active', now()+interval '1 day'
		  FROM users u CROSS JOIN users inviter
		 WHERE u.id=$1 AND inviter.id=$2`, guestID, hostID, hostDomainID, profileID); err != nil {
		t.Fatalf("create guest satellite: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO user_app_entitlements(user_id,app,enabled) VALUES ($1,'drive',true)`, guestID); err != nil {
		t.Fatalf("grant derived Drive entitlement: %v", err)
	}

	var channelID int64
	if err := pool.QueryRow(ctx, `SELECT chat_channel_create($1,$2)`, hostID, "g4-drive-"+suffix).Scan(&channelID); err != nil {
		t.Fatalf("chat_channel_create: %v", err)
	}
	if _, err := pool.Exec(ctx, `SELECT chat_member_add($1,$2,$3)`, hostID, channelID, guestID); err != nil {
		t.Fatalf("chat_member_add guest: %v", err)
	}
	var spaceID int64
	if err := pool.QueryRow(ctx, `SELECT chat_space_ensure($1,$2)`, hostID, channelID).Scan(&spaceID); err != nil {
		t.Fatalf("chat_space_ensure: %v", err)
	}

	fake := newFakeStore()
	h := NewHandler(pool, nil, fake, "b", toggle.NewTestFlags(map[string]bool{"feature.drive": true}), discardLogger())
	versionID := driveLiveOfficeVersion(t, pool, h, hostID, spaceID, "g4-brief.docx")
	var nodeID int64
	if err := pool.QueryRow(ctx, `SELECT file_node_id FROM drive_file_versions WHERE id=$1`, versionID).Scan(&nodeID); err != nil {
		t.Fatalf("resolve version node: %v", err)
	}

	// Attach the version to a real live message so the G2 remembered-id belt
	// admits it. Direct fixture insertion is deliberate: this test isolates
	// the read routes, while chat_message_send's attachment transaction has
	// its own integration suite.
	if _, err := pool.Exec(ctx, `UPDATE chat_channels SET change_seq=change_seq+1 WHERE id=$1`, channelID); err != nil {
		t.Fatalf("bump channel seq: %v", err)
	}
	var messageID int64
	if err := pool.QueryRow(ctx, `
		INSERT INTO chat_messages(channel_id,seq,author_id,body)
		SELECT $1, change_seq, $2, 'G4 office attachment' FROM chat_channels WHERE id=$1
		RETURNING id`, channelID, hostID).Scan(&messageID); err != nil {
		t.Fatalf("insert live attachment message: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO chat_message_attachments
		       (channel_id,message_id,file_node_id,version_id,filename,content_type,size_bytes)
		VALUES ($1,$2,$3,$4,'g4-brief.docx',
		        'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
		        length('pretend docx bytes'))`, channelID, messageID, nodeID, versionID); err != nil {
		t.Fatalf("link live attachment: %v", err)
	}

	previewSum := sha256.Sum256(fixturePDF)
	previewSHA := hex.EncodeToString(previewSum[:])
	if _, err := pool.Exec(ctx, `SELECT drive_preview_attach($1,$2,$3::jsonb,'ready')`, versionID, previewSHA,
		`[{"sha256":"`+previewSHA+`","size":`+strconv.Itoa(len(fixturePDF))+`}]`); err != nil {
		t.Fatalf("attach preview rendition: %v", err)
	}
	fake.objects["drive/g/"+previewSHA] = fixturePDF

	raw := driveLiveDo(t, h, guestID, http.MethodGet, "/drive/versions/"+strconv.FormatInt(versionID, 10)+"/content", nil)
	if raw.Code != http.StatusForbidden {
		t.Fatalf("view-only raw GET: want 403, got %d: %s", raw.Code, raw.Body.String())
	}
	if got := raw.Body.String(); got != "{\"type\":\"about:blank\",\"title\":\"Forbidden\",\"status\":403,\"detail\":\"forbidden\",\"instance\":\"/drive/versions/"+strconv.FormatInt(versionID, 10)+"/content\"}\n" {
		t.Fatalf("view-only raw GET must use the constant redacted BZ215 projection, body=%s", got)
	}

	preview := driveLiveDo(t, h, guestID, http.MethodGet, "/drive/versions/"+strconv.FormatInt(versionID, 10)+"/preview", nil)
	if preview.Code != http.StatusOK || !bytes.Equal(preview.Body.Bytes(), fixturePDF) {
		t.Fatalf("view-only preview GET: want ready PDF 200, got %d (%d bytes): %s", preview.Code, preview.Body.Len(), preview.Body.String())
	}

	if _, err := pool.Exec(ctx, `UPDATE guest_profiles SET allow_download=true WHERE id=$1`, profileID); err != nil {
		t.Fatalf("enable guest download: %v", err)
	}
	raw = driveLiveDo(t, h, guestID, http.MethodGet, "/drive/versions/"+strconv.FormatInt(versionID, 10)+"/content", nil)
	if raw.Code != http.StatusOK {
		t.Fatalf("download-enabled raw GET: want 200, got %d: %s", raw.Code, raw.Body.String())
	}

	if _, err := pool.Exec(ctx, `UPDATE chat_messages SET deleted_at=now() WHERE id=$1`, messageID); err != nil {
		t.Fatalf("soft-delete attachment message: %v", err)
	}
	preview = driveLiveDo(t, h, guestID, http.MethodGet, "/drive/versions/"+strconv.FormatInt(versionID, 10)+"/preview", nil)
	if preview.Code != http.StatusNotFound {
		t.Fatalf("soft-deleted attachment preview: want 404, got %d: %s", preview.Code, preview.Body.String())
	}
}
