// admin_chat_ediscovery_export.go — Chat A4b Task 7: the streamed ZIP export
// (spec §7 verbatim artifact contract, §6.1 row 5, D-B, L8, §14 "Export
// (Go)"). Depends on Tasks 4-6 (chat_ediscovery_export_begin,
// chat_ediscovery_message_json, ChatEDiscoveryHandler.requireEDiscoveryClaims).
//
// The whole export runs in exactly TWO database round-trip shapes: (1)
// chat_ediscovery_export_begin on workerPool — its OWN implicit txn, writes
// the export.run acts + the kind='export' search row and commits BEFORE
// anything is streamed; (2) ONE REPEATABLE READ read-only transaction opened
// AFTER that commit, which every content/count read in this file runs
// inside. Counts are computed in the SAME SNAPSHOT that streams the
// content — content committed between (1) and (2) can never diverge
// manifest.json from messages.jsonl, and manifest.json is the ZIP's LAST
// entry: its per-channel counts and the whole-file sha256 of messages.jsonl
// cannot exist before those bytes do.
//
// pgx gives ONE query at a time on a single tx/conn (ErrConnBusy on a nested
// query while a rows cursor is open) — every multi-row read here is fully
// drained and rows.Close()'d before the next query starts on the same tx.
package admin

import (
	"archive/zip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/minio/minio-go/v7"

	"setjoin.com/mailserver/internal/audit"
	"setjoin.com/shared/httputil"
)

// exportTxOptions is the ONE export read transaction (spec §7): REPEATABLE
// READ + read-only, opened AFTER chat_ediscovery_export_begin commits.
var exportTxOptions = pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly}

// exportDisclaimers is the fixed L8/contract-#3 language, verbatim in every
// manifest (and mirrored in the console i18n — Task 10). Do not soften it.
// exportDisclaimers[2] is the canonical L8 sentence — Task 10's i18n mirrors
// it character-for-character.
var exportDisclaimers = []string{
	"Chain heads pin the per-channel audit-chain state at export time; verify with the chain verifier and retain off-box.",
	"This record begins above the recorded purge floors. lastPurgedSeq is provenance only, never a replayable cursor (seq is re-stamped on edit).",
	"The audit chain proves what the destroyedElems leaves say and nothing more: it does not prove that a specific held message was not destroyed, and no claim is made about records that never existed.",
}

// ── begin-result decode shapes (chat_ediscovery_export_begin's JSONB) ──────

type exportChainHead struct {
	ID       int64  `json:"id"`
	Checksum string `json:"checksum"`
}

type exportBeginChannel struct {
	ChannelID     int64           `json:"channelId"`
	ExportActID   int64           `json:"exportActId"`
	ChainHead     exportChainHead `json:"chainHead"`
	LastPurgedSeq int64           `json:"lastPurgedSeq"`
	PurgeActs     json.RawMessage `json:"purgeActs"`
}

type exportBeginResult struct {
	SearchID int64                `json:"searchId"`
	Channels []exportBeginChannel `json:"channels"`
}

// ── manifest.json shape ─────────────────────────────────────────────────────

type exportManifestChannel struct {
	ChannelID       int64           `json:"channelId"`
	MessageCount    int             `json:"messageCount"`
	RevisionCount   int             `json:"revisionCount"`
	ScheduledCount  int             `json:"scheduledCount"`
	AttachmentCount int             `json:"attachmentCount"`
	ChainHead       exportChainHead `json:"chainHead"`
	LastPurgedSeq   int64           `json:"lastPurgedSeq"`
	PurgeActs       json.RawMessage `json:"purgeActs"`
	ExportActID     int64           `json:"exportActId"`
}

// ── federated room coverage facts (Pillar C2 Task 8 Step 1, ratified Q1) ───
//
// "Every ACCEPTED message is archived by each org WHILE ACTIVELY
// RECEIVING" — parking + no-backfill make an unconditional "full stream"
// claim false, so the manifest must PROVE its own coverage boundary rather
// than merely assert completeness. Sourced from federation_room_members
// (invited_at / left_at+left_reason / coverage_epochs, V140) — read on
// h.workerPool (BYPASSRLS), the SAME connection every other manifest field
// in this file is read from; federation_room_members/federation_rooms are
// FORCE RLS deny-all-to-setjoin_app, but the export's own tx already runs
// on the BYPASSRLS worker pool (the plan's "if the export runs on the
// tenant pool, add a small DEFINER read reducer instead" fallback does not
// apply here — verified at exec).
type coverageInterval struct {
	From   time.Time  `json:"from"`
	To     *time.Time `json:"to"` // nil = gap ongoing at export time (an open coverage_epochs entry)
	Reason string     `json:"reason"`
}

type federatedRoomMemberCoverage struct {
	Domain                string             `json:"domain"`
	JoinedAt              time.Time          `json:"joinedAt"` // federation_room_members.invited_at
	RemovedAt             *time.Time         `json:"removedAt,omitempty"`
	RemovedReason         string             `json:"removedReason,omitempty"` // 'removed' | 'revoked'
	KnownMissingIntervals []coverageInterval `json:"knownMissingIntervals"`
}

// federatedRoomDisclosure is one exported room-bound channel's coverage
// block. IsHub branches the manifest.Disclaimers text (federatedHub/
// federatedSpokeDisclaimer below) — a spoke-worded sentence on a hub export
// would UNDERSELL the record (the ratified Q1 honesty: every "authoritative"
// claim is qualified).
type federatedRoomDisclosure struct {
	ChannelID int64                         `json:"channelId"`
	RoomID    string                        `json:"roomId"`
	HubDomain string                        `json:"hubDomain"`
	IsHub     bool                          `json:"isHub"`
	Members   []federatedRoomMemberCoverage `json:"members"`
}

// coverageEpochRaw decodes one federation_room_members.coverage_epochs
// element ({parkedAt, resumedAt, reason} — V140/the Q9 ratified split).
// resumedAt absent (nil) means the gap is still open at export time.
type coverageEpochRaw struct {
	ParkedAt  time.Time  `json:"parkedAt"`
	ResumedAt *time.Time `json:"resumedAt"`
	Reason    string     `json:"reason"`
}

// The Q1-ratified disclaimer lines (Task 8 Step 1) — verbatim, the artifact
// lawyers read. federatedSpokeDisclaimer's "%s" is the hub domain (or a
// comma-joined set, the rare case an export spans spoke mirrors of rooms
// hosted by different hubs).
const (
	federatedSpokeDisclaimer = "One or more exported channels are spoke mirrors of federated multi-org rooms. " +
		"This archive is THIS organization's copy of every message it accepted while actively receiving, " +
		"from its join date forward; delivery gaps (if any) are listed per member organization in this manifest. " +
		"Other member organizations hold independent copies governed by their own retention. " +
		"The hub organization (%s) holds the hub's record of messages it accepted and relayed."

	federatedHubDisclaimer = "One or more exported channels are federated multi-org rooms for which THIS organization is the hub. " +
		"This archive is the hub's record of messages it accepted and relayed (messages refused at ingest never entered it); " +
		"member organizations hold independent copies of what each accepted while actively receiving, governed by their own retention " +
		"— per-member coverage boundaries are listed in this manifest."

	federatedOutboxResidueDisclaimer = "Federation transport queues are delivery residue, not an archive: they may retain redacted " +
		"delivery envelopes, and undelivered message bodies queued to unreachable member organizations, after local purge; " +
		"see the retention policy."

	federatedTypingExclusionDisclaimer = "Ephemeral typing signals are not archived and are excluded from eDiscovery by design."
)

type exportManifest struct {
	CaseID         int64                     `json:"caseId"`
	CaseName       string                    `json:"caseName"`
	Query          json.RawMessage           `json:"query"`
	ExportedBy     int64                     `json:"exportedBy"`
	ExecutedAt     time.Time                 `json:"executedAt"`
	SearchID       int64                     `json:"searchId"`
	Channels       []exportManifestChannel   `json:"channels"`
	MessagesSha256 string                    `json:"messagesSha256"`
	Disclaimers    []string                  `json:"disclaimers"`
	FederatedRooms []federatedRoomDisclosure `json:"federatedRooms,omitempty"`
}

// exportScheduledLine is a scheduled (pending/failed) chat_send row's
// messages.jsonl representation (contract #7, review F4: scheduledActionId
// is a uuid STRING, never a JSON number — scheduled_actions.id is uuid).
//
// Pillar C1 Task 4 (N1 fix): AuthorID is *int64, not int64 — a scheduled
// row's payload->>'userId' cast to bigint scans as SQL NULL whenever the
// key is absent/malformed, and pgx hard-errors scanning NULL into a
// non-pointer int64 (the same null-author trap V139 made reachable for
// chat_messages.author_id — this struct closes it for the scheduled leg
// too, defensively, since scheduled sends and federated messages now share
// one export path). FederatedSenderAddr rides alongside it so a federated
// row's attribution is always the REMOTE ADDRESS, never a bare local id —
// scheduled_actions carries no federated-sender concept today (a scheduled
// send is always authored by a local user), so it is always empty for this
// leg; chat_ediscovery_message_json (chat_ediscovery_read.sql) is where the
// messages.jsonl leg gets it, since that leg streams raw JSONB bytes
// through with no Go struct at all.
type exportScheduledLine struct {
	Type                string    `json:"type"`
	ScheduledActionID   string    `json:"scheduledActionId"`
	ChannelID           int64     `json:"channelId"`
	AuthorID            *int64    `json:"authorId"`
	FederatedSenderAddr string    `json:"federatedSenderAddr,omitempty"`
	Status              string    `json:"status"`
	FireAt              time.Time `json:"fireAt"`
	Body                *string   `json:"body"`
}

// parseExportChannelIDs comma-splits the channels query param into int64s,
// 400ing (via a nil, non-nil-error return) on any unparseable entry — an
// export scope typo must not silently drop a channel from the record.
func parseExportChannelIDs(s string) ([]int64, error) {
	parts := strings.Split(s, ",")
	out := make([]int64, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		id, err := strconv.ParseInt(p, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid channel id %q: %w", p, err)
		}
		out = append(out, id)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("channels is required")
	}
	return out, nil
}

// Export implements GET /admin/chat-ediscovery/export. chat.ediscovery only.
// See the package doc comment above for the two-round-trip shape.
func (h *ChatEDiscoveryHandler) Export(w http.ResponseWriter, r *http.Request) {
	if !h.gate(w, r) {
		return
	}
	claims, ok := h.requireEDiscoveryClaims(w, r)
	if !ok {
		return
	}
	ctx := r.Context()

	q := r.URL.Query()
	caseIDStr := q.Get("caseId")
	if caseIDStr == "" {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "caseId is required"})
		return
	}
	caseID, err := strconv.ParseInt(caseIDStr, 10, 64)
	if err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "invalid caseId"})
		return
	}
	channelIDs, err := parseExportChannelIDs(q.Get("channels"))
	if err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: err.Error()})
		return
	}
	includeAttachments := q.Get("includeAttachments") == "1"

	queryJSON, err := json.Marshal(map[string]any{"channels": channelIDs, "includeAttachments": includeAttachments})
	if err != nil {
		httputil.WriteDBErr(w, r, h.logger, "marshal ediscovery export query failed", err)
		return
	}

	// Step 1: begin on workerPool — its OWN implicit txn, commits the
	// export.run acts + the kind='export' search row BEFORE anything
	// streams. Errors here happen BEFORE any header is written.
	var beginRaw []byte
	err = h.workerPool.QueryRow(ctx, `SELECT chat_ediscovery_export_begin($1, $2, $3, $4)`,
		claims.UserID, caseID, channelIDs, queryJSON).Scan(&beginRaw)
	if err != nil {
		if h.mapErr(w, r, err) {
			return
		}
		httputil.WriteDBErr(w, r, h.logger, "chat_ediscovery_export_begin failed", err)
		return
	}
	var begin exportBeginResult
	if err := json.Unmarshal(beginRaw, &begin); err != nil {
		httputil.WriteDBErr(w, r, h.logger, "decode chat_ediscovery_export_begin failed", err)
		return
	}

	_ = audit.Write(ctx, h.pool, audit.Entry{
		Actor: claims.UserID, Action: "chat_ediscovery_export", TargetType: "ediscovery_case", TargetID: &caseID,
		IP: httputil.ClientIP(r), Tier: "core",
	})

	// Step 2: ONE REPEATABLE READ read-only transaction for the entire
	// export — every count/content read below runs inside it.
	tx, err := h.workerPool.BeginTx(ctx, exportTxOptions)
	if err != nil {
		httputil.WriteDBErr(w, r, h.logger, "begin export tx failed", err)
		return
	}
	// review F10: context.WithoutCancel — a mid-stream client disconnect or
	// request-context cancellation must not race the rollback itself; a
	// canceled ctx here can make Rollback silently fail to run, leaving the
	// connection in an unclean state until the pool's own health check
	// notices (rather than the ordinary, cheap rollback path).
	defer tx.Rollback(context.WithoutCancel(ctx)) //nolint:errcheck // read-only tx; rollback-on-return is a no-op after nothing was ever committed

	var caseName string
	if err := tx.QueryRow(ctx, `SELECT name FROM ediscovery_cases WHERE id = $1`, caseID).Scan(&caseName); err != nil {
		httputil.WriteDBErr(w, r, h.logger, "read case name failed", err)
		return
	}

	// Headers + the mbox-export precedent (admin_ediscovery.go:432-511):
	// nosniff + attachment disposition, written before any zip byte.
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=chat-ediscovery-case%d-%s.zip",
		caseID, time.Now().UTC().Format("20060102-150405")))
	w.WriteHeader(http.StatusOK)

	// Mid-stream errors after this point: log + ABANDON the stream (the
	// admin_ediscovery.go:502 posture) — no zw.Close(), so the response
	// never gets a valid End-Of-Central-Directory record. A truncated ZIP
	// missing its manifest is self-evidently incomplete, which is exactly
	// why manifest.json is written LAST.
	abandon := func(msg string, err error, channelID int64) {
		h.logger.Error("chat ediscovery export: "+msg, "channel_id", channelID, "error", err)
	}

	zw := zip.NewWriter(w)
	mw, err := zw.Create("messages.jsonl")
	if err != nil {
		abandon("create messages.jsonl entry failed", err, 0)
		return
	}
	hasher := sha256.New()
	out := io.MultiWriter(mw, hasher)

	// C2 Task 8 Step 1: federated-room coverage facts + the flags that drive
	// the conditional disclaimer lines below — collected alongside the
	// per-channel message stream, same RR snapshot as everything else.
	manifestChannels := make([]exportManifestChannel, 0, len(begin.Channels))
	var federatedRooms []federatedRoomDisclosure
	var hasHubRoom, hasSpokeRoom, hasFederatedDM bool
	spokeHubDomains := map[string]struct{}{}
	for _, ch := range begin.Channels {
		mc, err := h.streamExportChannel(ctx, tx, out, ch)
		if err != nil {
			abandon("stream channel content failed", err, ch.ChannelID)
			return
		}
		manifestChannels = append(manifestChannels, mc)

		disclosure, isFederatedDM, err := h.federationCoverageFor(ctx, tx, ch.ChannelID)
		if err != nil {
			abandon("read federation coverage failed", err, ch.ChannelID)
			return
		}
		switch {
		case disclosure != nil && disclosure.IsHub:
			hasHubRoom = true
			federatedRooms = append(federatedRooms, *disclosure)
		case disclosure != nil:
			hasSpokeRoom = true
			spokeHubDomains[disclosure.HubDomain] = struct{}{}
			federatedRooms = append(federatedRooms, *disclosure)
		case isFederatedDM:
			hasFederatedDM = true
		}
	}

	if includeAttachments {
		if err := h.streamExportAttachments(ctx, tx, zw, begin.Channels); err != nil {
			abandon("stream attachments failed", err, 0)
			return
		}
	}

	disclaimers := append([]string(nil), exportDisclaimers...)
	if hasSpokeRoom {
		hubs := make([]string, 0, len(spokeHubDomains))
		for d := range spokeHubDomains {
			hubs = append(hubs, d)
		}
		sort.Strings(hubs)
		disclaimers = append(disclaimers, fmt.Sprintf(federatedSpokeDisclaimer, strings.Join(hubs, ", ")))
	}
	if hasHubRoom {
		disclaimers = append(disclaimers, federatedHubDisclaimer)
	}
	if hasHubRoom || hasSpokeRoom || hasFederatedDM {
		disclaimers = append(disclaimers, federatedOutboxResidueDisclaimer, federatedTypingExclusionDisclaimer)
	}

	manifest := exportManifest{
		CaseID: caseID, CaseName: caseName, Query: json.RawMessage(queryJSON), ExportedBy: claims.UserID,
		ExecutedAt: time.Now().UTC(), SearchID: begin.SearchID, Channels: manifestChannels,
		MessagesSha256: hex.EncodeToString(hasher.Sum(nil)), Disclaimers: disclaimers,
		FederatedRooms: federatedRooms,
	}
	mf, err := zw.Create("manifest.json")
	if err != nil {
		abandon("create manifest.json entry failed", err, 0)
		return
	}
	if err := json.NewEncoder(mf).Encode(manifest); err != nil {
		abandon("encode manifest.json failed", err, 0)
		return
	}
	if err := zw.Close(); err != nil {
		h.logger.Error("chat ediscovery export: close zip failed", "error", err)
		return
	}
}

// streamExportChannel writes one channel's messages.jsonl content — the
// canonical per-message projection (chat_ediscovery_message_json, ordered
// (channel_id, id)) then the channel's pending/failed scheduled chat_send
// rows — to out, and returns the manifest row for it. revisionCount/
// attachmentCount come from COUNT(*) on the SAME tx (snapshot-identical to
// the streamed rows, plan-time delta 4) — attachmentCount NEVER from the
// attachments zip stream (review F6: that stream is deduped by content
// sha256, not one entry per attachment row).
//
// review F2: lastPurgedSeq/purgeActs are re-read HERE, inside the RR tx, per
// channel — NOT taken from ch.LastPurgedSeq/ch.PurgeActs (chat_ediscovery_
// export_begin's BEGIN-time values). Begin runs before the RR tx opens, so a
// purge committing in the gap between begin and this read would otherwise
// stamp the manifest with a floor the streamed content has already moved
// past — content missing above the claimed floor with no explaining act.
// chainHead is ALSO re-read at the RR snapshot (re-score residual): the
// manifest's retained-off-box pin must cover every act the manifest itself
// lists — a gap-committed purge act with actId > a begin-time head would sit
// un-pinned until the next export. The RR head is ≥ the begin head by
// construction (begin's export.run act committed before the snapshot opened),
// so nothing is lost. Only exportActId stays from begin (it identifies THIS
// export's act; the head vouches for the chain up to and including it).
// Queries mirror chat_ediscovery_read.sql's last_purged_seq/purgeActs shape
// verbatim (single-homed intent — any drift there should be reflected here
// too).
//
// ONE query at a time (review F2): each multi-row Query below is fully
// drained + rows.Close()'d before the next one starts on this tx.
func (h *ChatEDiscoveryHandler) streamExportChannel(ctx context.Context, tx pgx.Tx, out io.Writer, ch exportBeginChannel) (exportManifestChannel, error) {
	messageCount := 0
	rows, err := tx.Query(ctx, `SELECT chat_ediscovery_message_json(m.id) FROM chat_messages m WHERE m.channel_id = $1 ORDER BY m.id`, ch.ChannelID)
	if err != nil {
		return exportManifestChannel{}, fmt.Errorf("query messages: %w", err)
	}
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			rows.Close()
			return exportManifestChannel{}, fmt.Errorf("scan message: %w", err)
		}
		if _, err := out.Write(raw); err != nil {
			rows.Close()
			return exportManifestChannel{}, fmt.Errorf("write message: %w", err)
		}
		if _, err := out.Write([]byte("\n")); err != nil {
			rows.Close()
			return exportManifestChannel{}, fmt.Errorf("write message newline: %w", err)
		}
		messageCount++
	}
	rowsErr := rows.Err()
	rows.Close()
	if rowsErr != nil {
		return exportManifestChannel{}, fmt.Errorf("stream messages: %w", rowsErr)
	}

	scheduledCount := 0
	schedRows, err := tx.Query(ctx, `SELECT sa.id::text, (sa.payload->>'userId')::bigint, sa.status, sa.fire_at, sa.payload->>'body'
		FROM scheduled_actions sa
		WHERE sa.action_kind = 'chat_send' AND sa.status IN ('pending', 'failed')
		  AND (sa.payload->>'channelId')::bigint = $1
		ORDER BY sa.id`, ch.ChannelID)
	if err != nil {
		return exportManifestChannel{}, fmt.Errorf("query scheduled rows: %w", err)
	}
	for schedRows.Next() {
		var line exportScheduledLine
		line.Type = "scheduledSend"
		line.ChannelID = ch.ChannelID
		if err := schedRows.Scan(&line.ScheduledActionID, &line.AuthorID, &line.Status, &line.FireAt, &line.Body); err != nil {
			schedRows.Close()
			return exportManifestChannel{}, fmt.Errorf("scan scheduled row: %w", err)
		}
		lineJSON, err := json.Marshal(line)
		if err != nil {
			schedRows.Close()
			return exportManifestChannel{}, fmt.Errorf("marshal scheduled row: %w", err)
		}
		if _, err := out.Write(lineJSON); err != nil {
			schedRows.Close()
			return exportManifestChannel{}, fmt.Errorf("write scheduled row: %w", err)
		}
		if _, err := out.Write([]byte("\n")); err != nil {
			schedRows.Close()
			return exportManifestChannel{}, fmt.Errorf("write scheduled row newline: %w", err)
		}
		scheduledCount++
	}
	schedRowsErr := schedRows.Err()
	schedRows.Close()
	if schedRowsErr != nil {
		return exportManifestChannel{}, fmt.Errorf("stream scheduled rows: %w", schedRowsErr)
	}

	var revisionCount int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM chat_message_revisions rv JOIN chat_messages m ON m.id = rv.message_id WHERE m.channel_id = $1`, ch.ChannelID).Scan(&revisionCount); err != nil {
		return exportManifestChannel{}, fmt.Errorf("count revisions: %w", err)
	}
	var attachmentCount int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM chat_message_attachments a JOIN chat_messages m ON m.id = a.message_id WHERE m.channel_id = $1`, ch.ChannelID).Scan(&attachmentCount); err != nil {
		return exportManifestChannel{}, fmt.Errorf("count attachments: %w", err)
	}

	// review F2: re-read fresh, inside this RR tx — never ch.LastPurgedSeq/
	// ch.PurgeActs (begin-time values, read before the RR tx opened).
	var lastPurgedSeq int64
	if err := tx.QueryRow(ctx, `SELECT last_purged_seq FROM chat_channels WHERE id = $1`, ch.ChannelID).Scan(&lastPurgedSeq); err != nil {
		return exportManifestChannel{}, fmt.Errorf("read last_purged_seq: %w", err)
	}
	// Re-pin the chain head at the RR snapshot (see the function comment): the
	// head must cover every act this manifest lists, including any purge act
	// that committed in the begin→RR gap.
	chainHead := ch.ChainHead
	if err := tx.QueryRow(ctx, `SELECT a.id, a.after_state->>'_checksum' FROM chat_audit_log a
		WHERE a.channel_id = $1 ORDER BY a.id DESC LIMIT 1`, ch.ChannelID).Scan(&chainHead.ID, &chainHead.Checksum); err != nil {
		return exportManifestChannel{}, fmt.Errorf("read chain head: %w", err)
	}
	var purgeActs []byte
	if err := tx.QueryRow(ctx, `SELECT COALESCE(jsonb_agg(jsonb_build_object(
			'actId', pa.id, 'idFrom', (pa.after_state->>'idFrom')::bigint,
			'idTo', (pa.after_state->>'idTo')::bigint,
			'purgedCount', (pa.after_state->>'purgedCount')::int) ORDER BY pa.id), '[]'::jsonb)
		FROM chat_audit_log pa
		WHERE pa.channel_id = $1 AND pa.action = 'purge.execute'`, ch.ChannelID).Scan(&purgeActs); err != nil {
		return exportManifestChannel{}, fmt.Errorf("read purge acts: %w", err)
	}

	return exportManifestChannel{
		ChannelID: ch.ChannelID, MessageCount: messageCount, RevisionCount: revisionCount,
		ScheduledCount: scheduledCount, AttachmentCount: attachmentCount, ChainHead: chainHead,
		LastPurgedSeq: lastPurgedSeq, PurgeActs: purgeActs, ExportActID: ch.ExportActID,
	}, nil
}

// federationCoverageFor reads ONE exported channel's federation binding
// (Pillar C2 Task 8 Step 1, ratified Q1) inside the SAME RR transaction
// every other manifest field is read from. Returns:
//   - (disclosure, false, nil) for a room-bound channel (disclosure.IsHub
//     distinguishes the hub/spoke shape — Task 1's "federated_room_id set +
//     federated_peer_domain NULL IS the hub self-check").
//   - (nil, true, nil) for a federated-DM channel (federated_peer_domain set,
//     federated_room_id NULL) — DMs carry no roster to project, but still
//     drive the outbox-residue/typing disclaimer lines below.
//   - (nil, false, nil) for a plain, non-federated channel.
//
// "chat_channels.federated_room_id set + federated_peer_domain NULL IS the
// hub self-check" is the SAME shape federation_outbox_redact_purged.sql
// uses (single-homed intent — a reducer can't see process config either;
// the row shape carries the proof both places).
func (h *ChatEDiscoveryHandler) federationCoverageFor(ctx context.Context, tx pgx.Tx, channelID int64) (*federatedRoomDisclosure, bool, error) {
	var roomID, peerDomain *string
	if err := tx.QueryRow(ctx, `SELECT federated_room_id, federated_peer_domain FROM chat_channels WHERE id = $1`,
		channelID).Scan(&roomID, &peerDomain); err != nil {
		return nil, false, fmt.Errorf("read federation binding: %w", err)
	}
	if roomID == nil {
		return nil, peerDomain != nil, nil
	}

	var hubDomain string
	if err := tx.QueryRow(ctx, `SELECT hub_domain FROM federation_rooms WHERE room_id = $1`, *roomID).Scan(&hubDomain); err != nil {
		return nil, false, fmt.Errorf("read federation room: %w", err)
	}
	isHub := peerDomain == nil

	rows, err := tx.Query(ctx, `SELECT member_domain, invited_at, left_at, left_reason, coverage_epochs
		FROM federation_room_members WHERE room_id = $1 ORDER BY member_domain`, *roomID)
	if err != nil {
		return nil, false, fmt.Errorf("query room members: %w", err)
	}
	var members []federatedRoomMemberCoverage
	for rows.Next() {
		var m federatedRoomMemberCoverage
		var leftAt *time.Time
		var leftReason *string
		var epochsRaw []byte
		if err := rows.Scan(&m.Domain, &m.JoinedAt, &leftAt, &leftReason, &epochsRaw); err != nil {
			rows.Close()
			return nil, false, fmt.Errorf("scan room member: %w", err)
		}
		m.RemovedAt = leftAt
		if leftReason != nil {
			m.RemovedReason = *leftReason
		}
		var epochs []coverageEpochRaw
		if len(epochsRaw) > 0 {
			if err := json.Unmarshal(epochsRaw, &epochs); err != nil {
				rows.Close()
				return nil, false, fmt.Errorf("decode coverage_epochs: %w", err)
			}
		}
		m.KnownMissingIntervals = make([]coverageInterval, 0, len(epochs))
		for _, e := range epochs {
			m.KnownMissingIntervals = append(m.KnownMissingIntervals,
				coverageInterval{From: e.ParkedAt, To: e.ResumedAt, Reason: e.Reason})
		}
		members = append(members, m)
	}
	rowsErr := rows.Err()
	rows.Close()
	if rowsErr != nil {
		return nil, false, fmt.Errorf("list room members: %w", rowsErr)
	}

	return &federatedRoomDisclosure{
		ChannelID: channelID, RoomID: *roomID, HubDomain: hubDomain, IsHub: isHub, Members: members,
	}, false, nil
}

// streamExportAttachments writes one "attachments/<sha256>" zip entry per
// DISTINCT content sha256 referenced by any of the given channels' attached
// messages (review F5: DISTINCT ON (content_sha256), not a plain DISTINCT on
// (sha, version) pairs — two versions with identical content would otherwise
// emit duplicate same-name zip entries). Resolved node->version->chunks on
// workerPool + h.s3, NEVER the member content route (DES-009 D5, spec §6.2)
// — the content.go:190-196 chunk-manifest query shape.
func (h *ChatEDiscoveryHandler) streamExportAttachments(ctx context.Context, tx pgx.Tx, zw *zip.Writer, channels []exportBeginChannel) error {
	channelIDs := make([]int64, len(channels))
	for i, ch := range channels {
		channelIDs[i] = ch.ChannelID
	}

	// Drain the full (sha, version_id) list into a slice and close the rows
	// FIRST (review F2 — a per-sha manifest query while this outer cursor is
	// open would hit pgx ErrConnBusy), then loop the slice.
	type shaVersion struct {
		sha       string
		versionID int64
	}
	var shaVersions []shaVersion
	rows, err := tx.Query(ctx, `SELECT DISTINCT ON (v.content_sha256) v.content_sha256, v.id
		FROM chat_message_attachments a
		JOIN chat_messages m ON m.id = a.message_id
		JOIN drive_file_versions v ON v.id = a.version_id
		WHERE m.channel_id = ANY($1)
		ORDER BY v.content_sha256, v.id`, channelIDs)
	if err != nil {
		return fmt.Errorf("query attachment shas: %w", err)
	}
	for rows.Next() {
		var sv shaVersion
		if err := rows.Scan(&sv.sha, &sv.versionID); err != nil {
			rows.Close()
			return fmt.Errorf("scan attachment sha: %w", err)
		}
		shaVersions = append(shaVersions, sv)
	}
	rowsErr := rows.Err()
	rows.Close()
	if rowsErr != nil {
		return fmt.Errorf("list attachment shas: %w", rowsErr)
	}

	for _, sv := range shaVersions {
		type manifestChunk struct {
			storageRef string
		}
		var chunks []manifestChunk
		mrows, err := tx.Query(ctx, `SELECT c.storage_ref
			FROM drive_version_chunks vc
			JOIN drive_chunks c ON c.scope_key = vc.scope_key AND c.sha256 = vc.chunk_sha256
			WHERE vc.version_id = $1 AND vc.stream = 'content'
			ORDER BY vc.ordinal`, sv.versionID)
		if err != nil {
			return fmt.Errorf("query chunk manifest for sha %s: %w", sv.sha, err)
		}
		for mrows.Next() {
			var c manifestChunk
			if err := mrows.Scan(&c.storageRef); err != nil {
				mrows.Close()
				return fmt.Errorf("scan chunk manifest for sha %s: %w", sv.sha, err)
			}
			chunks = append(chunks, c)
		}
		mrowsErr := mrows.Err()
		mrows.Close()
		if mrowsErr != nil {
			return fmt.Errorf("list chunk manifest for sha %s: %w", sv.sha, mrowsErr)
		}

		aw, err := zw.Create("attachments/" + sv.sha)
		if err != nil {
			return fmt.Errorf("create attachment entry for sha %s: %w", sv.sha, err)
		}
		// review F4: tee every written byte through a hasher and verify the
		// sum against the entry's own name (the expected sha256) once the
		// chunk loop drains — a corrupted/substituted chunk must not silently
		// ship under a filename that claims a content hash it doesn't have.
		// On mismatch: log + abandon (return the error up to Export's
		// existing abandon() closure), the same truncated-zip-no-manifest
		// posture every other mid-stream failure in this file uses.
		hasher := sha256.New()
		out := io.MultiWriter(aw, hasher)
		for _, c := range chunks {
			obj, err := h.s3.GetObject(ctx, h.s3Bucket, c.storageRef, minio.GetObjectOptions{})
			if err != nil {
				return fmt.Errorf("fetch chunk %s for sha %s: %w", c.storageRef, sv.sha, err)
			}
			_, copyErr := io.Copy(out, obj)
			_ = obj.Close()
			if copyErr != nil {
				return fmt.Errorf("stream chunk %s for sha %s: %w", c.storageRef, sv.sha, copyErr)
			}
		}
		if got := hex.EncodeToString(hasher.Sum(nil)); got != sv.sha {
			return fmt.Errorf("attachment content hash mismatch for %s: streamed bytes hash to %s", sv.sha, got)
		}
	}
	return nil
}
