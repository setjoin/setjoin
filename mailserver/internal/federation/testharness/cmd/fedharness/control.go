package main

import (
	"fmt"
	"log/slog"
	"net/http"
	"sort"
	"strconv"
	"time"

	"setjoin.com/shared/httputil"
	"setjoin.com/shared/pgxutil"
)

// controlServer is the loopback-only HTTP control surface E2/E3's
// experiment scripts drive: inject traffic (/enqueue, /room/fanout) and
// observe the durable state the reducers left behind (/inbox, /cursors,
// /latency) without ever going near the s2s wire themselves.
type controlServer struct {
	pool        pgxutil.WorkerPool
	localDomain string
	logger      *slog.Logger
}

func (c *controlServer) mux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/enqueue", c.handleEnqueue)
	mux.HandleFunc("/inbox", c.handleInbox)
	mux.HandleFunc("/cursors", c.handleCursors)
	mux.HandleFunc("/latency", c.handleLatency)
	mux.HandleFunc("/room/fanout", c.handleRoomFanout)
	mux.HandleFunc("/healthz", c.handleHealthz)
	return mux
}

// queryInt reads an int query param, falling back to def when absent,
// non-numeric, or <= 0.
func queryInt(r *http.Request, key string, def int) int {
	v, err := strconv.Atoi(r.URL.Query().Get(key))
	if err != nil || v <= 0 {
		return def
	}
	return v
}

// handleEnqueue is POST /enqueue?peer=<d>&n=<N>&size=<bytes> — calls
// federation_enqueue N times for peer with unique stanza IDs and a
// ~size-byte payload (E2: inject 1000 messages), returning the assigned seq
// range.
func (c *controlServer) handleEnqueue(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		httputil.WriteError(w, http.StatusMethodNotAllowed, "POST only")
		return
	}
	peer := r.URL.Query().Get("peer")
	if peer == "" {
		httputil.WriteError(w, http.StatusBadRequest, "peer query param required")
		return
	}
	n := queryInt(r, "n", 1)
	size := queryInt(r, "size", 0)

	requestedAt := time.Now().UTC().Format(time.RFC3339Nano)
	var minSeq, maxSeq int64
	for i := 0; i < n; i++ {
		stanzaID := fmt.Sprintf("%s-%d-%06d", c.localDomain, time.Now().UnixNano(), i)
		payload, err := buildPayload(i, size)
		if err != nil {
			httputil.WriteError(w, http.StatusInternalServerError, err.Error())
			return
		}
		var seq int64
		err = c.pool.QueryRow(r.Context(),
			`SELECT federation_enqueue($1,$2,$3,$4)`, peer, stanzaID, "application/json", payload,
		).Scan(&seq)
		if err != nil {
			c.logger.Error("fedharness: federation_enqueue failed", "peer", peer, "error", err)
			httputil.WriteError(w, http.StatusInternalServerError, err.Error())
			return
		}
		if i == 0 {
			minSeq = seq
		}
		maxSeq = seq
	}
	httputil.WriteJSON(w, http.StatusOK, map[string]any{
		"peer": peer, "n": n, "minSeq": minSeq, "maxSeq": maxSeq, "requestedAt": requestedAt,
	})
}

// handleInbox is GET /inbox?peer=<d> — the exactly-once/gap-free assertion
// surface (E2): count/min/max plus every missing seq in 1..max.
func (c *controlServer) handleInbox(w http.ResponseWriter, r *http.Request) {
	peer := r.URL.Query().Get("peer")
	if peer == "" {
		httputil.WriteError(w, http.StatusBadRequest, "peer query param required")
		return
	}
	rows, err := c.pool.Query(r.Context(), `SELECT peer_seq FROM federation_inbox WHERE peer_domain = $1`, peer)
	if err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	var seqs []int64
	for rows.Next() {
		var s int64
		if err := rows.Scan(&s); err != nil {
			rows.Close()
			httputil.WriteError(w, http.StatusInternalServerError, err.Error())
			return
		}
		seqs = append(seqs, s)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	count, minSeq, maxSeq, gaps := computeInboxGaps(seqs)
	httputil.WriteJSON(w, http.StatusOK, map[string]any{
		"peer": peer, "count": count, "minSeq": minSeq, "maxSeq": maxSeq, "gaps": gaps,
		"requestedAt": time.Now().UTC().Format(time.RFC3339Nano),
	})
}

// handleCursors is GET /cursors?peer=<d> — outbound (federation_peers) and
// inbound (federation_inbox_cursor) cursor observability, for watching acks
// advance across a reconnect.
func (c *controlServer) handleCursors(w http.ResponseWriter, r *http.Request) {
	peer := r.URL.Query().Get("peer")
	if peer == "" {
		httputil.WriteError(w, http.StatusBadRequest, "peer query param required")
		return
	}
	var lastSeq, lastAcked, lastApplied int64
	err := c.pool.QueryRow(r.Context(), `
		SELECT
		  COALESCE((SELECT last_seq        FROM federation_peers        WHERE peer_domain = $1), 0),
		  COALESCE((SELECT last_acked_seq  FROM federation_peers        WHERE peer_domain = $1), 0),
		  COALESCE((SELECT last_applied_seq FROM federation_inbox_cursor WHERE peer_domain = $1), 0)
	`, peer).Scan(&lastSeq, &lastAcked, &lastApplied)
	if err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	httputil.WriteJSON(w, http.StatusOK, map[string]any{
		"peer": peer, "lastSeq": lastSeq, "lastAckedSeq": lastAcked, "lastAppliedSeq": lastApplied,
	})
}

// handleLatency is GET /latency?peer=<d> — p50/p95 enqueue-commit -> apply
// latency, computed from the enqueuedAt wall-clock timestamp /enqueue stashed
// in the payload versus federation_inbox.applied_at. Only rows whose payload
// carries that field (i.e. rows this harness itself enqueued via /enqueue or
// /room/fanout) are counted.
func (c *controlServer) handleLatency(w http.ResponseWriter, r *http.Request) {
	peer := r.URL.Query().Get("peer")
	if peer == "" {
		httputil.WriteError(w, http.StatusBadRequest, "peer query param required")
		return
	}
	rows, err := c.pool.Query(r.Context(), `
		SELECT payload->>'enqueuedAt', applied_at
		  FROM federation_inbox
		 WHERE peer_domain = $1 AND payload ? 'enqueuedAt'
	`, peer)
	if err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	var deltasMs []float64
	for rows.Next() {
		var enqStr string
		var appliedAt time.Time
		if err := rows.Scan(&enqStr, &appliedAt); err != nil {
			rows.Close()
			httputil.WriteError(w, http.StatusInternalServerError, err.Error())
			return
		}
		enq, err := time.Parse(time.RFC3339Nano, enqStr)
		if err != nil {
			continue // malformed/foreign payload — skip rather than fail the whole read
		}
		deltasMs = append(deltasMs, appliedAt.Sub(enq).Seconds()*1000)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	sort.Float64s(deltasMs)
	httputil.WriteJSON(w, http.StatusOK, map[string]any{
		"peer": peer, "count": len(deltasMs),
		"p50Ms": percentile(deltasMs, 0.50),
		"p95Ms": percentile(deltasMs, 0.95),
	})
}

// handleRoomFanout is POST /room/fanout?room=<r>&n=<N>&size=<bytes> —
// calls federation_room_fanout for E3's 3-org hub fan-out proof. n/size
// default to 1/0, mirroring /enqueue.
//
// C2 Task 3 promoted federation_room_fanout to a 5-arg signature
// (p_origin_domain, Q2) and per-member disposition now runs the promoted
// authorize/park/warn discipline (federation_room_enqueue_member) — a Phase
// B live run against this endpoint needs its room members allow-listed at
// scope 'room' (federation_peer_authorize) or every member is REVOKED
// rather than delivered. NULL origin here means "the hub's own send".
func (c *controlServer) handleRoomFanout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		httputil.WriteError(w, http.StatusMethodNotAllowed, "POST only")
		return
	}
	room := r.URL.Query().Get("room")
	if room == "" {
		httputil.WriteError(w, http.StatusBadRequest, "room query param required")
		return
	}
	n := queryInt(r, "n", 1)
	size := queryInt(r, "size", 0)

	stanzaIDs := make([]string, 0, n)
	for i := 0; i < n; i++ {
		stanzaID := fmt.Sprintf("%s-room-%s-%d-%06d", c.localDomain, room, time.Now().UnixNano(), i)
		payload, err := buildPayload(i, size)
		if err != nil {
			httputil.WriteError(w, http.StatusInternalServerError, err.Error())
			return
		}
		if _, err := c.pool.Exec(r.Context(),
			`SELECT federation_room_fanout($1,$2,$3,$4,NULL)`, room, stanzaID, "application/json", payload,
		); err != nil {
			c.logger.Error("fedharness: federation_room_fanout failed", "room", room, "error", err)
			httputil.WriteError(w, http.StatusInternalServerError, err.Error())
			return
		}
		stanzaIDs = append(stanzaIDs, stanzaID)
	}
	httputil.WriteJSON(w, http.StatusOK, map[string]any{"room": room, "n": n, "stanzaIds": stanzaIDs})
}

// handleHealthz is GET /healthz — 200 once the daemon's HTTP server is up
// (doesn't probe the DB pool or any peer stream; that's what /cursors and
// /inbox are for).
func (c *controlServer) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	httputil.WriteJSON(w, http.StatusOK, map[string]any{
		"status": "ok", "domain": c.localDomain, "time": time.Now().UTC().Format(time.RFC3339Nano),
	})
}
