// poll_route_test.go — Chat A3 QoL Task 9: the poll routes as real HTTP
// round trips (chatDSN/chatTestPool/chatTestUser/chatDo, the
// tracer_integration_test.go genre). Reducer-level scenarios (BZ177 lumped
// invalid states, single-vote-replaces, multi-accumulates, BZ161 wrong-actor
// close, anchor-soft-delete retention, non-anonymous results) are already
// pinned by mailserver/sql/tests/chat_poll.pg — this file only proves the Go
// route layer wires straight through to those reducers (claims.UserID as
// p_user_id, path ids, error mapping), not the reducer logic itself.
package chat_test

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"testing"

	"setjoin.com/mailserver/internal/chat"
	"setjoin.com/shared/toggle"
)

func TestPollRouteRoundTrip(t *testing.T) {
	dsn := chatDSN(t)
	pool := chatTestPool(t, dsn)
	h := chat.NewHandler(pool, toggle.NewTestFlags(map[string]bool{"feature.chat": true}), slog.Default())

	owner := chatTestUser(t, pool, "a3pollOwner")
	member := chatTestUser(t, pool, "a3pollMember")
	outsider := chatTestUser(t, pool, "a3pollOutsider")

	var channelID int64
	if err := pool.QueryRow(context.Background(), `SELECT chat_channel_create($1, $2)`, owner, "a3-poll-chan").Scan(&channelID); err != nil {
		t.Fatalf("chat_channel_create: %v", err)
	}
	if _, err := pool.Exec(context.Background(), `SELECT chat_member_add($1, $2, $3)`, owner, channelID, member); err != nil {
		t.Fatalf("chat_member_add: %v", err)
	}

	// Create a poll via the route.
	createRR := chatDo(t, h, owner, "POST", fmt.Sprintf("/chat/channels/%d/polls", channelID),
		`{"question":"route poll?","options":["A","B"],"multi":false}`)
	if createRR.Code != http.StatusCreated {
		t.Fatalf("create poll: want 201, got %d: %s", createRR.Code, createRR.Body.String())
	}
	var created struct {
		MessageID int64 `json:"messageId"`
		PollID    int64 `json:"pollId"`
	}
	if err := json.Unmarshal(createRR.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode create: %v", err)
	}
	if created.PollID == 0 || created.MessageID == 0 {
		t.Fatalf("create poll: want non-zero messageId/pollId, got %+v", created)
	}

	var optionID int64
	if err := pool.QueryRow(context.Background(), `SELECT id FROM chat_poll_options WHERE poll_id = $1 AND ordinal = 1`, created.PollID).Scan(&optionID); err != nil {
		t.Fatalf("resolve option id: %v", err)
	}

	// A non-member cannot vote (BZ163 -> 403).
	rrForbidden := chatDo(t, h, outsider, "POST", fmt.Sprintf("/chat/polls/%d/vote", created.PollID),
		fmt.Sprintf(`{"optionId":%d}`, optionID))
	if rrForbidden.Code != http.StatusForbidden {
		t.Errorf("non-member vote: want 403 (BZ163), got %d: %s", rrForbidden.Code, rrForbidden.Body.String())
	}

	// The member votes.
	rrVote := chatDo(t, h, member, "POST", fmt.Sprintf("/chat/polls/%d/vote", created.PollID),
		fmt.Sprintf(`{"optionId":%d}`, optionID))
	if rrVote.Code != http.StatusNoContent {
		t.Fatalf("vote: want 204, got %d: %s", rrVote.Code, rrVote.Body.String())
	}

	// Results reflect the vote (non-anonymous — voter id present).
	rrResults := chatDo(t, h, member, "GET", fmt.Sprintf("/chat/polls/%d/results", created.PollID), "")
	if rrResults.Code != http.StatusOK {
		t.Fatalf("results: want 200, got %d: %s", rrResults.Code, rrResults.Body.String())
	}
	var results struct {
		Options []struct {
			OptionID int64   `json:"optionId"`
			Count    int     `json:"count"`
			Voters   []int64 `json:"voters"`
		} `json:"options"`
	}
	if err := json.Unmarshal(rrResults.Body.Bytes(), &results); err != nil {
		t.Fatalf("decode results: %v", err)
	}
	found := false
	for _, o := range results.Options {
		if o.OptionID == optionID {
			if o.Count != 1 {
				t.Errorf("voted option count = %d, want 1", o.Count)
			}
			for _, v := range o.Voters {
				if v == member {
					found = true
				}
			}
		}
	}
	if !found {
		t.Errorf("results = %+v, want member %d listed as a voter", results, member)
	}

	// A plain member (not creator, not admin) cannot close (BZ161 -> 403).
	rrCloseForbidden := chatDo(t, h, member, "POST", fmt.Sprintf("/chat/polls/%d/close", created.PollID), "")
	if rrCloseForbidden.Code != http.StatusForbidden {
		t.Errorf("non-creator close: want 403 (BZ161), got %d: %s", rrCloseForbidden.Code, rrCloseForbidden.Body.String())
	}

	// The creator closes.
	rrClose := chatDo(t, h, owner, "POST", fmt.Sprintf("/chat/polls/%d/close", created.PollID), "")
	if rrClose.Code != http.StatusNoContent {
		t.Fatalf("close: want 204, got %d: %s", rrClose.Code, rrClose.Body.String())
	}

	// Voting a closed poll now 422s (BZ177).
	rrVoteClosed := chatDo(t, h, member, "POST", fmt.Sprintf("/chat/polls/%d/vote", created.PollID),
		fmt.Sprintf(`{"optionId":%d}`, optionID))
	if rrVoteClosed.Code != http.StatusUnprocessableEntity {
		t.Errorf("vote on closed poll: want 422 (BZ177), got %d: %s", rrVoteClosed.Code, rrVoteClosed.Body.String())
	}
}
