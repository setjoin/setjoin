package user

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// The tests in this file pin the er5-s05 rule-program closures:
//   - personal rules are ORGANIZE-ONLY: the engine's send-time action set
//     (forward_to/redirect/bcc/add_header/append_footer) is refused on create
//     and update, so a client-authored rule can never queue or mutate outbound
//     mail (occ_0cd0f2f744230e79abc58690);
//   - rule programs are size- and count-bounded, and the per-mailbox rule
//     count is capped — the delivery engine evaluates every enabled rule per
//     message on the shared cluster (occ_ad8a413b31c65399a5a6abeb);
//   - retro-apply sweeps are concurrency-admitted per mailbox so one caller
//     cannot stack unbounded heavy jobs onto the shared scheduled-actions
//     dispatcher (occ_9e336c84f2d3596e2e86941d).

// TestUserRules_CreateRejectsSendTimeActions: every engine send-time action is
// refused with a 400 and NOTHING is persisted — one inbound message must never
// be amplifiable into arbitrary outbound work through a personal rule.
func TestUserRules_CreateRejectsSendTimeActions(t *testing.T) {
	pool := testPool(t)
	h := NewUserRulesHandler(pool, testLogger())
	userID, mailboxID := seedUserWithMailbox(t, pool)

	for _, actionType := range []string{"forward_to", "redirect", "bcc", "add_header", "append_footer"} {
		t.Run(actionType, func(t *testing.T) {
			before := mailboxRuleCount(t, pool, mailboxID)
			rec := httptest.NewRecorder()
			h.Create(rec, userRuleReq(t, http.MethodPost, "/settings/rules", userID, map[string]any{
				"name": "leak " + actionType, "enabled": true, "priority": 1,
				"conditions": json.RawMessage(`[{"field":"from","op":"contains","value":"x@y.test"}]`),
				"actions":    json.RawMessage(fmt.Sprintf(`[{"type":%q,"params":{"address":"attacker@evil.example"}}]`, actionType)),
			}))
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("create with %s returned %d, want 400: %s", actionType, rec.Code, rec.Body.String())
			}
			if after := mailboxRuleCount(t, pool, mailboxID); after != before {
				t.Errorf("send-time rule persisted despite 400: before=%d after=%d", before, after)
			}
		})
	}
}

// TestUserRules_UpdateRejectsSendTimeActions: an existing organize-only rule
// cannot be mutated into an outbound amplifier; the stored actions survive the
// refused update unchanged.
func TestUserRules_UpdateRejectsSendTimeActions(t *testing.T) {
	pool := testPool(t)
	h := NewUserRulesHandler(pool, testLogger())
	userID, mailboxID := seedUserWithMailbox(t, pool)

	var ruleID int64
	if err := pool.QueryRow(context.Background(),
		`INSERT INTO rules (mailbox_id, name, enabled, priority, run_on, is_transport_rule, conditions, actions, stop_processing)
		 VALUES ($1, 'organize', TRUE, 1, 'server', FALSE, '[{"field":"from","op":"contains","value":"news"}]', '[{"type":"mark_read"}]', FALSE)
		 RETURNING id`, mailboxID,
	).Scan(&ruleID); err != nil {
		t.Fatalf("seed rule: %v", err)
	}

	req := userRuleReq(t, http.MethodPut, fmt.Sprintf("/settings/rules/%d", ruleID), userID, map[string]any{
		"name": "organize", "enabled": true, "priority": 1,
		"actions": json.RawMessage(`[{"type":"forward_to","params":{"address":"attacker@evil.example"}}]`),
	})
	req.SetPathValue("id", fmt.Sprintf("%d", ruleID))
	rec := httptest.NewRecorder()
	h.Update(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("update to forward_to returned %d, want 400: %s", rec.Code, rec.Body.String())
	}
	var actions string
	if err := pool.QueryRow(context.Background(),
		`SELECT actions::text FROM rules WHERE id = $1`, ruleID).Scan(&actions); err != nil {
		t.Fatalf("read actions: %v", err)
	}
	if !strings.Contains(actions, "mark_read") || strings.Contains(actions, "forward_to") {
		t.Errorf("stored actions changed after refused update: %s", actions)
	}
}

// TestUserRules_ProgramBounds pins the size/count admission: oversized body,
// oversized program JSON, too many entries, and an oversized name are 400s
// with nothing persisted.
func TestUserRules_ProgramBounds(t *testing.T) {
	pool := testPool(t)
	h := NewUserRulesHandler(pool, testLogger())
	userID, mailboxID := seedUserWithMailbox(t, pool)

	conds := `[{"field":"from","op":"contains","value":"x@y.test"}]`

	t.Run("oversized body", func(t *testing.T) {
		big := strings.Repeat("a", maxRuleBodyBytes+1024)
		rec := httptest.NewRecorder()
		h.Create(rec, userRuleReq(t, http.MethodPost, "/settings/rules", userID, map[string]any{
			"name": big, "enabled": true, "priority": 1,
			"conditions": json.RawMessage(conds),
			"actions":    json.RawMessage(`[{"type":"mark_read"}]`),
		}))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("oversized body returned %d, want 400", rec.Code)
		}
		if n := mailboxRuleCount(t, pool, mailboxID); n != 0 {
			t.Errorf("oversized body persisted %d rules, want 0", n)
		}
	})

	t.Run("oversized conditions json", func(t *testing.T) {
		var entries []string
		for i := 0; i < maxRuleConditions*25; i++ {
			entries = append(entries, conds[1:len(conds)-1])
		}
		big := json.RawMessage("[" + strings.Join(entries, ",") + "]")
		if len(big) <= maxRuleProgramBytes {
			t.Fatalf("fixture too small: %d bytes", len(big))
		}
		rec := httptest.NewRecorder()
		h.Create(rec, userRuleReq(t, http.MethodPost, "/settings/rules", userID, map[string]any{
			"name": "big conds", "enabled": true, "priority": 1,
			"conditions": big,
			"actions":    json.RawMessage(`[{"type":"mark_read"}]`),
		}))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("oversized conditions returned %d, want 400: %s", rec.Code, rec.Body.String())
		}
	})

	t.Run("too many action entries", func(t *testing.T) {
		var entries []string
		for i := 0; i <= maxRuleActions; i++ {
			entries = append(entries, `{"type":"flag"}`)
		}
		rec := httptest.NewRecorder()
		h.Create(rec, userRuleReq(t, http.MethodPost, "/settings/rules", userID, map[string]any{
			"name": "many actions", "enabled": true, "priority": 1,
			"conditions": json.RawMessage(conds),
			"actions":    json.RawMessage("[" + strings.Join(entries, ",") + "]"),
		}))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("%d actions returned %d, want 400", maxRuleActions+1, rec.Code)
		}
	})

	t.Run("non-array actions", func(t *testing.T) {
		rec := httptest.NewRecorder()
		h.Create(rec, userRuleReq(t, http.MethodPost, "/settings/rules", userID, map[string]any{
			"name": "object actions", "enabled": true, "priority": 1,
			"conditions": json.RawMessage(conds),
			"actions":    json.RawMessage(`{"type":"flag"}`),
		}))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("object actions returned %d, want 400", rec.Code)
		}
	})

	t.Run("oversized name", func(t *testing.T) {
		rec := httptest.NewRecorder()
		h.Create(rec, userRuleReq(t, http.MethodPost, "/settings/rules", userID, map[string]any{
			"name": strings.Repeat("n", maxRuleNameLen+1), "enabled": true, "priority": 1,
			"conditions": json.RawMessage(conds),
			"actions":    json.RawMessage(`[{"type":"mark_read"}]`),
		}))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("oversized name returned %d, want 400", rec.Code)
		}
	})
}

// TestUserRules_UpdateBounds: the update path enforces the same name and
// program bounds as create (both validation arms, each a 400 with the stored
// rule untouched).
func TestUserRules_UpdateBounds(t *testing.T) {
	pool := testPool(t)
	h := NewUserRulesHandler(pool, testLogger())
	userID, mailboxID := seedUserWithMailbox(t, pool)

	var ruleID int64
	if err := pool.QueryRow(context.Background(),
		`INSERT INTO rules (mailbox_id, name, enabled, priority, run_on, is_transport_rule, conditions, actions, stop_processing)
		 VALUES ($1, 'bounds', TRUE, 1, 'server', FALSE, '[{"field":"from","op":"contains","value":"news"}]', '[{"type":"mark_read"}]', FALSE)
		 RETURNING id`, mailboxID,
	).Scan(&ruleID); err != nil {
		t.Fatalf("seed rule: %v", err)
	}

	t.Run("oversized name", func(t *testing.T) {
		req := userRuleReq(t, http.MethodPut, fmt.Sprintf("/settings/rules/%d", ruleID), userID,
			map[string]any{"name": strings.Repeat("n", maxRuleNameLen+1), "enabled": true, "priority": 1})
		req.SetPathValue("id", fmt.Sprintf("%d", ruleID))
		rec := httptest.NewRecorder()
		h.Update(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("oversized name update returned %d, want 400", rec.Code)
		}
	})

	t.Run("oversized conditions", func(t *testing.T) {
		var entries []string
		for i := 0; i < maxRuleConditions*25; i++ {
			entries = append(entries, `{"field":"from","op":"contains","value":"x@y.test"}`)
		}
		req := userRuleReq(t, http.MethodPut, fmt.Sprintf("/settings/rules/%d", ruleID), userID,
			map[string]any{"name": "bounds", "enabled": true, "priority": 1,
				"conditions": json.RawMessage("[" + strings.Join(entries, ",") + "]")})
		req.SetPathValue("id", fmt.Sprintf("%d", ruleID))
		rec := httptest.NewRecorder()
		h.Update(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("oversized conditions update returned %d, want 400", rec.Code)
		}
	})

	// The stored rule is unchanged after both refused updates.
	var name string
	if err := pool.QueryRow(context.Background(),
		`SELECT name FROM rules WHERE id = $1`, ruleID).Scan(&name); err != nil {
		t.Fatalf("read rule: %v", err)
	}
	if name != "bounds" {
		t.Errorf("rule name changed after refused updates: %q", name)
	}
}

// TestUserRules_RuleCountCap pins the per-mailbox rule admission: at the cap a
// new create is refused, so one mailbox cannot grow the per-message delivery
// evaluation work without bound.
func TestUserRules_RuleCountCap(t *testing.T) {
	pool := testPool(t)
	h := NewUserRulesHandler(pool, testLogger())
	userID, mailboxID := seedUserWithMailbox(t, pool)

	for i := 0; i < maxRulesPerMailbox; i++ {
		if _, err := pool.Exec(context.Background(),
			`INSERT INTO rules (mailbox_id, name, enabled, priority, run_on, is_transport_rule, conditions, actions, stop_processing)
			 VALUES ($1, $2, FALSE, 1, 'server', FALSE, '[]'::jsonb, '[]'::jsonb, FALSE)`,
			mailboxID, fmt.Sprintf("bulk-%d", i)); err != nil {
			t.Fatalf("seed rule %d: %v", i, err)
		}
	}

	rec := httptest.NewRecorder()
	h.Create(rec, userRuleReq(t, http.MethodPost, "/settings/rules", userID, map[string]any{
		"name": "one over the cap", "enabled": true, "priority": 1,
		"conditions": json.RawMessage(`[{"field":"from","op":"contains","value":"x"}]`),
		"actions":    json.RawMessage(`[{"type":"mark_read"}]`),
	}))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("create at cap returned %d, want 400: %s", rec.Code, rec.Body.String())
	}
	if got := mailboxRuleCount(t, pool, mailboxID); got != maxRulesPerMailbox {
		t.Errorf("rule count %d after refused create, want %d", got, maxRulesPerMailbox)
	}
}

// TestUserRules_ApplyRetroCapsInFlightSweeps pins the dispatcher admission:
// once the mailbox holds the cap of pending/processing rules_retro sweeps, a
// further apply is 429 and enqueues nothing; terminal sweeps do not count.
func TestUserRules_ApplyRetroCapsInFlightSweeps(t *testing.T) {
	pool := testPool(t)
	h := NewUserRulesHandler(pool, testLogger())
	userID, mailboxID := seedUserWithMailbox(t, pool)

	var ruleID int64
	if err := pool.QueryRow(context.Background(),
		`INSERT INTO rules (mailbox_id, name, enabled, priority, run_on, is_transport_rule, conditions, actions, stop_processing)
		 VALUES ($1, 'retro', TRUE, 1, 'server', FALSE, '[]'::jsonb, '[{"type":"mark_read"}]'::jsonb, FALSE)
		 RETURNING id`, mailboxID,
	).Scan(&ruleID); err != nil {
		t.Fatalf("seed rule: %v", err)
	}

	seed := func(status, dedup string) {
		t.Helper()
		if _, err := pool.Exec(context.Background(),
			`INSERT INTO scheduled_actions (action_kind, fire_at, status, dedup_key, mailbox_id)
			 VALUES ('rules_retro', now() + interval '1 hour', $1, $2, $3)`,
			status, dedup, mailboxID); err != nil {
			t.Fatalf("seed scheduled_action: %v", err)
		}
	}
	seed("pending", "rules_retro:cap-test:1")
	seed("processing", "rules_retro:cap-test:2")
	seed("pending", "rules_retro:cap-test:3")
	// Terminal rows must not count against the cap.
	seed("done", "rules_retro:cap-test:done")
	t.Cleanup(func() {
		pool.Exec(context.Background(),
			`DELETE FROM scheduled_actions WHERE mailbox_id = $1 AND dedup_key LIKE 'rules_retro:cap-test:%'`, mailboxID)
	})

	req := userRuleReq(t, http.MethodPost, fmt.Sprintf("/settings/rules/%d/apply", ruleID), userID, map[string]any{"window": "90d"})
	req.SetPathValue("id", fmt.Sprintf("%d", ruleID))
	rec := httptest.NewRecorder()
	h.ApplyRetro(rec, req)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("apply at cap returned %d, want 429: %s", rec.Code, rec.Body.String())
	}
	var n int
	if err := pool.QueryRow(context.Background(),
		`SELECT COUNT(*) FROM scheduled_actions WHERE mailbox_id = $1 AND action_kind = 'rules_retro' AND status IN ('pending','processing')`,
		mailboxID,
	).Scan(&n); err != nil {
		t.Fatalf("count in-flight: %v", err)
	}
	if n != maxRetroSweepsInFlight {
		t.Errorf("in-flight sweeps %d after refused apply, want %d (nothing enqueued)", n, maxRetroSweepsInFlight)
	}
}

func mailboxRuleCount(t *testing.T, pool *pgxpool.Pool, mailboxID int64) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(context.Background(),
		`SELECT COUNT(*) FROM rules WHERE mailbox_id = $1`, mailboxID).Scan(&n); err != nil {
		t.Fatalf("count rules: %v", err)
	}
	return n
}
