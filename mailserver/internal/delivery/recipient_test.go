package delivery

import "testing"

func TestMapRecipientStatus(t *testing.T) {
	cases := map[string]string{
		"accepted": "delivered",
		"rejected": "bounced",
		"deferred": "deferred",
		"error":    "deferred",
		"unknown":  "queued",
		"":         "queued",
	}
	for outcome, want := range cases {
		if got := MapRecipientStatus(outcome); got != want {
			t.Errorf("MapRecipientStatus(%q) = %q, want %q", outcome, got, want)
		}
	}
}

func TestMapOverallStatus(t *testing.T) {
	cases := map[string]string{
		"pending":   "queued",
		"sending":   "sending",
		"delivered": "delivered",
		"bounced":   "bounced",
		"deferred":  "deferred",
	}
	for queueStatus, want := range cases {
		if got := MapOverallStatus(queueStatus); got != want {
			t.Errorf("MapOverallStatus(%q) = %q, want %q", queueStatus, got, want)
		}
	}
}

func TestIsTerminalStatus(t *testing.T) {
	terminal := []string{"delivered", "bounced"}
	for _, s := range terminal {
		if !IsTerminalStatus(s) {
			t.Errorf("IsTerminalStatus(%q) = false, want true", s)
		}
	}
	nonTerminal := []string{"queued", "deferred", "sending", "pending", ""}
	for _, s := range nonTerminal {
		if IsTerminalStatus(s) {
			t.Errorf("IsTerminalStatus(%q) = true, want false", s)
		}
	}
}

func TestStatusRank(t *testing.T) {
	// Problems-first ordering: bounced < deferred < sending < queued < delivered < other.
	order := []string{"bounced", "deferred", "sending", "queued", "delivered", "anything-else"}
	for i := 0; i < len(order)-1; i++ {
		if StatusRank(order[i]) >= StatusRank(order[i+1]) {
			t.Errorf("StatusRank(%q)=%d should be < StatusRank(%q)=%d",
				order[i], StatusRank(order[i]), order[i+1], StatusRank(order[i+1]))
		}
	}
}

func TestSortProblemsFirst(t *testing.T) {
	recips := []Recipient{
		{Email: "z-delivered@x.test", Status: "delivered"},
		{Email: "a-delivered@x.test", Status: "delivered"},
		{Email: "b-bounced@x.test", Status: "bounced"},
		{Email: "a-bounced@x.test", Status: "bounced"},
		{Email: "m-deferred@x.test", Status: "deferred"},
	}
	SortProblemsFirst(recips)

	want := []string{
		"a-bounced@x.test",   // bounced, email asc
		"b-bounced@x.test",   // bounced, email asc
		"m-deferred@x.test",  // deferred
		"a-delivered@x.test", // delivered last, email asc
		"z-delivered@x.test", // delivered last, email asc
	}
	for i, w := range want {
		if recips[i].Email != w {
			t.Errorf("SortProblemsFirst[%d] = %q, want %q (full order: %v)", i, recips[i].Email, w, emails(recips))
		}
	}
}

func emails(recips []Recipient) []string {
	out := make([]string, len(recips))
	for i, r := range recips {
		out[i] = r.Email
	}
	return out
}
