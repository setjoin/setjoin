package imap

import (
	"reflect"
	"testing"
)

// mkMsgs builds an ascending UID-ordered list with sequence numbers filled,
// from a slice of UIDs. ids are uid*10 so id != uid != seq (catches confusions).
func mkMsgs(uids ...int64) []storeMsg {
	out := make([]storeMsg, len(uids))
	for i, u := range uids {
		out[i] = storeMsg{id: u * 10, imapUID: u, seq: int64(i + 1)}
	}
	return out
}

func ids(msgs []storeMsg) []int64 {
	if len(msgs) == 0 {
		return nil
	}
	out := make([]int64, len(msgs))
	for i, m := range msgs {
		out[i] = m.id
	}
	return out
}

func TestParseSeqSet(t *testing.T) {
	tests := []struct {
		in   string
		want []seqRange
	}{
		{"1", []seqRange{{1, 1}}},
		{"1:5", []seqRange{{1, 5}}},
		{"1,3,5", []seqRange{{1, 1}, {3, 3}, {5, 5}}},
		{"2:4,7", []seqRange{{2, 4}, {7, 7}}},
		{"1:*", []seqRange{{1, seqStar}}},
		{"*", []seqRange{{seqStar, seqStar}}},
		{"*:4", []seqRange{{seqStar, 4}}},
		{"5:2", []seqRange{{5, 2}}}, // un-normalised; resolveSeqSet flips it
		{" 2 : 4 ", []seqRange{{2, 4}}},
		{"", nil},
		{"abc", nil},
		{"0", nil},     // seq numbers are 1-based
		{"1:abc", nil}, // bad endpoint → dropped
		{"3(FLAGS)", []seqRange{{3, 3}}},
	}
	for _, tc := range tests {
		got := parseSeqSet(tc.in)
		if !reflect.DeepEqual(got, tc.want) {
			t.Errorf("parseSeqSet(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestResolveSeqSetSequence(t *testing.T) {
	// UIDs 10,20,30,40 → seq 1,2,3,4 ; ids 100,200,300,400.
	msgs := mkMsgs(10, 20, 30, 40)

	cases := []struct {
		name    string
		ranges  []seqRange
		wantIDs []int64
	}{
		{"single", parseSeqSet("2"), []int64{200}},
		{"range", parseSeqSet("2:3"), []int64{200, 300}},
		{"gaps", parseSeqSet("1,3"), []int64{100, 300}},
		{"star", parseSeqSet("*"), []int64{400}},
		{"to-star", parseSeqSet("3:*"), []int64{300, 400}},
		{"reversed", parseSeqSet("3:2"), []int64{200, 300}},
		{"out-of-range-high", parseSeqSet("9"), nil},
		{"dedup overlap", parseSeqSet("1:3,2:4"), []int64{100, 200, 300, 400}},
	}
	for _, tc := range cases {
		got := ids(resolveSeqSet(tc.ranges, msgs, false))
		if !reflect.DeepEqual(got, tc.wantIDs) {
			t.Errorf("%s: resolveSeqSet(seq) = %v, want %v", tc.name, got, tc.wantIDs)
		}
	}
}

func TestResolveSeqSetUID(t *testing.T) {
	// UIDs 10,20,30,40 (non-contiguous; UID != seq). This is the BUG-2 regression
	// guard: UID STORE must match imap_uid, not the positional sequence offset.
	msgs := mkMsgs(10, 20, 30, 40)

	cases := []struct {
		name    string
		ranges  []seqRange
		wantIDs []int64
	}{
		{"single-uid", parseSeqSet("20"), []int64{200}},
		{"uid-range", parseSeqSet("20:30"), []int64{200, 300}},
		{"uid-not-a-seq-offset", parseSeqSet("2"), nil}, // UID 2 doesn't exist
		{"uid-star", parseSeqSet("*"), []int64{400}},    // highest UID = 40
		{"uid-to-star", parseSeqSet("30:*"), []int64{300, 400}},
		{"uid-gap-in-middle", parseSeqSet("15:25"), []int64{200}}, // only UID 20 is inside
	}
	for _, tc := range cases {
		got := ids(resolveSeqSet(tc.ranges, msgs, true))
		if !reflect.DeepEqual(got, tc.wantIDs) {
			t.Errorf("%s: resolveSeqSet(uid) = %v, want %v", tc.name, got, tc.wantIDs)
		}
	}
}

func TestResolveSeqSetEmpty(t *testing.T) {
	if got := resolveSeqSet(parseSeqSet("1:*"), nil, false); got != nil {
		t.Errorf("empty mailbox: want nil, got %v", got)
	}
}

func TestParseStoreFlags(t *testing.T) {
	cases := []struct {
		op, list   string
		wantAdd    bool
		wantRemove bool
		wantRepl   bool
		wantSilent bool
		wantSeen   bool
		wantFlag   bool
	}{
		{"+FLAGS", `(\Seen)`, true, false, false, false, true, false},
		{"-FLAGS", `(\Flagged)`, false, true, false, false, false, true},
		{"FLAGS", `(\Seen \Flagged)`, false, false, true, false, true, true},
		{"+FLAGS.SILENT", `(\Seen)`, true, false, false, true, true, false},
		{"flags", `\Seen`, false, false, true, false, true, false}, // case-insensitive, no parens
	}
	for _, tc := range cases {
		d, silent := parseStoreFlags(tc.op, tc.list)
		if d.add != tc.wantAdd || d.remove != tc.wantRemove || d.replace != tc.wantRepl {
			t.Errorf("%s %s: add/remove/replace = %v/%v/%v", tc.op, tc.list, d.add, d.remove, d.replace)
		}
		if silent != tc.wantSilent {
			t.Errorf("%s: silent = %v, want %v", tc.op, silent, tc.wantSilent)
		}
		if d.seen != tc.wantSeen || d.flagged != tc.wantFlag {
			t.Errorf("%s %s: seen/flagged = %v/%v, want %v/%v", tc.op, tc.list, d.seen, d.flagged, tc.wantSeen, tc.wantFlag)
		}
	}
}

func TestApplyStoreDeltaRelative(t *testing.T) {
	// +FLAGS \Seen on an unread message → read; other flags untouched.
	m := storeMsg{isFlagged: true}
	d, _ := parseStoreFlags("+FLAGS", `(\Seen)`)
	got := applyStoreDelta(m, d)
	if !got.isRead || !got.isFlagged {
		t.Errorf("+FLAGS \\Seen: got isRead=%v isFlagged=%v, want true/true", got.isRead, got.isFlagged)
	}

	// -FLAGS \Flagged on a \Flagged \Seen message → \Seen stays, \Flagged cleared.
	m = storeMsg{isRead: true, isFlagged: true}
	d, _ = parseStoreFlags("-FLAGS", `(\Flagged)`)
	got = applyStoreDelta(m, d)
	if !got.isRead || got.isFlagged {
		t.Errorf("-FLAGS \\Flagged: got isRead=%v isFlagged=%v, want true/false", got.isRead, got.isFlagged)
	}
}

// TestApplyStoreDeltaReplaceClearsUnmentioned is the RFC 9051 §6.4.6 fix
// (Decision 2): FLAGS (\Seen) on a \Flagged \Seen message must CLEAR \Flagged.
func TestApplyStoreDeltaReplaceClearsUnmentioned(t *testing.T) {
	m := storeMsg{isRead: true, isFlagged: true, isAnswered: true}
	d, _ := parseStoreFlags("FLAGS", `(\Seen)`)
	got := applyStoreDelta(m, d)
	if !got.isRead {
		t.Errorf("FLAGS (\\Seen): \\Seen should remain set")
	}
	if got.isFlagged {
		t.Errorf("FLAGS (\\Seen): \\Flagged must be CLEARED (RFC 9051 §6.4.6)")
	}
	if got.isAnswered {
		t.Errorf("FLAGS (\\Seen): \\Answered must be CLEARED (RFC 9051 §6.4.6)")
	}

	// FLAGS () clears everything.
	d, _ = parseStoreFlags("FLAGS", `()`)
	got = applyStoreDelta(storeMsg{isRead: true, isFlagged: true}, d)
	if got.isRead || got.isFlagged {
		t.Errorf("FLAGS (): all flags must clear, got %+v", got)
	}
}

func TestFormatFlagList(t *testing.T) {
	if got := formatFlagList(storeMsg{}); got != "()" {
		t.Errorf("empty flags = %q, want ()", got)
	}
	got := formatFlagList(storeMsg{isRead: true, isFlagged: true, isDeleted: true})
	want := `(\Seen \Flagged \Deleted)`
	if got != want {
		t.Errorf("formatFlagList = %q, want %q", got, want)
	}
}
