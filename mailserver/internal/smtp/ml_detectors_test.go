package smtp

import (
	"reflect"
	"testing"

	"setjoin.com/shared/toggle"
)

// spammyFixture triggers all four wired detectors: sender mismatch (envelope
// domain != header domain, no SPF/DKIM), forged recipients (SMTP rcpt absent
// from To/Cc), mixed charset (Latin + CJK), and fake HTML (hidden text via
// display:none).
const (
	spammySMTPFrom   = "spammer@evil.example"
	spammyHeaderFrom = "ceo@company.example"
	spammyTo         = "someone-else@company.example"
	spammyCc         = ""
	spammyBody       = "buy cheap 伟哥 now, limited time offer, click here"
	spammyHTML       = `<div style="display:none">hidden spam keywords viagra free</div>`
)

var spammyRcpts = []string{"victim@company.example"}

// hamFixture matches on every axis: identical From, SPF+DKIM both pass, the
// recipient is in To, single-script body, plain HTML.
const (
	hamSMTPFrom   = "alice@company.example"
	hamHeaderFrom = "alice@company.example"
	hamTo         = "bob@company.example"
	hamCc         = ""
	hamBody       = "Hi Bob, attaching the quarterly report as discussed."
	hamHTML       = "<p>Hi Bob, attaching the quarterly report as discussed.</p>"
)

var hamRcpts = []string{"bob@company.example"}

func TestApplyMLDetectorSignal_ToggleOff_NeverRuns(t *testing.T) {
	toggles := toggle.NewTestFlags(map[string]bool{toggle.FeatureSpamMLDetectors: false})
	before := AntiSpamResult{Score: 3.5, Symbols: []string{"MISSING_MID"}}
	got := before
	applyMLDetectorSignal(toggles, &got,
		spammySMTPFrom, spammyHeaderFrom, spammyRcpts, spammyTo, spammyCc, spammyBody, spammyHTML,
		false, false,
	)
	if !reflect.DeepEqual(got, before) {
		t.Fatalf("toggle off must be a no-op: before=%+v after=%+v", before, got)
	}
}

func TestApplyMLDetectorSignal_DefaultIsOff(t *testing.T) {
	// No override, no DB row: IsEnabled must resolve to the registryDefaults
	// entry (false) — the seeded-OFF contract this whole feature depends on.
	toggles := toggle.NewTestFlags(nil)
	if toggles.IsEnabled(toggle.FeatureSpamMLDetectors) {
		t.Fatal("feature.spam_ml_detectors must default OFF")
	}
}

func TestApplyMLDetectorSignal_ToggleOn_SpammyFixtureGetsAdditiveSignal(t *testing.T) {
	toggles := toggle.NewTestFlags(map[string]bool{toggle.FeatureSpamMLDetectors: true})
	got := AntiSpamResult{Score: 1.0, Symbols: []string{"MISSING_MID"}}
	applyMLDetectorSignal(toggles, &got,
		spammySMTPFrom, spammyHeaderFrom, spammyRcpts, spammyTo, spammyCc, spammyBody, spammyHTML,
		false, false,
	)
	if got.DetectorScore <= 0 {
		t.Fatalf("expected positive detector score for spammy fixture, got %f", got.DetectorScore)
	}
	if got.Score != 1.0+got.DetectorScore {
		t.Fatalf("detector score must be ADDED to the existing score: got Score=%f DetectorScore=%f", got.Score, got.DetectorScore)
	}
	for _, want := range []string{"ML_SENDER_MISMATCH", "ML_FORGED_RECIPIENTS", "ML_MIXED_CHARSET", "ML_FAKE_HTML"} {
		found := false
		for _, s := range got.Symbols {
			if s == want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected symbol %q in %v", want, got.Symbols)
		}
	}
	// The pre-existing heuristic symbol must survive — additive, not replaced.
	if len(got.Symbols) == 0 || got.Symbols[0] != "MISSING_MID" {
		t.Errorf("pre-existing symbols must be preserved: %v", got.Symbols)
	}
}

func TestApplyMLDetectorSignal_ToggleOn_HamFixtureNotFalselyBoosted(t *testing.T) {
	toggles := toggle.NewTestFlags(map[string]bool{toggle.FeatureSpamMLDetectors: true})
	got := AntiSpamResult{}
	applyMLDetectorSignal(toggles, &got,
		hamSMTPFrom, hamHeaderFrom, hamRcpts, hamTo, hamCc, hamBody, hamHTML,
		true, true,
	)
	if got.DetectorScore != 0 {
		t.Errorf("expected zero detector score for clean matched ham, got %f (symbols=%v)", got.DetectorScore, got.Symbols)
	}
	if len(got.Symbols) != 0 {
		t.Errorf("expected no detector symbols for ham, got %v", got.Symbols)
	}
	if got.Score != 0 {
		t.Errorf("ham must not be boosted, got Score=%f", got.Score)
	}
}

func TestAddrList(t *testing.T) {
	got := addrList("Alice <alice@example.com>, bob@example.com")
	want := []string{"alice@example.com", "bob@example.com"}
	if len(got) != len(want) {
		t.Fatalf("addrList = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("addrList[%d] = %q, want %q", i, got[i], want[i])
		}
	}
	if addrList("") != nil {
		t.Error("empty header must yield nil (fail open)")
	}
	if got := addrList("not a valid address list <<<"); got != nil {
		t.Errorf("malformed header must yield nil (fail open), got %v", got)
	}
}
