package spam

import (
	"fmt"
	"testing"
)

func TestCountCaps_NonASCIIUpper(t *testing.T) {
	if countCaps("А") != 1 {
		t.Error("expected Cyrillic upper to count")
	}
}

// featureSet hashes each token with the given per-user key so tests can assert
// on exact feature membership the way the extractor computes it.
func featureSet(key uint32, tokens ...string) map[uint32]string {
	set := make(map[uint32]string, len(tokens))
	for _, tok := range tokens {
		set[featureIndex(key, tok)] = tok
	}
	return set
}

func featsToSet(key uint32, feats []uint32) map[uint32]bool {
	set := make(map[uint32]bool, len(feats))
	for _, f := range feats {
		set[f] = true
	}
	return set
}

func TestExtractFeatures_CommonCase(t *testing.T) {
	raw := []byte("From: spammer@evil.com\r\n" +
		"Subject: WINNER!!! You have won a prize\r\n" +
		"Content-Type: text/html\r\n" +
		"\r\n" +
		"<html><body>Click <a href='http://evil.com/prize'>here</a> to claim your prize!</body></html>")

	feats := ExtractFeatures(raw, DefaultFeatureSize)
	if len(feats) == 0 {
		t.Fatal("expected non-empty features")
	}
	present := featsToSet(DefaultFeatureSize, feats)
	want := featureSet(DefaultFeatureSize,
		"from:spammer@evil.com", "ct:html", "url:evil.com", "susp:prize", "miss:mid")
	for idx, tok := range want {
		if !present[idx] {
			t.Errorf("expected feature %q missing from extraction", tok)
		}
	}
}

func TestExtractFeatures_Empty(t *testing.T) {
	feats := ExtractFeatures([]byte{}, 1<<20)
	// Empty email yields only the missing-header features, not a panic.
	if len(feats) != 2 {
		t.Logf("empty email produced %d features", len(feats))
	}
}

func TestExtractFeatures_Idempotent(t *testing.T) {
	raw := []byte("From: alice@setjoin.com\r\nSubject: Q3 Budget Review\r\n\r\nHere is the budget.")
	f1 := ExtractFeatures(raw, 1<<20)
	f2 := ExtractFeatures(raw, 1<<20)
	if len(f1) != len(f2) {
		t.Fatalf("non-deterministic: len(f1)=%d, len(f2)=%d", len(f1), len(f2))
	}
	for i := range f1 {
		if f1[i] != f2[i] {
			t.Fatalf("non-deterministic at index %d: %d vs %d", i, f1[i], f2[i])
		}
	}
}

// TestExtractFeatures_HeaderImpersonation is the med-shard3-016 regression for
// body-planted identity headers: attacker-controlled body bytes carrying
// "From:"/"Subject:"/"Content-Type:"/"Message-Id:"/"Date:" lines must never
// contribute header features. The clean and impersonated messages share every
// header-derived feature; only genuine body-word features may differ.
func TestExtractFeatures_HeaderImpersonation(t *testing.T) {
	const key = DefaultFeatureSize
	clean := []byte("From: alice@bank.example.com\r\n" +
		"Subject: Q3 budget review\r\n" +
		"Date: Mon, 1 Jun 2026\r\n" +
		"Message-Id: <q3@bank.example.com>\r\n" +
		"Content-Type: text/plain\r\n" +
		"\r\n" +
		"Please review the attached budget numbers.")
	impersonated := []byte("From: alice@bank.example.com\r\n" +
		"Subject: Q3 budget review\r\n" +
		"Date: Mon, 1 Jun 2026\r\n" +
		"Message-Id: <q3@bank.example.com>\r\n" +
		"Content-Type: text/plain\r\n" +
		"\r\n" +
		"Please review the attached budget numbers.\r\n" +
		"--attacker-controlled body below--\r\n" +
		"From: victim@victim.example.net\r\n" +
		"Subject: URGENT WINNER claim your million prize now\r\n" +
		"Date: bad date\r\n" +
		"Message-Id: <forged@attacker.example>\r\n" +
		"Content-Type: text/html\r\n" +
		"\r\n" +
		"planted trailer")

	cleanFeats := ExtractFeatures(clean, key)
	impFeats := ExtractFeatures(impersonated, key)
	cleanSet := featsToSet(key, cleanFeats)
	impSet := featsToSet(key, impFeats)

	// Every header feature of the clean message must survive identically.
	for idx, tok := range featureSet(key,
		"from:alice@bank.example.com", "s:budget", "s:review", "ct:plain") {
		if !cleanSet[idx] || !impSet[idx] {
			t.Errorf("header feature %q: clean=%t impersonated=%t, want present in both", tok, cleanSet[idx], impSet[idx])
		}
	}

	// The planted header lines must not create header features...
	planted := featureSet(key,
		"from:victim@victim.example.net", "s:urgent", "s:winner", "s:claim", "s:million", "s:prize", "ct:html")
	for idx, tok := range planted {
		if impSet[idx] {
			t.Errorf("body-planted header feature %q leaked into extraction (header impersonation)", tok)
		}
	}

	// ...and must not defeat the missing-header features: Message-Id and Date
	// exist in the real header block, so miss:* must be absent even though the
	// body carries such lines. The clean message pins the same.
	for idx := range featureSet(key, "miss:mid", "miss:date") {
		if cleanSet[idx] || impSet[idx] {
			t.Error("miss:mid/miss:date present although the parsed header block carries them (body scan defeated the feature)")
		}
	}

	// The planted trailer is still ordinary body content — its words may
	// appear as body words, but the header spaces stay clean.
	if !impSet[featureIndex(key, "w:trailer")] {
		t.Error("planted trailer body word missing — body parsing regressed")
	}
}

// TestExtractFeatures_HeaderFoldingAndCase pins the parsed-header contract:
// header names are case-insensitive, continuation lines unfold, and bare-LF
// messages parse like CRLF ones.
func TestExtractFeatures_HeaderFoldingAndCase(t *testing.T) {
	raw := []byte("FROM: bob@example.org\n" +
		"Subject: weekly\n" +
		" status update\n" +
		"MESSAGE-ID: <w@example.org>\n" +
		"date: Mon, 1 Jun 2026\n" +
		"\n" +
		"see attached")

	feats := ExtractFeatures(raw, DefaultFeatureSize)
	present := featsToSet(DefaultFeatureSize, feats)
	for idx, tok := range featureSet(DefaultFeatureSize,
		"from:bob@example.org", "s:weekly", "s:status", "s:update", "w:attached") {
		if !present[idx] {
			t.Errorf("feature %q missing (case-insensitive names / unfolded continuation / LF body)", tok)
		}
	}
	for idx, tok := range featureSet(DefaultFeatureSize, "miss:mid", "miss:date") {
		if present[idx] {
			t.Errorf("miss feature for %q present although Message-Id/Date headers parsed", tok)
		}
	}
}

// TestExtractFeatures_PerUserKeying_IsolatesCollisions is the med-shard3-016
// cross-user poisoning regression: a bucket collision crafted in one user's
// feature space must not exist in another user's space. The test
// deterministically forges a colliding token pair for user A (the poisoning
// primitive) and proves the pair lands in different buckets for user B —
// collision work cannot be shared across victims.
func TestExtractFeatures_PerUserKeying_IsolatesCollisions(t *testing.T) {
	keyA := PerUserFeatureKey(101)
	keyB := PerUserFeatureKey(202)
	if keyA == keyB {
		t.Fatal("per-user key derivation collided for distinct users")
	}

	// Forge a collision under user A's space (deterministic counter search).
	collide := func(key uint32) (string, string) {
		buckets := make(map[uint32]string)
		for i := 0; ; i++ {
			tok := fmt.Sprintf("zorphblat%d", i)
			idx := featureIndex(key, tok)
			if prev, ok := buckets[idx]; ok {
				return prev, tok
			}
			buckets[idx] = tok
			if i > 1<<22 {
				t.Fatal("no collision found — feature space or hash broken")
			}
		}
	}
	a1, a2 := collide(keyA)
	if featureIndex(keyA, a1) != featureIndex(keyA, a2) {
		t.Fatal("setup invalid: forged pair does not collide under user A")
	}
	if featureIndex(keyB, a1) == featureIndex(keyB, a2) {
		t.Fatalf("cross-user poisoning: collision (%s,%s) forged for user A also collides under user B", a1, a2)
	}

	// End to end: identical messages hash to different bucket sets under
	// different users' keys, so trained weights never line up across victims.
	raw := []byte("From: bulk@evil.example\r\nSubject: zorphblat\r\n\r\nzorphblat body")
	if sameFeats(ExtractFeatures(raw, keyA), ExtractFeatures(raw, keyB)) {
		t.Error("identical message produced identical buckets under two users' keys — keying is not mixed into the hash")
	}
	// Same user: stable and identical.
	if !sameFeats(ExtractFeatures(raw, keyA), ExtractFeatures(raw, keyA)) {
		t.Error("same user's extraction is not deterministic")
	}
}

func sameFeats(a, b []uint32) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
