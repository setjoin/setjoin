package vad

import "testing"

func TestDetectorSilenceNeverActive(t *testing.T) {
	d := NewDetector(0.1, 3)
	for i := 0; i < 10; i++ {
		if d.Update(0.0) {
			t.Fatalf("frame %d: silence reported active", i)
		}
	}
}

func TestDetectorSpeechAcquires(t *testing.T) {
	d := NewDetector(0.1, 3)
	if !d.Update(0.5) {
		t.Fatal("a frame above threshold did not acquire activity immediately (attack)")
	}
}

func TestDetectorHangoverReleases(t *testing.T) {
	d := NewDetector(0.1, 3)
	d.Update(0.5) // acquire
	for i := 0; i < 3; i++ {
		if !d.Update(0.0) {
			t.Fatalf("frame %d: released before hangover elapsed", i)
		}
	}
	if d.Update(0.0) {
		t.Fatal("still active after hangover elapsed")
	}
}

func TestDetectorHangoverResetsOnSpeech(t *testing.T) {
	d := NewDetector(0.1, 3)
	d.Update(0.5)
	d.Update(0.0)
	d.Update(0.0)
	d.Update(0.5) // speech again before hangover expired — resets the clock
	for i := 0; i < 3; i++ {
		if !d.Update(0.0) {
			t.Fatalf("frame %d: hangover clock did not reset on renewed speech", i)
		}
	}
}

func TestManagerSilenceNeverHoldsSlot(t *testing.T) {
	m := NewManager(4, 0.1, 3)
	if m.Update("a", 0.0) {
		t.Fatal("silence acquired a slot")
	}
}

func TestManagerSpeechAcquiresSlot(t *testing.T) {
	m := NewManager(4, 0.1, 3)
	if !m.Update("a", 0.9) {
		t.Fatal("loud speech under the cap did not acquire a slot")
	}
}

func TestManagerHangoverReleasesSlot(t *testing.T) {
	m := NewManager(4, 0.1, 1)
	m.Update("a", 0.9)
	if !m.Update("a", 0.0) {
		t.Fatal("released before hangover elapsed")
	}
	if m.Update("a", 0.0) {
		t.Fatal("still holding a slot after hangover elapsed")
	}
}

// TestManagerCapLowestEnergyYields is the F10 invariant: with Cap=2 and 3
// simultaneous speakers, the two loudest hold slots and the quietest is
// evicted — and recovers its slot the instant it becomes the loudest.
func TestManagerCapLowestEnergyYields(t *testing.T) {
	m := NewManager(2, 0.1, 5)

	if !m.Update("a", 0.9) {
		t.Fatal("a: expected to acquire (1st of 3, under cap)")
	}
	if !m.Update("b", 0.8) {
		t.Fatal("b: expected to acquire (2nd of 3, at cap)")
	}
	if m.Update("c", 0.2) {
		t.Fatal("c: expected to yield — quietest of 3 over a cap of 2")
	}

	// c gets louder than b — b (now quietest) should yield to c.
	if !m.Update("c", 0.95) {
		t.Fatal("c: expected to acquire after becoming the loudest")
	}
	if m.Update("b", 0.8) {
		t.Fatal("b: expected to yield after becoming the quietest of the 3")
	}
	if !m.Update("a", 0.9) {
		t.Fatal("a: expected to keep holding — still one of the 2 loudest")
	}
}

func TestManagerRemoveClearsSlot(t *testing.T) {
	m := NewManager(1, 0.1, 5)
	m.Update("a", 0.9)
	m.Remove("a")
	// a's departure must free the cap for a new speaker immediately.
	if !m.Update("b", 0.5) {
		t.Fatal("b: expected to acquire after a's slot was removed")
	}
}
