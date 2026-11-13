// Package vad implements a minimal energy-based voice-activity detector.
//
// ponytail: energy VAD — upgrade to a real VAD model if zh WER on real audio
// demands it (the §1.3 live proof is where that verdict lands).
package vad

// Detector tracks voice-activity state for one audio track using an
// attack/hangover energy threshold: once the RMS-ish energy of a frame
// crosses Threshold, the track is "active" immediately (attack — no delay
// admitting a real speaker); once it drops below Threshold, the track stays
// "active" for Hangover more frames before flipping back to silent (hangover
// — swallows short pauses mid-sentence instead of chopping speech into
// fragments).
type Detector struct {
	Threshold float64
	Hangover  int

	active      bool
	silentSince int
}

// NewDetector returns a Detector with the given energy threshold and
// hangover frame count.
func NewDetector(threshold float64, hangover int) *Detector {
	return &Detector{Threshold: threshold, Hangover: hangover}
}

// Energy computes a simple mean-absolute-amplitude energy for a frame of
// 16-bit PCM samples — cheap, no FFT, good enough to distinguish silence
// from speech at the levels real microphones produce.
func Energy(pcm []int16) float64 {
	if len(pcm) == 0 {
		return 0
	}
	var sum float64
	for _, s := range pcm {
		v := float64(s)
		if v < 0 {
			v = -v
		}
		sum += v
	}
	return sum / float64(len(pcm))
}

// Update feeds one frame's energy through the attack/hangover state machine
// and returns whether the track is currently considered voice-active.
func (d *Detector) Update(energy float64) bool {
	if energy >= d.Threshold {
		d.active = true
		d.silentSince = 0
		return true
	}
	if !d.active {
		return false
	}
	d.silentSince++
	if d.silentSince > d.Hangover {
		d.active = false
		return false
	}
	return true
}

// Active reports the detector's current state without feeding a new frame.
func (d *Detector) Active() bool {
	return d.active
}
