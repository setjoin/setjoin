// Package opus is the ONE cgo/libopus dependency in the asrbot module
// (plan delta 9) — every other package under asrbot/ is pure Go so
// asrbot/go.build ./... only needs libopus for this one file. Requires
// libopus development headers (brew install opus / apt install
// libopus-dev), guarded at the build-script level by `pkg-config --exists
// opus` (scripts/build.sh, scripts/test.sh, scripts/lint.sh).
package opus

import hopus "gopkg.in/hraban/opus.v2"

const (
	// SampleRate and Channels are the FIXED decode target (delta 9 — no
	// resampler in this process): libopus decodes directly to 16kHz mono,
	// which is exactly what FunASR's streaming mode consumes, even though
	// LiveKit clients negotiate the Opus RTP payload at 48kHz/stereo on the
	// wire — libopus's own internal resampler bridges that gap inside
	// opus_decode, so no separate resampling stage exists in this codebase.
	SampleRate = 16000
	Channels   = 1

	// maxFrameSamples bounds one decoded Opus frame at (16000,1): Opus
	// frames are at most 120ms, i.e. 1920 samples at 16kHz — 5760 leaves a
	// 3x margin so Decode never truncates a legitimate frame.
	maxFrameSamples = 5760
)

// Decoder wraps one hraban/opus.v2 Decoder instance, fixed at (16000, 1).
// Not safe for concurrent use — session.go owns one Decoder per
// currently-slotted track (never per-frame), matching the VAD manager's own
// per-track lifecycle.
type Decoder struct {
	d *hopus.Decoder
}

// NewDecoder allocates a libopus decoder initialized at (16000, 1).
func NewDecoder() (*Decoder, error) {
	d, err := hopus.NewDecoder(SampleRate, Channels)
	if err != nil {
		return nil, err
	}
	return &Decoder{d: d}, nil
}

// Decode decodes one Opus RTP payload into 16-bit PCM samples at (16000,1).
// The returned slice is only valid until the next Decode call (it reuses an
// internal buffer) — callers that need to retain it must copy.
func (dec *Decoder) Decode(payload []byte) ([]int16, error) {
	pcm := make([]int16, maxFrameSamples)
	n, err := dec.d.Decode(payload, pcm)
	if err != nil {
		return nil, err
	}
	return pcm[:n], nil
}

// PCM16LE encodes 16-bit PCM samples as little-endian bytes — the wire
// shape FunASR's binary frames expect.
func PCM16LE(samples []int16) []byte {
	out := make([]byte, len(samples)*2)
	for i, s := range samples {
		out[2*i] = byte(uint16(s))
		out[2*i+1] = byte(uint16(s) >> 8)
	}
	return out
}
