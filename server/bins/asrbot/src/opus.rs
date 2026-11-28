//! Opus decode, fixed at 16 kHz mono (Go `internal/opus`, plan delta 9: no
//! resampler; libopus bridges the 48 kHz/stereo wire format internally).
//!
//! This is the one file in the crate that touches `unsafe`: the transpiled
//! libopus (`unsafe-libopus`, pure Rust, no native library) exposes a C-shaped
//! API. Everything else in the crate is `deny(unsafe_code)`.
#![allow(unsafe_code)]

use unsafe_libopus::{opus_decode, opus_decoder_create, opus_decoder_destroy, OpusDecoder};

/// The FIXED decode target: FunASR's streaming mode consumes 16 kHz mono.
pub const SAMPLE_RATE: i32 = 16000;
pub const CHANNELS: i32 = 1;

/// Bounds one decoded frame: Opus frames are at most 120 ms (1920 samples at
/// 16 kHz); 5760 leaves a 3x margin so a legitimate frame is never truncated.
const MAX_FRAME_SAMPLES: usize = 5760;

/// One libopus decoder at (16000, 1). Not shareable between tracks.
pub struct Decoder {
    state: *mut OpusDecoder,
}

// SAFETY: the state is owned exclusively by this value and only touched
// through `&mut self`, so moving it between threads is sound.
unsafe impl Send for Decoder {}

impl Decoder {
    pub fn new() -> Result<Self, String> {
        let mut error = 0i32;
        // SAFETY: valid out-pointer; returns null on failure with `error` set.
        let state = unsafe { opus_decoder_create(SAMPLE_RATE, CHANNELS, &mut error) };
        if error != 0 || state.is_null() {
            return Err(format!("opus: decoder init failed ({error})"));
        }
        Ok(Self { state })
    }

    /// Decode one Opus RTP payload into 16-bit PCM at (16000, 1).
    pub fn decode(&mut self, payload: &[u8]) -> Result<Vec<i16>, String> {
        if payload.is_empty() {
            return Err("opus: no data supplied".into());
        }
        let mut pcm = vec![0i16; MAX_FRAME_SAMPLES];
        // SAFETY: `state` is live; `payload` and `pcm` are valid for the stated lengths.
        let n = unsafe {
            opus_decode(
                self.state,
                payload.as_ptr(),
                payload.len() as i32,
                pcm.as_mut_ptr(),
                (MAX_FRAME_SAMPLES as i32) / CHANNELS,
                0,
            )
        };
        if n < 0 {
            return Err(format!("opus: error code {n}"));
        }
        pcm.truncate(n as usize);
        Ok(pcm)
    }
}

impl Drop for Decoder {
    fn drop(&mut self) {
        // SAFETY: allocated by `opus_decoder_create`, freed exactly once.
        unsafe { opus_decoder_destroy(self.state) }
    }
}

/// 16-bit PCM as little-endian bytes: FunASR's binary frame shape.
pub fn pcm16le(samples: &[i16]) -> Vec<u8> {
    samples.iter().flat_map(|s| s.to_le_bytes()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pcm16le_is_little_endian() {
        assert_eq!(
            pcm16le(&[1, -1, 0x1234]),
            vec![1, 0, 0xff, 0xff, 0x34, 0x12]
        );
        assert!(pcm16le(&[]).is_empty());
    }

    #[test]
    fn empty_payload_is_an_error_and_garbage_does_not_panic() {
        let mut d = Decoder::new().unwrap();
        assert_eq!(d.decode(&[]).unwrap_err(), "opus: no data supplied");
        // A TOC byte with an invalid frame count code is rejected, never UB.
        let _ = d.decode(&[0xff, 0xff, 0xff]);
    }

    #[test]
    fn a_silence_frame_decodes_to_20ms_of_16k_mono() {
        // TOC 0xF8: CELT fullband 20 ms, one frame; a 1-byte frame is DTX-like silence.
        let mut d = Decoder::new().unwrap();
        let pcm = d.decode(&[0xF8, 0xFF, 0xFE]).unwrap();
        assert_eq!(pcm.len(), 320, "20 ms at 16 kHz mono");
    }
}
