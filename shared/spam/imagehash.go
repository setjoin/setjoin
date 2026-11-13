package spam

import (
	"image"
	"math/bits"

	// Register standard image decoders so callers can decode JPEG/PNG/GIF.
	_ "image/gif"
	_ "image/jpeg"
	_ "image/png"
)

// AverageHash computes a 64-bit perceptual hash (aHash) of an image.
//
// Algorithm (rspamd-compatible):
//  1. Downsample the image to an 8x8 grayscale thumbnail.
//  2. Compute the mean pixel value across all 64 pixels.
//  3. For each pixel, if above the mean, set the corresponding bit to 1.
//
// The result is a 64-bit integer where each bit represents whether a region
// of the image is brighter than the overall average.
//
// Visually identical images produce identical hashes.
// Visually similar images produce hashes with small Hamming distance.
//
// Ref: rspamd uses the same aHash approach for detecting spam campaigns
// that reuse the same image with minor variations (resizing, recompression).
func AverageHash(img image.Image) uint64 {
	bounds := img.Bounds()
	width := bounds.Dx()
	height := bounds.Dy()

	var pixels [64]float64
	var sum float64

	for y := 0; y < 8; y++ {
		for x := 0; x < 8; x++ {
			// Map each 8x8 cell to a point in the source image.
			sx := bounds.Min.X + x*width/8
			sy := bounds.Min.Y + y*height/8

			r, g, b, _ := img.At(sx, sy).RGBA()
			// RGBA() returns values in [0, 65535]; convert to [0, 255].
			gray := 0.299*float64(r>>8) + 0.587*float64(g>>8) + 0.114*float64(b>>8)
			pixels[y*8+x] = gray
			sum += gray
		}
	}

	mean := sum / 64

	var hash uint64
	for i, p := range pixels {
		if p > mean {
			hash |= 1 << i
		}
	}
	return hash
}

// HammingDistance returns the number of differing bits between two hashes.
// 0 means identical; 64 means completely different (every bit flipped).
func HammingDistance(a, b uint64) int {
	return bits.OnesCount64(a ^ b)
}

// IsSimilar returns true if two perceptual hashes are within the given
// Hamming distance threshold. Typical thresholds:
//
//	≤5  — near-identical images (same source, different compression)
//	≤10 — visually similar (resized, watermarked, slightly cropped)
//	≤20 — loosely related (same layout, different content)
func IsSimilar(a, b uint64, threshold int) bool {
	return HammingDistance(a, b) <= threshold
}
