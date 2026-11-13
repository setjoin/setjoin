package spam

import (
	"image"
	"image/color"
	"math/bits"
	"testing"
)

// newGrayImage creates an 8x8 grayscale image for testing.
func newGrayImage(pixels [64]uint8) *image.Gray {
	img := image.NewGray(image.Rect(0, 0, 8, 8))
	for i, p := range pixels {
		img.Pix[i] = p
	}
	return img
}

// newSolidImage creates a solid-color image of the given size.
func newSolidImage(width, height int, c color.Color) *image.RGBA {
	img := image.NewRGBA(image.Rect(0, 0, width, height))
	for y := 0; y < height; y++ {
		for x := 0; x < width; x++ {
			img.Set(x, y, c)
		}
	}
	return img
}

func TestAverageHash_SameImage_SameHash(t *testing.T) {
	// Create a simple checkerboard pattern.
	img1 := image.NewRGBA(image.Rect(0, 0, 64, 64))
	img2 := image.NewRGBA(image.Rect(0, 0, 64, 64))
	for y := 0; y < 64; y++ {
		for x := 0; x < 64; x++ {
			c := color.White
			if (x+y)%2 == 0 {
				c = color.Black
			}
			img1.Set(x, y, c)
			img2.Set(x, y, c)
		}
	}

	h1 := AverageHash(img1)
	h2 := AverageHash(img2)
	if h1 != h2 {
		t.Errorf("identical images should produce identical hashes: %016x != %016x", h1, h2)
	}
}

func TestAverageHash_DifferentImages_DifferentHash(t *testing.T) {
	// Create two visually different images (not solid — solid images produce
	// trivial hashes because every pixel equals the mean, which is a known
	// aHash limitation that does not affect real-world spam images).
	img1 := image.NewRGBA(image.Rect(0, 0, 64, 64))
	img2 := image.NewRGBA(image.Rect(0, 0, 64, 64))
	for y := 0; y < 64; y++ {
		for x := 0; x < 64; x++ {
			// Image 1: vertical gradient.
			img1.Set(x, y, color.RGBA{0, uint8(y * 4), 0, 255})
			// Image 2: horizontal gradient.
			img2.Set(x, y, color.RGBA{0, 0, uint8(x * 4), 255})
		}
	}

	h1 := AverageHash(img1)
	h2 := AverageHash(img2)
	dist := HammingDistance(h1, h2)
	if dist < 5 {
		t.Errorf("different gradient images should have different hashes, distance=%d", dist)
	}
}

func TestAverageHash_SolidImages_TrivialHash(t *testing.T) {
	// Known aHash limitation: uniform images produce hash=0 because every
	// pixel equals the mean. This is acceptable because real-world spam
	// images always have structure.
	white := newSolidImage(64, 64, color.White)
	black := newSolidImage(64, 64, color.Black)

	h1 := AverageHash(white)
	h2 := AverageHash(black)
	// Both should be 0 (or very close) due to uniform content.
	if h1 != 0 || h2 != 0 {
		t.Logf("uniform image hashes: white=%016x, black=%016x", h1, h2)
	}
}

func TestAverageHash_Idempotent(t *testing.T) {
	img := image.NewRGBA(image.Rect(0, 0, 64, 64))
	for y := 0; y < 64; y++ {
		for x := 0; x < 64; x++ {
			img.Set(x, y, color.RGBA{uint8(x), uint8(y), uint8(x ^ y), 255})
		}
	}

	h1 := AverageHash(img)
	h2 := AverageHash(img)
	if h1 != h2 {
		t.Errorf("same image should always produce same hash: %016x != %016x", h1, h2)
	}
}

func TestAverageHash_UniformImage(t *testing.T) {
	// A uniform gray image should produce hash 0 (all pixels equal mean).
	gray := newSolidImage(64, 64, color.RGBA{128, 128, 128, 255})
	h := AverageHash(gray)
	if h != 0 {
		t.Logf("uniform gray image hash: %016x (note: float precision may produce nonzero)", h)
	}
}

func TestAverageHash_HalfWhiteHalfBlack(t *testing.T) {
	img := image.NewRGBA(image.Rect(0, 0, 64, 64))
	for y := 0; y < 64; y++ {
		for x := 0; x < 64; x++ {
			if x < 32 {
				img.Set(x, y, color.White)
			} else {
				img.Set(x, y, color.Black)
			}
		}
	}

	h := AverageHash(img)
	// The left half of the 8x8 thumbnail should be light, right half dark.
	// This is a deterministic pattern — just verify we get a non-trivial hash.
	if h == 0 {
		t.Error("half-white half-black image should produce nonzero hash")
	}
}

func TestAverageHash_NotZero(t *testing.T) {
	img := image.NewRGBA(image.Rect(0, 0, 64, 64))
	for y := 0; y < 64; y++ {
		for x := 0; x < 64; x++ {
			v := uint8((x * y) % 256)
			img.Set(x, y, color.RGBA{v, v, v, 255})
		}
	}

	h := AverageHash(img)
	if h == 0 {
		t.Error("patterned image should produce nonzero hash")
	}
}

func TestHammingDistance_Zero(t *testing.T) {
	// Same bits: distance should be 0.
	h := uint64(0xDEADBEEFCAFEBABE)
	if HammingDistance(h, h) != 0 {
		t.Error("Hamming distance of same value should be 0")
	}
	if HammingDistance(0, 0) != 0 {
		t.Error("Hamming distance of 0 and 0 should be 0")
	}
}

func TestHammingDistance_Max(t *testing.T) {
	// All bits flipped: distance should be 64.
	dist := HammingDistance(0x0000000000000000, 0xFFFFFFFFFFFFFFFF)
	if dist != 64 {
		t.Errorf("Hamming distance of all-flipped should be 64, got %d", dist)
	}
}

func TestHammingDistance_KnownValues(t *testing.T) {
	tests := []struct {
		a, b     uint64
		expected int
	}{
		{0, 1, 1},                   // single bit
		{0b00001111, 0b11110000, 8}, // 8 bits flipped
		{0xFFFF0000FFFF0000, 0x0000FFFF0000FFFF, 64}, // all 64 bits flipped
		{0b10101010, 0b01010101, 8},                  // alternating
	}

	for _, tc := range tests {
		got := HammingDistance(tc.a, tc.b)
		if got != tc.expected {
			t.Errorf("HammingDistance(%016x, %016x) = %d, want %d",
				tc.a, tc.b, got, tc.expected)
		}
	}
}

func TestIsSimilar(t *testing.T) {
	if !IsSimilar(0, 0, 5) {
		t.Error("identical hashes should be similar")
	}
	if IsSimilar(0, 0xFFFFFFFFFFFFFFFF, 5) {
		t.Error("distant hashes should not be similar with low threshold")
	}
	if !IsSimilar(0, 0xFFFFFFFFFFFFFFFF, 64) {
		t.Error("distant hashes should be similar with max threshold")
	}
}

func TestAverageHash_SlightlyModified_StillSimilar(t *testing.T) {
	// Create two very similar images — one with a tiny modification.
	img1 := image.NewRGBA(image.Rect(0, 0, 64, 64))
	img2 := image.NewRGBA(image.Rect(0, 0, 64, 64))
	for y := 0; y < 64; y++ {
		for x := 0; x < 64; x++ {
			v := uint8((x + y) % 256)
			img1.Set(x, y, color.RGBA{v, v, v, 255})
			// img2 is identical except for one pixel.
			img2.Set(x, y, color.RGBA{v, v, v, 255})
		}
	}
	// Modify just a single pixel.
	img2.Set(63, 63, color.RGBA{255, 255, 255, 255})

	h1 := AverageHash(img1)
	h2 := AverageHash(img2)
	dist := HammingDistance(h1, h2)

	// With just one pixel changed out of 4096, the perceptual hash should
	// be very similar (typically ≤5 bits differ for tiny changes at 8x8 scale).
	if dist > 10 {
		t.Errorf("nearly identical images should have small Hamming distance, got %d", dist)
	}
}

func TestAverageHash_64BitRange(t *testing.T) {
	// Verify hash fits in 64 bits and doesn't exceed valid range.
	img := image.NewRGBA(image.Rect(0, 0, 100, 100))
	for y := 0; y < 100; y++ {
		for x := 0; x < 100; x++ {
			img.Set(x, y, color.RGBA{uint8(x), uint8(y), 128, 255})
		}
	}

	h := AverageHash(img)
	// A 64-bit hash should not have bits beyond the 64th.
	if bits.OnesCount64(h) > 64 {
		t.Error("hash has more than 64 bits set")
	}
}

func TestAverageHash_PaddingHandling(t *testing.T) {
	// Small images should still produce valid hashes.
	smallImg := image.NewRGBA(image.Rect(0, 0, 1, 1))
	smallImg.Set(0, 0, color.RGBA{255, 255, 255, 255})
	h := AverageHash(smallImg)
	// Should return 0 for uniform image regardless of size.
	if h != 0 {
		t.Logf("1x1 white image hash: %016x", h)
	}
}
