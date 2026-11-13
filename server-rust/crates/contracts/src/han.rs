//! Han script property recorded from go1.26.6 (Unicode 15.0.0).
//! Provenance: tests/conformance/chat-b/unicode-han.json; public search cases
//! remain the behaviour oracle. This is data from Go's unicode.Han API.
pub fn contains(c: char) -> bool {
    const RANGES: &[(u32, u32, u32)] = &[
        (0x2E80, 0x2E99, 1),
        (0x2E9B, 0x2EF3, 1),
        (0x2F00, 0x2FD5, 1),
        (0x3005, 0x3007, 2),
        (0x3021, 0x3029, 1),
        (0x3038, 0x303B, 1),
        (0x3400, 0x4DBF, 1),
        (0x4E00, 0x9FFF, 1),
        (0xF900, 0xFA6D, 1),
        (0xFA70, 0xFAD9, 1),
        (0x16FE2, 0x16FE3, 1),
        (0x16FF0, 0x16FF1, 1),
        (0x20000, 0x2A6DF, 1),
        (0x2A700, 0x2B739, 1),
        (0x2B740, 0x2B81D, 1),
        (0x2B820, 0x2CEA1, 1),
        (0x2CEB0, 0x2EBE0, 1),
        (0x2F800, 0x2FA1D, 1),
        (0x30000, 0x3134A, 1),
        (0x31350, 0x323AF, 1),
    ];
    let n = c as u32;
    RANGES
        .iter()
        .any(|&(lo, hi, stride)| n >= lo && n <= hi && (n - lo) % stride == 0)
}
