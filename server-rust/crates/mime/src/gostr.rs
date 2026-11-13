//! Go string semantics over bytes. Go strings are arbitrary bytes; `strings`
//! and `unicode` decode UTF-8 lazily and treat an invalid byte as U+FFFD of
//! width one. Everything here reproduces that, so the MIME port sees the same
//! boundaries Go's does.

pub const RUNE_ERROR: u32 = 0xFFFD;

/// `utf8.DecodeRune`: `(rune, width)`; `(RuneError, 0)` for empty input and
/// `(RuneError, 1)` for an invalid sequence.
pub fn decode_rune(b: &[u8]) -> (u32, usize) {
    let Some(&first) = b.first() else {
        return (RUNE_ERROR, 0);
    };
    let width = match first {
        0x00..=0x7f => return (u32::from(first), 1),
        0xc2..=0xdf => 2,
        0xe0..=0xef => 3,
        0xf0..=0xf4 => 4,
        _ => return (RUNE_ERROR, 1),
    };
    if b.len() < width {
        return (RUNE_ERROR, 1);
    }
    match std::str::from_utf8(&b[..width]) {
        Ok(s) => (s.chars().next().map_or(RUNE_ERROR, u32::from), width),
        Err(_) => (RUNE_ERROR, 1),
    }
}

/// `unicode.IsSpace`.
pub fn is_space(r: u32) -> bool {
    matches!(
        r,
        0x09..=0x0d | 0x20 | 0x85 | 0xa0 | 0x1680 | 0x2000..=0x200a | 0x2028 | 0x2029 | 0x202f | 0x205f | 0x3000
    )
}

/// `strings.TrimLeftFunc(s, unicode.IsSpace)`.
pub fn trim_left_space(mut b: &[u8]) -> &[u8] {
    loop {
        let (r, n) = decode_rune(b);
        if n == 0 || !is_space(r) {
            return b;
        }
        b = &b[n..];
    }
}

/// `strings.TrimSpace`.
pub fn trim_space(b: &[u8]) -> &[u8] {
    let b = trim_left_space(b);
    let (mut at, mut end) = (0, 0);
    while at < b.len() {
        let (r, n) = decode_rune(&b[at..]);
        at += n;
        if !is_space(r) {
            end = at;
        }
    }
    &b[..end]
}

/// `strings.TrimRight(s, "\r")`.
pub fn trim_right_cr(mut b: &[u8]) -> &[u8] {
    while let [rest @ .., b'\r'] = b {
        b = rest;
    }
    b
}

pub fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }
    hay.windows(needle.len()).position(|w| w == needle)
}

/// `strings.EqualFold` for an ASCII `name` already in lower case.
pub fn equal_fold_ascii(a: &[u8], name_lower: &str) -> bool {
    let mut folded = Vec::new();
    let mut rest = a;
    while !rest.is_empty() {
        let (r, n) = decode_rune(rest);
        rest = &rest[n..];
        folded.push(match r {
            0x17f => u32::from(b's'),
            0x212a => u32::from(b'k'),
            0x41..=0x5a => r + 32,
            _ => r,
        });
    }
    folded.len() == name_lower.len()
        && folded
            .iter()
            .zip(name_lower.bytes())
            .all(|(x, y)| *x == u32::from(y))
}

/// `strings.ToLower` as far as it can create ASCII: ASCII letters, U+0130
/// (Go maps it to `i`) and the Kelvin sign (`k`). Other runes are kept; an
/// invalid byte becomes U+FFFD as `bytes.Map` does.
pub fn to_lower(b: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(b.len());
    let mut rest = b;
    while !rest.is_empty() {
        let (r, n) = decode_rune(rest);
        match r {
            0x41..=0x5a => out.push((r + 32) as u8),
            0x130 => out.push(b'i'),
            0x212a => out.push(b'k'),
            _ if n == 1 && r == RUNE_ERROR => out.extend_from_slice("\u{fffd}".as_bytes()),
            _ => out.extend_from_slice(&rest[..n]),
        }
        rest = &rest[n..];
    }
    out
}

pub fn contains(hay: &[u8], needle: &str) -> bool {
    find(hay, needle.as_bytes()).is_some()
}
