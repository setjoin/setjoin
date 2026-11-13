//! Go identity matching: canonical addresses are ASCII-only; the two callers
//! that use strings.ToLower/EqualFold need Unicode *simple* mappings instead.
//! ICU supplies Unicode tables; mailparse supplies the RFC 5322 grammar.
#[derive(Clone, Debug)]
pub struct CanonicalAddress(String);
impl CanonicalAddress {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
pub fn canonical(raw: &str) -> CanonicalAddress {
    let folded = raw.trim().to_ascii_lowercase();
    let address = match mailparse::addrparse(&folded) {
        Ok(list) if list.len() == 1 => match &list[0] {
            mailparse::MailAddr::Single(a) if !a.addr.is_empty() => a.addr.clone(),
            _ => folded,
        },
        _ => folded,
    };
    CanonicalAddress(address)
}
pub fn lower(raw: &str) -> String {
    let cm = icu_casemap::CaseMapper::new();
    raw.chars().map(|c| cm.simple_lowercase(c)).collect()
}
pub fn equal_fold(a: &str, b: &str) -> bool {
    let cm = icu_casemap::CaseMapper::new();
    a.chars()
        .map(|c| cm.simple_fold(c))
        .eq(b.chars().map(|c| cm.simple_fold(c)))
}
