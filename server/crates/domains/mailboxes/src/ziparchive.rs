//! ZIP handling for mailbox import and export.
//!
//! Reading follows Go's `archive/zip` use in `importZIP`: the central directory
//! decides the entries and their order, the declared sizes are checked against
//! the same limits before anything is opened, and an entry that fails to open,
//! fails its checksum or outgrows its budget is an error for that entry only.
//! Writing (the export stream) is in [`ZipStream`].
#![allow(clippy::result_unit_err)]
use std::io::{Cursor, Read};

pub const MAX_ENTRIES: usize = 10_000;
pub const MAX_EXPANDED_BYTES: i64 = 2 << 30;
pub const MAX_ENTRY_BYTES: i64 = 128 << 20;
pub const MAX_RATIO: u64 = 100;

pub struct Archive<'a> {
    inner: zip::ZipArchive<Cursor<&'a [u8]>>,
}

impl<'a> Archive<'a> {
    /// `zip.NewReader`: `Err` is any archive Go would call invalid.
    pub fn open(bytes: &'a [u8]) -> Result<Self, ()> {
        zip::ZipArchive::new(Cursor::new(bytes))
            .map(|inner| Archive { inner })
            .map_err(|_| ())
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// `validateMailboxZIP`: entry count, declared sizes and ratios.
    pub fn validate(&mut self) -> Result<(), ()> {
        if self.len() > MAX_ENTRIES {
            return Err(());
        }
        let mut declared: u64 = 0;
        for i in 0..self.len() {
            let f = self.inner.by_index_raw(i).map_err(|_| ())?;
            let (size, compressed) = (f.size(), f.compressed_size());
            if size > MAX_ENTRY_BYTES as u64 {
                return Err(());
            }
            if size > 0 && (compressed == 0 || size > compressed.saturating_mul(MAX_RATIO)) {
                return Err(());
            }
            declared += size;
            if declared > MAX_EXPANDED_BYTES as u64 {
                return Err(());
            }
        }
        Ok(())
    }

    /// The raw name bytes of entry `i`, as Go's `File.Name` holds them.
    pub fn name(&mut self, i: usize) -> Result<Vec<u8>, ()> {
        let f = self.inner.by_index_raw(i).map_err(|_| ())?;
        Ok(f.name_raw().to_vec())
    }

    /// `f.Open` + `readMailboxZIPEntry`: the whole entry, or `Err` when it cannot
    /// be opened or read, fails its checksum or holds more than `limit` bytes.
    pub fn read(&mut self, i: usize, limit: i64) -> Result<Vec<u8>, ()> {
        let limit = limit.max(0) as u64;
        let f = self.inner.by_index(i).map_err(|_| ())?;
        let mut raw = Vec::new();
        f.take(limit + 1).read_to_end(&mut raw).map_err(|_| ())?;
        if raw.len() as u64 > limit {
            return Err(());
        }
        Ok(raw)
    }
}

/// What the central directory keeps of one written entry.
struct DirEntry {
    name: Vec<u8>,
    flags: u16,
    crc: u32,
    compressed: u64,
    uncompressed: u64,
    offset: u64,
}

/// Streaming ZIP writer with the header fields of Go's `archive/zip` `Create`:
/// deflate, a data descriptor after each entry, no timestamp (zero DOS time and
/// date), version 2.0 (4.5 with zip64 sizes), the UTF-8 flag only for a name that
/// needs it, no external attributes, and zip64 records past 65535 entries or
/// 4 GiB. The deflate stream itself is `flate2`'s, not Go's, so compressed bytes
/// differ; names, order, sizes, contents and header fields do not.
#[derive(Default)]
pub struct ZipStream {
    dir: Vec<DirEntry>,
    written: u64,
}

const U32_MAX: u64 = 0xffff_ffff;

fn utf8_flag(name: &[u8]) -> u16 {
    // Go's detectUTF8: required when a rune is outside 0x20..=0x7d (or is a
    // backslash); an invalid sequence means the flag is not set.
    let mut require = false;
    let mut rest = name;
    while !rest.is_empty() {
        let (r, n) = crate::mimeutil::decode_rune(rest);
        if n == 1 && r == 0xFFFD {
            return 0;
        }
        if !(0x20..=0x7d).contains(&r) || r == 0x5c {
            require = true;
        }
        rest = &rest[n..];
    }
    if require {
        0x800
    } else {
        0
    }
}

impl ZipStream {
    pub fn new() -> Self {
        Self::default()
    }

    /// One complete entry: local header, deflated `data`, data descriptor.
    pub fn entry(&mut self, name: &[u8], data: &[u8]) -> Vec<u8> {
        use std::io::Write;
        let flags = 0x8 | utf8_flag(name);
        let mut out = Vec::new();
        out.extend_from_slice(&0x0403_4b50u32.to_le_bytes());
        out.extend_from_slice(&20u16.to_le_bytes());
        out.extend_from_slice(&flags.to_le_bytes());
        out.extend_from_slice(&8u16.to_le_bytes());
        out.extend_from_slice(&[0; 4]); // DOS time and date
        out.extend_from_slice(&[0; 12]); // crc and sizes follow in the descriptor
        out.extend_from_slice(&(name.len() as u16).to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(name);

        let mut crc = flate2::Crc::new();
        crc.update(data);
        let mut encoder =
            flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::new(5));
        encoder.write_all(data).expect("write to memory");
        let compressed = encoder.finish().expect("finish in memory");
        let (csize, usize_) = (compressed.len() as u64, data.len() as u64);
        out.extend_from_slice(&compressed);

        out.extend_from_slice(&0x0807_4b50u32.to_le_bytes());
        out.extend_from_slice(&crc.sum().to_le_bytes());
        if csize >= U32_MAX || usize_ >= U32_MAX {
            out.extend_from_slice(&csize.to_le_bytes());
            out.extend_from_slice(&usize_.to_le_bytes());
        } else {
            out.extend_from_slice(&(csize as u32).to_le_bytes());
            out.extend_from_slice(&(usize_ as u32).to_le_bytes());
        }
        self.dir.push(DirEntry {
            name: name.to_vec(),
            flags,
            crc: crc.sum(),
            compressed: csize,
            uncompressed: usize_,
            offset: self.written,
        });
        self.written += out.len() as u64;
        out
    }

    /// The central directory and end record.
    pub fn finish(self) -> Vec<u8> {
        let mut out = Vec::new();
        let start = self.written;
        for h in &self.dir {
            let zip64 = h.compressed >= U32_MAX || h.uncompressed >= U32_MAX;
            let big = zip64 || h.offset >= U32_MAX;
            out.extend_from_slice(&0x0201_4b50u32.to_le_bytes());
            out.extend_from_slice(&20u16.to_le_bytes()); // creator version
            out.extend_from_slice(&(if zip64 { 45u16 } else { 20 }).to_le_bytes());
            out.extend_from_slice(&h.flags.to_le_bytes());
            out.extend_from_slice(&8u16.to_le_bytes());
            out.extend_from_slice(&[0; 4]);
            out.extend_from_slice(&h.crc.to_le_bytes());
            if big {
                out.extend_from_slice(&(U32_MAX as u32).to_le_bytes());
                out.extend_from_slice(&(U32_MAX as u32).to_le_bytes());
            } else {
                out.extend_from_slice(&(h.compressed as u32).to_le_bytes());
                out.extend_from_slice(&(h.uncompressed as u32).to_le_bytes());
            }
            out.extend_from_slice(&(h.name.len() as u16).to_le_bytes());
            out.extend_from_slice(&(if big { 28u16 } else { 0 }).to_le_bytes());
            out.extend_from_slice(&0u16.to_le_bytes()); // comment length
            out.extend_from_slice(&[0; 4]); // disk number and internal attributes
            out.extend_from_slice(&0u32.to_le_bytes()); // external attributes
            if h.offset > U32_MAX {
                out.extend_from_slice(&(U32_MAX as u32).to_le_bytes());
            } else {
                out.extend_from_slice(&(h.offset as u32).to_le_bytes());
            }
            out.extend_from_slice(&h.name);
            if big {
                out.extend_from_slice(&1u16.to_le_bytes());
                out.extend_from_slice(&24u16.to_le_bytes());
                out.extend_from_slice(&h.uncompressed.to_le_bytes());
                out.extend_from_slice(&h.compressed.to_le_bytes());
                out.extend_from_slice(&h.offset.to_le_bytes());
            }
        }
        let end = start + out.len() as u64;
        let (mut records, mut size, mut offset) = (self.dir.len() as u64, out.len() as u64, start);
        if records >= 0xffff || size >= U32_MAX || offset >= U32_MAX {
            out.extend_from_slice(&0x0606_4b50u32.to_le_bytes());
            out.extend_from_slice(&44u64.to_le_bytes());
            out.extend_from_slice(&45u16.to_le_bytes());
            out.extend_from_slice(&45u16.to_le_bytes());
            out.extend_from_slice(&0u32.to_le_bytes());
            out.extend_from_slice(&0u32.to_le_bytes());
            out.extend_from_slice(&records.to_le_bytes());
            out.extend_from_slice(&records.to_le_bytes());
            out.extend_from_slice(&size.to_le_bytes());
            out.extend_from_slice(&offset.to_le_bytes());
            out.extend_from_slice(&0x0706_4b50u32.to_le_bytes());
            out.extend_from_slice(&0u32.to_le_bytes());
            out.extend_from_slice(&end.to_le_bytes());
            out.extend_from_slice(&1u32.to_le_bytes());
            records = 0xffff;
            size = U32_MAX;
            offset = U32_MAX;
        }
        out.extend_from_slice(&0x0605_4b50u32.to_le_bytes());
        out.extend_from_slice(&[0; 4]);
        out.extend_from_slice(&(records as u16).to_le_bytes());
        out.extend_from_slice(&(records as u16).to_le_bytes());
        out.extend_from_slice(&(size as u32).to_le_bytes());
        out.extend_from_slice(&(offset as u32).to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out
    }
}
