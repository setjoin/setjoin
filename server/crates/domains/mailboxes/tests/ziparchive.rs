//! The export ZIP writer is read back by the `zip` crate (and by the import
//! reader), including the zip64 end records past 65535 entries.
use setjoin_mailboxes::ziparchive::{Archive, ZipStream};
use std::io::Read;

fn build(entries: &[(&[u8], &[u8])]) -> Vec<u8> {
    let mut zip = ZipStream::new();
    let mut out = Vec::new();
    for (name, data) in entries {
        out.extend(zip.entry(name, data));
    }
    out.extend(zip.finish());
    out
}

#[test]
fn entries_round_trip_in_order() {
    let bytes = build(&[
        (b"1_a.eml", b"hello\r\nworld"),
        (b"2_b.eml", b""),
        ("3_\u{e9}.eml".as_bytes(), &[7u8; 5000]),
    ]);
    let mut archive = zip::ZipArchive::new(std::io::Cursor::new(&bytes)).expect("valid zip");
    assert_eq!(archive.len(), 3);
    let mut seen = Vec::new();
    for i in 0..3 {
        let mut f = archive.by_index(i).expect("entry");
        let mut body = Vec::new();
        f.read_to_end(&mut body).expect("crc and sizes hold");
        seen.push((
            String::from_utf8_lossy(f.name_raw()).into_owned(),
            body.len(),
            f.size(),
        ));
    }
    assert_eq!(seen[0], ("1_a.eml".into(), 12, 12));
    assert_eq!(seen[1], ("2_b.eml".into(), 0, 0));
    assert_eq!(seen[2], ("3_\u{e9}.eml".into(), 5000, 5000));
}

#[test]
fn import_reader_reads_what_export_writes() {
    let bytes = build(&[(b"x.eml", b"Subject: s\r\n\r\nb"), (b"readme.txt", b"skip")]);
    let mut archive = Archive::open(&bytes).expect("open");
    archive.validate().expect("limits");
    assert_eq!(archive.len(), 2);
    assert_eq!(archive.name(0).unwrap(), b"x.eml");
    assert_eq!(archive.read(0, 1 << 20).unwrap(), b"Subject: s\r\n\r\nb");
    assert!(archive.read(0, 3).is_err(), "over the entry budget");
}

#[test]
fn more_than_65535_entries_use_zip64_end_records() {
    let mut zip = ZipStream::new();
    let mut out = Vec::new();
    for i in 0..70_000u32 {
        out.extend(zip.entry(format!("{i}.eml").as_bytes(), b""));
    }
    out.extend(zip.finish());
    let archive = zip::ZipArchive::new(std::io::Cursor::new(&out)).expect("zip64 archive");
    assert_eq!(archive.len(), 70_000);
}

#[test]
fn corrupt_archives_are_refused() {
    assert!(Archive::open(b"not a zip").is_err());
    let mut bytes = build(&[(b"a.eml", b"hello hello hello")]);
    let n = bytes.len();
    bytes.truncate(n - 5);
    assert!(Archive::open(&bytes).is_err());
}

#[test]
fn ratio_limit_refuses_a_bomb() {
    let big = vec![0u8; 5 << 20];
    let bytes = build(&[(b"bomb.eml", &big)]);
    let mut archive = Archive::open(&bytes).expect("open");
    assert!(archive.validate().is_err());
}
