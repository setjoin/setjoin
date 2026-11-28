use setjoin_blobs::parse_chunk_range;

#[test]
fn recovery_chunk_range_preserves_inclusive_byte_offsets() {
    let range = parse_chunk_range("bytes 0-262143/300000").unwrap();
    assert_eq!((range.start, range.end, range.total), (0, 262143, 300000));
}

#[test]
fn recovery_chunk_cannot_exceed_the_256_kibibyte_limit() {
    assert!(parse_chunk_range("bytes 0-262143/300000")
        .unwrap()
        .fits_chunk_limit());
    assert!(!parse_chunk_range("bytes 0-262144/300000")
        .unwrap()
        .fits_chunk_limit());
}

#[test]
fn recovery_chunk_range_rejects_noncanonical_and_inconsistent_offsets() {
    for value in [
        "bytes 00-1/2",
        "bytes +0-1/2",
        "bytes 0-1/01",
        "bytes 1-0/2",
        "bytes 0-2/2",
        "bytes 0-1/*",
        "bytes 0-1/2\n",
        "bytes 0-1/2/3",
        "bytes 0-1/9223372036854775808",
    ] {
        assert!(parse_chunk_range(value).is_none(), "{value:?}");
    }
}
