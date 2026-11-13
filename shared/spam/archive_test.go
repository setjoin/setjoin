package spam

import (
	"bytes"
	"compress/flate"
	"encoding/binary"
	"hash/crc32"
	"math/rand"
	"testing"
)

// --- Real-format fixture builders ---
//
// Every builder assembles bytes that conform to the published format
// specifications (ZIP APPNOTE, rarlab technote.txt for RAR 4.x, rarlab
// technote.htm for RAR 5.0, ip7z DOC/7zFormat.txt for 7z), with genuine
// CRC fields wherever the format defines one. These replace the earlier
// fixtures that documented impossible layouts (RAR byte 7 = 0x80, 7z
// byte 12 flags, EOCD at offset 0).

func le16(v uint16) []byte {
	b := make([]byte, 2)
	binary.LittleEndian.PutUint16(b, v)
	return b
}

// le16x2 renders two back-to-back little-endian uint16 fields.
func le16x2(a, b uint16) []byte {
	return append(le16(a), le16(b)...)
}

func le32(v uint32) []byte {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, v)
	return b
}

func le64(v uint64) []byte {
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, v)
	return b
}

type zipMember struct {
	name       string
	method     uint16
	gpFlags    uint16
	data       []byte // stored bytes or pre-compressed payload
	uncompSize uint32 // declared uncompressed size; defaults to len(data)
}

// buildZip assembles local headers + central directory + EOCD with a
// comment, exactly as real ZIP writers do (CD entries carry the same GP
// flags as their local headers).
func buildZip(members []zipMember, comment string) []byte {
	var buf, cd []byte
	for _, m := range members {
		uncomp := m.uncompSize
		if uncomp == 0 {
			uncomp = uint32(len(m.data))
		}
		localOff := uint32(len(buf))
		buf = append(buf, zipLocalSig...)
		buf = append(buf, le16(20)...)        // version needed
		buf = append(buf, le16(m.gpFlags)...) // GP flags
		buf = append(buf, le16(m.method)...)  // method
		buf = append(buf, le16x2(0, 0)...)    // mod time/date
		buf = append(buf, le32(crc32.ChecksumIEEE(m.data))...)
		buf = append(buf, le32(uint32(len(m.data)))...) // compressed size
		buf = append(buf, le32(uncomp)...)              // uncompressed size
		buf = append(buf, le16(uint16(len(m.name)))...)
		buf = append(buf, le16(0)...) // extra len
		buf = append(buf, m.name...)
		buf = append(buf, m.data...)

		cd = append(cd, zipCDSig...)
		cd = append(cd, le16(20)...)        // version made by
		cd = append(cd, le16(20)...)        // version needed
		cd = append(cd, le16(m.gpFlags)...) // GP flags
		cd = append(cd, le16(m.method)...)  // method
		cd = append(cd, le16x2(0, 0)...)
		cd = append(cd, le32(crc32.ChecksumIEEE(m.data))...)
		cd = append(cd, le32(uint32(len(m.data)))...)
		cd = append(cd, le32(uncomp)...)
		cd = append(cd, le16(uint16(len(m.name)))...)
		cd = append(cd, le16x2(0, 0)...) // extra len, comment len
		cd = append(cd, le16x2(0, 0)...) // disk start, internal attrs
		cd = append(cd, le32(0)...)      // external attrs
		cd = append(cd, le32(localOff)...)
		cd = append(cd, m.name...)
	}
	eocd := bytes.Join([][]byte{
		zipEOCDSig,
		le16(0), le16(0), // disk numbers
		le16(uint16(len(members))), le16(uint16(len(members))),
		le32(uint32(len(cd))), le32(uint32(len(buf))),
		le16(uint16(len(comment))),
	}, nil)
	return bytes.Join([][]byte{buf, cd, eocd, []byte(comment)}, nil)
}

// buildRAR4 assembles marker + MAIN_HEAD + file blocks (+ ENDARC) per the
// RAR 4.x technote: HEAD_CRC is the low 16 bits of the CRC32 over
// HEAD_TYPE..end-of-block; MAIN_HEAD flags live at absolute bytes 10-11;
// FILE_HEAD carries PACK_SIZE/UNP_SIZE at +7/+11 and LONG_BLOCK data.
func buildRAR4(mainFlags uint16, files []zipMember) []byte {
	mainBody := bytes.Join([][]byte{
		{rar4TypeMain}, le16(mainFlags), le16(13), // type, flags, HEAD_SIZE
		le16(0), le32(0), // RESERVED1, RESERVED2
	}, nil)
	buf := bytes.Join([][]byte{
		rar4Magic,
		le16(uint16(crc32.ChecksumIEEE(mainBody) & 0xFFFF)), mainBody,
	}, nil)

	for _, f := range files {
		uncomp := f.uncompSize
		if uncomp == 0 {
			uncomp = uint32(len(f.data))
		}
		fileBody := bytes.Join([][]byte{
			{rar4TypeFile},
			le16(f.gpFlags | rar4FlagLongBlock), // file heads always carry data
			le16(uint16(32 + len(f.name))),      // HEAD_SIZE
			le32(uint32(len(f.data))),           // PACK_SIZE
			le32(uncomp),                        // UNP_SIZE
			{3},                                 // HOST_OS = Unix
			le32(0), le32(0),                    // FILE_CRC, FTIME
			{20, 0x30},                         // UNP_VER 2.0, METHOD store
			le16(uint16(len(f.name))), le32(0), // NAME_SIZE, ATTR
			[]byte(f.name),
		}, nil)
		buf = append(buf, le16(uint16(crc32.ChecksumIEEE(fileBody)&0xFFFF))...)
		buf = append(buf, fileBody...)
		buf = append(buf, f.data...)
	}

	endBody := bytes.Join([][]byte{
		{rar4TypeEnd}, le16(0), le16(7), // HEAD_TYPE, HEAD_FLAGS, HEAD_SIZE
	}, nil)
	buf = append(buf, le16(uint16(crc32.ChecksumIEEE(endBody)&0xFFFF))...)
	buf = append(buf, endBody...)
	return buf
}

// rar5Vint encodes a RAR 5.0 vint (7 bits/byte, little-endian, high bit = continuation).
func rar5Vint(v uint64) []byte {
	var out []byte
	for {
		c := byte(v & 0x7F)
		v >>= 7
		if v != 0 {
			c |= 0x80
		}
		out = append(out, c)
		if v == 0 {
			return out
		}
	}
}

// rar5Block wraps a header body in CRC32 + HeaderSize(vint), per the RAR
// 5.0 technote's general block format: "Header CRC32 — CRC32 of header
// data starting from Header size field and up to and including the
// optional extra area", i.e. the CRC covers the HeaderSize vint PLUS the
// body; "Header size — size of header data starting from Header type
// field", i.e. the body length. (The previous fixture CRC'd only the body,
// so real RAR5 readers — bsdtar/libarchive — rejected every header as
// corrupt.)
func rar5Block(body []byte) []byte {
	size := rar5Vint(uint64(len(body)))
	hdr := make([]byte, 0, len(size)+len(body))
	hdr = append(hdr, size...)
	hdr = append(hdr, body...)
	out := le32(crc32.ChecksumIEEE(hdr))
	return append(out, hdr...)
}

func buildRAR5(bodies [][]byte) []byte {
	buf := append([]byte{}, rar5Magic...)
	for _, b := range bodies {
		buf = append(buf, rar5Block(b)...)
	}
	return buf
}

// rar5MainHeader / rar5EndHeader: type + flags + archive flags.
func rar5MainHeader() []byte {
	return bytes.Join([][]byte{rar5Vint(rar5HeaderTypeMain), rar5Vint(0), rar5Vint(0)}, nil)
}

func rar5EndHeader() []byte {
	// End-of-archive header fields per the technote: type, header flags,
	// end-of-archive flags (0 = last volume).
	return bytes.Join([][]byte{rar5Vint(rar5HeaderTypeEnd), rar5Vint(0), rar5Vint(0)}, nil)
}

// rar5EncryptionHeader: archive encryption header (type 4) — headers and
// data are password-encrypted. Minimal fields: archive flags = 0.
func rar5EncryptionHeader() []byte {
	return bytes.Join([][]byte{rar5Vint(rar5HeaderTypeEncryption), rar5Vint(0), rar5Vint(0)}, nil)
}

// rar5FileBody: type, flags (extra area + data area present), extra-area
// size, data size, file flags, unpacked size, attributes, compression
// information, host OS, name length, name, extra area — the technote's
// file-header field order (Compression information and Host OS are
// unconditional fields; the previous fixture omitted them, which real
// readers read as name-length garbage).
// The extra area carries a file-encryption record (type 0x01) when encrypt
// is true. Returns the RAW header body — wrap with rar5Block at assembly
// and emit the data-area bytes directly after the wrapped block (data
// areas follow their own header in RAR 5.0, before the next header, and
// are not counted in Header CRC or Header size).
func rar5FileBody(name string, unpacked uint64, encrypt bool, dataSize uint64) []byte {
	var extra []byte
	flags := uint64(0)
	if encrypt {
		recData := bytes.Join([][]byte{
			rar5Vint(0),      // encryption version (AES-256 v0)
			rar5Vint(0),      // record flags
			{0},              // KDF count
			make([]byte, 16), // salt
			make([]byte, 16), // IV
		}, nil)
		// Extra-area record per the rarlab technote ("Extra area record
		// format"): Size(vint) FIRST — "Size of record data starting from
		// Type", i.e. covering the Type field and the data but not the Size
		// field itself — then Type(vint), then data. (The previous fixture
		// emitted Type before Size, repeating the parser's error, so real
		// parsers saw a bogus 36-byte record of type 1.)
		rec := bytes.Join([][]byte{rar5Vint(rar5RecordFileEncryption), recData}, nil)
		extra = append(rar5Vint(uint64(len(rec))), rec...)
		flags |= rar5FlagExtraArea
	}
	if dataSize > 0 {
		flags |= rar5FlagDataArea
	}
	body := bytes.Join([][]byte{
		rar5Vint(rar5HeaderTypeFile),
		rar5Vint(flags),
	}, nil)
	if flags&rar5FlagExtraArea != 0 {
		body = append(body, rar5Vint(uint64(len(extra)))...)
	}
	if flags&rar5FlagDataArea != 0 {
		body = append(body, rar5Vint(dataSize)...)
	}
	body = append(body, rar5Vint(0)...) // file flags: not a directory
	body = append(body, rar5Vint(unpacked)...)
	body = append(body, rar5Vint(0)...) // attributes
	// Compression information: version 0 (low 6 bits), not solid, method 0
	// (store), dictionary 128 KiB (bits 11-15 = 0) — matches the stored
	// plaintext data area. Host OS: 0x0001 = Unix.
	body = append(body, rar5Vint(0)...)
	body = append(body, rar5Vint(1)...)
	body = append(body, rar5Vint(uint64(len(name)))...)
	body = append(body, name...)
	body = append(body, extra...)
	return body
}

// buildRAR5WithFile assembles sig + main + file header + data area + end,
// the real on-disk ordering for a one-file archive.
func buildRAR5WithFile(name string, payload []byte, encrypt bool) []byte {
	return bytes.Join([][]byte{
		rar5Magic,
		rar5Block(rar5MainHeader()),
		rar5Block(rar5FileBody(name, uint64(len(payload)), encrypt, uint64(len(payload)))),
		payload,
		rar5Block(rar5EndHeader()),
	}, nil)
}

// build7z assembles a real signature header: signature, version 0.04,
// StartHeaderCRC (CRC32 IEEE of the 20-byte StartHeader), StartHeader
// (NextHeaderOffset, NextHeaderSize, NextHeaderCRC), then the next header.
// NextHeaderOffset counts from byte 32; 0 places it right after.
func build7z(nextHeader []byte) []byte {
	sh := bytes.Join([][]byte{le64(0), le64(uint64(len(nextHeader)))}, nil) // offset 0, size, CRC
	sh = append(sh, le32(crc32.ChecksumIEEE(nextHeader))...)
	sigHeader := bytes.Join([][]byte{
		sevenzMagic,
		{0x00, 0x04},                 // version 0.04
		le32(crc32.ChecksumIEEE(sh)), // StartHeaderCRC
		sh,
	}, nil)
	return append(sigHeader, nextHeader...)
}

// sevenzStreamsInfoHeader builds PackInfo + UnpackInfo with the given coder
// ID, terminated properly (kCodersUnpackSize, kEnd, kEnd).
func sevenzStreamsInfoHeader(coderID []byte, coderFlags byte, coderProps []byte) []byte {
	var b []byte
	b = append(b, sevenzPropPackInfo)
	b = append(b, 0) // PackPos
	b = append(b, 1) // NumPackStreams
	b = append(b, sevenzPropSize)
	b = append(b, 32) // pack size (cosmetic)
	b = append(b, sevenzPropEnd)

	b = append(b, sevenzPropUnpackInfo)
	b = append(b, sevenzPropFolder)
	b = append(b, 1) // NumFolders
	b = append(b, 0) // External = inline
	b = append(b, 1) // NumCoders
	b = append(b, coderFlags)
	b = append(b, coderID...)
	if coderFlags&sevenzCoderAttrsFlag != 0 {
		b = append(b, byte(len(coderProps)))
		b = append(b, coderProps...)
	}
	b = append(b, sevenzPropSize) // kCodersUnpackSize
	b = append(b, 16)             // unpack size (cosmetic)
	b = append(b, sevenzPropEnd)
	b = append(b, sevenzPropEnd)
	return b
}

// sevenzEncryptedNextHeader: kEncodedHeader whose single coder is 7zAES —
// the real layout of a header-encrypted (-mhe=on) 7z archive.
func sevenzEncryptedNextHeader(withCoderProps bool) []byte {
	flags := byte(0x04) // codec ID size 4
	var props []byte
	if withCoderProps {
		flags |= sevenzCoderAttrsFlag
		props = []byte{0x53, 0x0B, 0x07, 0x0B, 0x19} // rounds/IV form, cosmetic
	}
	b := []byte{sevenzPropEncodedHdr}
	return append(b, sevenzStreamsInfoHeader(sevenzAESCodecID, flags, props)...)
}

// sevenzContentNextHeader: kHeader + main StreamsInfo with a plain LZMA2
// coder — a real content-bearing archive without encryption.
func sevenzContentNextHeader() []byte {
	b := []byte{sevenzPropHeader, sevenzPropStreamsInfo}
	b = append(b, sevenzStreamsInfoHeader([]byte{0x21}, 0x01, nil)...) // LZMA2, ID size 1
	b = append(b, sevenzPropEnd)
	return b
}

// --- Legacy DetectEncryptedArchive tests (bool wrapper) ---

func TestDetectEncryptedArchive_EncryptedZIP(t *testing.T) {
	// ZIP local file header: PK\x03\x04, then 2 bytes version, 2 bytes flag
	// Bit 0 of flag = encrypted
	data := []byte{0x50, 0x4B, 0x03, 0x04, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00}
	if !DetectEncryptedArchive(data, "application/zip") {
		t.Error("should detect encrypted ZIP (bit 0 of general purpose flag set)")
	}
}

func TestDetectEncryptedArchive_PlainZIP(t *testing.T) {
	// ZIP local file header with bit 0 clear = not encrypted
	data := []byte{0x50, 0x4B, 0x03, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	if DetectEncryptedArchive(data, "application/zip") {
		t.Error("should NOT detect unencrypted ZIP")
	}
}

func TestDetectEncryptedArchive_EncryptedZIP_HighBit(t *testing.T) {
	// Bit 0 set via 0x09 (bits 0 and 3)
	data := []byte{0x50, 0x4B, 0x03, 0x04, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00}
	if !DetectEncryptedArchive(data, "application/zip") {
		t.Error("should detect encrypted ZIP when bit 0 is set alongside other bits")
	}
}

func TestDetectEncryptedArchive_EncryptedRAR5(t *testing.T) {
	// Real RAR5 layout: signature (byte 7 is the constant 0x00 terminator —
	// it is NOT a flags byte) followed by an archive encryption header
	// (type 4). The old fixture set byte 7 to 0x80, which cannot occur in a
	// genuine RAR5 file.
	data := buildRAR5([][]byte{rar5EncryptionHeader()})
	if !DetectEncryptedArchive(data, "application/x-rar-compressed") {
		t.Error("should detect encrypted RAR5 via archive encryption header")
	}
	res := ScanArchive(data, DefaultArchiveBudget())
	if res.Status != ArchiveStatusIncomplete || !res.Encrypted {
		t.Errorf("RAR5 archive-encryption header: want Encrypted + Incomplete, got %+v", res)
	}
}

func TestDetectEncryptedArchive_PlainRAR5(t *testing.T) {
	// Signature + MAIN_HEAD + end-of-archive: no encryption anywhere.
	data := buildRAR5([][]byte{rar5MainHeader(), rar5EndHeader()})
	if DetectEncryptedArchive(data, "application/x-rar-compressed") {
		t.Error("should NOT detect unencrypted RAR5")
	}
	res := ScanArchive(data, DefaultArchiveBudget())
	if res.Status != ArchiveStatusOK || res.Encrypted || res.Entries != 0 {
		t.Errorf("plain header-only RAR5: want clean OK scan, got %+v", res)
	}
}

func TestDetectEncryptedArchive_RAR5FileEncryptionRecord(t *testing.T) {
	// Per-file encryption: file header whose extra area carries the
	// encryption record (type 0x01). RAR5 file flags have NO password bit;
	// this record is the only file-level encryption signal.
	data := buildRAR5WithFile("secret.doc", []byte("encrypted payload bytes"), true)
	if !DetectEncryptedArchive(data, "application/x-rar-compressed") {
		t.Error("should detect RAR5 file encryption record in extra area")
	}
	res := ScanArchive(data, DefaultArchiveBudget())
	if !res.Encrypted || res.Entries != 1 {
		t.Errorf("RAR5 file encryption record: want Encrypted with 1 entry, got %+v", res)
	}
}

func TestDetectEncryptedArchive_RAR5PlainFileHeader(t *testing.T) {
	data := buildRAR5WithFile("doc.txt", []byte("plain stored payload"), false)
	if DetectEncryptedArchive(data, "application/x-rar-compressed") {
		t.Error("should NOT detect encryption in plain RAR5")
	}
	res := ScanArchive(data, DefaultArchiveBudget())
	if res.Encrypted || res.Entries != 1 || res.Status != ArchiveStatusIncomplete {
		// Incomplete: the member was enumerated but its content is not
		// inspected for RAR in this package — never a silent clean OK.
		t.Errorf("plain RAR5 with member: want 1 entry, Incomplete, got %+v", res)
	}
}

func TestDetectEncryptedArchive_EncryptedRAR4(t *testing.T) {
	// Real RAR4 layout: MAIN_HEAD HEAD_FLAGS at absolute bytes 10-11;
	// MHD_PASSWORD (0x0080) = block headers encrypted. Byte 7 is the low
	// byte of HEAD_CRC (checksum data) — the old fixture put 0x80 there,
	// which is checksum noise, not a flags field.
	data := buildRAR4(rar4FlagMHDPassword, nil)
	if !DetectEncryptedArchive(data, "application/x-rar-compressed") {
		t.Error("should detect encrypted RAR4 via MHD_PASSWORD at bytes 10-11")
	}
	if data[7] == 0x80 {
		t.Error("fixture sanity: byte 7 is HEAD_CRC data, not the flags byte")
	}
	res := ScanArchive(data, DefaultArchiveBudget())
	if !res.Encrypted || res.Status != ArchiveStatusIncomplete {
		t.Errorf("RAR4 MHD_PASSWORD: want Encrypted + Incomplete, got %+v", res)
	}
}

func TestDetectEncryptedArchive_PlainRAR4(t *testing.T) {
	data := buildRAR4(0, nil)
	if DetectEncryptedArchive(data, "application/x-rar-compressed") {
		t.Error("should NOT detect unencrypted RAR4")
	}
	res := ScanArchive(data, DefaultArchiveBudget())
	if res.Encrypted || res.Status != ArchiveStatusOK {
		t.Errorf("plain RAR4: want clean OK, got %+v", res)
	}
}

func TestDetectEncryptedArchive_RAR4FilePassword(t *testing.T) {
	// LHD_PASSWORD (0x0004) in a FILE_HEAD: that member is encrypted. (The
	// ledger's "0x0004 at bytes 10-11" conflated this file-level bit with
	// MAIN_HEAD offsets; 0x0004 in MAIN_HEAD flags is LOCK.)
	files := []zipMember{{name: "doc.txt", data: []byte("content"), gpFlags: rar4FlagLHDPassword}}
	data := buildRAR4(0, files)
	if !DetectEncryptedArchive(data, "application/x-rar-compressed") {
		t.Error("should detect RAR4 file-level password flag")
	}
	res := ScanArchive(data, DefaultArchiveBudget())
	if !res.Encrypted || res.Entries != 1 {
		t.Errorf("RAR4 LHD_PASSWORD: want Encrypted, 1 entry, got %+v", res)
	}
}

func TestDetectEncryptedArchive_RAR4PlainFile(t *testing.T) {
	files := []zipMember{{name: "doc.txt", data: []byte("content")}}
	data := buildRAR4(0, files)
	if DetectEncryptedArchive(data, "application/x-rar-compressed") {
		t.Error("should NOT detect plain RAR4 file")
	}
	res := ScanArchive(data, DefaultArchiveBudget())
	if res.Encrypted || res.Entries != 1 || res.Status != ArchiveStatusIncomplete {
		t.Errorf("plain RAR4 file: want 1 entry, Incomplete, no encryption, got %+v", res)
	}
}

func TestDetectEncryptedArchive_Encrypted7z(t *testing.T) {
	// Real 7z header encryption: kEncodedHeader + StreamsInfo whose coder
	// is 7zAES (06 F1 07 01). The old fixtures read byte 12 — the low byte
	// of NextHeaderOffset, which is not an encryption field.
	data := build7z(sevenzEncryptedNextHeader(false))
	if !DetectEncryptedArchive(data, "application/x-7z-compressed") {
		t.Error("should detect encrypted 7z via kEncodedHeader AES coder")
	}
	res := ScanArchive(data, DefaultArchiveBudget())
	if !res.Encrypted || res.Status != ArchiveStatusIncomplete {
		t.Errorf("header-encrypted 7z: want Encrypted + Incomplete, got %+v", res)
	}
}

func TestDetectEncryptedArchive_Encrypted7z_CoderWithProperties(t *testing.T) {
	// Same AES detection with the coder carrying its attributes block
	// (real AES coders carry properties: salt flags + rounds).
	data := build7z(sevenzEncryptedNextHeader(true))
	if !DetectEncryptedArchive(data, "application/x-7z-compressed") {
		t.Error("should detect encrypted 7z whose AES coder carries properties")
	}
}

func TestDetectEncryptedArchive_Plain7z(t *testing.T) {
	data := build7z(sevenzContentNextHeader())
	if DetectEncryptedArchive(data, "application/x-7z-compressed") {
		t.Error("should NOT detect unencrypted 7z (LZMA2 coder)")
	}
	res := ScanArchive(data, DefaultArchiveBudget())
	if res.Encrypted || res.Status != ArchiveStatusIncomplete {
		// Content members exist; this package does not inspect them.
		t.Errorf("plain content 7z: want Incomplete without encryption, got %+v", res)
	}
}

func TestDetectEncryptedArchive_Empty7z(t *testing.T) {
	// NextHeaderSize == 0: an archive with no content — fully inspected.
	data := build7z(nil)
	res := ScanArchive(data, DefaultArchiveBudget())
	if res.Status != ArchiveStatusOK || res.Encrypted {
		t.Errorf("empty 7z: want clean OK, got %+v", res)
	}
	if DetectEncryptedArchive(data, "application/x-7z-compressed") {
		t.Error("empty 7z is not encrypted")
	}
}

func TestDetectEncryptedArchive_7z_CorruptStartHeaderCRC(t *testing.T) {
	// The StartHeader is CRC32-protected in every real 7z file; corrupting
	// it must yield Malformed, not a verdict.
	data := build7z(sevenzEncryptedNextHeader(false))
	data[9] ^= 0xFF
	res := ScanArchive(data, DefaultArchiveBudget())
	if res.Status != ArchiveStatusMalformed || res.Encrypted {
		t.Errorf("corrupt StartHeaderCRC: want Malformed without verdict, got %+v", res)
	}
}

func TestDetectEncryptedArchive_TooShort(t *testing.T) {
	// Less than 8 bytes should return false
	data := []byte{0x50, 0x4B}
	if DetectEncryptedArchive(data, "application/zip") {
		t.Error("data shorter than 8 bytes should not be detected as encrypted")
	}
}

func TestDetectEncryptedArchive_NonArchive(t *testing.T) {
	// Random bytes that don't match any archive signature
	data := []byte("hello world this is a test")
	if DetectEncryptedArchive(data, "text/plain") {
		t.Error("non-archive data should not be detected as encrypted archive")
	}
	res := ScanArchive(data, DefaultArchiveBudget())
	if res.Status != ArchiveStatusMalformed {
		t.Errorf("non-archive data: want Malformed, got %v", res.Status)
	}
}

func TestDetectEncryptedArchive_EmptyData(t *testing.T) {
	if DetectEncryptedArchive(nil, "application/zip") {
		t.Error("nil data should not be detected")
	}
	if DetectEncryptedArchive([]byte{}, "application/zip") {
		t.Error("empty data should not be detected")
	}
}

func TestDetectEncryptedArchive_ZIPCentralDirectory(t *testing.T) {
	// CORRECTION of the old fixture: an EOCD at offset 0 with flag bits at
	// 6-7 cannot occur in a real ZIP (EOCD lives at the end, comment-length
	// validated; the old bytes were EOCD fields misread as a local-header
	// flag). The dead EOCD-at-0 branch is gone: such bytes are Malformed
	// and NOT detected. Real EOCD-based detection is covered by the
	// encrypted-second-entry test below.
	stale := []byte{0x50, 0x4B, 0x05, 0x06, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00}
	if DetectEncryptedArchive(stale, "application/zip") {
		t.Error("EOCD-at-offset-0 is not a real ZIP layout; must not be detected")
	}
	if res := ScanArchive(stale, DefaultArchiveBudget()); res.Status != ArchiveStatusMalformed {
		t.Errorf("EOCD-at-0 bytes: want Malformed, got %v", res.Status)
	}
}

func TestDetectEncryptedArchive_ZIPRealEOCDDetectsLaterEncryptedEntry(t *testing.T) {
	// The first entry is plain; the second carries the encryption bit in
	// BOTH its local header and central-directory entry, exactly as real
	// ZipCrypto writers emit. Real EOCD at the end.
	zip := buildZip([]zipMember{
		{name: "readme.txt", data: []byte("nothing to see here")},
		{name: "payload.bin", gpFlags: zipFlagEncrypt, data: []byte{0x9A, 0x1F, 0x77, 0xC2}},
	}, "")

	// Mutation-proofing: the first entry is demonstrably plain, so a
	// regression to first-local-header-only logic returns false and this
	// test fails.
	if binary.LittleEndian.Uint16(zip[6:8])&zipFlagEncrypt != 0 {
		t.Fatal("fixture sanity: first local header must be unencrypted")
	}
	if !DetectEncryptedArchive(zip, "application/zip") {
		t.Error("should detect encryption in the SECOND entry via central directory walk")
	}
	res := ScanArchive(zip, DefaultArchiveBudget())
	if !res.Encrypted || res.Entries != 2 {
		t.Errorf("two-entry zip: want Encrypted, 2 entries, got %+v", res)
	}
	if res.Status != ArchiveStatusIncomplete {
		t.Errorf("encrypted member is not inspectable: want Incomplete, got %v", res.Status)
	}
}

func TestDetectEncryptedArchive_ZIPWithComment(t *testing.T) {
	// EOCD comment-length validation: a real trailing comment must not
	// defeat EOCD discovery — and a fake EOCD signature embedded inside the
	// comment must not hijack it.
	zip := buildZip([]zipMember{
		{name: "a.txt", data: []byte("plain")},
		{name: "b.txt", gpFlags: zipFlagEncrypt, data: []byte{0xDE, 0xAD}},
	}, "... PK\x05\x06 fake signature inside comment ...")

	if !DetectEncryptedArchive(zip, "application/zip") {
		t.Error("should find the real EOCD past a comment containing a fake signature")
	}
}

// --- Corrupted archive defense tests ---

func TestDetectEncryptedArchive_BoundaryLength_ZIP(t *testing.T) {
	// Exactly 8 bytes — just enough to read the flag field at offset 6-7.
	data := []byte{0x50, 0x4B, 0x03, 0x04, 0x00, 0x00, 0x01, 0x00}
	if !DetectEncryptedArchive(data, "application/zip") {
		t.Error("should detect encrypted ZIP with exactly 8 bytes")
	}
	if res := ScanArchive(data, DefaultArchiveBudget()); res.Status != ArchiveStatusMalformed {
		t.Errorf("8-byte truncated zip: want Malformed (no EOCD), got %v", res.Status)
	}
}

func TestDetectEncryptedArchive_BoundaryLength_RAR5(t *testing.T) {
	// CORRECTION: the old fixture asserted an 8-byte RAR5 with byte 7 = 0x80
	// detects — an impossible layout. A real RAR5 encryption record needs a
	// signature plus a CRC32'd header; the minimal genuine fixture detects.
	data := buildRAR5([][]byte{rar5EncryptionHeader()})
	if !DetectEncryptedArchive(data, "application/x-rar-compressed") {
		t.Error("should detect a real minimal RAR5 encryption record")
	}

	bare := append([]byte{}, rar5Magic...)
	if DetectEncryptedArchive(bare, "application/x-rar-compressed") {
		t.Error("bare RAR5 signature carries no encryption evidence")
	}
}

func TestDetectEncryptedArchive_BoundaryLength_7z(t *testing.T) {
	// CORRECTION: the old fixture asserted byte-12 detection at 13 bytes;
	// byte 12 is NextHeaderOffset data and a 13-byte 7z is truncated. The
	// smallest real 7z is the 32-byte signature header (NextHeaderSize 0).
	full := build7z(nil)
	if len(full) != 32 {
		t.Fatalf("fixture sanity: signature header is 32 bytes, got %d", len(full))
	}
	if DetectEncryptedArchive(full, "application/x-7z-compressed") {
		t.Error("empty 7z should not be detected as encrypted")
	}
	truncated := full[:13]
	if DetectEncryptedArchive(truncated, "application/x-7z-compressed") {
		t.Error("truncated 13-byte 7z should not be detected")
	}
}

func TestDetectEncryptedArchive_TruncatedZIP(t *testing.T) {
	// ZIP header truncated to 7 bytes — not enough for the flag field.
	// Should return false safely (no panic).
	data := []byte{0x50, 0x4B, 0x03, 0x04, 0x00, 0x00, 0x01}
	result := DetectEncryptedArchive(data, "application/zip")
	if result {
		t.Error("truncated ZIP should return false, not panic")
	}
}

func TestDetectEncryptedArchive_TruncatedRAR(t *testing.T) {
	data := []byte{'R', 'a', 'r', '!', 0x1a, 0x07, 0x01}
	result := DetectEncryptedArchive(data, "application/x-rar-compressed")
	if result {
		t.Error("truncated RAR signature should return false, not panic")
	}
}

func TestDetectEncryptedArchive_Truncated7z(t *testing.T) {
	data := []byte{0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	result := DetectEncryptedArchive(data, "application/x-7z-compressed")
	if result {
		t.Error("truncated 7z should return false, not panic")
	}
}

func TestDetectEncryptedArchive_ExactLengths_PanicFree(t *testing.T) {
	// Test every length from 0 to 64 bytes to ensure no panic.
	for l := 0; l <= 64; l++ {
		data := make([]byte, l)
		for i := range data {
			data[i] = 'A'
		}
		// This must never panic.
		result := DetectEncryptedArchive(data, "application/zip")
		_ = result
		_ = ScanArchive(data, DefaultArchiveBudget()) // direct scan: no recovery net
	}
}

func TestDetectEncryptedArchive_AllZeros(t *testing.T) {
	// Zeroed data of various lengths — should never panic.
	for _, l := range []int{0, 1, 4, 8, 16, 32, 64} {
		data := make([]byte, l)
		result := DetectEncryptedArchive(data, "application/zip")
		if result {
			t.Errorf("zeroed data of length %d should not be detected as encrypted", l)
		}
	}
}

func TestDetectEncryptedArchive_LargeInput(t *testing.T) {
	// Large input should be handled safely (only header bytes inspected).
	data := make([]byte, 1024*1024) // 1 MiB
	data[0] = 'P'
	data[1] = 'K'
	data[2] = 0x03
	data[3] = 0x04
	data[6] = 0x01 // encryption bit set
	data[7] = 0x00
	if !DetectEncryptedArchive(data, "application/zip") {
		t.Error("should detect encrypted ZIP even with large input")
	}
}

func TestDetectEncryptedArchive_MaliciousCrafted(t *testing.T) {
	// Craft a buffer that looks like a RAR header but has insufficient length
	// for the MAIN_HEAD fields if bounds checking is missing.
	data := []byte{'R', 'a', 'r', '!', 0x1a, 0x07}
	// Must not panic.
	result := DetectEncryptedArchive(data, "application/x-rar-compressed")
	if result {
		t.Error("6-byte RAR-like data should not be detected")
	}
}

// --- ScanArchive: nesting depth seam (r2-C7-3 / r3-C7-3) ---

func scanBudget(maxDepth int) ArchiveBudget {
	return ArchiveBudget{MaxDepth: maxDepth, MaxEntries: 100, MaxUncompressedBytes: 1 << 30}
}

func TestScanArchive_StoredNestedZIP_DepthThree_OK(t *testing.T) {
	// 3-level stored-ZIP nest within the cap → OK with Depth == 3.
	// Mutation contract: removing the depth increment breaks Depth == 3;
	// removing the cap breaks the over-cap test below.
	inner := buildZip([]zipMember{{name: "file.txt", data: []byte("innermost")}}, "")
	mid := buildZip([]zipMember{{name: "inner.zip", data: inner}}, "")
	outer := buildZip([]zipMember{{name: "mid.zip", data: mid}}, "")

	res := ScanArchive(outer, scanBudget(4))
	if res.Status != ArchiveStatusOK {
		t.Fatalf("3-level stored nest within cap: want OK, got %v (%+v)", res.Status, res)
	}
	if res.Depth != 3 {
		t.Errorf("want Depth == 3, got %d — depth increment broken?", res.Depth)
	}
	if res.Entries != 3 {
		t.Errorf("want 3 entries (one per level), got %d", res.Entries)
	}
	if res.Encrypted {
		t.Error("plain nest must not be flagged encrypted")
	}
}

func TestScanArchive_StoredNestedZIP_OverDepth_BudgetExceeded(t *testing.T) {
	// Chain of 4 zip levels against MaxDepth 3 → BudgetExceeded.
	payload := []byte("bottom")
	var blob []byte
	blob = buildZip([]zipMember{{name: "f.txt", data: payload}}, "")
	for i := 0; i < 3; i++ {
		blob = buildZip([]zipMember{{name: "wrap.zip", data: blob}}, "")
	}

	res := ScanArchive(blob, scanBudget(3))
	if res.Status != ArchiveStatusBudgetExceeded {
		t.Fatalf("over-cap stored nest: want BudgetExceeded, got %v (%+v)", res.Status, res)
	}
	if res.Depth > 3 {
		t.Errorf("depth reported %d must not exceed budget 3", res.Depth)
	}
}

// --- ScanArchive: discriminating fixtures (r3-C7-3 point 3) ---

func deepStoredZipChain(levels int) []byte {
	blob := buildZip([]zipMember{{name: "bottom.txt", data: []byte("x")}}, "")
	for i := 1; i < levels; i++ {
		blob = buildZip([]zipMember{{name: "nested.zip", data: blob}}, "")
	}
	return blob
}

func deflateBytes(t *testing.T, b []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w, err := flate.NewWriter(&buf, flate.BestCompression)
	if err != nil {
		t.Fatalf("flate.NewWriter: %v", err)
	}
	if _, err := w.Write(b); err != nil {
		t.Fatalf("flate write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("flate close: %v", err)
	}
	return buf.Bytes()
}

func TestScanArchive_CompressedMemberHidingOverDepthArchive_Incomplete(t *testing.T) {
	// r3 discriminating fixture: outer stored-ZIP within ALL budgets
	// containing a single COMPRESSED (Deflate) member that by construction
	// contains a nested archive exceeding MaxDepth. The compressed member
	// is NOT recursed into, so the scan is Incomplete (reporting inspected
	// Depth 1) — NOT OK (clean miss), NOT BudgetExceeded.
	deepInner := deepStoredZipChain(4) // would be Depth 5 > MaxDepth 3 if inspected
	compressed := deflateBytes(t, deepInner)

	outer := buildZip([]zipMember{{
		name:       "hidden.zip",
		method:     8, // Deflate
		data:       compressed,
		uncompSize: uint32(len(deepInner)),
	}}, "")

	res := ScanArchive(outer, scanBudget(3))
	if res.Status != ArchiveStatusIncomplete {
		t.Fatalf("compressed member hiding over-depth archive: want Incomplete, got %v (%+v)", res.Status, res)
	}
	if res.Encrypted {
		t.Error("compressed member is not encrypted: Encrypted must stay false")
	}
	if res.Depth != 1 {
		t.Errorf("only the outer level is inspected: want Depth 1, got %d", res.Depth)
	}
	if res.Entries != 1 {
		t.Errorf("want 1 entry, got %d", res.Entries)
	}
}

func TestScanArchive_CompressedMemberContrastStored_BudgetExceeded(t *testing.T) {
	// Contrast fixture: the IDENTICAL nest with the inner level STORED —
	// the walk can inspect it, so the same content yields BudgetExceeded.
	// (Mutation contract: conflating Incomplete with BudgetExceeded fails
	// this pair.)
	deepInner := deepStoredZipChain(4)

	outer := buildZip([]zipMember{{
		name:       "visible.zip",
		method:     0, // STORED — inspectable without decompression
		data:       deepInner,
		uncompSize: uint32(len(deepInner)),
	}}, "")

	res := ScanArchive(outer, scanBudget(3))
	if res.Status != ArchiveStatusBudgetExceeded {
		t.Fatalf("identical nest, stored member: want BudgetExceeded, got %v (%+v)", res.Status, res)
	}
}

// --- ScanArchive: budget exhaustion (WP-C) ---

func TestScanArchive_MaxEntriesExhaustion(t *testing.T) {
	members := make([]zipMember, 5)
	for i := range members {
		members[i] = zipMember{name: "f.txt", data: []byte("x")}
	}
	zip := buildZip(members, "")

	res := ScanArchive(zip, ArchiveBudget{MaxDepth: 8, MaxEntries: 3, MaxUncompressedBytes: 1 << 30})
	if res.Status != ArchiveStatusBudgetExceeded {
		t.Errorf("5 entries vs MaxEntries 3: want BudgetExceeded, got %v (%+v)", res.Status, res)
	}
}

func TestScanArchive_DeclaredUncompressedSizeExhaustion(t *testing.T) {
	// Declared sizes are header fields: a member may CLAIM 2 GiB
	// uncompressed while the archive is tiny — the declared-size budget
	// must catch the bomb without decompressing anything.
	zip := buildZip([]zipMember{{
		name:       "bomb.txt",
		data:       []byte{0x00},
		uncompSize: 2 << 30, // 2 GiB declared
	}}, "")

	res := ScanArchive(zip, ArchiveBudget{MaxDepth: 8, MaxEntries: 100, MaxUncompressedBytes: 1 << 30})
	if res.Status != ArchiveStatusBudgetExceeded {
		t.Errorf("declared 2 GiB vs 1 GiB budget: want BudgetExceeded, got %v (%+v)", res.Status, res)
	}
}

func TestScanArchive_MaxEntriesSharedAcrossNesting(t *testing.T) {
	// The entry budget is shared across nested container levels: an inner
	// archive cannot smuggle unbounded entries past the cap.
	innerMembers := make([]zipMember, 4)
	for i := range innerMembers {
		innerMembers[i] = zipMember{name: "f.txt", data: []byte("x")}
	}
	inner := buildZip(innerMembers, "")
	outer := buildZip([]zipMember{{name: "inner.zip", data: inner}}, "")

	res := ScanArchive(outer, ArchiveBudget{MaxDepth: 8, MaxEntries: 3, MaxUncompressedBytes: 1 << 30})
	if res.Status != ArchiveStatusBudgetExceeded {
		t.Errorf("nested entries vs shared MaxEntries 3: want BudgetExceeded, got %v (%+v)", res.Status, res)
	}
}

func TestScanArchive_RARDeclaredSizeBudget(t *testing.T) {
	// RAR4 UNP_SIZE is a declared field; the bomb guard applies without
	// decompression.
	files := []zipMember{{name: "bomb", data: []byte{0x00}, uncompSize: 2 << 30, gpFlags: rar4FlagLHDPassword}}
	data := buildRAR4(0, files)
	res := ScanArchive(data, ArchiveBudget{MaxDepth: 8, MaxEntries: 100, MaxUncompressedBytes: 1 << 30})
	if res.Status != ArchiveStatusBudgetExceeded {
		t.Errorf("RAR4 declared 2 GiB vs 1 GiB: want BudgetExceeded, got %v (%+v)", res.Status, res)
	}
}

func TestScanArchive_NonPositiveBudgetFailsClosed(t *testing.T) {
	zip := buildZip([]zipMember{{name: "f.txt", data: []byte("x")}}, "")
	for _, budget := range []ArchiveBudget{
		{},
		{MaxDepth: 0, MaxEntries: 100, MaxUncompressedBytes: 1 << 30},
		{MaxDepth: 8, MaxEntries: 0, MaxUncompressedBytes: 1 << 30},
		{MaxDepth: 8, MaxEntries: 100, MaxUncompressedBytes: 0},
	} {
		res := ScanArchive(zip, budget)
		if res.Status != ArchiveStatusBudgetExceeded {
			t.Errorf("budget %+v: want BudgetExceeded (fail closed), got %v", budget, res.Status)
		}
	}
}

func TestDefaultArchiveBudget_Sane(t *testing.T) {
	b := DefaultArchiveBudget()
	if b.MaxDepth != 8 || b.MaxEntries != 4096 || b.MaxUncompressedBytes != 1<<30 {
		t.Errorf("DefaultArchiveBudget = %+v, want depth 8 / entries 4096 / 1 GiB", b)
	}
}

// --- ZIP64 and multi-disk boundaries ---

func TestScanArchive_ZIP64Sentinel_Incomplete(t *testing.T) {
	// EOCD with 0xFFFFFFFF sentinels (ZIP64): the central directory is not
	// locatable by this scan — members uninspectable, typed Incomplete.
	zip := buildZip([]zipMember{{name: "f.txt", data: []byte("x")}}, "")
	eocd := len(zip) - 22
	binary.LittleEndian.PutUint32(zip[eocd+16:eocd+20], 0xFFFFFFFF) // cdOffset sentinel

	res := ScanArchive(zip, DefaultArchiveBudget())
	if res.Status != ArchiveStatusIncomplete {
		t.Errorf("ZIP64 sentinel: want Incomplete, got %v (%+v)", res.Status, res)
	}
}

func TestScanArchive_MultiDisk_Incomplete(t *testing.T) {
	zip := buildZip([]zipMember{{name: "f.txt", data: []byte("x")}}, "")
	eocd := len(zip) - 22
	binary.LittleEndian.PutUint16(zip[eocd+4:eocd+6], 1) // disk number 1

	res := ScanArchive(zip, DefaultArchiveBudget())
	if res.Status != ArchiveStatusIncomplete {
		t.Errorf("multi-disk archive: want Incomplete, got %v (%+v)", res.Status, res)
	}
}

// --- Malformed / adversarial corpus (WP-C) ---

func TestScanArchive_MalformedCorpus_NoPanic(t *testing.T) {
	realFixtures := [][]byte{
		buildZip([]zipMember{{name: "f.txt", data: []byte("hello")}}, ""),
		buildZip([]zipMember{{name: "f.txt", gpFlags: zipFlagEncrypt, data: []byte("enc")}}, "comment"),
		buildRAR4(rar4FlagMHDPassword, nil),
		buildRAR4(0, []zipMember{{name: "a", data: []byte("data")}}),
		buildRAR5([][]byte{rar5EncryptionHeader()}),
		buildRAR5WithFile("f", []byte("payload"), true),
		build7z(sevenzEncryptedNextHeader(true)),
		build7z(sevenzContentNextHeader()),
		build7z(nil),
	}

	// 1. Every prefix of every real fixture, every length: no panic.
	for _, fx := range realFixtures {
		for l := 0; l <= len(fx); l++ {
			res := ScanArchive(fx[:l], DefaultArchiveBudget())
			_ = res.Status
		}
	}

	// 2. Single-byte mutations of every real fixture: no panic, verdicts
	// only through the typed status.
	for _, fx := range realFixtures {
		for i := 0; i < len(fx); i++ {
			mutated := append([]byte{}, fx...)
			mutated[i] ^= 0xA5
			res := ScanArchive(mutated, DefaultArchiveBudget())
			_ = res.Status
		}
	}

	// 3. Deterministic pseudo-random garbage: no panic.
	rng := rand.New(rand.NewSource(20260912))
	for i := 0; i < 2000; i++ {
		blob := make([]byte, rng.Intn(512))
		rng.Read(blob)
		res := ScanArchive(blob, DefaultArchiveBudget())
		_ = res.Status
	}

	// 4. Archive magic followed by huge vint/size fields: bounds must hold.
	hostile := append([]byte{}, rar5Magic...)
	for i := 0; i < 40; i++ {
		hostile = append(hostile, 0xFF) // maximal vints forever
	}
	_ = ScanArchive(hostile, DefaultArchiveBudget())

	hostile7z := append([]byte{}, sevenzMagic...)
	hostile7z = append(hostile7z, make([]byte, 26)...)
	binary.LittleEndian.PutUint64(hostile7z[12:20], 1<<40) // absurd NextHeaderOffset
	_ = ScanArchive(hostile7z, DefaultArchiveBudget())
}

func TestScanArchive_TruncatedRealFixtures_TypedStatuses(t *testing.T) {
	// Truncation yields Malformed (or a header-level verdict from the
	// bytes that survived) — never a panic, never a silent OK.
	fixtures := [][]byte{
		buildZip([]zipMember{{name: "f.txt", gpFlags: zipFlagEncrypt, data: []byte("enc")}}, ""),
		buildRAR5([][]byte{rar5EncryptionHeader()}),
		build7z(sevenzEncryptedNextHeader(false)),
	}
	for _, fx := range fixtures {
		for l := 0; l < len(fx); l++ {
			res := ScanArchive(fx[:l], DefaultArchiveBudget())
			if res.Status == ArchiveStatusOK {
				t.Errorf("truncated fixture (len %d/%d) must not scan as OK", l, len(fx))
			}
		}
	}
}

// --- Astra L2-C7 impl-r2 delta: 7z kCRC panic, RAR4 ENDARC, RAR5 extra records ---

func TestScanArchive_7zKCRCDefinedCountOverflow_NoPanic(t *testing.T) {
	// Astra L2-C7: the kCRC branch accepted an attacker-controlled defined
	// count and computed int(defined)*4 without overflow checking; a count
	// of 2^61 wrapped the product negative, drove pos negative, and the
	// next b[pos] panicked — with no recovery boundary in ScanArchive. The
	// fixture is a genuine 7z file (build7z computes both CRCs): the
	// 9-byte ReadNumber form 0xFF,0x00…,0x20 encodes exactly 2^61
	// (0x20 << 56), the smallest value whose *4 product overflows int64.
	streamsInfo := []byte{
		sevenzPropPackInfo,
		0, // PackPos = 0
		1, // NumPackStreams = 1
		sevenzPropCRC,
		0,                                                    // allAreDefined = 0: the defined count follows
		0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, // defined count = 2^61
	}
	nh := append([]byte{sevenzPropHeader, sevenzPropStreamsInfo}, streamsInfo...)
	data := build7z(nh)

	// 1. The internal PackInfo walk has NO recovery net: the count must be
	// rejected by bounds-checked arithmetic itself. Mutation check:
	// reverting to unchecked int(defined)*4 panics right here.
	s := &archiveScan{budget: DefaultArchiveBudget()}
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("7z kCRC defined-count arithmetic panicked: %v", r)
			}
		}()
		s.sevenzStreamsInfo(streamsInfo)
	}()
	if !s.failed() || s.status != ArchiveStatusMalformed {
		t.Errorf("hostile kCRC count: want failed Malformed, got failed=%v status=%v", s.failed(), s.status)
	}

	// 2. End-to-end through the public boundary: typed Malformed, never a
	// panic, never a verdict.
	res := ScanArchive(data, DefaultArchiveBudget())
	if res.Status != ArchiveStatusMalformed || res.Encrypted {
		t.Errorf("7z kCRC count overflow fixture: want Malformed without encryption, got %+v", res)
	}
}

func TestRAR4Fixture_ENDARCIsSpecConstant(t *testing.T) {
	// Astra L2-C7: RAR 4.x ENDARC_HEAD is HEAD_TYPE 0x7b (technote block
	// table; Kaitai Struct rar block_types: "0x7b: terminator"; forensics
	// literature: "HEAD_TYPE=0x7b terminator"). The previous 0x3b matched
	// no real block, so every real RAR4 archive walked off its end and
	// scanned Malformed instead of terminating at its end block.
	data := buildRAR4(0, []zipMember{{name: "a.txt", data: []byte("x")}})
	// ENDARC is the last 7 bytes: HEAD_CRC(2) HEAD_TYPE(1) HEAD_FLAGS(2)
	// HEAD_SIZE(2); HEAD_TYPE sits at len-5.
	if got := data[len(data)-5]; got != 0x7b {
		t.Fatalf("fixture ENDARC HEAD_TYPE = %#x, want 0x7b", got)
	}
	res := ScanArchive(data, DefaultArchiveBudget())
	// Reaching the spec ENDARC terminates the walk normally: the member
	// stays enumerated-Incomplete, never Malformed.
	if res.Status != ArchiveStatusIncomplete || res.Entries != 1 {
		t.Errorf("RAR4 with spec ENDARC: want 1 entry Incomplete, got %+v", res)
	}
	// Parser-discriminating check: force a genuine 0x7b ENDARC byte into a
	// copy of the archive (what a real RAR writer emits). Mutation check:
	// with the old 0x3b constant the walk no longer recognizes the end
	// block, runs off the archive's end, and reports Malformed.
	patched := append([]byte{}, data...)
	patched[len(patched)-5] = 0x7b
	if res := ScanArchive(patched, DefaultArchiveBudget()); res.Status != ArchiveStatusIncomplete || res.Entries != 1 {
		t.Errorf("RAR4 with real 0x7b ENDARC byte: want 1 entry Incomplete, got %+v", res)
	}
}

func TestRAR5ExtraRecordFixture_SizeBeforeType(t *testing.T) {
	// Astra L2-C7: RAR5 extra-area records encode Size(vint) FIRST, with
	// Size covering "record data starting from Type" — the Type field and
	// the data, but not the Size field itself (rarlab technote.htm, "Extra
	// area record format"). The previous fixture emitted Type before Size,
	// repeating the parser's error. Byte-level fixture evidence: the file
	// header body must end with Size=36, Type=0x01, then the 35 data bytes
	// (version 0, flags 0, KDF count 0, 16-byte salt, 16-byte IV).
	body := rar5FileBody("secret.doc", 23, true, 0)
	n := len(body)
	if n < 37 {
		t.Fatalf("fixture body too short: %d bytes", n)
	}
	tail := body[n-37:]
	if tail[0] != 36 || tail[1] != rar5RecordFileEncryption {
		t.Fatalf("fixture extra record must be Size(36)-then-Type(0x01), got % x", tail[:2])
	}
	for i, b := range tail[2:] {
		if b != 0 {
			t.Fatalf("fixture record data byte %d = %#x, want 0 (version/flags/KDF/salt/IV zeros)", i, b)
		}
	}
}

func TestScanArchive_RAR5ExtraRecordSizeOverrun_Malformed(t *testing.T) {
	// A record whose declared Size exceeds the remaining extra area is
	// malformed: the parser must validate Size against the area bound
	// before skipping (impossible in the old type-first layout, which never
	// knew where the next record began).
	body := bytes.Join([][]byte{
		rar5Vint(rar5HeaderTypeFile),
		rar5Vint(rar5FlagExtraArea),
		rar5Vint(3),              // extra area size: last 3 bytes of the body
		rar5Vint(0),              // file flags
		rar5Vint(0),              // unpacked size
		rar5Vint(0),              // attributes
		rar5Vint(1), []byte("n"), // name length + name
		rar5Vint(9), rar5Vint(rar5RecordFileEncryption), []byte{0xAA}, // record: Size=9, only 1 byte remains after Type
	}, nil)
	data := buildRAR5([][]byte{rar5MainHeader(), body, rar5EndHeader()})
	res := ScanArchive(data, DefaultArchiveBudget())
	if res.Status != ArchiveStatusMalformed {
		t.Errorf("RAR5 extra record Size overrun: want Malformed, got %+v", res)
	}
}

// --- DetectPasswordInBody tests ---

func TestDetectPasswordInBody_English(t *testing.T) {
	cases := []string{
		"password is hunter2",
		"Password: secret123",
		"password: welcome",
		"password = mypass",
		"password=abc123",
	}
	for _, c := range cases {
		if !DetectPasswordInBody(c) {
			t.Errorf("should detect password pattern: %q", c)
		}
	}
}

func TestDetectPasswordInBody_Chinese(t *testing.T) {
	cases := []string{
		"密码是 123456",
		"密码：abc123",
		"密码: hello",
		"密码为 test123",
		"密码= secret",
		"解压密码是 888888",
		"解压密码：test123",
		"解压密码: hello",
		"解压密码为 passw0rd",
		"解压密码= abc",
	}
	for _, c := range cases {
		if !DetectPasswordInBody(c) {
			t.Errorf("should detect Chinese password pattern: %q", c)
		}
	}
}

func TestDetectPasswordInBody_ShortForms(t *testing.T) {
	cases := []string{
		"pw: abc123",
		"pw: hunter2",
		"pw:secret",
		"pass: mysecret",
		"pass: hello123",
		"PASS: test",
	}
	for _, c := range cases {
		if !DetectPasswordInBody(c) {
			t.Errorf("should detect short-form password pattern: %q", c)
		}
	}
}

func TestDetectPasswordInBody_NoMatch(t *testing.T) {
	cases := []string{
		"hello world",
		"please find the attached document",
		"thank you for your email",
		"password",              // no password value given
		"the password field is", // no actual password
		"",                      // empty string
	}
	for _, c := range cases {
		if DetectPasswordInBody(c) {
			t.Errorf("should NOT detect password pattern: %q", c)
		}
	}
}

func TestDetectPasswordInBody_CaseInsensitive(t *testing.T) {
	cases := []string{
		"PASSWORD is secret",
		"Password IS hunter2",
		"PW: abc",
		"Pass: test",
	}
	for _, c := range cases {
		if !DetectPasswordInBody(c) {
			t.Errorf("should detect case-insensitive pattern: %q", c)
		}
	}
}

func TestDetectPasswordInBody_Multiline(t *testing.T) {
	body := `Dear user,

Please find the attached document.

The password is: secure123

Best regards,
Sender`
	if !DetectPasswordInBody(body) {
		t.Error("should detect password in multiline body")
	}
}

// --- Straggler-wave gap tests: malformed-arm coverage per container format ---

func TestArchiveStatus_String_AllStatuses(t *testing.T) {
	cases := []struct {
		status ArchiveStatus
		want   string
	}{
		{ArchiveStatusOK, "ok"},
		{ArchiveStatusBudgetExceeded, "budget_exceeded"},
		{ArchiveStatusMalformed, "malformed"},
		{ArchiveStatusIncomplete, "incomplete"},
		{ArchiveStatus(99), "unknown"},
	}
	for _, tc := range cases {
		if got := tc.status.String(); got != tc.want {
			t.Errorf("ArchiveStatus(%d).String() = %q, want %q", uint8(tc.status), got, tc.want)
		}
	}
}

func TestScanArchive_ContainerGuard_NoOpAfterFailure(t *testing.T) {
	// White-box: container() must be a no-op once the scan has failed —
	// a nested walk can never resurrect a terminal outcome.
	s := &archiveScan{budget: DefaultArchiveBudget(), status: ArchiveStatusMalformed}
	s.container(buildZip([]zipMember{{name: "f.txt", data: []byte("x")}}, ""), 1)
	res := s.result()
	if res.Status != ArchiveStatusMalformed {
		t.Errorf("status = %v, want unchanged malformed", res.Status)
	}
	if res.Entries != 0 || res.Depth != 0 {
		t.Errorf("failed scan must not walk: entries=%d depth=%d, want 0/0", res.Entries, res.Depth)
	}
}

// buildZipLocalHeaders emits n local file headers with the given GP flags
// and NO central directory or EOCD — the truncated/streaming shape that
// scanZipLocalFallback walks.
func buildZipLocalHeaders(n int, gpFlags uint16) []byte {
	var buf []byte
	for i := 0; i < n; i++ {
		name := []byte{byte('a' + i)}
		buf = append(buf, zipLocalSig...)
		buf = append(buf, le16(20)...) // version needed
		buf = append(buf, le16(gpFlags)...)
		buf = append(buf, le16(0)...) // method store
		buf = append(buf, le16x2(0, 0)...)
		buf = append(buf, le32(0)...) // CRC
		buf = append(buf, le32(0)...) // compressed size
		buf = append(buf, le32(0)...) // uncompressed size
		buf = append(buf, le16(uint16(len(name)))...)
		buf = append(buf, le16(0)...) // extra len
		buf = append(buf, name...)
	}
	return buf
}

func TestScanArchive_ZIPLocalFallback_EntryBudgetExhaustion(t *testing.T) {
	// Truncated ZIP (no EOCD) with more local headers than MaxEntries:
	// the fallback walk must stop at the entry budget.
	data := buildZipLocalHeaders(3, 0)
	res := ScanArchive(data, ArchiveBudget{MaxDepth: 8, MaxEntries: 2, MaxUncompressedBytes: 1 << 30})
	if res.Status != ArchiveStatusBudgetExceeded {
		t.Errorf("3 local headers vs MaxEntries 2: want BudgetExceeded, got %v (%+v)", res.Status, res)
	}
	if res.Entries != 3 {
		t.Errorf("entries = %d, want 3 (counter increments before the budget check)", res.Entries)
	}
}

func TestScanArchive_ZIPLocalFallback_DataDescriptor_StopsIncomplete(t *testing.T) {
	// Streaming entry (flag bit 3): sizes live in an unlocatable trailing
	// descriptor, so the walk must stop and the scan stay non-OK.
	data := buildZipLocalHeaders(2, zipFlagDataDescriptor)
	res := ScanArchive(data, ArchiveBudget{MaxDepth: 8, MaxEntries: 100, MaxUncompressedBytes: 1 << 30})
	if res.Status != ArchiveStatusMalformed {
		t.Errorf("EOCD-less ZIP: want Malformed (terminal), got %v (%+v)", res.Status, res)
	}
	if res.Entries != 1 {
		t.Errorf("entries = %d, want 1 (walk stops at descriptor)", res.Entries)
	}
}

func TestScanArchive_RAR4_MainHeadSizeTooSmall(t *testing.T) {
	// MAIN_HEAD with HEAD_SIZE < 13 cannot hold the documented fields.
	data := bytes.Join([][]byte{
		rar4Magic,
		le16(0),         // HEAD_CRC (unchecked)
		{rar4TypeMain},  // HEAD_TYPE
		le16(0),         // HEAD_FLAGS
		le16(12),        // HEAD_SIZE = 12 < 13 minimum
		make([]byte, 8), // RESERVED1/2 + padding so len >= 7+13
	}, nil)
	res := ScanArchive(data, DefaultArchiveBudget())
	if res.Status != ArchiveStatusMalformed {
		t.Errorf("MAIN_HEAD HEAD_SIZE 12: want Malformed, got %v (%+v)", res.Status, res)
	}
}

func TestScanArchive_RAR4_BlockSizeTooSmall(t *testing.T) {
	// A non-file, non-end block declaring HEAD_SIZE < 7 is malformed.
	data := bytes.Join([][]byte{
		rar4Magic,
		le16(0x8AC1), // MAIN_HEAD CRC (unchecked by the scanner)
		{rar4TypeMain}, le16(0), le16(13),
		le16(0), le32(0), // RESERVED1, RESERVED2
		le16(0), // block HEAD_CRC
		{0x75},  // HEAD_TYPE: comment sub-block, not ENDARC/file
		le16(0), // HEAD_FLAGS
		le16(3), // HEAD_SIZE = 3 < 7 minimum
		le16(0), // padding so the block start is reachable
	}, nil)
	res := ScanArchive(data, DefaultArchiveBudget())
	if res.Status != ArchiveStatusMalformed {
		t.Errorf("block HEAD_SIZE 3: want Malformed, got %v (%+v)", res.Status, res)
	}
}

func TestScanArchive_RAR4_FileEntryBudgetExhaustion(t *testing.T) {
	files := make([]zipMember, 3)
	for i := range files {
		files[i] = zipMember{name: "f", data: []byte("x")}
	}
	data := buildRAR4(0, files)
	res := ScanArchive(data, ArchiveBudget{MaxDepth: 8, MaxEntries: 2, MaxUncompressedBytes: 1 << 30})
	if res.Status != ArchiveStatusBudgetExceeded {
		t.Errorf("3 file blocks vs MaxEntries 2: want BudgetExceeded, got %v (%+v)", res.Status, res)
	}
}

func TestScanArchive_RAR4_LongBlockTruncated(t *testing.T) {
	// LONG_BLOCK adds ADD_SIZE to the advance, read at cur+7..cur+11; a
	// block that ends inside those bytes is truncated, not skippable.
	data := bytes.Join([][]byte{
		rar4Magic,
		le16(0), // MAIN_HEAD CRC
		{rar4TypeMain}, le16(0), le16(13),
		le16(0), le32(0), // RESERVED1, RESERVED2
		le16(0),                 // block HEAD_CRC
		{0x75},                  // HEAD_TYPE: neither ENDARC nor FILE
		le16(rar4FlagLongBlock), // HEAD_FLAGS: ADD_SIZE follows
		le16(7),                 // HEAD_SIZE
		{0xAA},                  // truncates before the full ADD_SIZE
	}, nil)
	res := ScanArchive(data, DefaultArchiveBudget())
	if res.Status != ArchiveStatusMalformed {
		t.Errorf("truncated LONG_BLOCK ADD_SIZE: want Malformed, got %v (%+v)", res.Status, res)
	}
}

func TestScanArchive_RAR5_HeaderBodyMissingTypeOrFlags(t *testing.T) {
	// Header body holding only the type vint: flags vint cannot be read.
	data := buildRAR5([][]byte{rar5Vint(rar5HeaderTypeFile)})
	res := ScanArchive(data, DefaultArchiveBudget())
	if res.Status != ArchiveStatusMalformed {
		t.Errorf("RAR5 body without flags vint: want Malformed, got %v (%+v)", res.Status, res)
	}
}

func TestScanArchive_RAR5_DataSizeVintTruncated(t *testing.T) {
	// File header declaring extra+data areas whose data-size vint is cut off.
	body := bytes.Join([][]byte{
		rar5Vint(rar5HeaderTypeFile),
		rar5Vint(rar5FlagExtraArea | rar5FlagDataArea),
		rar5Vint(1), // extra area size
		// data-size vint would follow here — truncated
	}, nil)
	data := buildRAR5([][]byte{rar5MainHeader(), body})
	res := ScanArchive(data, DefaultArchiveBudget())
	if res.Status != ArchiveStatusMalformed {
		t.Errorf("RAR5 truncated data-size vint: want Malformed, got %v (%+v)", res.Status, res)
	}
}

func TestScanArchive_RAR5_FileEntryBudgetExhaustion(t *testing.T) {
	fileBody := rar5FileBody("f", 0, false, 0)
	bodies := [][]byte{rar5MainHeader()}
	for i := 0; i < 3; i++ {
		bodies = append(bodies, fileBody) // buildRAR5 wraps each raw body
	}
	res := ScanArchive(buildRAR5(bodies), ArchiveBudget{MaxDepth: 8, MaxEntries: 2, MaxUncompressedBytes: 1 << 30})
	if res.Status != ArchiveStatusBudgetExceeded {
		t.Errorf("3 file headers vs MaxEntries 2: want BudgetExceeded, got %v (%+v)", res.Status, res)
	}
}

func TestScanArchive_RAR5_FileHeaderMissingFileFields(t *testing.T) {
	// File header body ends after type+flags: FileFlags cannot be read.
	body := bytes.Join([][]byte{
		rar5Vint(rar5HeaderTypeFile),
		rar5Vint(0),
	}, nil)
	data := buildRAR5([][]byte{rar5MainHeader(), body})
	res := ScanArchive(data, DefaultArchiveBudget())
	if res.Status != ArchiveStatusMalformed {
		t.Errorf("RAR5 file header without FileFlags: want Malformed, got %v (%+v)", res.Status, res)
	}
}

func TestScanArchive_RAR5_UnpackedSizeBudgetExhaustion(t *testing.T) {
	body := rar5FileBody("bomb", 1<<20, false, 0)
	data := buildRAR5([][]byte{rar5MainHeader(), body})
	res := ScanArchive(data, ArchiveBudget{MaxDepth: 8, MaxEntries: 100, MaxUncompressedBytes: 1 << 10})
	if res.Status != ArchiveStatusBudgetExceeded {
		t.Errorf("RAR5 declared 1 MiB vs 1 KiB budget: want BudgetExceeded, got %v (%+v)", res.Status, res)
	}
}

func TestScanArchive_RAR5_ExtraAreaRecordSizeVintTruncated(t *testing.T) {
	// Extra area whose first record's Size vint is truncated.
	body := bytes.Join([][]byte{
		rar5Vint(rar5HeaderTypeFile),
		rar5Vint(rar5FlagExtraArea),
		rar5Vint(1), // extra area size = 1
		rar5Vint(0), // file flags
		rar5Vint(0), // unpacked size
		rar5Vint(0), // attributes
		rar5Vint(0), // compression information
		rar5Vint(1), // host OS
		rar5Vint(1), // name length
		[]byte("a"),
		{0x80}, // extra area: continuation byte with no tail
	}, nil)
	data := buildRAR5([][]byte{rar5MainHeader(), body})
	res := ScanArchive(data, DefaultArchiveBudget())
	if res.Status != ArchiveStatusMalformed {
		t.Errorf("extra-area Size vint truncated: want Malformed, got %v (%+v)", res.Status, res)
	}
}

func TestScanArchive_RAR5_ExtraAreaRecordTypeVintTruncated(t *testing.T) {
	// Extra area whose record declares a Size but the Type vint is missing.
	body := bytes.Join([][]byte{
		rar5Vint(rar5HeaderTypeFile),
		rar5Vint(rar5FlagExtraArea),
		rar5Vint(1), // extra area size = 1
		rar5Vint(0), // file flags
		rar5Vint(0), // unpacked size
		rar5Vint(0), // attributes
		rar5Vint(0), // compression information
		rar5Vint(1), // host OS
		rar5Vint(1), // name length
		[]byte("a"),
		{0x01}, // extra area: Size vint = 1, no Type follows
	}, nil)
	data := buildRAR5([][]byte{rar5MainHeader(), body})
	res := ScanArchive(data, DefaultArchiveBudget())
	if res.Status != ArchiveStatusMalformed {
		t.Errorf("extra-area Type vint missing: want Malformed, got %v (%+v)", res.Status, res)
	}
}

func TestReadNum7z_TruncationReturnsZero(t *testing.T) {
	// Empty input at pos: nothing to read.
	if v, n := readNum7z(nil, 0); v != 0 || n != 0 {
		t.Errorf("readNum7z(nil, 0) = %d, %d; want 0, 0", v, n)
	}
	// High continuation bit with no following byte: truncated.
	if v, n := readNum7z([]byte{0x80}, 0); v != 0 || n != 0 {
		t.Errorf("readNum7z([0x80], 0) = %d, %d; want 0, 0", v, n)
	}
}

// --- 7z next-header malformed arms ---

func TestScanArchive_7z_NextHeaderExplicitEnd_NoContent(t *testing.T) {
	// kHeader followed immediately by kEnd: a well-formed empty archive.
	res := ScanArchive(build7z([]byte{sevenzPropHeader, sevenzPropEnd}), DefaultArchiveBudget())
	if res.Status != ArchiveStatusOK {
		t.Errorf("empty 7z with explicit kEnd: want OK, got %v (%+v)", res.Status, res)
	}
}

func TestScanArchive_7z_StreamsInfoImmediateEnd_Incomplete(t *testing.T) {
	// kStreamsInfo whose block terminates instantly: content is declared
	// but no members are inspectable.
	nh := []byte{sevenzPropHeader, sevenzPropStreamsInfo, sevenzPropEnd}
	res := ScanArchive(build7z(nh), DefaultArchiveBudget())
	if res.Status != ArchiveStatusIncomplete {
		t.Errorf("streams info kEnd: want Incomplete, got %v (%+v)", res.Status, res)
	}
}

func TestScanArchive_7z_SubStreamsWithoutFolders_Incomplete(t *testing.T) {
	// kSubStreams without a preceding kUnpackInfo: no coders to inspect.
	nh := []byte{sevenzPropHeader, sevenzPropStreamsInfo, sevenzPropSubStreams}
	res := ScanArchive(build7z(nh), DefaultArchiveBudget())
	if res.Status != ArchiveStatusIncomplete {
		t.Errorf("substreams without folders: want Incomplete, got %v (%+v)", res.Status, res)
	}
}

func TestScanArchive_7z_PackInfoTruncatedArms(t *testing.T) {
	cases := []struct {
		name string
		nh   []byte
	}{
		{"pack pos vint truncated", []byte{sevenzPropHeader, sevenzPropStreamsInfo, sevenzPropPackInfo, 0x80}},
		{"num streams vint truncated", []byte{sevenzPropHeader, sevenzPropStreamsInfo, sevenzPropPackInfo, 0x00, 0x80}},
		{"kSize value truncated", []byte{sevenzPropHeader, sevenzPropStreamsInfo, sevenzPropPackInfo, 0x00, 0x01, sevenzPropSize, 0x80}},
		{"kCRC at block end", []byte{sevenzPropHeader, sevenzPropStreamsInfo, sevenzPropPackInfo, 0x00, 0x01, sevenzPropCRC}},
		{"kCRC defined-count truncated", []byte{sevenzPropHeader, sevenzPropStreamsInfo, sevenzPropPackInfo, 0x00, 0x01, sevenzPropCRC, 0x00, 0x80}},
		{"no kEnd after sections", []byte{sevenzPropHeader, sevenzPropStreamsInfo, sevenzPropPackInfo, 0x00, 0x00}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := ScanArchive(build7z(tc.nh), DefaultArchiveBudget())
			if res.Status != ArchiveStatusMalformed {
				t.Errorf("want Malformed, got %v (%+v)", res.Status, res)
			}
		})
	}
}

func TestScanArchive_7z_PackInfoCRCAllDefined_BoundedSkip(t *testing.T) {
	// kCRC with the all-defined byte set: each CRC is 4 bytes, the bounded
	// skip consumes exactly numStreams*4, and kEnd terminates cleanly.
	nh := []byte{
		sevenzPropHeader, sevenzPropStreamsInfo, sevenzPropPackInfo,
		0x00,                   // PackPos
		0x01,                   // NumPackStreams
		sevenzPropCRC,          // no kSize section: kCRC directly
		0x01,                   // all CRCs defined
		0x00, 0x00, 0x00, 0x00, // one 4-byte CRC
		sevenzPropEnd,
	}
	res := ScanArchive(build7z(nh), DefaultArchiveBudget())
	if res.Status != ArchiveStatusIncomplete {
		t.Errorf("pack info with all-defined CRC: want Incomplete (content uninspected), got %v (%+v)", res.Status, res)
	}
}

func TestScanArchive_7z_UnpackInfoTruncatedArms(t *testing.T) {
	cases := []struct {
		name string
		nh   []byte
	}{
		{"num folders truncated", []byte{sevenzPropHeader, sevenzPropStreamsInfo, sevenzPropUnpackInfo, sevenzPropFolder, 0x80}},
		{"end after num folders", []byte{sevenzPropHeader, sevenzPropStreamsInfo, sevenzPropUnpackInfo, sevenzPropFolder, 0x01}},
		{"end after num coders", []byte{sevenzPropHeader, sevenzPropStreamsInfo, sevenzPropUnpackInfo, sevenzPropFolder, 0x01, 0x00, 0x01}},
		{"coder id size zero", []byte{sevenzPropHeader, sevenzPropStreamsInfo, sevenzPropUnpackInfo, sevenzPropFolder, 0x01, 0x00, 0x01, 0x00}},
		{"complex coder streams truncated", []byte{sevenzPropHeader, sevenzPropStreamsInfo, sevenzPropUnpackInfo, sevenzPropFolder, 0x01, 0x00, 0x01, 0x11, 0x21}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := ScanArchive(build7z(tc.nh), DefaultArchiveBudget())
			if res.Status != ArchiveStatusMalformed {
				t.Errorf("want Malformed, got %v (%+v)", res.Status, res)
			}
		})
	}
}

func TestScanArchive_7z_ComplexCoderWellFormed_Incomplete(t *testing.T) {
	// A complex coder (flag 0x10) with both stream-count vints present and
	// a non-AES codec ID: parses cleanly, content stays uninspected.
	nh := []byte{
		sevenzPropHeader, sevenzPropStreamsInfo, sevenzPropUnpackInfo,
		sevenzPropFolder,
		0x01, // NumFolders
		0x00, // External = inline
		0x01, // NumCoders
		0x11, // flags: id size 1, complex
		0x21, // codec ID (LZMA2)
		0x01, // NumOutStreams
		0x01, // NumInStreams
	}
	res := ScanArchive(build7z(nh), DefaultArchiveBudget())
	if res.Status != ArchiveStatusIncomplete {
		t.Errorf("well-formed complex coder: want Incomplete, got %v (%+v)", res.Status, res)
	}
}

func TestScanArchive_RAR5_MaxVintDeclaredSize_FailsClosed(t *testing.T) {
	// Boundary: 2^56-1 is the largest size a RAR5 vint can encode (8 bytes
	// x 7 bits). It must still trip the declared-size budget — and it is
	// also why the int64 accumulator cannot wrap through the public API:
	// each entry's declared size is checked against the budget before the
	// sum can grow past it.
	maxVint := (uint64(1) << 56) - 1
	body := rar5FileBody("bomb", maxVint, false, 0)
	res := ScanArchive(buildRAR5([][]byte{rar5MainHeader(), body}), DefaultArchiveBudget())
	if res.Status != ArchiveStatusBudgetExceeded {
		t.Errorf("declared 2^56-1 vs 1 GiB budget: want BudgetExceeded, got %v (%+v)", res.Status, res)
	}
}
