package spam

import (
	"bytes"
	"encoding/binary"
	"hash/crc32"
	"log/slog"
	"regexp"
)

// This file implements spec-correct, bounded archive inspection.
//
// OWNERSHIP POLICY DECISION (surfaced to the owner, recorded in packet
// retired-docs:glm-plan-review/nightly/packets/L2-C7-spam-bounds-proposal/manifest.md
// §5 and r2-C7-3 point 2): when the attachment-bytes wiring package lands,
// non-OK archive outcomes (ArchiveStatusBudgetExceeded,
// ArchiveStatusMalformed, ArchiveStatusIncomplete) and Encrypted=true must
// be mapped at THAT call site either to delivery rejection (quarantine/
// refuse) or to static classification (score as suspicious and continue).
// RECOMMENDATION (not yet an owner decision): static-classify, matching
// the additive-scoring posture and avoiding delivery-failure false
// positives. The typed statuses below are the one-line mapping surface;
// they must never map to a benign miss. Both detectors remain UNWIRED at
// HEAD; this package changes no live verdict.

// ArchiveStatus is the typed outcome of a bounded archive scan. It is the
// fail-closed channel: only ArchiveStatusOK means the walk inspected every
// member it encountered and stayed within budget.
type ArchiveStatus uint8

const (
	// ArchiveStatusOK: the container was parsed and every member encountered
	// was inspectable without decompression; budgets were not exceeded.
	ArchiveStatusOK ArchiveStatus = iota
	// ArchiveStatusBudgetExceeded: a budget (depth, entry count, or declared
	// uncompressed size) was exceeded; the walk was abandoned.
	ArchiveStatusBudgetExceeded
	// ArchiveStatusMalformed: the container header/structure is invalid,
	// truncated, or the data is not an archive at all.
	ArchiveStatusMalformed
	// ArchiveStatusIncomplete: the scan completed within budget but
	// encountered at least one member it does not inspect (e.g. a
	// compressed or encrypted member of a ZIP, or any member of a
	// RAR/7z archive, which this package inspects at header level only).
	// Such an archive may conceal arbitrary nested content, so an
	// incomplete scan is a distinct non-OK outcome — never a clean miss.
	ArchiveStatusIncomplete
)

// String returns a stable, lowercase name for the status, for logs.
func (s ArchiveStatus) String() string {
	switch s {
	case ArchiveStatusOK:
		return "ok"
	case ArchiveStatusBudgetExceeded:
		return "budget_exceeded"
	case ArchiveStatusMalformed:
		return "malformed"
	case ArchiveStatusIncomplete:
		return "incomplete"
	default:
		return "unknown"
	}
}

// Caps for archive scanning. Named constants with rationale, owner-tunable
// at the wiring seam via ArchiveBudget, not config surfaces.
const (
	// defaultArchiveMaxDepth bounds nested-container depth reachable without
	// decompression (STORED members only). Legitimate archives rarely nest
	// more than one or two containers; 8 is generous headroom.
	defaultArchiveMaxDepth = 8
	// defaultArchiveMaxEntries bounds header-chain/central-directory entries
	// iterated (per scan, shared across nesting levels).
	defaultArchiveMaxEntries = 4096
	// defaultArchiveMaxUncompressedBytes bounds the SUM of declared
	// uncompressed member sizes — a decompression-bomb guard available
	// without decompressing anything.
	defaultArchiveMaxUncompressedBytes = 1 << 30 // 1 GiB declared
)

// ArchiveBudget bounds the work ScanArchive performs. A non-positive limit
// fails closed: everything exceeds it.
type ArchiveBudget struct {
	MaxDepth             int // maximum container nesting levels (outer = 1)
	MaxEntries           int // maximum member entries iterated
	MaxUncompressedBytes int // maximum sum of declared uncompressed member sizes
}

// DefaultArchiveBudget returns the package-default budget.
func DefaultArchiveBudget() ArchiveBudget {
	return ArchiveBudget{
		MaxDepth:             defaultArchiveMaxDepth,
		MaxEntries:           defaultArchiveMaxEntries,
		MaxUncompressedBytes: defaultArchiveMaxUncompressedBytes,
	}
}

// ArchiveScanResult is the typed result of a bounded archive scan.
//
// Inspection boundary (deliberate, explicitly narrowed per manifest
// r3-C7-3): nesting is enforced ONLY for members reachable without
// decompression — ZIP STORED members are walked into (any recognizable
// container format inside), while compressed members are NOT recursed into
// and surface ArchiveStatusIncomplete instead. Decompression-requiring
// nesting inspection (with decompression-bomb limits) is RETAINED as the
// obligation of the future attachment-bytes wiring package; the seam it
// must adopt is exactly this result type.
type ArchiveScanResult struct {
	Encrypted bool // encryption detected at header/central-directory level
	Depth     int  // deepest container level inspected (outer = 1)
	Entries   int  // member entries iterated (across all inspected levels)
	Status    ArchiveStatus
}

// Signature and record constants, per the published format specifications:
//   - ZIP: APPNOTE (PKWARE), local file header / central directory / EOCD.
//   - RAR 4.x: rarlab technote.txt (MAIN_HEAD/FILE_HEAD block tables).
//   - RAR 5.0: rarlab technote.htm (header chain, vint encoding).
//   - 7z: 7zFormat.txt (ip7z/7zip DOC) + DOC/Methods.txt for the codec ID.
const (
	zipMethodStore        = 0
	zipFlagEncrypt        = 0x0001 // general purpose bit 0: member encrypted
	zipFlagDataDescriptor = 0x0008

	rar4BlockSizeMin    = 7
	rar4TypeMain        = 0x73
	rar4TypeFile        = 0x74
	rar4TypeEnd         = 0x7B   // ENDARC_HEAD terminator (technote block table: 0x72 marker … 0x7b end)
	rar4FlagMHDPassword = 0x0080 // MAIN_HEAD HEAD_FLAGS: block headers encrypted
	rar4FlagLHDPassword = 0x0004 // FILE_HEAD HEAD_FLAGS: member encrypted
	rar4FlagLongBlock   = 0x8000 // ADD_SIZE/PACK_SIZE data follows the block

	rar5HeaderTypeMain       = 1
	rar5HeaderTypeFile       = 2
	rar5HeaderTypeService    = 3
	rar5HeaderTypeEncryption = 4 // archive encryption header: headers AND data encrypted
	rar5HeaderTypeEnd        = 5
	rar5FlagExtraArea        = 0x0001
	rar5FlagDataArea         = 0x0002
	rar5RecordFileEncryption = 0x01 // file-header extra-area record: member encrypted

	sevenzSigHeaderSize    = 32
	sevenzPropEnd          = 0x00
	sevenzPropHeader       = 0x01
	sevenzPropStreamsInfo  = 0x04
	sevenzPropPackInfo     = 0x06
	sevenzPropUnpackInfo   = 0x07
	sevenzPropSubStreams   = 0x08
	sevenzPropSize         = 0x09
	sevenzPropCRC          = 0x0A
	sevenzPropFolder       = 0x0B
	sevenzPropEncodedHdr   = 0x17
	sevenzCoderAttrsFlag   = 0x20 // coder flags byte: properties present
	sevenzCoderComplexFlag = 0x10 // coder flags byte: complex (multiple streams)
)

// sevenzAESCodecID is the 7zAES coder (AES-256 + SHA-256), DOC/Methods.txt
// method ID 06 F1 07 01. Encrypted 7z archives always carry this coder,
// either in the decoded header's folders or behind kEncodedHeader.
var sevenzAESCodecID = []byte{0x06, 0xF1, 0x07, 0x01}

var (
	zipLocalSig = []byte{'P', 'K', 0x03, 0x04}
	zipCDSig    = []byte{'P', 'K', 0x01, 0x02}
	zipEOCDSig  = []byte{'P', 'K', 0x05, 0x06}
	rar4Magic   = []byte{'R', 'a', 'r', '!', 0x1a, 0x07, 0x00}
	rar5Magic   = []byte{'R', 'a', 'r', '!', 0x1a, 0x07, 0x01, 0x00}
	sevenzMagic = []byte{0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C}
)

// ScanArchive performs a bounded, purely structural inspection of data —
// no decompression, no crypto. It detects encryption at header level,
// counts members, sums declared uncompressed sizes, and walks nested
// containers reachable through ZIP STORED members up to budget.MaxDepth.
//
// Fail-closed contract: any member the walk encounters but cannot inspect
// (compressed, encrypted, or a format whose members this package does not
// enumerate) yields ArchiveStatusIncomplete; budget exhaustion yields
// ArchiveStatusBudgetExceeded; invalid structure yields
// ArchiveStatusMalformed. Only ArchiveStatusOK certifies a fully inspected
// scan. See the ownership policy decision at the top of this file for how
// wiring must map these outcomes.
func ScanArchive(data []byte, budget ArchiveBudget) (result ArchiveScanResult) {
	// Defense-in-depth (Astra L2-C7): every walk above is bounds-checked by
	// construction, but ScanArchive takes attacker-controlled bytes on the
	// message path — if a panic ever escapes anyway, degrade to a typed
	// fail-closed outcome (Malformed, never OK) instead of crashing the
	// caller. The overflow-checked kCRC arithmetic is the actual fix; this
	// boundary is the safety net behind it. The panic is logged loudly: the
	// documented contract is log-and-fail-closed, never a silent permissive
	// verdict (D-SHARED-SPAM-004).
	defer func() {
		if r := recover(); r != nil {
			slog.Error("spam: ScanArchive panic recovered — degrading to malformed (fail-closed)",
				"panic", r)
			result = ArchiveScanResult{Status: ArchiveStatusMalformed}
		}
	}()
	s := &archiveScan{budget: budget}
	if len(data) == 0 {
		s.fail(ArchiveStatusMalformed)
		return s.result()
	}
	s.container(data, 1)
	return s.result()
}

// archiveScan accumulates one scan's findings and abort state.
type archiveScan struct {
	budget     ArchiveBudget
	encrypted  bool
	depth      int
	entries    int
	declared   int64 // sum of declared uncompressed member sizes
	status     ArchiveStatus
	incomplete bool
}

func (s *archiveScan) fail(status ArchiveStatus) {
	// BudgetExceeded and Malformed are terminal; the first one wins.
	if s.status == ArchiveStatusOK {
		s.status = status
	}
}

func (s *archiveScan) failed() bool {
	return s.status != ArchiveStatusOK
}

func (s *archiveScan) markIncomplete() {
	s.incomplete = true
}

func (s *archiveScan) addEntry() bool {
	s.entries++
	if s.entries > s.budget.MaxEntries {
		s.fail(ArchiveStatusBudgetExceeded)
		return false
	}
	return true
}

func (s *archiveScan) addDeclared(size uint64) bool {
	s.declared += int64(size)
	if s.declared > int64(s.budget.MaxUncompressedBytes) {
		s.fail(ArchiveStatusBudgetExceeded)
		return false
	}
	return true
}

func (s *archiveScan) result() ArchiveScanResult {
	status := s.status
	if status == ArchiveStatusOK && s.incomplete {
		status = ArchiveStatusIncomplete
	}
	return ArchiveScanResult{
		Encrypted: s.encrypted,
		Depth:     s.depth,
		Entries:   s.entries,
		Status:    status,
	}
}

// container scans one container level. depth 1 is the outermost container;
// levels beyond budget.MaxDepth fail closed.
func (s *archiveScan) container(data []byte, depth int) {
	if s.failed() {
		return
	}
	if depth > s.budget.MaxDepth {
		s.fail(ArchiveStatusBudgetExceeded)
		return
	}
	if depth > s.depth {
		s.depth = depth
	}
	switch {
	case bytes.HasPrefix(data, rar4Magic):
		s.scanRAR4(data)
	case bytes.HasPrefix(data, rar5Magic):
		s.scanRAR5(data)
	case bytes.HasPrefix(data, sevenzMagic):
		s.scan7z(data)
	case len(data) >= 4 && (bytes.HasPrefix(data, zipLocalSig) ||
		bytes.HasPrefix(data, zipCDSig) || bytes.HasPrefix(data, zipEOCDSig)):
		s.scanZip(data, depth)
	default:
		s.fail(ArchiveStatusMalformed) // not an archive
	}
}

// isContainerMagic reports whether b starts with a known archive signature.
func isContainerMagic(b []byte) bool {
	return bytes.HasPrefix(b, rar4Magic) || bytes.HasPrefix(b, rar5Magic) ||
		bytes.HasPrefix(b, sevenzMagic) ||
		(len(b) >= 4 && (bytes.HasPrefix(b, zipLocalSig) ||
			bytes.HasPrefix(b, zipCDSig) || bytes.HasPrefix(b, zipEOCDSig)))
}

// ---------------------------------------------------------------------------
// ZIP
// ---------------------------------------------------------------------------

// findEOCD locates the end-of-central-directory record: scan the trailing
// ≤64 KiB+22 window for the signature whose comment length exactly reaches
// the end of input (comment-length validated).
func findEOCD(data []byte) int {
	lo := 0
	if len(data) > 0xFFFF+22 {
		lo = len(data) - (0xFFFF + 22)
	}
	for i := len(data) - 22; i >= lo; i-- {
		if !bytes.Equal(data[i:i+4], zipEOCDSig) {
			continue
		}
		commentLen := int(binary.LittleEndian.Uint16(data[i+20 : i+22]))
		if i+22+commentLen == len(data) {
			return i
		}
	}
	return -1
}

// scanZip walks the central directory (authoritative member metadata),
// checking the general-purpose encryption bit of EVERY entry — the
// first-local-header-only read this replaces missed archives whose first
// entry is plain. STORED members are inspected for nested containers.
// Without an EOCD the input is truncated/streaming: fall back to a bounded
// local-header walk for encryption detection, but the scan stays Malformed.
func (s *archiveScan) scanZip(data []byte, depth int) {
	eocd := findEOCD(data)
	if eocd < 0 {
		s.scanZipLocalFallback(data)
		return
	}

	diskNum := binary.LittleEndian.Uint16(data[eocd+4 : eocd+6])
	diskCD := binary.LittleEndian.Uint16(data[eocd+6 : eocd+8])
	entriesDisk := binary.LittleEndian.Uint16(data[eocd+8 : eocd+10])
	totalEntries := binary.LittleEndian.Uint16(data[eocd+10 : eocd+12])
	cdSize := binary.LittleEndian.Uint32(data[eocd+12 : eocd+16])
	cdOffset := binary.LittleEndian.Uint32(data[eocd+16 : eocd+20])

	if cdOffset == 0xFFFFFFFF || cdSize == 0xFFFFFFFF || totalEntries == 0xFFFF {
		// ZIP64: central directory location needs EOCD64 parsing — deferred
		// to the attachment-bytes wiring package. Members uninspectable.
		s.markIncomplete()
		return
	}
	if diskNum != diskCD || entriesDisk != totalEntries {
		// Multi-disk archive: members on other disks are uninspectable here.
		s.markIncomplete()
	}
	if int64(cdOffset)+int64(cdSize) > int64(len(data)) {
		s.fail(ArchiveStatusMalformed)
		return
	}

	cur := int64(cdOffset)
	for i := 0; i < int(totalEntries); i++ {
		if cur+46 > int64(len(data)) || !bytes.Equal(data[cur:cur+4], zipCDSig) {
			s.fail(ArchiveStatusMalformed)
			return
		}
		if !s.addEntry() {
			return
		}
		gpFlags := binary.LittleEndian.Uint16(data[cur+8 : cur+10])
		method := binary.LittleEndian.Uint16(data[cur+10 : cur+12])
		compSize := binary.LittleEndian.Uint32(data[cur+20 : cur+24])
		uncompSize := binary.LittleEndian.Uint32(data[cur+24 : cur+28])
		nameLen := int(binary.LittleEndian.Uint16(data[cur+28 : cur+30]))
		extraLen := int(binary.LittleEndian.Uint16(data[cur+30 : cur+32]))
		commentLen := int(binary.LittleEndian.Uint16(data[cur+32 : cur+34]))
		localOff := binary.LittleEndian.Uint32(data[cur+42 : cur+46])

		if gpFlags&zipFlagEncrypt != 0 {
			s.encrypted = true
		}
		if !s.addDeclared(uint64(uncompSize)) {
			return
		}

		switch {
		case gpFlags&zipFlagEncrypt != 0, method != zipMethodStore,
			compSize != uncompSize, compSize == 0xFFFFFFFF, localOff == 0xFFFFFFFF:
			// Compressed, encrypted, or ZIP64-sized member: not inspectable
			// without decompression — the r3 incomplete-scan boundary.
			s.markIncomplete()
		default:
			s.inspectStoredZipMember(data, int64(localOff), int64(compSize), depth)
			if s.failed() {
				return
			}
		}

		cur += int64(46 + nameLen + extraLen + commentLen)
	}
}

// inspectStoredZipMember looks at a STORED (method 0, unencrypted) member's
// verbatim bytes; if they carry a container signature, recurse at depth+1.
func (s *archiveScan) inspectStoredZipMember(data []byte, localOff, compSize int64, depth int) {
	if localOff < 0 || localOff+30 > int64(len(data)) || !bytes.Equal(data[localOff:localOff+4], zipLocalSig) {
		s.fail(ArchiveStatusMalformed)
		return
	}
	nameLen := int64(binary.LittleEndian.Uint16(data[localOff+26 : localOff+28]))
	extraLen := int64(binary.LittleEndian.Uint16(data[localOff+28 : localOff+30]))
	start := localOff + 30 + nameLen + extraLen
	if start+compSize > int64(len(data)) {
		s.fail(ArchiveStatusMalformed)
		return
	}
	member := data[start : start+compSize]
	if isContainerMagic(member) {
		s.container(member, depth+1)
	}
	// Stored non-container member: verbatim bytes, fully inspected.
}

// scanZipLocalFallback handles truncated/streaming ZIPs with no EOCD: walk
// local file headers while they parse, recording encryption, but keep the
// scan Malformed (a ZIP without an EOCD is incomplete by definition).
func (s *archiveScan) scanZipLocalFallback(data []byte) {
	cur := int64(0)
	for {
		if cur+8 > int64(len(data)) || !bytes.Equal(data[cur:cur+4], zipLocalSig) {
			break
		}
		gpFlags := binary.LittleEndian.Uint16(data[cur+6 : cur+8])
		if gpFlags&zipFlagEncrypt != 0 {
			s.encrypted = true
		}
		if !s.addEntry() {
			return
		}
		if cur+30 > int64(len(data)) {
			break // truncated header: encryption bit already recorded
		}
		if gpFlags&zipFlagDataDescriptor != 0 {
			// Streaming entry: sizes live in a trailing descriptor we cannot
			// locate without parsing compressed data — stop walking.
			s.markIncomplete()
			break
		}
		compSize := int64(binary.LittleEndian.Uint32(data[cur+18 : cur+22]))
		nameLen := int64(binary.LittleEndian.Uint16(data[cur+26 : cur+28]))
		extraLen := int64(binary.LittleEndian.Uint16(data[cur+28 : cur+30]))
		next := cur + 30 + nameLen + extraLen + compSize
		if next > int64(len(data)) {
			s.fail(ArchiveStatusMalformed)
			return
		}
		cur = next
	}
	s.fail(ArchiveStatusMalformed)
}

// ---------------------------------------------------------------------------
// RAR 4.x
// ---------------------------------------------------------------------------

// scanRAR4 parses the MAIN_HEAD and the following block chain per the RAR
// 4.x technote: after the 7-byte marker, MAIN_HEAD is HEAD_CRC(2),
// HEAD_TYPE(1), HEAD_FLAGS(2), HEAD_SIZE(2), RESERVED(6) — so HEAD_FLAGS
// sits at absolute bytes 10-11 (this replaces the old byte-7 read, which
// consumed HEAD_CRC checksum data). MHD_PASSWORD (0x0080) means all block
// headers are encrypted; LHD_PASSWORD (0x0004) in a file head means that
// member's data is encrypted. (The old code's 0x0004-at-byte-7 reading
// conflated the lock bit with the password bit at a checksum offset.)
func (s *archiveScan) scanRAR4(data []byte) {
	if len(data) < 7+13 { // marker + minimum MAIN_HEAD
		s.fail(ArchiveStatusMalformed)
		return
	}
	main := data[7:]
	if main[2] != rar4TypeMain {
		s.fail(ArchiveStatusMalformed)
		return
	}
	mainFlags := binary.LittleEndian.Uint16(main[3:5])
	headSize := int(binary.LittleEndian.Uint16(main[5:7]))
	if headSize < 13 {
		s.fail(ArchiveStatusMalformed)
		return
	}
	if mainFlags&rar4FlagMHDPassword != 0 {
		// Whole-archive password: every header is encrypted, so no member
		// can be inspected at all.
		s.encrypted = true
		s.markIncomplete()
		return
	}

	cur := int64(7 + headSize)
	for cur+rar4BlockSizeMin <= int64(len(data)) {
		blockType := data[cur+2]
		if blockType == rar4TypeEnd {
			return
		}
		blockFlags := binary.LittleEndian.Uint16(data[cur+3 : cur+5])
		blockSize := int(binary.LittleEndian.Uint16(data[cur+5 : cur+7]))
		if blockSize < rar4BlockSizeMin {
			s.fail(ArchiveStatusMalformed)
			return
		}
		if blockType == rar4TypeFile {
			if !s.addEntry() {
				return
			}
			if cur+15 > int64(len(data)) {
				s.fail(ArchiveStatusMalformed)
				return
			}
			if blockFlags&rar4FlagLHDPassword != 0 {
				s.encrypted = true
			}
			// FILE_HEAD: PACK_SIZE(4) at +7, UNP_SIZE(4) at +11.
			if !s.addDeclared(uint64(binary.LittleEndian.Uint32(data[cur+11 : cur+15]))) {
				return
			}
			// RAR members are enumerated but not content-inspected in this
			// package (no stored-member walk for RAR): incomplete scan.
			s.markIncomplete()
		}
		advance := int64(blockSize)
		if blockFlags&rar4FlagLongBlock != 0 {
			if cur+11 > int64(len(data)) {
				s.fail(ArchiveStatusMalformed)
				return
			}
			advance += int64(binary.LittleEndian.Uint32(data[cur+7 : cur+11]))
		}
		cur += advance
	}
	// Ran off the end without ENDARC: truncated, but everything read so far
	// stands (encryption flags already recorded).
	s.fail(ArchiveStatusMalformed)
}

// ---------------------------------------------------------------------------
// RAR 5.0
// ---------------------------------------------------------------------------

// readVintRAR5 decodes a RAR 5.0 vint (7 bits per byte, little-endian,
// high bit = continuation). Returns n == 0 on truncation/overflow.
func readVintRAR5(b []byte, pos int) (uint64, int) {
	var value uint64
	for i := 0; i < 8; i++ {
		if pos+i >= len(b) {
			return 0, 0
		}
		c := b[pos+i]
		value |= uint64(c&0x7F) << (7 * i)
		if c&0x80 == 0 {
			return value, i + 1
		}
	}
	return 0, 0 // more than 8 bytes: not a valid RAR5 vint here
}

// scanRAR5 walks the RAR 5.0 header chain: each header is CRC32(4) +
// HeaderSize(vint) + body{HeaderType, HeaderFlags[, ExtraAreaSize]
// [, DataSize], type-specific fields...}, followed by DataSize bytes of
// data area. Detection reads header types and extra-area encryption
// records — never a byte-offset guess at the signature terminator.
func (s *archiveScan) scanRAR5(data []byte) {
	if len(data) < len(rar5Magic)+4 {
		// A real RAR5 archive carries at least a main header; a bare (or
		// nearly bare) signature is truncated, not a clean empty archive.
		s.fail(ArchiveStatusMalformed)
		return
	}
	cur := int64(len(rar5Magic))
	for cur+4 <= int64(len(data)) {
		cur += 4 // Header CRC32: not load-bearing for detection
		headerSize, n := readVintRAR5(data, int(cur))
		if n == 0 {
			s.fail(ArchiveStatusMalformed)
			return
		}
		cur += int64(n)
		bodyEnd := cur + int64(headerSize)
		if headerSize == 0 || bodyEnd > int64(len(data)) {
			s.fail(ArchiveStatusMalformed)
			return
		}
		body := data[cur:bodyEnd]

		headerType, n1 := readVintRAR5(body, 0)
		headerFlags, n2 := readVintRAR5(body, n1)
		pos := n1 + n2
		if n1 == 0 || n2 == 0 || pos > len(body) {
			s.fail(ArchiveStatusMalformed)
			return
		}
		extraSize := 0
		dataSize := 0
		if headerFlags&rar5FlagExtraArea != 0 {
			v, n3 := readVintRAR5(body, pos)
			if n3 == 0 {
				s.fail(ArchiveStatusMalformed)
				return
			}
			extraSize = int(v)
			pos += n3
		}
		if headerFlags&rar5FlagDataArea != 0 {
			v, n4 := readVintRAR5(body, pos)
			if n4 == 0 {
				s.fail(ArchiveStatusMalformed)
				return
			}
			dataSize = int(v)
			pos += n4
		}

		switch headerType {
		case rar5HeaderTypeEncryption:
			// Archive encryption header: headers AND data are encrypted.
			s.encrypted = true
			s.markIncomplete()
			return
		case rar5HeaderTypeFile, rar5HeaderTypeService:
			if !s.addEntry() {
				return
			}
			// File/service header: FileFlags(vint), UnpackedSize(vint),
			// Attributes(vint) are unconditional (rarlab technote).
			_, nA := readVintRAR5(body, pos)
			unpacked, nB := readVintRAR5(body, pos+nA)
			if nA == 0 || nB == 0 {
				s.fail(ArchiveStatusMalformed)
				return
			}
			if !s.addDeclared(unpacked) {
				return
			}
			if extraSize > 0 {
				if extraSize > len(body) {
					s.fail(ArchiveStatusMalformed)
					return
				}
				s.rar5ExtraArea(body[len(body)-extraSize:])
				if s.failed() {
					return
				}
			}
			// RAR members are enumerated but not content-inspected in this
			// package: incomplete scan.
			s.markIncomplete()
		case rar5HeaderTypeEnd:
			return
		default:
			// Main header (type 1) and unknown types: skip.
		}
		cur = bodyEnd + int64(dataSize)
	}
}

// rar5ExtraArea scans a file/service header's extra area (the last
// extraSize bytes of the header body). Per the rarlab RAR 5.0 technote
// ("Extra area record format") each record is Size(vint) + Type(vint) +
// data — Size FIRST, counting "record data starting from Type": the Type
// field and the data, but not the Size field itself. (The previous parser
// read Type before Size, so real encrypted-file records — type 0x01 —
// could be missed.) Unknown record types are skipped by their declared
// size per the technote's forward-compatibility rule.
func (s *archiveScan) rar5ExtraArea(area []byte) {
	pos := 0
	for pos < len(area) {
		recordSize, n1 := readVintRAR5(area, pos)
		if n1 == 0 {
			s.fail(ArchiveStatusMalformed)
			return
		}
		recordType, n2 := readVintRAR5(area, pos+n1)
		if n2 == 0 {
			s.fail(ArchiveStatusMalformed)
			return
		}
		// Size must at least cover the Type field and must fit the
		// remaining area — validated before any skip.
		if recordSize < uint64(n2) || recordSize > uint64(len(area)-pos-n1) {
			s.fail(ArchiveStatusMalformed)
			return
		}
		if recordType == rar5RecordFileEncryption {
			s.encrypted = true
			s.markIncomplete()
			return
		}
		pos += n1 + int(recordSize)
	}
}

// ---------------------------------------------------------------------------
// 7z
// ---------------------------------------------------------------------------

// readNum7z decodes a 7z variable-length number (7zFormat.txt ReadNumber):
// the first byte's high bits flag continuation; following bytes are
// little-endian low parts. Returns n == 0 on truncation.
func readNum7z(b []byte, pos int) (uint64, int) {
	if pos >= len(b) {
		return 0, 0
	}
	first := b[pos]
	mask := byte(0x80)
	var value uint64
	for i := 0; i < 8; i++ {
		if first&mask == 0 {
			value += uint64(first&(mask-1)) << (8 * i)
			return value, i + 1
		}
		if pos+1+i >= len(b) {
			return 0, 0
		}
		value |= uint64(b[pos+1+i]) << (8 * i)
		mask >>= 1
	}
	return value, 9
}

// scan7z inspects the signature header (StartHeaderCRC-verified) and the
// next-header structure. The old byte-12 "encrypted" bit read the low byte
// of the 64-bit NextHeaderOffset — meaningless. Real 7z encryption is
// detected by locating the 7zAES coder ID (06 F1 07 01) among header
// coders: content encryption in kHeader StreamsInfo folders, header
// encryption behind kEncodedHeader. Member content is never inspected.
func (s *archiveScan) scan7z(data []byte) {
	if len(data) < sevenzSigHeaderSize {
		s.fail(ArchiveStatusMalformed)
		return
	}
	// StartHeader (offsets 12-31) is CRC32-protected by bytes 8-11; require
	// the checksum to match — real 7z files always satisfy this, fake
	// hand-built bytes do not.
	startCRC := binary.LittleEndian.Uint32(data[8:12])
	if crc32.ChecksumIEEE(data[12:32]) != startCRC {
		s.fail(ArchiveStatusMalformed)
		return
	}
	nextOffset := binary.LittleEndian.Uint64(data[12:20])
	nextSize := binary.LittleEndian.Uint64(data[20:28])
	if nextSize == 0 {
		// Empty archive: no members, nothing uninspectable.
		return
	}
	nhStart := 32 + int64(nextOffset)
	if nextOffset > uint64(len(data)) || nextSize > uint64(len(data)) ||
		nhStart < 32 || nhStart+int64(nextSize) > int64(len(data)) {
		s.fail(ArchiveStatusMalformed)
		return
	}
	nh := data[nhStart : nhStart+int64(nextSize)]

	hasContent := false
	switch {
	case nh[0] == sevenzPropEncodedHdr:
		// Encoded header: the archive's real header is stored as a packed
		// stream (always the case for header-encrypted archives).
		hasContent = true
		s.sevenzStreamsInfo(nh[1:])
	case nh[0] == sevenzPropHeader:
		for pos := 1; pos < len(nh); {
			switch nh[pos] {
			case sevenzPropStreamsInfo:
				hasContent = true
				s.sevenzStreamsInfo(nh[pos+1:])
				pos = len(nh)
			case sevenzPropEnd:
				pos = len(nh)
			default:
				// Properties blocks (names, times, ...) — not scanned.
				pos = len(nh)
			}
		}
	default:
		s.fail(ArchiveStatusMalformed)
		return
	}
	if s.failed() {
		return
	}
	if hasContent {
		// Content members exist but are not inspected in this package.
		s.markIncomplete()
	}
}

// sevenzStreamsInfo parses a StreamsInfo block far enough to see folder
// coder IDs (PackInfo is skipped structurally; UnpackInfo folders are
// parsed; everything after the folders is not needed for coder detection).
func (s *archiveScan) sevenzStreamsInfo(b []byte) {
	pos := 0
	for pos < len(b) {
		switch b[pos] {
		case sevenzPropEnd:
			return
		case sevenzPropPackInfo:
			var ok bool
			pos, ok = sevenzSkipPackInfo(b, pos+1)
			if !ok {
				s.fail(ArchiveStatusMalformed)
				return
			}
		case sevenzPropUnpackInfo:
			s.sevenzUnpackInfo(b, pos+1)
			return // coder IDs seen; the rest of the block is irrelevant here
		case sevenzPropSubStreams:
			return // only reachable when UnpackInfo was absent: no coders
		default:
			s.fail(ArchiveStatusMalformed)
			return
		}
	}
}

// sevenzSkipPackInfo steps over PackInfo: PackPos(vint) NumPackStreams(vint)
// then optional kSize and kCRC sections, terminated by kEnd.
func sevenzSkipPackInfo(b []byte, pos int) (int, bool) {
	_, n := readNum7z(b, pos) // PackPos
	if n == 0 {
		return 0, false
	}
	pos += n
	numStreams, n := readNum7z(b, pos)
	if n == 0 || numStreams > 1<<32 {
		return 0, false
	}
	pos += n
	for pos < len(b) {
		switch b[pos] {
		case sevenzPropEnd:
			return pos + 1, true
		case sevenzPropSize:
			pos++
			for i := uint64(0); i < numStreams; i++ {
				_, n := readNum7z(b, pos)
				if n == 0 {
					return 0, false
				}
				pos += n
			}
		case sevenzPropCRC:
			pos++
			if pos >= len(b) {
				return 0, false
			}
			defined := numStreams
			if b[pos] == 0 { // not all defined: count follows
				cnt, n := readNum7z(b, pos+1)
				if n == 0 {
					return 0, false
				}
				defined = cnt
				pos += 1 + n
			} else {
				pos++
			}
			// Astra L2-C7: `defined` is attacker-controlled. The unchecked
			// int(defined) * 4 wrapped negative for counts ≥ 2^61, drove
			// `pos` negative, and the next b[pos] panicked. Each defined CRC
			// is 4 bytes, so the count can never legitimately exceed
			// numStreams or a quarter of the remaining input; bound it in
			// uint64 BEFORE any int conversion (also bounds the skip).
			if defined > numStreams || defined > uint64(len(b)-pos)/4 {
				return 0, false
			}
			pos += int(defined) * 4 // ≤ len(b)-pos: bounded, no overflow
		default:
			return 0, false
		}
	}
	return 0, false
}

// sevenzUnpackInfo parses UnpackInfo folders to inspect coder IDs:
// kFolder(0x0B) NumFolders(vint) External(byte) folders...
// Each folder: NumCoders(vint), then per coder a flags byte
// (low nibble = codec ID size, 0x10 complex, 0x20 attributes),
// CodecId[idSize], optional stream counts and properties.
func (s *archiveScan) sevenzUnpackInfo(b []byte, pos int) {
	if pos >= len(b) || b[pos] != sevenzPropFolder {
		s.fail(ArchiveStatusMalformed)
		return
	}
	pos++
	numFolders, n := readNum7z(b, pos)
	if n == 0 || numFolders > 1<<16 {
		s.fail(ArchiveStatusMalformed)
		return
	}
	pos += n
	if pos >= len(b) {
		s.fail(ArchiveStatusMalformed)
		return
	}
	if b[pos] != 0 { // External: folders stored in a data stream, not inline
		return
	}
	pos++
	for f := uint64(0); f < numFolders; f++ {
		numCoders, n := readNum7z(b, pos)
		if n == 0 || numCoders == 0 || numCoders > 64 {
			s.fail(ArchiveStatusMalformed)
			return
		}
		pos += n
		for c := uint64(0); c < numCoders; c++ {
			if pos >= len(b) {
				s.fail(ArchiveStatusMalformed)
				return
			}
			flags := b[pos]
			pos++
			idSize := int(flags & 0x0F)
			if idSize == 0 || pos+idSize > len(b) {
				s.fail(ArchiveStatusMalformed)
				return
			}
			if idSize == len(sevenzAESCodecID) && bytes.Equal(b[pos:pos+idSize], sevenzAESCodecID) {
				s.encrypted = true
			}
			pos += idSize
			if flags&sevenzCoderComplexFlag != 0 {
				_, n1 := readNum7z(b, pos)
				_, n2 := readNum7z(b, pos+n1)
				if n1 == 0 || n2 == 0 {
					s.fail(ArchiveStatusMalformed)
					return
				}
				pos += n1 + n2
			}
			if flags&sevenzCoderAttrsFlag != 0 {
				propsSize, n := readNum7z(b, pos)
				if n == 0 || propsSize > uint64(len(b)) || pos+n+int(propsSize) > len(b) {
					s.fail(ArchiveStatusMalformed)
					return
				}
				pos += n + int(propsSize)
			}
			if s.encrypted {
				return // AES coder found; further folders are irrelevant
			}
		}
	}
}

// ---------------------------------------------------------------------------
// Legacy compatibility wrapper
// ---------------------------------------------------------------------------

// DetectEncryptedArchive checks archive bytes for encryption at header
// level (ZIP central-directory general-purpose flags of every entry, RAR4
// MAIN_HEAD MHD_PASSWORD / FILE_HEAD LHD_PASSWORD, RAR5 archive-encryption
// header and per-file encryption records, 7z AES coder in the next-header
// structures). It is a structural scan: no decompression, no crypto.
//
// Compatibility wrapper over ScanArchive (returns only the Encrypted bit);
// mimeType is retained for call-site compatibility and is not consulted.
// Panic recovery is defense-in-depth on both layers: ScanArchive itself
// recovers into a typed Malformed outcome, and this wrapper keeps its
// recover for the bool contract. On a recovered panic the wrapper reports
// ENCRYPTED (fail-closed) and logs loudly — the ownership policy at the top
// of this file forbids mapping an unknown outcome to a benign miss, and a
// silent false would classify an unscannable archive as clean
// (D-SHARED-SPAM-004).
func DetectEncryptedArchive(data []byte, mimeType string) (result bool) {
	defer func() {
		if r := recover(); r != nil {
			slog.Error("spam: DetectEncryptedArchive panic recovered — reporting encrypted (fail-closed, never a benign miss)",
				"panic", r)
			result = true
		}
	}()
	if len(data) == 0 {
		return false
	}
	return ScanArchive(data, DefaultArchiveBudget()).Encrypted
}

// passwordInBodyRegex matches common password-sharing patterns in email bodies.
// Covers English and Chinese variants with various separators.
var passwordInBodyRegex = []*regexp.Regexp{
	regexp.MustCompile(`(?i)password\s*(?:is|:|=>|=>|=)\s*\S+`),
	regexp.MustCompile(`密码\s*(?:是|:|：|为|=)\s*\S+`),
	regexp.MustCompile(`解压密码\s*(?:是|:|：|为|=)\s*\S+`),
	regexp.MustCompile(`(?i)pw\s*:\s*\S+`),
	regexp.MustCompile(`(?i)pass\s*:\s*\S+`),
}

// DetectPasswordInBody checks message body text for password-sharing patterns.
// This is used in combination with DetectEncryptedArchive: an encrypted attachment
// accompanied by a password in the body is a strong signal of malicious intent
// (credential phishing payloads, ransomware droppers).
func DetectPasswordInBody(body string) bool {
	for _, re := range passwordInBodyRegex {
		if re.MatchString(body) {
			return true
		}
	}
	return false
}
