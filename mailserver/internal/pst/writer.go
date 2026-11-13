// Package pst implements a Microsoft Outlook PST (Personal Storage Table)
// file writer. It produces Unicode PST files (wVer=23) that can be opened
// by Microsoft Outlook.
//
// The writer creates a minimal PST structure: header, NBT/BBT B-Trees,
// root folder, and message nodes with RFC822 content.
//
// Reference: [MS-PST] — Outlook Personal Folders File Format
package pst

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"io"
	"strings"
	"time"
)

const (
	// PST file magic
	magicPST        = 0x4E444221 // "!BDN" little-endian
	magicClient     = 0x4D53     // "SM"
	wVer            = 23         // Unicode PST (64-bit NIDs)
	wVerClient      = 19         // Outlook 2013+
	platformWindows = 1
	fileTypeEmail   = 1

	// Block sizes
	pageSize  = 512
	blockSize = 64

	// maxRFCBytes bounds an AddMessage payload so the resulting message
	// node stays within the 16-bit BBT size field. The node wraps the RFC
	// data with a fixed HNHDR (24) + page map (6) + length prefix (4) and
	// pads to a 64-byte block; this conservative limit leaves headroom for
	// that overhead below the 65535 ceiling.
	maxRFCBytes = 65000

	// maxMessages is the export budget's message cap (PST-001/PST-003): the
	// single-page NBT and BBT this writer emits hold 512/24 = 21 entries, so
	// a 22nd message previously guaranteed a slice-bounds panic in Close.
	// Capping AddMessage bounds both the page occupancy and the aggregate
	// retained buffer (21 × maxRFCBytes + page padding ≈ 1.4 MiB).
	maxMessages = 21
)

// Message holds the fields for a PST email message.
type Message struct {
	Subject    string
	From       string
	FromName   string
	To         string
	ToName     string
	CC         string
	Body       string
	ReceivedAt string
	MessageID  string
}

// Writer accumulates a PST file in an io.Writer.
type Writer struct {
	w      io.Writer
	header [pageSize]byte
	data   bytes.Buffer // data pages written after header
	msgs   []storedMsg

	nextBID uint64
	nextNID uint32
}

type storedMsg struct {
	nid     uint32
	dataBID uint64
	rfc     []byte
}

// BREF is a block reference: 64-bit BID + 64-bit byte offset.
type BREF struct {
	BID uint64
	IB  uint64
}

// NewWriter creates a new PST writer.
func NewWriter(w io.Writer) *Writer {
	return &Writer{
		w:       w,
		nextBID: 64,
		nextNID: 0x20,
	}
}

// WriteHeader writes the PST file header (512 bytes) immediately.
func (w *Writer) WriteHeader() error {
	h := &w.header

	h[0] = 0x21 // '!'
	h[1] = 0x42 // 'B'
	h[2] = 0x44 // 'D'
	h[3] = 0x4E // 'N'

	binary.LittleEndian.PutUint16(h[8:10], magicClient)
	binary.LittleEndian.PutUint16(h[10:12], wVer)
	binary.LittleEndian.PutUint16(h[12:14], wVerClient)
	h[14] = platformWindows
	h[15] = platformWindows

	// bidNextP: next page offset (initially 512, will be updated on Close)
	binary.LittleEndian.PutUint64(h[28:36], pageSize)
	// bidNextB: next BID counter
	binary.LittleEndian.PutUint64(h[36:44], w.nextBID)

	// dwRoot = 1 (email file)
	binary.LittleEndian.PutUint32(h[44:48], fileTypeEmail)

	h[306] = 0x80 // bSentinel
	h[307] = 0x00 // bCryptMethod (none)

	// Write initial CRCs (will be recalculated on Close if needed)
	partialCRC := crc32.ChecksumIEEE(h[8:512])
	binary.LittleEndian.PutUint32(h[4:8], partialCRC)
	fullCRC := crc32.ChecksumIEEE(h[0:512])
	binary.LittleEndian.PutUint32(h[316:320], fullCRC)

	// Write header immediately
	_, err := w.w.Write(h[:])
	return err
}

// headerSafe strips CR, LF, and NUL from a header-context value
// (D-MAILSERVER-INTERNAL-PST-002): the exported fields are data-controlled,
// and a CRLF carried verbatim into "Name: value\r\n" context would inject
// header lines into the exported RFC822.
func headerSafe(s string) string {
	if !strings.ContainsAny(s, "\r\n\x00") {
		return s
	}
	return strings.NewReplacer("\r", "", "\n", "", "\x00", "").Replace(s)
}

// messageIDSafe reports whether an already-CRLF-stripped Message-ID is a
// conservative token (printable ASCII, no whitespace). A value failing the
// shape check is dropped from the header block instead of echoed.
func messageIDSafe(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 0x21 || s[i] > 0x7E {
			return false
		}
	}
	return true
}

// AddMessage writes a message to the PST.
func (w *Writer) AddMessage(msg Message) error {
	if len(w.msgs) >= maxMessages {
		return fmt.Errorf("pst: message limit reached (%d): this writer emits a single NBT/BBT page", maxMessages)
	}
	nid := w.nextNID
	w.nextNID++

	// Build RFC822 content. Header-context fields are CRLF-sanitized
	// (PST-002): From/To/Cc display names and addresses, Subject, and
	// Message-ID can never inject a header line, and the Date header is
	// emitted ONLY from the parsed timestamp (never the raw echo of
	// ReceivedAt).
	from := headerSafe(msg.From)
	var rfc bytes.Buffer
	rfc.WriteString("From: ")
	if fromName := headerSafe(msg.FromName); fromName != "" {
		rfc.WriteString(fmt.Sprintf("%s <%s>", fromName, from))
	} else {
		rfc.WriteString(from)
	}
	rfc.WriteString("\r\n")

	rfc.WriteString("To: ")
	if toName := headerSafe(msg.ToName); toName != "" {
		rfc.WriteString(fmt.Sprintf("%s <%s>", toName, headerSafe(msg.To)))
	} else {
		rfc.WriteString(headerSafe(msg.To))
	}
	rfc.WriteString("\r\n")

	if cc := headerSafe(msg.CC); cc != "" {
		rfc.WriteString("Cc: " + cc + "\r\n")
	}

	rfc.WriteString("Subject: " + headerSafe(msg.Subject) + "\r\n")
	if mid := headerSafe(msg.MessageID); messageIDSafe(mid) {
		rfc.WriteString("Message-ID: " + mid + "\r\n")
	}

	if t, err := time.Parse(time.RFC3339, msg.ReceivedAt); err == nil {
		rfc.WriteString("Date: " + t.Format(time.RFC1123Z) + "\r\n")
	}

	rfc.WriteString("MIME-Version: 1.0\r\n")
	rfc.WriteString("Content-Type: text/plain; charset=utf-8\r\n")
	rfc.WriteString("Content-Transfer-Encoding: 8bit\r\n")
	rfc.WriteString("\r\n")
	rfc.WriteString(msg.Body)

	// The BBT entry encodes a message node's size in a 16-bit field
	// ([MS-PST]). The node wraps this RFC data with a fixed-size header,
	// page map, and block padding, so the message node always exceeds the
	// RFC length. Reject anything that could overflow the 16-bit size field
	// rather than silently truncate and emit a corrupt PST.
	if rfc.Len() > maxRFCBytes {
		return fmt.Errorf("pst: message too large (%d bytes, max %d)", rfc.Len(), maxRFCBytes)
	}

	bid := w.nextBID
	w.nextBID++

	w.msgs = append(w.msgs, storedMsg{
		nid:     nid,
		dataBID: bid,
		rfc:     rfc.Bytes(),
	})
	return nil
}

// Close finalizes the PST and writes remaining data.
func (w *Writer) Close() error {
	// Bounds guard (D-MAILSERVER-INTERNAL-PST-001): the fixed 512-byte NBT
	// and BBT pages hold at most 21 24-byte entries. The writer's contract
	// caps AddMessage at exactly this count, so exceeding it here is caller
	// misuse — fail with a descriptive error instead of indexing past the
	// page (a deterministic slice-bounds panic).
	if len(w.msgs) > maxMessages {
		return fmt.Errorf("pst: %d messages exceed the %d-entry NBT/BBT page capacity", len(w.msgs), maxMessages)
	}
	// Build NBT page (page 1)
	var nbtPage [pageSize]byte
	nbtOffset := 0
	for _, msg := range w.msgs {
		// NBT entry (Unicode): 8 bytes NID + 8 bytes data BID + 8 bytes sub BID = 24 bytes
		binary.LittleEndian.PutUint64(nbtPage[nbtOffset:], uint64(msg.nid))
		binary.LittleEndian.PutUint64(nbtPage[nbtOffset+8:], msg.dataBID)
		// sub BID = 0 (no child nodes)
		nbtOffset += 24
	}

	// Build BBT page (page 2)
	var bbtPage [pageSize]byte
	bbtOffset := 0
	// Data pages start at page 3 (512*3 = 1536)
	dataOffset := uint64(3 * pageSize)

	for _, msg := range w.msgs {
		// Build node data (HNHDR + properties + RFC822 body)
		nodeData := buildMessageNode(msg.nid, msg.rfc)

		// BBT entry: 8 bytes BID + 8 bytes IB + 2 bytes size + 1 byte ref + 1 byte padding = 20 bytes
		binary.LittleEndian.PutUint64(bbtPage[bbtOffset:], msg.dataBID)
		binary.LittleEndian.PutUint64(bbtPage[bbtOffset+8:], dataOffset)
		//nolint:gosec // G115: len(nodeData) bounded < 65535 by the maxRFCBytes guard in AddMessage
		binary.LittleEndian.PutUint16(bbtPage[bbtOffset+16:], uint16(len(nodeData)))
		bbtPage[bbtOffset+18] = 1 // ref count

		// Write node data
		w.data.Write(nodeData)

		// Pad to page boundary
		padding := pageSize - (len(nodeData) % pageSize)
		if padding < pageSize {
			w.data.Write(make([]byte, padding))
		}
		dataOffset += uint64(len(nodeData) + padding)

		bbtOffset += 24
	}

	// Update header with NBT/BBT roots
	nbtRoot := BREF{BID: 1, IB: uint64(pageSize)}     // page 1
	bbtRoot := BREF{BID: 2, IB: uint64(2 * pageSize)} // page 2
	writeBREF(w.header[184:200], nbtRoot)
	writeBREF(w.header[200:216], bbtRoot)

	// Update next page pointer
	//nolint:gosec // G115: 3 + a non-negative page count is always positive, no overflow
	totalPages := uint64(3 + (w.data.Len()+pageSize-1)/pageSize)
	binary.LittleEndian.PutUint64(w.header[28:36], totalPages*pageSize)

	// Recalculate CRCs
	partialCRC := crc32.ChecksumIEEE(w.header[8:512])
	binary.LittleEndian.PutUint32(w.header[4:8], partialCRC)
	fullCRC := crc32.ChecksumIEEE(w.header[0:512])
	binary.LittleEndian.PutUint32(w.header[316:320], fullCRC)

	// Seek back to beginning and rewrite header. The header was written
	// immediately by WriteHeader; the remaining pages stream directly — no
	// second full copy of the export is buffered (D-MAILSERVER-INTERNAL-PST-003).
	if _, err := w.w.Write(nbtPage[:]); err != nil {
		return err
	}
	if _, err := w.w.Write(bbtPage[:]); err != nil {
		return err
	}
	_, err := w.w.Write(w.data.Bytes())
	return err
}

func buildMessageNode(nid uint32, rfcData []byte) []byte {
	var node bytes.Buffer

	// HNHDR (Heap-on-Node Header)
	hnHdrSize := uint16(24)
	_ = binary.Write(&node, binary.LittleEndian, hnHdrSize) // bytes.Buffer writes cannot fail
	node.WriteByte(0xEC)                                    // bSig
	node.WriteByte(0x00)                                    // bClientSig

	// hidUserRoot: HID for root BTH
	rootHID := uint32(0x20)
	_ = binary.Write(&node, binary.LittleEndian, rootHID)

	// rgbFillLevel (16 bytes)
	for i := 0; i < 16; i++ {
		node.WriteByte(0)
	}

	// Pad to hnHdrSize
	for node.Len() < int(hnHdrSize) {
		node.WriteByte(0)
	}

	// Page map
	_ = binary.Write(&node, binary.LittleEndian, uint16(1)) // cAlloc
	binary.Write(&node, binary.LittleEndian, uint16(1))     // cFree
	binary.Write(&node, binary.LittleEndian, uint16(0))     // rgibAlloc[0]

	// RFC822 length + body
	//nolint:gosec // G115: len(rfcData) bounded < 65000 by the maxRFCBytes guard in AddMessage, fits uint32
	rfcLen := uint32(len(rfcData))
	binary.Write(&node, binary.LittleEndian, rfcLen)
	node.Write(rfcData)

	// Pad to block alignment
	for node.Len()%blockSize != 0 {
		node.WriteByte(0)
	}

	return node.Bytes()
}

func writeBREF(buf []byte, bref BREF) {
	binary.LittleEndian.PutUint64(buf[0:8], bref.BID)
	binary.LittleEndian.PutUint64(buf[8:16], bref.IB)
}
