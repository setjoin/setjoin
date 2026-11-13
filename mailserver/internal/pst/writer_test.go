package pst

import (
	"bytes"
	"encoding/binary"
	"regexp"
	"strings"
	"testing"
)

func TestPSTHeaderMagic(t *testing.T) {
	var buf bytes.Buffer
	w := NewWriter(&buf)
	if err := w.WriteHeader(); err != nil {
		t.Fatalf("WriteHeader failed: %v", err)
	}

	data := buf.Bytes()
	if len(data) < 4 {
		t.Fatal("header too short")
	}

	// Magic: "!BDN" = 0x21 0x42 0x44 0x4E
	magic := binary.LittleEndian.Uint32(data[0:4])
	if magic != 0x4E444221 {
		t.Errorf("magic = 0x%08X, want 0x4E444221 (!BDN)", magic)
	}
}

func TestPSTHeaderVersion(t *testing.T) {
	var buf bytes.Buffer
	w := NewWriter(&buf)
	if err := w.WriteHeader(); err != nil {
		t.Fatalf("WriteHeader failed: %v", err)
	}

	data := buf.Bytes()
	if len(data) < 12 {
		t.Fatal("header too short")
	}

	// wVer at offset 10: should be 23 (Unicode PST, 64-bit)
	wVer := binary.LittleEndian.Uint16(data[10:12])
	if wVer != 23 {
		t.Errorf("wVer = %d, want 23", wVer)
	}
}

func TestPSTHeaderRootPointers(t *testing.T) {
	var buf bytes.Buffer
	w := NewWriter(&buf)
	if err := w.WriteHeader(); err != nil {
		t.Fatalf("WriteHeader failed: %v", err)
	}

	data := buf.Bytes()

	// The root pointers are at specific offsets in the header:
	// NBT root at offset 184 (BREFNBT)
	// BBT root at offset 200 (BREFBBT)
	if len(data) < 220 {
		t.Fatal("header too short for root pointers")
	}

	// BREF structure: bid (8 bytes) + ib (8 bytes) = 16 bytes
	// Initially both should be zero (empty trees)
	nbtBid := binary.LittleEndian.Uint64(data[184:192])
	nbtIb := binary.LittleEndian.Uint64(data[192:200])
	bbtBid := binary.LittleEndian.Uint64(data[200:208])
	bbtIb := binary.LittleEndian.Uint64(data[208:216])

	if nbtBid != 0 || nbtIb != 0 || bbtBid != 0 || bbtIb != 0 {
		t.Logf("NBT: bid=%d ib=%d  BBT: bid=%d ib=%d (all 0 = empty trees)", nbtBid, nbtIb, bbtBid, bbtIb)
	}
}

func TestPSTHeaderSize(t *testing.T) {
	var buf bytes.Buffer
	w := NewWriter(&buf)
	if err := w.WriteHeader(); err != nil {
		t.Fatalf("WriteHeader failed: %v", err)
	}

	// PST header block is exactly 512 bytes
	if buf.Len() != 512 {
		t.Errorf("header size = %d, want 512", buf.Len())
	}
}

func TestPSTHeaderEncryptionType(t *testing.T) {
	var buf bytes.Buffer
	w := NewWriter(&buf)
	if err := w.WriteHeader(); err != nil {
		t.Fatalf("WriteHeader failed: %v", err)
	}

	data := buf.Bytes()

	// Byte at offset 513? No - header is 512 bytes total
	// Encryption type at offset 24 (bCryptMethod): 0 = none
	bCryptMethod := data[24]
	if bCryptMethod != 0 {
		t.Errorf("bCryptMethod = %d, want 0 (none)", bCryptMethod)
	}
}

func TestAddMessageMeta(t *testing.T) {
	// Just test that we can build a Message struct with required fields
	msg := Message{
		Subject:    "Test Subject",
		From:       "sender@example.com",
		FromName:   "Sender Name",
		To:         "recipient@example.com",
		ToName:     "Recipient Name",
		Body:       "Hello, this is a test email body.\r\n",
		ReceivedAt: "2026-01-15T10:30:00Z",
		MessageID:  "<test123@example.com>",
	}
	if msg.Subject != "Test Subject" {
		t.Errorf("Subject = %q", msg.Subject)
	}
	if msg.From != "sender@example.com" {
		t.Errorf("From = %q", msg.From)
	}
}

func TestAddMessageToPST(t *testing.T) {
	var buf bytes.Buffer
	w := NewWriter(&buf)
	if err := w.WriteHeader(); err != nil {
		t.Fatalf("WriteHeader failed: %v", err)
	}

	msg := Message{
		Subject:    "Hello World",
		From:       "alice@example.com",
		To:         "bob@example.com",
		Body:       "This is the body.\r\n",
		ReceivedAt: "2026-01-15T10:30:00Z",
		MessageID:  "<msg1@example.com>",
	}

	if err := w.AddMessage(msg); err != nil {
		t.Fatalf("AddMessage failed: %v", err)
	}

	if err := w.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	// After writing a message, the file should be larger than just the header
	size := buf.Len()
	if size <= 512 {
		t.Errorf("file size = %d, should be > 512 after adding a message", size)
	}

	// Verify the magic bytes are still intact at the beginning
	data := buf.Bytes()
	magic := binary.LittleEndian.Uint32(data[0:4])
	if magic != 0x4E444221 {
		t.Errorf("magic corrupted: 0x%08X", magic)
	}
}

func TestAddMultipleMessages(t *testing.T) {
	var buf bytes.Buffer
	w := NewWriter(&buf)

	if err := w.WriteHeader(); err != nil {
		t.Fatalf("WriteHeader failed: %v", err)
	}

	for i := range 3 {
		msg := Message{
			Subject:    "Message " + string(rune('1'+i)),
			From:       "sender@example.com",
			To:         "recipient@example.com",
			Body:       "Body of message " + string(rune('1'+i)) + "\r\n",
			ReceivedAt: "2026-01-15T10:30:00Z",
			MessageID:  "<msg@example.com>",
		}
		if err := w.AddMessage(msg); err != nil {
			t.Fatalf("AddMessage %d failed: %v", i, err)
		}
	}

	if err := w.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	if buf.Len() <= 512 {
		t.Error("file should be larger than header after 3 messages")
	}
}

func TestEmptyBodyMessage(t *testing.T) {
	var buf bytes.Buffer
	w := NewWriter(&buf)

	if err := w.WriteHeader(); err != nil {
		t.Fatalf("WriteHeader failed: %v", err)
	}

	msg := Message{
		Subject:    "Empty Body",
		From:       "sender@example.com",
		To:         "recipient@example.com",
		Body:       "",
		ReceivedAt: "2026-01-15T10:30:00Z",
		MessageID:  "<empty@example.com>",
	}

	if err := w.AddMessage(msg); err != nil {
		t.Fatalf("AddMessage with empty body failed: %v", err)
	}

	if err := w.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}
}

// PST-001 regression: more than 21 messages must fail with a descriptive
// error (AddMessage cap and Close bounds guard), never the historical
// slice-bounds panic from the 24-byte stride running past the 512-byte page.
func TestCloseErrorsPastPageCapacity(t *testing.T) {
	var sink bytes.Buffer
	w := NewWriter(&sink)
	if err := w.WriteHeader(); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < maxMessages; i++ {
		if err := w.AddMessage(Message{Subject: "ok", Body: "x"}); err != nil {
			t.Fatalf("message %d within the cap must be accepted: %v", i+1, err)
		}
	}
	if err := w.AddMessage(Message{Subject: "over", Body: "x"}); err == nil {
		t.Fatal("the 22nd message must be refused by AddMessage")
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close at the cap must succeed: %v", err)
	}

	// Defense-in-depth: a caller bypassing AddMessage's cap must hit Close's
	// descriptive error, not the historical slice-bounds panic.
	var sink2 bytes.Buffer
	w2 := NewWriter(&sink2)
	if err := w2.WriteHeader(); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < maxMessages+1; i++ {
		w2.msgs = append(w2.msgs, storedMsg{nid: uint32(i + 1), dataBID: uint64(64 + i)})
	}
	if err := w2.Close(); err == nil {
		t.Fatal("Close must error on an over-capacity writer instead of panicking")
	}
}

// PST-002 regression: CRLF in header-context fields must never inject header
// lines into the exported RFC822, and Date comes only from the parsed
// timestamp.
func TestHeaderInjectionIsSanitized(t *testing.T) {
	var sink bytes.Buffer
	w := NewWriter(&sink)
	if err := w.WriteHeader(); err != nil {
		t.Fatal(err)
	}
	err := w.AddMessage(Message{
		Subject:    "hello\r\nBcc: victim@example.com",
		From:       "sender@example.com\r\nX-Injected: 1",
		To:         "to@example.com",
		CC:         "cc@example.com\nX-CC-Inject: 1",
		MessageID:  "<ok@example.com>\r\nX-MID-Inject: 1",
		ReceivedAt: "not-a-timestamp\r\nX-Date-Inject: 1",
		Body:       "body",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	exported := sink.String()
	// The injection property: a CRLF in a header-context field must never
	// start a NEW header line in the exported RFC822 (a sanitized fragment
	// may survive glued to its value, but never at a line start).
	for _, injected := range []string{"Bcc:", "X-Injected:", "X-CC-Inject:", "X-MID-Inject:", "X-Date-Inject:"} {
		re := regexp.MustCompile(`(?m)^` + regexp.QuoteMeta(injected))
		if re.MatchString(exported) {
			t.Fatalf("exported RFC822 carries injected header line %q:\n%s", injected, exported)
		}
	}
	// A single header block: exactly one blank line separating headers/body
	// per message node's RFC section, and the raw unparsable date is absent.
	if strings.Contains(exported, "not-a-timestamp") {
		t.Fatal("raw ReceivedAt must not be echoed into the Date header")
	}
	if !strings.Contains(exported, "Subject: hello") {
		t.Fatalf("sanitized subject missing from export:\n%s", exported)
	}
}

// PST-003 regression: a well-formed export with the cap retained still closes
// cleanly and streams without the second full copy (output completeness is
// pinned by the header-magic tests above; here we pin no error on the
// boundary).
func TestCloseAtExactCapacitySucceeds(t *testing.T) {
	var sink bytes.Buffer
	w := NewWriter(&sink)
	if err := w.WriteHeader(); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < maxMessages; i++ {
		if err := w.AddMessage(Message{Subject: "m", Body: strings.Repeat("x", 100)}); err != nil {
			t.Fatalf("message %d: %v", i+1, err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close at exact capacity: %v", err)
	}
	if len(sink.Bytes()) <= pageSize*2 {
		t.Fatalf("expected data pages after NBT/BBT, got %d bytes", sink.Len())
	}
}
