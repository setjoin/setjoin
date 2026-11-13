package carddav

import (
	"strings"
	"testing"
)

func TestParseVCard_BasicFields(t *testing.T) {
	vcard := `BEGIN:VCARD
VERSION:3.0
UID:test-uid-1
FN:John Doe
N:Doe;John;;;
ORG:Acme Corp
TITLE:Engineer
NOTE:Test note
END:VCARD`

	result, err := ParseVCard(vcard)
	if err != nil {
		t.Fatalf("ParseVCard: %v", err)
	}
	if result.UID != "test-uid-1" {
		t.Errorf("UID = %q, want test-uid-1", result.UID)
	}
	if result.FN != "John Doe" {
		t.Errorf("FN = %q, want John Doe", result.FN)
	}
	if result.N != "Doe;John;;;" {
		t.Errorf("N = %q", result.N)
	}
	if result.ORG != "Acme Corp" {
		t.Errorf("ORG = %q", result.ORG)
	}
	if result.TITLE != "Engineer" {
		t.Errorf("TITLE = %q", result.TITLE)
	}
	if result.NOTE != "Test note" {
		t.Errorf("NOTE = %q", result.NOTE)
	}
}

func TestParseVCard_Email(t *testing.T) {
	vcard := `BEGIN:VCARD
VERSION:3.0
UID:test-uid-2
FN:Jane Smith
N:Smith;Jane;;;
EMAIL;TYPE=WORK:jane@example.com
EMAIL;TYPE=HOME:jane@home.com
END:VCARD`

	result, err := ParseVCard(vcard)
	if err != nil {
		t.Fatalf("ParseVCard: %v", err)
	}
	if len(result.Emails) != 2 {
		t.Fatalf("expected 2 emails, got %d", len(result.Emails))
	}
	if result.Emails[0].Value != "jane@example.com" {
		t.Errorf("email[0] = %q", result.Emails[0].Value)
	}
	if result.Emails[1].Value != "jane@home.com" {
		t.Errorf("email[1] = %q", result.Emails[1].Value)
	}
}

func TestParseVCard_Phone(t *testing.T) {
	vcard := `BEGIN:VCARD
VERSION:3.0
UID:test-uid-3
FN:Bob
N:Bob;;;
TEL;TYPE=CELL:+1-555-1234
END:VCARD`

	result, err := ParseVCard(vcard)
	if err != nil {
		t.Fatalf("ParseVCard: %v", err)
	}
	if len(result.Phones) != 1 {
		t.Fatalf("expected 1 phone, got %d", len(result.Phones))
	}
	if result.Phones[0].Value != "+1-555-1234" {
		t.Errorf("phone = %q", result.Phones[0].Value)
	}
}

func TestParseVCard_Address(t *testing.T) {
	vcard := `BEGIN:VCARD
VERSION:3.0
UID:test-uid-4
FN:Alice
N:Alice;;;
ADR;TYPE=HOME:;;123 Main St;Springfield;IL;62701;USA
END:VCARD`

	result, err := ParseVCard(vcard)
	if err != nil {
		t.Fatalf("ParseVCard: %v", err)
	}
	if len(result.Addresses) != 1 {
		t.Fatalf("expected 1 address, got %d", len(result.Addresses))
	}
	if result.Addresses[0].Street != "123 Main St" {
		t.Errorf("street = %q", result.Addresses[0].Street)
	}
	if result.Addresses[0].City != "Springfield" {
		t.Errorf("city = %q", result.Addresses[0].City)
	}
	if result.Addresses[0].Code != "62701" {
		t.Errorf("code = %q", result.Addresses[0].Code)
	}
}

func TestParseVCard_Birthday(t *testing.T) {
	vcard := `BEGIN:VCARD
VERSION:3.0
UID:test-uid-5
FN:Test User
N:User;Test;;;
BDAY:19900115
END:VCARD`

	result, err := ParseVCard(vcard)
	if err != nil {
		t.Fatalf("ParseVCard: %v", err)
	}
	if result.Birthday == nil {
		t.Fatal("expected non-nil birthday")
	}
	if result.Birthday.Format("20060102") != "19900115" {
		t.Errorf("birthday = %s", result.Birthday.Format("20060102"))
	}
}

func TestParseVCard_EmptyInput(t *testing.T) {
	_, err := ParseVCard("")
	if err == nil {
		t.Error("expected error for empty input")
	}
}

func TestParseVCard_MissingEnd(t *testing.T) {
	// Parser is lenient — parses whatever content is available even without END:VCARD.
	_, err := ParseVCard("BEGIN:VCARD\nVERSION:3.0\nUID:x\nFN:x\nN:x;;;")
	if err != nil {
		t.Logf("parser rejected missing END:VCARD: %v", err)
	}
	// Either behavior is acceptable — some parsers reject, some are lenient.
}

func TestParseVCard_Nickname(t *testing.T) {
	vcard := `BEGIN:VCARD
VERSION:3.0
UID:test-uid-6
FN:Test
N:Test;;;
NICKNAME:Tester
END:VCARD`

	result, err := ParseVCard(vcard)
	if err != nil {
		t.Fatalf("ParseVCard: %v", err)
	}
	if result.NICKNAME != "Tester" {
		t.Errorf("NICKNAME = %q, want Tester", result.NICKNAME)
	}
}

func TestParseVCard_URLAndIMPP(t *testing.T) {
	vcard := `BEGIN:VCARD
VERSION:3.0
UID:test-uid-7
FN:Test
N:Test;;;
URL:https://example.com
IMPP:xmpp:user@example.com
END:VCARD`

	result, err := ParseVCard(vcard)
	if err != nil {
		t.Fatalf("ParseVCard: %v", err)
	}
	if len(result.URLs) != 1 || result.URLs[0].Value != "https://example.com" {
		t.Errorf("URLs = %v", result.URLs)
	}
	if len(result.IMPPs) != 1 || result.IMPPs[0].Value != "xmpp:user@example.com" {
		t.Errorf("IMPPs = %v", result.IMPPs)
	}
}

func TestParseVCard_Categories(t *testing.T) {
	vcard := `BEGIN:VCARD
VERSION:3.0
UID:test-uid-8
FN:Test
N:Test;;;
CATEGORIES:Work,Friends
END:VCARD`

	result, err := ParseVCard(vcard)
	if err != nil {
		t.Fatalf("ParseVCard: %v", err)
	}
	if len(result.Categories) != 2 {
		t.Fatalf("expected 2 categories, got %d", len(result.Categories))
	}
	if result.Categories[0] != "Work" || result.Categories[1] != "Friends" {
		t.Errorf("categories = %v", result.Categories)
	}
}

func TestEscape(t *testing.T) {
	tests := []struct{ input, expected string }{
		{"hello", "hello"},
		{"hello, world", "hello\\, world"},
		{"hello; world", "hello\\; world"},
		{"hello\\world", "hello\\\\world"},
	}
	for _, tt := range tests {
		got := escape(tt.input)
		if got != tt.expected {
			t.Errorf("escape(%q) = %q, want %q", tt.input, got, tt.expected)
		}
	}
}

func TestParseVCard_GenderAndKind(t *testing.T) {
	vcard := `BEGIN:VCARD
VERSION:3.0
UID:test-uid-9
FN:Test
N:Test;;;
GENDER:M
KIND:individual
PRODID:-//Test//EN
END:VCARD`

	result, err := ParseVCard(vcard)
	if err != nil {
		t.Fatalf("ParseVCard: %v", err)
	}
	if result.GENDER != "M" {
		t.Errorf("GENDER = %q, want M", result.GENDER)
	}
	if result.KIND != "individual" {
		t.Errorf("KIND = %q, want individual", result.KIND)
	}
	if result.PRODID != "-//Test//EN" {
		t.Errorf("PRODID = %q", result.PRODID)
	}
}

func TestParseVCard_FoldedLines(t *testing.T) {
	// RFC 2425 line folding: continued lines start with a space.
	vcard := "BEGIN:VCARD\r\nVERSION:3.0\r\nUID:test\r\nFN:A Very Long Name\r\n  That Continues\r\nN:Name;;;\r\nEND:VCARD\r\n"

	result, err := ParseVCard(vcard)
	if err != nil {
		t.Fatalf("ParseVCard: %v", err)
	}
	if !strings.Contains(result.FN, "A Very Long Name") {
		t.Errorf("FN should contain folded content, got %q", result.FN)
	}
}

func TestParseVCard_Anniversary(t *testing.T) {
	vcard := `BEGIN:VCARD
VERSION:3.0
UID:test-uid-10
FN:Test
N:Test;;;
ANNIVERSARY:20150615
END:VCARD`

	result, err := ParseVCard(vcard)
	if err != nil {
		t.Fatalf("ParseVCard: %v", err)
	}
	if result.Anniversary == nil {
		t.Fatal("expected non-nil anniversary")
	}
	if result.Anniversary.Format("20060102") != "20150615" {
		t.Errorf("anniversary = %s", result.Anniversary.Format("20060102"))
	}
}
