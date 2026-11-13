package smtp

import (
	"bytes"
	"strings"
	"testing"
)

func TestExtractAddr(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"<user@example.com>", "user@example.com"},
		{"user@example.com", "user@example.com"},
		{"Name <user@example.com>", "user@example.com"},
		{"", ""},
		{"<user@example.com>", "user@example.com"},
	}
	for _, tc := range tests {
		got := extractAddr(tc.input)
		if got != tc.want {
			t.Errorf("extractAddr(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

func TestExtractHeader(t *testing.T) {
	msg := "Subject: Hello World\r\nFrom: sender@example.com\r\n\r\nBody here"
	if got := extractHeader(msg, "Subject"); got != "Hello World" {
		t.Errorf("extractHeader Subject = %q, want %q", got, "Hello World")
	}
	if got := extractHeader(msg, "From"); got != "sender@example.com" {
		t.Errorf("extractHeader From = %q, want %q", got, "sender@example.com")
	}
	if got := extractHeader(msg, "Missing"); got != "" {
		t.Errorf("extractHeader Missing = %q, want empty", got)
	}
}

func TestParseFrom(t *testing.T) {
	tests := []struct {
		input    string
		wantName string
		wantAddr string
	}{
		{"user@example.com", "", "user@example.com"},
		{"John Doe <john@example.com>", "John Doe", "john@example.com"},
		{"\"Jane Doe\" <jane@example.com>", "Jane Doe", "jane@example.com"},
	}
	for _, tc := range tests {
		name, addr := parseFrom(tc.input)
		if name != tc.wantName || addr != tc.wantAddr {
			t.Errorf("parseFrom(%q) = (%q, %q), want (%q, %q)", tc.input, name, addr, tc.wantName, tc.wantAddr)
		}
	}
}

func TestParseAddressList(t *testing.T) {
	tests := []struct {
		input string
		want  string // JSON string representation
	}{
		{"", "[]"},
		{"alice@example.com", `[{"email":"alice@example.com"}]`},
		{"Alice <alice@example.com>, Bob <bob@example.com>", `[{"name":"Alice","email":"alice@example.com"},{"name":"Bob","email":"bob@example.com"}]`},
		{"broken address, Bob <bob@example.com>", `[{"email":"broken address"},{"name":"Bob","email":"bob@example.com"}]`},
	}
	for _, tc := range tests {
		got := string(parseAddressList(tc.input))
		if got != tc.want {
			t.Errorf("parseAddressList(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

func TestExtractBodyText(t *testing.T) {
	msg := "Content-Type: text/plain\r\n\r\nHello world"
	got := extractBodyText(msg)
	if got != "Hello world" {
		t.Errorf("extractBodyText = %q, want %q", got, "Hello world")
	}
}

func TestExtractBodyHTML(t *testing.T) {
	msg := "Content-Type: text/html\r\n\r\n<html><body>Hello</body></html>"
	got := extractBodyHTML(msg)
	if got != "<html><body>Hello</body></html>" {
		t.Errorf("extractBodyHTML = %q, want %q", got, "<html><body>Hello</body></html>")
	}
}

func TestExtractBodyTextMultipart(t *testing.T) {
	msg := "Content-Type: multipart/alternative; boundary=\"boundary123\"\r\n" +
		"\r\n" +
		"--boundary123\r\n" +
		"Content-Type: text/plain\r\n" +
		"\r\n" +
		"Plain text body\r\n" +
		"--boundary123\r\n" +
		"Content-Type: text/html\r\n" +
		"\r\n" +
		"<p>HTML body</p>\r\n" +
		"--boundary123--"
	got := extractBodyText(msg)
	if !strings.Contains(got, "Plain text body") {
		t.Errorf("extractBodyText multipart = %q, want to contain 'Plain text body'", got)
	}
}

func TestExtractBodyHTMLMultipart(t *testing.T) {
	msg := "Content-Type: multipart/alternative; boundary=\"boundary123\"\r\n" +
		"\r\n" +
		"--boundary123\r\n" +
		"Content-Type: text/plain\r\n" +
		"\r\n" +
		"Plain text body\r\n" +
		"--boundary123\r\n" +
		"Content-Type: text/html\r\n" +
		"\r\n" +
		"<p>HTML body</p>\r\n" +
		"--boundary123--"
	got := extractBodyHTML(msg)
	if !strings.Contains(got, "<p>HTML body</p>") {
		t.Errorf("extractBodyHTML multipart = %q, want to contain '<p>HTML body</p>'", got)
	}
}

func TestRandomID(t *testing.T) {
	id1 := randomID()
	id2 := randomID()
	if id1 == id2 {
		t.Error("randomID should produce unique values")
	}
	if len(id1) != 32 {
		t.Errorf("randomID length = %d, want 32", len(id1))
	}
}

func TestSplitHeadersBody(t *testing.T) {
	tests := []struct {
		input       string
		wantHeaders string
		wantBody    string
	}{
		{"Subject: test\r\n\r\nbody", "Subject: test\r\n", "body"},
		{"Subject: test\n\nbody", "Subject: test\n", "body"},
		{"no body", "no body", ""},
	}
	for _, tc := range tests {
		h, b := splitHeadersBody([]byte(tc.input))
		if string(h) != tc.wantHeaders || string(b) != tc.wantBody {
			t.Errorf("splitHeadersBody(%q) = (%q, %q), want (%q, %q)", tc.input, string(h), string(b), tc.wantHeaders, tc.wantBody)
		}
	}
}

func TestBytesIndex(t *testing.T) {
	s := []byte("hello world")
	sub := []byte("world")
	if got := bytes.Index(s, sub); got != 6 {
		t.Errorf("bytes.Index = %d, want 6", got)
	}
}

func TestDetectAttachmentTypes(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "plain text email",
			input: "Content-Type: text/plain\r\n\r\nHello",
			want:  nil,
		},
		{
			name: "multipart with PDF attachment",
			input: "Content-Type: multipart/mixed; boundary=\"boundary123\"\r\n" +
				"\r\n" +
				"--boundary123\r\n" +
				"Content-Type: text/plain\r\n" +
				"\r\n" +
				"Body text\r\n" +
				"--boundary123\r\n" +
				"Content-Type: application/pdf\r\n" +
				"Content-Disposition: attachment; filename=\"doc.pdf\"\r\n" +
				"\r\n" +
				"PDF content\r\n" +
				"--boundary123--",
			want: []string{"application/pdf"},
		},
		{
			name: "multipart with DOCX (prefix match)",
			input: "Content-Type: multipart/mixed; boundary=\"b\"\r\n" +
				"\r\n" +
				"--b\r\n" +
				"Content-Type: application/vnd.openxmlformats-officedocument.wordprocessingml.document\r\n" +
				"Content-Disposition: attachment; filename=\"doc.docx\"\r\n" +
				"\r\n" +
				"DOCX content\r\n" +
				"--b--",
			want: []string{"application/vnd.openxmlformats-officedocument"},
		},
		{
			name: "multipart with ZIP",
			input: "Content-Type: multipart/mixed; boundary=\"b\"\r\n" +
				"\r\n" +
				"--b\r\n" +
				"Content-Type: application/zip\r\n" +
				"\r\n" +
				"ZIP content\r\n" +
				"--b--",
			want: []string{"application/zip"},
		},
		{
			name: "multipart with executable",
			input: "Content-Type: multipart/mixed; boundary=\"b\"\r\n" +
				"\r\n" +
				"--b\r\n" +
				"Content-Type: application/x-msdownload\r\n" +
				"\r\n" +
				"EXE content\r\n" +
				"--b--",
			want: []string{"application/x-msdownload"},
		},
		{
			name: "multipart with PDF and XLSX",
			input: "Content-Type: multipart/mixed; boundary=\"b\"\r\n" +
				"\r\n" +
				"--b\r\n" +
				"Content-Type: application/pdf\r\n" +
				"\r\n" +
				"PDF content\r\n" +
				"--b\r\n" +
				"Content-Type: application/vnd.openxmlformats-officedocument.spreadsheetml.sheet\r\n" +
				"\r\n" +
				"XLSX content\r\n" +
				"--b--",
			want: []string{"application/pdf", "application/vnd.openxmlformats-officedocument"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := detectAttachmentTypes([]byte(tc.input))
			if len(got) != len(tc.want) {
				t.Errorf("detectAttachmentTypes = %v, want %v", got, tc.want)
				return
			}
			for i, wantType := range tc.want {
				if got[i] != wantType {
					t.Errorf("detectAttachmentTypes[%d] = %q, want %q", i, got[i], wantType)
				}
			}
		})
	}
}

func TestDetectAttachmentTypesBinaryExecutableTypes(t *testing.T) {
	execTypes := []string{
		"application/x-msdownload",
		"application/x-dosexec",
		"application/x-mach-binary",
		"application/x-elf",
		"application/x-executable",
	}
	for _, mimeType := range execTypes {
		msg := "Content-Type: multipart/mixed; boundary=\"b\"\r\n" +
			"\r\n" +
			"--b\r\n" +
			"Content-Type: " + mimeType + "\r\n" +
			"\r\n" +
			"binary content\r\n" +
			"--b--"
		got := detectAttachmentTypes([]byte(msg))
		if len(got) != 1 || got[0] != mimeType {
			t.Errorf("detectAttachmentTypes for %s = %v, want [%s]", mimeType, got, mimeType)
		}
	}
}

func TestDetectAttachmentTypesDeduplication(t *testing.T) {
	// Two parts with same MIME type should only be reported once
	msg := "Content-Type: multipart/mixed; boundary=\"b\"\r\n" +
		"\r\n" +
		"--b\r\n" +
		"Content-Type: application/pdf\r\n" +
		"\r\n" +
		"PDF 1\r\n" +
		"--b\r\n" +
		"Content-Type: application/pdf\r\n" +
		"\r\n" +
		"PDF 2\r\n" +
		"--b--"
	got := detectAttachmentTypes([]byte(msg))
	if len(got) != 1 {
		t.Errorf("detectAttachmentTypes with duplicates = %v, want 1 unique entry", got)
	}
}
