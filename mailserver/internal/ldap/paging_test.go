package ldap

import (
	"bytes"
	"encoding/asn1"
	"testing"
)

// encodeForTest builds the BER-encoded control value the way the old
// pagedResultsControl.Encode method did, for exercising the decode path.
func encodeForTest(t *testing.T, pageSize int32, cookie []byte) []byte {
	t.Helper()
	ber, err := asn1.Marshal(pagedResultsControlValue{Size: pageSize, Cookie: cookie})
	if err != nil {
		t.Fatalf("asn1.Marshal: %v", err)
	}
	return ber
}

func TestParsePagedResultsControl(t *testing.T) {
	encoded := encodeForTest(t, 250, []byte{0x01, 0x02, 0x03})

	parsed, err := parsePagedResultsControl(encoded)
	if err != nil {
		t.Fatalf("failed to parse encoded control: %v", err)
	}
	if parsed.pageSize != 250 {
		t.Errorf("expected pageSize 250, got %d", parsed.pageSize)
	}
	if !bytes.Equal(parsed.cookie, []byte{0x01, 0x02, 0x03}) {
		t.Errorf("expected cookie {1,2,3}, got %v", parsed.cookie)
	}
}

func TestParsePagedResultsControlEmptyCookie(t *testing.T) {
	encoded := encodeForTest(t, 500, nil)

	parsed, err := parsePagedResultsControl(encoded)
	if err != nil {
		t.Fatalf("failed to parse encoded control: %v", err)
	}
	if parsed.pageSize != 500 {
		t.Errorf("expected pageSize 500, got %d", parsed.pageSize)
	}
	if len(parsed.cookie) != 0 {
		t.Errorf("expected empty cookie, got %v", parsed.cookie)
	}
}

func TestPagedResultsOIDConstant(t *testing.T) {
	// OID 1.2.840.113556.1.4.319
	if pagedResultsOID != "1.2.840.113556.1.4.319" {
		t.Errorf("unexpected OID constant: %s", pagedResultsOID)
	}
}
