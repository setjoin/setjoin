package ldap

import (
	"encoding/asn1"
	"fmt"
)

// pagedResultsOID is the OID for SimplePagedResultsControl (RFC 2696).
const pagedResultsOID = "1.2.840.113556.1.4.319"

// pagedResultsControl implements the SimplePagedResultsControl per RFC 2696.
// It carries a page size and an opaque cookie for resuming paged searches.
type pagedResultsControl struct {
	pageSize int32
	cookie   []byte
}

// pagedResultsControlValue is the ASN.1 structure for the control value.
//
//	realSearchControlValue ::= SEQUENCE {
//	    size    INTEGER (0..maxInt),
//	    cookie  OCTET STRING
//	}
type pagedResultsControlValue struct {
	Size   int32
	Cookie []byte `asn1:"optional,tag:4"`
}

// parsePagedResultsControl decodes a BER-encoded paged results control value.
func parsePagedResultsControl(encoded []byte) (*pagedResultsControl, error) {
	var val pagedResultsControlValue
	rest, err := asn1.Unmarshal(encoded, &val)
	if err != nil {
		return nil, fmt.Errorf("paged results control: %w", err)
	}
	if len(rest) > 0 {
		return nil, fmt.Errorf("paged results control: trailing bytes after value")
	}
	return &pagedResultsControl{
		pageSize: val.Size,
		cookie:   val.Cookie,
	}, nil
}
