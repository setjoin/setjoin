package threat

import "testing"

func TestClientTypeLegacyUmbrella(t *testing.T) {
	// Without the legacy umbrella, imap/smtp keep their specific type.
	if got := clientTypeFromProtocolUmbrella(ProtocolIMAP, "", false); got != ProtocolIMAP {
		t.Fatalf("imap non-umbrella: got %q want imap", got)
	}
	// With the umbrella requested, imap/smtp collapse to "legacy".
	if got := clientTypeFromProtocolUmbrella(ProtocolIMAP, "", true); got != ClientTypeLegacy {
		t.Fatalf("imap umbrella: got %q want legacy", got)
	}
	if got := clientTypeFromProtocolUmbrella(ProtocolSMTP, "", true); got != ClientTypeLegacy {
		t.Fatalf("smtp umbrella: got %q want legacy", got)
	}
	// HTTP is never legacy.
	if got := clientTypeFromProtocolUmbrella(ProtocolHTTP, "Mozilla", true); got == ClientTypeLegacy {
		t.Fatal("http must not collapse to legacy")
	}
}

func TestConnectionMetaDeviceBoundField(t *testing.T) {
	m := ConnectionMeta{DeviceBound: true, DeviceID: 42}
	if !m.DeviceBound || m.DeviceID != 42 {
		t.Fatal("ConnectionMeta must carry DeviceBound/DeviceID")
	}
}
