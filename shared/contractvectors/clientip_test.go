package contractvectors

import (
	"crypto/tls"
	"net/http"
	"testing"

	"setjoin.com/shared/clientip"
)

func TestRecordClientip(t *testing.T) {
	type input struct {
		Remote         string   `json:"remote"`
		Trusted        string   `json:"trusted"`
		ForwardedFor   []string `json:"forwarded_for"`
		ForwardedProto []string `json:"forwarded_proto"`
		TLS            bool     `json:"tls"`
	}
	type output struct {
		IP    string `json:"ip"`
		Proto string `json:"proto"`
	}
	tests := []struct {
		name string
		in   input
	}{
		{"trusted_proxy", input{Remote: "192.0.2.10:443", Trusted: "192.0.2.10", ForwardedFor: []string{"203.0.113.5"}, ForwardedProto: []string{"https"}}},
		{"spoofed_untrusted", input{Remote: "198.51.100.2:1234", Trusted: "192.0.2.10", ForwardedFor: []string{"203.0.113.5"}, ForwardedProto: []string{"https"}}},
		{"multi_header_rightmost", input{Remote: "192.0.2.10:443", Trusted: "192.0.2.10", ForwardedFor: []string{"10.0.0.1, 10.0.0.2", "2001:db8::123"}, ForwardedProto: []string{"http", " HTTPS "}}},
		{"invalid_rightmost", input{Remote: "192.0.2.10:443", Trusted: "192.0.2.10", ForwardedFor: []string{"203.0.113.5, bogus"}, ForwardedProto: []string{"https, http"}}},
		{"ipv6_zone", input{Remote: "[2001:db8::1]:8080", Trusted: "2001:db8::1", ForwardedFor: []string{"[fe80::1%25eth0]"}}},
		{"tls_overrides_forwarded", input{Remote: "192.0.2.10:443", Trusted: "192.0.2.10", ForwardedProto: []string{"http"}, TLS: true}},
	}
	cases := make([]map[string]any, 0, len(tests))
	for _, tc := range tests {
		r := &http.Request{RemoteAddr: tc.in.Remote, Header: make(http.Header)}
		for _, v := range tc.in.ForwardedFor {
			r.Header.Add("X-Forwarded-For", v)
		}
		for _, v := range tc.in.ForwardedProto {
			r.Header.Add("X-Forwarded-Proto", v)
		}
		if tc.in.TLS {
			r.TLS = &tls.ConnectionState{}
		}
		trust := func(peer string) bool { return tc.in.Trusted != "" && peer == tc.in.Trusted }
		cases = append(cases, map[string]any{"name": tc.name, "input": tc.in, "output": output{clientip.ExtractWithTrust(r, trust), clientip.ForwardedProtoWithTrust(r, trust)}})
	}
	writeVectors(t, "clientip", cases)
}
