package smtp

import (
	"testing"
)

func TestExtractDomain(t *testing.T) {
	tests := []struct {
		name     string
		fromAddr string
		want     string
	}{
		{
			name:     "normal domain",
			fromAddr: "user@example.com",
			want:     "example.com",
		},
		{
			name:     "subdomain",
			fromAddr: "admin@mail.example.co.uk",
			want:     "mail.example.co.uk",
		},
		{
			name:     "no at sign",
			fromAddr: "invalid-email",
			want:     "",
		},
		{
			name:     "empty string",
			fromAddr: "",
			want:     "",
		},
		{
			name:     "angle bracket address",
			fromAddr: "<user@example.com>",
			want:     "example.com>",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractDomain(tt.fromAddr)
			if got != tt.want {
				t.Errorf("extractDomain(%q) = %q, want %q", tt.fromAddr, got, tt.want)
			}
		})
	}
}
