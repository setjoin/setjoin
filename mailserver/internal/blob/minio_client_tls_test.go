package blob

import (
	"testing"

	"setjoin.com/mailserver/internal/config"
)

// TestNewMinIOClient_TLSPosture pins the shared blob client's transport-TLS
// matrix (D-MAILSERVER-INTERNAL-STORAGE-F-001). The client honors S3_SECURE as
// an explicit assertion resolved against the endpoint scheme — the posture is
// observable via minio.Client.EndpointURL(), which reflects the Secure flag.
func TestNewMinIOClient_TLSPosture(t *testing.T) {
	cases := []struct {
		name       string
		endpoint   string
		s3Secure   bool
		wantScheme string
		wantErr    bool
	}{
		{
			name:       "loopback default stays plaintext (deploy compatibility)",
			endpoint:   "127.0.0.1:9000",
			s3Secure:   false,
			wantScheme: "http",
		},
		{
			name:       "S3_SECURE=true forces TLS on scheme-less endpoint",
			endpoint:   "127.0.0.1:9000",
			s3Secure:   true,
			wantScheme: "https",
		},
		{
			name:       "https endpoint derives TLS",
			endpoint:   "https://minio.internal:9000",
			s3Secure:   true,
			wantScheme: "https",
		},
		{
			name:     "https endpoint with S3_SECURE=false is a rejected conflict",
			endpoint: "https://minio.internal:9000",
			s3Secure: false,
			wantErr:  true,
		},
		{
			name:     "scheme-less remote endpoint rejected fail-closed",
			endpoint: "minio.internal:9000",
			s3Secure: false,
			wantErr:  true,
		},
		{
			name:       "scheme-less remote with S3_SECURE=true uses TLS",
			endpoint:   "minio.internal:9000",
			s3Secure:   true,
			wantScheme: "https",
		},
		{
			name:     "http remote endpoint rejected",
			endpoint: "http://minio.internal:9000",
			s3Secure: false,
			wantErr:  true,
		},
		{
			name:       "http loopback remains supported",
			endpoint:   "http://127.0.0.1:9000",
			s3Secure:   false,
			wantScheme: "http",
		},
		{
			name:     "empty endpoint rejected",
			endpoint: "",
			s3Secure: false,
			wantErr:  true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &config.Config{
				S3Endpoint:  tc.endpoint,
				S3AccessKey: "k",
				S3SecretKey: "s",
				S3Bucket:    "blobs",
				S3Secure:    tc.s3Secure,
			}
			mc, err := NewMinIOClient(cfg)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("NewMinIOClient(%q, S3_SECURE=%v) succeeded, want fail-closed error", tc.endpoint, tc.s3Secure)
				}
				return
			}
			if err != nil {
				t.Fatalf("NewMinIOClient(%q, S3_SECURE=%v): %v", tc.endpoint, tc.s3Secure, err)
			}
			if got := mc.EndpointURL().Scheme; got != tc.wantScheme {
				t.Fatalf("EndpointURL scheme = %q, want %q", got, tc.wantScheme)
			}
		})
	}
}
