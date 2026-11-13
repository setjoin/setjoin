package main

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	"github.com/minio/minio-go/v7"
	"setjoin.com/mailserver/internal/config"
	"setjoin.com/mailserver/internal/linkprotect"
	"setjoin.com/mailserver/internal/smtp"
	"setjoin.com/mailserver/internal/spam"
)

type recordingSMTPInbound struct {
	t              *testing.T
	wantCalls      []string
	nextCall       int
	wantMinio      *minio.Client
	wantBucket     string
	wantMaxConns   int32
	wantClamAVAddr string
	wantJWTSecret  []byte
	wantDomains    []string
	// wantLinkProtectVersion is the key-set version SetLinkProtectKeys must
	// carry; gotLinkProtectKeys records the installed set for parity asserts.
	wantLinkProtectVersion int
	gotLinkProtectKeys     linkprotect.TokenKeys
	wantAntiPhish          []smtp.PhishDetector
	wantSpamStore          spam.ModelSource
	sandboxPipeline        *smtp.AttachmentAnalysisPipeline
}

func newRecordingSMTPInbound(t *testing.T, wantCalls ...string) *recordingSMTPInbound {
	t.Helper()
	fake := &recordingSMTPInbound{t: t, wantCalls: wantCalls}
	t.Cleanup(fake.verifyComplete)
	return fake
}

func (f *recordingSMTPInbound) record(call string) {
	f.t.Helper()
	if f.nextCall >= len(f.wantCalls) {
		f.t.Fatalf("unexpected inbound configuration call %q", call)
	}
	if want := f.wantCalls[f.nextCall]; call != want {
		f.t.Fatalf("inbound configuration call %d = %q, want %q", f.nextCall, call, want)
	}
	f.nextCall++
}

func (f *recordingSMTPInbound) verifyComplete() {
	f.t.Helper()
	if f.nextCall != len(f.wantCalls) {
		f.t.Errorf("inbound configuration made %d calls, want %d; missing %v", f.nextCall, len(f.wantCalls), f.wantCalls[f.nextCall:])
	}
}

func (f *recordingSMTPInbound) SetBlobStore(client *minio.Client, bucket string) {
	f.record("SetBlobStore")
	if client != f.wantMinio || bucket != f.wantBucket {
		f.t.Errorf("SetBlobStore(%p, %q), want (%p, %q)", client, bucket, f.wantMinio, f.wantBucket)
	}
}

func (f *recordingSMTPInbound) SetMaxConns(max int32) {
	f.record("SetMaxConns")
	if max != f.wantMaxConns {
		f.t.Errorf("SetMaxConns(%d), want %d", max, f.wantMaxConns)
	}
}

func (f *recordingSMTPInbound) SetClamAV(addr string) {
	f.record("SetClamAV")
	if addr != f.wantClamAVAddr {
		f.t.Errorf("SetClamAV(%q), want %q", addr, f.wantClamAVAddr)
	}
}

func (f *recordingSMTPInbound) SetSandbox(pipeline *smtp.AttachmentAnalysisPipeline) {
	f.record("SetSandbox")
	if pipeline == nil || pipeline.Len() != 1 {
		f.t.Fatalf("SetSandbox pipeline must contain exactly one CAPE analyzer")
	}
	f.sandboxPipeline = pipeline
}

func (f *recordingSMTPInbound) SetLinkProtect(secret []byte, domains []string) {
	f.record("SetLinkProtect")
	if !reflect.DeepEqual(secret, f.wantJWTSecret) || !reflect.DeepEqual(domains, f.wantDomains) {
		f.t.Errorf("SetLinkProtect(%q, %v), want (%q, %v)", secret, domains, f.wantJWTSecret, f.wantDomains)
	}
}

func (f *recordingSMTPInbound) SetLinkProtectKeys(keys linkprotect.TokenKeys) {
	f.record("SetLinkProtectKeys")
	f.gotLinkProtectKeys = keys
	if keys.Version != f.wantLinkProtectVersion {
		f.t.Errorf("SetLinkProtectKeys version = %d, want %d", keys.Version, f.wantLinkProtectVersion)
	}
}

func (f *recordingSMTPInbound) SetAntiPhish(detectors []smtp.PhishDetector) {
	f.record("SetAntiPhish")
	if !reflect.DeepEqual(detectors, f.wantAntiPhish) {
		f.t.Errorf("SetAntiPhish(%v), want %v", detectors, f.wantAntiPhish)
	}
}

func (f *recordingSMTPInbound) SetSpamStore(store spam.ModelSource) {
	f.record("SetSpamStore")
	if store != f.wantSpamStore {
		f.t.Errorf("SetSpamStore(%p), want %p", store, f.wantSpamStore)
	}
}

type noopPhishDetector struct{}

func (*noopPhishDetector) Name() string { return "noop" }
func (*noopPhishDetector) Check(context.Context, *smtp.PhishInput) (*smtp.PhishResult, error) {
	return nil, nil
}

func TestConfigureSMTPInboundCommon_ListenerParity(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	minioClient := &minio.Client{}
	spamStore := &spam.PGModelStore{}
	detectors := []smtp.PhishDetector{&noopPhishDetector{}}
	cfg := &config.Config{
		S3Bucket:            "mailblobs",
		SMTPInboundMaxConns: 275,
		ClamAVAddr:          "127.0.0.1:3310",
		SandboxEnabled:      true,
		SandboxCAPEURL:      "http://127.0.0.1:8090",
		SandboxCAPEKey:      "test-cape-key",
		SandboxTimeout:      37 * time.Second,
		SandboxFailMode:     "closed",
		InternalDomains:     " internal.example,mail.example ",
	}
	cfg.JWTSecret = "test-jwt-secret"

	for _, listenerMode := range []string{"starttls", "implicit-tls"} {
		t.Run(listenerMode, func(t *testing.T) {
			fake := newRecordingSMTPInbound(t,
				"SetBlobStore",
				"SetMaxConns",
				"SetClamAV",
				"SetSandbox",
				"SetLinkProtect",
				"SetLinkProtectKeys",
				"SetAntiPhish",
				"SetSpamStore",
			)
			fake.wantMinio = minioClient
			fake.wantBucket = cfg.S3Bucket
			fake.wantMaxConns = 275
			fake.wantClamAVAddr = cfg.ClamAVAddr
			fake.wantJWTSecret = []byte(cfg.JWTSecret)
			fake.wantDomains = []string{"internal.example", "mail.example"}
			fake.wantLinkProtectVersion = 1 // unset version normalizes to the pre-rotation v1
			fake.wantAntiPhish = detectors
			fake.wantSpamStore = spamStore

			configureSMTPInboundCommon(fake, cfg, minioClient, detectors, spamStore, logger)
			if len(fake.gotLinkProtectKeys.Secret) == 0 {
				t.Fatalf("SetLinkProtectKeys installed an empty key set")
			}
		})
	}
}

func TestConfigureSMTPInboundCommon_DisabledOptionalChecksStayDisabled(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	cfg := &config.Config{S3Bucket: "mailblobs", SMTPInboundMaxConns: 10}
	fake := newRecordingSMTPInbound(t, "SetBlobStore", "SetMaxConns", "SetAntiPhish", "SetSpamStore")
	fake.wantBucket = cfg.S3Bucket
	fake.wantMaxConns = 10

	configureSMTPInboundCommon(fake, cfg, nil, nil, nil, logger)
}

func TestConfigureSMTPInboundCommon_PreservesSandboxFailurePolicyForBothListeners(t *testing.T) {
	cape := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "hostile analyzer unavailable", http.StatusServiceUnavailable)
	}))
	defer cape.Close()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	const hostileMessage = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

	for _, failMode := range []string{"open", "closed"} {
		for _, listenerMode := range []string{"starttls", "implicit-tls"} {
			t.Run(failMode+"/"+listenerMode, func(t *testing.T) {
				cfg := &config.Config{
					S3Bucket:            "mailblobs",
					SMTPInboundMaxConns: 10,
					SandboxEnabled:      true,
					SandboxCAPEURL:      cape.URL,
					SandboxTimeout:      100 * time.Millisecond,
					SandboxFailMode:     failMode,
				}
				fake := newRecordingSMTPInbound(t, "SetBlobStore", "SetMaxConns", "SetSandbox", "SetAntiPhish", "SetSpamStore")
				fake.wantBucket = cfg.S3Bucket
				fake.wantMaxConns = 10

				configureSMTPInboundCommon(fake, cfg, nil, nil, nil, logger)
				verdict := fake.sandboxPipeline.Analyze(context.Background(), []byte(hostileMessage))
				if failMode == "closed" && verdict.Severity != smtp.SandboxMalicious {
					t.Fatalf("fail-closed CAPE error severity = %v, want malicious", verdict.Severity)
				}
				if failMode == "open" && verdict.Severity != smtp.SandboxClean {
					t.Fatalf("fail-open CAPE error severity = %v, want clean", verdict.Severity)
				}
			})
		}
	}
}

func TestConfigureSMTPInboundCommon_PreservesSandboxTimeoutForBothListeners(t *testing.T) {
	cape := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(100 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer cape.Close()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	for _, listenerMode := range []string{"starttls", "implicit-tls"} {
		t.Run(listenerMode, func(t *testing.T) {
			cfg := &config.Config{
				S3Bucket:            "mailblobs",
				SMTPInboundMaxConns: 10,
				SandboxEnabled:      true,
				SandboxCAPEURL:      cape.URL,
				SandboxTimeout:      25 * time.Millisecond,
				SandboxFailMode:     "closed",
			}
			fake := newRecordingSMTPInbound(t, "SetBlobStore", "SetMaxConns", "SetSandbox", "SetAntiPhish", "SetSpamStore")
			fake.wantBucket = cfg.S3Bucket
			fake.wantMaxConns = 10

			configureSMTPInboundCommon(fake, cfg, nil, nil, nil, logger)
			outerCtx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
			defer cancel()
			started := time.Now()
			verdict := fake.sandboxPipeline.Analyze(outerCtx, []byte("hostile attachment"))
			if elapsed := time.Since(started); elapsed >= 500*time.Millisecond {
				t.Fatalf("sandbox used outer timeout after %v instead of configured %v", elapsed, cfg.SandboxTimeout)
			}
			if verdict.Severity != smtp.SandboxMalicious {
				t.Fatalf("timed-out fail-closed CAPE severity = %v, want malicious", verdict.Severity)
			}
		})
	}
}

func TestSMTPInboundConstructionSites_UseCommonConfigurationExactlyOnce(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "main.go", nil, 0)
	if err != nil {
		t.Fatalf("parse main.go: %v", err)
	}

	commonCalls := map[string]int{}
	tlsPolicyCalls := map[string]map[string]int{
		"inboundSrv":    {},
		"tlsInboundSrv": {},
	}
	ast.Inspect(file, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		if helper, ok := call.Fun.(*ast.Ident); ok && helper.Name == "configureSMTPInboundCommon" {
			if len(call.Args) == 0 {
				t.Fatalf("configureSMTPInboundCommon call has no server argument")
			}
			server, ok := call.Args[0].(*ast.Ident)
			if !ok {
				t.Fatalf("configureSMTPInboundCommon server argument is %T, want identifier", call.Args[0])
			}
			commonCalls[server.Name]++
			return true
		}
		selector, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || (selector.Sel.Name != "SetTLSEnforce" && selector.Sel.Name != "SetTLS") {
			return true
		}
		server, ok := selector.X.(*ast.Ident)
		if !ok {
			return true
		}
		if _, tracked := tlsPolicyCalls[server.Name]; tracked {
			tlsPolicyCalls[server.Name][selector.Sel.Name]++
		}
		return true
	})

	if !reflect.DeepEqual(commonCalls, map[string]int{"inboundSrv": 1, "tlsInboundSrv": 1}) {
		t.Fatalf("common inbound configurator calls = %v, want exactly one per listener", commonCalls)
	}
	if got := tlsPolicyCalls["inboundSrv"]; got["SetTLSEnforce"] != 1 || got["SetTLS"] != 0 {
		t.Fatalf("STARTTLS-local policy calls = %v, want SetTLSEnforce exactly once and no SetTLS", got)
	}
	if got := tlsPolicyCalls["tlsInboundSrv"]; got["SetTLS"] != 1 || got["SetTLSEnforce"] != 0 {
		t.Fatalf("implicit-TLS-local policy calls = %v, want SetTLS exactly once and no SetTLSEnforce", got)
	}
}
