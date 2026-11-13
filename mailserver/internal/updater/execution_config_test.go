package updater

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeExecutionConfig(t *testing.T, raw string, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "execution.json")
	if err := os.WriteFile(path, []byte(raw), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestReadExecutionConfigDefaultsDisabledAndParsesEnabledS3(t *testing.T) {
	config, err := ReadExecutionConfig(filepath.Join(t.TempDir(), "missing"))
	if err != nil || config.Enabled || config.Version != ExecutionConfigVersion {
		t.Fatalf("missing config=%#v err=%v", config, err)
	}
	raw := `{"version":1,"enabled":true,"installRoot":"/opt/setjoin","recoveryProvider":"s3","recoveryEndpoint":"http://127.0.0.1:9000","recoveryRegion":"us-east-1","recoveryBucket":"setjoin-backup"}`
	config, err = ReadExecutionConfig(writeExecutionConfig(t, raw, 0o600))
	if err != nil || !config.Enabled || config.InstallRoot != "/opt/setjoin" {
		t.Fatalf("enabled config=%#v err=%v", config, err)
	}
	store, err := NewRecoveryStore(config, "access-key", "secret-key")
	if err != nil || store == nil {
		t.Fatalf("recovery store=%T err=%v", store, err)
	}
	if err := store.PutObject(context.Background(), "key", strings.NewReader("value"), 5); err == nil {
		t.Fatal("read-only updater recovery store accepted a write")
	}
}

func TestExecutionConfigRejectsUnsafeOrAmbiguousInput(t *testing.T) {
	valid := ExecutionConfig{Version: 1, Enabled: true, InstallRoot: "/opt/setjoin", RecoveryProvider: "s3", RecoveryEndpoint: "https://backup.example.test", RecoveryRegion: "us-east-1", RecoveryBucket: "setjoin-backup"}
	for name, mutate := range map[string]func(*ExecutionConfig){
		"version":         func(config *ExecutionConfig) { config.Version = 2 },
		"root":            func(config *ExecutionConfig) { config.InstallRoot = "/" },
		"relative":        func(config *ExecutionConfig) { config.InstallRoot = "opt/setjoin" },
		"provider":        func(config *ExecutionConfig) { config.RecoveryProvider = "posix" },
		"bucket":          func(config *ExecutionConfig) { config.RecoveryBucket = "Bad/Bucket" },
		"region":          func(config *ExecutionConfig) { config.RecoveryRegion = "bad\nregion" },
		"endpoint scheme": func(config *ExecutionConfig) { config.RecoveryEndpoint = "file:///tmp" },
		"endpoint user":   func(config *ExecutionConfig) { config.RecoveryEndpoint = "https://user@backup.test" },
		"endpoint path":   func(config *ExecutionConfig) { config.RecoveryEndpoint = "https://backup.test/path" },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := valid
			mutate(&candidate)
			if err := candidate.Validate(); err == nil {
				t.Fatalf("unsafe config accepted: %#v", candidate)
			}
		})
	}
	for name, raw := range map[string]string{
		"unknown":   `{"version":1,"enabled":false,"command":"sh"}`,
		"trailing":  `{"version":1,"enabled":false}{}`,
		"malformed": `{`,
		"semantic":  `{"version":2,"enabled":false}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ReadExecutionConfig(writeExecutionConfig(t, raw, 0o600)); err == nil {
				t.Fatal("invalid execution JSON accepted")
			}
		})
	}
	if _, err := ReadExecutionConfig(writeExecutionConfig(t, `{"version":1,"enabled":false}`, 0o666)); err == nil {
		t.Fatal("group/world-writable execution config accepted")
	}
	target := writeExecutionConfig(t, `{"version":1,"enabled":false}`, 0o600)
	link := filepath.Join(t.TempDir(), "execution-link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadExecutionConfig(link); err == nil {
		t.Fatal("symlink execution config accepted")
	}
}

func TestRecoveryStoreAndEndpointValidationFailsClosed(t *testing.T) {
	disabled := ExecutionConfig{Version: 1}
	if _, err := NewRecoveryStore(disabled, "access", "secret"); err == nil {
		t.Fatal("disabled recovery store opened")
	}
	if _, err := NewRecoveryStore(ExecutionConfig{Version: 2}, "access", "secret"); err == nil {
		t.Fatal("invalid recovery-store configuration accepted")
	}
	enabled := ExecutionConfig{Version: 1, Enabled: true, InstallRoot: "/opt/setjoin", RecoveryProvider: "s3", RecoveryEndpoint: "backup.test:9000", RecoveryBucket: "setjoin-backup"}
	if _, err := NewRecoveryStore(enabled, "", "secret"); err == nil {
		t.Fatal("empty access key accepted")
	}
	if _, err := NewRecoveryStore(enabled, "access", "bad\nsecret"); err == nil {
		t.Fatal("control byte in secret accepted")
	}
	endpoint, secure, err := normalizeRecoveryEndpoint("http://127.0.0.1:9000")
	if err != nil || endpoint != "127.0.0.1:9000" || secure {
		t.Fatalf("endpoint=%q secure=%t err=%v", endpoint, secure, err)
	}
	endpoint, secure, err = normalizeRecoveryEndpoint("backup.example.test")
	if err != nil || endpoint != "backup.example.test" || !secure {
		t.Fatalf("bare endpoint=%q secure=%t err=%v", endpoint, secure, err)
	}
	// Loopback cleartext stays accepted (the supported on-host SeaweedFS case).
	for _, loopback := range []string{"http://127.0.0.1:9000", "http://localhost:9000", "http://[::1]:9000"} {
		if _, sec, err := normalizeRecoveryEndpoint(loopback); err != nil || sec {
			t.Fatalf("loopback endpoint %q rejected: secure=%t err=%v", loopback, sec, err)
		}
	}
	// Cleartext http:// to any non-loopback host is rejected
	// (D-MAILSERVER-CMD-SETJOIN-UPDATER-P2-001): the recovery envelope is
	// HMAC-authenticated but not confidential, and the loopback-only rule
	// mirrors the appmarket insecure-transport posture.
	for _, cleartext := range []string{"http://backup.example.test", "http://10.0.0.8:9000", "HTTP://LOCALHOST.TEST:9000"} {
		if _, _, err := normalizeRecoveryEndpoint(cleartext); err == nil {
			t.Fatalf("non-loopback cleartext endpoint %q accepted", cleartext)
		}
	}
	for _, invalid := range []string{"", "bad\nendpoint", strings.Repeat("a", 2049), "bare/path", "https://backup.test?query=1", "https://backup.test#fragment"} {
		if _, _, err := normalizeRecoveryEndpoint(invalid); err == nil {
			t.Fatalf("invalid endpoint %q accepted", invalid)
		}
	}
	store, err := NewRecoveryStore(enabled, "access", "secret")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if _, err := store.HeadObject(ctx, "missing"); err == nil {
		t.Fatal("unreachable recovery store head accepted")
	}
	object, err := store.GetObject(context.Background(), "missing")
	if err != nil || object == nil {
		t.Fatalf("construct bounded recovery object reader: object=%T err=%v", object, err)
	}
	if err := object.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestValidateDistinctDatabaseCredentials(t *testing.T) {
	control := "postgres://setjoin_updater:control@127.0.0.1:5432/mailserver"
	owner := "postgres://setjoin_owner:owner@127.0.0.1:5432/mailserver"
	if err := ValidateDistinctDatabaseCredentials(control, owner); err != nil {
		t.Fatal(err)
	}
	for _, pair := range [][2]string{
		{"postgres://wrong:control@127.0.0.1/db", owner},
		{control, control},
		{control, "postgres://setjoin_updater:other@127.0.0.1/db"},
		{"not-a-dsn", owner},
		{control, "://not-a-dsn"},
	} {
		if err := ValidateDistinctDatabaseCredentials(pair[0], pair[1]); err == nil {
			t.Fatalf("credential pair accepted: %#v", pair)
		}
	}
}
