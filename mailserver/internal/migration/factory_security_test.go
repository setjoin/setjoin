package migration

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"

	"setjoin.com/shared/testsupport"
)

func TestFactoriesPreserveAdministratorPrivateNetworkPolicy(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	o := NewOrchestrator(pool, nil, "", "factory-security-root", logger, ctx, nil)

	var oldIMAP json.RawMessage
	var hadIMAP bool
	if err := pool.QueryRow(ctx, `SELECT value FROM system_config WHERE key='imap.defaults'`).Scan(&oldIMAP); err == nil {
		hadIMAP = true
	}
	t.Cleanup(func() {
		if hadIMAP {
			_, _ = pool.Exec(ctx, `INSERT INTO system_config(key,value,encrypted) VALUES('imap.defaults',$1,false) ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value, encrypted=false`, oldIMAP)
		} else {
			_, _ = pool.Exec(ctx, `DELETE FROM system_config WHERE key='imap.defaults'`)
		}
	})
	imapDefaults, _ := json.Marshal(GlobalIMAPConfig{Host: "imap.internal", Port: 993, TLSMode: "tls", PrivateHosts: []string{"imap.internal"}, PrivateCIDRs: []string{"10.0.0.0/8"}})
	if _, err := pool.Exec(ctx, `INSERT INTO system_config(key,value,encrypted) VALUES('imap.defaults',$1,false) ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value, encrypted=false`, imapDefaults); err != nil {
		t.Fatal(err)
	}
	merged, err := (imapFactory{o}).merge(&MigrationJobConfig{})
	if err != nil {
		t.Fatal(err)
	}
	imapConfig := merged.(*IMAPConfig)
	if len(imapConfig.PrivateHosts) != 1 || len(imapConfig.PrivateCIDRs) != 1 {
		t.Fatalf("IMAP private policy lost: %+v", imapConfig)
	}

	var oldEWS json.RawMessage
	var oldEWSEncrypted bool
	var hadEWS bool
	if err := pool.QueryRow(ctx, `SELECT value, encrypted FROM system_config WHERE key='ews.global'`).Scan(&oldEWS, &oldEWSEncrypted); err == nil {
		hadEWS = true
	}
	t.Cleanup(func() {
		if hadEWS {
			_, _ = pool.Exec(ctx, `INSERT INTO system_config(key,value,encrypted) VALUES('ews.global',$1,$2) ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value, encrypted=EXCLUDED.encrypted`, oldEWS, oldEWSEncrypted)
		} else {
			_, _ = pool.Exec(ctx, `DELETE FROM system_config WHERE key='ews.global'`)
		}
	})
	systemKey, _ := DeriveKey(o.encryptionRoot, "system")
	global := GlobalEWSConfig{ServerURL: "https://exchange.internal/EWS/Exchange.asmx", PrivateHosts: []string{"exchange.internal"}, PrivateCIDRs: []string{"10.0.0.0/8"}}
	encryptedGlobal, err := EncryptConfigAny(global, systemKey)
	if err != nil {
		t.Fatal(err)
	}
	wrapper, _ := json.Marshal(map[string]string{"_enc": base64.StdEncoding.EncodeToString(encryptedGlobal)})
	if _, err := pool.Exec(ctx, `INSERT INTO system_config(key,value,encrypted) VALUES('ews.global',$1,true) ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value, encrypted=true`, wrapper); err != nil {
		t.Fatal(err)
	}
	mergedEWS, err := (ewsFactory{o}).merge(&MigrationJobConfig{SelfService: CredentialProvenance(false)})
	if err != nil {
		t.Fatal(err)
	}
	ewsConfig := mergedEWS.(*EWSConfig)
	if len(ewsConfig.PrivateHosts) != 1 || len(ewsConfig.PrivateCIDRs) != 1 {
		t.Fatalf("EWS private policy lost: %+v", ewsConfig)
	}
}

// TestEWSFactoryRejectsInvalidPrivateNetworkPolicy pins the private-network
// policy gates in ewsFactory.Create. Since the bare-path containment
// (RejectUserSuppliedPrivatePolicy) the ownership gate runs FIRST on the
// non-global path — every per-job policy is caller-manufactured there, so it
// is rejected before it can even be compiled. The compile check ("invalid EWS
// source policy") still guards the ADMIN-owned policy donated by the global
// profile on the global path.
func TestEWSFactoryRejectsInvalidPrivateNetworkPolicy(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()
	o := NewOrchestrator(pool, nil, "", "factory-security-root", slog.New(slog.NewTextHandler(io.Discard, nil)), ctx, nil)

	// Bare path: a user-manufactured policy — even a malformed one — is
	// rejected as ownership violation before compilation.
	bare, err := EncryptConfigAny(MigrationJobConfig{
		SourceType:    "ews",
		UseGlobalAuth: false,
		SelfService:   CredentialProvenance(true),
		EWS: &MigrationEWSConfig{
			ServerURL:    "https://exchange.example/EWS/Exchange.asmx",
			PrivateCIDRs: []string{"not-a-cidr"},
		},
	}, o.encryptionKey)
	if err != nil {
		t.Fatal(err)
	}
	_, err = (ewsFactory{o}).Create(ctx, 1, bare, false)
	if !errors.Is(err, ErrUserSuppliedPrivatePolicy) {
		t.Fatalf("bare-path user-manufactured policy err = %v, want ErrUserSuppliedPrivatePolicy", err)
	}

	// Global path: the compile check still validates the ADMIN-owned policy
	// donated by the global profile.
	seedEWSGlobalConfig(t, pool, o, GlobalEWSConfig{
		ServerURL:    "https://exchange.example/EWS/Exchange.asmx",
		PrivateCIDRs: []string{"not-a-cidr"},
	})
	globalJob, err := EncryptConfigAny(MigrationJobConfig{
		SourceType:    "ews",
		UseGlobalAuth: true,
		SelfService:   CredentialProvenance(true),
		EWS:           &MigrationEWSConfig{Username: "alice@corp.example", Password: "pw"},
	}, o.encryptionKey)
	if err != nil {
		t.Fatal(err)
	}
	_, err = (ewsFactory{o}).Create(ctx, 1, globalJob, true)
	if err == nil || !strings.Contains(err.Error(), "invalid EWS source policy") {
		t.Fatalf("global-path invalid admin policy err = %v, want invalid EWS source policy", err)
	}
}
