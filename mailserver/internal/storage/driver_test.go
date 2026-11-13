package storage

import (
	"testing"
)

func TestNewDriver_DefaultProvider(t *testing.T) {
	d, err := NewDriver(DriverConfig{
		Endpoint:  "http://localhost:9000",
		Bucket:    "test",
		AccessKey: "k",
		SecretKey: "s",
	})
	if err != nil {
		t.Fatalf("NewDriver: %v", err)
	}
	if d.ProviderName() != "s3" {
		t.Errorf("default provider = %q, want s3", d.ProviderName())
	}
}

func TestNewDriver_ExplicitS3(t *testing.T) {
	d, err := NewDriver(DriverConfig{
		Provider:  "s3",
		Endpoint:  "https://s3.us-east-1.amazonaws.com",
		Bucket:    "test",
		AccessKey: "k",
		SecretKey: "s",
	})
	if err != nil {
		t.Fatalf("NewDriver(s3): %v", err)
	}
	if d.ProviderName() != "s3" {
		t.Errorf("ProviderName = %q, want s3", d.ProviderName())
	}
}

func TestNewDriver_UsesEndpoint(t *testing.T) {
	endpoint := "https://s3.custom.example.com"
	d, err := NewDriver(DriverConfig{
		Endpoint:  endpoint,
		Bucket:    "test",
		AccessKey: "k",
		SecretKey: "s",
	})
	if err != nil {
		t.Fatalf("NewDriver: %v", err)
	}
	if d.Endpoint() != endpoint {
		t.Errorf("Endpoint = %q, want %q", d.Endpoint(), endpoint)
	}
}

func TestNewDriver_OSSProvider(t *testing.T) {
	d, err := NewDriver(DriverConfig{
		Provider:  "oss",
		Endpoint:  "https://oss-cn-hangzhou.aliyuncs.com",
		Bucket:    "test",
		AccessKey: "k",
		SecretKey: "s",
	})
	if err != nil {
		t.Fatalf("NewDriver(oss): %v", err)
	}
	if d.ProviderName() != "oss" {
		t.Errorf("ProviderName = %q, want oss", d.ProviderName())
	}
}

func TestS3Driver_ImplementsInterface(t *testing.T) {
	d, err := NewBackupS3Driver(DriverConfig{
		Endpoint:  "https://s3.amazonaws.com",
		Bucket:    "test",
		AccessKey: "k",
		SecretKey: "s",
	})
	if err != nil {
		t.Fatalf("NewBackupS3Driver: %v", err)
	}
	// Compile-time check: d must satisfy Driver
	var _ Driver = d
}

func TestS3Driver_EmptyRegionDefaults(t *testing.T) {
	d, err := NewBackupS3Driver(DriverConfig{
		Endpoint:  "https://s3.us-west-2.amazonaws.com",
		Bucket:    "test",
		AccessKey: "k",
		SecretKey: "s",
	})
	if err != nil {
		t.Fatalf("NewBackupS3Driver with empty region: %v", err)
	}
	if d.Endpoint() == "" {
		t.Error("endpoint should not be empty")
	}
}

func TestDriverConfig_ObjectLock(t *testing.T) {
	cfg := DriverConfig{
		ObjectLockMode:          "governance",
		ObjectLockRetentionDays: 30,
		Bucket:                  "test",
		AccessKey:               "k",
		SecretKey:               "s",
	}
	if cfg.ObjectLockMode != "governance" {
		t.Errorf("ObjectLockMode = %q", cfg.ObjectLockMode)
	}
	if cfg.ObjectLockRetentionDays != 30 {
		t.Errorf("ObjectLockRetentionDays = %d", cfg.ObjectLockRetentionDays)
	}
}

func TestDriverConfig_ObjectLockDefaults(t *testing.T) {
	cfg := DriverConfig{}
	if cfg.ObjectLockMode != "" {
		t.Error("default ObjectLockMode should be empty")
	}
	if cfg.ObjectLockRetentionDays != 0 {
		t.Error("default ObjectLockRetentionDays should be 0")
	}
}
