package migration

import (
	"testing"

	"setjoin.com/mailserver/internal/storage"
)

func TestMigrationStore_SatisfiedByDriver(t *testing.T) {
	d, err := storage.NewDriver(storage.DriverConfig{Provider: "posix", Bucket: t.TempDir()})
	if err != nil {
		t.Fatalf("NewDriver: %v", err)
	}
	var _ MigrationStore = d // subset proof
}
