// Package directorysync owns the protocol-neutral normalized directory-sync
// engine. Protocol adapters keep transport, cursor, and directory-specific
// validation details in their owning packages.
package directorysync

import (
	"context"
	"encoding/json"

	"github.com/google/uuid"
	"setjoin.com/mailserver/internal/identitysource"
)

// Object is one connector-neutral directory object. RelationKey and
// ManagerRelationKey must already be normalized by the adapter; the engine
// treats them as opaque map keys.
type Object struct {
	Subject            string
	RelationKey        string
	ManagerRelationKey string
	ManagerSubject     string
	Email              string
	DisplayName        string
	FirstName          string
	LastName           string
	JobTitle           string
	Phone              string
	Department         string
	UPN                string
	Disabled           bool
	// Tombstone attests an explicit upstream deletion marker observed by the
	// connector (replicated tombstone, delete event, or equivalent
	// protocol-level deletion evidence). It is the ONLY deletion authority
	// this engine accepts besides a future store-side full-reconciliation
	// janitor: connectors set it exclusively from upstream tombstone
	// evidence, never from enumeration absence. A tombstoned object
	// propagates as disable-first revocation and may omit mail and profile
	// fields, which upstream deletion commonly scrubs.
	Tombstone   bool
	CursorValue string
}

// Cursor is an opaque committed connector position.
type Cursor interface {
	Encode() (json.RawMessage, error)
}

// Connector adapts one directory protocol to the normalized engine.
type Connector interface {
	Label() string
	Preflight() error
	DecodeCursor(json.RawMessage) (Cursor, error)
	Fetch(context.Context, Cursor) ([]Object, Cursor, error)
	ValidateObject(Object, bool) error
}

// PageStore is the database-owned normalized inbox/cursor surface used by the
// engine. *identitysource.Store satisfies it.
type PageStore interface {
	SourceByKey(context.Context, string) (identitysource.Source, error)
	AcquireLease(context.Context, identitysource.Source, uuid.UUID) (bool, error)
	ReleaseLease(context.Context, identitysource.Source, uuid.UUID) error
	ResumeUnfinished(context.Context, identitysource.Source, uuid.UUID) (identitysource.RecoveryResult, error)
	ApplyPage(context.Context, identitysource.Source, identitysource.Page, uuid.UUID) (identitysource.FinishResult, error)
}
