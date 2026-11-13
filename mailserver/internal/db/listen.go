// Package db preserves the mailserver-local name for the shared PostgreSQL
// LISTEN/NOTIFY implementation. New cross-binary consumers should import
// setjoin.com/shared/pgnotify directly.
package db

import (
	"log/slog"

	"github.com/jackc/pgx/v5"
	"setjoin.com/shared/pgnotify"
)

type Listener = pgnotify.Listener
type NotifyHandler = pgnotify.NotifyHandler

// NewListener preserves the mailserver-local constructor while delegating all
// behavior to the shared implementation.
func NewListener(conn *pgx.Conn, logger *slog.Logger) *Listener {
	return pgnotify.NewListener(conn, logger)
}
