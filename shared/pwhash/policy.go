package pwhash

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"
	"setjoin.com/shared/validate"
)

// LoadPasswordPolicy reads the org password policy from system_config, applying
// the same defaults everywhere (min length 8, all character classes required).
// Single source of truth for the query: mailserver admin user-create and the
// authserver pre-submit policy endpoint both call this, so the keys/defaults
// can never drift apart. DisallowEmail is left zero for the caller to set.
func LoadPasswordPolicy(ctx context.Context, pool *pgxpool.Pool) (validate.PasswordPolicy, error) {
	var p validate.PasswordPolicy
	err := pool.QueryRow(ctx,
		`SELECT
			COALESCE((SELECT (value->>0)::INT FROM system_config WHERE key = 'password_min_length'), 8),
			COALESCE((SELECT (value->>0)::BOOL FROM system_config WHERE key = 'password_require_uppercase'), true),
			COALESCE((SELECT (value->>0)::BOOL FROM system_config WHERE key = 'password_require_lowercase'), true),
			COALESCE((SELECT (value->>0)::BOOL FROM system_config WHERE key = 'password_require_digit'), true),
			COALESCE((SELECT (value->>0)::BOOL FROM system_config WHERE key = 'password_require_special'), true)`).Scan(
		&p.MinLength, &p.RequireUppercase, &p.RequireLowercase, &p.RequireDigit, &p.RequireSpecial)
	return p, err
}
