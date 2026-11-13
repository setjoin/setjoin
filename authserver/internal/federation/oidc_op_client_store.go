package federation

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
	"golang.org/x/crypto/bcrypt"
)

// oidcClientStore owns every read of the oidc_clients table for the OP. It is
// the one place an OIDC client is loaded and its secret verified, so client
// lookup and client authentication cannot drift apart (Wave 3 split of the
// OPStorage god-object). The zitadel op.Storage methods on OPStorage delegate
// to it verbatim, preserving behavior.
type oidcClientStore struct {
	pool *pgxpool.Pool
}

func newOIDCClientStore(pool *pgxpool.Pool) *oidcClientStore {
	return &oidcClientStore{pool: pool}
}

// getClient loads an enabled client by id, returning the op.Client adapter.
// A missing or disabled client is an error (the zitadel layer maps it to the
// appropriate OAuth error to the caller).
func (s *oidcClientStore) getClient(ctx context.Context, clientID string) (op.Client, error) {
	var c storedClient
	err := s.pool.QueryRow(ctx,
		`SELECT id, name, secret, redirect_uris, grant_types, scopes, enabled,
		        COALESCE(client_type, 'confidential')
		 FROM oidc_clients WHERE id = $1`, clientID,
	).Scan(&c.id, &c.name, &c.secretHash, &c.redirectURIs, &c.grantTypes, &c.scopes, &c.enabled, &c.clientType)
	if err != nil {
		return nil, fmt.Errorf("client not found: %s", clientID)
	}
	if !c.enabled {
		return nil, fmt.Errorf("client disabled: %s", clientID)
	}
	c.preComputeGrants()
	return &c, nil
}

// authorize verifies a client's secret (bcrypt) against the enabled row,
// returning the zitadel invalid-client error on any mismatch so the OP surfaces
// a uniform failure.
func (s *oidcClientStore) authorize(ctx context.Context, clientID, clientSecret string) error {
	var hash string
	err := s.pool.QueryRow(ctx,
		`SELECT secret FROM oidc_clients WHERE id = $1 AND enabled = TRUE`, clientID,
	).Scan(&hash)
	if err != nil {
		return oidc.ErrInvalidClient()
	}
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(clientSecret)); err != nil {
		return oidc.ErrInvalidClient()
	}
	return nil
}
