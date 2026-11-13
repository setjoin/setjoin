package handlers

import (
	"context"
	"net/http"

	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"
)

// clientCredentials carries an OAuth client's id+secret extracted from a
// request per RFC 6749 §2.3.1 (HTTP Basic preferred; form body fallback).
type clientCredentials struct {
	id     string
	secret string
	// present reports whether any client credential was supplied at all.
	present bool
}

// extractClientCredentials pulls client_id/client_secret from a request using
// the two transports RFC 7662 §2.1 / RFC 7009 §2.1 reference: HTTP Basic
// (preferred) then the request body (client_secret_post). It does NOT validate
// them — that is authenticateClient's job. It assumes r.ParseForm has already
// run so body parameters are available.
func extractClientCredentials(r *http.Request) clientCredentials {
	if id, secret, ok := r.BasicAuth(); ok {
		return clientCredentials{id: id, secret: secret, present: true}
	}
	id := r.PostFormValue("client_id")
	secret := r.PostFormValue("client_secret")
	if id != "" || secret != "" {
		return clientCredentials{id: id, secret: secret, present: true}
	}
	return clientCredentials{}
}

// authenticateClient verifies an OAuth client's credentials against the
// oidc_clients table (bcrypt secret), returning true only for an enabled client
// whose secret matches. It is constant-failure: an unknown client_id still runs
// a bcrypt comparison against a dummy hash so the response time does not reveal
// whether the client exists.
func authenticateClient(ctx context.Context, pool *pgxpool.Pool, creds clientCredentials) bool {
	if !creds.present || creds.id == "" {
		return false
	}
	var hash string
	err := pool.QueryRow(ctx,
		`SELECT secret FROM oidc_clients WHERE id = $1 AND enabled = TRUE`, creds.id,
	).Scan(&hash)
	if err != nil {
		// Unknown/disabled client: still spend a bcrypt comparison to avoid a
		// timing oracle on client existence.
		_ = bcrypt.CompareHashAndPassword(dummyBcryptHash, []byte(creds.secret))
		return false
	}
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(creds.secret)) == nil
}

// dummyBcryptHash is a valid bcrypt hash of a random value, used to equalize
// timing for unknown-client lookups (cost 10, matching the default).
var dummyBcryptHash = []byte("$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy")
