package token

import (
	"context"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
)

// IntrospectResponse is the RFC 7662 token introspection response.
//
// Per RFC 7662 §2.2, token_type is the *type of the token* (a Bearer token),
// not the internal access/refresh/app_password discriminator stored in
// oauth_tokens. iat/nbf/exp are seconds-since-epoch; iss/aud/sub/username/scope
// describe the bearer. Every field except active is omitempty so an inactive
// response is the bare {"active":false} an RFC 7662 caller expects — never an
// error oracle.
type IntrospectResponse struct {
	Active bool `json:"active"`
	// Scope is a space-separated list (RFC 7662 §2.2: the OPTIONAL "scope"
	// member is a JSON *string* of space-separated scope values, mirroring
	// RFC 6749 §3.3 — not a JSON array).
	Scope     string `json:"scope,omitempty"`
	ClientID  string `json:"client_id,omitempty"`
	Username  string `json:"username,omitempty"`
	TokenType string `json:"token_type,omitempty"`
	Exp       int64  `json:"exp,omitempty"`
	Iat       int64  `json:"iat,omitempty"`
	Nbf       int64  `json:"nbf,omitempty"`
	Sub       string `json:"sub,omitempty"`
	Aud       string `json:"aud,omitempty"`
	Iss       string `json:"iss,omitempty"`

	// Email mirrors username for backward compatibility with existing callers
	// that read the email field; new callers should use username (RFC 7662).
	Email string `json:"email,omitempty"`
}

// IntrospectOptions carries the issuer/audience the auth server stamps into
// the tokens it mints, so the introspection response can report a truthful
// iss/aud per RFC 7662 §2.2 without the token package reaching for globals.
type IntrospectOptions struct {
	Issuer   string
	Audience string
}

// Introspect validates a token against the oauth_tokens table and returns the
// RFC 7662 field set. Called by the mail gateway's IMAP/SMTP AUTH handlers and
// the HTTP introspection endpoint. An unknown, revoked, or expired token yields
// {active:false} with no other fields (no error oracle).
func Introspect(ctx context.Context, pool *pgxpool.Pool, token string, opts IntrospectOptions) (*IntrospectResponse, error) {
	hash := tokenHash(token)

	var (
		userID    int64
		email     string
		clientID  *string
		scope     []string
		issuedAt  *int64
		expiresAt *int64
	)

	err := pool.QueryRow(ctx,
		`SELECT o.user_id, u.email, o.client_id, coalesce(o.scope, '{}'),
		        extract(epoch FROM o.issued_at)::bigint,
		        extract(epoch FROM o.expires_at)::bigint
		 FROM oauth_tokens o JOIN users u ON u.id = o.user_id AND u.enabled = TRUE
		 WHERE o.token_hash = $1 AND o.revoked_at IS NULL
		 AND (o.expires_at IS NULL OR o.expires_at > now())`,
		hash,
	).Scan(&userID, &email, &clientID, &scope, &issuedAt, &expiresAt)
	if err != nil {
		// Unknown/revoked/expired/disabled — uniform inactive response.
		return &IntrospectResponse{Active: false}, nil
	}

	resp := &IntrospectResponse{
		Active:   true,
		Sub:      fmt.Sprint(userID),
		Username: email,
		Email:    email,
		// RFC 7662 §2.2: scope is a single space-delimited string, not an array.
		Scope:     strings.Join(scope, " "),
		TokenType: "Bearer",
		Iss:       opts.Issuer,
		Aud:       opts.Audience,
	}
	if clientID != nil {
		resp.ClientID = *clientID
	}
	if issuedAt != nil {
		resp.Iat = *issuedAt
		resp.Nbf = *issuedAt // valid from issuance; no separate not-before is stored
	}
	if expiresAt != nil {
		resp.Exp = *expiresAt
	}
	return resp, nil
}
