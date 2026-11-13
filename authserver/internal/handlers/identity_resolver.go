package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"

	"github.com/jackc/pgx/v5"

	"setjoin.com/shared/toggle"
)

var errNormalizedIdentityResolution = errors.New("normalized identity resolution failed")

// identityKeys is the bundle of identifiers an inbound SSO assertion can carry
// for a single person: the OIDC stable identity (sub+iss), the SAML stable
// identity (NameID + IdP entity ID), and the email/subject claim. It is the input
// to the SP-mode resolution cascade — exactly the values lookupOrJITUser already
// received as positional parameters, now named so the resolver seam can take one
// argument instead of five.
type identityKeys struct {
	email      string
	oidcSub    string
	oidcIss    string
	samlNameID string
	samlIDP    string
}

// hasOIDC reports whether a usable OIDC stable identity is present.
func (k identityKeys) hasOIDC() bool { return k.oidcSub != "" && k.oidcIss != "" }

// hasSAML reports whether a usable SAML stable identity is present.
func (k identityKeys) hasSAML() bool { return k.samlNameID != "" && k.samlIDP != "" }

// resolveSource names which leg of the cascade matched an existing person. The
// caller (lookupOrJITUser) uses it to replay the per-source side effect that has
// always followed a hit — an SSO-email refresh after a stable-ID match, or a
// stable-ID link after an address match — so the resolver stays side-effect-free
// while the observable behavior is byte-for-byte unchanged.
type resolveSource int

const (
	// resolveNone means no existing person matched (the caller proceeds to JIT).
	resolveNone resolveSource = iota
	// resolveOIDC: matched by the OIDC stable identity (sub+iss).
	resolveOIDC
	// resolveSAML: matched by the SAML stable identity (NameID + IdP entity ID).
	resolveSAML
	// resolveAddress: matched by the resolve_identity address seam (ADR-004) —
	// users.email ∪ aliases.email ∪ users.ad_upn, case-insensitive.
	resolveAddress
	// resolveNormalizedNone means the selected source is serving normalized
	// reads but the exact subject is unknown. Address auto-linking is forbidden;
	// an enabled JIT flow may create through the atomic normalized reducer.
	resolveNormalizedNone
)

// IdentityResolver encapsulates the SP-mode "is this assertion an existing
// person?" cascade behind one fake-able seam. ResolveExisting runs the EXACT
// existing priority order — OIDC stable identity → SAML stable identity →
// address (resolve_identity / ADR-004) — and returns the canonical userRow plus
// the leg that matched, or (nil, resolveNone, err) when no existing person is
// found. It performs NO mutation: linking, SSO-email refresh, token issuance and
// group-mapping all remain the caller's job, so the same-mailbox / org-scope
// rules (ADR-004) and the resolution semantics are unchanged — this is a pure
// extraction of the read cascade for testability.
type IdentityResolver interface {
	ResolveExisting(ctx context.Context, keys identityKeys) (*userRow, resolveSource, error)
}

// dbIdentityResolver is the production IdentityResolver, backed by the shared
// *deps DB helpers. It runs the same three lookups lookupOrJITUser ran inline
// (lookupUserByOIDC → lookupUserBySAML → resolveUserByAddress), in the same
// order, with the same short-circuit-on-first-hit behavior.
type dbIdentityResolver struct{ *deps }

// ResolveExisting implements IdentityResolver with the unchanged cascade order.
// The address leg's error (when no stable-ID matched and no address resolves) is
// returned so the caller logs/handles it exactly as before — it is the signal to
// JIT-provision.
func (r dbIdentityResolver) ResolveExisting(ctx context.Context, keys identityKeys) (*userRow, resolveSource, error) {
	var shadowKind, shadowProvider, shadowSubject string
	var shadowEvidence normalizedIdentityShadowEvidence
	if r.toggles != nil && r.toggles.IsEnabled(toggle.FeatureIdentityModelV2) {
		if keys.hasOIDC() {
			user, found, serve, evidence, err := r.resolveNormalized(
				ctx, "oidc", keys.oidcIss, keys.oidcSub,
			)
			if err != nil {
				return nil, resolveNone, fmt.Errorf("%w: %v", errNormalizedIdentityResolution, err)
			}
			if serve {
				if found {
					return user, resolveOIDC, nil
				}
				return nil, resolveNormalizedNone, nil
			}
			if evidence.SourceID > 0 {
				shadowKind, shadowProvider, shadowSubject =
					"oidc", keys.oidcIss, keys.oidcSub
				shadowEvidence = evidence
			}
		}
		if keys.hasSAML() {
			user, found, serve, evidence, err := r.resolveNormalized(
				ctx, "saml", keys.samlIDP, keys.samlNameID,
			)
			if err != nil {
				return nil, resolveNone, fmt.Errorf("%w: %v", errNormalizedIdentityResolution, err)
			}
			if serve {
				if found {
					return user, resolveSAML, nil
				}
				return nil, resolveNormalizedNone, nil
			}
			if shadowKind == "" && evidence.SourceID > 0 {
				shadowKind, shadowProvider, shadowSubject =
					"saml", keys.samlIDP, keys.samlNameID
				shadowEvidence = evidence
			}
		}
	}

	// 1. OIDC stable ID lookup.
	if keys.hasOIDC() {
		user, err := r.lookupUserByOIDC(ctx, keys.oidcSub, keys.oidcIss)
		if err == nil {
			r.observeAuthShadow(
				ctx, shadowKind, shadowProvider, shadowSubject,
				shadowEvidence, user,
			)
			return user, resolveOIDC, nil
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return nil, resolveNone, err
		}
	}

	// 2. SAML stable ID lookup.
	if keys.hasSAML() {
		user, err := r.lookupUserBySAML(ctx, keys.samlNameID, keys.samlIDP)
		if err == nil {
			r.observeAuthShadow(
				ctx, shadowKind, shadowProvider, shadowSubject,
				shadowEvidence, user,
			)
			return user, resolveSAML, nil
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return nil, resolveNone, err
		}
	}

	// 3. Address lookup (the resolve_identity seam, ADR-004): match the inbound
	//    assertion subject against the person's FULL address set — users.email ∪
	//    aliases.email ∪ users.ad_upn, case-insensitive — not the primary SMTP
	//    address alone. Resolution comes BEFORE JIT. The error here is the
	//    no-existing-person signal the caller turns into JIT provisioning.
	user, err := r.resolveUserByAddress(ctx, keys.email)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			r.observeAuthShadow(
				ctx, shadowKind, shadowProvider, shadowSubject,
				shadowEvidence, nil,
			)
		}
		return nil, resolveNone, err
	}
	r.observeAuthShadow(
		ctx, shadowKind, shadowProvider, shadowSubject, shadowEvidence, user,
	)
	return user, resolveAddress, nil
}

type normalizedIdentityShadowEvidence struct {
	SourceID         int64
	SourceGeneration int64
	LinkID           int64
	LinkGeneration   int64
	UserID           int64
}

func (r dbIdentityResolver) resolveNormalized(
	ctx context.Context,
	kind, provider, subject string,
) (*userRow, bool, bool, normalizedIdentityShadowEvidence, error) {
	var raw []byte
	if err := r.workerPool.QueryRow(ctx,
		`SELECT identity_auth_resolve($1,$2,$3)`,
		kind, provider, subject,
	).Scan(&raw); err != nil {
		return nil, false, false, normalizedIdentityShadowEvidence{}, err
	}
	user, found, serve, err := parseNormalizedIdentityResolution(
		raw, func(userID int64) (*userRow, error) {
			return r.lookupUser(ctx, "id", userID)
		})
	if err != nil {
		return nil, false, false, normalizedIdentityShadowEvidence{}, err
	}
	var wire normalizedIdentityResolution
	if err := json.Unmarshal(raw, &wire); err != nil {
		return nil, false, false, normalizedIdentityShadowEvidence{}, err
	}
	evidence, err := parseNormalizedIdentityShadowEvidence(wire)
	if err != nil {
		return nil, false, false, normalizedIdentityShadowEvidence{}, err
	}
	if found {
		evidence.UserID = user.ID
		evidence.LinkID = user.IdentityLinkID
		evidence.LinkGeneration = user.IdentityLinkGeneration
	}
	return user, found, serve, evidence, nil
}

func parseNormalizedIdentityShadowEvidence(
	wire normalizedIdentityResolution,
) (normalizedIdentityShadowEvidence, error) {
	evidence := normalizedIdentityShadowEvidence{}
	var err error
	if wire.SourceID != "" {
		evidence.SourceID, err = strconv.ParseInt(wire.SourceID, 10, 64)
		if err != nil || evidence.SourceID <= 0 {
			return normalizedIdentityShadowEvidence{},
				errors.New("normalized identity source id is invalid")
		}
		evidence.SourceGeneration, err = strconv.ParseInt(
			wire.SourceGeneration, 10, 64,
		)
		if err != nil || evidence.SourceGeneration <= 0 {
			return normalizedIdentityShadowEvidence{},
				errors.New("normalized identity source generation is invalid")
		}
	}
	return evidence, nil
}

func (r dbIdentityResolver) observeAuthShadow(
	ctx context.Context,
	kind, provider, subject string,
	evidence normalizedIdentityShadowEvidence,
	legacyUser *userRow,
) {
	if kind == "" || evidence.SourceID <= 0 {
		return
	}
	var linkID, linkGeneration, normalizedUserID, legacyUserID any
	if evidence.LinkID > 0 {
		linkID = evidence.LinkID
		linkGeneration = evidence.LinkGeneration
		normalizedUserID = evidence.UserID
	}
	if legacyUser != nil {
		legacyUserID = legacyUser.ID
	}
	var raw []byte
	err := r.workerPool.QueryRow(ctx, `
		SELECT identity_auth_shadow_observe(
			$1,$2,$3,$4,$5,$6,$7,$8,$9
		)`,
		kind, provider, subject,
		evidence.SourceID, evidence.SourceGeneration,
		linkID, linkGeneration, normalizedUserID, legacyUserID,
	).Scan(&raw)
	if err != nil && r.logger != nil {
		r.logger.Warn("normalized identity shadow observation failed",
			"kind", kind, "error", err)
	}
}

type normalizedIdentityResolution struct {
	Found            bool   `json:"found"`
	UserID           string `json:"userId"`
	Serve            bool   `json:"serveNormalized"`
	SourceID         string `json:"sourceId"`
	SourceGeneration string `json:"sourceGeneration"`
	LinkID           string `json:"linkId"`
	LinkGeneration   string `json:"linkGeneration"`
}

func parseNormalizedIdentityResolution(
	raw []byte,
	lookup func(int64) (*userRow, error),
) (*userRow, bool, bool, error) {
	var result normalizedIdentityResolution
	if err := json.Unmarshal(raw, &result); err != nil {
		return nil, false, false, err
	}
	if !result.Found {
		return nil, false, result.Serve, nil
	}
	userID, err := strconv.ParseInt(result.UserID, 10, 64)
	if err != nil {
		return nil, false, result.Serve, err
	}
	user, err := lookup(userID)
	if err != nil {
		return nil, false, result.Serve, err
	}
	user.IdentitySourceID, err = strconv.ParseInt(result.SourceID, 10, 64)
	if err != nil {
		return nil, false, result.Serve, err
	}
	user.IdentitySourceGeneration, err = strconv.ParseInt(
		result.SourceGeneration, 10, 64,
	)
	if err != nil {
		return nil, false, result.Serve, err
	}
	user.IdentityLinkID, err = strconv.ParseInt(result.LinkID, 10, 64)
	if err != nil {
		return nil, false, result.Serve, err
	}
	user.IdentityLinkGeneration, err = strconv.ParseInt(
		result.LinkGeneration, 10, 64,
	)
	if err != nil {
		return nil, false, result.Serve, err
	}
	return user, true, result.Serve, nil
}
