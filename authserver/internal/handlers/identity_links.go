package handlers

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"setjoin.com/authserver/internal/federation"
	"setjoin.com/shared/httputil"
	"setjoin.com/shared/identity"
	"setjoin.com/shared/jwtutil"
	"setjoin.com/shared/reducererr"
	"setjoin.com/shared/toggle"
)

const identityLinkFlowCookie = "identity_link_flow"

type identityLinkFlow struct {
	UserID      int64  `json:"userId"`
	Kind        string `json:"kind"`
	ProviderKey string `json:"providerKey"`
	FlowID      string `json:"flowId"`
	SessionJTI  string `json:"sessionJti"`
	SessionHash string `json:"sessionHash"`
	ExpiresAt   int64  `json:"expiresAt"`
}

func (h *loginHandler) identityLinksEnabled(w http.ResponseWriter, r *http.Request) bool {
	if h.toggles == nil ||
		!h.toggles.IsEnabled(toggle.FeatureIdentityModelV2) {
		http.NotFound(w, r)
		return false
	}
	return true
}

func (h *loginHandler) OIDCLink(w http.ResponseWriter, r *http.Request) {
	if !h.identityLinksEnabled(w, r) {
		return
	}
	providerName := r.URL.Query().Get("provider")
	if h.oidcRP == nil || h.oidcRP.Provider(providerName) == nil {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "unknown OIDC provider")
		return
	}
	cfg := h.oidcRP.Provider(providerName)
	if !h.beginIdentityLink(w, r, "oidc", cfg.SSOProviderKey()) {
		return
	}
	h.OIDCLogin(w, r)
}

func (h *loginHandler) SAMLLink(w http.ResponseWriter, r *http.Request) {
	if !h.identityLinksEnabled(w, r) {
		return
	}
	idp := r.PathValue("idp")
	if h.samlSP == nil || h.samlSP.Registration(idp) == nil {
		http.NotFound(w, r)
		return
	}
	reg := h.samlSP.Registration(idp)
	if !h.beginIdentityLink(w, r, "saml", reg.SSOProviderKey()) {
		return
	}
	h.SAMLLogin(w, r)
}

func (h *loginHandler) beginIdentityLink(
	w http.ResponseWriter, r *http.Request, kind, providerKey string,
) bool {
	claims := tokenClaims(r)
	rawToken, err := r.Cookie("access_token")
	if claims == nil || err != nil || rawToken.Value == "" ||
		claims.JTI == "" ||
		!jwtutil.ACRSatisfies(claims.ACR, jwtutil.ACRAAL2) ||
		claims.IssuedAt == nil || time.Since(claims.IssuedAt.Time) > 5*time.Minute {
		httputil.WriteProblemStatus(w, http.StatusForbidden,
			"fresh AAL2 step-up is required before linking")
		return false
	}
	sum := sha256.Sum256([]byte(rawToken.Value))
	flow := identityLinkFlow{
		UserID: claims.UserID, Kind: kind, ProviderKey: providerKey,
		FlowID:      uuid.NewString(),
		SessionJTI:  claims.JTI,
		SessionHash: hex.EncodeToString(sum[:]),
		ExpiresAt:   time.Now().Add(10 * time.Minute).Unix(),
	}
	if h.identityLinkElevationBegin == nil ||
		h.identityLinkElevationBegin(r.Context(), flow, sum[:]) != nil {
		httputil.WriteProblemStatus(w, http.StatusServiceUnavailable,
			"identity link authorization could not start")
		return false
	}
	raw, _ := json.Marshal(flow)
	sealed, err := h.encryptCookieValue(raw)
	if err != nil {
		httputil.WriteProblemStatus(w, http.StatusInternalServerError,
			"identity link flow could not start")
		return false
	}
	http.SetCookie(w, &http.Cookie{
		Name: identityLinkFlowCookie, Value: sealed, Path: "/",
		MaxAge: 600, HttpOnly: true,
		Secure:   h.cookieSecure || r.TLS != nil || h.forwardedHTTPS(r),
		SameSite: http.SameSiteStrictMode,
	})
	return true
}

func (h *loginHandler) consumeIdentityLink(
	w http.ResponseWriter, r *http.Request, kind, providerKey string,
) (identityLinkFlow, bool, bool) {
	cookie, err := r.Cookie(identityLinkFlowCookie)
	if err != nil {
		return identityLinkFlow{}, false, false
	}
	h.clearAuthCookie(w, r, identityLinkFlowCookie, "/")
	raw, err := h.decryptCookieValue(cookie.Value)
	if err != nil {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "invalid identity link flow")
		return identityLinkFlow{}, true, false
	}
	var flow identityLinkFlow
	if json.Unmarshal(raw, &flow) != nil || flow.Kind != kind ||
		flow.ProviderKey != providerKey || flow.FlowID == "" ||
		flow.SessionJTI == "" || flow.ExpiresAt < time.Now().Unix() {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "invalid identity link flow")
		return identityLinkFlow{}, true, false
	}
	access, err := r.Cookie("access_token")
	if err != nil || access.Value == "" {
		httputil.WriteProblemStatus(w, http.StatusUnauthorized, "linking session expired")
		return identityLinkFlow{}, true, false
	}
	sum := sha256.Sum256([]byte(access.Value))
	claims, err := h.jwt.Validate(access.Value)
	if err != nil || claims.Type != jwtutil.TypeAccess || claims.UserID != flow.UserID ||
		hex.EncodeToString(sum[:]) != flow.SessionHash ||
		!jwtutil.ACRSatisfies(claims.ACR, jwtutil.ACRAAL2) ||
		claims.IssuedAt == nil || time.Since(claims.IssuedAt.Time) > 15*time.Minute {
		httputil.WriteProblemStatus(w, http.StatusForbidden, "linking session changed")
		return identityLinkFlow{}, true, false
	}
	var live bool
	if err := h.pool.QueryRow(r.Context(), `
		SELECT EXISTS(
		  SELECT 1 FROM sessions
		   WHERE user_id=$1 AND token_hash=digest($2,'sha256')
		     AND expires_at>statement_timestamp()
		)`, flow.UserID, access.Value).Scan(&live); err != nil || !live {
		httputil.WriteProblemStatus(w, http.StatusUnauthorized, "linking session is no longer active")
		return identityLinkFlow{}, true, false
	}
	return flow, true, true
}

// finalizeFederatedIdentityLink keeps the security-sensitive post-callback
// sequence identical for OIDC and SAML. The link, exact-provider group evidence,
// normalized entitlements, and terminal redirect are one database transaction:
// a mapping/SoD/reconcile failure cannot leave a durable link with partially
// settled access.
func (h *loginHandler) finalizeFederatedIdentityLink(
	w http.ResponseWriter,
	r *http.Request,
	flow identityLinkFlow,
	provider, subject string,
	groups []string,
	mapper federation.GroupMappingProvider,
) bool {
	tx, err := h.workerPool.Begin(r.Context())
	if err != nil {
		httputil.WriteProblemStatus(w, http.StatusServiceUnavailable,
			"identity link transaction unavailable")
		return false
	}
	defer tx.Rollback(r.Context()) //nolint:errcheck -- commit below makes this a no-op.

	sessionHash, err := hex.DecodeString(flow.SessionHash)
	if err != nil || len(sessionHash) != sha256.Size {
		httputil.WriteProblemStatus(w, http.StatusBadRequest,
			"identity link authorization is invalid")
		return false
	}
	var result json.RawMessage
	if err := tx.QueryRow(r.Context(),
		`SELECT identity_auth_link_authorized(
			$1,$1,$2,$3,$4,$5,$6,$7::uuid,$8
		)`,
		flow.UserID, flow.Kind, provider, subject, flow.ProviderKey,
		"authenticated federated account linking", flow.FlowID, sessionHash,
	).Scan(&result); err != nil {
		if !reducererr.WriteClassified(w, r, err) {
			httputil.WriteProblemStatus(w, http.StatusConflict, "identity link failed")
		}
		return false
	}
	if err := h.applyGroupMappingsAtomic(
		r.Context(), tx, flow.UserID, groups, mapper,
	); err != nil {
		h.logger.Warn("atomic identity link group reconciliation failed",
			"kind", flow.Kind, "user_id", flow.UserID, "error", err)
		httputil.WriteProblemStatus(w, http.StatusConflict,
			"identity link entitlement reconciliation failed")
		return false
	}
	if err := h.reconcileSSOEntitlementsAtomic(
		r.Context(), tx, flow.UserID, flow.ProviderKey,
	); err != nil {
		h.logger.Warn("atomic normalized identity link entitlement reconciliation failed",
			"kind", flow.Kind, "user_id", flow.UserID, "error", err)
		httputil.WriteProblemStatus(w, http.StatusConflict,
			"identity link entitlement reconciliation failed")
		return false
	}
	if err := tx.Commit(r.Context()); err != nil {
		h.logger.Warn("atomic identity link commit failed",
			"kind", flow.Kind, "user_id", flow.UserID, "error", err)
		httputil.WriteProblemStatus(w, http.StatusServiceUnavailable,
			"identity link commit failed")
		return false
	}
	http.Redirect(w, r, "/settings?identity=linked", http.StatusSeeOther)
	return true
}

// applyGroupMappingsAtomic is the strict linking variant of applyGroupMappings.
// Ordinary SSO login retains the established best-effort/autocommit behavior;
// explicit account linking instead aborts the enclosing transaction on the first
// mapping error so the newly-created link and its access evidence cannot diverge.
func (h *deps) applyGroupMappingsAtomic(
	ctx context.Context,
	tx pgx.Tx,
	userID int64,
	idpGroups []string,
	mapper federation.GroupMappingProvider,
) error {
	if mapper == nil || idpGroups == nil {
		return nil
	}
	if err := identity.ValidateSSOGroupClaims(idpGroups); err != nil {
		return err
	}
	mappings := mapper.GetGroupMappings()
	if len(mappings) == 0 {
		return nil
	}
	mappingGroups := make([]string, len(mappings))
	for i := range mappings {
		mappingGroups[i] = mappings[i].IDPGroup
	}
	if err := identity.ValidateSSOGroupMappings(mappingGroups); err != nil {
		return err
	}
	providerKey := mapper.SSOProviderKey()
	if !federation.ValidSSOProviderKey(providerKey) {
		return fmt.Errorf("invalid SSO provider key")
	}

	var mailboxID int64
	if err := tx.QueryRow(ctx,
		`SELECT id FROM mailboxes
		  WHERE user_id=$1 AND is_primary=TRUE
		  ORDER BY id LIMIT 1`,
		userID,
	).Scan(&mailboxID); err != nil {
		return fmt.Errorf("load primary mailbox: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		WITH removed AS (
		    DELETE FROM sso_distribution_group_provenance
		     WHERE provider_key=$1 AND mailbox_id=$2
		    RETURNING group_id,mailbox_id
		)
		DELETE FROM distribution_group_members dgm
		 USING removed r
		 WHERE dgm.group_id=r.group_id
		   AND dgm.mailbox_id=r.mailbox_id
		   AND dgm.mailbox_id=$2
		   AND dgm.source='sso'
		   AND NOT EXISTS (
		       SELECT 1 FROM sso_distribution_group_provenance p
		        WHERE p.group_id=dgm.group_id
		          AND p.mailbox_id=dgm.mailbox_id
		          AND p.provider_key<>$1
		   )
		   AND NOT EXISTS (
		       SELECT 1 FROM sso_distribution_group_legacy_inventory legacy
		        WHERE legacy.group_id=dgm.group_id
		          AND legacy.mailbox_id=dgm.mailbox_id
		   )`,
		providerKey, mailboxID,
	); err != nil {
		return fmt.Errorf("remove stale distribution grants: %w", err)
	}

	superAdminStillMapped := false
	for _, mapping := range mappings {
		if mapping.AdminRole != nil &&
			*mapping.AdminRole == "super_admin" &&
			federation.ContainsString(idpGroups, mapping.IDPGroup) {
			superAdminStillMapped = true
			break
		}
	}
	excludeSuper := superAdminStillMapped && h.ssoAllowSuperAdminMapping
	if _, err := tx.Exec(ctx, `
		WITH removed AS (
		    DELETE FROM sso_admin_role_provenance p
		     USING admin_role_assignments ara
		     WHERE p.provider_key=$1
		       AND p.assignment_id=ara.id
		       AND ara.user_id=$2
		       AND NOT (ara.role_group_id=1 AND $3)
		    RETURNING p.assignment_id
		)
		DELETE FROM admin_role_assignments ara
		 USING removed r
		 WHERE ara.id=r.assignment_id
		   AND ara.user_id=$2
		   AND ara.granted_by IS NULL
		   AND NOT EXISTS (
		       SELECT 1 FROM sso_admin_role_provenance p
		        WHERE p.assignment_id=ara.id AND p.provider_key<>$1
		   )
		   AND NOT EXISTS (
		       SELECT 1 FROM sso_admin_role_legacy_inventory legacy
		        WHERE legacy.assignment_id=ara.id
		   )`,
		providerKey, userID, excludeSuper,
	); err != nil {
		return fmt.Errorf("remove stale admin grants: %w", err)
	}

	var departmentID *int64
	for _, mapping := range mappings {
		if !federation.ContainsString(idpGroups, mapping.IDPGroup) {
			continue
		}
		if mapping.DistributionGroupID != nil {
			if _, err := tx.Exec(ctx, `
				WITH effective AS (
				    INSERT INTO distribution_group_members(
				        group_id,mailbox_id,source
				    ) VALUES($1,$2,'sso')
				    ON CONFLICT DO NOTHING
				)
				INSERT INTO sso_distribution_group_provenance(
				    provider_key,group_id,mailbox_id
				)
				SELECT $3,group_id,mailbox_id
				  FROM distribution_group_members
				 WHERE group_id=$1 AND mailbox_id=$2
				ON CONFLICT DO NOTHING`,
				*mapping.DistributionGroupID, mailboxID, providerKey,
			); err != nil {
				return fmt.Errorf("apply distribution grant: %w", err)
			}
		}
		if mapping.AdminRole != nil {
			if *mapping.AdminRole == "super_admin" &&
				!h.ssoAllowSuperAdminMapping {
				h.logger.Warn("SSO admin mapping to super_admin refused during identity linking",
					"user_id", userID)
				continue
			}
			if groupID, ok := adminRoleToGroupID[*mapping.AdminRole]; ok && groupID > 0 {
				if _, err := tx.Exec(ctx, `
					WITH inserted AS (
					    INSERT INTO admin_role_assignments(
					        user_id,role_group_id,granted_by
					    ) VALUES($1,$2,NULL)
					    ON CONFLICT(user_id,role_group_id) DO NOTHING
					    RETURNING id
					), effective AS (
					    SELECT id FROM inserted
					    UNION ALL
					    SELECT id FROM admin_role_assignments
					     WHERE user_id=$1 AND role_group_id=$2
					    LIMIT 1
					)
					INSERT INTO sso_admin_role_provenance(
					    provider_key,assignment_id
					)
					SELECT $3,id FROM effective
					ON CONFLICT DO NOTHING`,
					userID, groupID, providerKey,
				); err != nil {
					return fmt.Errorf("apply admin grant: %w", err)
				}
			}
		}
		if mapping.DepartmentID != nil {
			departmentID = mapping.DepartmentID
		}
	}
	if departmentID != nil {
		if _, err := tx.Exec(ctx,
			`UPDATE users SET department_id=$2 WHERE id=$1`,
			userID, *departmentID,
		); err != nil {
			return fmt.Errorf("apply department mapping: %w", err)
		}
	}
	return nil
}

func (h *deps) reconcileSSOEntitlementsAtomic(
	ctx context.Context,
	tx pgx.Tx,
	userID int64,
	providerKey string,
) error {
	var raw []byte
	if err := tx.QueryRow(ctx,
		`SELECT identity_entitlements_reconcile_sso($1,$2)`,
		userID, providerKey,
	).Scan(&raw); err != nil {
		return err
	}
	var result struct {
		Reconciled bool   `json:"reconciled"`
		Reason     string `json:"reason"`
	}
	if err := json.Unmarshal(raw, &result); err != nil {
		return fmt.Errorf("decode normalized entitlement result: %w", err)
	}
	if !result.Reconciled {
		return fmt.Errorf("normalized entitlement reconciliation refused: %s",
			result.Reason)
	}
	return nil
}

type federatedIdentityLink struct {
	kind, providerKey, provider, subject string
	groups                               []string
	mapper                               federation.GroupMappingProvider
}

// handleFederatedIdentityLink centralizes the callback branch shared by OIDC
// and SAML. A missing flow means this is an ordinary login; any present flow is
// terminal (success or a fail-closed validation/link error).
func (h *loginHandler) handleFederatedIdentityLink(
	w http.ResponseWriter,
	r *http.Request,
	link federatedIdentityLink,
) bool {
	if _, err := r.Cookie(identityLinkFlowCookie); err == nil &&
		(h.toggles == nil ||
			!h.toggles.IsEnabled(toggle.FeatureIdentityModelV2)) {
		h.clearAuthCookie(w, r, identityLinkFlowCookie, "/")
		http.NotFound(w, r)
		return true
	}
	flow, attempted, valid := h.consumeIdentityLink(w, r, link.kind, link.providerKey)
	if !attempted {
		return false
	}
	if valid {
		h.finalizeFederatedIdentityLink(w, r, flow, link.provider, link.subject, link.groups, link.mapper)
	}
	return true
}

func (h *loginHandler) rejectFederatedGroupError(
	w http.ResponseWriter, r *http.Request, protocol string, err error,
) bool {
	if err == nil {
		return false
	}
	h.logger.Error(protocol+" group extraction failed", "error", err)
	httputil.WriteProblem(w, r, &httputil.Problem{
		Status: http.StatusUnauthorized, Detail: "invalid " + protocol + " group assertion",
	})
	return true
}

func (h *loginHandler) completeFederatedCallback(
	w http.ResponseWriter,
	r *http.Request,
	protocol string,
	groups []string,
	groupErr error,
	link federatedIdentityLink,
) bool {
	if h.rejectFederatedGroupError(w, r, protocol, groupErr) {
		return true
	}
	link.groups = groups
	return h.handleFederatedIdentityLink(w, r, link)
}

func (h *loginHandler) IdentityLinks(w http.ResponseWriter, r *http.Request) {
	if !h.identityLinksEnabled(w, r) {
		return
	}
	claims := tokenClaims(r)
	if claims == nil {
		httputil.WriteProblemStatus(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	rows, err := h.workerPool.Query(r.Context(), `
		SELECT l.id::text,s.kind,s.display_name,l.state,l.last_seen_at
		  FROM user_identity_links l
		  JOIN identity_sources s ON s.id=l.source_id
		 WHERE l.user_id=$1 AND 'authenticate'=ANY(l.purposes)
		 ORDER BY s.kind,s.display_name,l.id LIMIT 8
	`, claims.UserID)
	if err != nil {
		httputil.WriteProblemStatus(w, http.StatusServiceUnavailable, "identity links unavailable")
		return
	}
	defer rows.Close()
	items := make([]map[string]any, 0)
	for rows.Next() {
		var id, kind, name, state string
		var seen time.Time
		if rows.Scan(&id, &kind, &name, &state, &seen) != nil {
			httputil.WriteProblemStatus(w, http.StatusServiceUnavailable, "identity links unavailable")
			return
		}
		items = append(items, map[string]any{
			"id": id, "kind": kind, "displayName": name,
			"state": state, "lastSeenAt": seen,
		})
	}
	httputil.WriteJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (h *loginHandler) IdentityUnlink(w http.ResponseWriter, r *http.Request) {
	if !h.identityLinksEnabled(w, r) {
		return
	}
	claims := tokenClaims(r)
	if claims == nil || !jwtutil.ACRSatisfies(claims.ACR, jwtutil.ACRAAL2) ||
		claims.IssuedAt == nil || time.Since(claims.IssuedAt.Time) > 5*time.Minute {
		httputil.WriteProblemStatus(w, http.StatusForbidden, "fresh AAL2 step-up is required")
		return
	}
	linkID, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	var req struct {
		Reason string `json:"reason"`
	}
	if err != nil || json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&req) != nil ||
		req.Reason == "" {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "invalid identity unlink")
		return
	}
	var result json.RawMessage
	if err := h.workerPool.QueryRow(r.Context(),
		`SELECT identity_auth_unlink($1,$2,$3)`,
		claims.UserID, linkID, req.Reason).Scan(&result); err != nil {
		if !reducererr.WriteClassified(w, r, err) {
			httputil.WriteProblemStatus(w, http.StatusConflict, "identity unlink failed")
		}
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(result)
}
