package admin

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"sort"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/httputil"
	"setjoin.com/shared/identity"
	"setjoin.com/shared/permissions"
)

type IdentityHandler struct {
	pool          *pgxpool.Pool
	workerPool    identityWorkerQuerier
	inventoryDB   identityInventoryQuerier
	logger        *slog.Logger
	sourceSecrets *ConfigSecretCodec
	sourceProbe   func(context.Context, IdentitySourceRuntimeConfig) error
	runtime       IdentityRuntimeReadiness
}

func NewIdentityHandler(pool, inventoryPool *pgxpool.Pool, logger *slog.Logger) *IdentityHandler {
	var inventoryDB identityInventoryQuerier
	var workerDB identityWorkerQuerier
	if inventoryPool != nil {
		inventoryDB = inventoryPool
		workerDB = inventoryPool
	}
	return &IdentityHandler{
		pool: pool, workerPool: workerDB, inventoryDB: inventoryDB, logger: logger,
		sourceProbe: func(ctx context.Context, cfg IdentitySourceRuntimeConfig) error {
			return probeIdentitySourceRuntime(ctx, cfg, logger)
		},
	}
}

// SetSourceSecretCodec enables normalized source-document and credential
// envelopes. A missing codec makes every source mutation fail closed.
func (h *IdentityHandler) SetSourceSecretCodec(codec *ConfigSecretCodec) {
	h.sourceSecrets = codec
}

// IdentityRuntimeReadiness contains non-secret startup facts that PostgreSQL
// cannot discover itself. It is captured once after startup validation and is
// exposed only through the read-only doctor/preflight reducers.
type IdentityRuntimeReadiness struct {
	ExpectedSchemaVersion int
	WorkerDSNReady        bool
	OwnerDSNReady         bool
	DirectDSNReady        bool
	AuthserverConfigured  bool
}

func (h *IdentityHandler) SetRuntimeReadiness(readiness IdentityRuntimeReadiness) {
	h.runtime = readiness
}

type identityInventoryQuerier interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

type identityWorkerQuerier interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

type groupMapping struct {
	IDPGroup            string  `json:"idp_group"`
	DistributionGroupID *int64  `json:"distribution_group_id,omitempty"`
	AdminRole           *string `json:"admin_role,omitempty"`
	DepartmentID        *int64  `json:"department_id,omitempty"`
}

// ssoAdminRoleMintAuthorityKey is the system_config key holding the per-role
// grant-authority records the authserver login-time mint fence evaluates
// (applyGroupMappings): authorized_perms is the ceiling the role group's live
// permissions must stay within at mint time. UpdateGroupMappings is the
// roles.manage-side refresher — each fenced mapping write re-records the
// authority it exercised.
const ssoAdminRoleMintAuthorityKey = "sso_admin_role_grant_authority"

// governedSSORoleGroupIDs is the write-side mirror of the authserver's
// adminRoleToGroupID (authserver/internal/handlers/auth.go): the ONLY role
// labels an IdP group mapping may carry, and the builtin admin_role_groups.id
// each mints at login (V010-baseline builtins). Both sides must agree or a
// mapping could mint a role this fence never validated; shared/ is the
// eventual single source (cross-package note recorded for the owner).
var governedSSORoleGroupIDs = map[string]int64{
	"super_admin": 1,
	"user_admin":  2,
	"auditor":     4,
	"read_only":   8,
}

type identityInventoryPeople struct {
	Total                      int64 `json:"total"`
	Enabled                    int64 `json:"enabled"`
	Disabled                   int64 `json:"disabled"`
	Guests                     int64 `json:"guests"`
	Members                    int64 `json:"members"`
	UnclassifiedWithoutMailbox int64 `json:"unclassifiedWithoutMailbox"`
}

type identityInventoryMailboxes struct {
	Shared    int64 `json:"shared"`
	Resources int64 `json:"resources"`
}

type identityInventoryFederationPairs struct {
	OIDCComplete      int64 `json:"oidcComplete"`
	OIDCPartial       int64 `json:"oidcPartial"`
	SAMLComplete      int64 `json:"samlComplete"`
	SAMLPartial       int64 `json:"samlPartial"`
	LegacyInventoried int64 `json:"legacyInventoried"`
}

type identityInventoryProtectedAccounts struct {
	Total                int64 `json:"total"`
	BreakGlass           int64 `json:"breakGlass"`
	SensitiveRoleHolders int64 `json:"sensitiveRoleHolders"`
}

type identityInventoryEntitlementAmbiguity struct {
	DistributionGroupMemberships int64 `json:"distributionGroupMemberships"`
	AdminRoleAssignments         int64 `json:"adminRoleAssignments"`
}

// IdentityInventory is deliberately aggregate-only. It is safe for operator
// evidence and automation because it contains neither principal identifiers,
// federation subjects, email addresses, nor connector ciphertext.
type IdentityInventory struct {
	SchemaVersion        int                                   `json:"schemaVersion"`
	GeneratedAt          time.Time                             `json:"generatedAt"`
	People               identityInventoryPeople               `json:"people"`
	Mailboxes            identityInventoryMailboxes            `json:"mailboxes"`
	LifecycleSources     map[string]int64                      `json:"lifecycleSources"`
	FederationPairs      identityInventoryFederationPairs      `json:"federationPairs"`
	ProtectedAccounts    identityInventoryProtectedAccounts    `json:"protectedAccounts"`
	EntitlementAmbiguity identityInventoryEntitlementAmbiguity `json:"entitlementAmbiguity"`
	ConnectorSecrets     map[string]string                     `json:"connectorSecrets"`
	Blockers             []string                              `json:"blockers"`
}

// Inventory returns a PII-free release-zero snapshot of the current identity
// model. Cross-tenant reads use the explicitly supplied worker pool; callers
// must still wrap this handler in the audited admin read permission.
func (h *IdentityHandler) Inventory(w http.ResponseWriter, r *http.Request) {
	if !requireAnyUnscopedIdentityAdmin(w, r, ConsoleScopes[ConsoleAuth]...) {
		return
	}
	ctx := r.Context()
	if h.inventoryDB == nil {
		h.logger.Error("identity inventory worker pool is not configured")
		httputil.WriteError(w, http.StatusInternalServerError, "inventory unavailable")
		return
	}

	out := IdentityInventory{
		SchemaVersion:    1,
		GeneratedAt:      time.Now().UTC(),
		LifecycleSources: map[string]int64{},
		ConnectorSecrets: map[string]string{"ad": "unset", "ldap": "unset"},
		Blockers:         []string{},
	}

	err := h.inventoryDB.QueryRow(ctx, `
		SELECT
			count(*)::bigint,
			count(*) FILTER (WHERE u.enabled)::bigint,
			count(*) FILTER (WHERE NOT u.enabled)::bigint,
			count(*) FILTER (WHERE g.user_id IS NOT NULL)::bigint,
			count(*) FILTER (WHERE g.user_id IS NULL)::bigint,
			count(*) FILTER (
				WHERE g.user_id IS NULL
				  AND NOT EXISTS (
					SELECT 1 FROM public.mailboxes mb
					 WHERE mb.user_id = u.id AND mb.is_primary
				  )
			)::bigint,
			count(*) FILTER (
				WHERE u.oidc_subject IS NOT NULL AND u.oidc_issuer IS NOT NULL
			)::bigint,
			count(*) FILTER (
				WHERE (u.oidc_subject IS NULL) <> (u.oidc_issuer IS NULL)
			)::bigint,
			count(*) FILTER (
				WHERE u.saml_name_id IS NOT NULL AND u.saml_idp_entity_id IS NOT NULL
			)::bigint,
			count(*) FILTER (
				WHERE (u.saml_name_id IS NULL) <> (u.saml_idp_entity_id IS NULL)
			)::bigint
		FROM public.users u
		LEFT JOIN public.guest_accounts g ON g.user_id = u.id
	`).Scan(
		&out.People.Total,
		&out.People.Enabled,
		&out.People.Disabled,
		&out.People.Guests,
		&out.People.Members,
		&out.People.UnclassifiedWithoutMailbox,
		&out.FederationPairs.OIDCComplete,
		&out.FederationPairs.OIDCPartial,
		&out.FederationPairs.SAMLComplete,
		&out.FederationPairs.SAMLPartial,
	)
	if err != nil {
		h.inventoryError(w, "people", err)
		return
	}

	var adSecretState, ldapSecretState string
	err = h.inventoryDB.QueryRow(ctx, `
		SELECT
			count(*) FILTER (
				WHERE user_id IS NULL AND resource_type IS NULL
			)::bigint,
			count(*) FILTER (
				WHERE user_id IS NULL AND resource_type IS NOT NULL
			)::bigint
		FROM public.mailboxes
	`).Scan(&out.Mailboxes.Shared, &out.Mailboxes.Resources)
	if err != nil {
		h.inventoryError(w, "mailboxes", err)
		return
	}

	var lifecycleSourcesJSON []byte
	err = h.inventoryDB.QueryRow(ctx, `
		SELECT COALESCE(jsonb_object_agg(source, source_count), '{}'::jsonb)
		  FROM (
			SELECT COALESCE(NULLIF(btrim(sync_source), ''), 'unknown') AS source,
			       count(*)::bigint AS source_count
			  FROM public.users
			 GROUP BY 1
		  ) counts
	`).Scan(&lifecycleSourcesJSON)
	if err != nil {
		h.inventoryError(w, "lifecycle sources", err)
		return
	}
	if err := json.Unmarshal(lifecycleSourcesJSON, &out.LifecycleSources); err != nil {
		h.inventoryError(w, "lifecycle sources", err)
		return
	}

	err = h.inventoryDB.QueryRow(ctx, `
		SELECT
			(SELECT count(*)::bigint
			   FROM public.identity_legacy_federation_pair_inventory),
			(SELECT count(*)::bigint
			   FROM public.sso_distribution_group_legacy_inventory),
			(SELECT count(*)::bigint
			   FROM public.sso_admin_role_legacy_inventory)
	`).Scan(
		&out.FederationPairs.LegacyInventoried,
		&out.EntitlementAmbiguity.DistributionGroupMemberships,
		&out.EntitlementAmbiguity.AdminRoleAssignments,
	)
	if err != nil {
		h.inventoryError(w, "legacy identity state", err)
		return
	}

	sensitive := make([]string, 0, len(permissions.SensitivePermissions))
	for permission, isSensitive := range permissions.SensitivePermissions {
		if isSensitive {
			sensitive = append(sensitive, permission)
		}
	}
	sort.Strings(sensitive)
	err = h.inventoryDB.QueryRow(ctx, `
		WITH break_glass AS (
			SELECT DISTINCT elem.raw_user_id::bigint AS user_id
			  FROM public.system_config sc,
			       LATERAL jsonb_array_elements_text(sc.value) AS elem(raw_user_id)
			 WHERE sc.key = 'ca_break_glass_user_ids'
		),
		sensitive_holders AS (
			SELECT DISTINCT ara.user_id
			  FROM public.admin_role_assignments ara
			  JOIN public.admin_role_groups rg ON rg.id = ara.role_group_id
			 WHERE rg.permissions && $1::text[]
			   AND (ara.expires_at IS NULL OR ara.expires_at > now())
			   AND public.admin_assignment_active(ara.eligible, ara.activated_until)
		),
		protected AS (
			SELECT user_id FROM break_glass
			UNION
			SELECT user_id FROM sensitive_holders
		)
		SELECT
			(SELECT count(*)::bigint FROM protected),
			(SELECT count(*)::bigint FROM break_glass),
			(SELECT count(*)::bigint FROM sensitive_holders)
	`, sensitive).Scan(
		&out.ProtectedAccounts.Total,
		&out.ProtectedAccounts.BreakGlass,
		&out.ProtectedAccounts.SensitiveRoleHolders,
	)
	if err != nil {
		h.inventoryError(w, "protected accounts", err)
		return
	}

	err = h.inventoryDB.QueryRow(ctx, `
		WITH secret_rows AS (
			SELECT
				CASE
					WHEN key LIKE 'ad_sync_%' THEN 'ad'
					WHEN key LIKE 'ldap_sync_%' THEN 'ldap'
				END AS connector,
				CASE
					WHEN value IS NULL OR value = 'null'::jsonb OR value = '""'::jsonb
						THEN 'unset'
					WHEN jsonb_typeof(value) = 'object'
					  AND value->>'format' = 'setjoin-config-secret'
					  AND value->>'version' = '1'
					  AND value ? 'ciphertext'
						THEN 'encrypted'
					ELSE 'attention_required'
				END AS state
			  FROM public.system_config
			 WHERE right(key, 4) = '_enc'
			   AND (key LIKE 'ad_sync_%' OR key LIKE 'ldap_sync_%')
		), connector_states AS (
			SELECT
				connector,
				CASE
					WHEN bool_or(state = 'attention_required') THEN 'attention_required'
					WHEN bool_or(state = 'encrypted') THEN 'encrypted'
					ELSE 'unset'
				END AS state
			  FROM secret_rows
			 GROUP BY connector
		)
		SELECT
			COALESCE(max(state) FILTER (WHERE connector = 'ad'), 'unset'),
			COALESCE(max(state) FILTER (WHERE connector = 'ldap'), 'unset')
		  FROM connector_states
	`).Scan(&adSecretState, &ldapSecretState)
	if err != nil {
		h.inventoryError(w, "connector secret posture", err)
		return
	}
	out.ConnectorSecrets["ad"] = adSecretState
	out.ConnectorSecrets["ldap"] = ldapSecretState

	if out.People.UnclassifiedWithoutMailbox > 0 {
		out.Blockers = append(out.Blockers, "unclassified_user_without_primary_mailbox")
	}
	if out.FederationPairs.OIDCPartial > 0 || out.FederationPairs.SAMLPartial > 0 ||
		out.FederationPairs.LegacyInventoried > 0 {
		out.Blockers = append(out.Blockers, "legacy_incomplete_federation_pair")
	}
	if out.EntitlementAmbiguity.DistributionGroupMemberships > 0 ||
		out.EntitlementAmbiguity.AdminRoleAssignments > 0 {
		out.Blockers = append(out.Blockers, "legacy_sso_entitlement_provenance")
	}
	if out.ConnectorSecrets["ad"] == "attention_required" ||
		out.ConnectorSecrets["ldap"] == "attention_required" {
		out.Blockers = append(out.Blockers, "connector_secret_attention_required")
	}

	httputil.WriteJSON(w, http.StatusOK, out)
}

func (h *IdentityHandler) inventoryError(w http.ResponseWriter, section string, err error) {
	h.logger.Error("identity inventory query failed", "section", section, "error", err)
	httputil.WriteError(w, http.StatusInternalServerError, "inventory unavailable")
}

func (h *IdentityHandler) GetGroupMappings(w http.ResponseWriter, r *http.Request) {
	if !requireAnyUnscopedIdentityAdmin(w, r, ConsoleScopes[ConsoleAuth]...) {
		return
	}
	ctx := r.Context()
	result := map[string]map[string][]groupMapping{
		"saml": {},
		"oidc": {},
	}

	rows, err := h.pool.Query(ctx,
		`SELECT idp_entity_id, COALESCE(group_mappings, '[]'::JSONB) FROM saml_sp_registrations WHERE enabled = TRUE`)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var idp string
			var raw json.RawMessage
			if rows.Scan(&idp, &raw) == nil {
				var mappings []groupMapping
				json.Unmarshal(raw, &mappings)
				if mappings == nil {
					mappings = []groupMapping{}
				}
				result["saml"][idp] = mappings
			}
		}
	}

	rows2, err := h.pool.Query(ctx,
		`SELECT key, value FROM system_config WHERE key LIKE 'oidc_provider_%_config'`)
	if err == nil {
		defer rows2.Close()
		for rows2.Next() {
			var key string
			var raw json.RawMessage
			if rows2.Scan(&key, &raw) == nil {
				var cfg struct {
					Name          string         `json:"name"`
					GroupMappings []groupMapping `json:"group_mappings"`
				}
				if json.Unmarshal(raw, &cfg) == nil {
					if cfg.GroupMappings == nil {
						cfg.GroupMappings = []groupMapping{}
					}
					result["oidc"][cfg.Name] = cfg.GroupMappings
				}
			}
		}
	}

	httputil.WriteJSON(w, http.StatusOK, result)
}

func (h *IdentityHandler) UpdateGroupMappings(w http.ResponseWriter, r *http.Request) {
	if !requireUnscopedIdentityAdmin(w, r) {
		return
	}
	ctx := r.Context()
	providerType := r.PathValue("type")
	providerID := r.PathValue("id")

	var mappings []groupMapping
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if err := json.NewDecoder(r.Body).Decode(&mappings); err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if mappings == nil {
		mappings = []groupMapping{}
	}
	mappingGroups := make([]string, len(mappings))
	for i := range mappings {
		mappingGroups[i] = mappings[i].IDPGroup
	}
	if err := identity.ValidateSSOGroupMappings(mappingGroups); err != nil {
		httputil.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Rule A — grant-only-what-you-hold (F-004, Astra waves34 HOLD 1): a
	// mapping entry carrying an admin_role label mints a PERSISTENT
	// admin_role_assignments row at login (the authserver login-time
	// upsertSSOAdminAssignment consumer, granted_by NULL). Checking only
	// roles.manage is NOT Rule A: a principal holding identity.write +
	// roles.manage could map a role granting permissions they do not hold.
	// Exactly like admin_roles.go AssignMember, the TARGET ROLE's full
	// permission and scope grant is validated under the authority fence
	// (acquireAdminAuthorityFence + role row FOR UPDATE, so the validated
	// permissions/scope cannot change before the mapping commits), and the
	// mapping write plus the mint-authority record refresh commit on the SAME
	// transaction. Distribution-group-only mappings stay identity.write.
	type roleAuth struct {
		label string
		perms []string
	}
	var authorizedRoles []roleAuth
	rolesRequested := make(map[string]bool)
	for _, m := range mappings {
		if m.AdminRole != nil && *m.AdminRole != "" && !rolesRequested[*m.AdminRole] {
			rolesRequested[*m.AdminRole] = true
		}
	}
	if len(rolesRequested) > 0 {
		claims := auth.UserFromContext(ctx)
		if claims == nil || !claims.HasPermission(permissions.PermRolesManage) {
			httputil.WriteError(w, http.StatusForbidden, "roles.manage required to map IdP groups to admin roles")
			return
		}

		tx, err := h.pool.Begin(ctx)
		if err != nil {
			h.logger.Error("group mapping authority fence tx begin failed", "error", err)
			httputil.WriteError(w, http.StatusInternalServerError, "update failed")
			return
		}
		defer tx.Rollback(ctx) //nolint:errcheck

		fenceErr := func() error {
			if err := acquireAdminAuthorityFence(ctx, tx); err != nil {
				return err
			}
			for label := range rolesRequested {
				groupID, governed := governedSSORoleGroupIDs[label]
				if !governed {
					httputil.WriteError(w, http.StatusBadRequest,
						"unknown admin role label: "+label)
					return errHandled
				}
				var rolePerms []string
				var roleScope *int64
				err := tx.QueryRow(ctx,
					`SELECT permissions, domain_scope FROM admin_role_groups WHERE id = $1 FOR UPDATE`,
					groupID).Scan(&rolePerms, &roleScope)
				if err != nil {
					if errors.Is(err, pgx.ErrNoRows) {
						httputil.WriteError(w, http.StatusBadRequest,
							"unknown admin role label: "+label)
						return errHandled
					}
					return err
				}
				// Rule A permission arm — the login-time mint hands the target
				// every permission the role embeds; the mapping author must hold
				// each of them (mirrors AssignMember's per-permission check).
				for _, p := range rolePerms {
					if !claims.HasPermission(p) {
						httputil.WriteError(w, http.StatusForbidden,
							"cannot map a role granting a permission you do not hold: "+p)
						return errHandled
					}
				}
				// Rule A scope arm — the minted assignment inherits the role's
				// domain_scope, so the author's own reach must cover it
				// (mirrors AssignMember's admin_scope_within check; the
				// unscoped-actor gate above keeps global writers passing).
				var scopeAllowed bool
				if err := tx.QueryRow(ctx,
					`SELECT admin_scope_within($1, NULL, NULL, $2)`,
					claims.UserID, roleScope).Scan(&scopeAllowed); err != nil {
					return err
				}
				if !scopeAllowed {
					httputil.WriteError(w, http.StatusForbidden,
						"cannot map a role granting a scope broader than your own reach")
					return errHandled
				}
				authorizedRoles = append(authorizedRoles, roleAuth{label: label, perms: rolePerms})
			}
			return nil
		}()
		if fenceErr != nil && fenceErr != errHandled {
			h.logger.Error("group mapping authority fence failed", "error", fenceErr)
			httputil.WriteError(w, http.StatusInternalServerError, "update failed")
			return
		}
		if fenceErr == errHandled {
			return
		}

		// Persist the mappings on the SAME transaction that holds the fence, so
		// a mapping never survives without its validated authority record.
		if err := h.persistGroupMappings(ctx, w, tx, providerType, providerID, mappings); err != nil {
			if errors.Is(err, errHandled) {
				return
			}
			h.logger.Error("group mappings update failed", "error", err)
			httputil.WriteError(w, http.StatusInternalServerError, "update failed")
			return
		}

		// Refresh the login-time mint-authority records for exactly the labels
		// this write authorized (atomic with the mapping write). authorized_by
		// is the acting roles.manage holder; authorized_perms is the ceiling
		// the authserver fence enforces at mint time.
		authority := map[string]any{}
		now := time.Now().UTC().Format(time.RFC3339)
		for _, ra := range authorizedRoles {
			authority[ra.label] = map[string]any{
				"authorized_by":    claims.UserID,
				"authorized_at":    now,
				"authorized_perms": ra.perms,
			}
		}
		authorityJSON, err := json.Marshal(authority)
		if err != nil {
			h.logger.Error("grant authority marshal failed", "error", err)
			httputil.WriteError(w, http.StatusInternalServerError, "update failed")
			return
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO system_config (key, value, updated_at)
			 VALUES ($1, $2::jsonb, now())
			 ON CONFLICT (key) DO UPDATE SET value = system_config.value || EXCLUDED.value, updated_at = now()`,
			ssoAdminRoleMintAuthorityKey, string(authorityJSON)); err != nil {
			h.logger.Error("grant authority refresh failed", "error", err)
			httputil.WriteError(w, http.StatusInternalServerError, "update failed")
			return
		}

		if err := tx.Commit(ctx); err != nil {
			h.logger.Error("group mappings commit failed", "error", err)
			httputil.WriteError(w, http.StatusInternalServerError, "update failed")
			return
		}
		w.WriteHeader(http.StatusNoContent)
		return
	}

	// No admin-role labels: distribution-group/department-only mappings stay
	// identity.write and need no authority fence.
	if err := h.persistGroupMappings(ctx, w, h.pool, providerType, providerID, mappings); err != nil {
		if errors.Is(err, errHandled) {
			return
		}
		h.logger.Error("group mappings update failed", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "update failed")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// errHandled marks that persistGroupMappings already wrote its HTTP error.
var errHandled = errors.New("response already written")

// persistGroupMappings writes the mapping set for the SAML or OIDC provider on
// the supplied querier (the fence transaction for admin-role mappings, the
// pool otherwise). A bad provider type or unknown OIDC provider writes the
// HTTP error and returns errHandled.
func (h *IdentityHandler) persistGroupMappings(
	ctx context.Context,
	w http.ResponseWriter,
	db interface {
		Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
		QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
	},
	providerType, providerID string,
	mappings []groupMapping,
) error {
	switch providerType {
	case "saml":
		raw, _ := json.Marshal(mappings)
		_, err := db.Exec(ctx,
			`UPDATE saml_sp_registrations SET group_mappings = $2::JSONB WHERE idp_entity_id = $1`, providerID, raw)
		return err
	case "oidc":
		key := "oidc_provider_" + providerID + "_config"
		var raw json.RawMessage
		err := db.QueryRow(ctx, `SELECT value FROM system_config WHERE key = $1`, key).Scan(&raw)
		if err != nil {
			httputil.WriteError(w, http.StatusNotFound, "provider not found")
			return errHandled
		}
		var cfg map[string]interface{}
		if err := json.Unmarshal(raw, &cfg); err != nil {
			return err
		}
		cfg["group_mappings"] = mappings
		updated, _ := json.Marshal(cfg)
		_, err = db.Exec(ctx, `UPDATE system_config SET value = $2 WHERE key = $1`, key, updated)
		return err
	default:
		httputil.WriteError(w, http.StatusBadRequest, "invalid provider type")
		return errHandled
	}
}
