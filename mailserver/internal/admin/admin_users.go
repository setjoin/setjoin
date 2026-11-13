package admin

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/mailserver/internal/handlerutil"
	"setjoin.com/mailserver/internal/middleware"
	"setjoin.com/mailserver/internal/notify"
	"setjoin.com/mailserver/internal/scim"
	"setjoin.com/mailserver/internal/webhook"
	"setjoin.com/shared/httputil"
	"setjoin.com/shared/identity"
	"setjoin.com/shared/pgxutil"
	"setjoin.com/shared/pwhash"
	"setjoin.com/shared/reducererr"
	"setjoin.com/shared/validate"
	wh "setjoin.com/shared/webhook"
)

// UsersHandler provides admin CRUD for user accounts.
type UsersHandler struct {
	pool           *pgxpool.Pool
	workerPool     *pgxpool.Pool // setjoin_worker (BYPASSRLS) pool for the cross-tenant welcome deliver() (native-RLS W4)
	logger         *slog.Logger
	dispatcher     userEventDispatcher
	authServerURL  string // for immediate session revocation on suspend (see scim.RevokeAuthSessions); "" disables (best-effort no-op)
	internalAPIKey string
}

type userEventDispatcher interface {
	Dispatch(context.Context, wh.CloudEvent)
	DispatchForUser(context.Context, int64, wh.CloudEvent)
}

// NewUsersHandler creates an admin users handler. workerPool is the
// setjoin_worker (BYPASSRLS) pool — the welcome email runs deliver() into the
// freshly-provisioned user's mailbox (cross-tenant from the admin caller), so it
// must run on the bypass pool to survive the native-RLS W6 FORCE flip. workerPool
// aliases pool until DB_WORKER_DSN is set (W1b), so this is INERT today.
// authServerURL/internalAPIKey wire the suspend path to the SAME authserver
// session-revocation seam SCIM disable uses (scim.RevokeAuthSessions) — empty
// values degrade to a best-effort no-op (the refresh-time enabled check in
// authserver/internal/token/refresh.go is the structural guarantee regardless).
func NewUsersHandler(pool *pgxpool.Pool, workerPool pgxutil.WorkerPool, logger *slog.Logger, dispatcher *webhook.Dispatcher, authServerURL, internalAPIKey string) *UsersHandler {
	return &UsersHandler{pool: pool, workerPool: workerPool.Pool, logger: logger, dispatcher: dispatcher, authServerURL: authServerURL, internalAPIKey: internalAPIKey}
}

// adminRefuseGuestTarget writes a 409 problem and returns true when targetID
// is a guest account (guest-accounts G0, codex C-4): generic admin user
// mutations must route through the guest console — guest_set_status is the
// single writer for status/users.enabled/refresh-revocation, and a
// users-only flip here would desync the satellite belt (a "suspended" guest
// whose satellite still says active, or an "enabled" one still disabled).
// Fail CLOSED on lookup error (the is_guest_account DEFINER helper — never
// a raw guest_accounts read, which FORCE RLS would silently empty).
func adminRefuseGuestTarget(ctx context.Context, pool *pgxpool.Pool, logger *slog.Logger, w http.ResponseWriter, r *http.Request, targetID int64) bool {
	var isGuest bool
	if err := pool.QueryRow(ctx, `SELECT is_guest_account($1)`, targetID).Scan(&isGuest); err != nil {
		httputil.WriteDBErr(w, r, logger, "guest target check failed", err)
		return true // fail closed
	}
	if isGuest {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusConflict,
			Detail: "guest accounts are managed via the guest console (/admin/guests), not the generic user endpoints"})
		return true
	}
	return false
}

// validateAdminPassword checks password against policy, common passwords, and email inclusion.
func (h *UsersHandler) validateAdminPassword(ctx context.Context, password, email string) error {
	policy, err := pwhash.LoadPasswordPolicy(ctx, h.pool)
	if err != nil {
		h.logger.Error("admin: failed to read password policy", "error", err)
		// Fall back to default policy rather than blocking.
		policy = validate.PasswordPolicy{MinLength: 8, RequireUppercase: true, RequireLowercase: true, RequireDigit: true, RequireSpecial: true}
	}
	policy.DisallowEmail = email

	if err := validate.ValidatePassword(password, policy); err != nil {
		return err
	}

	if common, err := pwhash.CheckCommonPassword(ctx, h.pool, password); err == nil && common {
		return validate.NewValidationError("password", "This password is too common and easily guessed. Please choose a stronger password.", "COMMON_PASSWORD")
	}

	return nil
}

// resolveLocalDomain returns the id of the local domain matching the domain part
// of email. Both users.domain_id and mailboxes.domain_id are NOT NULL, so user
// and mailbox creation must resolve it up front. Returns an error if the email
// has no '@', or its domain is not a registered local domain.
func (h *UsersHandler) resolveLocalDomain(ctx context.Context, email string) (int64, error) {
	at := strings.LastIndexByte(email, '@')
	if at < 0 || at == len(email)-1 {
		return 0, errors.New("email has no domain part")
	}
	domain := strings.ToLower(email[at+1:])
	var domainID int64
	if err := h.pool.QueryRow(ctx,
		`SELECT id FROM domains WHERE lower(name) = $1 AND is_local = TRUE LIMIT 1`,
		domain,
	).Scan(&domainID); err != nil {
		return 0, err
	}
	return domainID, nil
}

// UserResponse is the admin-API representation of a user account (the GET/list
// shape). It is the source of truth for the OpenAPI `User` schema, which
// cmd/schemagen reflects from this type — keep the json tags in sync with the
// generated spec (regenerate via `go generate ./mailserver/api/...`). The
// `openapi:"format=…"` tags carry the semantic OpenAPI `format` hints that Go's
// type system can't express (a Go string is just a string); schemagen's
// SchemaCustomizer applies them so the generated schema keeps `format: email`
// etc. that the hand-authored spec carried.
type UserResponse struct {
	ID           int64     `json:"id" openapi:"format=int64"`
	Email        string    `json:"email" openapi:"format=email"`
	DisplayName  string    `json:"displayName"`
	Enabled      bool      `json:"enabled"`
	IsLocalAdmin bool      `json:"isLocalAdmin"`
	DepartmentID *int64    `json:"departmentId,omitempty" openapi:"format=int64"`
	CreatedAt    time.Time `json:"createdAt"`
	MailboxID    *int64    `json:"mailboxId,omitempty" openapi:"format=int64"`
	// Manageable indicates whether the caller has sufficient authority to manage
	// this user (same definition as admin_protection_check uses). Only populated
	// by the List endpoint; always false on the Get endpoint (not needed there).
	Manageable bool `json:"manageable"`
	// IsSelf is true when this row is the caller's own account.
	IsSelf bool `json:"isSelf"`
}

// UserCreateRequest is the admin create-user request body (the OpenAPI
// `UserCreate` schema, reflected by cmd/schemagen). `openapi:"required"` marks
// the wire-required fields (schemagen folds them into the schema's required list,
// matching the hand-authored contract).
type UserCreateRequest struct {
	Email        string `json:"email" openapi:"format=email,required"`
	DisplayName  string `json:"displayName"`
	Password     string `json:"password" openapi:"format=password,required"`
	IsLocalAdmin bool   `json:"isLocalAdmin"`
}

// UserUpdateRequest is the admin patch-user request body (the OpenAPI
// `UserUpdate` schema, reflected by cmd/schemagen). All fields are pointers so an
// omitted field is left unchanged.
type UserUpdateRequest struct {
	DisplayName  *string `json:"displayName,omitempty"`
	Enabled      *bool   `json:"enabled,omitempty"`
	IsLocalAdmin *bool   `json:"isLocalAdmin,omitempty"`
}

// List returns a paginated list of users.
func (h *UsersHandler) List(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	q := r.URL.Query().Get("q")
	limit, offset := httputil.ParseLimitOffset(r, 50, 100)

	// Domain-scoped admins (claims.DomainScope) see only users in their domain.
	// domainScope == 0 means a global (unscoped) admin → no extra predicate.
	domainScope := middleware.DomainScopeFromContext(ctx)

	var rows pgx.Rows
	var err error
	switch {
	case q != "" && domainScope > 0:
		pattern := "%" + q + "%"
		rows, err = h.pool.Query(ctx,
			`SELECT id, email, display_name, enabled, is_local_admin, department_id, created_at
			 FROM users
			 WHERE (email ILIKE $1 OR display_name ILIKE $1) AND domain_id = $2
			 ORDER BY id DESC LIMIT $3 OFFSET $4`,
			pattern, domainScope, limit, offset)
	case q != "":
		pattern := "%" + q + "%"
		rows, err = h.pool.Query(ctx,
			`SELECT id, email, display_name, enabled, is_local_admin, department_id, created_at
			 FROM users
			 WHERE email ILIKE $1 OR display_name ILIKE $1
			 ORDER BY id DESC LIMIT $2 OFFSET $3`,
			pattern, limit, offset)
	case domainScope > 0:
		rows, err = h.pool.Query(ctx,
			`SELECT id, email, display_name, enabled, is_local_admin, department_id, created_at
			 FROM users
			 WHERE domain_id = $1
			 ORDER BY id DESC LIMIT $2 OFFSET $3`,
			domainScope, limit, offset)
	default:
		rows, err = h.pool.Query(ctx,
			`SELECT id, email, display_name, enabled, is_local_admin, department_id, created_at
			 FROM users
			 ORDER BY id DESC LIMIT $1 OFFSET $2`,
			limit, offset)
	}
	if err != nil {
		httputil.WriteDBErr(w, r, h.logger, "admin users list failed", err)
		return
	}
	defer rows.Close()

	out := []UserResponse{}
	for rows.Next() {
		var u UserResponse
		if err := rows.Scan(&u.ID, &u.Email, &u.DisplayName, &u.Enabled, &u.IsLocalAdmin, &u.DepartmentID, &u.CreatedAt); err != nil {
			continue
		}
		out = append(out, u)
	}
	if err := rows.Err(); err != nil {
		httputil.WriteDBErr(w, r, h.logger, "admin users list rows error", err)
		return
	}

	// Populate manageable + is_self flags per row. The actor's authority is
	// resolved DB-side from claims.UserID via the same admin_effective_authority
	// helper as the guard reducer — so the hint matches enforcement under one
	// definition. One query for the whole page (LATERAL once per listed user).
	if len(out) > 0 {
		claims := auth.UserFromContext(ctx)
		var actorID int64
		if claims != nil {
			actorID = claims.UserID
		}

		// Collect page IDs for the unnest($1) input.
		ids := make([]int64, len(out))
		for i, u := range out {
			ids[i] = u.ID
		}

		flagRows, flagErr := h.pool.Query(ctx, `
WITH actor AS (
  SELECT EXISTS(SELECT 1 FROM admin_role_assignments
                 WHERE user_id=$2 AND role_group_id=1
                   AND (expires_at IS NULL OR expires_at > now())) AS is_super,
         a.perms, a.scope
    FROM admin_effective_authority($2) AS a
)
SELECT u.id,
       (u.id = $2::bigint) AS is_self,
       CASE WHEN a.is_super THEN true
            ELSE ea.perms <@ a.perms
                 AND NOT (cardinality(ea.perms) > 0 AND a.scope IS NOT NULL AND ea.scope IS NULL)
                 AND (cardinality(a.perms) = 0 OR admin_can_reach($2, u.id))
       END AS manageable,
       (SELECT m.id FROM mailboxes m
         WHERE m.user_id=u.id AND m.is_primary
         ORDER BY m.id LIMIT 1) AS mailbox_id
  FROM unnest($1::bigint[]) AS u(id)
  CROSS JOIN LATERAL admin_effective_authority(u.id) AS ea
  CROSS JOIN actor a
`, ids, actorID)
		if flagErr != nil {
			h.logger.Error("admin users list flags query failed", "error", flagErr)
			// Non-fatal: return the page without flags rather than 500-ing.
		} else {
			defer flagRows.Close()
			// Build index by user id for O(n) assignment.
			idxByID := make(map[int64]int, len(out))
			for i, u := range out {
				idxByID[u.ID] = i
			}
			for flagRows.Next() {
				var uid int64
				var isSelf, manageable bool
				var mailboxID *int64
				if err := flagRows.Scan(&uid, &isSelf, &manageable, &mailboxID); err != nil {
					continue
				}
				if i, ok := idxByID[uid]; ok {
					out[i].IsSelf = isSelf
					out[i].Manageable = manageable
					out[i].MailboxID = mailboxID
				}
			}
			if err := flagRows.Err(); err != nil {
				h.logger.Error("admin users list flags rows error", "error", err)
			}
		}
	}

	httputil.WriteJSON(w, http.StatusOK, out)
}

// Get returns a single user by ID.
func (h *UsersHandler) Get(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	idStr := r.PathValue("id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "invalid user id"})
		return
	}

	// Domain-scoped admins fold their domain into the same SELECT so an
	// out-of-scope id is indistinguishable from missing (404).
	domainScope := middleware.DomainScopeFromContext(ctx)
	var u UserResponse
	if domainScope > 0 {
		err = h.pool.QueryRow(ctx,
			`SELECT id, email, display_name, enabled, is_local_admin, department_id, created_at
			 FROM users WHERE id = $1 AND domain_id = $2`, id, domainScope,
		).Scan(&u.ID, &u.Email, &u.DisplayName, &u.Enabled, &u.IsLocalAdmin, &u.DepartmentID, &u.CreatedAt)
	} else {
		err = h.pool.QueryRow(ctx,
			`SELECT id, email, display_name, enabled, is_local_admin, department_id, created_at
			 FROM users WHERE id = $1`, id,
		).Scan(&u.ID, &u.Email, &u.DisplayName, &u.Enabled, &u.IsLocalAdmin, &u.DepartmentID, &u.CreatedAt)
	}
	if err != nil {
		if err == pgx.ErrNoRows {
			httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusNotFound, Detail: "user not found"})
			return
		}
		httputil.WriteDBErr(w, r, h.logger, "admin user get failed", err)
		return
	}

	httputil.WriteJSON(w, http.StatusOK, u)
}

// Create creates a new user with a bcrypt password and primary mailbox.
func (h *UsersHandler) Create(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)

	var req UserCreateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "invalid JSON"})
		return
	}
	if req.Email == "" || req.Password == "" {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "email and password required"})
		return
	}
	if req.DisplayName == "" {
		req.DisplayName = strings.Split(req.Email, "@")[0]
	}
	// Validate AND canonicalize in one step: ValidateAndCanonicalizeEmail mints
	// the identity.ValidatedAddress that ProvisionAccount demands, so the address
	// is validated at the same boundary that forces canonicalization (the prior
	// separate validate.ValidateEmail call is now redundant — the mint runs the
	// same validate.ValidateEmail on the canonical form). Rejection surfaces the
	// identical HTTP 400 as before.
	validatedEmail, err := identity.ValidateAndCanonicalizeEmail(req.Email)
	if err != nil {
		if ve := new(validate.ValidationError); errors.As(err, &ve) {
			httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: ve.ToFieldError().Message})
		} else {
			httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: err.Error()})
		}
		return
	}
	if err := validate.ValidateDisplayName(req.DisplayName); err != nil {
		if ve, ok := err.(*validate.ValidationError); ok {
			httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: ve.ToFieldError().Message})
		} else {
			httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: err.Error()})
		}
		return
	}
	// The containment policy token is the CANONICAL validated address, not the
	// raw request string — a display-name/quoted-local form would make the
	// DisallowEmail check evaluate a token that never matches what provisioning
	// stores (passwordContainsEmail canonicalizes defensively too; feeding it
	// the mint keeps one definition of the address being written).
	if err := h.validateAdminPassword(ctx, req.Password, validatedEmail.String()); err != nil {
		if ve, ok := err.(*validate.ValidationError); ok {
			httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: ve.ToFieldError().Message})
		} else {
			httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: err.Error()})
		}
		return
	}

	hash, err := auth.HashPassword(req.Password)
	if err != nil {
		h.logger.Error("password hash failed", "error", err)
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusInternalServerError, Detail: "password hashing failed"})
		return
	}

	// Reject non-local domains up front (provision_account would auto-create the
	// domain, but admin-created users must land in an existing local domain).
	resolvedDomainID, err := h.resolveLocalDomain(ctx, req.Email)
	if err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "email domain is not a local domain"})
		return
	}

	// Domain-scoped admins may only create users in their own domain. Reject
	// when the new user's resolved domain differs from the scope (403).
	if domainScope := middleware.DomainScopeFromContext(ctx); domainScope > 0 && resolvedDomainID != domainScope {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusForbidden, Detail: "email domain is not in your domain scope"})
		return
	}

	// Create the person + their primary mailbox atomically via the single
	// provisioning seam (resolves domain_id, derives username, sets every NOT
	// NULL column, creates the primary personal mailbox). "Logic where the data
	// is" — the gateway no longer hand-rolls the users/mailboxes INSERTs.
	//
	// The operator-supplied req.Email was validated AND canonicalized above into
	// validatedEmail — identity.ProvisionAccount's Email param is ValidatedAddress,
	// so only a value that passed validate.ValidateEmail on its canonical form can
	// reach the write. This forces the admin-create path onto the same fold as
	// AD/LDAP AND compile-enforces validation, so users.email is always Go-canonical
	// and structurally valid regardless of how an operator typed the address.
	// Provision and publication enrollment share the worker transaction. This is
	// an admin cross-tenant mutation and the outbox reducer is intentionally not
	// executable by the tenant app credential.
	tx, err := h.workerPool.Begin(ctx)
	if err != nil {
		httputil.WriteDBErr(w, r, h.logger, "admin user create tx begin failed", err)
		return
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	enabled := true
	var createActorID *int64
	if claims := auth.UserFromContext(ctx); claims != nil {
		id := claims.UserID
		createActorID = &id
	}
	provision, err := identity.ProvisionAccount(ctx, tx, identity.ProvisionAccountParams{
		Email:        validatedEmail,
		DisplayName:  req.DisplayName,
		PasswordHash: hash,
		IsLocalAdmin: &req.IsLocalAdmin,
		Enabled:      &enabled,
		SyncSource:   "local",
		CreateOnly:   true,
		ActorID:      createActorID,
	})
	if err != nil {
		h.logger.Error("admin user create failed", "error", err)
		if pgErr, ok := err.(*pgconn.PgError); ok && pgErr.Code == "23505" {
			httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusConflict, Detail: "user already exists"})
		} else {
			httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusInternalServerError, Detail: "database error"})
		}
		return
	}
	var prov struct {
		UserID  int64 `json:"user_id"`
		Created bool  `json:"created"`
	}
	if err := json.Unmarshal(provision, &prov); err != nil {
		httputil.WriteDBErr(w, r, h.logger, "admin user create: bad provision result", err)
		return
	}
	if !prov.Created {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusConflict, Detail: "user already exists"})
		return
	}
	userID := prov.UserID

	adminUser := auth.UserFromContext(r.Context())
	publicationQueued := false
	if adminUser != nil {
		if err := tx.QueryRow(ctx,
			`SELECT webhook_user_changed_publish($1,$2,$3)`, adminUser.UserID, userID, wh.EventUserCreated,
		).Scan(&publicationQueued); err != nil {
			httputil.WriteDBErr(w, r, h.logger, "admin user create webhook publication failed", err)
			return
		}
	}
	if err := tx.Commit(ctx); err != nil {
		httputil.WriteDBErr(w, r, h.logger, "admin user create tx commit failed", err)
		return
	}
	if adminUser != nil && !publicationQueued && h.dispatcher != nil {
		h.dispatcher.DispatchForUser(r.Context(), userID, wh.NewCloudEvent("mailserver/auth", wh.EventUserCreated, map[string]interface{}{
			"user_id":    userID,
			"email":      req.Email,
			"created_by": adminUser.Email,
		}))
	}

	// Welcome email: fire only for a genuinely new mailbox (created=true — already
	// enforced by the 409 early-return above; the explicit guard documents intent),
	// async, cross-tenant via the worker (BYPASSRLS) pool, not the tenant app pool
	// (native-RLS W4; INERT until W6 while DB_WORKER_DSN is unset). Locale "" → the
	// configured default_locale. Idempotency-guarded inside SendWelcomeEmail.
	if prov.Created {
		go notify.SendWelcomeEmail(context.Background(), h.workerPool, userID, "", h.logger) //nolint:gosec // G118: fire-and-forget background task must outlive the request (welcome email sent async, must not be cancelled when the response returns)
	}

	httputil.WriteJSON(w, http.StatusCreated, map[string]int64{"id": userID})
}

// Update patches a user's fields.
func (h *UsersHandler) Update(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)

	idStr := r.PathValue("id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "invalid user id"})
		return
	}

	if adminRefuseGuestTarget(ctx, h.pool, h.logger, w, r, id) {
		return
	}

	claims := auth.RequireUser(w, r)
	if claims == nil {
		return
	}
	actor := claims.UserID

	var req UserUpdateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "invalid JSON"})
		return
	}

	b := &handlerutil.UpdateBuilder{}
	b.SetStr("display_name", req.DisplayName)
	b.SetBool("enabled", req.Enabled)
	b.SetBool("is_local_admin", req.IsLocalAdmin)

	// Rule B — reach check: target must be reachable by the actor.
	extraWhere := ""
	var extraArgs []interface{}
	if domainScope := middleware.DomainScopeFromContext(ctx); domainScope > 0 {
		// Domain-scoped actor: fold the scope into the UPDATE WHERE clause (R3 pattern —
		// the domain check and the mutation are the same statement, no TOCTOU).
		nFields := 0
		if req.DisplayName != nil {
			nFields++
		}
		if req.Enabled != nil {
			nFields++
		}
		if req.IsLocalAdmin != nil {
			nFields++
		}
		extraWhere = "domain_id = $" + strconv.Itoa(nFields+2)
		extraArgs = []interface{}{domainScope}
		// ponytail: AND gate — domain check folded into WHERE above; now enforce OU narrowing.
		// A domain-only actor (no OU assignment) short-circuits true in admin_can_reach.
		var canReach bool
		if err := h.pool.QueryRow(ctx, `
			SELECT admin_can_manage($1, $2)`, actor, id).Scan(&canReach); err != nil {
			httputil.WriteDBErr(w, r, h.logger, "admin user update reach check (scoped) failed", err)
			return
		}
		if !canReach {
			httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusNotFound, Detail: "admin user not found"})
			return
		}
	} else {
		// Unscoped actor: admin_can_reach enforces OU scope (and any domain-restricted
		// assignments). Returns true for global actors (NULL scope on every assignment).
		// ponytail: actors without any active DB assignments pass through — in production
		// every admin has at least one active assignment. TOCTOU window accepted.
		var canReach bool
		if err := h.pool.QueryRow(ctx, `
			SELECT admin_can_manage($1, $2)`, actor, id).Scan(&canReach); err != nil {
			httputil.WriteDBErr(w, r, h.logger, "admin user update reach check failed", err)
			return
		}
		if !canReach {
			httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusNotFound, Detail: "admin user not found"})
			return
		}
	}

	// Every update now owns one worker transaction so the user mutation and an
	// enabled publication fact commit or roll back together. The suspend-only
	// protection check remains in that same snapshot.
	tx, err := h.workerPool.Begin(ctx)
	if err != nil {
		httputil.WriteDBErr(w, r, h.logger, "admin user update tx begin failed", err)
		return
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	disabling := req.Enabled != nil && !*req.Enabled
	if disabling {
		if _, err := tx.Exec(ctx, `SELECT admin_protection_check($1,$2,'suspend',NULL)`, actor, id); err != nil {
			if mapProtectionErr(h.pool, h.logger, w, r, err, actor, id) {
				return
			}
			httputil.WriteDBErr(w, r, h.logger, "admin user update (suspend) protection check failed", err)
			return
		}

	}
	q, args, buildErr := b.Build("users", "id", id, false, extraWhere, extraArgs...)
	if buildErr != nil {
		if errors.Is(buildErr, handlerutil.ErrNoFields) {
			httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "no fields to update"})
			return
		}
		httputil.WriteDBErr(w, r, h.logger, "admin user update build failed", buildErr)
		return
	}
	tag, execErr := tx.Exec(ctx, q, args...)
	if execErr != nil {
		httputil.WriteDBErr(w, r, h.logger, "admin user update exec failed", execErr)
		return
	}
	if tag.RowsAffected() == 0 {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusNotFound, Detail: "admin user not found"})
		return
	}
	var publicationQueued bool
	if err := tx.QueryRow(ctx,
		`SELECT webhook_user_changed_publish($1,$2,$3)`, actor, id, wh.EventUserUpdated,
	).Scan(&publicationQueued); err != nil {
		httputil.WriteDBErr(w, r, h.logger, "admin user update webhook publication failed", err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		httputil.WriteDBErr(w, r, h.logger, "admin user update tx commit failed", err)
		return
	}
	if disabling {
		// Immediacy leg: best-effort and strictly post-commit.
		go scim.RevokeAuthSessions(r.Context(), h.logger, h.authServerURL, h.internalAPIKey, id)
	}

	w.WriteHeader(http.StatusNoContent)

	if !publicationQueued && h.dispatcher != nil {
		h.dispatcher.DispatchForUser(r.Context(), id, wh.NewCloudEvent("mailserver/auth", wh.EventUserUpdated, map[string]interface{}{
			"user_id": id,
		}))
	}
}

// Delete removes a user and all associated data (mailboxes, messages, aliases).
// This is irreversible — the frontend should show a confirmation dialog.
func (h *UsersHandler) Delete(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	idStr := r.PathValue("id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "invalid user id"})
		return
	}

	if adminRefuseGuestTarget(ctx, h.pool, h.logger, w, r, id) {
		return
	}

	claims := auth.RequireUser(w, r)
	if claims == nil {
		return
	}
	actor := claims.UserID

	// Once the explicit mailbox lifecycle rail is enabled, the overloaded
	// compatibility DELETE may no longer erase a mailbox as a side effect. The
	// caller must choose detach-retain and, later, the independently approved
	// purge protocol. OFF preserves the bounded legacy rollback path.
	var lifecycleEnabled bool
	if err := h.workerPool.QueryRow(ctx, `SELECT mailbox_lifecycle_enabled()`).Scan(&lifecycleEnabled); err != nil {
		httputil.WriteDBErr(w, r, h.logger, "mailbox lifecycle gate failed", err)
		return
	}
	if lifecycleEnabled {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusConflict,
			Detail: "direct user deletion is disabled; suspend or detach and retain the mailbox, then use the approved purge workflow"})
		return
	}

	// Use a transaction to ensure everything is cleaned up atomically.
	// native-RLS W7: this admin delete fan-out wipes ANOTHER user's messages /
	// message_attachments (DELETE … WHERE mailbox_id IN (… user_id = $1)) — a
	// cross-tenant admin write. It is a PLAIN tx with NO app.current_mailbox_id,
	// so under the W6 FORCE flip the app role's policy would deny/orphan the
	// message deletes. It runs on the BYPASSRLS worker pool. workerPool aliases
	// pool until DB_WORKER_DSN is set (W1b), so this is INERT.
	tx, err := h.workerPool.Begin(ctx)
	if err != nil {
		httputil.WriteDBErr(w, r, h.logger, "user delete tx begin failed", err)
		return
	}
	defer tx.Rollback(ctx)

	// Rule B — reach check: target must be reachable by the actor.
	// Runs on the tx (snapshot consistency — same snapshot as the cascade below).
	if domainScope := middleware.DomainScopeFromContext(ctx); domainScope > 0 {
		// Domain-scoped actor: verify target's domain_id == domainScope in the same tx
		// (no TOCTOU); an out-of-scope or missing id is 404 — indistinguishable.
		var targetDomainID int64
		if err := tx.QueryRow(ctx,
			`SELECT domain_id FROM users WHERE id = $1 AND domain_id = $2`,
			id, domainScope).Scan(&targetDomainID); err != nil {
			if err == pgx.ErrNoRows {
				httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusNotFound, Detail: "user not found"})
				return
			}
			h.logger.Error("user delete scope check failed", "user_id", id, "error", err)
			httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusInternalServerError, Detail: "database error"})
			return
		}
		// ponytail: AND gate — domain check above passed; now enforce OU narrowing.
		// A domain-only actor (no OU assignment) short-circuits true in admin_can_reach.
		var canReach bool
		if err := tx.QueryRow(ctx, `
			SELECT admin_can_manage($1, $2)`, actor, id).Scan(&canReach); err != nil {
			h.logger.Error("user delete reach check (scoped) failed", "user_id", id, "error", err)
			httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusInternalServerError, Detail: "database error"})
			return
		}
		if !canReach {
			httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusNotFound, Detail: "user not found"})
			return
		}
	} else {
		// Unscoped actor: admin_can_reach enforces OU scope (and domain for any
		// domain-restricted assignments). Returns true for global actors (NULL scope
		// on every assignment).
		// ponytail: actors without any active DB assignments pass through — in
		// production every admin has at least one active assignment.
		var canReach bool
		if err := tx.QueryRow(ctx, `
			SELECT admin_can_manage($1, $2)`, actor, id).Scan(&canReach); err != nil {
			h.logger.Error("user delete reach check failed", "user_id", id, "error", err)
			httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusInternalServerError, Detail: "database error"})
			return
		}
		if !canReach {
			httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusNotFound, Detail: "user not found"})
			return
		}
	}

	// Protection check: reject deletes blocked by policy before the cascade.
	// Must run on the transaction (snapshot consistency — BZ065/BZ066 axes).
	if _, err := tx.Exec(ctx, `SELECT admin_protection_check($1,$2,'delete',NULL)`, actor, id); err != nil {
		if mapProtectionErr(h.pool, h.logger, w, r, err, actor, id) {
			return
		}
		h.logger.Error("user delete protection check failed", "user_id", id, "error", err)
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusInternalServerError, Detail: "database error"})
		return
	}

	// The gate controls only enrollment. When enabled, the reducer derives the
	// subject from the locked users row and inserts the approved publication fact
	// in this same destructive transaction. A later failure rolls both back.
	var publicationQueued bool
	if err := tx.QueryRow(ctx,
		`SELECT webhook_user_deleted_publish($1,$2)`, actor, id,
	).Scan(&publicationQueued); err != nil {
		h.logger.Error("user delete webhook publication failed", "user_id", id, "error", err)
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusInternalServerError, Detail: "database error"})
		return
	}

	// Clean up role assignments before the cascade (avoids orphaned RBAC rows
	// when cascade deletes race against concurrent role-assignment queries).
	if _, err := tx.Exec(ctx, `DELETE FROM admin_role_assignments WHERE user_id = $1`, id); err != nil {
		h.logger.Error("user delete role assignments failed", "user_id", id, "error", err)
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusInternalServerError, Detail: "database error"})
		return
	}

	// Delete aliases for user's primary mailbox first.
	_, err = tx.Exec(ctx, `
		DELETE FROM aliases WHERE mailbox_id IN (
			SELECT id FROM mailboxes WHERE user_id = $1
		)
	`, id)
	if err != nil {
		h.logger.Error("user delete aliases failed", "user_id", id, "error", err)
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusInternalServerError, Detail: "database error"})
		return
	}

	// Delete message attachments.
	_, err = tx.Exec(ctx, `
		DELETE FROM message_attachments WHERE message_id IN (
			SELECT id FROM messages WHERE mailbox_id IN (
				SELECT id FROM mailboxes WHERE user_id = $1
			)
		)
	`, id)
	if err != nil {
		h.logger.Error("user delete attachments failed", "user_id", id, "error", err)
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusInternalServerError, Detail: "database error"})
		return
	}

	// Delete messages.
	_, err = tx.Exec(ctx, `
		DELETE FROM messages WHERE mailbox_id IN (
			SELECT id FROM mailboxes WHERE user_id = $1
		)
	`, id)
	if err != nil {
		h.logger.Error("user delete messages failed", "user_id", id, "error", err)
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusInternalServerError, Detail: "database error"})
		return
	}

	// Delete folders.
	_, err = tx.Exec(ctx, `DELETE FROM folders WHERE mailbox_id IN (SELECT id FROM mailboxes WHERE user_id = $1)`, id)
	if err != nil {
		h.logger.Error("user delete folders failed", "user_id", id, "error", err)
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusInternalServerError, Detail: "database error"})
		return
	}

	// Delete mailboxes.
	_, err = tx.Exec(ctx, `DELETE FROM mailboxes WHERE user_id = $1`, id)
	if err != nil {
		h.logger.Error("user delete mailboxes failed", "user_id", id, "error", err)
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusInternalServerError, Detail: "database error"})
		return
	}

	// Delete user.
	// Delete sessions (refresh tokens) for this user.
	_, err = tx.Exec(ctx, `DELETE FROM sessions WHERE user_id = $1`, id)
	if err != nil {
		h.logger.Error("user delete sessions failed", "user_id", id, "error", err)
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusInternalServerError, Detail: "database error"})
		return
	}

	_, err = tx.Exec(ctx, `DELETE FROM users WHERE id = $1`, id)
	if err != nil {
		h.logger.Error("user delete failed", "user_id", id, "error", err)
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusInternalServerError, Detail: "database error"})
		return
	}

	if err := tx.Commit(ctx); err != nil {
		h.logger.Error("user delete tx commit failed", "user_id", id, "error", err)
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusInternalServerError, Detail: "database error"})
		return
	}

	// A deletion webhook describes committed state. Dispatch only after the
	// destructive transaction succeeds so a failed DELETE or COMMIT cannot
	// publish a user.deleted event for data that was rolled back.
	if !publicationQueued {
		h.dispatcher.DispatchForUser(r.Context(), id, wh.NewCloudEvent("mailserver/auth", wh.EventUserDeleted, map[string]interface{}{
			"user_id": id,
		}))
	}

	w.WriteHeader(http.StatusNoContent)
}

// ResetPassword sets a new bcrypt password for a user.
func (h *UsersHandler) ResetPassword(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)

	idStr := r.PathValue("id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "invalid user id"})
		return
	}

	claims := auth.RequireUser(w, r)
	if claims == nil {
		return
	}
	actor := claims.UserID

	var req struct {
		Password   string `json:"password"`
		MustChange *bool  `json:"mustChange,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "invalid JSON"})
		return
	}
	// Domain-scoped admins fold their domain into both the lookup and the
	// authoritative reducer below (R3). An out-of-scope id is 404 here and the
	// reducer repeats current domain+OU reach after locking the target.
	domainScope := middleware.DomainScopeFromContext(ctx)

	// Enforce OU scope via admin_can_reach for all actors (scoped and unscoped).
	// ponytail: actors without any active DB assignments pass through — in
	// production every admin has at least one active assignment.
	// For domainScope > 0: domain check is folded into the email lookup below;
	// this AND gate adds OU narrowing for stacked (domain+OU) admins.
	{
		var canReach bool
		if err := h.pool.QueryRow(ctx, `
			SELECT admin_can_manage($1, $2)`, actor, id).Scan(&canReach); err != nil {
			h.logger.Error("password reset reach check failed", "user_id", id, "error", err)
			httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusInternalServerError, Detail: "database error"})
			return
		}
		if !canReach {
			httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusNotFound, Detail: "user not found"})
			return
		}
	}

	// Look up user email for password validation context (on pool, not tx — this
	// is a read-only lookup and doesn't need snapshot consistency with the mutation).
	var targetEmail string
	var lookupErr error
	if domainScope > 0 {
		lookupErr = h.pool.QueryRow(ctx,
			`SELECT email FROM users
			  WHERE id = $1
			    AND COALESCE(guest_account_host_domain(id), domain_id) = $2`,
			id, domainScope,
		).Scan(&targetEmail)
	} else {
		lookupErr = h.pool.QueryRow(ctx, `SELECT email FROM users WHERE id = $1`, id).Scan(&targetEmail)
	}
	if lookupErr != nil {
		if lookupErr == pgx.ErrNoRows {
			httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusNotFound, Detail: "user not found"})
		} else {
			httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusInternalServerError, Detail: "database error"})
		}
		return
	}

	// Classify guests only after the privacy-preserving domain/OU checks above.
	// Otherwise an out-of-scope guest would return 409 while an out-of-scope
	// member returns 404, exposing account class across the authority boundary.
	if adminRefuseGuestTarget(ctx, h.pool, h.logger, w, r, id) {
		return
	}

	if err := h.validateAdminPassword(ctx, req.Password, targetEmail); err != nil {
		if ve, ok := err.(*validate.ValidationError); ok {
			httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: ve.ToFieldError().Message})
		} else {
			httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: err.Error()})
		}
		return
	}

	hash, err := auth.HashPassword(req.Password)
	if err != nil {
		h.logger.Error("password hash failed", "error", err)
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusInternalServerError, Detail: "password hashing failed"})
		return
	}

	mustChange := true
	if req.MustChange != nil {
		mustChange = *req.MustChange
	}

	// One reducer owns the current authorization decision, credential mutation,
	// complete session revocation, audit, and notification. It rechecks
	// admin_can_manage only after locking the final target state, closing a
	// department/domain move between the early privacy check and bcrypt.
	var revocationID int64
	err = h.pool.QueryRow(ctx,
		`SELECT admin_reset_password($1,$2,$3,$4,$5)`,
		actor, id, domainScope, hash, mustChange,
	).Scan(&revocationID)
	if err != nil {
		if mapProtectionErr(h.pool, h.logger, w, r, err, actor, id) {
			return
		}
		if writeResetPasswordReducerError(w, r, err) {
			return
		}
		httputil.WriteDBErr(w, r, h.logger, "password reset reducer failed", err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func writeResetPasswordReducerError(
	w http.ResponseWriter, r *http.Request, err error,
) bool {
	if reducererr.IsCode(err, "BZ060", "BZ061") {
		httputil.WriteProblem(w, r, &httputil.Problem{
			Status: http.StatusNotFound,
			Detail: "user not found",
		})
		return true
	}
	if reducererr.IsCode(err, "BZ221") {
		httputil.WriteProblem(w, r, &httputil.Problem{
			Status: http.StatusConflict,
			Detail: "guest accounts are managed via the guest console (/admin/guests), not the generic user endpoints",
		})
		return true
	}
	return false
}

// ListAliases returns aliases for a user's primary mailbox.
func (h *UsersHandler) ListAliases(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	idStr := r.PathValue("id")
	id, _ := strconv.ParseInt(idStr, 10, 64)
	if id <= 0 {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "invalid user id"})
		return
	}

	// Domain-scoped admins only see aliases of users in their domain; an
	// out-of-scope user id yields an empty set (the users join + domain predicate
	// filters it out).
	domainScope := middleware.DomainScopeFromContext(ctx)
	var rows pgx.Rows
	var err error
	if domainScope > 0 {
		rows, err = h.pool.Query(ctx, `
			SELECT a.id, a.email, a.is_primary
			FROM aliases a
			JOIN mailboxes m ON m.id = a.mailbox_id
			JOIN users u ON u.id = m.user_id
			WHERE m.user_id = $1 AND u.domain_id = $2
			ORDER BY a.is_primary DESC, a.email
		`, id, domainScope)
	} else {
		rows, err = h.pool.Query(ctx, `
			SELECT a.id, a.email, a.is_primary
			FROM aliases a
			JOIN mailboxes m ON m.id = a.mailbox_id
			WHERE m.user_id = $1
			ORDER BY a.is_primary DESC, a.email
		`, id)
	}
	if err != nil {
		httputil.WriteDBErr(w, r, h.logger, "list aliases failed", err)
		return
	}
	defer rows.Close()

	out := []map[string]any{}
	for rows.Next() {
		var aliasID int64
		var email string
		var isPrimary bool
		if err := rows.Scan(&aliasID, &email, &isPrimary); err == nil {
			out = append(out, map[string]any{"id": aliasID, "email": email, "isPrimary": isPrimary})
		}
	}

	httputil.WriteJSON(w, http.StatusOK, out)
}

// AddAlias creates an alias for a user's primary mailbox.
func (h *UsersHandler) AddAlias(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)

	idStr := r.PathValue("id")
	id, _ := strconv.ParseInt(idStr, 10, 64)
	if id <= 0 {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "invalid user id"})
		return
	}

	var req struct {
		Email string `json:"email"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "invalid JSON"})
		return
	}
	if req.Email == "" {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "email required"})
		return
	}

	// Domain-scoped admins may only add aliases for users in their own domain;
	// the domain predicate folds into the primary-mailbox resolution so an
	// out-of-scope user is 404 (primary mailbox not found) — indistinguishable.
	domainScope := middleware.DomainScopeFromContext(ctx)
	var mailboxID, domainID int64
	var resolveErr error
	if domainScope > 0 {
		resolveErr = h.pool.QueryRow(ctx, `
			SELECT id, domain_id FROM mailboxes WHERE user_id = $1 AND is_primary = TRUE AND domain_id = $2 LIMIT 1
		`, id, domainScope).Scan(&mailboxID, &domainID)
	} else {
		resolveErr = h.pool.QueryRow(ctx, `
			SELECT id, domain_id FROM mailboxes WHERE user_id = $1 AND is_primary = TRUE LIMIT 1
		`, id).Scan(&mailboxID, &domainID)
	}
	if resolveErr != nil {
		h.logger.Error("add alias find mailbox failed", "error", resolveErr)
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusNotFound, Detail: "primary mailbox not found"})
		return
	}

	// Validate AND canonicalize before the aliases.email write so the alias
	// matches the users.email fold (shared/identity.CanonicalizeAddress) — an
	// operator-typed mixed-case/whitespace alias must resolve identically to the
	// canonical primary, or the matcher would miss it. The mint replaces the
	// prior never-validating CanonicalizeAddress persist (which stored canonical
	// but structurally-unchecked strings, control characters included) and its
	// RFC 2142 reserved-local-part gate stops aliases from claiming system
	// identities; only a validated canonical address reaches aliases.email.
	validatedAlias, err := identity.ValidateAndCanonicalizeEmail(req.Email)
	if err != nil {
		if ve := new(validate.ValidationError); errors.As(err, &ve) {
			httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: ve.ToFieldError().Message})
		} else {
			httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: err.Error()})
		}
		return
	}
	var aliasID int64
	if err := h.pool.QueryRow(ctx, `
		INSERT INTO aliases (mailbox_id, email, domain_id) VALUES ($1, $2, $3) RETURNING id
	`, mailboxID, validatedAlias.String(), domainID).Scan(&aliasID); err != nil {
		h.logger.Error("add alias failed", "error", err)
		if pgErr, ok := err.(*pgconn.PgError); ok && pgErr.Code == "23505" {
			httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusConflict, Detail: "alias already exists"})
		} else {
			httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusInternalServerError, Detail: "database error"})
		}
		return
	}

	httputil.WriteJSON(w, http.StatusCreated, map[string]int64{"id": aliasID})
}

// RemoveAlias deletes an alias.
func (h *UsersHandler) RemoveAlias(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userIDStr := r.PathValue("id")
	userID, _ := strconv.ParseInt(userIDStr, 10, 64)
	aliasIDStr := r.PathValue("aliasId")
	aliasID, _ := strconv.ParseInt(aliasIDStr, 10, 64)
	if userID <= 0 || aliasID <= 0 {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "invalid id"})
		return
	}

	// Ensure alias belongs to user's primary mailbox. For a domain-scoped admin
	// the domain predicate folds into the SAME delete (R3) — an out-of-scope user
	// matches no mailbox, so the delete is a no-op.
	domainScope := middleware.DomainScopeFromContext(ctx)
	var err error
	if domainScope > 0 {
		_, err = h.pool.Exec(ctx, `
			DELETE FROM aliases WHERE id = $1 AND mailbox_id IN (
				SELECT id FROM mailboxes WHERE user_id = $2 AND is_primary = TRUE AND domain_id = $3
			)
		`, aliasID, userID, domainScope)
	} else {
		_, err = h.pool.Exec(ctx, `
			DELETE FROM aliases WHERE id = $1 AND mailbox_id IN (
				SELECT id FROM mailboxes WHERE user_id = $2 AND is_primary = TRUE
			)
		`, aliasID, userID)
	}
	if err != nil {
		httputil.WriteDBErr(w, r, h.logger, "remove alias failed", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// GetQuota returns mailbox quota for a user.
func (h *UsersHandler) GetQuota(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	idStr := r.PathValue("id")
	id, _ := strconv.ParseInt(idStr, 10, 64)
	if id <= 0 {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "invalid user id"})
		return
	}

	var q struct {
		QuotaBytes       int64 `json:"quotaBytes"`
		UsedBytes        int64 `json:"usedBytes"`
		SendingQuotaDay  int   `json:"sendingQuotaDay"`
		SendingSentToday int   `json:"sendingSentToday"`
	}
	// Domain-scoped admins only read quotas of users in their own domain; the
	// domain predicate folds into the resolving SELECT (out-of-scope → 404).
	domainScope := middleware.DomainScopeFromContext(ctx)
	var quotaErr error
	if domainScope > 0 {
		quotaErr = h.pool.QueryRow(ctx, `
			SELECT quota_bytes, used_bytes, sending_quota_day, sending_sent_today
			FROM mailboxes WHERE user_id = $1 AND is_primary = TRUE AND domain_id = $2 LIMIT 1
		`, id, domainScope).Scan(&q.QuotaBytes, &q.UsedBytes, &q.SendingQuotaDay, &q.SendingSentToday)
	} else {
		quotaErr = h.pool.QueryRow(ctx, `
			SELECT quota_bytes, used_bytes, sending_quota_day, sending_sent_today
			FROM mailboxes WHERE user_id = $1 AND is_primary = TRUE LIMIT 1
		`, id).Scan(&q.QuotaBytes, &q.UsedBytes, &q.SendingQuotaDay, &q.SendingSentToday)
	}
	if quotaErr != nil {
		h.logger.Error("get quota failed", "error", quotaErr)
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusNotFound, Detail: "mailbox not found"})
		return
	}

	httputil.WriteJSON(w, http.StatusOK, q)
}

// SetQuota updates mailbox quota for a user.
func (h *UsersHandler) SetQuota(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)

	idStr := r.PathValue("id")
	id, _ := strconv.ParseInt(idStr, 10, 64)
	if id <= 0 {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "invalid user id"})
		return
	}

	var req struct {
		QuotaBytes      *int64 `json:"quotaBytes,omitempty"`
		SendingQuotaDay *int   `json:"sendingQuotaDay,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "invalid JSON"})
		return
	}

	var sets []string
	var args []any
	argIdx := 1
	if req.QuotaBytes != nil && *req.QuotaBytes > 0 {
		sets = append(sets, "quota_bytes = $"+strconv.Itoa(argIdx))
		args = append(args, *req.QuotaBytes)
		argIdx++
	}
	if req.SendingQuotaDay != nil && *req.SendingQuotaDay > 0 {
		sets = append(sets, "sending_quota_day = $"+strconv.Itoa(argIdx))
		args = append(args, *req.SendingQuotaDay)
		argIdx++
	}
	if len(sets) == 0 {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "no fields to update"})
		return
	}

	args = append(args, id)
	query := "UPDATE mailboxes SET " + strings.Join(sets, ", ") + " WHERE user_id = $" + strconv.Itoa(argIdx) + " AND is_primary = TRUE"
	argIdx++
	// Domain-scoped admins fold their domain into the SAME mutating statement
	// (R3); an out-of-scope user matches no mailbox → 0 rows → 404.
	if domainScope := middleware.DomainScopeFromContext(ctx); domainScope > 0 {
		query += " AND domain_id = $" + strconv.Itoa(argIdx)
		args = append(args, domainScope)
	}
	tag, err := h.pool.Exec(ctx, query, args...)
	if err != nil {
		httputil.WriteDBErr(w, r, h.logger, "set quota failed", err)
		return
	}
	if tag.RowsAffected() == 0 {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusNotFound, Detail: "mailbox not found"})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ImportCSV bulk-creates users from an uploaded CSV file.
// Expected columns: email, display_name, password, is_local_admin, department_id, quota_bytes
// All rows are processed independently — one row failing does not block others.
func (h *UsersHandler) ImportCSV(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	r.Body = http.MaxBytesReader(w, r.Body, 10<<20)        // 10MB max
	if err := r.ParseMultipartForm(10 << 20); err != nil { //nolint:gosec // G120: bounded by MaxBytesReader (10MB) above
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "invalid multipart form"})
		return
	}
	file, _, err := r.FormFile("file")
	if err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "file required"})
		return
	}
	defer file.Close()

	reader := csv.NewReader(file)
	headers, err := reader.Read()
	if err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "unable to read CSV headers"})
		return
	}

	colIdx := make(map[string]int)
	for i, h := range headers {
		colIdx[strings.ToLower(strings.TrimSpace(h))] = i
	}
	required := []string{"email", "password"}
	for _, col := range required {
		if _, ok := colIdx[col]; !ok {
			httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "missing required CSV column: " + col})
			return
		}
	}

	type rowErr struct {
		Row   int    `json:"row"`
		Email string `json:"email"`
		Error string `json:"error"`
	}

	var created int
	var failed []rowErr
	rowNum := 1 // header is row 0

	// Domain-scoped admins (claims.DomainScope) may only import users into their
	// own domain — mirroring Create's 403 gate. Read the scope once before the
	// loop; each row whose resolved domain differs is rejected per-row (added to
	// `failed`, like every other bad-row case here) so the partial-success/skip
	// semantics are preserved. domainScope == 0 (global admin) → no per-row gate.
	domainScope := middleware.DomainScopeFromContext(ctx)
	// Rule B narrowing (D-MAILSERVER-INTERNAL-ADMIN-F-007): an OU-confined
	// actors.create holder must not place imported users into an out-of-reach
	// department. Same admin_scope_within('ou', dept) guard AssignUser enforces,
	// resolved per row (dept placement is the row's own data). Resolved once:
	// the actor id and grant-domain come from the request context.
	var csvActorID int64
	if claims := auth.UserFromContext(ctx); claims != nil {
		csvActorID = claims.UserID
	}
	var csvGrantDomain *int64
	if domainScope > 0 {
		csvGrantDomain = &domainScope
	}

	// Read password policy once before the loop (avoid per-row DB queries).
	policy, policyErr := pwhash.LoadPasswordPolicy(ctx, h.pool)
	if policyErr != nil {
		policy = validate.PasswordPolicy{MinLength: 8, RequireUppercase: true, RequireLowercase: true, RequireDigit: true, RequireSpecial: true}
	}

	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			rowNum++
			h.logger.Warn("csv parse error", "row", rowNum, "error", err)
			failed = append(failed, rowErr{Row: rowNum, Error: "Failed to parse CSV row. The file may be malformed."})
			continue
		}
		rowNum++

		email := strings.TrimSpace(record[colIdx["email"]])
		password := strings.TrimSpace(record[colIdx["password"]])
		if email == "" || password == "" {
			failed = append(failed, rowErr{Row: rowNum, Email: email, Error: "email and password required"})
			continue
		}
		// Validate AND canonicalize the row's email in one step — the mint that
		// produces the identity.ValidatedAddress ProvisionAccount demands. A
		// malformed CSV email is rejected per-row (partial-success preserved)
		// instead of reaching the write; valid rows are canonicalized identically
		// to AD/LDAP/admin-create.
		validatedEmail, err := identity.ValidateAndCanonicalizeEmail(email)
		if err != nil {
			if ve := new(validate.ValidationError); errors.As(err, &ve) {
				failed = append(failed, rowErr{Row: rowNum, Email: email, Error: ve.ToFieldError().Message})
			} else {
				failed = append(failed, rowErr{Row: rowNum, Email: email, Error: err.Error()})
			}
			continue
		}
		// Validate password against policy, common passwords, and email inclusion.
		// DisallowEmail gets the canonical validated row address, not the raw CSV
		// string, so quoted-local/display-name rows cannot dodge containment.
		policy.DisallowEmail = validatedEmail.String()
		if err := validate.ValidatePassword(password, policy); err != nil {
			if ve, ok := err.(*validate.ValidationError); ok {
				failed = append(failed, rowErr{Row: rowNum, Email: email, Error: ve.ToFieldError().Message})
			} else {
				failed = append(failed, rowErr{Row: rowNum, Email: email, Error: err.Error()})
			}
			continue
		}
		if common, err := pwhash.CheckCommonPassword(ctx, h.pool, password); err == nil && common {
			failed = append(failed, rowErr{Row: rowNum, Email: email, Error: "This password is too common and easily guessed. Please choose a stronger password."})
			continue
		}

		displayName := ""
		if idx, ok := colIdx["display_name"]; ok && idx < len(record) {
			displayName = strings.TrimSpace(record[idx])
		}

		isLocalAdmin := false
		if idx, ok := colIdx["is_local_admin"]; ok && idx < len(record) {
			isLocalAdmin, _ = strconv.ParseBool(strings.TrimSpace(record[idx]))
		}

		var deptID *int64
		if idx, ok := colIdx["department_id"]; ok && idx < len(record) {
			if v, err := strconv.ParseInt(strings.TrimSpace(record[idx]), 10, 64); err == nil && v > 0 {
				deptID = &v
			}
		}
		// Department scope gate (per-row, partial-success preserved): mirrors
		// AssignUser's admin_scope_within('ou', deptID) — an OU-narrowed admin
		// bulk-importing users must not reach departments outside their subtree.
		// Unconfined (global) actors pass via admin_scope_within's NULL-scope arm.
		if deptID != nil && csvActorID > 0 {
			var scopeOK bool
			if err := h.pool.QueryRow(ctx, `SELECT admin_scope_within($1, $2, $3, $4)`,
				csvActorID, "ou", *deptID, csvGrantDomain).Scan(&scopeOK); err != nil {
				h.logger.Error("csv import scope_within check failed", "row", rowNum, "error", err)
				failed = append(failed, rowErr{Row: rowNum, Email: email, Error: "department scope check failed"})
				continue
			}
			if !scopeOK {
				failed = append(failed, rowErr{Row: rowNum, Email: email, Error: "department not within your administrative scope"})
				continue
			}
		}

		var quotaBytes *int64
		if idx, ok := colIdx["quota_bytes"]; ok && idx < len(record) {
			if v, err := strconv.ParseInt(strings.TrimSpace(record[idx]), 10, 64); err == nil && v > 0 {
				quotaBytes = &v
			}
		}

		hash, err := auth.HashPassword(password)
		if err != nil {
			failed = append(failed, rowErr{Row: rowNum, Email: email, Error: "password hashing failed"})
			continue
		}

		// Require an existing local domain (provision_account would otherwise
		// auto-create it; imported users must land in a configured domain).
		resolvedDomainID, err := h.resolveLocalDomain(ctx, email)
		if err != nil {
			failed = append(failed, rowErr{Row: rowNum, Email: email, Error: "email domain is not a local domain"})
			continue
		}

		// Domain-scoped admins may only import into their own domain. Reject this
		// row (per-row, preserving partial-success) when its resolved domain
		// differs from the scope — same 403 reason Create surfaces.
		if domainScope > 0 && resolvedDomainID != domainScope {
			failed = append(failed, rowErr{Row: rowNum, Email: email, Error: "email domain is not in your domain scope"})
			continue
		}

		if displayName == "" {
			displayName = email
		}

		// Person + primary mailbox via the single provisioning seam (atomic in
		// one reducer call). p_quota_bytes is NULL unless the CSV supplied one.
		// The CSV email was validated AND canonicalized above into validatedEmail —
		// the ValidatedAddress param makes a raw/unvalidated CSV string a compile
		// error, so an imported address is folded identically to AD/LDAP/admin-create
		// and is structurally valid by the time it reaches the write.
		// Bulk CSV import: intentionally NO welcome email. Mass imports must not
		// flood every imported user (spec §7). Admins enable per-user welcomes via
		// single-create; the org toggle is at /admin/system/welcome-email.
		enabled := true
		csvAdmin := isLocalAdmin
		var csvActor *int64
		if csvActorID != 0 {
			id := csvActorID
			csvActor = &id
		}
		provision, err := identity.ProvisionAccount(ctx, h.pool, identity.ProvisionAccountParams{
			Email:        validatedEmail,
			DisplayName:  displayName,
			PasswordHash: hash,
			IsLocalAdmin: &csvAdmin,
			Enabled:      &enabled,
			SyncSource:   "local",
			DepartmentID: deptID,
			QuotaBytes:   quotaBytes,
			CreateOnly:   true,
			ActorID:      csvActor, // nil when the import ran without an admin context

		})
		if err != nil {
			msg := "database error"
			if pgErr, ok := err.(*pgconn.PgError); ok && pgErr.Code == "23505" {
				msg = "user already exists"
			}
			failed = append(failed, rowErr{Row: rowNum, Email: email, Error: msg})
			continue
		}
		var prov struct {
			Created bool `json:"created"`
		}
		if err := json.Unmarshal(provision, &prov); err != nil || !prov.Created {
			failed = append(failed, rowErr{Row: rowNum, Email: email, Error: "user already exists"})
			continue
		}

		created++
	}

	httputil.WriteJSON(w, http.StatusOK, map[string]any{
		"created": created,
		"failed":  failed,
	})
}
