package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"setjoin.com/authserver/internal/token"
	sharedauth "setjoin.com/shared/auth"
	"setjoin.com/shared/httputil"
	"setjoin.com/shared/middleware"
	"setjoin.com/shared/permissions"
	"setjoin.com/shared/pgnotify"
	"setjoin.com/shared/pgxutil"
	"setjoin.com/shared/threat"
	"setjoin.com/shared/toggle"
)

const configListenerRetryDelay = 5 * time.Second

type configChangeListener interface {
	OnReconnect(func(context.Context) error)
	RegisterReconnect(func(context.Context) error) func()
	SubscribeDurable(context.Context, string, pgnotify.NotifyHandler) (int, error)
	Unsubscribe(string, int)
}

type configListenerFactory func(context.Context, string) (configChangeListener, error)

type featureFlagRuntime interface {
	IsEnabled(string) bool
	OnNotify(string, bool)
	Reload(context.Context) error
}

type conditionalAccessRuntime interface {
	InvalidateCache()
	SetBreakGlass([]int64)
}

func openConfigListener(
	ctx context.Context,
	directDSN string,
	poolDSN string,
	name string,
	logger *slog.Logger,
) (configChangeListener, error) {
	conn, err := pgxutil.OpenDirectConn(ctx, directDSN, poolDSN)
	if err != nil {
		return nil, err
	}
	listener := pgnotify.NewListener(conn, logger.With("listener", name))
	if directDSN != "" {
		listener.SetDSN(directDSN)
	} else {
		listener.SetDSN(poolDSN)
	}
	go listener.Run(ctx)
	return listener, nil
}

func waitConfigListenerRetry(ctx context.Context) bool {
	timer := time.NewTimer(configListenerRetryDelay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func superviseOptionalConfigListener(
	ctx context.Context,
	logger *slog.Logger,
	name string,
	open configListenerFactory,
	register func(configChangeListener) error,
	wait func(context.Context) bool,
) {
	// #340/#341 transfer these named listeners only. Other process-local caches keep
	// running until their own transfer or the whole-process retirement.
	if name == "oidc_rp" || name == "saml_sp" {
		for _, disabled := range strings.Split(os.Getenv("GO_WORKERS_OFF"), ",") {
			if strings.TrimSpace(disabled) == name {
				logger.Info("configuration listener transferred to Rust", "listener", name)
				return
			}
		}
	}

	for {
		if ctx.Err() != nil {
			return
		}
		attemptCtx, cancel := context.WithCancel(ctx)
		listener, err := open(attemptCtx, name)
		if err == nil {
			err = register(listener)
		}
		if err == nil {
			// The listener Run goroutine owns attemptCtx for the remainder of the
			// process lifetime. Ensure the explicit attempt cancel is also consumed
			// when the parent ends; the parent-to-child propagation remains primary.
			context.AfterFunc(ctx, cancel)
			return
		}
		cancel()
		logger.Warn("configuration listener setup failed; retrying",
			"listener", name, "error", err)
		if !wait(ctx) {
			return
		}
	}
}

func newConditionalAccessReloader(
	runtime conditionalAccessRuntime,
	loadBreakGlass func(context.Context) ([]int64, error),
) func(context.Context) error {
	return func(ctx context.Context) error {
		runtime.InvalidateCache()
		breakGlass, err := loadBreakGlass(ctx)
		if err != nil {
			// Never retain an exclusion after its authoritative snapshot became
			// unreadable. Empty break-glass is the fail-closed posture.
			runtime.SetBreakGlass(nil)
			return err
		}
		runtime.SetBreakGlass(breakGlass)
		return nil
	}
}

func configureConditionalAccessListener(
	ctx context.Context,
	listener configChangeListener,
	reload func(context.Context) error,
	logger *slog.Logger,
) error {
	listener.OnReconnect(reload)
	_, err := listener.SubscribeDurable(ctx, threat.ConditionalAccessChannel, func(*pgconn.Notification) {
		if err := reload(ctx); err != nil {
			logger.Error("conditional access cache reload failed", "error", err)
		}
	})
	if err != nil {
		return err
	}
	return reload(ctx)
}

func credentialRouteHandlers(
	login http.Handler,
	refresh http.Handler,
	flags featureFlagRuntime,
	threatMiddleware func(http.Handler) http.Handler,
) (http.Handler, http.Handler) {
	return dynamicCredentialHandler(login, flags, threatMiddleware),
		dynamicCredentialHandler(refresh, flags, threatMiddleware)
}

func dynamicCredentialHandler(
	next http.Handler,
	flags featureFlagRuntime,
	threatMiddleware func(http.Handler) http.Handler,
) http.Handler {
	// CSRF is a credential-route invariant, not a threat feature: it is mounted
	// on BOTH branches so disabling the five threat toggles can never drop the
	// sole origin check from login/refresh (D-AUTHSERVER-CMD-AUTHSERVERD-001).
	// The threat middleware stays outside CSRF, unchanged, when any is enabled.
	csrfProtected := middleware.CSRF(next)
	protected := threatMiddleware(csrfProtected)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if anyThreatFeatureEnabled(flags) {
			protected.ServeHTTP(w, r)
			return
		}
		csrfProtected.ServeHTTP(w, r)
	})
}

// anyThreatFeatureEnabled reports whether ANY admission control the threat
// interceptor pipeline owns is live, and therefore whether credential routes
// need the interceptor mounted at all. Every interceptor control MUST be
// represented here or toggling on only that control silently bypasses it on
// login/refresh — exactly the fail-open bug class the interceptor's own
// fast-path documents for FeatureRateLimit (shared/threat/interceptor.go
// "Every active control MUST be represented here"): enabling only the rate
// limiter (the seeded default, feature.rate_limit=true) must keep the pipeline
// — and with it stepRateLimit's per-IP admission cap — live on credential
// routes (ER5 occ_c1905b449b2220c3d02fcf5e).
func anyThreatFeatureEnabled(flags featureFlagRuntime) bool {
	return flags.IsEnabled(toggle.FeatureThreatFeed) ||
		flags.IsEnabled(toggle.FeatureGeoBlock) ||
		flags.IsEnabled(toggle.FeatureSprayDetect) ||
		flags.IsEnabled(toggle.FeatureCaptcha) ||
		flags.IsEnabled(toggle.FeatureTarpit) ||
		flags.IsEnabled(toggle.FeatureRateLimit)
}

// impersonationPermissionResolver resolves the live governed permission set of
// a user. main.go binds it to permissions.ResolveAuthority — the single source
// of truth that minted the JWT's own permission projection — so the mount and
// the mint agree by sharing code.
type impersonationPermissionResolver func(ctx context.Context, userID int64) (permissions.Authority, error)

// impersonationDenialAuditor records a refused impersonation attempt. main.go
// binds it to the audit_log row the handler itself writes on refusals.
type impersonationDenialAuditor func(r *http.Request, userID int64)

// requireImpersonatePermission gates the DIRECT authserver impersonation mount
// on the actor's governed users.impersonate grant (ER5
// occ_beacdec12aebffd6bf626c41). The handler only re-validates that the actor
// is *an* admin; the console path additionally requires the discrete
// users.impersonate permission through the gateway console guard
// (mailserver/internal/middleware/console_guard.go RequirePermAudited — the
// same deny-by-default permissions.HasPermission set-membership semantics).
// A governed admin WITHOUT that grant could therefore walk past the console,
// call the authserver directly, and mint an impersonation session. This gate
// binds the same permission the console requires, resolved through the same
// live governed-assignment resolver the login mint uses
// (permissions.ResolveAuthority: multi-role union, expires_at and
// admin_assignment_active honored), so a demoted or expired grant stops
// authorizing immediately. Fail-closed: a resolution error denies and logs,
// never admits.
//
// The gate re-validates the request through the SAME shared Authenticator seam
// RequireAuth uses (the composition root has no access to the handler
// package's unexported context key), so it must be mounted INSIDE
// requireAuth — an unauthenticated request receives RequireAuth's canonical
// 401 before this gate runs.
func requireImpersonatePermission(
	authn sharedauth.Authenticator,
	resolve impersonationPermissionResolver,
	audit impersonationDenialAuditor,
	logger *slog.Logger,
) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims, err := authn.Authenticate(r.Context(), r)
			if err != nil {
				if errors.Is(err, token.ErrWrongTokenType) {
					httputil.WriteProblemStatus(w, http.StatusForbidden, "Invalid token type")
					return
				}
				w.Header().Set("WWW-Authenticate", `Bearer realm="authserver"`)
				httputil.WriteProblemStatus(w, http.StatusUnauthorized, "Unauthorized")
				return
			}
			if !claims.IsAdmin {
				httputil.WriteProblemStatus(w, http.StatusForbidden, "admin access required")
				return
			}

			authority, err := resolve(r.Context(), claims.UserID)
			if err != nil {
				logger.Warn("impersonation permission resolution failed; denying (fail closed)",
					"actor_id", claims.UserID, "error", err)
				httputil.WriteProblemStatus(w, http.StatusForbidden, "Forbidden")
				return
			}
			if !permissions.HasPermission(authority.Permissions, permissions.PermUsersImpersonate) {
				logger.Warn("impersonation refused: actor lacks the users.impersonate permission",
					"actor_id", claims.UserID)
				if audit != nil {
					audit(r, claims.UserID)
				}
				httputil.WriteProblemStatus(w, http.StatusForbidden, "Forbidden")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
