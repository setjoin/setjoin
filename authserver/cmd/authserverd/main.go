package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/oschwald/geoip2-golang"
	"github.com/rs/cors"
	"github.com/zitadel/oidc/v3/pkg/op"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"

	"setjoin.com/shared/cryptokey"
	shareddevice "setjoin.com/shared/device"
	"setjoin.com/shared/pgxutil"
	"setjoin.com/shared/push"

	"setjoin.com/authserver/internal/authn"
	"setjoin.com/authserver/internal/config"
	"setjoin.com/authserver/internal/connector"
	connectorad "setjoin.com/authserver/internal/connector/ad"
	connectorlocal "setjoin.com/authserver/internal/connector/local"
	"setjoin.com/authserver/internal/device"
	"setjoin.com/authserver/internal/federation"
	"setjoin.com/authserver/internal/handlers"
	"setjoin.com/authserver/internal/middleware"
	"setjoin.com/authserver/internal/token"
	maildbschema "setjoin.com/mailserver/sql/dbschema"
	sharedcfg "setjoin.com/shared/config"
	"setjoin.com/shared/httputil"
	sharedmw "setjoin.com/shared/middleware"
	"setjoin.com/shared/permissions"
	"setjoin.com/shared/threat"
	"setjoin.com/shared/toggle"
)

const guestInviteAcceptBodyLimit int64 = 1 << 20

// webauthnRegistrationBodyLimit caps the WebAuthn registration ceremony
// bodies (ER5 occ_243999e65729c68c82041ce8, maxbytes-body-cap control): a
// real attestation object is a few KB (packed/self attestation) and even
// certificate-based attestations stay far below 64KB, so the cap admits every
// legitimate authenticator while refusing unbounded admission before JSON
// decode. Mirrors the telemetry 64KB precedent
// (mailserver/internal/telemetry/handler.go:97-98) via limitRequestBody.
const webauthnRegistrationBodyLimit int64 = 64 << 10

// pushDeviceRegistrationBodyLimit caps /auth/device/register bodies (ER5
// occ_fd402745b2ea6bc50f8a9d14): a native push token or a WebPush
// PushSubscription JSON is at most a few KB; 64KB (telemetry precedent) leaves
// orders-of-magnitude headroom while bounding the storage side of the
// registration amplification. The fan-out side is bounded by mounting the
// threat interceptor (per-IP admission) on the route.
const pushDeviceRegistrationBodyLimit int64 = 64 << 10

// reloadReport is the honest outcome of a hot reload: which security seams
// re-armed live and which boot-time consumers keep their pre-reload values
// until restart. It replaces the previous unconditional {"status":"reloaded"}
// response that reported success while boot-time consumers kept the old
// values (D-AUTHSERVER-CMD-AUTHSERVERD-002).
type reloadReport struct {
	Rearmed         []string `json:"rearmed"`
	RestartRequired []string `json:"restart_required"`
}

// restartBoundConfigConsumers names the security-relevant config consumers
// this composition root captures at boot and cannot re-arm live:
//   - threat_settings: threat.ThreatConfig (spray/captcha/tarpit/rate/geo) is
//     baked into the threat interceptor at boot;
//   - jwt_secret_derived_material: the JWT provider, ES256 signing keystore,
//     cookie key and OIDC OP crypto key all derive from JWT_SECRET at boot;
//   - sso_and_authn_boot_options: env-seeded SSO toggle rows and auth-handler
//     options captured at construction (super-admin mapping, JIT, cookie
//     Secure, trust proxy).
var restartBoundConfigConsumers = []string{
	"threat_settings",
	"jwt_secret_derived_material",
	"sso_and_authn_boot_options",
}

// reloadCommitMu serializes commitReload. Both reload entry points — the
// HTTP /admin/reload handler goroutine and the SIGHUP drain goroutine — funnel
// through commitReload concurrently. Without this lock their Store/rebuild
// halves could interleave (A stores, B stores and rebuilds, A's stale rebuild
// overwrites B's handlers), leaving the published config and the rebuilt
// introspect/revoke handlers in different reload generations: the dynamic
// RequireAPIKey gates would serve one key while introspect/revoke retained
// another (Astra wave89 P2, med-shard3-001).
var reloadCommitMu sync.Mutex

// commitReload publishes a freshly loaded config and re-arms every consumer
// the composition root can update live: the config pointer behind the dynamic
// RequireAPIKey gates (/auth/scim/disable, /admin/reload) and the
// introspect/revoke handler pair via rebuild, so a rotated INTERNAL_API_KEY
// takes effect on all four without restart. Config values captured at boot by
// other consumers are reported restart-required rather than silently retained.
//
// Publication is serialized by reloadCommitMu so the Store and rebuild always
// land as ONE generation: overlapping reloads apply whole, and the final
// published config always matches the final rebuilt handlers.
func commitReload(
	cfgPtr *sharedcfg.ConfigPtr[config.Config],
	rebuild func(*config.Config),
	newCfg *config.Config,
) reloadReport {
	reloadCommitMu.Lock()
	defer reloadCommitMu.Unlock()
	cfgPtr.Store(newCfg)
	if rebuild != nil {
		rebuild(newCfg)
	}
	return reloadReport{
		Rearmed:         []string{"internal_api_key"},
		RestartRequired: restartBoundConfigConsumers,
	}
}

// requireAPIKeyLive resolves the current INTERNAL_API_KEY from the live config
// pointer on every request and delegates to the shared RequireAPIKey
// middleware, so a hot reload re-arms the gate without restart. A missing
// pointer or an empty key fails closed through RequireAPIKey's empty-key
// behavior (500), never open.
func requireAPIKeyLive(cfgPtr *sharedcfg.ConfigPtr[config.Config]) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			apiKey := ""
			if cur := cfgPtr.Load(); cur != nil {
				apiKey = cur.InternalAPIKey
			}
			middleware.RequireAPIKey(apiKey)(next).ServeHTTP(w, r)
		})
	}
}

func oidcProviderCORSOptions(hostname, configured string) *cors.Options {
	origins := []string{"https://" + hostname}
	seen := map[string]struct{}{origins[0]: {}}
	for _, origin := range splitCSV(configured) {
		origin = strings.TrimRight(origin, "/")
		if _, ok := seen[origin]; ok {
			continue
		}
		seen[origin] = struct{}{}
		origins = append(origins, origin)
	}
	return &cors.Options{
		AllowedOrigins: origins,
		AllowedHeaders: []string{
			"Origin", "Accept", "Accept-Language", "Authorization",
			"Content-Type", "X-Requested-With",
		},
		AllowedMethods: []string{http.MethodGet, http.MethodHead, http.MethodPost},
		ExposedHeaders: []string{"Location", "Content-Length"},
		// OIDC requests use authorization codes, PKCE, client authentication,
		// and bearer tokens. Browser cookies are not a cross-origin credential.
		AllowCredentials: false,
	}
}

func limitRequestBody(limit int64, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, limit)
		body, err := io.ReadAll(r.Body)
		_ = r.Body.Close()
		if err != nil {
			var tooLarge *http.MaxBytesError
			if errors.As(err, &tooLarge) {
				http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
				return
			}
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		r.ContentLength = int64(len(body))
		next.ServeHTTP(w, r)
	})
}

// ── Auth listen address resolution (D-AUTHSERVER-CMD-AUTHSERVERD-005, option a) ──
//
// The authserver's listen address is DERIVED from AUTHSERVER_URL — the same
// derivation deploy/scripts/install.sh has always applied when rendering
// auth.env ("AUTH_LISTEN=${AUTHSERVER_URL#http://}": strip scheme, strip path,
// keep host:port). AUTHSERVER_URL is the address the gateway proxies auth
// traffic to, so it is the reachability contract the bind address must
// satisfy. The derivation may legitimately name a non-loopback host (split
// gateway/authserver hosts); on the standard single-node deploy it resolves
// to 127.0.0.1:8443.
//
// Resolution precedence, most explicit first:
//  1. LISTEN_ADDR env (auth.env override / process env) — the operator's
//     explicit bind. config.Load applies env over YAML, so when the env var
//     is set, cfg.ListenAddr already IS this value.
//  2. A SETJOIN_CONFIG YAML listen.addr key — explicit operator config, kept
//     as-is. Presence is tracked by config.Load (cfg.ListenAddrExplicit), NOT
//     inferred from value equality: an operator who explicitly writes
//     listen.addr: ":8443" — the same text as the compiled default — has
//     stated intent, and that address must win over AUTHSERVER_URL exactly
//     like any other explicit bind (AUTHSERVERD-005 finding 1).
//  3. AUTHSERVER_URL host:port — installer-parity derivation, applied only
//     when nothing above resolved an explicit address. This repairs the
//     silent failure mode where a missing or mis-ordered auth.env left
//     authserverd on the all-interfaces ":8443" default while the gateway
//     called a different AUTHSERVER_URL.
//  4. The compiled ":8443" default (config post-processing), unchanged — but
//     see the refusal below.
//
// STARTUP REFUSAL (AUTHSERVERD-005 finding 2, schema-mismatch precedent):
// when the EFFECTIVE listen address binds beyond loopback (an all-interfaces
// wildcard like ":8443" or a non-loopback host) AND AUTHSERVER_URL is absent
// or not a usable http(s) URL, main exits instead of listening: an exposed
// auth port with no configured reachability contract is a misconfiguration,
// not a default to ship. The error names the remediation — bind loopback via
// authserver.listen.addr/LISTEN_ADDR, or configure a valid AUTHSERVER_URL.
// Loopback binds stay allowed without AUTHSERVER_URL.
//
// The resolved address and its derivation source are logged at Debug on every
// boot and named in the Info startup line ("listen_source"). A derived
// NON-LOOPBACK listen (valid AUTHSERVER_URL, so no refusal) logs a WARN — not
// a refusal, split-host is a supported topology — asking the operator to
// verify the exposure is intentional; loopback results and explicit overrides
// stay silent.
const (
	// authListenPortFallback is the authserver stock port, applied when a
	// parsed AUTHSERVER_URL carries no explicit port (install.sh standardizes
	// on 8443).
	authListenPortFallback = "8443"
)

// Listen address derivation sources, reported in the startup logs.
const (
	listenSourceEnv     = "LISTEN_ADDR"    // explicit env override (auth.env / process env)
	listenSourceYAML    = "listen.addr"    // explicit SETJOIN_CONFIG YAML listen.addr
	listenSourceAuthURL = "AUTHSERVER_URL" // derived from the gateway-facing URL (installer parity)
	listenSourceDefault = "default"        // compiled-in :8443
)

// resolvedAuthListen is the boot-time outcome of listen address resolution.
// The listen address is boot-time by construction (http.Server is built once),
// so the resolution result is consumed once and never re-armed by reloads.
type resolvedAuthListen struct {
	Addr    string // host:port for http.Server.Addr
	Source  string // one of the listenSource* constants
	Derived bool   // true when Addr was derived from AUTHSERVER_URL (precedence case 3)
	// NonLoopback reports whether Addr binds beyond the loopback interface —
	// a non-loopback IP/hostname OR an empty host (":8443" binds all
	// interfaces). Informational: only a DERIVED non-loopback bind WARNs.
	NonLoopback bool
}

// resolveAuthListenAddr resolves the effective listen address per the
// precedence documented above. It returns an error — a startup refusal, not a
// warning — when the effective address binds beyond loopback while
// AUTHSERVER_URL is absent or unparseable (see the block comment). On success
// it logs the resolved address + source at Debug and a WARN when an
// AUTHSERVER_URL-derived bind is non-loopback.
func resolveAuthListenAddr(cfg *config.Config, listenAddrFromEnv bool, authserverURL string, logger *slog.Logger) (resolvedAuthListen, error) {
	res := resolvedAuthListen{Addr: cfg.ListenAddr, Source: listenSourceDefault}

	switch {
	case listenAddrFromEnv:
		// Case 1: explicit LISTEN_ADDR (auth.env / process env). The env
		// layer beats YAML in config.Load, so cfg.ListenAddr is this value.
		res.Source = listenSourceEnv
	case cfg.ListenAddrExplicit:
		// Case 2: explicit YAML listen.addr (LISTEN_ADDR env unset). Presence
		// is tracked by config.Load — an explicit ":8443" is still explicit
		// (AUTHSERVERD-005 finding 1).
		res.Source = listenSourceYAML
	default:
		// Case 3: nothing explicit — derive from AUTHSERVER_URL (installer
		// parity, see the block comment above).
		if host, port, ok := authserverURLHostPort(authserverURL); ok {
			res.Addr = net.JoinHostPort(host, port)
			res.Source = listenSourceAuthURL
			res.Derived = true
		}
		// Case 4: unparseable/absent AUTHSERVER_URL — the config-provided
		// compiled default survives into res.Addr, and the refusal below
		// decides whether that default may listen.
	}

	res.NonLoopback = !isLoopbackListenHost(listenHost(res.Addr))

	// Startup refusal: an effective non-loopback/wildcard bind with no usable
	// AUTHSERVER_URL means the operator never stated a reachability contract.
	// Defaulting such a bind to listening exposed the auth port on every
	// interface (AUTHSERVERD-005 finding 2). When a URL was configured but is
	// unusable, the refusal names it so the bad value is visible in the boot
	// log (r3 P2: an out-of-range URL port previously counted as usable).
	if _, _, urlOK := authserverURLHostPort(authserverURL); res.NonLoopback && !urlOK {
		urlState := "absent"
		if authserverURL != "" {
			urlState = fmt.Sprintf("not a usable http(s) URL (%q)", authserverURL)
		}
		return res, fmt.Errorf(
			"effective auth listen address %q binds beyond loopback (all-interfaces or non-loopback host) while AUTHSERVER_URL is %s — refusing startup: set authserver.listen.addr (or LISTEN_ADDR) to an explicit loopback bind, or configure a valid AUTHSERVER_URL (scheme://host[:port]) so the listen address derives from the gateway contract",
			res.Addr,
			urlState,
		)
	}

	if res.Derived && res.NonLoopback {
		logger.Warn(
			"auth listen address derived from a non-loopback AUTHSERVER_URL — verify this exposure is intentional "+
				"(split-host deployments are legitimate; single-node deploys should bind loopback, e.g. LISTEN_ADDR=127.0.0.1:8443)",
			"addr", res.Addr,
			"authserver_url", authserverURL,
		)
	}
	logger.Debug("auth listen address resolved",
		"addr", res.Addr,
		"source", res.Source,
		"derived_from_authserver_url", res.Derived,
		"non_loopback", res.NonLoopback)
	return res, nil
}

// authserverURLHostPort extracts the listen host:port an AUTHSERVER_URL
// implies, mirroring install.sh's shell derivation. Only http/https are
// accepted — any other scheme, an unparseable URL, an empty host, or an
// explicit port outside 1..65535 is not a usable bind contract and reports
// !ok. A URL without a port falls back to the stock 8443.
func authserverURLHostPort(raw string) (host, port string, ok bool) {
	if raw == "" {
		return "", "", false
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return "", "", false
	}
	host = u.Hostname()
	if host == "" {
		return "", "", false
	}
	port = u.Port()
	if port == "" {
		// No explicit port (also the case for default ports like :80/:443,
		// which u.Port() reports as "") — install.sh standardizes on 8443.
		port = authListenPortFallback
		return host, port, true
	}
	// Explicit port: must parse as an integer within 1..65535. net/url does
	// NOT range-check ports — its validOptionalPort only requires digits, so
	// on this toolchain (go1.27.1) url.Parse accepts 65536, 70000, port 0 and
	// arbitrarily large digit strings, and u.Port() returns them verbatim
	// ("99999999999999999999" stays a string). The Atoi error path is what
	// rejects those oversized values; the bounds reject 65536/0. Without this
	// check an unusable URL port counted as "usable" and slipped past the
	// startup refusal above (AUTHSERVERD-005 r3 P2).
	if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
		return "", "", false
	}
	return host, port, true
}

// isLoopbackListenHost reports whether a listen host binds only the loopback
// interface. An empty host (":8443", "0.0.0.0", "::") binds all interfaces
// and is NOT loopback.
func isLoopbackListenHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

// listenHost splits the host portion off a listen address; an address without
// a host part (":8443") returns "" (all interfaces).
func listenHost(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return ""
	}
	return host
}

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	cfg, err := config.Load()
	if err != nil {
		logger.Error("configuration error", "error", err)
		os.Exit(1)
	}

	// Sync the configured crypto profile into the pwhash global (password hashing
	// algorithm selection) once at startup — without this an smx/hybrid deploy
	// would silently bcrypt-hash new passwords. authserver has no CryptoReloader,
	// so the returned hot-swap callback is intentionally discarded.
	_ = sharedcfg.InitCryptoProfile(cfg.CryptoProfile)

	// ── 0. Auth listen resolution (D-AUTHSERVER-CMD-AUTHSERVERD-005) ──
	// Boot-time decision: explicit LISTEN_ADDR > explicit YAML listen.addr >
	// AUTHSERVER_URL host:port (install.sh derivation parity) > compiled
	// ":8443". resolveAuthListenAddr documents the outcome (Debug log of the
	// resolved address + derivation source, echoed in the Info startup line
	// below as listen_source) and WARNs when AUTHSERVER_URL implies a
	// non-loopback bind. It REFUSES startup — mirroring the schema-mismatch
	// precedent — when the effective bind is wildcard/non-loopback without a
	// usable AUTHSERVER_URL (AUTHSERVERD-005 finding 2). The listen address is
	// never re-armed by reload: the http.Server below is built once from this
	// result.
	authListen, listenErr := resolveAuthListenAddr(
		cfg,
		os.Getenv("LISTEN_ADDR") != "",
		os.Getenv("AUTHSERVER_URL"),
		logger,
	)
	if listenErr != nil {
		logger.Error("refusing to start: unsafe auth listen configuration", "error", listenErr)
		os.Exit(1)
	}

	// Atomic config pointer for hot reload (SIGHUP or HTTP POST /admin/reload).
	// The pointer backs the dynamic INTERNAL_API_KEY gates (see requireAPIKeyLive)
	// and is republished by commitReload; boot-captured consumers that cannot
	// re-arm live are reported restart-required by the reload response
	// (D-AUTHSERVER-CMD-AUTHSERVERD-002).
	var cfgPtr sharedcfg.ConfigPtr[config.Config]
	cfgPtr.Store(cfg)

	// Register for SIGHUP early so the signal handler exists during the boot
	// window; the drain goroutine starts once the reload seam is wired (after
	// route registration) and signals coalesce in the buffered channel until
	// then. On platforms without SIGHUP (Windows), use HTTP POST /admin/reload.
	reloadCh := sharedcfg.NotifyReloadOnSIGHUP()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// ── 1. Database ──
	// Audit chain V3 (V087): the authserver writes admin_audit_log rows too
	// (TOTP handlers). Without AUDIT_HMAC_KEY its sessions write unkeyed V2
	// sha256 checksums — loud fallback WARN, not a boot refusal.
	if cfg.AuditHMACKey == "" {
		logger.Warn("AUDIT_HMAC_KEY not set — admin_audit_log hash chain falls back to unkeyed V2 sha256 (set the key to enable HMAC tamper-evidence)")
	}
	pool, err := pgxutil.OpenPool(ctx, cfg.DatabaseDSN, cfg.DBMaxConns, cfg.DBEncryptionKey, cfg.AuditHMACKey)
	if err != nil {
		logger.Error("DB pool failed", "error", err)
		return
	}
	defer pool.Close()
	if err := pgxutil.EnforceAuditCutover(ctx, pool, cfg.AuditHMACKey); err != nil {
		logger.Error("audit chain trust unavailable", "error", err)
		return
	}
	workerPool := pgxutil.WorkerPool{Pool: pool}
	if cfg.DatabaseWorker != "" && cfg.DatabaseWorker != cfg.DatabaseDSN {
		worker, err := pgxutil.OpenPool(ctx, cfg.DatabaseWorker, cfg.DBMaxConns, cfg.DBEncryptionKey, cfg.AuditHMACKey)
		if err != nil {
			logger.Error("DB worker pool failed", "error", err)
			return
		}
		defer worker.Close()
		workerPool = pgxutil.WorkerPool{Pool: worker}
	}

	// Verify schema migrations are up to date.
	// Post-collapse (ARCH-007): the schema is one baseline (V001), shared with
	// Authserver and mailserver share one schema ledger. Derive the required
	// version from the same embedded migration set as the gateway/mailctl so an
	// auth-only binary can never start against a silently stale schema.
	expectedVersion := maildbschema.ExpectedVersion()
	var actualVersion int
	pool.QueryRow(ctx, `SELECT COALESCE(MAX(version), 0) FROM schema_migrations`).Scan(&actualVersion)
	if actualVersion < expectedVersion {
		logger.Error("schema migrations not applied",
			"expected", expectedVersion, "actual", actualVersion)
		os.Exit(1)
	}
	logger.Info("schema migrations verified", "version", actualVersion)

	// ── 2. Toggle system ──
	featureToggles, err := toggle.New(ctx, pool, toggleOverrides(cfg))
	if err != nil {
		logger.Error("toggle init failed", "error", err)
		return
	}

	// Drifted-DB tripwire — see mailserverd: security-family toggle rows are
	// baseline-seeded; missing rows must fail boot, not silently default.
	if err := featureToggles.RequireSeeded(toggle.SecuritySeededKeys...); err != nil {
		logger.Error("security toggle seed check failed", "error", err)
		os.Exit(1)
	}

	var newConfigListener configListenerFactory = func(listenerCtx context.Context, name string) (configChangeListener, error) {
		return openConfigListener(listenerCtx, cfg.DatabaseDirect, cfg.DatabaseDSN, name, logger)
	}
	startOptionalConfigListener := func(name string, register func(configChangeListener) error) {
		go superviseOptionalConfigListener(
			ctx, logger, name, newConfigListener, register, waitConfigListenerRetry,
		)
	}

	// Feature-toggle invalidation has its own reconnecting direct connection so
	// an unavailable external federation endpoint cannot stall security-gate
	// notifications. Reload reconstructs authoritative state missed while down.
	toggleListener, err := newConfigListener(ctx, "feature_toggles")
	if err != nil {
		logger.Error("toggle listen connection failed", "error", err)
		os.Exit(1)
	}
	if err := toggle.BindNotifications(ctx, toggleListener, featureToggles, nil, logger); err != nil {
		logger.Error("toggle LISTEN registration or reconciliation failed", "error", err)
		os.Exit(1)
	}

	// ── 3. Threat detection ──
	var geoipReader *geoip2.Reader
	if cfg.GeoIPDBPath != "" {
		geoipReader, err = geoip2.Open(cfg.GeoIPDBPath)
		if err != nil {
			logger.Warn("geoip database not loaded, geo-blocking disabled", "path", cfg.GeoIPDBPath, "error", err)
		}
	}
	// CAPTCHA token signing key: config.LoadWithKoanf derives a
	// domain-separated HKDF key from JWT_SECRET when CAPTCHA_SECRET is unset
	// (key-purpose separation, D-AUTHSERVER-CMD-AUTHSERVERD-004 — the raw JWT
	// secret must never sign captcha challenges, mirroring the AUDIT_HMAC_KEY
	// fallback WARN doctrine). This branch is a defensive WARN for the empty
	// case, not a re-application of the raw-secret fallback; with an empty key
	// the threat interceptor treats captcha as disabled rather than guessing.
	captchaSecret := cfg.CaptchaSecret
	if captchaSecret == "" {
		logger.Warn("CAPTCHA_SECRET unresolved and JWT secret unavailable — captcha challenge signing disabled (set CAPTCHA_SECRET or JWT_SECRET)")
	}
	threatCfg := threat.ThreatConfig{
		SprayWindowSecs:   cfg.ThreatSprayWindowSecs,
		SprayMaxUsers:     cfg.ThreatSprayMaxUsers,
		SprayLockoutMins:  cfg.ThreatSprayLockoutMins,
		CaptchaWindowMins: cfg.ThreatCaptchaWindowMins,
		CaptchaThreshold:  cfg.ThreatCaptchaThreshold,
		TarpitWindowMins:  cfg.ThreatTarpitWindowMins,
		TarpitThreshold:   cfg.ThreatTarpitThreshold,
		RateLimitPerMin:   cfg.ThreatRateLimitPerMin,
		BlockCountries:    splitCSV(cfg.GeoBlockCountries),
		CaptchaSecret:     []byte(captchaSecret),
	}
	// The lockout/spray stores ride the WORKER credential: their auth_lockouts
	// statements resolve through worker-only SECURITY DEFINER accessors (V259
	// deny-all FORCE). workerPool aliases pool until DB_WORKER_DSN is set (W1b),
	// so this is INERT today.
	threatInterceptor := threat.New(pool, workerPool.Pool, featureToggles, geoipReader, threatCfg, logger, nil)
	go threat.RefreshFeeds(ctx, pool, 30*time.Minute, logger)

	// Conditional access policy engine (may be nil if DB tables not yet created)
	policyStore := threat.NewPolicyStore(pool, logger)
	// Single resolver instance: drives both the conditional-access policy engine
	// and the login-time DeviceClaim production (P1, device-trust enforcement).
	deviceTrustResolver := threat.NewDeviceTrustResolver(pool, logger)
	policyEngine := threat.NewPolicyEngine(policyStore, featureToggles,
		deviceTrustResolver,
		threat.NewIPRiskScorer(pool, logger),
		logger, os.Getenv("CONDITIONAL_ACCESS_FAIL_CLOSED") == "true",
	)
	// Read ca_fail_mode from system_config and apply it to the engine (I1).
	// The seeded default is "closed"; "open" is the only recognised override.
	// On any read/parse error we stay fail-closed (safe default).
	{
		var rawFailMode []byte
		if err := pool.QueryRow(ctx,
			`SELECT value FROM system_config WHERE key = 'ca_fail_mode'`,
		).Scan(&rawFailMode); err == nil {
			// value is JSONB — strip surrounding quotes: "open" → open
			mode := strings.Trim(strings.TrimSpace(string(rawFailMode)), `"`)
			policyEngine.SetFailMode(mode)
			logger.Info("ca_fail_mode loaded from system_config", "mode", mode)
		}
		// err != nil (row absent / DB unavailable) → engine stays fail-closed by default
	}
	policyEngine.CheckFailModePosture()
	// CA-0a: load break-glass set at startup so the engine honours it immediately.
	if bg, bgErr := policyStore.LoadBreakGlass(ctx); bgErr == nil {
		policyEngine.SetBreakGlass(bg)
		logger.Info("ca_break_glass_user_ids loaded", "count", len(bg))
	}
	threatInterceptor.SetPolicyEngine(policyEngine)

	// Conditional Access owns a fourth independent durable listener. A missed
	// notification invalidates both caches and reloads break-glass state;
	// failures clear stale exclusions rather than retaining a bypass.
	reloadConditionalAccess := newConditionalAccessReloader(
		policyEngine, policyStore.LoadBreakGlass,
	)
	startOptionalConfigListener("conditional_access", func(listener configChangeListener) error {
		return configureConditionalAccessListener(
			ctx, listener, reloadConditionalAccess, logger,
		)
	})

	go func() {
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				token.CleanupRotatedTokens(ctx, pool)
				federation.GCExpiredOIDCTokens(ctx, pool)
			}
		}
	}()

	// ── 4. JWT provider ──
	var sm2Key *ecdsa.PrivateKey
	if cfg.CryptoProfile == cryptokey.ProfileSMx || (cfg.CryptoProfile == cryptokey.ProfileHybrid && cfg.SM2PrivateKeyFile != "") {
		sm2Key, err = cryptokey.LoadSM2PrivateKey(cfg.SM2PrivateKeyFile)
		if err != nil {
			slog.Error("failed to load SM2 key", "path", cfg.SM2PrivateKeyFile, "error", err)
			os.Exit(1)
		}
	}
	jwtProvider := token.NewJWTProvider(cfg.JWTSecret, sm2Key, cfg.CryptoProfile, cfg.JWTExpiry, cfg.JWTRefreshExpiry, cfg.JWTIssuer)

	// ── 4a. ES256 signing keystore (ADR-005) ──
	// Load-or-generate the DB-backed encrypted keystore. Always loaded (even on
	// the HS256 default) so the first-party JWKS publishes the public key and the
	// gateway can dual-verify ES256 BEFORE issuance flips. The private key is
	// encrypted at rest under the derived DB key. sign() emits ES256 only when
	// JWT_SIGNING_ALG=ES256 (and an active key exists); Validate accepts ES256
	// by kid regardless.
	// Pass the RAW secret: cryptokey.EncryptColumn/DecryptColumn derive the column
	// key from it internally (DeriveDBEncryptionKey), so pre-deriving here would
	// double-derive and break the documented master-key contract.
	signingKeySet, err := token.Load(ctx, pool, []byte(cfg.JWTSecret), cfg.CryptoProfile)
	if err != nil {
		logger.Error("signing keystore load/generate failed", "error", err)
		os.Exit(1)
	}
	jwtProvider.WithKeySet(signingKeySet, token.ParseSigningAlg(cfg.JWTSigningAlg))
	logger.Info("signing keystore loaded", "signing_alg", jwtProvider.SigningAlg())

	// ── 4a-bis. Device HMAC secret codec (med-auth-baseline-secrets-001) ──
	// Seals/opens devices.hmac_secret_enc (AES-256-GCM EK01 envelope) for the
	// register + verify seams. Same raw-secret contract as the keystore above:
	// cryptokey derives the column key internally.
	deviceSecretCodec := shareddevice.NewSecretCodec([]byte(cfg.JWTSecret), cfg.CryptoProfile)

	// ── 4b. TokenService (Wave 3 seam) ──
	// Composes the signing core (jwtProvider, KeySet/ES256 dual-verify intact)
	// with the oauth_tokens store. The single owner of the first-party token
	// lifecycle: issue/validate/introspect/refresh/revoke. Every revocation path
	// funnels through it.
	tokenSvc := token.NewTokenService(jwtProvider, pool, featureToggles)

	// ── 5. Cookie key (sha256 of JWT secret) ──
	cookieKey := cryptokey.DeriveCookieKey([]byte(cfg.JWTSecret))

	// ── 6. Federation (SAML SP + OIDC RP) ──
	cookieSecure := cfg.TLSCertFile != ""
	var samlSP *federation.SAMLSPRegistry
	var oidcRP *federation.OIDCRPProvider

	if cfg.SAMLEnabled && cfg.SAMLCertFile != "" && cfg.SAMLKeyFile != "" {
		samlSP, err = federation.NewSAMLSPRegistry(ctx, pool, cfg.SAMLCertFile, cfg.SAMLKeyFile)
		if err != nil {
			logger.Warn("one or more SAML registrations failed closed", "error", err)
		}
	}
	// Startup re-seal gate (mirrors mailserverd's EnsureSecretEncryption):
	// upgrade legacy plaintext client_secret rows to the cryptokey column
	// envelope before the fail-closed loader reads them. The storage migration
	// runs INDEPENDENTLY of provider activation: with OIDC disabled no RP
	// provider is constructed, yet stored credentials must still be re-sealed —
	// otherwise they remain plaintext indefinitely. Idempotent. Rotation of
	// previously exposed values is an operator action at the IdP.
	if upgraded, err := federation.ResealOIDCProviderClientSecrets(
		ctx, pool, []byte(cfg.JWTSecret), cfg.CryptoProfile,
	); err != nil {
		logger.Warn("OIDC client secret re-seal migration failed; plaintext providers will fail closed",
			"error", err)
	} else if upgraded > 0 {
		logger.Info("re-sealed legacy OIDC provider client secrets", "upgraded", upgraded)
	}
	if cfg.OIDCEnabled {
		oidcRP, err = federation.NewOIDCRPProvider(ctx, pool, []byte(cfg.JWTSecret))
		if err != nil {
			logger.Warn("one or more OIDC providers failed closed", "error", err)
		}
	}

	// Each federation cache gets its own reconnecting direct connection. Sharing
	// one pgx.Conn across the OIDC and SAML wait loops is unsafe, and independent
	// listeners prevent one external provider's reload failure from stalling the
	// other provider or the feature-toggle security boundary.
	if samlSP != nil {
		startOptionalConfigListener("saml_sp", func(listener configChangeListener) error {
			return samlSP.ListenForChanges(ctx, listener, logger)
		})
	}
	if oidcRP != nil {
		startOptionalConfigListener("oidc_rp", func(listener configChangeListener) error {
			return oidcRP.ListenForChanges(ctx, listener, logger)
		})
	}

	// ── 7. OIDC Provider (IdP mode) ──
	var oidcOP *op.Provider
	var oidcOpStorage *federation.OPStorage
	if cfg.OIDCProviderEnabled {
		oidcKeyMgr, err := federation.LoadOrGenerateKey(
			cfg.OIDCProviderPrivateKeyFile,
			cfg.OIDCProviderPublicKeyFile,
		)
		if err != nil {
			logger.Error("OIDC key init failed", "error", err)
			os.Exit(1)
		}

		oidcOpStorage = federation.NewOPStorage(pool, oidcKeyMgr)

		var oidcCryptoKeyBytes [32]byte
		copy(oidcCryptoKeyBytes[:], cryptokey.DeriveOIDCCryptoKey([]byte(cfg.JWTSecret)))
		opConfig := &op.Config{
			CryptoKey:               oidcCryptoKeyBytes,
			CryptoKeyId:             "authserver-enc-1",
			GrantTypeRefreshToken:   true,
			CodeMethodS256:          true,
			AuthMethodPost:          true,
			AuthMethodPrivateKeyJWT: false,
			RequestObjectSupported:  false,
		}

		oidcOP, err = op.NewProvider(opConfig, oidcOpStorage,
			op.StaticIssuer("https://"+cfg.Hostname),
			op.WithCORSOptions(oidcProviderCORSOptions(cfg.Hostname, cfg.OIDCProviderAllowedOrigins)),
		)
		if err != nil {
			logger.Error("OIDC provider init failed", "error", err)
			os.Exit(1)
		}
	}
	// ── 8. Passkeys (WebAuthn) + Push MFA ──
	var passkey *authn.PasskeyProvider
	passkey, err = authn.NewPasskeyProvider(pool, cfg.WebAuthnRPID, cfg.WebAuthnRPDisplayName, cfg.WebAuthnRPOrigin)
	if err != nil {
		logger.Warn("WebAuthn initialization failed, passkeys disabled", "error", err)
	}

	var pushMFA authn.ChallengeProvider
	var pushProvider *authn.NumberMatchPushProvider
	var vapidPublicKey string
	if cfg.VAPIDPrivateKey != "" {
		// The recovery-lockout verification transaction MUST run on the
		// WORKER credential: its auth_lockouts statements go through the
		// worker-only SECURITY DEFINER push_lockout_* accessors (V259), and
		// a constrained request credential gets 42501 at acquisition.
		// workerPool aliases pool until DB_WORKER_DSN is set (W1b INERT).
		pushProvider = authn.NewNumberMatchPushProvider(context.Background(), pool, workerPool.Pool, cfg.VAPIDPrivateKey, cfg.VAPIDSubject, logger)
		pushMFA = pushProvider
		if vapidPublicKey, err = authn.DeriveVAPIDPublicKey(cfg.VAPIDPrivateKey); err != nil {
			logger.Warn("VAPID public key derivation failed: webmail push-subscribe will be unavailable", "error", err)
			vapidPublicKey = ""
		}
	} else {
		logger.Info("push MFA disabled: VAPID_PRIVATE_KEY not set")
	}

	// ── 8.1. Native push dispatchers (APNs / FCM / HMS) ──
	// Built by shared/push from the environment (one implementation, shared with
	// the mailserver mail-push worker). A present-but-broken provider is logged
	// loudly as INVALID rather than silently skipped.
	if pushProvider != nil {
		pushSet, statuses := push.Build(push.LoadConfig())
		for _, st := range statuses {
			switch st.State {
			case push.Configured:
				logger.Info("push provider configured", "provider", st.Kind, "detail", st.Detail)
			case push.Invalid:
				logger.Error("push provider present but INVALID config", "provider", st.Kind, "detail", st.Detail)
			}
		}
		var apnsD *push.APNsDispatcher
		var fcmD *push.FCMDispatcher
		var hmsD *push.HMSDispatcher
		if d, ok := pushSet.Get(push.APNs); ok {
			apnsD, _ = d.(*push.APNsDispatcher)
		}
		if d, ok := pushSet.Get(push.FCM); ok {
			fcmD, _ = d.(*push.FCMDispatcher)
		}
		if d, ok := pushSet.Get(push.HMS); ok {
			hmsD, _ = d.(*push.HMSDispatcher)
		}
		pushProvider.SetNativeDispatchers(apnsD, fcmD, hmsD)
	}

	// ── 9. Handlers ──
	// Connector manager: explicit factory registration (no import-side-effect
	// init()) + cache warm-up. The manager is injected into the auth handler so the
	// AD password write-back reads it (h.connectors.CachedGet("ad")) instead of a
	// package global. We warm the local connector (its factory needs only the pool,
	// never errors); the AD connector is created on demand at sync time and only
	// when AD is configured, so its CachedGet stays nil here (the write-back then
	// no-ops, unchanged from before).
	connectorManager := connector.NewManager()
	connectorManager.Register("ad", connectorad.Factory)
	connectorManager.Register("local", connectorlocal.Factory)
	if _, err := connectorManager.Create(ctx, "local", 0, map[string]interface{}{"pool": pool}, nil); err != nil {
		logger.Warn("local connector warm-up failed", "error", err)
	}

	authH := handlers.NewAuthHandler(handlers.AuthHandlerConfig{
		Pool:           pool,
		DatabaseWorker: workerPool,
		JWT:            jwtProvider,
		CookieKey:      cookieKey,
		Logger:         logger,
		SAMLSP:         samlSP,
		OIDCRP:         oidcRP,
		Passkey:        passkey,
		PushMFA:        pushMFA,
		JITEnabled:     cfg.JITEnabled,
		CookieSecure:   cookieSecure,
		TrustProxy:     cfg.AuthTrustProxy,
		// Trusted-proxy allowlist (AUTHSERVERD-005 finding 3): loopback peers
		// are always trusted for forwarded-header trust; these CIDRs widen it.
		// Empty by default = loopback-only.
		TrustedProxyCIDRs: splitCSV(cfg.AuthTrustedProxyCIDRs),
		PolicyEngine:      policyEngine,
		GeoipDB:           geoipReader,
		Connectors:        connectorManager,
		// Operator-controlled ceiling: an IdP group->role mapping can confer
		// super_admin only when this is explicitly enabled (default false).
		SSOAllowSuperAdminMapping: cfg.SSOAllowSuperAdminMapping,
		// Device-trust enforcement (P1): login embeds the managed_devices-derived
		// DeviceClaim ONLY when feature.device_trust_enforcement is flipped on
		// (default OFF). Fail-open on any lookup error.
		DeviceTrust: deviceTrustResolver,
		Toggles:     featureToggles,
		// CA-0b T8: inject real recorder so login telemetry writes to ca_signin_log.
		SignInRecorder: threat.NewPgxSignInRecorder(pool, logger),
		// CA-2 T7: resolve device-bound credential signals at login time.
		DeviceResolver: threat.NewDeviceCredentialResolver(pool, logger, deviceSecretCodec),
		VAPIDPublicKey: vapidPublicKey,
	})
	// ── 9a. Session-revocation denylist (CA-3a, s08→s07 handoff) ──
	// bearerAuth is the single acceptance funnel for EVERY authserver route the
	// gateway proxies AND every direct route mounted below, but only the
	// gateway's RequireRuntimeAccess spine consulted the CA-3a
	// session_revocations authority — direct routes accepted revoked sessions
	// until token expiry. Attach the same shared threat.SessionDenylist mirror
	// the revoke_user_sessions reducer feeds (app_notify('session_revoke') +
	// durable reconcile) so BearerAuthenticator rejects a positive IsRevoked
	// match with 401. Mirrors the gateway wiring (mailserverd §4.4): the
	// reconcile query rides the WORKER credential because session_revocations
	// is FORCE RLS (V259) and the mirror is cross-tenant by nature; the 30s
	// ticker is the documented staleness bound that repairs missed NOTIFYs,
	// and the startup seed closes most of the cold-start window. Fail-closed
	// on reconcile error: the denylist keeps existing entries (denylist.go §14).
	sessionDenylist := threat.NewSessionDenylist(func(rctx context.Context) ([]threat.RevocationRow, error) {
		rows, err := workerPool.Query(rctx,
			`SELECT user_id, scope, COALESCE(jti,''), COALESCE(family_id,''),
			        not_before, expires_at
			   FROM session_revocations
			  WHERE expires_at > now()`)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		var out []threat.RevocationRow
		for rows.Next() {
			var row threat.RevocationRow
			if err := rows.Scan(
				&row.UserID, &row.Scope, &row.JTI, &row.FamilyID,
				&row.NotBefore, &row.ExpiresAt,
			); err != nil {
				return nil, err
			}
			out = append(out, row)
		}
		return out, rows.Err()
	}, logger)
	if refreshErr := sessionDenylist.Refresh(ctx); refreshErr != nil {
		logger.Warn("session denylist: startup reconcile failed — direct-route revocation mirror stale until first success", "error", refreshErr)
	}
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := sessionDenylist.Refresh(ctx); err != nil {
					logger.Warn("session denylist: reconcile failed (existing entries retained)", "error", err)
				}
			}
		}
	}()

	bearerAuth := token.NewBearerAuthenticator(jwtProvider).WithRevocations(sessionDenylist)
	// The dual-admission possession endpoints resolve their access-token
	// admission through the same funnel (DPoP + revocation, r1 defect 4).
	authH.AttachBearer(bearerAuth)
	requireAuth := middleware.RequireAuth(bearerAuth, logger)
	requireAuthOrLogin := middleware.RequireAuthOrRedirect(bearerAuth, "/")

	// ── 10. Routes ──
	mux := http.NewServeMux()

	// Well-known discovery (no auth)
	mux.HandleFunc("GET /.well-known/setjoin", authH.WellKnown)
	// Client version check (no auth)
	mux.HandleFunc("GET /api/v1/version", authH.ClientVersion)

	// First-party JWKS (ADR-005): active + retiring ES256 public keys keyed by
	// kid, for the gateway to verify first-party tokens offline. Distinct from the
	// OIDC OP /keys endpoint (RS256), which is untouched.
	mux.Handle("GET /.well-known/jwks.json", &handlers.JWKSHandler{KeySet: signingKeySet})

	// RFC 8414 OAuth 2.0 Authorization Server Metadata (no auth). The issuer
	// and every endpoint describe the OIDC OP's RS256 token universe; the
	// separate first-party ES256 JWKS above is not mixed into this document.
	oauthMetadata := &handlers.OAuthMetadataHandler{
		Issuer:             "https://" + cfg.Hostname,
		ACRValuesSupported: federation.SupportedACRValues,
	}
	mux.Handle("GET /.well-known/oauth-authorization-server", oauthMetadata)

	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status":"ok"}`))
	})
	mux.HandleFunc("GET /ready", func(w http.ResponseWriter, r *http.Request) {
		pingCtx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
		defer cancel()
		if err := pool.Ping(pingCtx); err != nil {
			http.Error(w, "not ready", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	mux.HandleFunc("GET /auth/password-policy", authH.PasswordPolicy)
	// Guest invite acceptance is pre-auth. Both methods apply the shared
	// enumeration rate limit internally; POST additionally accepts a new
	// credential, so it passes through the threat interceptor (no CSRF: the
	// single-use invite token is the pre-auth authorization).
	mux.HandleFunc("GET /auth/guest-invite/accept", authH.GuestInviteAcceptGet)
	mux.Handle("POST /auth/guest-invite/accept", limitRequestBody(guestInviteAcceptBodyLimit,
		threatInterceptor.Middleware(http.HandlerFunc(authH.GuestInviteAcceptPost))))

	// Only wrap in threat interceptor when at least one threat feature is enabled.
	loginH, refreshH := credentialRouteHandlers(
		http.HandlerFunc(authH.Login),
		http.HandlerFunc(authH.Refresh),
		featureToggles,
		threatInterceptor.Middleware,
	)
	mux.Handle("POST /auth/login", loginH)
	mux.Handle("POST /auth/refresh", refreshH)
	mux.Handle("POST /auth/logout", requireAuth(sharedmw.CSRF(http.HandlerFunc(authH.Logout))))
	mux.Handle("GET /auth/me", requireAuth(http.HandlerFunc(authH.Me)))
	// Per-tab DPoP admission recovery (r3): mounted WITHOUT requireAuth on
	// purpose — requireAuth enforces the ath claim the recovering tab cannot
	// compute yet. The handler self-authenticates through
	// BearerAuthenticator.AuthenticateAdmissionRecovery (everything but ath;
	// a cnf-bound token still proves possession of its binding key).
	mux.Handle("GET /auth/session/token", http.HandlerFunc(authH.SessionToken))
	mux.Handle("PUT /auth/password", requireAuth(sharedmw.CSRF(http.HandlerFunc(authH.ChangePassword))))

	// SAML 2.0 routes
	mux.HandleFunc("GET /auth/saml/{idp}/login", authH.SAMLLogin)
	mux.Handle("POST /auth/saml/{idp}/link",
		requireAuth(sharedmw.CSRF(http.HandlerFunc(authH.SAMLLink))))
	mux.HandleFunc("GET /auth/saml/{idp}/metadata", authH.SAMLMetadata)
	mux.HandleFunc("POST /auth/saml/{idp}/acs", authH.SAMLACS)

	// OIDC routes
	mux.HandleFunc("GET /auth/oidc/login", authH.OIDCLogin)
	mux.Handle("POST /auth/oidc/link",
		requireAuth(sharedmw.CSRF(http.HandlerFunc(authH.OIDCLink))))
	mux.HandleFunc("GET /auth/oidc/callback", authH.OIDCCallback)
	mux.Handle("GET /auth/identity-links", requireAuth(http.HandlerFunc(authH.IdentityLinks)))
	mux.Handle("DELETE /auth/identity-links/{id}",
		requireAuth(sharedmw.CSRF(http.HandlerFunc(authH.IdentityUnlink))))

	// WebAuthn (passkeys) routes
	// Registration ceremonies are admission-bounded like the other factor
	// management routes (worker-admission-bounds control). register/finish is
	// additionally CSRF-checked and body-bounded (ER5 occ_243999e65729c68c82041ce8):
	// it is the one authenticated mutating auth route that previously skipped
	// the CSRF invariant every other mutating mount carries, so a drive-by
	// browser request on a victim's ambient session could enroll an
	// attacker-controlled passkey (persistent authentication capability) with
	// no origin check at all. sharedmw.CSRF only denies when a request
	// self-identifies as cross-site browser traffic (Origin/Referer mismatch or
	// Sec-Fetch-Site: cross-site) — native clients without fetch metadata keep
	// the documented passthrough. limitRequestBody sits OUTERMOST so the
	// oversized body is refused 413 before the threat middleware's own body
	// reader runs (the guest-invite mount precedent, limitRequestBody →
	// threatInterceptor → handler).
	mux.Handle("GET /auth/webauthn/register/begin",
		threatInterceptor.Middleware(requireAuth(http.HandlerFunc(authH.WebAuthnRegisterBegin))))
	mux.Handle("POST /auth/webauthn/register/finish",
		limitRequestBody(webauthnRegistrationBodyLimit,
			threatInterceptor.Middleware(requireAuth(sharedmw.CSRF(http.HandlerFunc(authH.WebAuthnRegisterFinish))))))
	mux.HandleFunc("GET /auth/webauthn/login/begin", authH.WebAuthnLoginBegin)
	mux.HandleFunc("POST /auth/webauthn/login/finish", authH.WebAuthnLoginFinish)
	mux.Handle("GET /auth/webauthn/credentials", requireAuth(http.HandlerFunc(authH.WebAuthnListCredentials)))
	mux.Handle("PUT /auth/webauthn/credential/{id}/name", requireAuth(sharedmw.CSRF(http.HandlerFunc(authH.WebAuthnNameCredential))))
	mux.Handle("DELETE /auth/webauthn/credential/{id}", requireAuth(sharedmw.CSRF(http.HandlerFunc(authH.WebAuthnRevokeCredential))))

	// TOTP (time-based one-time password) routes
	mux.Handle("POST /auth/totp/verify", threatInterceptor.Middleware(http.HandlerFunc(authH.TOTPVerify)))
	mux.Handle("POST /auth/totp/enroll/setup", threatInterceptor.Middleware(http.HandlerFunc(authH.TOTPEnrollmentSetup)))
	mux.Handle("POST /auth/totp/enroll/confirm", threatInterceptor.Middleware(http.HandlerFunc(authH.TOTPEnrollmentConfirm)))
	// Factor-management routes carry the threat interceptor's per-IP admission
	// bounds (ER5 occ_78eced11bd69fcba59acdfe7 / occ_7a9d036764bc3916be52505c,
	// worker-admission-bounds control): these are exactly the routes that mint
	// or activate persistent authentication capability (TOTPSetup generates the
	// pending secret, TOTPConfirm activates it, GenerateBackupCodes replaces
	// every recovery code), so scripted bulk abuse is capped by the same
	// per-IP pipeline that guards the pre-auth credential routes. The
	// interceptor is mounted OUTSIDE requireAuth/CSRF, the same order as the
	// forgot-password mounts.
	mux.Handle("GET /auth/totp/setup",
		threatInterceptor.Middleware(requireAuth(http.HandlerFunc(authH.TOTPSetup))))
	mux.Handle("POST /auth/totp/confirm",
		threatInterceptor.Middleware(requireAuth(sharedmw.CSRF(http.HandlerFunc(authH.TOTPConfirm)))))
	// De-enrollment (factor removal): requireAuth + CSRF at both steps. The
	// begin step runs the password+code decision table and issues the
	// single-use session-bound step-up token; the remove step consumes it with
	// a typed confirmation inside one serialized transaction. No
	// unauthenticated /auth/totp/remove* route may exist.
	mux.Handle("POST /auth/totp/remove/begin", requireAuth(sharedmw.CSRF(http.HandlerFunc(authH.TOTPRemovalBegin))))
	mux.Handle("POST /auth/totp/remove", requireAuth(sharedmw.CSRF(http.HandlerFunc(authH.TOTPRemovalConfirm))))
	// First-factor step-up re-auth challenge (ER5 s07 residual): verifies the
	// session holder's current password and issues the single-use
	// session-bound reauth_token that the /auth/totp/setup + /auth/totp/confirm
	// first-enrollment arms and /auth/backup-codes/generate consume (typed 403
	// reauth_required problem names this path). Same mount posture as the
	// other factor-management routes: threat interceptor's per-IP admission
	// bounds + requireAuth + CSRF.
	mux.Handle("POST /auth/mfa/reauth",
		threatInterceptor.Middleware(requireAuth(sharedmw.CSRF(handlers.RequireJSONContentType(http.HandlerFunc(authH.MFAReauthBegin))))))

	// First-factor possession gate (v7 §3): the C1 possession-proof issuance
	// family. The reauth row above stays password-only; these endpoints
	// accept the possession proofs for possession-capable accounts.
	//
	//   - possession/totp rides the SAME posture as /auth/mfa/reauth
	//     (threat interceptor + requireAuth + CSRF) — session scope only.
	//   - webauthn/begin|finish carry threatInterceptor + CSRF but NO
	//     requireAuth: admission is resolved IN the handler (valid access
	//     bearer or ambient cookie → session scope; else a presented
	//     mfa_token validating as TypeMFAPending → mfa_pending scope;
	//     §3.2 T1). CSRF is unconditional on begin because it DELETES the
	//     user's prior management-assertion ceremonies — a mutation on a
	//     route whose access authentication accepts the ambient cookie
	//     (r5 finding 2; the same defect class ER5 closed on register/finish
	//     above). Native callers keep the documented header-absence
	//     passthrough, and the mfa_token path needs no browser CSRF cookie.
	//   - All four issuance endpoints require Content-Type: application/json
	//     (§3.2 T2 — the strict media-type policy closes non-JSON body
	//     smuggling at the mint points; the check runs before the decoder).
	mux.Handle("POST /auth/mfa/possession/totp",
		threatInterceptor.Middleware(requireAuth(sharedmw.CSRF(handlers.RequireJSONContentType(http.HandlerFunc(authH.MFAPossessionTOTP))))))
	mux.Handle("POST /auth/mfa/possession/webauthn/begin",
		threatInterceptor.Middleware(sharedmw.CSRF(handlers.RequireJSONContentType(http.HandlerFunc(authH.MFAPossessionWebAuthnBegin)))))
	mux.Handle("POST /auth/mfa/possession/webauthn/finish",
		threatInterceptor.Middleware(sharedmw.CSRF(handlers.RequireJSONContentType(http.HandlerFunc(authH.MFAPossessionWebAuthnFinish)))))

	// Push MFA routes
	mux.Handle("POST /auth/push/verify", threatInterceptor.Middleware(http.HandlerFunc(authH.PushMFAVerify)))
	mux.Handle("POST /auth/mfa/push/send", threatInterceptor.Middleware(http.HandlerFunc(authH.PushMFASend)))
	// Out-of-band approval poll (C10): the browser/webpush login flow polls this
	// after /auth/mfa/push/send until the enrolled device approves, then it issues
	// the session. NOT wrapped in threatInterceptor: it is a benign poll bound to a
	// valid MFA-pending token (a bad/expired one is rejected 401), and the per-IP
	// auth rate limiter would otherwise trip a normal 2s polling cadence.
	mux.Handle("POST /auth/push/status", http.HandlerFunc(authH.PushMFAStatus))
	// Webpush VAPID public key (QoL #9): unauthenticated, not a secret.
	mux.Handle("GET /auth/push/vapid-key", http.HandlerFunc(authH.VAPIDKey))

	// Push device registration (native ECIES devices + webpush subscriptions; requires auth)
	// Admission-bounded (ER5 occ_fd402745b2ea6bc50f8a9d14): the body cap bounds
	// per-request storage amplification (push_devices has no per-user row cap or
	// token uniqueness constraint — an unbounded body once meant an unbounded
	// encrypted row), and the threat interceptor adds the per-IP admission cap
	// bounding the notification fan-out a scripted registration loop could
	// build. limitRequestBody outermost, mirroring the guest-invite mount.
	mux.Handle("POST /auth/device/register",
		limitRequestBody(pushDeviceRegistrationBodyLimit,
			threatInterceptor.Middleware(requireAuth(sharedmw.CSRF(http.HandlerFunc(authH.DeviceRegister))))))
	// Native push MFA approval (no auth -- uses nonce)
	mux.Handle("POST /auth/mfa/approve", threatInterceptor.Middleware(http.HandlerFunc(authH.MFAApprove)))

	// Device-trust routes (MDM-style identity registration, check-in, policy read).
	// Wired through device.RegisterRoutes so each endpoint goes through its
	// authentication seam in one place: /device/register is bound to the
	// authenticated user (RequireUserAuth + CSRF), and /device/checkin and
	// /device/policy require a per-device HMAC proof (RequireDeviceHMAC). No
	// device endpoint is exposed unauthenticated.
	device.RegisterRoutes(mux, pool, jwtProvider, logger, deviceSecretCodec, sharedmw.CSRF)

	// Backup codes routes
	// GenerateBackupCodes replaces EVERY recovery code and returns the new
	// ones, so it rides the threat interceptor's per-IP admission bounds like
	// the other recovery-affecting mutations (ER5 occ_7a9d036764bc3916be52505c).
	mux.Handle("POST /auth/backup-codes/generate",
		threatInterceptor.Middleware(requireAuth(sharedmw.CSRF(http.HandlerFunc(authH.GenerateBackupCodes)))))
	mux.Handle("POST /auth/backup-codes/verify", threatInterceptor.Middleware(http.HandlerFunc(authH.BackupCodeVerify)))

	// Forgot password (self-service reset via MFA)
	if featureToggles.IsEnabled(toggle.FeatureForgotPassword) {
		mux.Handle("POST /auth/forgot-password/begin", threatInterceptor.Middleware(http.HandlerFunc(authH.ForgotPasswordBegin)))
		mux.Handle("POST /auth/forgot-password/verify", threatInterceptor.Middleware(http.HandlerFunc(authH.ForgotPasswordVerify)))
		mux.Handle("POST /auth/forgot-password/reset", threatInterceptor.Middleware(sharedmw.CSRF(http.HandlerFunc(authH.ForgotPasswordReset))))
	}

	// End-user Terms-of-Use API (CA-3b Task 9): pending list + acceptance.
	// GET is read-only (no CSRF needed); POST mutates and requires CSRF.
	termsH := handlers.NewTermsHandler(pool)
	mux.Handle("GET /terms/pending", requireAuth(http.HandlerFunc(termsH.Pending)))
	mux.Handle("POST /terms/accept", requireAuth(sharedmw.CSRF(http.HandlerFunc(termsH.Accept))))

	// Direct authserver impersonation (ER5 occ_beacdec12aebffd6bf626c41,
	// domain-scope-guard control genre — the console permission guard bound at
	// the auth surface): the handler only re-validates "is an admin", so a
	// governed admin WITHOUT the discrete users.impersonate grant could bypass
	// the console's permission gate by calling the authserver directly. The
	// mount now enforces that same permission through requireImpersonatePermission,
	// resolved LIVE from the governed admin_role_assignments by
	// permissions.ResolveAuthority — the identical resolver the login mint and
	// the gateway console guard's deny-by-default membership test draw from —
	// so demotion/expiry revokes the authority immediately and a resolution
	// failure fails closed. Denials are audited to audit_log with the same
	// admin_impersonate_denied event the handler uses for refusals.
	mux.Handle("POST /auth/admin/users/{id}/impersonate",
		requireAuth(sharedmw.CSRF(requireImpersonatePermission(
			bearerAuth,
			func(ctx context.Context, userID int64) (permissions.Authority, error) {
				return permissions.ResolveAuthority(ctx, pool, userID)
			},
			func(r *http.Request, userID int64) {
				pool.Exec(r.Context(),
					`INSERT INTO audit_log (user_id, source_ip, event_type, metadata)
					 VALUES ($1, $2::INET, 'admin_impersonate_denied',
					         jsonb_build_object('reason','missing_permission','permission',$3::text))`,
					userID, httputil.ClientIP(r), permissions.PermUsersImpersonate)
			},
			logger,
		)(http.HandlerFunc(authH.AdminImpersonate)))))

	// Token introspection (RFC 7662) and revocation (RFC 7009). Both accept the
	// INTERNAL_API_KEY (the gateway's IMAP/SMTP path) AND standard OAuth client
	// authentication (client_id+secret via Basic/POST), so they are registered
	// regardless of whether INTERNAL_API_KEY is set. The handlers enforce auth
	// internally and return {active:false}/200 (never an oracle) for unknown
	// tokens once the caller is authenticated.
	//
	// The INTERNAL_API_KEY-bearing handlers are held behind atomic pointers and
	// rebuilt by the reload seam, so a rotated key re-arms both gates without
	// restart (D-AUTHSERVER-CMD-AUTHSERVERD-002) while the mux registrations
	// stay fixed.
	var introspectLive atomic.Pointer[handlers.IntrospectHandler]
	var revokeLive atomic.Pointer[handlers.RevokeHandler]
	rebuildInternalTokenHandlers := func(cfg *config.Config) {
		introspectLive.Store(&handlers.IntrospectHandler{
			Svc:      tokenSvc,
			Pool:     pool,
			APIKey:   cfg.InternalAPIKey,
			Issuer:   jwtProvider.Issuer(),
			Audience: jwtProvider.Audience(),
		})
		revokeLive.Store(&handlers.RevokeHandler{Svc: tokenSvc, Pool: pool, APIKey: cfg.InternalAPIKey})
	}
	rebuildInternalTokenHandlers(cfg)
	mux.Handle("POST /auth/introspect", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		introspectLive.Load().ServeHTTP(w, r)
	}))

	mux.Handle("POST /auth/revoke", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		revokeLive.Load().ServeHTTP(w, r)
	}))

	// SCIM session revocation + config reload — strictly INTERNAL_API_KEY gated.
	// The gate resolves the current key from the live config pointer per request
	// so a rotated key takes effect without restart
	// (D-AUTHSERVER-CMD-AUTHSERVERD-002). Route registration itself stays a
	// boot-time decision: an empty boot key registers neither route.
	//
	// D-AUTHSERVER-INTERNAL-CONFIG-003: that empty-key skip must never be
	// silent — the config requirement is coupled to AD sync, so a gateway-style
	// topology without AD sync can reach this point with no key. Warn loudly
	// naming exactly which surfaces were not registered.
	if cfg.InternalAPIKey != "" {
		// SCIM session revocation — called by gateway on user disable/delete
		scimDisableH := &handlers.SCIMDisableHandler{Svc: tokenSvc, Pool: pool}
		mux.Handle("POST /auth/scim/disable", requireAPIKeyLive(&cfgPtr)(http.HandlerFunc(scimDisableH.ServeHTTP)))

		// Config hot reload — cross-platform: SIGHUP on Unix, HTTP POST on Windows.
		mux.Handle("POST /admin/reload", requireAPIKeyLive(&cfgPtr)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			newCfg, err := config.LoadWithKoanf(os.Getenv("SETJOIN_CONFIG"))
			if err != nil {
				logger.Error("config reload via HTTP failed", "error", err)
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusInternalServerError)
				w.Write([]byte(`{"error":"config reload failed: ` + err.Error() + `"}`))
				return
			}
			report := commitReload(&cfgPtr, rebuildInternalTokenHandlers, newCfg)
			logger.Info("config reloaded via HTTP",
				"rearmed", report.Rearmed, "restart_required", report.RestartRequired)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			// Marshal of a plain string-slice struct cannot fail.
			body, _ := json.Marshal(report)
			w.Write(body)
		})))
	} else {
		logger.Warn("INTERNAL_API_KEY not set at boot — POST /auth/scim/disable (gateway-driven session revocation on user disable/delete) and POST /admin/reload are NOT registered; set INTERNAL_API_KEY if any internal API consumer depends on these surfaces")
	}

	// Drain SIGHUP-driven reloads now that the reload seam is wired; signals
	// delivered during boot coalesced in the buffered channel and apply here.
	// A reload re-arms the INTERNAL_API_KEY consumers live and reports the
	// boot-captured consumers that still need a restart — it never claims an
	// unconditional success the process did not perform.
	go func() {
		for range reloadCh {
			logger.Info("SIGHUP received, reloading config")
			newCfg, err := config.LoadWithKoanf(os.Getenv("SETJOIN_CONFIG"))
			if err != nil {
				logger.Error("config reload failed, keeping old config", "error", err)
				continue
			}
			report := commitReload(&cfgPtr, rebuildInternalTokenHandlers, newCfg)
			logger.Info("config reloaded",
				"rearmed", report.Rearmed, "restart_required", report.RestartRequired)
		}
	}()

	// OIDC Provider endpoints (gated behind OIDC_PROVIDER_ENABLED)
	if oidcOP != nil {
		// Wrap discovery so it advertises acr_values_supported (zitadel omits it
		// and exposes no hook); all other paths pass through untouched.
		mux.Handle("/.well-known/", federation.NewOPDiscoveryWrapper(oidcOP))
		mux.Handle("/authorize", threatInterceptor.Middleware(oidcOP))
		mux.Handle("/oauth/", threatInterceptor.Middleware(oidcOP))
		mux.Handle("/userinfo", threatInterceptor.Middleware(oidcOP))
		mux.Handle("/keys", oidcOP)
		mux.Handle("/authorize/callback", threatInterceptor.Middleware(oidcOP))
		mux.Handle("/end_session", threatInterceptor.Middleware(oidcOP))
		mux.Handle("/revoke", threatInterceptor.Middleware(oidcOP))
		mux.Handle(
			"GET /auth/oidc/op/complete",
			requireAuthOrLogin(&handlers.OIDCProviderCompleteHandler{Completer: oidcOpStorage}),
		)
	}

	// ── 11. Startup log ──
	logger.Info("auth server starting", "addr", authListen.Addr, "listen_source", authListen.Source, "issuer", cfg.JWTIssuer)

	// ── 12. HTTP server ──
	srv := &http.Server{
		Addr:        authListen.Addr,
		Handler:     h2c.NewHandler(sharedmw.RequestID(mux), &http2.Server{}),
		ReadTimeout: 15 * time.Second,
		IdleTimeout: 120 * time.Second,
	}

	go func() {
		logger.Info("listening", "addr", authListen.Addr)
		if cfg.TLSCertFile != "" {
			srv.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
			if err := srv.ListenAndServeTLS(cfg.TLSCertFile, cfg.TLSKeyFile); err != http.ErrServerClosed {
				logger.Error("server error", "error", err)
			}
		} else {
			if err := srv.ListenAndServe(); err != http.ErrServerClosed {
				logger.Error("server error", "error", err)
			}
		}
	}()

	<-ctx.Done()
	logger.Info("shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	srv.Shutdown(shutdownCtx)
}

func toggleOverrides(cfg *config.Config) map[string]bool {
	return map[string]bool{
		toggle.FeatureKerberos:     cfg.KerberosEnabled,
		toggle.FeatureSAMLSso:      cfg.SAMLEnabled,
		toggle.FeatureOIDCSso:      cfg.OIDCEnabled,
		toggle.FeatureADSync:       cfg.ADSyncEnabled,
		toggle.FeatureOIDCOp:       false,
		toggle.FeatureAppPasswords: true,
		toggle.FeatureThreatFeed:   cfg.ThreatFeedEnabled,
		toggle.FeatureGeoBlock:     cfg.GeoBlockEnabled,
		toggle.FeatureSprayDetect:  cfg.SprayDetectEnabled,
		toggle.FeatureCaptcha:      cfg.CaptchaEnabled,
		toggle.FeatureTarpit:       cfg.TarpitEnabled,
	}
}

func splitCSV(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	var out []string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}
