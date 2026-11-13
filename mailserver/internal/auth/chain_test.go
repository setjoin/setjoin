package auth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"setjoin.com/shared/permissions"
	"setjoin.com/shared/testsupport"
)

func TestContextWithUser(t *testing.T) {
	claims := &Claims{UserID: 42, Email: "alice@example.com", IsAdmin: true, Type: TypeAccess}
	ctx := ContextWithUser(context.Background(), claims)
	got := UserFromContext(ctx)
	if got == nil {
		t.Fatal("UserFromContext returned nil")
	}
	if got.UserID != 42 {
		t.Errorf("UserID = %d, want 42", got.UserID)
	}
	if got.Email != "alice@example.com" {
		t.Errorf("Email = %q, want alice@example.com", got.Email)
	}
	if !got.IsAdmin {
		t.Error("IsAdmin should be true")
	}
}

func TestUserFromContextMissing(t *testing.T) {
	ctx := context.Background()
	got := UserFromContext(ctx)
	if got != nil {
		t.Error("UserFromContext should return nil for empty context")
	}
}

func TestContextOverwrite(t *testing.T) {
	ctx := ContextWithUser(context.Background(), &Claims{UserID: 1})
	ctx = ContextWithUser(ctx, &Claims{UserID: 2})
	got := UserFromContext(ctx)
	if got.UserID != 2 {
		t.Errorf("UserID = %d, want 2", got.UserID)
	}
}

// TestAuthMethodField guards that basic and kerberos success Claims carry a
// non-empty AuthMethod equal to the method's Slug(). Both success paths build
// Claims with AuthMethod: m.Slug(), so runtime CA eval sees "basic_auth"/
// "kerberos" instead of defaulting an empty field to jwt_bearer (audit #24).
// The full success path needs a DB (password / principal lookup), so this
// asserts the Slug() the code embeds matches the CA-policy discriminator — if
// Slug() drifts, both the CA policy match and this test drift together.
func TestAuthMethodField(t *testing.T) {
	basic := &basicAuthMethod{}
	if basic.Slug() != "basic_auth" {
		t.Errorf("basic AuthMethod/Slug = %q, want basic_auth", basic.Slug())
	}
	krb := &kerberosAuthMethod{}
	if krb.Slug() != "kerberos" {
		t.Errorf("kerberos AuthMethod/Slug = %q, want kerberos", krb.Slug())
	}
}

func TestJWTAuthMethodSlugAndPriority(t *testing.T) {
	jwtProv := NewJWTProvider(testSecret, nil, testIssuer)
	m := &jwtAuthMethod{jwt: jwtProv}
	if m.Slug() != "jwt_bearer" {
		t.Errorf("slug = %q, want jwt_bearer", m.Slug())
	}
	if m.Priority() != 10 {
		t.Errorf("priority = %d, want 10", m.Priority())
	}
}

func TestJWTAuthMethodNoToken(t *testing.T) {
	jwtProv := NewJWTProvider(testSecret, nil, testIssuer)
	m := &jwtAuthMethod{jwt: jwtProv}
	req, _ := http.NewRequest(http.MethodGet, "/", nil)
	_, err := m.Authenticate(req)
	if err == nil {
		t.Error("expected error when no token provided")
	}
}

func TestJWTAuthMethodInvalidToken(t *testing.T) {
	jwtProv := NewJWTProvider(testSecret, nil, testIssuer)
	m := &jwtAuthMethod{jwt: jwtProv}
	req, _ := http.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer invalid-token")
	_, err := m.Authenticate(req)
	if err == nil {
		t.Error("expected error for invalid token")
	}
}

func TestJWTAuthMethodValidAccessToken(t *testing.T) {
	jwtProv := NewJWTProvider(testSecret, nil, testIssuer)
	m := &jwtAuthMethod{jwt: jwtProv}
	token := mintHS256(t, testSecret, testClaims(42, "alice@example.com", false, TypeAccess, time.Hour))
	req, _ := http.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	claims, err := m.Authenticate(req)
	if err != nil {
		t.Fatalf("authenticate failed: %v", err)
	}
	if claims.UserID != 42 {
		t.Errorf("UserID = %d, want 42", claims.UserID)
	}
}

func TestJWTAuthMethodRejectsMFAPending(t *testing.T) {
	jwtProv := NewJWTProvider(testSecret, nil, testIssuer)
	m := &jwtAuthMethod{jwt: jwtProv}
	token := mintHS256(t, testSecret, testClaims(42, "alice@example.com", false, TypeMFAPending, time.Hour))
	req, _ := http.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	_, err := m.Authenticate(req)
	if err == nil {
		t.Error("expected error for MFA pending token")
	}
}

func TestJWTAuthMethodRejectsRefreshToken(t *testing.T) {
	jwtProv := NewJWTProvider(testSecret, nil, testIssuer)
	m := &jwtAuthMethod{jwt: jwtProv}
	token := mintHS256(t, testSecret, testClaims(42, "alice@example.com", false, TypeRefresh, time.Hour))
	req, _ := http.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	_, err := m.Authenticate(req)
	if err == nil {
		t.Error("expected error for refresh token")
	}
}

func TestJWTAuthMethodRejectsForcePasswordChange(t *testing.T) {
	// TypeForcePasswordChange tokens are NOT accepted by the generic auth middleware.
	// Only the change-password handler accepts them directly.
	jwtProv := NewJWTProvider(testSecret, nil, testIssuer)
	m := &jwtAuthMethod{jwt: jwtProv}
	token := mintHS256(t, testSecret, testClaims(42, "alice@example.com", false, TypeForcePasswordChange, time.Hour))
	req, _ := http.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	_, err := m.Authenticate(req)
	if err == nil {
		t.Error("expected error for force_pw_change token in generic middleware")
	}
}

func TestJWTForcePasswordChangeRoundTrip(t *testing.T) {
	// Verify the token type issues and validates correctly even though
	// the generic middleware rejects it (change-password handler checks directly).
	jwtProv := NewJWTProvider(testSecret, nil, testIssuer)
	token := mintHS256(t, testSecret, testClaims(42, "alice@example.com", false, TypeForcePasswordChange, time.Hour))
	claims, err := jwtProv.Validate(token)
	if err != nil {
		t.Fatalf("validate failed: %v", err)
	}
	if claims.UserID != 42 || claims.Type != TypeForcePasswordChange {
		t.Errorf("wrong claims: uid=%d type=%s", claims.UserID, claims.Type)
	}
}

func TestJWTAuthMethodCookieFallback(t *testing.T) {
	jwtProv := NewJWTProvider(testSecret, nil, testIssuer)
	m := &jwtAuthMethod{jwt: jwtProv}
	token := mintHS256(t, testSecret, testClaims(42, "alice@example.com", false, TypeAccess, time.Hour))
	req, _ := http.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: accessTokenCookie, Value: token})
	claims, err := m.Authenticate(req)
	if err != nil {
		t.Fatalf("authenticate via cookie failed: %v", err)
	}
	if claims.UserID != 42 {
		t.Errorf("UserID = %d, want 42", claims.UserID)
	}
}

// ── RBAC: Permission resolution on Claims ──────────────────────────────────

func TestClaimsHasPermission_DirectMatch(t *testing.T) {
	claims := &Claims{
		UserID:      1,
		Email:       "admin@example.com",
		IsAdmin:     true,
		Permissions: []string{permissions.PermUsersRead, permissions.PermUsersCreate},
		Type:        TypeAccess,
	}
	if !claims.HasPermission(permissions.PermUsersRead) {
		t.Error("expected to have users.read")
	}
	if claims.HasPermission(permissions.PermUsersDelete) {
		t.Error("expected NOT to have users.delete")
	}
}

func TestClaimsHasPermission_LegacyIsAdminDenied(t *testing.T) {
	// Bridge deleted: IsAdmin=true with no resolved permissions grants nothing —
	// authorization flows exclusively from the Permissions slice (the admin_role
	// enum that once fed a fallback is gone).
	claims := &Claims{
		UserID:  1,
		Email:   "admin@example.com",
		IsAdmin: true,
		Type:    TypeAccess,
	}
	if claims.HasPermission(permissions.PermSystemConfig) {
		t.Error("IsAdmin with nil Permissions must NOT have access (bridge deleted)")
	}
	if claims.HasPermission(permissions.PermUsersRead) {
		t.Error("IsAdmin with nil Permissions must NOT have access (bridge deleted)")
	}
}

func TestClaimsHasPermission_NonAdminNoPermissions(t *testing.T) {
	claims := &Claims{
		UserID:  2,
		Email:   "user@example.com",
		IsAdmin: false,
		Type:    TypeAccess,
	}
	if claims.HasPermission(permissions.PermUsersRead) {
		t.Error("non-admin without permissions should NOT have any access")
	}
}

func TestResolvePermissionsLoadsGovernedAuthority(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()
	tag := time.Now().UnixNano()

	var domainID, userID, roleID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO domains(name,is_local) VALUES($1,TRUE) RETURNING id`,
		fmt.Sprintf("auth-chain-%d.test", tag),
	).Scan(&domainID); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx,
		`INSERT INTO users(username,email,display_name,domain_id)
		 VALUES($1,$1||'@auth-chain.test',$1,$2) RETURNING id`,
		fmt.Sprintf("auth-chain-%d", tag), domainID,
	).Scan(&userID); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx,
		`INSERT INTO admin_role_groups(name,permissions)
		 VALUES($1,$2) RETURNING id`,
		fmt.Sprintf("auth-chain-role-%d", tag),
		[]string{permissions.PermUsersRead, permissions.PermIdentityWrite},
	).Scan(&roleID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO admin_role_assignments(user_id,role_group_id,granted_by)
		 VALUES($1,$2,$1)`,
		userID, roleID,
	); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM admin_role_assignments WHERE user_id=$1`, userID)
		_, _ = pool.Exec(ctx, `DELETE FROM admin_role_groups WHERE id=$1`, roleID)
		_, _ = pool.Exec(ctx, `DELETE FROM users WHERE id=$1`, userID)
		_, _ = pool.Exec(ctx, `DELETE FROM domains WHERE id=$1`, domainID)
	})

	claims := &Claims{UserID: userID, IsAdmin: true}
	(&Chain{pool: pool}).resolvePermissions(ctx, claims)
	if !claims.HasPermission(permissions.PermUsersRead) ||
		!claims.HasPermission(permissions.PermIdentityWrite) {
		t.Fatalf("resolved permissions=%v, want governed role union", claims.Permissions)
	}
	if !permissions.HasPermission(claims.GlobalPermissions, permissions.PermIdentityWrite) {
		t.Fatalf("global permissions=%v, want identity.write", claims.GlobalPermissions)
	}
	if claims.DomainScope != nil {
		t.Fatalf("global role unexpectedly narrowed to domain %v", claims.DomainScope)
	}
}

func TestReloadMethodsFailsClosedWhenStoreUnavailable(t *testing.T) {
	pool, err := pgxpool.New(
		context.Background(),
		"postgres://setjoin-test:unused@127.0.0.1:1/setjoin?connect_timeout=1",
	)
	if err != nil {
		t.Fatal(err)
	}
	pool.Close()
	chain := &Chain{
		pool: pool,
		jwt:  NewJWTProvider(testSecret, nil, testIssuer),
	}
	if err := chain.ReloadMethods(context.Background()); err == nil {
		t.Fatal("closed auth-method store unexpectedly reloaded")
	}
	if len(chain.methods) != 1 || chain.methods[0].Slug() != "jwt_bearer" {
		t.Fatalf("fail-closed methods=%v, want JWT-only", chain.methods)
	}
}

func TestClaimsHasPermission_AdminWithEmptyPermissions(t *testing.T) {
	// Bridge deleted: IsAdmin=true with explicitly empty (but non-nil) Permissions
	// grants nothing.
	claims := &Claims{
		UserID:      1,
		Email:       "admin@example.com",
		IsAdmin:     true,
		Permissions: []string{},
		Type:        TypeAccess,
	}
	if claims.HasPermission(permissions.PermSystemConfig) {
		t.Error("IsAdmin with empty Permissions must NOT have access (bridge deleted)")
	}
}

// ── Drive P1 native-token scope containment (batch-3 item 6) ───────────────

// TestAuthenticateRequestRejectsScopedTokenOffSurface pins the guard: a token
// carrying a non-empty Scp (minted by IssueDriveNativeToken) must never
// authenticate a request whose path is outside "/"+scp — a leaked mirror
// token must stay contained to the one surface it was minted for.
func TestAuthenticateRequestRejectsScopedTokenOffSurface(t *testing.T) {
	jwtProv := NewJWTProvider(testSecret, nil, testIssuer)
	c := &Chain{jwt: jwtProv, methods: []AuthMethod{&jwtAuthMethod{jwt: jwtProv}}}

	token, _, err := jwtProv.IssueDriveNativeToken(testClaims(42, "alice@example.com", false, TypeAccess, time.Hour), "drive", 12*time.Hour)
	if err != nil {
		t.Fatalf("IssueDriveNativeToken: %v", err)
	}

	req, _ := http.NewRequest(http.MethodGet, "/jmap", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	if _, err := c.AuthenticateRequest(req); err == nil {
		t.Error("expected a scp=drive token to be rejected on a non-/drive path")
	}
}

// TestAuthenticateRequestAcceptsScopedTokenOnItsSurface is the positive half:
// the same token authenticates fine on a /drive path.
func TestAuthenticateRequestAcceptsScopedTokenOnItsSurface(t *testing.T) {
	jwtProv := NewJWTProvider(testSecret, nil, testIssuer)
	c := &Chain{jwt: jwtProv, methods: []AuthMethod{&jwtAuthMethod{jwt: jwtProv}}}

	token, _, err := jwtProv.IssueDriveNativeToken(testClaims(42, "alice@example.com", false, TypeAccess, time.Hour), "drive", 12*time.Hour)
	if err != nil {
		t.Fatalf("IssueDriveNativeToken: %v", err)
	}

	req, _ := http.NewRequest(http.MethodGet, "/drive/spaces", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	claims, err := c.AuthenticateRequest(req)
	if err != nil {
		t.Fatalf("expected a scp=drive token to authenticate on /drive/*, got: %v", err)
	}
	if claims.UserID != 42 {
		t.Errorf("UserID = %d, want 42", claims.UserID)
	}
	if claims.Scp != "drive" {
		t.Errorf("Scp = %q, want drive", claims.Scp)
	}
}

func TestAuthenticateRequestRejectsScopedTokenOnPrefixCollision(t *testing.T) {
	jwtProv := NewJWTProvider(testSecret, nil, testIssuer)
	c := &Chain{jwt: jwtProv, methods: []AuthMethod{&jwtAuthMethod{jwt: jwtProv}}}
	token, _, err := jwtProv.IssueDriveNativeToken(testClaims(42, "alice@example.com", false, TypeAccess, time.Hour), "drive", time.Hour)
	if err != nil {
		t.Fatalf("IssueDriveNativeToken: %v", err)
	}
	for _, path := range []string{"/drive-evil", "/drive2", "/driver"} {
		req, _ := http.NewRequest(http.MethodGet, path, nil)
		req.Header.Set("Authorization", "Bearer "+token)
		if _, err := c.AuthenticateRequest(req); err == nil {
			t.Errorf("prefix-collision path %q accepted", path)
		}
	}
}

// TestAuthenticateRequestUnscopedTokenAnyPath — a NORMAL (Scp=="") token is
// unaffected by the guard: it authenticates on any path, exactly as before.
func TestAuthenticateRequestUnscopedTokenAnyPath(t *testing.T) {
	jwtProv := NewJWTProvider(testSecret, nil, testIssuer)
	c := &Chain{jwt: jwtProv, methods: []AuthMethod{&jwtAuthMethod{jwt: jwtProv}}}
	token := mintHS256(t, testSecret, testClaims(42, "alice@example.com", false, TypeAccess, time.Hour))

	req, _ := http.NewRequest(http.MethodGet, "/jmap", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	if _, err := c.AuthenticateRequest(req); err != nil {
		t.Fatalf("unscoped token must authenticate on any path, got: %v", err)
	}
}

// ── Push-token acceptance seam (WS/SSE) ────────────────────────────────────

// TestAuthenticatePushToken_Guards pins the ONE push-acceptance seam: a scoped
// mirror token (IssueDriveNativeToken) is rejected, a refresh token (empty Scp
// but wrong Type — the F2 regression guard, since dropping the Type check would
// let a refresh token open a push stream) is rejected, and a plain unscoped
// access token is accepted. This is the primary defense for the WS/SSE push
// surface; scripts/check-scope-containment.sh is the backstop.
func TestAuthenticatePushToken_Guards(t *testing.T) {
	jwtProv := NewJWTProvider(testSecret, nil, testIssuer)
	c := &Chain{jwt: jwtProv}

	// scoped mirror token → reject
	driveTok, _, err := jwtProv.IssueDriveNativeToken(testClaims(42, "alice@example.com", false, TypeAccess, time.Hour), "drive", time.Hour)
	if err != nil {
		t.Fatalf("IssueDriveNativeToken: %v", err)
	}
	if _, err := c.AuthenticatePushToken(context.Background(), driveTok); err == nil {
		t.Fatal("scoped token must be rejected on the push acceptance path")
	}

	// refresh token (empty Scp, wrong Type) → reject  [F2 regression guard]
	refreshTok := mintHS256(t, testSecret, testClaims(42, "alice@example.com", false, TypeRefresh, time.Hour))
	if _, err := c.AuthenticatePushToken(context.Background(), refreshTok); err == nil {
		t.Fatal("refresh token must be rejected on the push acceptance path")
	}

	// access token without iat → reject: the runtime registry cannot place it
	// against an all-session revocation watermark.
	missingIssuedAt := testClaims(42, "alice@example.com", false, TypeAccess, time.Hour)
	missingIssuedAt.IssuedAt = nil
	missingIATToken := mintHS256(t, testSecret, missingIssuedAt)
	if _, err := c.AuthenticatePushToken(context.Background(), missingIATToken); !errors.Is(err, ErrMissingIssuedAtOnPush) {
		t.Fatalf("missing-iat access token error = %v, want ErrMissingIssuedAtOnPush", err)
	}

	// plain access token (Scp=="", Type==access) → accept
	fullTok := mintHS256(t, testSecret, testClaims(42, "alice@example.com", false, TypeAccess, time.Hour))
	if _, err := c.AuthenticatePushToken(context.Background(), fullTok); err != nil {
		t.Fatalf("unscoped access token must be accepted: %v", err)
	}
}

// ── F4: ClientCertPool (mTLS TLS listener) ──────────────────────────────────

// TestClientCertPoolNilWhenNoCertMethod verifies that a Chain with only a JWT
// auth method (no certificate method) returns nil from ClientCertPool — the
// TLS listener sets ClientCAs=nil, which is harmless and keeps Bearer fallback.
func TestClientCertPoolNilWhenNoCertMethod(t *testing.T) {
	c := &Chain{}
	c.methods = []AuthMethod{} // no cert method loaded
	if pool := c.ClientCertPool(); pool != nil {
		t.Fatal("ClientCertPool must be nil when no certificate method is loaded")
	}
}

// TestClientCertPoolReturnsCertMethodRoots verifies that a Chain with a
// certAuthMethod returns the CA root pool from ClientCertPool — main.go sets
// this on tls.Config.ClientCAs so the TLS handshake sends a CertificateRequest.
func TestClientCertPoolReturnsCertMethodRoots(t *testing.T) {
	_, roots := mkCert(t, "alice@test", time.Now().Add(time.Hour))
	cm := &certAuthMethod{roots: roots}
	c := &Chain{}
	c.methods = []AuthMethod{cm}
	got := c.ClientCertPool()
	if got == nil {
		t.Fatal("ClientCertPool must return the cert method's root pool")
	}
	// Verify it's the same pool object (not a copy).
	if got != roots {
		t.Fatal("ClientCertPool must return the exact pool from the cert method")
	}
}

func TestInstallFailClosedMethodsDropsStalePasswordMethod(t *testing.T) {
	jwtProv := NewJWTProvider(testSecret, nil, testIssuer)
	c := &Chain{
		jwt: jwtProv,
		methods: []AuthMethod{
			&basicAuthMethod{},
			&jwtAuthMethod{jwt: jwtProv},
		},
	}

	c.installFailClosedMethods()

	c.mu.RLock()
	defer c.mu.RUnlock()
	if len(c.methods) != 1 || c.methods[0].Slug() != "jwt_bearer" {
		t.Fatalf("fail-closed methods = %#v, want only jwt_bearer", c.methods)
	}
}
