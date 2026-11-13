package auth

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"setjoin.com/shared/cryptokey"
	"setjoin.com/shared/jwtutil"
)

const testSecret = "super-secret-32-byte-key-for-tests!"

func TestJWTValidate(t *testing.T) {
	p := NewJWTProvider(testSecret, nil, testIssuer)

	token := mintHS256(t, testSecret, testClaims(42, "alice@example.com", true, TypeAccess, time.Hour))

	claims, err := p.Validate(token)
	if err != nil {
		t.Fatalf("validate token: %v", err)
	}
	if claims.UserID != 42 {
		t.Errorf("expected UserID 42, got %d", claims.UserID)
	}
	if claims.Email != "alice@example.com" {
		t.Errorf("expected Email alice@example.com, got %s", claims.Email)
	}
	if !claims.IsAdmin {
		t.Error("expected IsAdmin true")
	}
	if claims.Type != TypeAccess {
		t.Errorf("expected Type access, got %s", claims.Type)
	}
}

// TestJWTValidateSM2 is the regression for the gateway never being able to verify
// SM2 access tokens: chain.go hardcoded the SM2 key to nil, so under ProfileSMx
// (the authserver issues SM2-only tokens, kid=authserver-sm2-1) the gateway's SM2
// verify branch always hit "no SM2 key configured" and rejected every token. With
// the shared SM2 key wired in, the SM2 branch verifies; with no key it must reject.
func TestJWTValidateSM2(t *testing.T) {
	key, _, err := cryptokey.GenerateSM2Key()
	if err != nil {
		t.Fatalf("GenerateSM2Key: %v", err)
	}
	tok := mintSM2(t, key, testClaims(7, "smx@example.com", false, TypeAccess, time.Hour))

	// A gateway provider configured with the shared SM2 key verifies an SM2 token.
	withKey := NewJWTProvider(testSecret, key, testIssuer)
	claims, err := withKey.Validate(tok)
	if err != nil {
		t.Fatalf("gateway WITH the SM2 key must verify an SM2 token, got: %v", err)
	}
	if claims.UserID != 7 {
		t.Errorf("expected UserID 7, got %d", claims.UserID)
	}

	// The pre-fix state: a gateway with NO SM2 key (chain.go passed nil) rejects
	// every SM2 token, locking SMx deployments out at the gateway.
	noKey := NewJWTProvider(testSecret, nil, testIssuer)
	if _, err := noKey.Validate(tok); err == nil {
		t.Error("gateway WITHOUT an SM2 key must reject SM2 tokens, got nil error")
	}
}

func TestJWTInvalidSecret(t *testing.T) {
	p2 := NewJWTProvider("secret-two-32-bytes-for-tests!!", nil, testIssuer)

	token := mintHS256(t, "secret-one-32-bytes-for-tests!!", testClaims(1, "a@b.com", false, TypeAccess, time.Hour))
	if _, err := p2.Validate(token); err == nil {
		t.Error("expected validation to fail with wrong secret")
	}
}

func TestJWTExpired(t *testing.T) {
	p := NewJWTProvider(testSecret, nil, testIssuer)

	token := mintHS256(t, testSecret, testClaims(1, "a@b.com", false, TypeAccess, -time.Hour))
	if _, err := p.Validate(token); err == nil {
		t.Error("expected validation to fail for expired token")
	}
}

// TestJWTWrongIssuer pins the config-drift closure: a token whose iss does not
// match the gateway's configured issuer is rejected.
func TestJWTWrongIssuer(t *testing.T) {
	p := NewJWTProvider(testSecret, nil, testIssuer)

	claims := testClaims(1, "a@b.com", false, TypeAccess, time.Hour)
	claims.Issuer = "wrong-issuer"
	token := mintHS256(t, testSecret, claims)

	if _, err := p.Validate(token); err == nil {
		t.Error("expected validation to fail with wrong issuer")
	}
}

// TestJWTRejectsSelfIssuedKID pins that the gateway no longer accepts its former
// self-issued HS256 kid ("mailserver-hmac-1") — only the authserver's kid.
func TestJWTRejectsSelfIssuedKID(t *testing.T) {
	p := NewJWTProvider(testSecret, nil, testIssuer)

	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, testClaims(1, "a@b.com", false, TypeAccess, time.Hour))
	tok.Header["kid"] = "mailserver-hmac-1"
	token, err := tok.SignedString([]byte(testSecret))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if _, err := p.Validate(token); err == nil {
		t.Error("expected validation to reject the retired mailserver-hmac-1 kid")
	}
}

// TestIssueDriveNativeToken pins the Drive P1 native-token bridge mint: the
// derived token validates, carries the requested scope, and — the load-bearing
// bit — carries the SOURCE claims' JTI/FamilyID forward unchanged so the CA-3a
// denylist can revoke it with the session it was minted from.
func TestIssueDriveNativeToken(t *testing.T) {
	p := NewJWTProvider(testSecret, nil, testIssuer)
	src := testClaims(42, "alice@example.com", false, TypeAccess, time.Hour)
	src.JTI = "session-jti-123"
	src.FamilyID = "family-abc"
	src.Cnf = &jwtutil.ConfirmationClaim{JKT: "device-bound-thumbprint"}
	src.AccountType = jwtutil.AccountTypeGuest

	token, expiresAt, err := p.IssueDriveNativeToken(src, "drive", 12*time.Hour)
	if err != nil {
		t.Fatalf("IssueDriveNativeToken: %v", err)
	}
	if expiresAt.Before(time.Now().Add(11 * time.Hour)) {
		t.Errorf("expiresAt = %v, want ~12h out", expiresAt)
	}

	claims, err := p.Validate(token)
	if err != nil {
		t.Fatalf("gateway must validate its own minted drive-native token: %v", err)
	}
	if claims.UserID != 42 {
		t.Errorf("UserID = %d, want 42", claims.UserID)
	}
	if claims.Scp != "drive" {
		t.Errorf("Scp = %q, want drive", claims.Scp)
	}
	if claims.JTI != "session-jti-123" {
		t.Errorf("JTI = %q, want it carried forward from the source session (revocation-with-session)", claims.JTI)
	}
	if claims.FamilyID != "family-abc" {
		t.Errorf("FamilyID = %q, want it carried forward from the source session", claims.FamilyID)
	}
	if claims.Cnf != nil {
		t.Error("Cnf must NEVER be copied — the derived token must stay unbound (skips the DPoP branch)")
	}
	if claims.AccountType != jwtutil.AccountTypeGuest {
		t.Errorf("AccountType = %q, want it carried forward from the source claims (POST /drive/native-token is guest-DENIED at the route layer, but the mint itself must not silently launder a guest claim)", claims.AccountType)
	}
}

// TestIssueDriveNativeTokenDistinctKid pins that the mint uses its OWN kid
// (kidDriveNative), never the retired general-issuance "mailserver-hmac-1" kid
// TestJWTRejectsSelfIssuedKID still requires be rejected.
func TestIssueDriveNativeTokenDistinctKid(t *testing.T) {
	p := NewJWTProvider(testSecret, nil, testIssuer)
	token, _, err := p.IssueDriveNativeToken(testClaims(1, "a@b.com", false, TypeAccess, time.Hour), "drive", time.Hour)
	if err != nil {
		t.Fatalf("IssueDriveNativeToken: %v", err)
	}
	parsed, _, err := jwt.NewParser().ParseUnverified(token, jwt.MapClaims{})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if kid, _ := parsed.Header["kid"].(string); kid != kidDriveNative || kid == "mailserver-hmac-1" {
		t.Errorf("kid = %q, want %q and never the retired self-issuance kid", kid, kidDriveNative)
	}
}

func TestIssueMailAttachmentTokenExactBindingAndUniqueJTI(t *testing.T) {
	p := NewJWTProvider(testSecret, nil, testIssuer)
	src := testClaims(42, "alice@example.com", false, TypeAccess, time.Hour)
	src.JTI = "origin-session-jti"
	src.FamilyID = "origin-family"
	src.Device = &jwtutil.DeviceClaim{ID: "device-fingerprint", Platform: "desktop"}
	src.Cnf = &jwtutil.ConfirmationClaim{JKT: "origin-binding"}
	binding := jwtutil.AttachmentTransferClaim{
		SHA256:            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		AccountID:         71,
		MailboxID:         70,
		DeviceID:          9,
		DeviceFingerprint: "device-fingerprint",
		PolicyGeneration:  "policy-digest",
	}

	tokenA, expiresAt, err := p.IssueMailAttachmentToken(src, binding)
	if err != nil {
		t.Fatalf("IssueMailAttachmentToken: %v", err)
	}
	tokenB, _, err := p.IssueMailAttachmentToken(src, binding)
	if err != nil {
		t.Fatalf("IssueMailAttachmentToken second mint: %v", err)
	}
	if expiresAt.Before(time.Now().Add(4*time.Minute+50*time.Second)) ||
		expiresAt.After(time.Now().Add(5*time.Minute+5*time.Second)) {
		t.Fatalf("expiresAt = %v, want fixed five-minute lifetime", expiresAt)
	}

	claimsA, err := p.Validate(tokenA)
	if err != nil {
		t.Fatalf("validate A: %v", err)
	}
	claimsB, err := p.Validate(tokenB)
	if err != nil {
		t.Fatalf("validate B: %v", err)
	}
	if claimsA.JTI == src.JTI || claimsA.JTI == "" || claimsA.JTI == claimsB.JTI {
		t.Fatalf("derived JTIs = %q/%q, want unique and distinct from origin %q", claimsA.JTI, claimsB.JTI, src.JTI)
	}
	if claimsA.FamilyID != src.FamilyID || claimsA.Scp != "mail-attachment" {
		t.Fatalf("family/scope = %q/%q", claimsA.FamilyID, claimsA.Scp)
	}
	if claimsA.Attachment == nil || claimsA.Attachment.OriginJTI != src.JTI ||
		claimsA.Attachment.OriginIssuedAt != src.IssuedAt.Unix() ||
		claimsA.Attachment.SHA256 != binding.SHA256 ||
		claimsA.Attachment.PolicyGeneration != binding.PolicyGeneration {
		t.Fatalf("attachment binding = %+v", claimsA.Attachment)
	}
	if claimsA.Cnf != nil {
		t.Fatal("derived attachment token must not copy cnf")
	}
	if claimsA.Device == nil || claimsA.Device.ID != src.Device.ID {
		t.Fatalf("device claim = %+v, want originating device", claimsA.Device)
	}

	parsed, _, err := jwt.NewParser().ParseUnverified(tokenA, jwt.MapClaims{})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if kid, _ := parsed.Header["kid"].(string); kid != kidMailAttachment || kid == kidDriveNative {
		t.Fatalf("kid = %q, want dedicated %q", kid, kidMailAttachment)
	}
}

func TestIssueMailAttachmentTokenRejectsUnfencedOrigin(t *testing.T) {
	p := NewJWTProvider(testSecret, nil, testIssuer)
	for name, src := range map[string]*Claims{
		"nil":         nil,
		"missing jti": testClaims(1, "a@b.com", false, TypeAccess, time.Hour),
		"refresh":     testClaims(1, "a@b.com", false, TypeRefresh, time.Hour),
	} {
		t.Run(name, func(t *testing.T) {
			if src != nil && name == "refresh" {
				src.JTI = "refresh-jti"
			}
			if _, _, err := p.IssueMailAttachmentToken(src, jwtutil.AttachmentTransferClaim{}); err == nil {
				t.Fatal("unfenced origin accepted")
			}
		})
	}
	src := testClaims(1, "a@b.com", false, TypeAccess, time.Hour)
	src.JTI = "origin"
	if _, _, err := p.IssueMailAttachmentToken(src, jwtutil.AttachmentTransferClaim{OriginJTI: "request-owned"}); err == nil {
		t.Fatal("request-owned origin accepted")
	}
}

func TestMailAttachmentTokenUsesDedicatedDerivedKey(t *testing.T) {
	p := NewJWTProvider(testSecret, nil, testIssuer)
	src := testClaims(42, "alice@example.com", false, TypeAccess, time.Hour)
	src.JTI = "origin-session"
	token, _, err := p.IssueMailAttachmentToken(src, jwtutil.AttachmentTransferClaim{
		SHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	})
	if err != nil {
		t.Fatalf("IssueMailAttachmentToken: %v", err)
	}
	if _, err := p.Validate(token); err != nil {
		t.Fatalf("dedicated verifier rejected minted token: %v", err)
	}

	claims := testClaims(42, "alice@example.com", false, TypeAccess, time.Hour)
	claims.JTI = "forged-under-raw-secret"
	forged := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	forged.Header["kid"] = kidMailAttachment
	forgedToken, err := forged.SignedString([]byte(testSecret))
	if err != nil {
		t.Fatalf("sign forged token: %v", err)
	}
	if _, err := p.Validate(forgedToken); err == nil {
		t.Fatal("attachment kid signed with raw JWT secret must be rejected")
	}
}

func TestMailAttachmentTokenRollingRotationMixedPods(t *testing.T) {
	const (
		authSecret = "shared-auth-secret-32-bytes-for-test!!"
		oldSecret  = "old-gateway-secret-32-bytes-for-test!!"
		newSecret  = "new-gateway-secret-32-bytes-for-test!!"
	)
	oldPod := NewJWTProvider(authSecret, nil, testIssuer)
	oldPod.SetMailAttachmentSecret(oldSecret)
	oldPod.SetMailAttachmentPreviousSecret(newSecret)
	newPod := NewJWTProvider(authSecret, nil, testIssuer)
	newPod.SetMailAttachmentSecret(newSecret)
	newPod.SetMailAttachmentPreviousSecret(oldSecret)

	src := testClaims(42, "alice@example.com", false, TypeAccess, time.Hour)
	src.JTI = "origin-session"
	binding := jwtutil.AttachmentTransferClaim{
		SHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	}
	oldToken, _, err := oldPod.IssueMailAttachmentToken(src, binding)
	if err != nil {
		t.Fatalf("mint old token: %v", err)
	}
	newToken, _, err := newPod.IssueMailAttachmentToken(src, binding)
	if err != nil {
		t.Fatalf("mint new token: %v", err)
	}
	for name, tc := range map[string]struct {
		provider *JWTProvider
		token    string
	}{
		"new pod accepts old token": {newPod, oldToken},
		"old pod accepts new token": {oldPod, newToken},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := tc.provider.Validate(tc.token); err != nil {
				t.Fatalf("mixed-pod token rejected: %v", err)
			}
		})
	}

	newOnly := NewJWTProvider(authSecret, nil, testIssuer)
	newOnly.SetMailAttachmentSecret(newSecret)
	if _, err := newOnly.Validate(oldToken); err == nil {
		t.Fatal("old token must fail after the previous key is removed")
	}

	// The retiring secret is attachment-only. It must not widen normal auth JWT
	// acceptance on a new pod.
	oldAttachmentMasterNormal := mintHS256(t, oldSecret, testClaims(42, "alice@example.com", false, TypeAccess, time.Hour))
	if _, err := newPod.Validate(oldAttachmentMasterNormal); err == nil {
		t.Fatal("attachment previous master must not verify normal auth tokens")
	}
	sharedNormal := mintHS256(t, authSecret, testClaims(42, "alice@example.com", false, TypeAccess, time.Hour))
	if _, err := oldPod.Validate(sharedNormal); err != nil {
		t.Fatalf("attachment rotation must not disrupt normal auth on old pod: %v", err)
	}
	if _, err := newPod.Validate(sharedNormal); err != nil {
		t.Fatalf("attachment rotation must not disrupt normal auth on new pod: %v", err)
	}
}

func TestJWTTypeChecks(t *testing.T) {
	p := NewJWTProvider(testSecret, nil, testIssuer)

	for _, tc := range []TokenType{TypeAccess, TypeMFAPending, TypeRefresh, TypeForcePasswordChange} {
		token := mintHS256(t, testSecret, testClaims(1, "a@b.com", false, tc, time.Hour))
		claims, err := p.Validate(token)
		if err != nil {
			t.Fatalf("type %s: unexpected validation error: %v", tc, err)
		}
		if claims.Type != tc {
			t.Errorf("type %s: expected type %s, got %s", tc, tc, claims.Type)
		}
	}
}
