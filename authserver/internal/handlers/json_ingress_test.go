package handlers

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

type jsonIngressInventoryRow struct {
	Endpoint      string
	File          string
	Function      string
	Decoder       string
	SizeBound     string
	TrailingJSON  string
	UnknownFields string
	ContentType   string
	EmptyBody     string
	ErrorResponse string
	SourceMarker  string
}

// authJSONIngressInventory is the executable R5-2 characterization artifact.
// It intentionally records compatibility behavior instead of prescribing one
// global JSON policy for security-sensitive and protocol-owned exceptions.
var authJSONIngressInventory = []jsonIngressInventoryRow{
	// med-shard2-006: Login decodes through the shared bounded ingress so the
	// server-computed body digest is stamped before the login CA evaluation's
	// device-proof resolution reads X-Device-* headers (the decode consumes the
	// body first). Same 400 problem contract; the size bound is now the shared
	// 1 MiB ingress cap instead of unbounded.
	{"POST /auth/login", "auth.go", "Login", "shared bounded", "1 MiB", "accepted", "accepted", "ignored", "400", `400 problem: "invalid JSON"`, "decodeBoundedAuthJSON"},
	{"PUT /auth/password", "auth.go", "ChangePassword", "direct", "unbounded", "accepted", "accepted", "ignored", "400", `400 problem: "invalid JSON"`, "json.NewDecoder"},
	{"POST /auth/device/register", "device.go", "DeviceRegister", "direct + MaxBytesReader", "1 MiB", "accepted", "accepted", "ignored", "400", `400 problem: "invalid JSON"`, "json.NewDecoder"},
	{"POST /auth/mfa/approve", "device.go", "MFAApprove", "direct", "unbounded", "accepted", "accepted", "ignored", "400", `400 problem: "invalid JSON"`, "json.NewDecoder"},
	{"POST /auth/forgot-password/begin", "forgot_password.go", "ForgotPasswordBegin", "direct", "1 MiB", "accepted", "accepted", "ignored", "400", `400 JSON: {"error":"invalid JSON"}`, "json.NewDecoder"},
	{"POST /auth/forgot-password/verify", "forgot_password.go", "ForgotPasswordVerify", "direct", "1 MiB", "accepted", "accepted", "ignored", "400", `400 JSON: {"error":"invalid JSON"}`, "json.NewDecoder"},
	{"POST /auth/forgot-password/reset", "forgot_password.go", "ForgotPasswordReset", "direct", "1 MiB", "accepted", "accepted", "ignored", "400", `400 JSON: {"error":"invalid JSON"}`, "json.NewDecoder"},
	{"POST /auth/guest-invite/accept", "guest_invite.go", "GuestInviteAcceptPost", "strict direct", "1 MiB", "rejected", "rejected", "ignored", "400", `400 JSON: {"error":"invalid JSON body"}`, "DisallowUnknownFields"},
	{"DELETE /auth/identity-links/{id}", "identity_links.go", "IdentityUnlink", "direct", "16 KiB", "accepted", "accepted", "ignored", "400", `400 problem: "invalid identity unlink"`, "json.NewDecoder"},
	{"POST /auth/introspect JSON branch", "introspect_handler.go", "authenticateAndExtractToken", "content-negotiated direct", "unbounded", "accepted", "accepted", "application/json prefix selects JSON; otherwise form", "400", `400 problem: "token is required"`, "json.NewDecoder"},
	{"POST /auth/backup-codes/verify authenticated", "mfa.go", "VerifyBackupCode", "direct", "unbounded", "accepted", "accepted", "ignored", "400", `400 problem: "invalid JSON"`, "json.NewDecoder"},
	{"POST /auth/backup-codes/verify MFA", "mfa.go", "BackupCodeVerify", "shared bounded", "1 MiB", "accepted", "accepted", "ignored", "400", `400 problem: "invalid JSON"`, "decodeBoundedAuthJSON"},
	{"POST /auth/push/verify", "push.go", "PushMFAVerify", "shared bounded", "1 MiB", "accepted", "accepted", "ignored", "400", `400 problem: "invalid JSON"`, "decodeBoundedAuthJSON"},
	{"POST /auth/push/status", "push.go", "PushMFAStatus", "shared bounded", "1 MiB", "accepted", "accepted", "ignored", "400", `400 problem: "invalid JSON"`, "decodeBoundedAuthJSON"},
	{"POST /auth/mfa/push/send", "push_mfa.go", "PushMFASend", "direct", "1 MiB", "accepted", "accepted", "ignored", "400", `400 problem: "mfa_token is required"`, "json.NewDecoder"},
	{"POST /auth/scim/disable", "scim.go", "ServeHTTP", "direct", "unbounded", "accepted", "accepted", "ignored", "400", `400 problem: "user_id or external_id is required"`, "json.NewDecoder"},
	{"POST /auth/refresh", "session.go", "Refresh", "shared bounded", "1 MiB", "accepted", "accepted", "ignored", "400", `400 problem: "invalid JSON"`, "decodeBoundedAuthJSON"},
	{"POST /terms/accept", "terms.go", "Accept", "direct", "unbounded", "accepted", "accepted", "ignored", "400", `400 problem: "tou_id and version required"`, "json.NewDecoder"},
	// REVISED (possession scheme v7 §3): TOTPSetup is a header-transport GET
	// under the gate — it reads no request body, so no decoder marker applies.
	{"GET /auth/totp/setup (header transport, no body)", "totp.go", "TOTPSetup", "no body decoded (grant token via X-MFA-Reauth header)", "none", "n/a", "n/a", "n/a", "n/a (gated arm answers 403 reauth_required)", "403 problem: \"reauth_required\"", "reauthTokenFromRequest"},
	{"POST /auth/mfa/possession/totp", "mfa_possession.go", "MFAPossessionTOTP", "shared bounded (strict application/json at the mount)", "1 MiB", "accepted", "accepted", "ignored", "400", `400 problem: "invalid JSON"`, "decodeBoundedAuthJSON"},
	{"POST /auth/mfa/possession/webauthn/begin", "mfa_possession.go", "MFAPossessionWebAuthnBegin", "shared bounded (strict application/json at the mount)", "1 MiB", "accepted", "accepted", "ignored", "400", `400 problem: "invalid JSON"`, "decodeBoundedAuthJSON"},
	{"POST /auth/mfa/possession/webauthn/finish", "mfa_possession.go", "MFAPossessionWebAuthnFinish", "bounded read-once decode (strict application/json at the mount; raw bytes re-verified for the assertion)", "1 MiB", "accepted", "accepted", "ignored", "400", `400 problem: "invalid JSON"`, "decodePossessionBody"},
	{"POST /auth/totp/enroll/setup", "totp.go", "TOTPEnrollmentSetup", "shared bounded", "1 MiB", "accepted", "accepted", "ignored", "400", `400 problem: "invalid JSON"`, "decodeBoundedAuthJSON"},
	{"POST /auth/totp/verify", "totp.go", "TOTPVerify", "shared bounded", "1 MiB", "accepted", "accepted", "ignored", "400", `400 problem: "invalid JSON"`, "decodeBoundedAuthJSON"},
	{"POST /auth/totp/enroll/confirm", "totp.go", "TOTPEnrollmentConfirm", "shared bounded", "1 MiB", "accepted", "accepted", "ignored", "400", `400 problem: "invalid JSON"`, "decodeBoundedAuthJSON"},
	{"POST /auth/totp/confirm", "totp.go", "TOTPConfirm", "shared bounded", "1 MiB", "accepted", "accepted", "ignored", "400", `400 problem: "invalid JSON"`, "decodeBoundedAuthJSON"},
	{"POST /auth/totp/remove/begin", "totp_removal.go", "TOTPRemovalBegin", "shared bounded", "1 MiB", "accepted", "accepted", "ignored", "400", `400 problem: "invalid JSON"`, "decodeBoundedAuthJSON"},
	{"POST /auth/totp/remove", "totp_removal.go", "TOTPRemovalConfirm", "shared bounded", "1 MiB", "accepted", "accepted", "ignored", "400", `400 problem: "invalid JSON"`, "decodeBoundedAuthJSON"},
	{"POST /auth/mfa/reauth", "mfa_reauth.go", "MFAReauthBegin", "shared bounded", "1 MiB", "accepted", "accepted", "ignored", "400", `400 problem: "invalid JSON"`, "decodeBoundedAuthJSON"},
	{"POST /auth/backup-codes/generate", "mfa.go", "GenerateBackupCodes", "tolerant reauth decode (bounded; header or body)", "1 MiB", "accepted", "accepted", "ignored", "403 reauth_required when no valid token", `403 problem: "reauth_required"`, "reauthTokenFromRequest"},
	{"POST /auth/webauthn/login/finish", "webauthn.go", "WebAuthnLoginFinish", "bounded replay to go-webauthn", "1 MiB", "library-owned assertion parse", "library-owned; dpop_jwk outer read is best-effort", "library-owned", "401 from assertion parser", `401 problem: "login failed: ..."`, "io.ReadAll(r.Body)"},
	{"PUT /auth/webauthn/credential/{id}/name", "webauthn.go", "WebAuthnNameCredential", "direct close-body helper", "unbounded", "accepted", "accepted", "ignored", "400", `400 problem: "invalid JSON"`, "decodeJSON"},
}

func TestAuthJSONIngressInventory_IsCompleteAndSourceBound(t *testing.T) {
	if len(authJSONIngressInventory) != 32 {
		t.Fatalf("inventory rows = %d, want 32", len(authJSONIngressInventory))
	}
	seen := map[string]bool{}
	for _, row := range authJSONIngressInventory {
		if row.Endpoint == "" || row.File == "" || row.Function == "" || row.Decoder == "" ||
			row.SizeBound == "" || row.TrailingJSON == "" || row.UnknownFields == "" ||
			row.ContentType == "" || row.EmptyBody == "" || row.ErrorResponse == "" || row.SourceMarker == "" {
			t.Fatalf("incomplete inventory row: %#v", row)
		}
		if seen[row.Endpoint] {
			t.Fatalf("duplicate endpoint inventory row %q", row.Endpoint)
		}
		seen[row.Endpoint] = true
		body := functionSource(t, row.File, row.Function)
		if !strings.Contains(body, row.SourceMarker) {
			t.Fatalf("%s:%s no longer contains source marker %q", row.File, row.Function, row.SourceMarker)
		}
	}

	wantDirectOwners := []string{
		"auth.go:ChangePassword", "device.go:DeviceRegister", "device.go:MFAApprove",
		"forgot_password.go:ForgotPasswordBegin", "forgot_password.go:ForgotPasswordReset", "forgot_password.go:ForgotPasswordVerify",
		"guest_invite.go:GuestInviteAcceptPost", "identity_links.go:IdentityUnlink", "introspect_handler.go:authenticateAndExtractToken",
		"json_ingress.go:decodeBoundedAuthJSON", "mfa.go:VerifyBackupCode", "mfa_possession.go:decodePossessionBody", "mfa_reauth.go:decodeReauthToken", "push_mfa.go:PushMFASend", "scim.go:ServeHTTP",
		"terms.go:Accept", "webauthn.go:WebAuthnLoginFinish", "webauthn.go:WebAuthnRegisterFinish", "webauthn.go:decodeJSON",
	}
	if got := directJSONDecoderOwners(t); !reflect.DeepEqual(got, wantDirectOwners) {
		t.Fatalf("direct JSON decoder owners changed\n got: %v\nwant: %v", got, wantDirectOwners)
	}
	if err := authJSONIngressInventoryMismatch(authJSONIngressInventory, boundedAuthJSONDecoderOwners(t)); err != nil {
		t.Fatal(err)
	}
}

func TestAuthJSONIngressInventory_RejectsUnlistedBoundedCaller(t *testing.T) {
	planted := boundedAuthJSONDecoderOwnersFromSources(t, map[string][]byte{
		"planted_unlisted.go": []byte(`package handlers
func PlantedUnlisted(w http.ResponseWriter, r *http.Request) {
	var req struct{}
	decodeBoundedAuthJSON(w, r, &req)
}`),
	})
	if want := []string{"planted_unlisted.go:PlantedUnlisted"}; !reflect.DeepEqual(planted, want) {
		t.Fatalf("planted AST caller = %v, want %v", planted, want)
	}
	owners := append(boundedAuthJSONDecoderOwners(t), planted...)
	err := authJSONIngressInventoryMismatch(authJSONIngressInventory, owners)
	if err == nil || !strings.Contains(err.Error(), "planted_unlisted.go:PlantedUnlisted") {
		t.Fatalf("unlisted bounded caller was not rejected: %v", err)
	}
}

func TestDecodeBoundedAuthJSON_CompatibilityContract(t *testing.T) {
	type payload struct {
		Known string `json:"known"`
	}
	t.Run("unknown fields trailing value and content type remain accepted", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/auth/test", strings.NewReader(`{"known":"ok","unknown":true} {"trailing":true}`))
		req.Header.Set("Content-Type", "text/plain")
		rec := httptest.NewRecorder()
		var got payload
		if !decodeBoundedAuthJSON(rec, req, &got) {
			t.Fatalf("compatible request rejected: %d %s", rec.Code, rec.Body.String())
		}
		if got.Known != "ok" {
			t.Fatalf("known = %q, want ok", got.Known)
		}
	})

	for _, tc := range []struct {
		name string
		body string
	}{
		{"empty body", ""},
		{"malformed body", `{"known":`},
		{"oversized body", `{"known":"` + strings.Repeat("x", int(authJSONBodyLimit)) + `"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/auth/test", strings.NewReader(tc.body))
			rec := httptest.NewRecorder()
			var got payload
			if decodeBoundedAuthJSON(rec, req, &got) {
				t.Fatal("invalid request accepted")
			}
			if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), `"detail":"invalid JSON"`) {
				t.Fatalf("response = %d %s, want 400 invalid JSON problem", rec.Code, rec.Body.String())
			}
		})
	}
}

func functionSource(t *testing.T, filename, function string) string {
	t.Helper()
	raw, err := os.ReadFile(filename)
	if err != nil {
		t.Fatalf("read %s: %v", filename, err)
	}
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, filename, raw, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", filename, err)
	}
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name.Name != function || fn.Body == nil {
			continue
		}
		start := fset.Position(fn.Pos()).Offset
		end := fset.Position(fn.End()).Offset
		return string(raw[start:end])
	}
	t.Fatalf("function %s not found in %s", function, filename)
	return ""
}

func directJSONDecoderOwners(t *testing.T) []string {
	t.Helper()
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	var owners []string
	for _, filename := range files {
		if strings.HasSuffix(filename, "_test.go") {
			continue
		}
		raw, err := os.ReadFile(filename)
		if err != nil {
			t.Fatal(err)
		}
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, filename, raw, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", filename, err)
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			body := string(raw[fset.Position(fn.Pos()).Offset:fset.Position(fn.End()).Offset])
			if (strings.Contains(body, "json.NewDecoder") && strings.Contains(body, "r.Body")) ||
				strings.Contains(body, "io.ReadAll(r.Body)") {
				owners = append(owners, filepath.Base(filename)+":"+fn.Name.Name)
			}
		}
	}
	sort.Strings(owners)
	return owners
}

func boundedAuthJSONDecoderOwners(t *testing.T) []string {
	t.Helper()
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	sources := make(map[string][]byte)
	for _, filename := range files {
		if strings.HasSuffix(filename, "_test.go") {
			continue
		}
		raw, err := os.ReadFile(filename)
		if err != nil {
			t.Fatal(err)
		}
		sources[filename] = raw
	}
	return boundedAuthJSONDecoderOwnersFromSources(t, sources)
}

func boundedAuthJSONDecoderOwnersFromSources(t *testing.T, sources map[string][]byte) []string {
	t.Helper()
	var owners []string
	filenames := make([]string, 0, len(sources))
	for filename := range sources {
		filenames = append(filenames, filename)
	}
	sort.Strings(filenames)
	for _, filename := range filenames {
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, filename, sources[filename], 0)
		if err != nil {
			t.Fatalf("parse %s: %v", filename, err)
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			ast.Inspect(fn.Body, func(node ast.Node) bool {
				call, ok := node.(*ast.CallExpr)
				if !ok {
					return true
				}
				callee, ok := call.Fun.(*ast.Ident)
				if ok && callee.Name == "decodeBoundedAuthJSON" {
					owners = append(owners, filepath.Base(filename)+":"+fn.Name.Name)
				}
				return true
			})
		}
	}
	sort.Strings(owners)
	return owners
}

func authJSONIngressInventoryMismatch(inventory []jsonIngressInventoryRow, actual []string) error {
	var expected []string
	for _, row := range inventory {
		if strings.HasPrefix(row.Decoder, "shared bounded") {
			expected = append(expected, row.File+":"+row.Function)
		}
	}
	sort.Strings(expected)
	actual = append([]string(nil), actual...)
	sort.Strings(actual)
	if !reflect.DeepEqual(actual, expected) {
		return fmt.Errorf("decodeBoundedAuthJSON call-site inventory mismatch\n got: %v\nwant: %v", actual, expected)
	}
	return nil
}
