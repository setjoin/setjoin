package handlers

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"

	shareddevice "setjoin.com/shared/device"
	"setjoin.com/shared/httputil"
)

const authJSONBodyLimit int64 = 1 << 20

// decodeBoundedAuthJSON preserves the common auth JSON ingress contract used
// by endpoints that already shared the same size bound and error response.
// Unknown fields, trailing JSON values, and non-JSON Content-Type headers stay
// accepted for compatibility; empty or malformed bodies get the existing 400.
//
// med-shard2-006 body binding: these login / MFA-completion bodies feed the
// login CA evaluation (threat.DeviceCredentialResolver →
// shared/device.VerifyDeviceRequest), whose device proof is bound to the
// SHA-256 of the exact request body. The decode below consumes the body before
// that resolver runs, so the server-computed digest of the buffered bytes is
// stamped on the request (shared/device.WithServerBodyDigest) — the trusted
// evidence binding the signed X-Device-Body-SHA256 commitment to the bytes
// this handler actually read. Without it the verifier fails closed on every
// body-carrying device proof.
func decodeBoundedAuthJSON(w http.ResponseWriter, r *http.Request, dst any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, authJSONBodyLimit)
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "invalid JSON"})
		return false
	}
	*r = *shareddevice.WithServerBodyDigest(r, bodySHA256Hex(raw))
	r.Body = io.NopCloser(bytes.NewReader(raw))
	if err := json.NewDecoder(r.Body).Decode(dst); err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "invalid JSON"})
		return false
	}
	return true
}

// bodySHA256Hex returns the lowercase hex SHA-256 of raw — the server-computed
// body digest stamped via shared/device.WithServerBodyDigest so a device proof
// can be bound to body bytes consumed before verification.
func bodySHA256Hex(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}
