// Package cryptokey — SM2 TLS notes
//
// Go's crypto/tls does not implement 国密 cipher suites (ECC-SM2-SM4-SM3).
// Community TLS forks exist (tjfoc/gmtls, tjfoc/gmsm/gmtls) but are
// unmaintained since 2022 and do not track Go security updates.
//
// SM2 TLS termination must be handled by a reverse proxy:
//
//	Browser (360/红莲花, SM2 cert) → 国密 nginx/BabaSSL/国密网关 → Go gateway
//
// The proxy handles GM/T 0024 TLS; the Go gateway runs standard crypto/tls
// behind it. Application-layer SM2/SM3/SM4 (JWT, hashing, envelope encryption)
// are handled in-process via smx.go and sm2jwt.go.
//
// See docs/design/platform/stage3-smx-crypto.md for the full architecture.
package cryptokey
