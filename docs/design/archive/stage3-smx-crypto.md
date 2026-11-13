# National Cryptographic Standards (国密 SM2/SM3/SM4) — Design Spec

> **Roadmap item:** Stage 3.2 — "Global Platform" Chinese sovereign cryptography
> **Date:** 2026-05-31 | **Updated:** 2026-06-08 | **Status:** Implemented (crypto), Designed (TLS proxy)

## 1. Implemented: Crypto Primitives

### Architecture

```
shared/cryptokey/
├── provider.go        ← CryptoProvider interface (profile dispatch)
├── smx.go             ← SMxSuite: SM2Signer + SM3Hasher + SM4GCMCipher
├── sm2jwt.go          ← JWT SM2 signing (alg: "SM2")
├── sm2key.go          ← SM2 PEM key loading
├── smx_tls.go         ← DEPRECATED: documented proxy fallback
└── smx_test.go        ← GM/T 0004 test vectors verified

shared/pwhash/
└── sm3.go             ← PBKDF2-SM3 password hashing ($sm3$ format)
```

### Algorithm dispatch by profile

| Profile | Signing | Hashing | Symmetric | TLS |
|---------|---------|---------|-----------|-----|
| `standard` | HMAC-SHA256/RS256 | bcrypt | AES-256-GCM | RSA/ECDSA |
| `smx` | SM2 (`alg: "SM2"`) | PBKDF2-SM3 | SM4-GCM | SM2 via proxy |
| `hybrid` | Both accepted | SM3 new, bcrypt verify old | AES-256-GCM | RSA/ECDSA or SM2 via proxy |

### Library choice: `emmansun/gmsm`

- MIT-licensed, actively maintained, assembly-optimized for ARM64/LoongArch/RISC-V
- Implements `crypto.Signer`, `hash.Hash`, `cipher.Block` — standard Go interfaces
- Verified against GM/T 0003-2012 (SM2), GM/T 0004-2012 (SM3), GM/T 0002-2012 (SM4) test vectors
- JWT SM2 signing uses `alg: "SM2"` (private per RFC 7518 §3.1, bilateral authserver↔gateway only)
- SM3 hash confirmed against GM/T 0004-2012 Appendix A.1/A.2 test vectors in `smx_test.go`

## 2. SM2 TLS: Proxy Pattern (Not In-Process)

### Why Go cannot terminate SM2 TLS

Go's `crypto/tls` only implements IANA-registered TLS cipher suites. 国密 suites (ECC-SM2-SM4-SM3, ECDHE-SM2-SM4-SM3) are not in the standard registry. Community forks exist:

| Library | TLS Support | Maintained |
|---------|------------|------------|
| **tjfoc/gmtls** | Full GM TLS (fork of Go tls stack) | ❌ Last commit 2022 |
| **tjfoc/gmsm/gmtls** | Full GM TLS with double handshake | ❌ Last commit 2022 |
| **emmansun/gmsm** | Crypto primitives only | ✅ Active |

Using an unmaintained TLS fork in production is a higher security risk than using a maintained proxy. Every TLS vulnerability (Heartbleed-class bugs, downgrade attacks, padding oracles) must be patched in the fork — a 2000-line TLS stack requires continuous maintenance.

**Reference standards for SM2 TLS:**
- GM/T 0024-2014: SSL VPN Protocol Specification (SM2 cipher suite definitions)
- IETF: draft-shen-sm2-ecdsa-02 (expired, informational)
- IETF: draft-oscca-cfrg-sm3-02 (expired, informational)
- OSCCA: GM/T 0002/0003/0004 for the underlying algorithms

The complete SM2 TLS handshake, if implemented from scratch, requires: SM2 ECDHE key exchange, SM4-GCM record layer, SM3 HMAC PRF, X.509 SM2 certificate validation, CIBA/SM2 client auth — approximately 2000 lines of security-critical Go code. **Not recommended.**

### Correct deployment architecture

```
   Browser (360/红莲花, SM2 certificate support)
        │
        ▼  TLS with SM2 certificate (GM/T 0024)
   ┌─────────────────────────┐
   │ 国密 Reverse Proxy       │
   │ • 国密 nginx (Tengine)   │
   │ • BabaSSL (OpenSSL fork) │
   │ • 国密 SSL 网关 appliance │
   │ • gmnginx (github)       │
   └──────────┬──────────────┘
              │  internal network
              ▼  standard TLS 1.3 or plain HTTP
   ┌─────────────────────────┐
   │ Go gateway :443          │
   │ standard crypto/tls      │
   │ (security-updated)       │
   └─────────────────────────┘
```

The `smx_tls.go` file is deprecated — it loaded SM2 certificates into Go's TLS config which cannot negotiate SM2 cipher suites. It now exists as a placeholder with documentation pointing to the proxy pattern.

### Browser support for SM2 TLS certificates

Only specific browsers recognize SM2/GM certificates:
- 360 Secure Browser (国产浏览器)
- 红莲花 Browser
- Other 信创-certified browsers

Chrome, Firefox, Safari, Edge do NOT support SM2 certificates natively. This is expected — 党政 deployments use 信创 browsers exclusively. Webmail users on standard browsers connect via the non-国密 path (standard TLS).

## 3. Verified Against Standards

### SM3 test vectors (GM/T 0004-2012)

| Test | Input | Expected (first 8 bytes) | Verified |
|------|-------|--------------------------|----------|
| Appendix A.1 | "abc" | 66c7f0f4 62eeedd9 | ✅ `smx_test.go:149` |
| Appendix A.2 | 64 bytes of "abcd" | debe9ff9 2275b8a1 | ✅ `smx_test.go:164` |

### SM4 GCM verification

| Test | Result |
|------|--------|
| Encrypt/decrypt roundtrip | ✅ |
| Wrong key fails | ✅ |
| Tampered ciphertext fails (GCM auth) | ✅ |
| Wrong AAD fails | ✅ |
| Wrong key size fails | ✅ |

### SM2 verification

| Test | Result |
|------|--------|
| Sign/verify roundtrip | ✅ |
| Wrong message fails | ✅ |
| Wrong key fails | ✅ |
| NIST P-256 key rejected (curve check) | ✅ |
| Nil key returns error | ✅ |

## 4. What's NOT Built (Future)

| Feature | Status | Recommended Approach |
|---------|--------|---------------------|
| SM2 TLS termination | ❌ | 国密 proxy (see §2) |
| Browser SM2 encrypt/decrypt | ❌ | `sm-crypto` npm package in webmail |
| SKF hardware key integration | ❌ | `ChallengeProvider` interface, SKF native messaging extension |
| SM9 identity-based crypto | ❌ | `emmansun/gmsm/sm9` — available if needed |
| ZUC stream cipher | ❌ | `emmansun/gmsm/zuc` — available if needed |

## 5. References

- `docs/ref/standards/draft-shen-sm2-ecdsa-02.txt` — IETF SM2 ECDSA draft (downloaded)
- `docs/ref/standards/draft-oscca-cfrg-sm3-02.txt` — IETF SM3 hash draft (downloaded)
- `shared/cryptokey/smx_test.go` — GM/T 0004 test vectors
- `shared/cryptokey/smx.go` — SMxSuite implementation
- `shared/cryptokey/sm2jwt.go` — JWT SM2 signing
- `shared/cryptokey/sm2key.go` — SM2 key loading
- `shared/pwhash/sm3.go` — PBKDF2-SM3 password hashing
- `emmansun/gmsm` — https://github.com/emmansun/gmsm (crypto primitives, MIT)
- `tjfoc/gmtls` — https://github.com/tjfoc/gmtls (TLS fork, reference only, unmaintained)
