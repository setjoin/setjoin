# SM2/SM3/SM4 National Cryptographic Standards (国密)

Reference for the Chinese national cryptography suite in Prism. Covers standards, test vectors, configuration, and Xinchuang (信创) compliance.

## Overview

| Algorithm | Standard | Purpose | Key Size | Output |
|-----------|----------|---------|----------|--------|
| SM2 | GM/T 0003-2012 | Digital signatures | 256-bit (P-256 curve) | ASN.1 DER signature |
| SM3 | GM/T 0004-2012 | Hash function | — | 256-bit digest |
| SM4 | GM/T 0002-2012 | Symmetric encryption | 128-bit | GCM-AEAD |

Library: `github.com/emmansun/gmsm` v0.43.0 (MIT-licensed, no CGo, standard `crypto.*` interfaces).

## SM2 — Digital Signature

- **Curve**: SM2 P-256 (`sm2.P256()`), distinct from NIST P-256
- **Key format**: PEM `EC PRIVATE KEY` (SEC 1) or `PRIVATE KEY` (PKCS#8)
- **JWT alg**: `"SM2"` (private algorithm per RFC 7518 §3.1)
- **Signing**: `sm2.SignASN1()` with SM3 pre-hash
- **Verification**: `sm2.VerifyASN1()`
- **Test vectors**: GM/T 0003-2012 Appendix A (verified by unit tests)

### SM3 — Hash Function

- **Output**: 32 bytes (256 bits)
- **Block size**: 64 bytes
- **Test vectors**: GM/T 0004-2012 Appendix A
  - `SM3("abc")` = `66c7f0f4 62eeedd9 d1f2d46b dc10e4e2 4167c487 5cf2f7a2 297da02b 8f4ba8e0`
  - `SM3("abcd"×16)` = `debe9ff9 2275b8a1 38604889 c18e5a4d 6fdb70e5 387e5765 293dcba3 9c0c5732`
- **Password hashing**: PBKDF2-HMAC-SM3 at 100,000 iterations (OWASP 2026), format `$sm3$iterations$salt$hash`

### SM4 — Symmetric Encryption

- **Key size**: 16 bytes (128 bits)
- **Mode**: GCM (AEAD) with 12-byte nonce
- **Format**: nonce || ciphertext || tag
- **Test vectors**: GM/T 0002-2012 Appendix A

## Profile Configuration

Environment variable: `CRYPTO_ALGORITHM_PROFILE`

| Profile | Signing | Hashing | Symmetric | Description |
|---------|---------|---------|-----------|-------------|
| `standard` (default) | HMAC-SHA256 | bcrypt/SHA-256 | AES-256-GCM | Western algorithm suite |
| `smx` | SM2 | PBKDF2-SM3 | SM4-GCM | Chinese national crypto |
| `hybrid` | Both accepted | SM3 new, bcrypt verify old | AES-256-GCM | Migration mode |

Additional env vars:
- `SM2_PRIVATE_KEY_FILE`: PEM path for SM2 signing key (required for `smx`, optional for `hybrid`)

## SM2 Key Management

```bash
# Generate a new SM2 key pair (via Go code)
# Output: PEM-encoded EC PRIVATE KEY

# Production deployment:
# 1. Generate key: call cryptokey.GenerateSM2Key()
# 2. Store PEM in secure location
# 3. Set SM2_PRIVATE_KEY_FILE=/path/to/sm2.key
# 4. Set CRYPTO_ALGORITHM_PROFILE=smx
```

Key loading: `cryptokey.LoadSM2PrivateKey(path)` accepts both SEC 1 and PKCS#8 PEM. Validates key is on SM2 P-256 curve.

## Compliance

- **SCA certification**: Required for government/military/SOE deployments in China
- **Xinchuang (信创) readiness**: SM2/SM3/SM4 are prerequisite algorithms
- **GM/T standards**:
  - GM/T 0002-2012: SM4 block cipher
  - GM/T 0003-2012: SM2 public key cryptographic algorithm
  - GM/T 0004-2012: SM3 cryptographic hash algorithm
  - GM/T 0009-2012: SM2 key management

## Deploy Checklist

- [ ] `CRYPTO_ALGORITHM_PROFILE=smx` set in environment
- [ ] `SM2_PRIVATE_KEY_FILE` points to valid SM2 PEM key
- [ ] `JWT_SECRET` ≥ 16 characters (relaxed for smx profile)
- [ ] `DB_ENCRYPTION_KEY` ≥ 16 characters (SM4-128)
- [ ] SM2 TLS certificates (optional, behind `smx` build tag)
- [ ] Verify: `go test ./shared/cryptokey/...`
- [ ] Verify: SM2 JWT issuance + validation
- [ ] Verify: SM3 password hash + verify

## Competitive Context

| Platform | SM2 | SM3 | SM4 | Xinchuang |
|----------|-----|-----|-----|-----------|
| NetEase / Tencent / DingTalk / 263 | Yes | Yes | Yes | Yes |
| Exchange Online / Gmail / Zimbra | No | No | No | No |
| **Prism** | **Yes** | **Yes** | **Yes** | **Targeting** |
