# shared

Shared Go packages consumed by both `authserver` and `mailserver/gateway`. Import via the module path `code/shared/<package>`.

## Packages

### `cryptokey`

CryptoProvider interface with pluggable algorithm suites: **StandardSuite** (HMAC-SHA256 + AES-256-GCM), **SMxSuite** (SM2 + SM3 + SM4-GCM), and future suites (post-quantum).

Also provides HKDF-SHA256 key derivation (NIST SP-800 compliant), profile-aware `DeriveEncryptionKey` (32 bytes standard, 16 bytes SM4), SM2 PEM key loading/generation via `LoadSM2PrivateKey`/`GenerateSM2Key`, and a JWT signing method for SM2 (`SigningMethodSM2`, private alg `"SM2"` per RFC 7518 §3.1). SM2 TLS certificate support is behind the `smx` build tag.

```go
key := cryptokey.DeriveCookieKey(jwtSecret)

// Crypto provider selection:
provider := &cryptokey.StandardSuite{}           // Western algorithms
provider := cryptokey.NewSMxSuite(sm2Key)        // Chinese national crypto
signer := provider.Signer()                      // Signer interface for JWT
hasher := provider.Hasher()                      // Hasher interface
cipher := provider.SymmetricCipher()             // SymmetricCipher for data-at-rest

// SM2 key management:
key, pem, _ := cryptokey.GenerateSM2Key()
key, _ = cryptokey.LoadSM2PrivateKey("/path/to/sm2.key")
```

### `envutil`

Environment variable helpers.

- `Getenv(key, fallback string) string` — read env var with a default
- `ParseBool(s string) bool` — lenient boolean parsing (`"1"`, `"true"`, `"yes"`)
- Random string/byte helpers for test fixture generation

### `pwhash`

bcrypt and PBKDF2-SM3 password hashing + a 60-second LRU auth cache.

Hash algorithm is controlled by `SetCryptoProfile(cryptokey.ProfileStandard|ProfileSMx|ProfileHybrid)`. SM3 uses PBKDF2-HMAC-SM3 at 100,000 iterations (OWASP 2026) in `$sm3$iterations$salt$hash` format. `CheckPassword` auto-dispatches on hash prefix (`$sm3$` → SM3 verify, `$2a$` → bcrypt verify), enabling seamless hybrid migration.

The cache absorbs reconnect storms (e.g. IMAP clients reconnecting after a network blip) by memoising recent successful verifications. Cache key is `email + sha256(password)[:8]`, so a password change automatically invalidates cached entries.

```go
// Set profile at startup:
pwhash.SetCryptoProfile(cryptokey.ProfileStandard) // bcrypt
pwhash.SetCryptoProfile(cryptokey.ProfileSMx)      // SM3

hash, err := pwhash.HashPasswordWithProfile(password) // profile-aware
hash, err := pwhash.HashPasswordSM3(password)         // SM3 directly
user, err := pwhash.CheckPassword(ctx, pool, email, password) // hybrid dispatch
```
