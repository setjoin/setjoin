# PUSH_ECIES_CONTRACT — ECDH push-challenge encryption (cross-end)

**Status: enforced.** This is the single source of truth for the ECIES scheme that
protects native push-MFA challenges (and security-alert payloads) in transit
between the auth server and a registered device. Two **independent**
implementations encrypt and decrypt it; they MUST agree byte-for-byte. A committed
cross-end golden vector pins them (see "Golden vector" below) so a drift fails a
test, not a user's push login.

| End | Role | Code |
|-----|------|------|
| Server (Go) | **encrypt** | `authserver/internal/authn/push_native.go` — `EncryptECIES` → `encryptECIESDeterministic` |
| Device (Rust) | **decrypt** | `clients/rust/guard-core/src/ecdh/mod.rs` — `decrypt_ecies` |

The server reaches `EncryptECIES` from `dispatchNativePush` / `dispatchSecurityNative`
(`authserver/internal/authn/push.go`); the device reaches `decrypt_ecies` via
`GuardCore::decrypt_push_challenge` (`clients/rust/guard-core/src/lib.rs`), wired to
APNs/FCM/HMS payloads by the platform push managers.

## Algorithm

ECIES over NIST **P-256** (secp256r1), single-pass:

1. **Ephemeral key** — the sender (server) generates a fresh P-256 keypair **per
   message**. The scheme is therefore non-deterministic: the same plaintext encrypts
   to different bytes each time. Never reuse an ephemeral key.
2. **ECDH** — `Z = ECDH(ephemeral_private, recipient_public)`. The shared secret is
   the **32-byte big-endian X-coordinate** of the shared point (Go
   `(*ecdh.PrivateKey).ECDH` and Rust `p256::ecdh::diffie_hellman(...).raw_secret_bytes()`
   both yield exactly this — the raw X, no cofactor/KDF baked in).
3. **KDF** — `key = HKDF-SHA256(ikm = Z, salt = <empty>, info = "push-challenge", L = 32)`.
   - `salt` is **empty/absent** (Go: `hkdf.New(sha256.New, Z, nil, info)`; Rust:
     `Hkdf::<Sha256>::new(None, Z)`). HKDF treats an empty salt as a zero-filled
     block of the hash length — both ends do this identically.
   - `info` is the **exact ASCII bytes** `push-challenge` (no NUL terminator).
   - Output length `L = 32` bytes → the AES-256 key.
4. **AEAD** — `AES-256-GCM`, 12-byte nonce, 16-byte tag, **no associated data**.
   `ciphertext = AES-256-GCM-Seal(key, nonce, plaintext, aad = <empty>)`. The
   12-byte nonce is sampled fresh per message from a CSPRNG.

## Wire format

A single opaque byte string, concatenated in this order:

```
┌───────────────────────────────┬──────────────┬───────────────────────────┐
│ ephemeral public key          │ nonce        │ ciphertext ‖ GCM tag      │
│ 65 bytes                      │ 12 bytes     │ len(plaintext) + 16 bytes │
│ uncompressed SEC1 (0x04‖X‖Y)  │              │                           │
└───────────────────────────────┴──────────────┴───────────────────────────┘
  offset 0..65                     65..77         77..end
```

- **Minimum length** = 65 + 12 + 16 = **93 bytes** (empty plaintext). The decryptor
  MUST reject anything shorter.
- The ephemeral public key is **uncompressed SEC1** — 65 bytes, first byte `0x04`,
  then the 32-byte X then the 32-byte Y coordinate. Compressed points (`0x02`/`0x03`)
  are **not** accepted on this wire.

## Key encodings (the subtle part — do not get these wrong)

The two ends use **different encodings for the long-lived recipient key**, even
though they agree on everything on the wire:

| Value | Encoding | Where |
|-------|----------|-------|
| Recipient **public** key (input to encrypt **and** the registration wire form) | **raw 65-byte uncompressed SEC1** | `EncryptECIES(recipientPubBytes, …)`; matches Go `ecdh.PublicKey.Bytes()` and Rust `p256::PublicKey::to_encoded_point(false)`. The device registers **this exact raw-65 form** hex-encoded — the server stores it verbatim and passes it straight to `EncryptECIES` with **no** DER→raw65 conversion. |
| Recipient **private** key (input to decrypt) | **PKCS#8 DER** | `decrypt_ecies(private_key_der, …)`; matches Rust `SecretKey::to_pkcs8_der()` / `generate_keypair()`'s `sk_der`. |
| **Ephemeral** public key (on the wire) | **raw 65-byte uncompressed SEC1** | both ends — see wire format above. |
| ECDH shared secret | raw 32-byte X-coordinate | both ends |

> Note: guard-core's `get_or_create_ecdh_public_key` returns the device public key
> as **SPKI/DER** (`to_public_key_der()`, ~91 bytes) — that form is **not** what the
> device registers, because `dispatchToNativeDevices` passes the stored bytes
> straight to `EncryptECIES` (raw-65 only) with no conversion. Registration uses
> `GuardCore::push_registration_public_key_hex()` (raw-65 SEC1 hex), exported to the
> shells as the `pushDevicePublicKey()` bridge method. The golden vector locks the
> raw-65 form.

## Parameters at a glance

| Parameter | Value |
|-----------|-------|
| Curve | NIST P-256 / secp256r1 |
| Point encoding (wire) | uncompressed SEC1, 65 bytes, `0x04` prefix |
| KDF | HKDF-SHA256 |
| HKDF salt | empty (absent) |
| HKDF info | ASCII `push-challenge` (14 bytes, no NUL) |
| Derived key length | 32 bytes (AES-256) |
| AEAD | AES-256-GCM |
| Nonce | 12 bytes, random per message |
| Tag | 16 bytes |
| Associated data | none |

## Golden vector (the enforcement)

Because the scheme is non-deterministic, a naïve `encrypt` is not byte-reproducible.
The cross-end pin uses approach **(a)** from the design brief — a committed fixed
vector that BOTH ends are anchored to:

- A fixed recipient P-256 keypair (private as PKCS#8 DER, public as raw-65) and a
  fixed plaintext (`"42"`).
- A **server-produced** ciphertext for that input, made reproducible by injecting a
  **fixed ephemeral private scalar + fixed nonce** via the test-only seam
  `encryptECIESDeterministic` (the shared implementation that the production
  `EncryptECIES` wraps with fresh randomness).
- **Go test** (`authserver/internal/authn/push_ecies_golden_test.go`,
  `TestECIESGoldenVector`): `encryptECIESDeterministic(recipPub, "42", fixedEph,
  fixedNonce)` == the committed `goldenPayload`.
- **Rust test** (`clients/rust/guard-core/tests/ecdh_golden.rs`,
  `ecies_cross_end_golden_vector`): `decrypt_ecies(recipPrivDer, GOLDEN_PAYLOAD)`
  == `"42"`, where `GOLDEN_PAYLOAD` is the **same hex string** the Go test produces.

The committed payload (identical hex on both ends), for reference:

```
0484d4083d3cce31d97122787043abdff18a900a421e471747e0aa0cad7ba4c00b
78422c16286d6f57ddd9d2cbaa429ee04efce4ffb5d944a3571bb7c38f9670b1
a4ff6b6dfd563c638179f6fa93db6bc2399d727d12c0f9c07916870c5a44
```
(95 bytes = 65 eph pub ‖ 12 nonce ‖ 2 ct ‖ 16 tag; recipient pub raw-65 =
`043ffa8457…09b8fc75`.) The Rust test additionally flips a tag bit to prove the GCM
tag is verified.

This mirrors the RFC-6238 discipline of guard-core's `tests/totp_vectors.rs`.

### Changing the contract

If you intend to change the curve, point encoding, KDF, `info` string, AEAD, or
wire layout, you MUST change BOTH ends in the same change and **deliberately
re-derive** the golden vector:

1. Update `encryptECIESDeterministic` / `decrypt_ecies` together.
2. Re-run the generator (a small Go program that calls the deterministic encrypt
   with a fixed recipient keypair + fixed ephemeral scalar + fixed nonce and prints
   the hex — see the brief in `push_ecies_golden_test.go`).
3. Paste the new hex into BOTH `push_ecies_golden_test.go` and `ecdh_golden.rs`.
4. Confirm `go test ./internal/authn/...` and `cargo test -p guard-core` are green.

Do **not** edit the constants on one end to "make the test pass" — that defeats the
entire purpose (silent interop break shipped to users).

## Verify

```bash
cd authserver && go test ./internal/authn/...
cd clients   && cargo test -p guard-core
```
