# EK01 config-secret codec (#379)

Foundation crate `setjoin-config-secret`, no database, HTTP or domain dependency.
It opens and seals sealed `system_config` values exactly as frozen Go does
(`mailserver/internal/admin/config_secret.go` over `shared/cryptokey`), for
Directory sync (AD/LDAP `_enc` values), Static/Assist (`assist.api_key`) and
Platform. Use it instead of re-deriving any of this.

## Format

Stored value: `{"format":"setjoin-config-secret","version":1,"keyVersion":N,
"sourceKey":S,"ciphertext":base64url-no-padding(EK01 envelope)}`. Envelope:
`EK01`, algo (0 AES-256-GCM, 1 SM4-GCM), key length u32 BE, two zero bytes, nonce
length u16 BE (12), nonce, ciphertext+tag. Column key = HKDF-SHA256(secret = master,
salt = `mailserver-db-encryption-v1`, info empty; Go's `hkdf.New` argument order, the
ticket called the string "info") at the header's key length (32 AES, 16
SM4); the master is the configured string's raw bytes (not hex-decoded). AAD =
`setjoin-system-config-v1 \0 deployment \0 sourceKey \0 configKey \0 keyVersion`.
Source key: `ad_sync_*` legacy:ad, `ldap_sync_*` legacy:ldap, `tls_*` legacy:tls,
`identity_source.<id>` is `<id>`, anything else legacy:system. The profile only
picks the algorithm when sealing (`smx` SM4, `standard`/`hybrid` AES); opening is
self-describing, so a standard codec opens an SM4 envelope and the reverse.

## API

`ConfigSecretCodec::new(ConfigSecretKeyring)`, `encrypt(config_key, json_bytes)`,
`decrypt(config_key, stored_bytes)`, `active_version()`, `is_config_secret_envelope`,
`parse_retiring_keys`, `keyring_from_lookup`/`keyring_from_env`. Keys come only from
Go's settings: `IDENTITY_CONFIG_SECRET_KEY` (else `DB_ENCRYPTION_KEY`),
`IDENTITY_CONFIG_SECRET_KEY_VERSION` (default 1), `IDENTITY_CONFIG_SECRET_RETIRING_KEYS`
(JSON version to key; decrypt only), `CRYPTO_ALGORITHM_PROFILE`; the deployment ID is
`system_config` key `identity.deployment_id`. Go also reads a `SETJOIN_CONFIG` yaml
layer: pass a lookup closure that covers it. Keyring/codec `Debug` omit key bytes, keys
are zeroized on drop, and no error text contains key material.

## Failure contract

Every malformed input is an error whose `Display` is Go's message: bad or missing
record shape, format/version, source mismatch, unavailable key version, bad base64
(padding refused, CR/LF ignored as in Go), header too short, bad magic, reserved
bytes, unknown algorithm, nonce length, short ciphertext, authentication failure
(wrong key, deployment, config key or version, truncation, tamper), non-JSON
plaintext. The kinds are the `ConfigSecretError` variants. Known deliberate
differences (all fail closed): an AES-192 header (only hand-built) is refused at
cipher setup where Go fails at authentication; record field names match exactly (Go
matches case-insensitively); the version setting accepts plain decimal only (Go also
takes hex/octal spellings); two spellings of one retiring version are refused (Go
keeps a random one); Go's JSON/base64 library detail text after the stable prefix is
not reproduced.

## Verification

`src/tests.rs` replays Go-recorded vectors byte for byte: `cryptokey.json` (#262
column envelopes, both profiles) and `configsecret.json` (seal bytes for standard,
smx and hybrid across all source families, ~45 decrypt failure cases, keyring and
retiring-key parsing). Re-record with
`GOFREE_VECTOR_DIR=<empty dir> go test -run TestRecordConfigSecretVectors ./internal/admin`
from `mailserver/` in the CI image. Go opening Rust seals: run the Rust test with
`SETJOIN_RUST_SEALED_FILE=<file>` (`rust_sealed_values_for_go`), then Go
`TestOpenRustSealedConfigSecrets` with `GOFREE_RUST_SEALED_FILE=<file>`. SM4-GCM is
RustCrypto `sm4` 0.5.1 under `aes-gcm` 0.10.3's generic `AesGcm<Sm4, U12>` (default
features off, so no AES), glue-free in `src/sm4.rs`; no cipher or GHASH is hand-written.
The GB/T block vector and the Go recordings pin it.
