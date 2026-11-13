# HUKS SecureStore — OHOS-003 skeleton: integration path and device-gated test plan

Package: OHOS-003. Triage row: `D-CLIENTS-RUST-OHOS-NATIVE-003`
(`retired-docs:zcode-security-deep/handoff/sj-glm-sec-20260909-003-triage/triage-ledger.jsonl`,
LOW / disposition **hardening**, `SEC-KEYSTORE-MISSING` / CWE-311). Roadmap P2
of the Model M custody rollout (`guard-core/src/securestore/mod.rs`: real
impls land per platform in P1–P4).

Code: `clients/rust/ohos-native/src/huks.rs` (`huks::HuksSecureStore`).

## What this is

A compile-checked, fail-loud `SecureStore` implementation against the HUKS
NDK (`libhuks_ndk.z.so`), giving HarmonyOS shells the same hardware
key-custody shape the Apple backend gives iOS/macOS:

- guard-core holds the trait once (`SecureStore`, `KeyTier`,
  `SecureStoreError` — public re-exports, one authority);
- HUKS holds one AES-256-GCM KEK per alias inside the secure environment;
- `wrap`/`unwrap` encrypt/decrypt the 32-byte vault key through HUKS
  sessions; the KEK never leaves HUKS, the vault key never leaves the
  process (and never crosses the napi bridge);
- the wrapped blob goes where guard-core's Model M already stores it — vault
  `meta` (`kek_wrapped` / `kek_bio_wrapped`), hex, next to the `kek_tier`
  tag. The blob's home does not change per platform.

Every FFI declaration, tag/enum constant and error code is transcribed from
the vendored OpenHarmony docs in this repo
(`clients/harmonyos/refs/openharmony-docs/`, UniversalKeystoreKit NDK guides
and `reference/apis-universal-keystore-kit/capi-native-huks-*.md`). Nothing
in the file has been executed against HUKS; assumptions a compile cannot
confirm are marked `SPIKE-TODO(device)` inline.

## Fail-loud posture (the triage row's requirement)

The triage row's core statement: *"no code path silently pretends custody
exists … a missing backend should fail loudly rather than fake it."*

- No software fallback, no in-memory stand-in, no synthesized key on any
  path. Every HUKS failure maps onto `SecureStoreError` (`Invalidated` /
  `Cancelled` / `Unavailable` / `Failed`).
- `available()`: `DeviceUnlock` is true only on ohos targets; `Biometric` is
  false everywhere until its UserIAM round trip is implemented AND
  device-verified; `DomainSso` false (N/A on OHOS, mirrors apple.rs).
  guard-core's orchestration keys on `available()`/tier, so the biometric
  tier is unreachable against this backend today.
- `FakeSecureStore` remains `#[cfg(test)]`-gated in guard-core, untouched.
- The module is wired into NO `#[napi]` export; shipping it changes no
  behavior. The shell's vault still opens by passphrase and
  `vault.unlockBiometric()` stays honestly `false` (the closed unlock-method
  contract in `clients/DOX.md`).

Config trap: the OpenHarmony triples report `target_os = "linux"` with
`target_env = "ohos"` (`rustc --target aarch64-unknown-linux-ohos --print
cfg`). All gating in `huks.rs` and the `rand` dependency stanza key on
`target_env = "ohos"` — never `target_os`.

## @ohos.security.asset (Asset Store Kit) — evaluated, not used

The kit stores <1 KB secrets with owner binding and lock-screen/user-auth
access control (vendored `security/AssetStoreKit/asset-store-kit-overview.md`).
It was considered and rejected for this trait, on purpose:

- Model M persists the wrapped blob in vault `meta` and the trait contract
  returns it (`wrap -> Vec<u8>`); putting the blob in the ASSET database
  would split the blob's authority across two stores and add an
  uninstall-persistence wrinkle (`IS_PERSISTENT` data survives uninstall).
- ASSET authenticates at the asset level with a validity window (max 10
  minutes), not at the key-use level; HUKS key ACLs (with
  `INVALID_NEW_BIO_ENROLL` invalidation + per-session challenge) model
  guard-core's `KeyTier`/`Invalidated` semantics directly.
- ASSET remains the right tool if a later feature needs small standalone
  secrets (e.g. a device push token) — it is a peer of this backend, not a
  layer under it.

## Integration path (when the OHOS SDK/device is available)

1. **Wire the vault open.** The vault seam lives in the byte-shared
   `clients/rust/native-shared/native_impl.rs` (`vault_unlock` currently
   constructs `GuardCore::new(db, passphrase)`), and that file must stay
   byte-identical across `desktop-native` and `ohos-native`. The wiring is
   therefore a native-shared lane change: an ohos-cfg'd branch that calls
   `GuardCore::new_with_keystore(db, &ohos_native_huks_store(), reason)`
   where desktop keeps the passphrase path (or both, per the deferred
   optional-passphrase tier design in the biometric P0 plan). The backend
   handle itself is already built: `huks::HuksSecureStore::new()` (stateless
   ZST, `Send + Sync`). First-run provisioning, the `kek_tier` tag, the
   sentinel check, the design-B biometric fallback and `mark_wiped` are all
   guard-core behavior that activates unchanged around the backend.
2. **Link the .so.** The HAP build must link `libhuks_ndk.z.so` from the
   OHOS SDK sysroot (`target_link_libraries(entry PUBLIC libhuks_ndk.z.so)`
   in the vendored guides). `cargo check`/`--tests` never link; the first
   link happens in the HAP build pipeline (hvigor/ohos-rs). The `rand` dep
   is already target-gated in `Cargo.toml`.
3. **Flip the biometric tier (separate, device-gated step).** Implement the
   UserIAM round trip: `OH_Huks_InitSession`'s `token` out-blob returns the
   challenge (`OH_HUKS_CHALLENGE_TYPE_NORMAL`), the app authenticates via
   UserAuthKit (fingerprint/face/PIN, reason string = the trait's `reason`),
   and `OH_Huks_FinishSession` receives the result as
   `OH_HUKS_TAG_AUTH_TOKEN`. Then flip `available(Biometric)` and the
   `wrap`/`unwrap` gates in `huks.rs`, map auth outcomes onto
   `Cancelled`/`Invalidated`, and let guard-core's existing design-B
   fallback (`drop_bio_wrap_to_device`) handle invalidation.
4. **Only then** revisit the honest `false` on `vault.unlockBiometric()` in
   the ArkTS/webmail unlock path — that claim flips when and only when
   hardware custody is real end-to-end.

## Device-gated test plan (none of this has run; nothing is claimed)

Gate order — a step runs only after the previous one passes:

- **G0 (done, host):** `cargo check -p ohos-native` clean; `cargo clippy -p
  ohos-native` clean; `cargo test -p ohos-native` (binding confinement
  tests) green; `cargo test -p guard-core` green (47 passed, 1 ignored =
  the manual Touch ID test). Policy layer (framing, tier params, error
  mapping) is type-checked on every target; the 11 `#[cfg(test)]` unit
  tests in `huks.rs` (framing, tier params, AE_TAG split, error mapping,
  r2-constant pins, r2 access-control/never-override pins, r3
  delete-selector pin, availability truth table) type-check for BOTH
  targets with the lib test target
  temporarily enabled (`cargo check [-–target
  aarch64-unknown-linux-ohos] -p ohos-native --tests` — the manifest keeps
  `lib.test = false`, so this was a one-off verification flip, reverted;
  check never links, so the missing Node-API symbols do not matter).
- **G1 (done, host w/ tier-2 std + OHOS SDK):** `cargo check --target
  aarch64-unknown-linux-ohos -p ohos-native` clean — type-checks the
  cfg'd FFI half (extern block, unions, call sequences) without linking.
- **G1b (blocked, environment — NOT a code failure):** the full
  `cargo build --target aarch64-unknown-linux-ohos --tests -p ohos-native`
  (and any ohos cdylib link) currently STALLS on this machine before
  reaching ohos-native: the OHOS SDK linker
  (`command-line-tools/sdk/default/openharmony/native/llvm/bin/clang-15`)
  carries `com.apple.quarantine` + hardened-runtime signing and hangs at
  `_dyld_start` on this macOS (verified by `sample`: the process never
  leaves dyld). guard-core's own ohos cdylib link hits the same wall, so
  the stall predates and is unrelated to this change. Remediation belongs
  to the OHOS build-environment owner (clear the quarantine attribute or
  re-sign the SDK llvm tools); after that, G1b + G2 give the first
  object-level proof of the FFI surface.
- **G2 (HAP build):** the cdylib links against `libhuks_ndk.z.so` in the
  SDK sysroot — first proof the extern surface matches the real library.
  Any missing-symbol error here means a signature/ABI drift to fix against
  the vendored headers.
- **G3 (device/smoke, real OHOS device or emulator with HUKS service):**
  add a temporary `#[napi]`-free harness (dev-only export or `cargo test`
  via `--tests` ON device — note `lib.test = false` exists because host
  lacks Node-API symbols; ON device those symbols exist) exercising:
  - T1 keygen + existence: `wrap` under `DeviceUnlock` creates an alias;
    `OH_Huks_IsKeyItemExist` reports it (the extern declaration stays for
    this harness — the wrap path itself no longer existence-checks, see T3);
    blob carries the `sj-huks-v1` magic.
  - T2 round trip: `unwrap` returns the wrapped 32-byte key; corrupting one
    ciphertext byte or the tag yields a `Failed` (GCM auth), not garbage.
  - T3 overwrite guard (r2: non-overriding provision): a second `wrap` with
    the same alias must REUSE the existing KEK — generation carries
    `OH_HUKS_TAG_KEY_OVERRIDE=false` (capi-native-huks-type-h.md L682), so
    the second GenerateKeyItem gets 12000017 `KEY_ALREADY_EXIST` (L425),
    which the backend accepts as success-with-existing; there is NO separate
    existence check (check-then-generate was racy AND the loser would have
    overwritten the winner's KEK — HUKS overwrites by default,
    generation-overview L15). Verify the FIRST blob still unwraps after the
    second wrap (an overwrite would strand it).
  - T4 AAD binding: unwrap the blob under a DIFFERENT alias fails (alias is
    the GCM associated data).
  - T5 clear + idempotence (r3: the delete carries the ECE selector):
    `clear` then `unwrap` -> `Invalidated`; `clear` of an absent alias ->
    `Ok`. The delete param set carries
    `OH_HUKS_TAG_AUTH_STORAGE_LEVEL=ECE` — the generation domain (a
    null/empty delete param set would target the CE default,
    capi-native-huks-api-h.md L199 / js-apis-huks.md deleteKeyItem L361).
    On device also confirm `OH_Huks_IsKeyItemExist` with the SAME selector
    reports 12000011 after the clear (the existence check carries the same
    CE-default contract, js-apis-huks.md isKeyItemExist L1992).
  - T6 output-length guards (r3-narrowed to what the code enforces): the
    session REJECTS any REPORTED `outData.size` other than the exact
    expected length (48 for wrap, 32 for unwrap) — 0 (unwritten/empty),
    short, or long all surface as a loud `Failed` — and unwrap rejects any
    non-48-byte ciphertext payload BEFORE the session, so a zero-filled
    synthetic key can never be returned. The guards do NOT detect an
    "unchanged size": `outData.size` is caller-initialized to the expected
    length before FinishSession, so a success that leaves `.size`
    untouched is indistinguishable from a correct write-back and passes
    the exact-length check. On device, confirm successful FinishSession
    calls write the true length back; an untouched-`.size` success is a
    device finding to resolve against the vendored headers — the
    exact-length guards cannot catch it, and it is not a tolerance to
    re-add.
  - T7 param-set ownership: confirm `OH_Huks_AddParams` copies blob values
    (so the builder's transient `blob_store` may drop after Build) —
    indirect proof: no crash/garbage across repeated wrap/unwrap with
    freshly-allocated specs.
  - T8 lock-screen + storage-level enforcement (r2: the generation params
    now actually carry the restrictions, and the SAME tag set rides wrap
    and unwrap sessions — `OH_HUKS_TAG_IS_DEVICE_PASSWORD_SET=true`,
    capi-native-huks-type-h.md L695, and
    `OH_HUKS_TAG_AUTH_STORAGE_LEVEL=ECE`, L514/generation-overview L33;
    the API-11 default is CE, generation-overview L27, which stays usable
    in later lock states and is therefore NOT set):
    - T8a with no lock-screen credential set, the first `wrap` (generation)
      must fail `OH_HUKS_ERR_CODE_DEVICE_PASSWORD_UNSET` (L424) ->
      `Unavailable` — never a silent fallback. After setting a credential,
      wrap/unwrap succeed; clearing the credential afterwards makes further
      use fail ("generated and used only when a password is set", L695).
    - T8b on a credentialed device, ECE means the KEK is usable ONLY while
      the device is unlocked: unwrap with the screen locked must fail
      loudly, not serve the key. The wiring lane should also heed the
      screen-locked session-cleanup advice (L517 /
      generation-overview L36, COMMON_EVENT_SCREEN_LOCKED).
    - T8c SPIKE: confirm HUKS accepts the generation-shaped access-control
      tags re-specified on session param sets (the inline SPIKE-TODO in
      `push_kek_access_controls`) — a rejection must surface as a loud
      failure, never by dropping the tags to make calls succeed.
  - T9 uninstall/reinstall: HUKS keys die with app data; a reinstall must
    hit `Invalidated` on open (orphaned `meta` blob) and follow guard-core's
    re-provision path — document the UX this produces.
- **G4 (biometric tier, after integration step 3):**
  - T10 wrap under `Biometric` prompts; correct biometric unwraps.
  - T11 enroll a NEW fingerprint -> key invalidated ->
    `SecureStoreError::Invalidated` -> guard-core falls back to the device
    wrap (`took_device_fallback`), matching `biometryCurrentSet` semantics.
  - T12 cancel/timout at the prompt -> `Cancelled`, no unlock, retryable.
  - T13 `AUTH_TIMEOUT` window: second unwrap inside the window does not
    re-prompt (accept or tighten to always-prompt before flipping the tier
    on — the shipped default is the strict one).
- **G5 (vault integration smoke):** `GuardCore::new_with_keystore` on
  device against a real SQLCipher store: first run provisions
  (`kek_wrapped` + sentinel), reopen unwraps, `mark_wiped` + reopen
  refuses; then the ArkTS unlock UX flips per step 4 with its own webmail
  checks.

Rollout posture: the backend stays OFF in behavior terms until the
integration wiring lands and is separately admitted; G0–G1 being green is a
compile statement, not a custody statement.

## r2 review fixes (Astra HOLD on the skeleton, all line-justified)

All five P2 findings were fixed against the vendored references, not from
memory; each constant below cites the justifying reference line:

1. **Tag-type discriminators** (was `BYTES = 3 << 28`, which is ULONG and
   corrupted NONCE/AAD/AE_TAG/AUTH_TOKEN): every discriminator re-checked —
   capi-native-huks-type-h.md L449-454 (INVALID=0, INT=1, UINT=2, ULONG=3,
   BOOL=4, BYTES=5, all `<< 28`). `BYTES = 5 << 28` now.
2. **Error codes** (were 6-digit `120_0xx`): all 8-digit per
   capi-native-huks-type-h.md L405-L425 — SUCCESS=0 (L405),
   PERMANENTLY_INVALIDATED=12000007 (L415), VERIFY_FAILED=12000008 (L416),
   TIME_OUT=12000009 (L417), ITEM_NOT_EXIST=12000011 (L419),
   CREDENTIAL_NOT_EXIST=12000013 (L421), DEVICE_PASSWORD_UNSET=12000016
   (L424), KEY_ALREADY_EXIST=12000017 (L425). Unit tests pin every value.
3. **Zero-length unwrap output** (was accepted -> synthetic zero key):
   `cipher_session` rejects a zero expectation outright and requires
   `outData.size == expected_out` exactly (0/short/long -> loud `Failed`);
   unwrap rejects any ciphertext payload other than the exact 48-byte
   `ct||tag` wrap frame BEFORE the session, and the unwrapped key must be
   exactly 32 bytes.
4. **KEK provision race** (was existence-check then generate -> concurrent
   first wraps could overwrite the KEK and strand blobs): generate with
   `OH_HUKS_TAG_KEY_OVERRIDE=false` (L682; HUKS overwrites by default,
   generation-overview L15) and treat 12000017 `KEY_ALREADY_EXIST` (L425)
   as success-with-existing. An existing KEK is never replaced.
5. **Missing DeviceUnlock access controls** (generation promised
   restrictions it did not set): `OH_HUKS_TAG_AUTH_STORAGE_LEVEL=ECE`
   (L514 — "only when the device is unlocked"; the CE default of
   generation-overview L27 stays accessible in later lock states) and
   `OH_HUKS_TAG_IS_DEVICE_PASSWORD_SET=true` (L695) now ride generation
   AND both session directions (`push_kek_access_controls`), and the T8
   plan above matches what the params actually enforce.

Unit tests added/updated to pin 1, 2 and 5
(`tag_discriminators_match_vendored_reference`,
`error_codes_are_reference_values`,
`kek_access_controls_and_never_override_on_every_op`); T1/T3/T6 rewritten
for the new provision/length semantics. No behavior flip: the module
remains unwired and `available()` unchanged.

## r3 review fixes (Astra delta re-review HOLD, both line-justified)

All five r2 findings were confirmed closed; two findings remained:

1. **ECE deletion mismatch (P2)** (was: `raw::delete_key` passed a null
   param set and treated `ITEM_NOT_EXIST` as success — but the null param
   set selects the CE storage domain, so `clear()` on the ECE KEK could
   report success while the key survived): the delete param set now carries
   `OH_HUKS_TAG_AUTH_STORAGE_LEVEL=ECE`, the same storage domain generation
   and both session directions select (`delete_key_params()` built from
   `kek_storage_level()`, one source of truth shared with
   `push_kek_access_controls`; tag = UINT|316, capi-native-huks-type-h.md
   L675; ECE=2, L514). The reference shows delete DOES honor the storage
   level — it is the documented key-identification form, not an unsupported
   tag:
   - capi-native-huks-api-h.md L199 (OH_Huks_DeleteKeyItem paramSet):
     "Pointer to the parameters for deleting the key. By default, this
     parameter is a null pointer. The default key storage level is
     OH_HUKS_AUTH_STORAGE_LEVEL_CE."
   - js-apis-huks.md L361 (deleteKeyItem options): "Attribute of the key to
     be deleted. If HuksAuthStorageLevel is used to specify the security
     level of the key to be deleted, this parameter can be left empty. If
     the API version is 12 or later, the default value CE is passed in."
     (Same selector contract for isKeyItemExist, L1992 — used by the T5
     device check.)
   Only the storage level rides on delete: it is the one tag the delete
   references name as the selector; no cipher/purpose/access tags are
   documented delete-time identification. `ITEM_NOT_EXIST` (12000011,
   capi-native-huks-type-h.md L419) stays success once the selector
   matches — now a true statement about the right domain. Unit test
   `delete_params_select_the_kek_storage_domain` pins the exact selector
   and drift-guards it against every tier's generation params. T5 updated
   to verify the removal on device through the same selector.
2. **T6 overstated (P3)** (claimed an unchanged output `.size` is detected,
   but `outData.size` is caller-initialized to the expected length, so an
   untouched `.size` passes): T6 reworded to what the code enforces — the
   exact-length guards reject a REPORTED 0/short/long output length, and
   cannot detect an "unchanged size"; an untouched-`.size` success is
   recorded as a device finding to resolve (T6 above). No code change: the
   huks.rs `cipher_session` comment already stated the honest posture.

No behavior flip: the module remains unwired, `available()` unchanged;
unit-test count 10 -> 11 (G0 updated).
