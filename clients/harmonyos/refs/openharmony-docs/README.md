# OpenHarmony docs — local reference (curated)

Curated, markdown-only mirror of the HarmonyOS NEXT developer docs we need for the
native-shell security work (biometric unlock P3, HUKS key custody, ArkWeb bridge).

## Source

- Upstream: **https://gitcode.com/openharmony/docs**
- Pinned commit: **`ea48936`** (fetched 2026-07-07)
- Only the English (`en/application-dev/`) security kits + their API references are
  mirrored here. Images (`figures/`, `*.png`) were stripped — text only (3.5M vs 71M).

## What's here (why)

| Path | Kit | Why we need it |
|------|-----|----------------|
| `security/UniversalKeystoreKit/` | HUKS (华为通用密钥库) | biometric-gated **KEK** — create a user-auth-bound key with new-enrollment invalidation; the P3 `SecureStore` HUKS impl |
| `security/UserAuthenticationKit/` | userIAM | the biometric prompt (fingerprint/face) that gates the HUKS key release |
| `security/AssetStoreKit/` | Asset Store | device-bound secret storage (alternative/companion to raw HUKS) |
| `security/CryptoArchitectureKit/` | Crypto | AES-GCM / ECDH primitives if any wrap logic runs ArkTS-side |
| `security/DataProtectionKit/` | Data protection | accessibility/backup-exclusion semantics (the `ThisDeviceOnly` analogue) |
| `reference/apis-universal-keystore-kit/` | HUKS API | `@kit.UniversalKeystoreKit` signatures — `huks.generateKeyItem`, auth-type/invalidation flags |
| `reference/apis-user-authentication-kit/` | userIAM API | `@kit.UserAuthenticationKit` signatures |
| `reference/apis-asset-store-kit/` | Asset API | `@kit.AssetStoreKit` signatures |

## Not mirrored (fetch from source when needed)

- **ArkWeb** (`en/application-dev/web/`, `reference/apis-arkweb/`) — 59M with images; the
  bridge pattern we already use lives in `clients/harmonyos/entry/`. Pull from the source
  link above if a bridge/webview API detail is needed.
- **Push Kit** — Huawei Push is closed HMS docs, not in this open repo. See
  `clients/harmonyos/entry/src/main/ets/common/PushService.ets` + Huawei AGC console docs.
- `zh-cn/` Chinese originals — English is sufficient; the source has both.

## Updating

```bash
# refresh against a newer upstream commit
git clone --depth 1 --filter=blob:none --no-checkout https://gitcode.com/openharmony/docs.git /tmp/oh-docs
cd /tmp/oh-docs && git sparse-checkout set en/application-dev/security en/application-dev/reference/apis-universal-keystore-kit en/application-dev/reference/apis-user-authentication-kit en/application-dev/reference/apis-asset-store-kit && git checkout HEAD
# rsync markdown-only back into this ref, then bump the pinned commit above
rsync -am --include='*/' --include='*.md' --exclude='*' en/application-dev/security/ <this-dir>/security/
```
