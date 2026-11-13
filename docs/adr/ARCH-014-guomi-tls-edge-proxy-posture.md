# ADR: ARCH-014 — 国密 TLS posture: edge-proxy termination primary, GmSSL native-shell TLCP a demand-gated fast-follow

**Status:** Accepted
**Date:** 2026-06-23
**Source:** Platform-shell + transport research + locked user decision 2026-06-23. Reconciles and supersedes the TLS half of the archived design `docs/design/archive/stage3-smx-crypto.md` (§2 "SM2 TLS: Proxy Pattern"), updating it for the client-unification fleet (WebView shells, iOS WKWebView) and a TLS 1.3 baseline. The crypto-primitive half of that doc (SM2/SM3/SM4 on the Go **server** via `emmansun/gmsm`) stands unchanged; client-side SM4 is covered by [ARCH-015](ARCH-015-platform-crypto-sm4-key-custody.md).

## Context

国密 (SM-suite) transport for 党政/信创 deployments needs **TLCP / GB/T 38636** (the Chinese TLS-equivalent, 双证书 SM2-sign + SM2-enc handshake). Two hard constraints shape where that termination happens:

1. **Go cannot terminate 国密 TLS in-process.** Go's `crypto/tls` only implements IANA-registered cipher suites; the 国密 suites (ECC-SM2-SM4-SM3, ECDHE-SM2-SM4-SM3) are not registered. The only Go forks that do TLCP (`tjfoc/gmtls`, `tjfoc/gmsm/gmtls`) are **unmaintained** (last commits 2022) — running a ~2000-line security-critical TLS fork with no upstream patch stream is a worse security posture than a maintained terminator. This is the standing conclusion of `stage3-smx-crypto.md` §2 and remains correct.
2. **iOS WKWebView cannot speak TLCP at all.** Apple's WebView uses the system Secure Transport stack, which has no 国密 cipher suites and no extension point. So for an iOS app that *must* do 国密 over the public internet, there is no in-WebView path.

## Decision

**1. Edge-proxy termination is PRIMARY.** A 国密 reverse proxy / SSL gateway terminates **TLCP / GB/T 38636** at the edge; the setjoin Go gateway and the WebView clients speak **ordinary TLS** behind it.

- Terminators: **Tongsuo (BabaSSL) + Angie/Tengine**, or the customer's HSM-backed 国密 SSL 网关 appliance.
- 双证书 = SM2 **sign** cert + SM2 **enc** cert; a **国密 + RSA dual-stack** edge config lets 信创 browsers (360/红莲花) negotiate 国密 while standard browsers fall back to RSA/ECDSA TLS.
- On an **air-gapped LAN**, edge-terminated 国密 + plain TLS on the internal hop **passes 密评** (commercial-cipher assessment) — the assessed boundary is the edge, and the LAN is trusted.

**2. Baseline transport = TLS 1.3** (not 1.2) for the non-国密 / behind-the-proxy hops. This raises the floor over the archived doc, which only said "standard TLS 1.3 or plain HTTP."

**3. GmSSL native-shell TLCP client = demand-gated fast-follow.** A native TLCP client linked into the shell (driving the **GmSSL C API** over loopback — Rust TLCP bindings are immature, so go through C) is built **only when** one of:
   - remote-internet 党政 deployment (no trusted LAN, so the edge boundary isn't sufficient), **or**
   - an **iOS app that requires 国密** (WKWebView can't do TLCP any other way — a loopback GmSSL terminator inside the app is the only route).

   Until one of those is contracted, do **not** build it. The setjoin gateway/WebView stay compatible behind 信创 browsers and 国密 SDP-VPNs in the meantime.

## Considered options

- **In-process Go 国密 TLS via an unmaintained fork (`tjfoc/gmtls`).** Rejected (carried over from `stage3-smx-crypto.md` §2): an unpatched 2000-line TLS stack is a higher risk than a maintained edge terminator; every TLS-class CVE would have to be self-patched.
- **Build the GmSSL native TLCP client now, unconditionally.** Rejected: immature Rust bindings force a C-API integration with real cost; with no contracted remote-党政 or iOS-国密 requirement, the edge proxy already covers every shipping deployment. Demand-gate it.
- **Require 国密 end-to-end into the WebView on all platforms.** Rejected: iOS WKWebView cannot negotiate 国密 suites at all; mandating it would block the iOS client. Edge termination + ordinary TLS to the WebView is the only fleet-wide-feasible posture.

## Consequences

- Deployment topology for 党政/信创: `信创 browser / 国密 SDP-VPN → 国密 edge proxy (Tongsuo+Angie, TLCP/GB-T-38636, 双证书) → [TLS 1.3 / loopback] → setjoin Go gateway`. The gateway config does **not** carry 国密 TLS.
- `stage3-smx-crypto.md` §2's proxy diagram is now the accepted design-of-record (reconciled here), upgraded with the TLS 1.3 baseline + 双证书 + dual-stack details and the iOS/WKWebView constraint it predated.
- The GmSSL native TLCP fast-follow is captured with its two trigger conditions so it is not re-litigated from scratch nor built speculatively.
- 密评 honesty: the binding 密评 constraints are **transport (this ADR) + key custody ([ARCH-015](ARCH-015-platform-crypto-sm4-key-custody.md))**, not the choice of crypto *library*. Using `emmansun/gmsm` as a library on the Go server is legally fine post-2023 商用密码管理条例 (product cert is voluntary except for catalog products).
- **Reversibility:** high. The edge proxy is a deployment artifact, not setjoin code; adding the GmSSL native client later is additive (a new loopback terminator in the shell) and does not change the gateway.
