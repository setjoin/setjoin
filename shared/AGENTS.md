# shared — cross-cutting Go packages

`contractvectors/` records frozen Go formats for the Rust oracle; see [DOX](DOX.md#contract-vectors).

Owns reusable Go seams, not business authority or service protocols. No upward imports or duplicated auth/tenant/JWT/proxy/error/config logic. User data queries require DATABASE_SECURITY; tenant GUC scope remains transaction-local and WorkerPool distinct. Preserve live revocation, auth-time watermarks, trusted-proxy and connect-time SSRF checks. CryptoProfile and existing durable envelope formats remain compatible. Toggle behavior comes from the finite registry and observe/enforce contract, never a blanket unknown-key assumption. Assist remains default-OFF egress. ValidationError codes are stable ALL_CAPS. Read affected package contracts and impacted consumers for public-seam changes; generator detail only for generator work.

## DOX sections

- [Purpose](DOX.md#purpose)
- [Ownership](DOX.md#ownership)
- [Local Contracts](DOX.md#local-contracts)
- [Features / Capabilities](DOX.md#features--capabilities)
  - [assist](DOX.md#assist)
  - [auth](DOX.md#auth)
  - [config](DOX.md#config)
  - [cryptokey](DOX.md#cryptokey)
  - [dbscope](DOX.md#dbscope)
  - [dnsresolver](DOX.md#dnsresolver)
  - [envutil](DOX.md#envutil)
  - [genutil](DOX.md#genutil)
  - [httputil](DOX.md#httputil)
  - [identity](DOX.md#identity)
  - [jwtutil](DOX.md#jwtutil)
  - [middleware](DOX.md#middleware)
  - [pal](DOX.md#pal)
  - [permissions](DOX.md#permissions)
  - [pgxutil](DOX.md#pgxutil)
  - [pwhash](DOX.md#pwhash)
  - [reducererr](DOX.md#reducererr)
  - [securityprogram](DOX.md#securityprogram)
  - [spam](DOX.md#spam)
  - [threat](DOX.md#threat)
  - [toggle](DOX.md#toggle)
  - [validate](DOX.md#validate)
  - [threat rate-limit persistence](DOX.md#threat-rate-limit-persistence)
  - [webhook](DOX.md#webhook)
- [Build-time generators](DOX.md#build-time-generators)
  - [cmd/genpinyin](DOX.md#cmdgenpinyin)
- [Work Guidance](DOX.md#work-guidance)
- [Verification](DOX.md#verification)
- [Child DOX Index](DOX.md#child-dox-index)

Auth runtime feed recording: [oracle](DOX.md#auth-runtime-recording-420).
