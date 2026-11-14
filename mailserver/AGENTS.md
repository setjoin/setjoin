# mailserver — module AGENTS.md (DOX rail)

Owns gateways, SQL, webmail, API contracts and deployment integration. Reducers own atomic business authority; Go translates protocols. Worker transfer names and per-task cron gates: `DOX.md` startup contracts. Preserve schema startup refusal, credential-separated app/worker/owner pools, direct LISTEN/reconnect and worker cancellation/drain gates. Gateway/private registrars own routes, never package init. Query changes require docs/standards/DATABASE_SECURITY.md; protocol changes require matching protocol references. Read local contracts for startup/pools and the owning capability for behavior. Children: internal/AGENTS.md, sql/AGENTS.md, api/AGENTS.md, webmail/AGENTS.md.

The frozen Go session-refresh oracle recorder and named-worker switch test are
`cmd/mailserverd/worker_oracle_test.go`; `worker_launch_test.go` covers the
certificate and ticket worker switches for later listener swaps. TLS recorders are in
`internal/tlsutil/`. Recording/replay details are in
[`server-rust/DOX.md`](../server-rust/DOX.md#worker-oracle).

## DOX sections

- [1. Purpose](DOX.md#1-purpose)
- [2. Ownership](DOX.md#2-ownership)
- [3. Local Contracts](DOX.md#3-local-contracts)
  - [Startup order (mandatory — `cmd/mailserverd/main.go`)](DOX.md#startup-order-mandatory--cmdmailserverdmaingo)
  - [Key files](DOX.md#key-files)
  - [Feature toggle gates](DOX.md#feature-toggle-gates)
  - [Auth priority chain (gateway layer)](DOX.md#auth-priority-chain-gateway-layer)
  - [Database security (enforced)](DOX.md#database-security-enforced)
  - [Account-scope currency — the `shared/identity` seam (ARCH-003)](DOX.md#account-scope-currency--the-sharedidentity-seam-arch-003)
- [4. Features / Capabilities](DOX.md#4-features--capabilities)
  - [4.1 Protocol layer](DOX.md#41-protocol-layer)
  - [4.2 Mail features](DOX.md#42-mail-features)
  - [4.3 Security features](DOX.md#43-security-features)
  - [4.4 Compliance features](DOX.md#44-compliance-features)
  - [4.5 Admin capabilities](DOX.md#45-admin-capabilities)
  - [4.6 Discovery + well-known + the public booking surface](DOX.md#46-discovery--well-known--the-public-booking-surface)
  - [4.7 First-boot setup](DOX.md#47-first-boot-setup)
  - [4.8 Webmail SPA (thin map — detail in `webmail/AGENTS.md`)](DOX.md#48-webmail-spa-thin-map--detail-in-webmailagentsmd)
- [5. Work Guidance](DOX.md#5-work-guidance)
- [6. Verification](DOX.md#6-verification)
- [7. Child DOX Index](DOX.md#7-child-dox-index)

- [Rust CLI release and backup worker transfer](DOX.md#rust-operator-cli-and-backup-transfer-355).

Federation socket installation, worker transfer and lifecycle: [native deployment](DOX.md#native-federation-deployment-347).

Native HTTPS/ACME listener transfer, least-privilege deployment files and whole-release recovery: [deployment contract](DOX.md#native-https-deployment-413).

Native updater/recovery swap, unchanged unit name and matching `*.prev` recovery: [installation contract](DOX.md#native-updaterrecovery-installation-359).

Native IMAP sockets and threat-gated transfer: [deployment](DOX.md#native-imap-deployment-202).

Default native SMTP sockets, protected pipeline settings and real-systemd rehearsal (#526): [deployment](DOX.md#native-smtp-deployment-501--526).
