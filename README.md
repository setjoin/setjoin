# setjoin

Setjoin is a private, on-premise productivity suite for organizations with
roughly 300–10,000 users. The monorepo contains Go protocol gateways, PostgreSQL
reducers, SvelteKit webmail, native client shells, and self-hosted collaboration
sidecars.

**A composable workplace. Choose your apps and providers. Keep control of your data.**

**集合：可组合的企业办公平台。应用按需选，服务可替换，数据自主掌控。**

This is our product direction: protected system apps with documented interfaces,
optional integrations and qualified providers. The closed Collabora CODE
install/recovery path and provider-neutral Office foundations exist today; the
general extension platform remains planned, not a shipped marketplace or universal
hot-reload guarantee. See [positioning and claim gates](docs/product-positioning.md)
and [feature inventory](docs/features.md).

For a fresh clone, follow the counted [clone-to-green contributor path](CONTRIBUTING.md#clone--green).
It names every prerequisite, command, expected result, and focused edit loop.

For Architecture Deepening Round 3 work, start here:

```bash
bash scripts/verify-architecture-r3.sh --doctor
bash scripts/verify-architecture-r3.sh --help
bash scripts/verify-architecture-r3.sh
```

The no-argument command runs all eight merge-focused lanes and retains
source-bound evidence. Retained previous binaries, physical devices, and live
media are separate release gates; missing real receipts fail closed.

For whole-codebase security coverage, use the read-only fresh-shell path:

```bash
bash scripts/verify-security-program.sh --doctor
bash scripts/verify-security-program.sh coverage status
bash scripts/verify-security-program.sh coverage resume
```

`resume` only explains the verified state and safe next action; it never starts a
scanner. Until the fresh-session T7-DX review closes and scan admission receives
separate approval, it intentionally returns HOLD. See [the security remediation
start guide](docs/guides/security-remediation/START-HERE.md).

Repository rules and component ownership live in [AGENTS.md](AGENTS.md). The
domain glossary is [CONTEXT.md](CONTEXT.md).

## Licensing

Setjoin is source-available, not open source. The code in this repository is
licensed under the [PolyForm Noncommercial License 1.0.0](LICENSE): you may
use, change and share it for any noncommercial purpose, as that license
defines it.

Commercial use needs a separate commercial license from the authors. Contact:
<softcat@softcat.info>.

Third-party components keep their own licenses; see [NOTICE](NOTICE) and
[THIRD_PARTY_LICENSES.md](THIRD_PARTY_LICENSES.md).
