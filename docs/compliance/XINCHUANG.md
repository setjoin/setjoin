# Xinchuang (信创) Certification Guide

> **Stage 3.1 — Global Platform** | **Date:** 2026-05-31

## 1. Overview

Xinchuang (信息技术应用创新 — Information Technology Application Innovation) is the mandatory
certification for selling software into Chinese government and state-owned enterprise (SOE)
procurement. This guide covers the certification process for SetJoin on the prescribed domestic
technology stack.

## 2. Target Combinations

The certification covers specific (CPU x OS x DB) combinations:

| # | CPU | OS | Database | Priority | Status |
|---|-----|----|----------|----------|--------|
| 1 | Kunpeng 920 (ARM64) | Kylin V10 | PolarDB for PostgreSQL | **Primary** | In progress |
| 2 | Loongson 3A5000 (LoongArch) | UOS V20 | | Secondary | Deferred — adapt on demand |
| 3 | Phytium FT-2000/64 (ARM64) | Kylin V10 |  4.3+ | CI-only | Deferred |

**Primary path:** Huawei ecosystem (Kunpeng + Kylin + PolarDB for PostgreSQL) — most common in government.
**Secondary path:** Defense/security sector (Loongson + UOS + non-PG domestic DB).

> **Scope decision (2026-07-11):** One 信创-certified PostgreSQL (PolarDB for PostgreSQL — certified + zero-migration, 100% PG15-compatible) is the shipping target. The non-PG domestic databases (KingbaseES / Dameng / OceanBase) are **deferred until a specific procurement demands one** — the `Adapter` interface + the per-reducer `sql/xinchuang/compatibility_matrix.csv` already scope that work, so it's fill-in-on-demand, not a rebuild. The default build path (PolarDB/PostgreSQL) is the whole product for now.

## 3. Certification Authority

| Authority | Chinese Name | Role |
|-----------|-------------|------|
| CESI | 中国电子技术标准化研究院 | Standards body; test procedures and specifications |
| CCRC | 中国网络安全审查技术与认证中心 | Security certification for classified (涉密) deployments |
| CSIP | 中国软件评测中心 | Software compatibility testing |

Initial submission goes to CESI for compatibility certification. CCRC involvement is required
only for classified-government deployments using SMx cryptography.

## 4. Certification Process

```
Phase A: Self-Assessment          (2 weeks)
  - Build on target architecture
  - Run smoke test harness
  - Verify database adapter connectivity
  - Audit webmail browser compatibility

Phase B: Third-Party Testing      (4 weeks)
  - Submit binaries + docs to CESI-authorized lab
  - Lab runs functional test suite on target hardware
  - Security audit (OWASP Top 10 + GB/T 22239-2019)
  - Performance baseline on domestic stack

Phase C: Evidence Package         (2 weeks)
  - Binary compatibility attestation per combination
  - Database adapter conformance test results
  - Webmail browser compatibility screenshots
  - SMx algorithm compliance (Stage 3.2, if applicable)

Phase D: Submission & Review      (4 weeks)
  - Formal submission to CESI
  - Review cycle (typically 2-3 iterations)
  - Certificate issuance (valid 3 years)
```

Total: ~12 weeks from self-assessment to certificate issuance.

## 5. Submission Checklist

### Required Evidence

- [ ] Cross-compiled binaries for target architecture (statically linked, stripped)
- [ ] SBOM (Software Bill of Materials) for each binary
- [ ] Database adapter conformance test results
- [ ] Smoke test output on physical hardware (or QEMU when unavailable)
- [ ] Webmail browser compatibility screenshots (Kylin Browser, UOS Browser, Firefox ESR)
- [ ] CSP headers audit — must not break domestic browser extensions
- [ ] Admin console Chinese localization (Stage 1.8 prerequisite)
- [ ] SMx algorithm compliance test vectors (Stage 3.2, for classified deployments only)

### Required Documentation

- [ ] System architecture diagram on domestic stack
- [ ] Deployment guide in Chinese (安装部署手册)
- [ ] Operations guide in Chinese (运维管理手册)
- [ ] Security architecture overview
- [ ] Component inventory with version numbers
- [ ] Third-party dependency audit (license compliance + supply chain)

## 6. CI Pipeline

The Xinchuang CI pipeline (`.github/workflows/xinchuang-ci.yml`) runs on every push to main
and on PRs touching authserver, gateway, or shared code. It builds for arm64 and loong64
architectures with QEMU user-mode smoke tests. The `compliance-check` job gates certification
readiness — all artifacts must build and pass tests before submission.

## 7. Post-Certification

Certificate is valid for 3 years. Renewal requires re-testing with updated binaries and any
new dependencies. Major version upgrades (new Go version, new database driver) may require
re-certification of affected combinations.

## 8. References

- [GB/T 32918-2016] SM2 elliptic curve public key cryptographic algorithm
- [GB/T 32905-2016] SM3 cryptographic hash algorithm
- [GB/T 32907-2016] SM4 block cipher algorithm
- [GB/T 22239-2019] Information security technology — baseline for classified protection
- [GB/T 25069-2022] Information security technology — terminology
