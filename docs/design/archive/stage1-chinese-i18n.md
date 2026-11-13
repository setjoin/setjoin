# Stage 1.8 — Chinese-Language Admin Console + Documentation

> **Date:** 2026-05-31 | **Roadmap:** Stage 1 — Enterprise Deal-Qualifier | **Effort:** ~4 weeks
> **Depends on:** Nothing (independent). **Blocks:** Chinese market entry.
> **Competitive context:** All 4 Chinese competitors (NetEase, Tencent, DingTalk, Feishu) provide Chinese-first admin UIs and documentation. Without this, we are disqualified from Chinese-market RFPs regardless of technical capability.

---

## 1. Goal

Deliver a full Simplified Chinese (zh-CN) translation of the SetJoin admin console UI and companion Chinese-language administrator documentation, making the product viable for Chinese-market evaluation.

## 2. Architecture

The existing i18n framework (`src/lib/i18n/index.ts`) already supports dynamic locale loading (en/de/zh) with a lightweight runtime — no i18next dependency needed. The admin shell hardcodes English labels in `allNavItems`; these must be replaced with `t()` calls. Chinese documentation lives in `docs/zh/` as a mirror of the admin-relevant English docs, translated and adapted for Chinese-market terminology. No server-side changes required — all i18n is client-side.

## 3. Files to Create / Modify

### i18n Infrastructure (modify)

| File | Change |
|------|--------|
| `mailserver/webmail/src/lib/i18n/en.ts` | Add ~200 admin keys covering all 27 admin sub-routes, common table/chart/form strings, sidebar labels, error messages, confirmation dialogs |
| `mailserver/webmail/src/lib/i18n/zh.ts` | Full Chinese translation of all new admin keys |
| `mailserver/webmail/src/lib/i18n/de.ts` | German translations of new admin keys (keep existing coverage parity) |

### Admin Shell (modify)

| File | Change |
|------|--------|
| `mailserver/webmail/src/routes/admin/+layout.svelte` | Derive `allNavItems[].label` from `t()` calls instead of hardcoded English strings; translate static text (hamburger aria-labels, logout, sidebar title, loading) |
| `mailserver/webmail/src/routes/admin/+page.svelte` | Translate dashboard widgets: headers, stat labels, chart titles |
| Each `+page.svelte` under `routes/admin/*/` | (27 pages) Replace hardcoded English strings with `t('admin.…')` calls. Scope per page below. |

### Admin Page Translation Scope (27 pages)

| Page | Key Sections to Translate |
|------|--------------------------|
| `users/` | Table columns (email, role, status, last login), create/edit user forms, bulk actions, search placeholder |
| `domains/` | Domain list, add domain form, MX/TXT verification, DKIM key display |
| `mailboxes/` | Mailbox table, quota bar, create/edit form, delegate access |
| `queue/` | Queue stats, message list, retry/delete actions, filter controls |
| `system/` | Service status cards, resource gauges, config editor, restart button |
| `logs/` | Log viewer toolbar, severity filter, date range, export |
| `auth/` | Auth method toggles, MFA policy, session list, LDAP/Kerberos config |
| `identity/` | Identity sources table, sync status, SAML/OIDC setup forms |
| `rules/` | Rule list, condition/action builder, priority ordering |
| `deploy/` | Deployment topology, node list, scale-up/down wizard |
| `dns/` | DNS record table, propagation check, wizard steps |
| `domains/` | Already listed above |
| `dmarc/` | DMARC aggregate report table, summary cards, policy config |
| `ediscovery/` | Case list, new case form, hold status, export controls |
| `content-search/` | KQL search bar, result table, preview panel, export controls |
| `quarantine/` | Quarantined message table, release/block actions, search |
| `alerts/` | Alert list, severity badges, acknowledge/dismiss actions |
| `audit/` | Audit log table, date filter, actor filter, export |
| `features/` | Feature toggle grid, config per feature |
| `limits/` | Rate limit table, quota config, threshold edit |
| `webhooks/` | Webhook list, create/edit form, delivery log, retry button |
| `storage/` | Storage pool table, usage chart, tier config |
| `reports/` | Report list, schedule config, generate button |
| `retention/` | Retention policy table, create/edit form, tag selector |
| `migration/` | Migration job list, create wizard, progress bar, log viewer |
| `trace/` | Trace search form, result timeline, detail panel |
| `departments/` | Department tree, member list, create/edit form |
| `mailboxes/` | Already listed above |

### Chinese Documentation (create)

| File | Content |
|------|---------|
| `docs/zh/README.md` | Index + navigation for all Chinese admin docs |
| `docs/zh/admin-console-guide.md` | Full walkthrough of all 27 admin sections with screenshots |
| `docs/zh/deployment-guide.md` | Translation/adaptation of deployment docs with Chinese-market notes (domestic OS, DB, network) |
| `docs/zh/identity-sso-guide.md` | SAML/OIDC/Kerberos/LDAP setup in Chinese |
| `docs/zh/security-features.md` | DLP, anti-spam, DKIM/DMARC/SPF, quarantine, rate limiting |
| `docs/zh/compliance-features.md` | eDiscovery, Content Search, retention, journaling, audit log |
| `docs/zh/faq.md` | Common setup and troubleshooting questions from Chinese-market context |

### Validation Script (create)

| File | Change |
|------|--------|
| `mailserver/webmail/src/lib/i18n/index.test.ts` | Add coverage check: every key in `en.ts` must have a matching key in `zh.ts` and `de.ts`. Add CI-visible assertion so missing keys fail `npm test`. |

## 4. Key Design Decisions

- **Keep the existing custom i18n runtime.** The lightweight `t()` + dynamic `import()` system in `index.ts` is sufficient. i18next adds ~35 kB gzipped, pluralization/formatting overhead, and framework coupling that over-serves our current needs (simple key lookup with `{param}` substitution). If pluralization is needed later, add a minimal ICU MessageFormat subset.
- **All hardcoded strings in admin pages must become `t()` calls.** This is the bulk of the work. The `allNavItems` array in `+layout.svelte` is the single most impactful change — those labels currently cannot be translated at all. Use derived stores: `const navItems = $derived(allNavItems.map(i => ({ ...i, label: t(i.key) })))`. Each admin page must be audited for raw English strings and converted.
- **Chinese documentation is not a word-for-word translation.** Chinese-market context differs: references to national crypto standards (SM2/SM3/SM4) and domestic OSes (麒麟 Kylin, 统信 UOS) must appear where relevant. Terminology must match what Chinese sysadmins expect (e.g., 邮箱 not 邮件箱, 管理员 not 行政). Audience is technical sysadmins — use precise, standard Chinese IT terminology.
- **Locale detection already works via `localStorage` preference.** The settings page offers en/de/zh selection. No automatic detection from `Accept-Language` header is needed for admin — the admin audience explicitly sets their language. Keep the current `detectLocale()` logic.

## 5. Dependencies

- **Blocks nothing in Stage 1** (parallel with items 1.1–1.7)
- **Blocks:** Stage 3.2 (SMx crypto — documentation must be in Chinese)
- **Depends on:** Nothing. The i18n framework, admin shell, and documentation structure all exist.

## 6. Effort Estimate

| Phase | Work | Estimate |
|-------|------|----------|
| A — Key expansion | Add ~200 keys to `en.ts` + translate to `zh.ts` + `de.ts` | 3 days |
| B — Admin shell wire-up | Replace hardcoded labels in `+layout.svelte` with `t()` calls; translate static chrome | 2 days |
| C — Page-by-page audit | Convert all 27 admin sub-pages (estimate ~8-15 strings per page) to `t()` calls | 8 days |
| D — Chinese documentation | Write 7 docs in `docs/zh/` with Chinese-market adaptations | 5 days |
| E — Test + lint + review | Key coverage assertion, manual UI audit for untranslated strings, `npm run check` | 2 days |
| **Total** | | **~20 days (~4 weeks)** |
