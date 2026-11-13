# Setjoin: a composable workplace

Status: approved product direction, 2026-09-06. This document separates positioning
from delivered capability. It does not grant implementation, rollout, certification,
license or compatibility claims.

## Selling point

**A composable workplace. Choose your apps and providers. Keep control of your data.**

**集合：可组合的企业办公平台。应用按需选，服务可替换，数据自主掌控。**

Setjoin's direction is a self-hosted workplace whose substantial capabilities have
explicit interfaces, dependencies and lifecycle rules. Organizations can extend
their workflows through designated extension points while protected system apps
retain authority over identity, permissions and business records. The intended
benefit is provider choice and community development without requiring customers
to replace their workplace or surrender control of its data.

Use this copy with the **planned platform capability** qualifier until the evidence
below exists. Do not describe the general extension platform as available today.

## What customers should gain

| Promise | Concrete customer outcome | Current status / claim gate |
|---|---|---|
| Choose what fits | Install approved apps and select qualified Office, AI, ASR and other providers through one workplace | Planned general platform; existing provider-neutral Office and closed CODE installation are foundations, not a generic app store |
| Extend without forking | First-party and community apps use documented commands, queries, events and UI contributions | Planned; public contract and independent-developer qualification required |
| Keep data ownership clear | Mail, files, versions, ACLs and audit records stay with their owning system apps when an integration is disabled | Existing domain ownership; generalized disable/remove continuity must be tested |
| Understand changes before applying them | Admin UI shows dependencies, permissions, version compatibility, affected work, restart needs and recovery progress | Planned lifecycle UI; existing Apps/Sources/Updates screens are reused |
| Evolve at a controlled pace | Qualified providers can be replaced through a documented drain/restart or approved live-switch procedure | Planned generalized lifecycle; no universal hot reload or zero-downtime promise |
| Build an open ecosystem | A small manifest, permissively licensed developer tooling subject to legal review, local validator and automated community submission path | Planned; existing license, ICLA/CCLA and publishing decisions remain authoritative |

## Engineering meaning of “plugin”

“Everything is a plugin” is inspiration, not a literal customer guarantee.

- **Trusted platform modules:** identity/tenant enforcement, reducer authorization,
  audit integrity, key custody and privileged upgrade authority remain Setjoin-controlled.
- **Protected system apps:** Mail, Drive, Calendar, Contacts and Tasks expose public
  contracts but are not ordinary uninstallable data authorities.
- **Optional apps and providers:** Office, eligible AI/ASR/search adapters and
  integrations can vary at explicitly supported extension points.
- **UI contributions:** approved slots and isolated rich surfaces share the design
  system; a store app does not receive arbitrary same-origin JavaScript execution.

An advertised stable public capability must have a real first-party consumer through
the same supported contract, alongside the independent external qualification gates.
That does not confer internal privileges on community code. Modularity does not require
one process, container, database or downloadable package per module. Startup-time
composition is the default; hot replacement is a separately qualified capability.

## Claims we will not make without evidence

- “Every function is a plugin,” “all apps are uninstallable,” or “replace any core.”
- “Any WPS/MS Office/provider version works” or “all updates are zero downtime.”
- “Disabling an app reverses sent mail, user edits or external deliveries.”
- “Plugins are safe because they declare permissions” without runtime isolation
  and authoritative per-request enforcement.
- “Plugin architecture improves database throughput” without a measured workload.
- “Fully open source,” “free commercial redistribution,” “certified,” or “production
  ready” solely because an upstream framework has those attributes or a permissive license.

Existing feature completion and GA/Beta/Experimental labels remain separate. New
claims need exact source-bound evidence, supported platform/provider combinations,
known limitations and an accountable release decision. See [feature inventory](features.md)
and [release maturity](designs/release-maturity-and-first-ga-boundary.md).

## Delivery and comparison material

The Composable Platform Refactor
owns delivery sequencing; its reconciliation ledger
maps existing plans rather than replacing their domain tests. Sales material and
Exchange comparisons must link these claim gates and distinguish tested replacement
outcomes from future ecosystem flexibility. No competitor inferiority claim follows
from choosing this architecture.

## Sources and limits

- User-supplied *A Programming Paradigm for Spatiotemporal Composability*, Yifan Shi,
  Wei Zhang and Tianyi Cui, 2026: §§3 and 5 for tracked effects/dependency lifecycle;
  §§6.1, 6.3 and 6.6 for irreversible effects, external sandboxing and versioning limits.
- [DeepSeek Harness architecture](https://github.com/deepseek-ai/deepseek-harness/blob/master/docs/architecture.md),
  inspected 2026-09-06: plugin composition, profiles, stable capability interfaces,
  and startup-only composition for shipped headless/SDK profiles.
- [DeepSeek Harness safety notice](https://github.com/deepseek-ai/deepseek-harness/blob/master/SAFETY.md),
  inspected 2026-09-06: developer-preview and isolation limitations. Its architecture
  is a reference, not Setjoin certification or a production-security proof.
- [Setjoin Extension Control Plane](designs/extension-control-plane-public-system-apps.md)
  remains the detailed product/trust contract.
