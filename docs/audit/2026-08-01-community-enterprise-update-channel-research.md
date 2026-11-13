# Community/Enterprise update-channel and monetization research

Date: 2026-08-01

> **Decision update, 2026-09-01:** the research below is preserved as historical
> input, but its LTS/backport recommendation is superseded. Setjoin now uses one
> forward-only signed build lineage: Community receives current builds first and
> Enterprise receives the same lineage after additional evidence and soak. Ordinary
> changes are not maintained on an Enterprise LTS fork. The current authority is
> `docs/designs/release-maturity-and-first-ga-boundary.md`.

## Question

What update-channel, entitlement, and revenue model best fits Setjoin as an
on-premise collaboration suite for organizations with roughly 300–10,000
users?

This note uses public first-party pricing and product documentation. Prices
are point-in-time evidence, not durable product requirements. Statements in
the Setjoin recommendation are inferences unless explicitly attributed.

## Primary-source findings

### Proxmox VE

- Proxmox sells annual subscriptions per occupied physical CPU socket. Its
  Enterprise Repository is available with an active subscription and is
  described as the stable, heavily tested production repository. Higher plans
  add support tickets and response commitments; some plans support offline key
  activation. Source: [Proxmox VE pricing](https://www.proxmox.com/en/proxmox-virtual-environment/pricing).
- A freely accessible `pve-no-subscription` repository exists, but Proxmox
  describes it as suitable for testing/non-production because packages are not
  always as heavily tested and validated. Source:
  [Proxmox package repositories](https://pve.proxmox.com/wiki/Package_Repositories).
- Inference for Setjoin: the two-channel trust model is useful, but socket
  pricing is not. A collaboration suite's delivered value and support load
  correlate more closely with people and organizational complexity than host
  CPU topology.

### Nextcloud

- Nextcloud Enterprise subscriptions are priced per user/year, start at 100
  users, and combine an optimized/hardened enterprise product with support,
  enterprise capabilities, longer support windows, and earlier access to
  security/stability patches. Published tiers extend to large deployments.
  Source: [Nextcloud Enterprise pricing](https://nextcloud.com/pricing/).
- Inference for Setjoin: this is the closest commercial analogue: AGPL
  self-hosting can remain usable without a subscription while production
  assurance, long-lived release support, certified scale, and accountable
  support form the paid product.

### Mattermost

- Mattermost sells annual self-hosted Professional and Enterprise licenses by
  activated-user seats. Its published comparison distinguishes community,
  professional, and enterprise support; Enterprise adds 24×7 support,
  compliance/administration, high availability and horizontal scale, while
  advanced offerings include air-gapped environments. Professional is capped
  at 250 users on the current page. Source:
  [Mattermost pricing](https://mattermost.com/pricing/).
- Mattermost documents that deactivated users do not consume the same active
  operational posture, and that a single-channel guest can be free within a
  stated ratio while broader guest participation can count as a paid active
  user. Source: [Mattermost pricing FAQ and feature comparison](https://mattermost.com/pricing/).
- Inference for Setjoin: a named "licensed member" rule must explicitly exclude
  disabled users, mailbox-less guests, shared mailboxes, rooms/resources, and
  service identities. Ambiguous raw-row counting would make directory sync and
  Guest Accounts commercially unsafe.

### Microsoft Teams

- Microsoft publishes annual per-user plans and separate per-user or per-room
  add-ons. The current comparison includes Teams Essentials, Microsoft 365
  bundles, Teams Phone, Teams Premium, and Teams Rooms licensing. Source:
  [Microsoft Teams plans and pricing](https://www.microsoft.com/en-us/microsoft-teams/compare-microsoft-teams-business-options).
- Inference for Setjoin: separate high-cost value axes can be add-ons, but a
  dense matrix of user, room, phone, AI, and bundle licenses would be excessive
  for an initial self-hosted product.

### 飞书 (Feishu)

- 飞书 currently publishes a free plan for up to 100 users, annual per-user
  Commercial Standard/Professional/Flagship tiers, and a custom-priced
  Enterprise Flagship tier with no published scale ceiling. Higher tiers add
  capacity, SSO/security, organizational control, and enterprise service.
  Source: [飞书定价](https://www.feishu.cn/pricing).
- The public pricing page does not establish an on-premise/offline entitlement
  contract or expired-license behavior. This note does not infer one.
- Inference for Setjoin: per-person bands are familiar in the Chinese
  collaboration market, but SaaS-style storage and meeting quotas are a poor
  primary boundary for customer-owned infrastructure.

## Recommended Setjoin model

Adopt Proxmox's **Community versus production-certified Enterprise channel**,
Nextcloud/Mattermost's **annual per-user commercial metric**, and Setjoin's own
air-gap requirements.

### Community channel

- Public, signed, self-service releases for the current supported line.
- Community support and public documentation.
- No intentional delay or paywall for critical security fixes.
- Shorter compatibility/support window; customers track the current supported
  release rather than receiving long-lived backports.
- No hard 10-seat product shutdown. The archived 10-seat proposal is
  unimplemented and is a weak enforcement boundary for AGPL software.

### Enterprise channel

- Annual subscription measured by active internal human members.
- A minimum commercial order aligned with Setjoin's target market, with volume
  bands and a negotiated site license for very large deployments.
- Production-certified LTS releases, longer security/stability backports,
  signed offline bundles and mirrors, certified upgrade/rollback paths,
  maintenance advisories, and accountable support SLAs.
- Optional paid support tiers (business-hours and 24×7), migration/deployment
  services, DR rehearsals, and compliance/identity integration assurance.
- Critical security fixes remain available to Community; Enterprise value is
  older-LTS backport coverage, advance coordination, validation evidence, and
  support accountability.

### Licensed-member rule

Count an enabled internal human identity capable of interactive login. Exclude:

- disabled or deleted identities;
- mailbox-less Guest Accounts;
- shared mailboxes and aliases;
- rooms/resources;
- service and automation principals;
- test/staging identities covered by an explicit non-production entitlement.

Use an annual true-forward process rather than suddenly blocking users when a
directory synchronization crosses the purchased band.

### Entitlement and expiry

- Enforce Enterprise repository access at the update service; do not rely only
  on a locally patchable feature check.
- Also support a signed, offline-importable entitlement file. Use a dedicated
  update-signing/entitlement trust domain, not authentication JWT signing keys.
- Expiry must never stop mail delivery, login, reads, writes, export, restore,
  or access to already-created customer data. The instance keeps its last
  licensed release; new Enterprise artifacts and support entitlements pause
  after a visible grace period.
- Do not require telemetry or continuous phone-home for air-gapped customers.

## Upgrade UI implications

- Show `Community` or `Enterprise` as the selected release source, not as a
  feature-quality judgment about the running installation.
- Both channels use the same signed manifest and root-owned updater protocol.
- Enterprise status shows entitlement expiry, support window, release support
  end, offline bundle import, and mirror status.
- Community-to-Enterprise activation changes channel eligibility without
  reinstalling or migrating customer data.

## Decision delta

This recommendation supersedes the cold, unimplemented proposal in
`docs/design/clients/archive/phase12-client-architecture.md` that limited the
Community edition to ten seats and treated seat count as the only product
boundary. The durable spec/ADR must record the replacement explicitly; the
archive remains historical evidence and should not be silently rewritten.
