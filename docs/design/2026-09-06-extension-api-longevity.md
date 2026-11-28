# Extension/API longevity: comparison and accepted Setjoin policy

Checked: 2026-09-06, official documentation through gstack browse.
Status: user accepted the successor/notice policy on 2026-09-06 with a 12-month
successor window instead of the proposed 24 months. Planning policy, not implementation.

## What established ecosystems actually promise

| Platform/surface | Published policy | Relevance and limit |
|---|---|---|
| [GitHub REST](https://docs.github.com/en/rest/about-the-rest-api/api-versions) | Previous API version supported for at least 24 months after a new version releases; deprecation/sunset signals and exceptional security interventions | A successor-based migration window, not two years of maintenance for every product binary |
| [Shopify versioned APIs](https://shopify.dev/docs/api/usage/versioning) | Quarterly versions, at least 12 months stable-version support and nine months overlap between consecutive versions | A hosted app ecosystem can require regular developer upgrades; unversioned surfaces follow different rules |
| [VS Code extension APIs](https://code.visualstudio.com/api/advanced-topics/using-proposed-api) | Best effort to avoid breaking published APIs; unstable proposed APIs are separated from stable and restricted to experimentation | Compatibility-first rather than a fixed short expiry; not an unconditional perpetual warranty |
| [VS Code engine declaration](https://code.visualstudio.com/api/working-with-extensions/publishing-extension) | Extensions declare compatible host versions through `engines.vscode` | Host availability and API promise are distinct; a version range alone is not conformance evidence |
| [Kubernetes versioned APIs](https://kubernetes.io/docs/reference/using-api/deprecation-policy/) | GA API versions may be deprecated but not removed within a Kubernetes major; beta retirement has both month and release-count rules | Stable infrastructure interfaces can last much longer than three years; do not confuse API rules with separate CLI/component support rules |

These are different ecosystems, not a universal industry-standard duration. API
contracts, plugin binary ABI, host release support, stored data formats and third-party
vendor service availability must not share one lifetime counter.

## Assessment

Three years is not unusually long for a stable public API. It is premature as a
blanket promise for Setjoin's still-evolving extension surfaces. The previous text
also does not clearly define the clock's start or the notice/replacement requirement.
Retaining a small old API adapter in a new rolling release is different from keeping
three years of old Setjoin binaries, schemas and dependencies maintained.

The more important cost controls are: publish fewer stable contracts, keep experimental
surfaces explicitly experimental, add compatible fields without creating new majors,
and change majors only for real semantic breaks. Do not manufacture annual API breaks
or maintain separate domain business logic for each API version.

## Accepted replacement policy

- Experimental/beta surfaces have explicit maturity and tested compatibility; no
  blanket multiyear guarantee before the stable promotion gates pass.
- Stable contracts remain compatible in supported rolling Setjoin releases.
- Ordinary retirement requires a stable replacement plus migration guidance and
  conformance fixtures. Do not remove the prior stable major earlier than **12 months
  after that replacement is available** and **12 months after explicit deprecation
  notice**, whichever deadline is later.
- The window is a minimum, not automatic expiry: keep low-cost compatible contracts
  longer where useful. Do not promise only two simultaneous majors if the windows overlap.
- Security exceptions can fence unsafe behavior sooner, with affected ranges, reason
  and remediation. They do not authorize the separately deferred remote mitigation service.
- Existing product/enterprise-channel, backup-format and dependency support decisions
  remain separate. This does not require supporting old product binaries for 12 months.
- Record deprecation and replacement per capability/major, show installed-app impact
  and deadline in admin UI, offer conformance/migration tools, and warn offline installs
  using signed release metadata without requiring telemetry or internet connectivity.

This policy may support an API for longer than three years in total if no successor
exists; it shortens and clarifies the migration window, not the total lifetime by decree.
It is Setjoin's chosen hybrid, not a claim that another platform uses this exact formula.

The clocks run concurrently, not consecutively: earliest ordinary retirement is
`max(stable_successor_release + 12 calendar months, deprecation_notice + 12 calendar months)`.
If successor and notice arrive together, the minimum is 12 months, not 24. Later
notice moves the deadline later. No successor or no notice means no ordinary
retirement deadline; the separately stated security exception still applies.

Decision history: prior three-year promise reopened; initial 24-month successor
proposal not adopted; user selected 12 months and retained the other safeguards.
The extension design is the normative contract owner. No product/version support
claim or completed compatibility-test evidence follows from this policy decision.

## Research execution

Task: `sj-api-longevity-20260906`; local read-only official-page browsing.
The task started browser daemon PID 87066 with one about:blank tab, then used that
tab for the five official pages above. No logins, downloads, test services, Docker
resources or remote runners. Root stopped the owned browser after research; shared
Graphify caches/indexes remain for navigation. Checked sources are summarized rather
than copied; current repository evidence remains separate from external policies.
