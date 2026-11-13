---
title: GitHub Actions Security Hardening Checklist
source_urls:
  - https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions
  - https://docs.github.com/en/actions/security-for-github-actions/security-guides/automatic-token-authentication
  - https://docs.github.com/en/actions/security-for-github-actions/using-artifact-attestations/using-artifact-attestations-to-establish-provenance-for-builds
  - https://github.com/actions/attest-build-provenance
  - https://github.com/step-security/harden-runner
  - https://github.com/zizmorcore/zizmor
  - https://docs.zizmor.sh/usage/
fetched: 2026-06-10
applies_to:
  - .github/workflows/release.yml
  - .github/workflows/xinchuang-ci.yml
---

# GitHub Actions Security Hardening (2026)

Tailored to this repo's two workflows:

- **release.yml** — tag-triggered, builds Tauri desktop apps (macOS arm/x86, Windows
  x64/arm64, Linux AppImage/deb/rpm), signs with Apple/GPG secrets, publishes a GitHub Release.
- **xinchuang-ci.yml** — push/PR-triggered, cross-arch Go builds (arm64, loong64),
  QEMU smoke test, unit tests, uploads binary artifacts.

Each item lists the rule, why, and what to change here. Severity: **[P0]** fix now, **[P1]** soon, **[P2]** hardening.

## 1. Pin every action to a full-length commit SHA [P0]

GitHub: "Pinning an action to a full-length commit SHA is currently the only way to
use an action as an immutable release… a bad actor would need to generate a SHA-1
collision for a valid Git object payload." Tags can be moved/deleted by anyone who
compromises the action's repo (cf. the `tj-actions/changed-files` breach).

Current state — **both workflows use floating tags / branches**:

| Action | Current | Fix |
|---|---|---|
| `actions/checkout@v5` | tag | pin to SHA `# v5` |
| `actions/setup-go@v6` | tag | pin to SHA `# v6` |
| `actions/upload-artifact@v4` | tag | pin to SHA `# v4` |
| `actions/download-artifact@v4` | tag | pin to SHA `# v4` |
| `dtolnay/rust-toolchain@stable` | **branch** (worst case) | pin to SHA `# stable` |

`@stable` is a moving branch ref — a backdoored commit lands in your build instantly. Pin it.

```yaml
# Before
- uses: actions/checkout@v5
# After (keep the version in a comment so Dependabot can update it)
- uses: actions/checkout@<40-char-sha> # v5
```

Enable **Dependabot for actions** (`.github/dependabot.yml`, `package-ecosystem: "github-actions"`)
so SHA pins still get update PRs. Note: Dependabot alerts do **not** fire for
SHA-pinned actions, so pair pinning with version-update PRs + dependency review.

## 2. Set least-privilege `GITHUB_TOKEN` permissions [P0]

GitHub: "grant the `GITHUB_TOKEN` the least required access." Default the whole repo
to read-only (org/repo setting **Settings → Actions → Workflow permissions →
Read repository contents**) and elevate per job.

**release.yml** declares `permissions: contents: write` at the top level, so *every*
build job inherits release-write. The five build jobs only need to read code and
upload artifacts — they should be read-only. Move write down to the publishing job:

```yaml
# top of file — safe default
permissions:
  contents: read

jobs:
  build-macos-arm:
    permissions:
      contents: read          # build jobs: read only
  github-release:
    permissions:
      contents: write         # only the job that runs `gh release create`
```

**xinchuang-ci.yml** declares **no `permissions:` block at all** → inherits the repo
default, which may be read/write. Add an explicit top-level `permissions: contents: read`.
None of its jobs push anything to the repo.

Available scopes incl. `contents`, `packages`, `id-token`, `attestations`,
`pull-requests`, `issues`, `actions`. Set only what each job uses.

## 3. Release artifact signing + build provenance attestation [P1]

Beyond Apple notarization / GPG (already present, both `continue-on-error: true`),
add **SLSA build provenance** so downstream consumers can cryptographically verify a
DMG/MSI/AppImage was built by *this* repo's workflow. Uses keyless Sigstore signing
via OIDC — no long-lived signing key.

Add to `github-release` (or each build job) in release.yml:

```yaml
permissions:
  id-token: write       # mint OIDC token for Sigstore cert
  attestations: write   # persist the attestation
  contents: read
steps:
  - uses: actions/attest-build-provenance@<sha> # v3
    with:
      subject-path: 'artifacts/**/*.dmg,artifacts/**/*.msi,artifacts/**/*.AppImage,artifacts/**/*.deb,artifacts/**/*.rpm'
```

(As of v4, `attest-build-provenance` is a thin wrapper over `actions/attest`; v3 is
fine and widely used. New work can use `actions/attest` directly.)

Consumers verify with:

```bash
gh attestation verify <downloaded-artifact> -R setjoin/setjoin
```

For xinchuang-ci.yml, attesting the `authserver-<arch>` / `mailserverd-<arch>`
binaries gives Xinchuang certification reviewers a provenance trail. Apply the same
block to the `cross-build` job (add `id-token`/`attestations: write` there).

**Note:** `continue-on-error: true` on the signing steps means an *unsigned* release
still ships silently. For tagged releases, consider failing hard when signing secrets
are expected to be present.

## 4. Fork-PR safety [P1]

xinchuang-ci.yml triggers on `pull_request` (incl. forks). Risks:

- **Secrets are withheld** from fork PRs by default for `pull_request` — good. Do **not**
  switch this workflow to `pull_request_target`, which runs in the *base* repo context
  with secrets and the checked-out PR head: that is the classic privilege-escalation /
  "pwn request" sink. Keep `pull_request`.
- The workflow runs **untrusted code** (`go build`, `go test`, downloaded
  `govulncheck@latest`) from fork branches. It currently has no secrets exposure, but
  keep it that way — never add secrets to the build/test jobs.
- Enable **"Require approval for all external contributors"** (Settings → Actions →
  Fork pull request workflows) so a maintainer must approve each fork run.
- `govulncheck@latest` and `cargo tauri` pull unpinned tool versions at runtime — a
  poisoned upstream release executes on your runner. Pin tool versions where feasible.

## 5. Prevent script injection from untrusted context [P1]

GitHub: never interpolate untrusted `${{ ... }}` (PR titles, branch names, issue
bodies) directly into `run:` shells — it breaks out of quotes and executes commands.
Use an **intermediate env var** and quote it:

```yaml
# Unsafe:  run: echo "${{ github.event.pull_request.title }}"
# Safe:
env:
  TITLE: ${{ github.event.pull_request.title }}
run: echo "$TITLE"
```

Audit here: release.yml uses `${{ github.ref_name }}` directly in the `gh release
create` command. `ref_name` for a `tags/v*` trigger is constrained but still
attacker-influenceable if someone can push arbitrary tags. Move it to an env var:

```yaml
env:
  TAG: ${{ github.ref_name }}
  GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
run: gh release create "$TAG" --title "$TAG" --generate-notes artifacts/**/...
```

The matrix `${{ matrix.arch }}` values in xinchuang-ci.yml are statically defined
(`arm64`, `loong64`) so are not untrusted — fine as-is.

## 6. Secrets handling [P1]

- Never `echo`/log a secret. Automatic redaction is best-effort and "is not
  guaranteed" for transformed values. release.yml pipes `$APPLE_DEVELOPER_CERT`,
  `$GPG_PRIVATE_KEY`, `$GPG_PASSPHRASE` through shell — verify none land in logs;
  add `::add-mask::` for any derived sensitive value.
- Don't store structured/multi-value blobs as one secret — redaction relies on exact
  matches. The base64 cert is one opaque value, acceptable; keep passwords separate
  (already are).
- Rotate Apple/GPG signing secrets periodically.
- Prefer **OIDC over long-lived secrets** for any future cloud upload (e.g. publishing
  artifacts to S3/SeaweedFS, R2, or a cloud KMS signer): "stop storing these
  credentials as long-lived secrets… short-lived, well-scoped access tokens."
  This repo already uses S3/OSS — if release uploads ever go to a cloud bucket, use
  `id-token: write` + the cloud's OIDC trust instead of static keys.

## 7. Runner hardening with step-security/harden-runner [P2]

Network-egress EDR for runners — detects/blocks exfiltration of secrets/source and
flags anomalous outbound traffic (it caught the axios trojan, Trivy, and tj-actions
compromises). Add as the **first step** of each job:

```yaml
- name: Harden Runner
  uses: step-security/harden-runner@f808768d1510423e83855289c910610ca9b43176 # v2.17.0
  with:
    egress-policy: audit   # start in audit; review the generated allowlist
```

Start with `egress-policy: audit`, review the insights, then switch to `block` with an
explicit allowed-endpoints list (crates.io, GitHub, apt mirrors, Apple notary,
Go proxy). Note: harden-runner is Linux-only — it works on the `ubuntu-latest`
jobs (xinchuang-ci entirely, release.yml's `build-linux` + `github-release`) but not
the macOS/Windows Tauri jobs.

## 8. Static-analyze workflows with zizmor [P1]

`zizmor` is a static analyzer for GitHub Actions that flags template injection,
unpinned actions, excessive permissions, credential persistence, dangerous triggers,
and impostor/confusable git refs — i.e. items 1–5 above, automatically.

Install + run locally:

```bash
uvx zizmor .github/workflows/      # or: pip install zizmor / cargo install zizmor / brew install zizmor
zizmor .github/workflows/release.yml .github/workflows/xinchuang-ci.yml
zizmor --offline .github/workflows/   # offline (no GitHub API lookups)
```

Add a CI gate (new workflow `zizmor.yml`) that uploads SARIF to code scanning:

```yaml
permissions:
  contents: read
  security-events: write   # required to upload SARIF
steps:
  - uses: actions/checkout@<sha> # v5
  - run: uvx zizmor --format=sarif .github/workflows/ > zizmor.sarif
  - uses: github/codeql-action/upload-sarif@<sha> # v3
    with:
      sarif_file: zizmor.sarif
```

Run `zizmor` against the current two files before merging the fixes in items 1–6.

## 9. Supply-chain monitoring & audit [P2]

- **Dependabot version updates** (`github-actions` ecosystem) keep SHA pins fresh;
  **dependency review action** on PRs touching `.github/workflows/**`.
- **CODEOWNERS**: add `/.github/workflows/ @<maintainer>` — workflow changes have
  access to all repo secrets and `GITHUB_TOKEN` write, so they must be reviewed.
- **OpenSSF Scorecard action** for a recurring supply-chain posture score (flags
  unpinned actions, token perms, dangerous patterns).
- Watch the **org audit log** for `org.update_actions_secret`.

## Quick remediation order for this repo

1. **[P0]** Pin all actions to SHA in both files (esp. `dtolnay/rust-toolchain@stable`).
2. **[P0]** `permissions: contents: read` top-level in both; `contents: write` only on
   `github-release`.
3. **[P1]** Add `actions/attest-build-provenance` to release + xinchuang binary jobs.
4. **[P1]** Move `${{ github.ref_name }}` into an env var in release.yml.
5. **[P1]** Add a `zizmor` CI gate; require approval for fork PRs.
6. **[P2]** `harden-runner` (audit→block) on Linux jobs; Dependabot + CODEOWNERS.

Source URLs in the `source_urls` frontmatter; all fetched 2026-06-10.
