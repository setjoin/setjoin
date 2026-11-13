# Updater security divergences from frozen Go

Owner-approved security fix 2026-11-05 (#506, #505, #507). Each behavioural fix has
a test and an `oracle-mutants` feature branch that restores the gap;
`scripts/test-updater-secfix-mutants.py` requires every mutant to be rejected, the
ordinary build green and the `--release` binary to reject the test-only verify flags.
Never enable the feature in a shipped build.

## What managed adoption guarantees (#506, #507)

`adopt-current-layout` on an existing `current` release:
- Managed release (has `manifest.json`): (1) self-consistency, as activation does:
  `manifest.digest`, canonical identity and `installed.evidence.json` content digest;
  (2) authenticity: the stored signed manifest must verify against the operator's
  release trust roots (`--trust-roots`, default `/etc/setjoin/release-roots.json`,
  root-owned) with at least the built-in two-signature floor and the manifest's own
  threshold, judged at the manifest's `published_at` (adoption does not re-judge
  freshness); (3) every installed non-webmail artifact (binaries, recovery guide,
  SBOM, provenance) must match the signed size and SHA-256. Failure is "refusing to
  adopt" before any `*.prev` is quarantined; `current` is untouched.
- Not covered: the webmail tree (the signed tarball is not kept; it is bound only
  by the local evidence digest) and config.env content.
- Without a trust-roots file adoption of a managed release is refused. Operator
  recovery: install the vendor `release-roots.json` (root-owned, purpose "release")
  at the default path or pass `--trust-roots`, then re-run the installer. There is
  no unsigned override.
- A release carrying both `adoption.json` and `manifest.json` is refused (in adoption
  and in activation/rollback validation): a stray `adoption.json` cannot divert a
  managed release onto the self-hashed path.
- A release with only `adoption.json` is a legacy cohort adopted from a flat install;
  it is self-hashed by design and carries no signed claim.
- Every file, directory and tree entry the updater trusts must be owned by root (or
  the euid, which is root in production): `files::open`, tree walk and `secure_dir`.

## Other fixes
- #506 `activate-previous --force` needs `isatty(0)`; `/dev/null`, `/dev/zero` are
  refused (`tests/recovery.py` uses a pty for the positive path).
- #506 the `setjoin-recovery` wrapper execs the absolute
  `/usr/libexec/setjoin-updater` (`tests/swap.rs`, decoy sibling must not run).
- #505 `secure_dir` creates missing directories (and parents) with `DirBuilder::mode`
  plus an exact-mode chmod to undo the umask.
- #505 `dbtls.rs` honours `sslmode` (disable, allow/prefer default, require,
  verify-ca, verify-full) and `sslrootcert` via rustls/ring and
  `tokio-postgres-rustls`; `require` encrypts without verifying, as pgx does.
- #505 `verify --allow-test-roots` and `--now` exist only when `debug_assertions` is
  on; a release binary rejects them as unknown flags.
- #507 `verify --minimum-threshold` is raise-only: release builds use
  `max(requested, 2)`; the manifest's own threshold already applies via max(). Only
  test builds may lower it (single-signer fixtures).

## Delivery of the release trust roots (#507)
The vendor PUBLIC release roots are not in the repository: they are provisioned in the
signing environment (`SETJOIN_RELEASE_TRUST_ROOTS_PATH`).
`scripts/package-server-release.sh` therefore takes them from the build input
`SETJOIN_RELEASE_TRUST_ROOTS` (validated: schema 1, purpose release, 1..16 ed25519 keys,
none test-only) and ships `server-rust/release-roots.json`; without it the package builds
with a warning. `install.sh` calls `install_release_roots`
(`mailserver/deploy/scripts/lib-release-roots.sh`) before `adopt-current-layout`: the package
copy is installed root-owned 0644 at `$CONFIG_DIR/release-roots.json`; else an existing
root-owned file there is used; else, if `current` is a managed release, the installer dies
with an operator message (provide the roots file or a package built with the input).
