// INSPECTION-CHECKED ARTIFACT — NOT MACHINE-RUN (med-shard2-013 r2).
//
// This repo carries no ArkTS test toolchain (no hvigor/DevEco test runner in
// CI), so this file is a negative-test ARTIFACT for review inspection, not an
// executed suite. Status:
//   - Rust-side machine evidence for the native seam: ../binding_confinement_test.rs.
//   - This artifact: inspection-checked coverage of the https-trust-anchor
//     minimum in entry/src/main/ets/pages/ServerConfigPage.ets —
//     D-CLIENTS-HARMONYOS-ENTRY-003, including the PERSISTED-value half of the
//     finding (aboutToAppear re-validates a stale anchor saved by an older
//     build before auto-navigating).
//
// Pins:
//   1. httpsTrustAnchorFromInput rejects explicit cleartext/unknown schemes:
//      http://, ftp://, file:// — null, never an anchor;
//   2. it rejects an authority-less "https://" (names no host);
//   3. it accepts https:// URLs verbatim and defaults scheme-less hosts to
//      https:// (project rule: no hardcoded server URLs — this is the input);
//   4. the persisted-anchor path: aboutToAppear reads `server_url` from
//      preferences and only auto-navigates when httpsTrustAnchorFromInput
//      (saved) is non-null — a stale http:// anchor from an older build is
//      rejected and the user stays on this control. The function-level cases
//      below drive the exact expression aboutToAppear evaluates
//      (`httpsTrustAnchorFromInput(saved)`); the preferences/router interaction
//      itself is inspection-read of the source (single call site, no scheme
//      bypass between read and evaluate).
//
// The preferences stub mirrors the persisted-shape cases so the stale-anchor
// scenario is concrete without a device; substitute a mocked preferences
// instance when this moves into a harness.

const STALE_HTTP_ANCHOR: string = 'http://mail.corp.example.org';
const STALE_HTTPS_ANCHOR: string = 'https://mail.corp.example.org';

let passed = 0;
let failed = 0;

function expectNullAnchor(input: string, label: string): void {
  const anchor: string | null = httpsTrustAnchorFromInput(input);
  if (anchor === null) {
    passed++;
    console.log(`[INSPECTION] ${label}: rejected (null anchor) as expected`);
  } else {
    failed++;
    console.error(`[INSPECTION] ${label}: expected null, got '${anchor}'`);
  }
}

function expectAnchor(input: string, expected: string, label: string): void {
  const anchor: string | null = httpsTrustAnchorFromInput(input);
  if (anchor === expected) {
    passed++;
    console.log(`[INSPECTION] ${label}: '${expected}' as expected`);
  } else {
    failed++;
    console.error(`[INSPECTION] ${label}: expected '${expected}', got '${anchor}'`);
  }
}

export function runPersistedHttpAnchorRejectionCases(): void {
  // 1. Explicit cleartext / unknown schemes never anchor.
  expectNullAnchor(STALE_HTTP_ANCHOR, 'persisted http:// anchor rejected');
  expectNullAnchor('http://mail.corp.example.org:8443', 'http with port rejected');
  expectNullAnchor('HTTP://mail.corp.example.org', 'uppercase http scheme rejected');
  expectNullAnchor('ftp://files.example.org', 'ftp scheme rejected');
  expectNullAnchor('file:///etc/hosts', 'file scheme rejected');

  // 2. An authority-less https:// names no host.
  expectNullAnchor('https://', 'authority-less https rejected');

  // 3. Acceptance shapes.
  expectAnchor(STALE_HTTPS_ANCHOR, STALE_HTTPS_ANCHOR, 'https anchor accepted verbatim');
  expectAnchor('mail.corp.example.org', 'https://mail.corp.example.org',
    'scheme-less host defaults to https');
  expectNullAnchor('   ', 'empty input rejected');

  // 4. Persisted-anchor decision table (the expression aboutToAppear
  //    evaluates against preferences 'server_url').
  const savedHttp: string = STALE_HTTP_ANCHOR;
  const staleAnchor: string | null =
    savedHttp.length > 0 ? httpsTrustAnchorFromInput(savedHttp) : null;
  if (staleAnchor === null) {
    passed++;
    console.log('[INSPECTION] aboutToAppear must NOT auto-navigate on the stale http anchor ' +
      '(stays on ServerConfigPage)');
  } else {
    failed++;
    console.error('[INSPECTION] stale http anchor would auto-navigate — persistence chain broken');
  }
  const savedHttps: string = STALE_HTTPS_ANCHOR;
  const freshAnchor: string | null =
    savedHttps.length > 0 ? httpsTrustAnchorFromInput(savedHttps) : null;
  if (freshAnchor === savedHttps) {
    passed++;
    console.log('[INSPECTION] valid persisted https anchor still auto-navigates');
  } else {
    failed++;
    console.error('[INSPECTION] valid persisted https anchor must not be stranded');
  }

  console.log(`[INSPECTION] persisted http-anchor rejection: ${passed} passed, ${failed} failed ` +
    `(inspection-only — see header)`);
}
