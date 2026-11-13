# MEET renderer/font qualification receipt — 2026-09-20 (owner decision D3)

Authorization: `docs/verification/2026-09-19-owner-consolidated-decisions.md` §D3
(one-suite constraint: LibreOffice headless is the single office engine; the PDF
paging primitive — poppler GPL or pdfium BSD-style — is chosen BY MEASUREMENT).
Corpus: `docs/verification/meet-m0-corpus.json` (revision 2, this run), plan M0
L647-668 + M1 L669-712 qualification requirements. Branch
`codex/meet-renderer-qualification` (base 9c12fd886). This run is the
**dev-side feasibility qualification on darwin/arm64**; the server-side
production pin re-qualifies on linux-ci-host (named follow-up below).

## 1. Environment and host

| Item | Value |
| --- | --- |
| Host | macOS darwin 25.6.0 arm64 (owner's Mac, Docker-free run) |
| Producer | LibreOffice headless via `brew install --cask libreoffice` |
| Producer pin (verbatim `soffice --version`) | `LibreOffice 26.8.0.3 bce0998afefdbc355585ca324285661a2170ba77` |
| Producer install digest | cask 26.8.0, dmg sha256 `8858d8058da4f862f47559486814e65efc27294da67c5e4bb56b006b1ee59f89` (`https://download.documentfoundation.org/libreoffice/stable/26.8.0/mac/aarch64/LibreOffice_26.8.0_MacOS_aarch64.dmg`) |
| Candidate A | poppler 26.09.0 (Homebrew bottle `arm64_tahoe` sha256 `282b89b8f5a4c802f178e596fc98a29171d01b34bd1198658c88a6b2deef2b9b`; upstream source `poppler-26.09.0.tar.xz` sha256 `8059eadb6805340768f138c465b57f8164c92b4a0773c37ef031ea6c0d987b2e`) |
| Candidate B | pdfium chromium/8057 (bblanchon/pdfium-binaries staged build; public API MAJOR=155; build `args.gn` pinned: `pdf_enable_v8=false`, `pdf_enable_xfa=false`, `is_debug=false`, `target_os=mac`, `target_cpu=arm64`) |

## 2. Network denial (measurement discipline)

All measurement commands ran under a macOS seatbelt profile denying every
network operation (`/tmp/setjoin-renderer-qual/net-deny.sb`:
`(deny network*) (allow default)`). The denial was proven to bite before the
runs:

- canary 1: `sandbox-exec -f net-deny.sb curl https://github.com` → FAILED (denied)
- canary 2: `sandbox-exec -f net-deny.sb python3 socket.create_connection(('github.com',443))` → `gaierror` (denied)
- control (no profile): same curl → HTTP 200

Acquisition of the candidates' artifacts happened as separate, digest-verified
downloads (§1, §4) — never inside the measurement runs. Both candidates and
the measurement harness are network-free by construction (no HTTP clients,
no font fetching — embedded subsets + local font dir only).

## 3. Corpus consumption (manifest revision 2)

The run consumed the five producer-pinned recipes of the frozen M0 corpus and
flipped them from acquisition-pending to frozen (digests + observed counts in
`meet-m0-corpus.json` revision 2):

| Entry | Bytes | sha256 | Count (observed) |
| --- | --- | --- | --- |
| `m0corpus-pdf-lo-ref20.pdf` (pptx→pdf) | 47,797 | `a0db64fb6d604acdc728c581c65ee9ddaa21900aa400124a852f93a9cbb70675` | 20 pages (expected 20) |
| `m0corpus-pdf-lo-odp10.pdf` (odp→pdf) | 36,392 | `49121c2693c0aaeacf99d248eb0f5cf728681e38fa74c1cbea7fe9f4a1609294` | 10 pages (expected 10) |
| `m0corpus-pdf-lo-docx12.pdf` (docx→pdf) | 26,589 | `9b5f8548dcd709d7f0b8eddff95540934d3fa2ea55b591f54ca0e89499c9a469` | 12 pages (observed; equals the seed's declared 12 as an observation) |
| `m0corpus-pdf-lo-xlsx3.pdf` (xlsx→pdf) | 60,394 | `a175162664cbdc8430c5e8083c2da5356b6eb013e3314dc50dd4457afa76dc78` | 3 pages |
| `m0corpus-odp-lo-ref20.odp` (pptx→odp) | 17,078 | `b0aa1e982f5d90980f24aabce92f82cda49d42d3bce9dfe2f6cdabb8d86e0807` | 20 slides (expected 20) |

soffice derives output names from the input stem; the recipe bytes were
renamed to the pinned entry names (rename only — digests are of content).

Producer determinism (measured): same recipe, same engine, three runs → three
different digests; a byte-diff of two ref20 PDFs showed **exactly 64 differing
bytes of 17,737**, confined to the trailer (`CreationDate`, `/ID` file ID);
rendered page content identical. This confirms the manifest's single-capture
pin semantics: producer-pinned bytes are pinned per acquisition, never
regenerated blindly.

### Corpus seed amendments (owned; both discovered by this run)

The pre-amendment pptx seed produced **all-blank** PDF pages: every page
carried only LibreOffice's white-background artifact stream. Two root causes,
both in `scripts/gen-meet-m0-corpus.sh` (synthetic-seed generator, run-owned):

1. **Empty `<p:spPr/>` shapes are dropped by the LibreOffice Impress import**
   — the seed's title/body shapes carried no `<a:xfrm>` geometry, so the
   pinned producer emitted nothing to render. Fix: explicit geometry + run
   color/size (deterministic). After the fix the reference deck renders
   non-blank with embedded subset fonts (`LiberationSans` + Bold, per
   `pdffonts`) and 20/20 slide titles extractable.
2. **SlideMaster relationship must come FIRST in `presentation.xml.rels`** —
   with a trailing master relationship, LibreOffice 26.8.0.3's pptx import
   consumed the first SLIDE relationship for the master: slide 1's content
   vanished, every slide shifted one page early, and a blank trailing page
   appeared (reproduced at 3 slides; bisected with minimal variants — notes
   slides and rels ordering alone do not trigger it). Fix: master-first
   (rId1), matching what real producers emit. Post-fix: 20/20 pages, 20/20
   titles in both the PDF and the ODF save-as.

Only `m0corpus-pptx-reference20.pptx` changed (37,957 → 40,403 bytes,
sha256 `7244cd1379093fb7dbd559ddb72d2393cf31d5e56f639538db9c93faedbd1141`);
the other nine synthetic-seed rows are byte-identical to revision 1. The two
pptx-sourced acquisitions were re-run after the fix; the docx/xlsx/odp-sourced
acquisitions were untouched by the seed change and keep their original
capture digests.

## 4. Candidates — artifact identity

| Criterion | poppler 26.09.0 | pdfium chromium/8057 |
| --- | --- | --- |
| OS/arch (this run) | darwin/arm64 | darwin/arm64 |
| Artifact shape | CLI tools + libs (`pdftoppm` sha256 `9a44364d0fa42a43c3efdb2cbab47d275973c4a5856c1109f6bf4513def6bb54`; `libpoppler.164.dylib` sha256 `9ab29594027975ab334880fd99c2cdd11465c3df34f6476a29430ceb59462f93`) | single dylib, 7,261,536 B, sha256 `818c96da82396168b6dd6e79e2a28065f3ac1d97e0f72d214b41be9decb7075a` |
| Release digests | bottle + upstream tarball digests (§1) | GitHub-published sha256 per release asset — verified on download (`pdfium-mac-arm64.tgz` `013ecc9e0a155dabb8dd006a73a028ea542965f80a4990e5f013de283b0e58a6`) |
| Signature/provenance | freedesktop.org tarball + distro packaging | **Sigstore keyless attestation** (`pdfium-attestation.json` sha256 `3928dc9e52ebda1b200d9cb2dcbd971aee57b08190a49ea3e6cd7c31ee445719`) binding the build to the upstream GitHub Actions workflow (`build-all.yml`); pinned `args.gn` |
| Active content | XFA/JS N/A (renderer does not execute document scripts; poppler renders static appearance only) | build flag pinned `pdf_enable_v8=false`, `pdf_enable_xfa=false` — no JS/XFA engine in the artifact |
| License | GPL-2.0-or-later (`COPYING` v2 + `COPYING3`) | BSD-3-Clause (`pdfium.txt`) + permissive bundled components (`dist/licenses/`: freetype FTL, ICU, lcms MIT, libpng, zlib, openjpeg BSD, abseil Apache-2.0, …) |

## 5. Measurement protocol

- Inputs: **all 9 frozen corpus PDFs** (5 synthetic-seed + 4 producer-pinned).
- Rendering: 150 dpi, one PPM (P6) page asset per page, annotations rendered
  (`pdftoppm` default; pdfium `FPDF_ANNOT`).
- 3 runs per candidate per document; per-page sha256 digests compared
  byte-for-byte across runs; retained per-document identity digests in
  `2026-09-20-meet-renderer-qualification-digests.json` (annex).
- Page-count fidelity: rendered page count vs frozen manifest counts
  (poppler `pdfinfo`/rendered files; pdfium `FPDF_GetPageCount`).
- Correctness: non-blank pixel sampling (pages 1/mid/last per doc per
  candidate — 54 renders) + text-bearing checks (poppler `pdftotext`;
  pdfium `FPDFText_CountChars`).
- Latency: whole-document wall time (process-inclusive for both: poppler is
  invoked per document, pdfium through a small offline C harness,
  `pdfium_qual.c`, doing one init + in-process page loop — this shape
  difference is itself part of the deployment decision).
- Memory: peak RSS (`/usr/bin/time -l` for poppler; `getrusage` for pdfium).

## 6. Results

### 6.1 Determinism (3 runs × 9 docs × 2 candidates)

**PASS for both**: every one of the 634 pages × 3 runs × 2 candidates produced
byte-identical page assets across runs. Per-document asset-sequence identity
digests are pinned in the annex (examples: pdfium on `m0corpus-pdf-lo-ref20`
= `2c877fe4dd8ff5586a6450126b9c2dd29983e99f148b1d49e8ad25eade9fa7f2`; poppler
on the same input = `35dd3f15c43b4e2c0780fcf1a589895e4e80dbdeb24fe02e7c02e3940799fea8`).
Cross-candidate digests differ (independent rasterizer identities) — expected;
the pinned renderer's identity defines the pinned page assets.

### 6.2 Page-count fidelity vs the frozen manifest

**PASS for both**: rendered counts equal the manifest count/expectedCount on
all 9 PDFs (20/20 ref20, 10/10 odp10, 12/12 docx12, 3/3 xlsx3, 500 large,
9 asset-heavy, 50 medium, 20 annotation-heavy, 10 small).

### 6.3 Rendering correctness spot-check

**PASS for both**: 54/54 sampled page renders (first/middle/last of every
document, both candidates) non-blank with plausible dark-pixel fractions
(0.003–0.42, consistent across candidates per document); text extraction
non-zero on all documents for both candidates. Tolerance note: poppler emits
`Bad appearance for annotation` syntax warnings on the synthetic
annotation-heavy fixture (minimal FreeText annots without appearance streams)
but renders its pages; pdfium renders the same input silently. The LO-produced
reference deck embeds font subsets (renders identically anywhere); the
base-14 synthetic PDFs exercise local substitution.

### 6.4 Whole-document latency (mean of 3 runs, 150 dpi, process-inclusive)

| Document | poppler | pdfium | pdfium advantage |
| --- | --- | --- | --- |
| m0corpus-pdf-small-deck (10p) | 0.08 s | 0.02 s | ~4x |
| m0corpus-pdf-medium-deck (50p) | 0.37 s | 0.04 s | ~9x |
| m0corpus-pdf-large-500p (500p) | 3.67 s | 0.18 s | ~20x |
| m0corpus-pdf-asset-heavy-9x3mib (9p) | 0.27 s | 0.07 s | ~4x |
| m0corpus-pdf-annotation-heavy-ref20 (20p) | 0.28 s | 0.09 s | ~3x |
| m0corpus-pdf-lo-ref20 (20p) | 0.57 s | 0.02 s | ~28x |
| m0corpus-pdf-lo-odp10 (10p) | 0.31 s | 0.02 s | ~16x |
| m0corpus-pdf-lo-docx12 (12p) | 0.11 s | 0.01 s | ~11x |
| m0corpus-pdf-lo-xlsx3 (3p) | 0.04 s | 0.01 s | ~4x |

pdfium's in-process per-page medians: 0.30 ms (large-500p) to 5.6 ms
(asset-heavy). Both candidates are orders of magnitude inside the R2 start
budgets (cached reference-deck start p95 ≤ 30 s; new-rendition start p95
≤ 90 s); rendering is not the budget driver for either.

### 6.5 Peak RSS (mean of 3 runs)

| Document | poppler | pdfium |
| --- | --- | --- |
| m0corpus-pdf-asset-heavy-9x3mib | **34.1 MiB** | 56.4 MiB |
| m0corpus-pdf-annotation-heavy-ref20 | 33.7 MiB | 26.8 MiB |
| m0corpus-pdf-large-500p | 31.2 MiB | 24.0 MiB |
| m0corpus-pdf-medium-deck | 30.0 MiB | 22.8 MiB |
| m0corpus-pdf-small-deck | 29.8 MiB | 22.6 MiB |
| m0corpus-pdf-lo-ref20 | 20.5 MiB | 22.1 MiB |
| m0corpus-pdf-lo-docx12 | 19.4 MiB | 21.3 MiB |
| m0corpus-pdf-lo-xlsx3 | 19.1 MiB | 22.0 MiB |
| m0corpus-pdf-lo-odp10 | 17.6 MiB | 19.4 MiB |

Both stay in the tens-of-MiB range on every cell including the 28.3 MiB
incompressible-asset fixture; poppler wins the asset-heavy cell (34 vs
56 MiB) — recorded as poppler's single measured advantage. Neither approaches
any plausible worker memory ceiling; M1's worker still enforces its own
limits by design (rendition.go ceilings), independent of these numbers.

## 7. Decision — pdfium pinned (with rationale)

Both candidates pass every M0/M1 qualification gate measured here
(determinism, fidelity, correctness, network-free operation, digest-verifiable
acquisition, redistributable license). The pin goes to **pdfium
chromium/8057** on the measured differentiators:

1. **Latency**: 3–28x faster whole-document rendering (in-process library vs
   poppler's subprocess-per-document shape — the shape a long-lived
   meet-pages-v1 rendition worker actually wants).
2. **License surface**: BSD-3-Clause with permissive bundled components; no
   GPL source-availability obligations attach to the distributed sidecar
   artifact (compliance cell below).
3. **Provenance strength**: per-release upstream-published sha256 digests
   plus a Sigstore keyless attestation binding binaries to the upstream build
   workflow; build flags pinned (`pdf_enable_v8=false`,
   `pdf_enable_xfa=false` — no script/XFA active content in the artifact).

poppler 26.09.0 remains fully recorded as the runner-up with its own complete
measurement table; it wins the asset-heavy peak-RSS cell and remains the
GPL-compliance-cell alternative should pdfium ever become unavailable. Per
D3 and the plan's version-pinned lifecycle, a swap is a requalification
through the owning authority, never a silent provider swap.

## 8. GPL / BSD source-availability compliance cell (D3)

- **Pinned (pdfium, BSD-3-Clause)**: redistribution of the dylib requires
  preserving the copyright + license text and the documented third-party
  notices (`dist/licenses/` ships per-component licenses: freetype FTL, ICU
  license, lcms MIT, libpng, zlib, OpenJPEG BSD, abseil Apache-2.0,
  llvm-libc, simdutf, agg23, fast_float). No source-availability obligation;
  no copyleft contagion for the sidecar. The pinned artifact carries the
  upstream attestation; setjoin does not modify the library bytes.
- **Runner-up cell (poppler, GPL-2.0-or-later)**: distribution of poppler
  binaries (sidecar packaging, update channels) triggers GPL-2.0-or-later §3:
  complete corresponding source must ship or be offerable for the exact
  binary version (upstream tarball + build scripts + the distro package diff).
  Server-side internal use without distribution triggers no §3 offer, but the
  deployment-unit distribution model (installers, update artifacts) would
  carry a permanent source-offer obligation. This cell is why poppler's
  licensing weighed against it, and it stands as the recorded alternative's
  obligation if poppler is ever pinned.
- **Producer (LibreOffice, MPL-2.0)**: file-level copyleft; unmodified
  upstream binaries distribute cleanly with attribution + license text; the
  engine pin records the upstream dmg digest.

## 9. Pins (catalog registration only — rendering NOT enabled)

Extended the compiled deployment-unit catalog + generator WITHOUT enabling
behavior (M0 L651; M1 "extend the existing compiled deployment-unit catalog,
generator"; plan's version-pinned lifecycle):

- `mailserver/internal/deploycatalog/rendition_artifact.go`:
  `pinnedRenditionArtifacts()` admits at init, through the same fail-closed
  `AdmitRenditionArtifact` validation (a malformed pin panics the build):
  - **renderer `pdfium`** — darwin/arm64, Mach-O arm64 dylib in signed
    release tgz, sha256 `818c96da82396168b6dd6e79e2a28065f3ac1d97e0f72d214b41be9decb7075a`,
    BSD-3-Clause, owned install path `/opt/setjoin-rendition/lib/libpdfium.dylib`,
    health identity `rendition-render-probe/v1`, sandbox identity
    `net-deny-namespace/v1`, evidence = this receipt + provenance naming the
    release asset, attestation, and args.gn digests.
  - **font_pack `lo-bundled-font-pack`** — the LibreOffice 26.8.0.3-bundled
    font directory the measurements ran against (127 ttf/otf files);
    artifact digest = sha256 over the sorted per-file sha256 manifest:
    `89e2b42f0254e3e96767f42b7802de00077b0bc4ec2930276ed61e87fc9c16a2`;
    owned install path `/opt/setjoin-rendition/share/fonts/truetype`;
    composite redistributable licenses (SIL OFL-1.1 dominant: Liberation,
    Noto, Amiri, DavidLibre, MiriamLibre, Carlito; Apache-2.0: Caladea;
    GPL+font-exception: LinLibertine/Biolinum, culmus CLM; Bitstream Vera:
    DejaVu; Liberation license: Sans Narrow).
  - No rendering behavior consumes `AdmittedRenditionArtifacts()` (verified:
    zero callers outside the catalog); the systemd unit inventory is
    untouched (8 units, pinned by test).
- `mailserver/cmd/unit-catalog-gen`: new allowlist-validated projection
  (`SETJOIN_RENDITION_ARTIFACTS` + per-field keyed arrays), every field
  pattern-gated and single-quote-escaped; projection regenerated
  (`deploy/generated/unit-catalog.sh`, +33 inert lines).
- `mailserver/internal/deploycatalog/rendition_artifact_test.go`: the
  fail-closed gate now pins the shipped set EXACTLY
  (`TestRenditionCatalogShipsExactlyTheQualifiedPins`) — any digest/platform/
  evidence drift fails the build — while keeping the full
  unqualified-admission refusal matrix and traversal regression tests.
- Guard: `bash scripts/check-deploy-unit-catalog.sh --self-test` → PASS
  (projection check, deploycatalog tests, lifecycle test, mutant self-test).

The engine pin (LibreOffice identity + version) lives in
`meet-m0-corpus.json` `producerPinning.engine`; soffice is not a catalog
artifact kind (renderer|font_pack) and is pinned where its contract lives.

## 10. Deviations and findings

1. **Host**: D3 names linux-ci-host as the qualification host; this run executed
   dev-side on darwin/arm64 per the owner-directed run authorization, as
   feasibility evidence. The server-side production pin (linux/amd64)
   **re-qualifies on linux-ci-host** — see §11. Nothing here enables behavior.
2. **Corpus seed amendments** (§3): the pptx seed needed geometry +
   master-first rels because the pinned producer rendered blank/slide-shifted
   pages otherwise. Synthetic-seed digest re-pinned; all other synthetic rows
   byte-identical. This is a genuine qualification payoff: the run found and
   fixed two seed defects that would have made the reference deck vacuous.
3. **Corpus guard extension** (owned by this run's contract): the Go corpus
   helper's PDF token measurer now counts the unspaced `/Type/Page` spelling
   LibreOffice emits (lockstep with the bash verifier), and the freeze-shape
   test asserts the post-acquisition state (5 frozen producer-pinned rows,
   0 pending). Fabrication guard semantics unchanged (acquisition-pending
   names with bytes on disk are still refused). No meet behavior source
   touched.
4. **pdfium measurement harness**: a small offline C harness (`pdfium_qual.c`,
   temp dir) drove the library; the PIN is the pristine upstream dylib digest
   (re-extracted from the verified tarball — the harness build re-targets the
   dylib's install name, which changes only the local copy, never the pin).
5. **Producer output non-determinism**: 64 trailer metadata bytes per run
   (`CreationDate`/`/ID`); single-capture pinning is the documented answer.
6. **Latency methodology**: poppler measured per-process (CLI), pdfium
   in-process (one init). The asymmetry is inherent to the candidates'
   deployment shapes and is part of the decision, not a hidden handicap.
7. poppler `Bad appearance for annotation` warnings on the synthetic
   annotation fixture (§6.3) — rendering unaffected; recorded for M1's
   malicious-document/robustness corpus work.
8. Transient measurement resources (pdfium tarball + harness, measurement
   dirs, seatbelt profile) live under `/tmp/setjoin-renderer-qual/`; all
   load-bearing digests are pinned in this receipt, the annex, and the
   catalog, so the temp tree can be discarded.

## 11. What remains

- **linux-ci-host re-qualification (named follow-up, blocks the production pin)**:
  install the pinned engine (LibreOffice 26.8.0.3.x) on linux-ci-host, acquire
  the linux pdfium artifact (`pdfium-linux-x64.tgz` chromium/8057, digest
  verified), run `scripts/gen-meet-m0-corpus.sh acquire` + the same
  measurement protocol under Linux network denial (bubblewrap namespace),
  re-pin the engine capture + producer-pinned corpus rows + renderer/font
  pack (linux/amd64) with a dated receipt, and admit the linux pins beside
  (not replacing) these darwin/arm64 pins.
- M1 owns the `rendition-render-probe/v1` health protocol implementation and
  the installer/lifecycle legs that will consume the projected artifact data
  (no second installer; a manifest can never authorize arbitrary commands,
  units, or paths).
- Malicious-document corpus, decompression-bomb, timeout/OOM,
  cache-poisoning, font-digest, cross-tenant oracle tests: M1 serve-path gate,
  separate corpus, explicitly out of scope here.

### 11.1 Corpus decision (wave-1 B2 addendum, 2026-09-23)

Recorded per the opus-5.5 module B fix plan (step 2), binding all future
renderer qualification runs:

- **The frozen revision-2 corpus stays the renderer input on every platform
  and is never overwritten.** The five producer-pinned recipes and their
  digests (§3) are the comparison inputs everywhere; a Linux capture never
  replaces or rewrites them.
- **Linux LibreOffice captures go into NEW rows marked with their platform**
  (`platform: linux/amd64`) — manifest **revision 3, schema version bump** —
  under a separate engine pin carrying the exact Linux engine version string
  (LibreOffice 26.8.0.3.x as installed on the qualification host). Platform
  marking is what makes the second platform representable next to the frozen
  darwin/arm64 rows (catalog keying ships in wave-1 B1).
- **The TDF Linux build is pinned as the font source, with its digest** —
  font-pack rows for linux/amd64 cite the TDF build artifact and its sha-256;
  an unpinned font source cannot pass re-qualification.
- The linux-ci-host re-qualification above consumes this decision: acquire →
  capture into rev-3 platform rows → measure → pin linux/amd64 renderer+font
  beside the darwin/arm64 pins.

## 12. Verification receipts (this run)

- `bash scripts/gen-meet-m0-corpus.sh verify` → OK (15 frozen entries verified)
- `go test ./internal/meet/presentation/ -count=1` (mailserver module) → ok
  (includes TestM0CorpusFrozenManifestVerifies, fabrication guard, drift
  guards, measurer fail-closed arms)
- `go test ./internal/deploycatalog ./cmd/unit-catalog-gen -count=1` → ok
- `bash scripts/check-deploy-unit-catalog.sh --self-test` → PASS (8 units;
  projection; lifecycle; mutant self-test)
