#!/usr/bin/env python3
"""Generate deterministic, physically separate Noto Sans SC fallback shards.

Run with the pinned toolchain (runtime deployments do not need Python):

  uv run --isolated --with fonttools==4.63.0 --with brotli==1.2.0 \
    python scripts/generate-cjk-font-shards.py

The source WOFF2 files live outside ``static`` so the adapter cannot deploy the
monoliths. Product-Chinese glyphs form a small core shard; all remaining CJK
glyphs are partitioned by sorted codepoint into bounded, non-overlapping shards.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import sys
import tempfile
from pathlib import Path

import brotli
import fontTools
from fontTools import subset
from fontTools.ttLib import TTFont

ROOT = Path(__file__).resolve().parents[1]
SOURCE_DIR = ROOT / "assets" / "fonts" / "source"
PIN_PATH = SOURCE_DIR / "sha256sums"
PIN_NOTICE = SOURCE_DIR / "NOTICE.md"
OUTPUT_DIR = ROOT / "static" / "fonts"
CSS_PATH = ROOT / "src" / "lib" / "theme" / "fonts-cjk.generated.css"
MANIFEST_PATH = OUTPUT_DIR / "noto-sans-sc-shards.json"
ZH_CATALOG = ROOT / "src" / "lib" / "i18n" / "zh.ts"
WEIGHTS = (400, 500, 600, 700)
REMAINDER_SHARDS = 8

# CJK punctuation, radicals, Kana/Bopomofo, unified ideographs, compatibility
# forms, full-width forms, and the supported supplementary ideograph planes.
CJK_RANGES = (
    (0x2000, 0x206F),
    (0x2E80, 0x33FF),
    (0x3400, 0x4DBF),
    (0x4E00, 0x9FFF),
    (0xF900, 0xFAFF),
    (0xFE10, 0xFE1F),
    (0xFE30, 0xFE4F),
    (0xFF00, 0xFFEF),
    (0x20000, 0x2FA1F),
    (0x30000, 0x3134F),
)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def in_cjk_scope(codepoint: int) -> bool:
    return any(start <= codepoint <= end for start, end in CJK_RANGES)


def unicode_ranges(codepoints: set[int]) -> list[str]:
    ordered = sorted(codepoints)
    if not ordered:
        return []
    ranges: list[str] = []
    start = previous = ordered[0]
    for codepoint in ordered[1:]:
        if codepoint == previous + 1:
            previous = codepoint
            continue
        ranges.append(
            f"U+{start:X}" if start == previous else f"U+{start:X}-{previous:X}"
        )
        start = previous = codepoint
    ranges.append(f"U+{start:X}" if start == previous else f"U+{start:X}-{previous:X}")
    return ranges


def cmap(font: TTFont) -> set[int]:
    return set().union(
        *(table.cmap.keys() for table in font["cmap"].tables if table.isUnicode())
    )


def partition(codepoints: set[int], count: int) -> list[set[int]]:
    ordered = sorted(codepoints)
    if not ordered:
        return []
    size = (len(ordered) + count - 1) // count
    return [
        set(ordered[offset : offset + size]) for offset in range(0, len(ordered), size)
    ]


def write_subset(source: Path, destination: Path, codepoints: set[int]) -> set[int]:
    font = TTFont(source, recalcTimestamp=False)
    options = subset.Options()
    options.flavor = "woff2"
    options.layout_features = ["*"]
    options.name_IDs = ["*"]
    options.name_legacy = True
    options.name_languages = ["*"]
    options.recalc_timestamp = False
    options.canonical_order = True
    options.notdef_glyph = True
    options.notdef_outline = True
    options.recommended_glyphs = True
    subsetter = subset.Subsetter(options=options)
    subsetter.populate(unicodes=codepoints)
    subsetter.subset(font)
    font.flavor = "woff2"
    destination.parent.mkdir(parents=True, exist_ok=True)
    font.save(destination, reorderTables=False)
    rendered = TTFont(destination, recalcTimestamp=False)
    actual = cmap(rendered) & set(codepoints)
    if actual != codepoints:
        missing = sorted(codepoints - actual)[:8]
        extra = sorted(actual - codepoints)[:8]
        raise RuntimeError(
            f"subset cmap mismatch for {destination.name}: missing={missing} extra={extra}"
        )
    return actual


def verify_source_pins() -> None:
    """Fail closed when a vendored source no longer matches its provenance pin.

    The committed WOFF2 files are trust-on-first-commit binaries: sha256sums
    (see NOTICE.md beside it) is the pin of record, so a swapped or re-encoded
    source must fail the build instead of silently re-sharding an unreviewed
    font into static/.
    """
    if not PIN_PATH.is_file():
        raise RuntimeError(f"missing font provenance pin: {PIN_PATH}")
    if not PIN_NOTICE.is_file():
        raise RuntimeError(f"missing font provenance notice: {PIN_NOTICE}")
    pinned: dict[str, str] = {}
    for line in PIN_PATH.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        digest, _, name = line.partition("  ")
        if len(digest) != 64 or not name:
            raise RuntimeError(f"malformed pin line in {PIN_PATH}: {line!r}")
        pinned[name] = digest
    on_disk = {path.name for path in SOURCE_DIR.glob("*.woff2")}
    for name in sorted(on_disk - set(pinned)):
        raise RuntimeError(
            f"unpinned font source {name} — vendor it and extend {PIN_PATH.name} "
            "(see NOTICE.md) before generating shards"
        )
    for name, want in sorted(pinned.items()):
        path = SOURCE_DIR / name
        if not path.is_file():
            raise RuntimeError(f"pinned font source {name} is missing from {SOURCE_DIR}")
        got = sha256(path)
        if got != want:
            raise RuntimeError(
                f"font source {name} does not match its provenance pin "
                f"(on disk {got}, pinned {want}) — re-vendoring requires updating "
                f"{PIN_PATH.name} and {PIN_NOTICE.name} with review justification"
            )


def main() -> int:
    verify_source_pins()
    product_cjk = {
        ord(char)
        for char in ZH_CATALOG.read_text(encoding="utf-8")
        if in_cjk_scope(ord(char))
    }
    if not product_cjk:
        raise RuntimeError("Chinese catalog produced no CJK codepoints")

    manifest: dict[str, object] = {
        "version": 1,
        "family": "Setjoin Noto SC Fallback",
        "license": {
            "spdx": "OFL-1.1",
            "copyright": "(c) 2014-2021 Adobe, with Reserved Font Name 'Source'",
            "url": "https://scripts.sil.org/OFL",
        },
        "generator": {"fonttools": fontTools.__version__, "brotli": brotli.__version__},
        "catalog": "src/lib/i18n/zh.ts",
        "remainder_shards": REMAINDER_SHARDS,
        "weights": {},
    }
    css_lines = [
        "/* Generated by scripts/generate-cjk-font-shards.py; do not edit. */",
        "/* Physical unicode-range shards keep the monolithic source out of static/. */",
    ]

    with tempfile.TemporaryDirectory(prefix="setjoin-cjk-shards-") as temp:
        temp_dir = Path(temp)
        expected_outputs: set[str] = set()
        for weight in WEIGHTS:
            source = SOURCE_DIR / f"noto-sans-sc-{weight}.woff2"
            if not source.is_file():
                raise RuntimeError(f"missing pinned source: {source}")
            source_font = TTFont(source, recalcTimestamp=False)
            available = {
                codepoint for codepoint in cmap(source_font) if in_cjk_scope(codepoint)
            }
            core = product_cjk & available
            groups = [
                ("core", core),
                *[
                    (f"r{index:02d}", group)
                    for index, group in enumerate(
                        partition(available - core, REMAINDER_SHARDS), 1
                    )
                ],
            ]
            covered: set[int] = set()
            weight_records: list[dict[str, object]] = []
            for name, codepoints in groups:
                if not codepoints:
                    continue
                if covered & codepoints:
                    raise RuntimeError(
                        f"overlapping shard input for weight {weight}: {name}"
                    )
                filename = f"noto-sans-sc-{weight}-{name}.woff2"
                destination = temp_dir / filename
                actual = write_subset(source, destination, codepoints)
                covered.update(actual)
                declared = unicode_ranges(actual)
                weight_records.append(
                    {
                        "name": name,
                        "file": f"/fonts/{filename}",
                        "bytes": destination.stat().st_size,
                        "sha256": sha256(destination),
                        "glyph_codepoints": len(actual),
                        "unicode_ranges": declared,
                    }
                )
                expected_outputs.add(filename)
                css_lines.extend(
                    [
                        "",
                        "@font-face {",
                        "  font-family: 'Setjoin Noto SC Fallback';",
                        "  font-style: normal;",
                        f"  font-weight: {weight};",
                        "  font-display: swap;",
                        f"  src: url('/fonts/{filename}') format('woff2');",
                        f"  unicode-range: {', '.join(declared)};",
                        "}",
                    ]
                )
            if covered != available:
                raise RuntimeError(f"incomplete CJK coverage for weight {weight}")
            manifest["weights"][str(weight)] = {
                "source": f"assets/fonts/source/{source.name}",
                "source_bytes": source.stat().st_size,
                "source_sha256": sha256(source),
                "covered_codepoints": len(covered),
                "product_codepoints": len(core),
                "shards": weight_records,
            }

        for old in OUTPUT_DIR.glob("noto-sans-sc-*.woff2"):
            old.unlink()
        for filename in sorted(expected_outputs):
            shutil.copyfile(temp_dir / filename, OUTPUT_DIR / filename)

    manifest_bytes = (
        json.dumps(manifest, indent=2, sort_keys=True, ensure_ascii=True) + "\n"
    ).encode("utf-8")
    MANIFEST_PATH.write_bytes(manifest_bytes)
    CSS_PATH.write_text("\n".join(css_lines) + "\n", encoding="utf-8", newline="\n")
    print(
        f"generated {len(expected_outputs)} physical CJK shards ({sum((OUTPUT_DIR / name).stat().st_size for name in expected_outputs)} bytes)"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(
            f"E_CJK_SHARDS problem=generation-failed cause={exc!s} fix='verify pinned sources and tool versions'",
            file=sys.stderr,
        )
        raise
