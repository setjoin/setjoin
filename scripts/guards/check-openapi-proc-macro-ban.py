#!/usr/bin/env python3
"""Fail if OpenAPI proc-macro crates or attributes enter domain, contract, or pg crates.

Enforces the #561 edge-only plain-serde DTO architecture:
  - Scans `server-rust/crates/domains/*`, `server-rust/crates/contracts/*`, and
    `server-rust/crates/pg/*` (`Cargo.toml` and `*.rs`).
  - Fails if any banned crate name or derive/attribute symbol appears outside
    comments.
"""

from __future__ import annotations

import argparse
import pathlib
import re
import sys

BANNED_CRATES = (
    "utoipa",
    "aide",
    "poem-openapi",
    "poem_openapi",
    "okapi",
    "paperclip",
    "dropshot",
    "schemars",
)

BANNED_RS_TOKENS = (
    "utoipa",
    "aide",
    "poem_openapi",
    "okapi",
    "paperclip",
    "dropshot",
    "schemars",
    "ToSchema",
    "IntoParams",
    "OperationIo",
)

TOML_PATTERN = re.compile(
    r"(?<![A-Za-z0-9_-])("
    + "|".join(re.escape(c) for c in BANNED_CRATES)
    + r")(?![A-Za-z0-9_-])"
)

RS_PATTERN = re.compile(
    r"(?<![A-Za-z0-9_])("
    + "|".join(re.escape(t) for t in BANNED_RS_TOKENS)
    + r")(?![A-Za-z0-9_])"
)


def strip_rust_comments_preserve_lines(text: str) -> str:
    """Strip /* ... */ and // ... comments while preserving line numbers."""
    # Replace block comments with equivalent newlines so line numbers stay exact.
    def _block_repl(match: re.Match[str]) -> str:
        return "\n" * match.group(0).count("\n")

    without_blocks = re.sub(r"/\*.*?\*/", _block_repl, text, flags=re.DOTALL)
    # Strip line comments without touching string literals containing `//`?
    # Conservative line-by-line stripping: ignore `//` inside double-quoted strings.
    out_lines: list[str] = []
    for line in without_blocks.splitlines():
        in_str = False
        escaped = False
        cut = len(line)
        i = 0
        while i < len(line):
            ch = line[i]
            if in_str:
                if escaped:
                    escaped = False
                elif ch == "\\":
                    escaped = True
                elif ch == '"':
                    in_str = False
            else:
                if ch == '"':
                    in_str = True
                elif ch == "/" and i + 1 < len(line) and line[i + 1] == "/":
                    cut = i
                    break
            i += 1
        out_lines.append(line[:cut])
    return "\n".join(out_lines)


def strip_toml_comments_preserve_lines(text: str) -> str:
    out_lines: list[str] = []
    for line in text.splitlines():
        in_str = False
        quote = ""
        escaped = False
        cut = len(line)
        for i, ch in enumerate(line):
            if in_str:
                if escaped:
                    escaped = False
                elif ch == "\\" and quote == '"':
                    escaped = True
                elif ch == quote:
                    in_str = False
            else:
                if ch in ('"', "'"):
                    in_str = True
                    quote = ch
                elif ch == "#":
                    cut = i
                    break
        out_lines.append(line[:cut])
    return "\n".join(out_lines)


def collect_target_dirs(server_rust_root: pathlib.Path) -> list[pathlib.Path]:
    targets: list[pathlib.Path] = []
    domains = server_rust_root / "crates" / "domains"
    if domains.is_dir():
        for child in sorted(domains.iterdir()):
            if child.is_dir():
                targets.append(child)
    for single in ("contracts", "pg", "edge-contract"):
        path = server_rust_root / "crates" / single
        if path.is_dir():
            targets.append(path)
    return targets


def scan_root(server_rust_root: pathlib.Path) -> tuple[int, list[str]]:
    violations: list[str] = []
    files_scanned = 0
    for crate_dir in collect_target_dirs(server_rust_root):
        for path in sorted(crate_dir.rglob("*")):
            if not path.is_file():
                continue
            rel = path.relative_to(server_rust_root).as_posix()
            if "/target/" in f"/{rel}":
                continue
            if path.name == "Cargo.toml":
                files_scanned += 1
                raw = path.read_text(encoding="utf-8", errors="ignore")
                cleaned = strip_toml_comments_preserve_lines(raw)
                for lineno, line in enumerate(cleaned.splitlines(), start=1):
                    match = TOML_PATTERN.search(line)
                    if match:
                        violations.append(
                            f"{rel}:{lineno}: banned OpenAPI proc-macro crate `{match.group(1)}`"
                        )
            elif path.suffix == ".rs":
                files_scanned += 1
                raw = path.read_text(encoding="utf-8", errors="ignore")
                cleaned = strip_rust_comments_preserve_lines(raw)
                for lineno, line in enumerate(cleaned.splitlines(), start=1):
                    match = RS_PATTERN.search(line)
                    if match:
                        violations.append(
                            f"{rel}:{lineno}: banned OpenAPI proc-macro symbol `{match.group(1)}`"
                        )
    return files_scanned, violations


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root",
        type=pathlib.Path,
        default=pathlib.Path(__file__).resolve().parents[2] / "server-rust",
        help="Path to server-rust workspace root",
    )
    args = parser.parse_args()
    root = args.root.resolve()
    if not root.is_dir():
        print(f"OPENAPI-PROC-MACRO-BAN-FAIL: root directory not found: {root}", file=sys.stderr)
        return 2

    files_scanned, violations = scan_root(root)
    if violations:
        print(
            "OPENAPI-PROC-MACRO-BAN-FAIL: OpenAPI proc-macro crates/attributes are forbidden "
            "outside the edge-contract pipeline (see #561):",
            file=sys.stderr,
        )
        for item in violations:
            print(f"  - {item}", file=sys.stderr)
        return 1

    print(
        f"openapi-proc-macro-ban: clean ({files_scanned} files scanned across domains/contracts/pg/edge-contract)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
