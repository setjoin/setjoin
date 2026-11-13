#!/usr/bin/env python3
"""Check ELF dynamic version requirements against a glibc deployment floor."""

import argparse
import itertools
import re
import subprocess
import sys
from pathlib import Path


def version(value):
    if not re.fullmatch(r"[0-9]+(?:\.[0-9]+)+", value):
        raise ValueError(f"invalid version: {value}")
    return tuple(map(int, value.split(".")))


def newer(required, floor):
    for a, b in itertools.zip_longest(required, floor, fillvalue=0):
        if a != b:
            return a > b
    return False


def check(binary, floor, floor_text):
    result = subprocess.run(
        ["readelf", "--wide", "--version-info", str(binary)],
        universal_newlines=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if result.returncode:
        raise ValueError(f"{binary}: readelf failed: {result.stderr.strip()}")
    needs = result.stdout.split("Version needs section", 1)
    if len(needs) != 2:
        raise ValueError(f"{binary}: no ELF version needs section")
    requirements = re.findall(r"\bName:\s+(GLIBC_\S+)", needs[1])
    if not requirements:
        raise ValueError(f"{binary}: no versioned glibc requirements")
    for requirement in sorted(set(requirements)):
        suffix = requirement[len("GLIBC_"):]
        # GNU ld emits this ABI marker when DT_RELR is used (glibc 2.36).
        if suffix == "ABI_DT_RELR":
            required = (2, 36)
        else:
            try:
                required = version(suffix)
            except ValueError as exc:
                raise ValueError(f"{binary}: unknown glibc requirement {requirement}") from exc
        if newer(required, floor):
            raise ValueError(f"{binary}: {requirement} exceeds floor GLIBC_{floor_text}")
    print(f"{binary}: glibc requirements within {floor_text}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--floor", required=True, help="maximum glibc version, e.g. 2.28")
    parser.add_argument("binaries", nargs="+", type=Path)
    args = parser.parse_args()
    try:
        floor = version(args.floor)
        for binary in args.binaries:
            check(binary, floor, args.floor)
    except (ValueError, OSError) as exc:
        print(exc, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
