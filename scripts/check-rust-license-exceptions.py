#!/usr/bin/env python3
"""Require a written reason for every cargo-deny license exception and advisory ignore."""
import pathlib
import sys
import tomllib

root = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else pathlib.Path(__file__).resolve().parents[1] / "server-rust")
try:
    with (root / "deny.toml").open("rb") as policy_file:
        policy = tomllib.load(policy_file)
    exceptions = policy.get("licenses", {}).get("exceptions", [])
    ignores = policy.get("advisories", {}).get("ignore", [])
    with (root / "license-exception-reasons.toml").open("rb") as reasons_file:
        reasons = tomllib.load(reasons_file)["reasons"]
    errors = []
    for exception in exceptions:
        spec = exception.get("crate")
        if not spec and exception.get("name"):
            spec = exception["name"]
            if exception.get("version"):
                spec += ":" + exception["version"]
        if not isinstance(spec, str) or not spec.strip():
            errors.append("exception without a crate spec")
        elif not isinstance(reasons.get(spec), str) or not reasons[spec].strip():
            errors.append(f"{spec}: missing written reason")
    # An advisory ignore is `{ id = "RUSTSEC-…", reason = "…" }`; a bare ID has no reason.
    for ignore in ignores:
        if not isinstance(ignore, dict) or not str(ignore.get("id") or ignore.get("crate") or "").strip():
            errors.append(f"advisory ignore {ignore!r}: needs an id and a written reason")
        elif not isinstance(ignore.get("reason"), str) or not ignore["reason"].strip():
            errors.append(f"advisory ignore {ignore.get('id') or ignore.get('crate')}: missing written reason")
    if errors:
        print("license exceptions: " + "; ".join(errors), file=sys.stderr)
        sys.exit(1)
    print("license exception reasons: ok")
except (OSError, ValueError, KeyError, TypeError, AttributeError) as exc:
    print(f"license exception check failed: {exc}", file=sys.stderr)
    sys.exit(1)
