#!/usr/bin/env python3
"""Monotonic CI coverage ratchet for Setjoin HTTP EdgeContract (#561).

Reads `server-rust/bins/gateway/route-inventory.json`, filters to contractable
non-JMAP / non-DAV / non-internal / non-SPA-catchall HTTP routes, and enforces:
  1. No new contractable route may be added without an OpenAPI 3.1 entry in
     `contracts/edge/openapi/edge.v1.yaml` (legacy uncovered set is a hard ceiling).
  2. Covered route count may never regress below `covered_routes_floor`.
  3. Every contracted route called anywhere in webmail (`mailserver/webmail/src/lib/`
     and `mailserver/webmail/src/routes/`, `.ts` and `.svelte`) must bind via an
     actual `openapi-fetch` edge client (`edgeClient` / `createEdgeClient(...)`),
     not raw `fetch`/`httpRequest`/`typedFetch`, and the webmail-bound count may
     never regress below `webmail_bound_routes_floor`.
  4. All contracted OpenAPI operations are transparently accounted for as either
     inventory-backed covered routes or explicit gateway-level liveness routes
     (`GET /healthz`, `GET /_gateway/healthz`).
  5. When `--diff-base <git-ref>` is provided, fails closed on invalid refs,
     rejects any added/modified contractable route lacking an EdgeContract entry,
     and rejects any regression in `config/edge-contract-ratchet.json` itself
     (lowered floor or expanded legacy ceiling).
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import pathlib
import re
import subprocess
import sys
from typing import Any

EXCLUDED_LISTENERS = frozenset({"control", "asrbot", "fedharness", "acme"})
EXCLUDED_PROTOCOL_PREFIXES = ("/jmap", "/dav", "/caldav", "/carddav", "/.well-known")
GATEWAY_LIVENESS_OPERATIONS = frozenset({"GET /healthz", "GET /_gateway/healthz"})
HTTP_METHODS = ("get", "post", "put", "delete", "patch", "head", "options")

EDGE_CLIENT_IMPORT_RE = re.compile(
    r"import\s*\{[^}]*\b(edgeClient|createEdgeClient)\b[^}]*\}\s*from\s*['\"]\$lib/edge/client['\"]"
)
CREATE_EDGE_CLIENT_DECL_RE = re.compile(
    r"\b(?:const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*createEdgeClient\s*\("
)
LEGACY_FETCH_CALL_RE = re.compile(
    r"\b(?:fetch|httpRequest|typedFetch)\s*(?:<[^>]*>)?\s*\(\s*[`'\"](/[^`'\"\s]+)[`'\"]"
)


def load_yaml_via_breaking(root: pathlib.Path, spec_path: pathlib.Path) -> dict[str, Any]:
    helper = root / "scripts" / "check-edge-contract-breaking.py"
    spec = importlib.util.spec_from_file_location("edge_breaking_helper", str(helper))
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Failed to load OpenAPI parser helper: {helper}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.load_openapi(spec_path)


def normalize_path(path: str) -> str:
    p = path.strip()
    if p == "/api":
        return "/"
    if p.startswith("/api/"):
        p = p[4:]
    # Replace JS template interpolations `${...}` BEFORE OpenAPI `{...}` so
    # `/api/messages/${id}/trace` normalizes cleanly to `/messages/{}/trace`.
    p = re.sub(r"\$\{[^}]+\}", "{}", p)
    p = re.sub(r"\{[^}]+\}", "{}", p)
    return p


def is_contractable_route(entry: dict[str, Any]) -> bool:
    listener = str(entry.get("listener", ""))
    path = str(entry.get("path", ""))
    method = str(entry.get("method", "")).upper()
    if listener in EXCLUDED_LISTENERS:
        return False
    norm = normalize_path(path)
    # Exclude SPA static catch-all root mounts (`/` or `/api/`).
    if norm == "/" and method in ("*", "ANY", "GET"):
        return False
    # Exact segment-boundary exclusion for JMAP, DAV, and well-known protocol endpoints.
    for prefix in EXCLUDED_PROTOCOL_PREFIXES:
        if path == prefix or path.startswith(prefix + "/"):
            return False
    return True


def canonical_route_key(entry: dict[str, Any]) -> str:
    method = str(entry.get("method", "*")).upper()
    if method == "*":
        method = "ANY"
    return f"{method} {normalize_path(str(entry.get('path', '')))}"


def extract_contractable_inventory(
    inventory_data: dict[str, Any],
) -> dict[str, list[dict[str, Any]]]:
    routes: dict[str, list[dict[str, Any]]] = {}
    for entry in inventory_data.get("routes", []):
        if not isinstance(entry, dict) or not is_contractable_route(entry):
            continue
        key = canonical_route_key(entry)
        routes.setdefault(key, []).append(entry)
    return routes


def extract_openapi_operations(openapi_doc: dict[str, Any]) -> set[str]:
    ops: set[str] = set()
    paths = openapi_doc.get("paths") or {}
    if not isinstance(paths, dict):
        return ops
    for raw_path, item in paths.items():
        if not isinstance(item, dict):
            continue
        norm_path = normalize_path(str(raw_path))
        for method in HTTP_METHODS:
            if method in item:
                ops.add(f"{method.upper()} {norm_path}")
    return ops


def scan_webmail_bindings(
    webmail_src_dir: pathlib.Path, openapi_ops: set[str]
) -> tuple[set[str], list[str]]:
    """Scan webmail `src/lib` and `src/routes` (.ts/.svelte) for openapi-fetch bindings & raw fetch regressions."""
    bound: set[str] = set()
    legacy_regressions: list[str] = []
    if not webmail_src_dir.is_dir():
        return bound, legacy_regressions

    scan_roots = [webmail_src_dir / "lib", webmail_src_dir / "routes"]
    # Support legacy callers passing `src/lib` directly (e.g., selftests).
    if not any(d.is_dir() for d in scan_roots):
        scan_roots = [webmail_src_dir]

    for base in scan_roots:
        if not base.is_dir():
            continue
        for src_file in sorted(base.rglob("*")):
            if not src_file.is_file() or src_file.suffix not in (".ts", ".svelte"):
                continue
            rel = src_file.relative_to(webmail_src_dir).as_posix()
            if (
                rel.endswith(".test.ts")
                or rel.endswith(".spec.ts")
                or rel.endswith("edge/schema.d.ts")
                or rel.endswith("edge/client.ts")
            ):
                continue
            text = src_file.read_text(encoding="utf-8", errors="ignore")

            # Only count `.GET`/`.POST`/etc. calls made on verified `$lib/edge/client` instances.
            client_names: set[str] = set()
            if EDGE_CLIENT_IMPORT_RE.search(text):
                if re.search(r"\bedgeClient\b", text):
                    client_names.add("edgeClient")
                for decl in CREATE_EDGE_CLIENT_DECL_RE.finditer(text):
                    client_names.add(decl.group(1))
            if client_names:
                call_re = re.compile(
                    r"\b(?:"
                    + "|".join(re.escape(n) for n in sorted(client_names))
                    + r")\s*\.\s*(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s*\(\s*['\"](/[^'\"]+)['\"]"
                )
                for match in call_re.finditer(text):
                    method = match.group(1).upper()
                    norm_path = normalize_path(match.group(2))
                    key = f"{method} {norm_path}"
                    if key in openapi_ops:
                        bound.add(key)

            # Reject ANY raw fetch / httpRequest / typedFetch call targeting a contracted path.
            for match in LEGACY_FETCH_CALL_RE.finditer(text):
                raw_path = match.group(1)
                norm_path = normalize_path(raw_path)
                matching_ops = sorted(
                    op for op in openapi_ops if op.split(" ", 1)[1] == norm_path
                )
                if matching_ops:
                    legacy_regressions.append(
                        f"{rel}: raw fetch/httpRequest/typedFetch call to contracted path `{raw_path}` "
                        f"(expected openapi-fetch edge client for {', '.join(matching_ops)})"
                    )
    return bound, legacy_regressions


def verify_git_ref(repo_root: pathlib.Path, diff_base: str) -> None:
    try:
        subprocess.check_output(
            ["git", "-C", str(repo_root), "rev-parse", "--verify", f"{diff_base}^{{commit}}"],
            stderr=subprocess.DEVNULL,
            text=True,
        )
    except subprocess.CalledProcessError as exc:
        raise ValueError(f"cannot resolve --diff-base '{diff_base}' to a git commit") from exc


def git_show_optional(repo_root: pathlib.Path, diff_base: str, rel_path: str) -> str | None:
    check = subprocess.run(
        ["git", "-C", str(repo_root), "cat-file", "-e", f"{diff_base}:{rel_path}"],
        stderr=subprocess.DEVNULL,
    )
    if check.returncode != 0:
        return None
    return subprocess.check_output(
        ["git", "-C", str(repo_root), "show", f"{diff_base}:{rel_path}"],
        text=True,
    )


def diff_inventory_against_git(
    repo_root: pathlib.Path,
    inventory_rel: str,
    current_data: dict[str, Any],
    diff_base: str,
) -> set[str]:
    raw = git_show_optional(repo_root, diff_base, inventory_rel)
    if raw is None:
        return set()
    base_data = json.loads(raw)
    base_map = extract_contractable_inventory(base_data)
    curr_map = extract_contractable_inventory(current_data)

    touched: set[str] = set()
    for key, curr_entries in curr_map.items():
        if key not in base_map:
            touched.add(key)
        else:
            base_norm = json.dumps(base_map[key], sort_keys=True)
            curr_norm = json.dumps(curr_entries, sort_keys=True)
            if base_norm != curr_norm:
                touched.add(key)
    return touched


def main() -> int:
    repo_root = pathlib.Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--inventory",
        type=pathlib.Path,
        default=repo_root / "server-rust" / "bins" / "gateway" / "route-inventory.json",
    )
    parser.add_argument(
        "--openapi",
        type=pathlib.Path,
        default=repo_root / "contracts" / "edge" / "openapi" / "edge.v1.yaml",
    )
    parser.add_argument(
        "--webmail-src",
        "--webmail-lib",
        dest="webmail_src",
        type=pathlib.Path,
        default=repo_root / "mailserver" / "webmail" / "src",
    )
    parser.add_argument(
        "--ratchet",
        type=pathlib.Path,
        default=repo_root / "config" / "edge-contract-ratchet.json",
    )
    parser.add_argument(
        "--diff-base",
        type=str,
        default=None,
        help="Optional git ref; fails closed if invalid, and rejects modified uncovered routes or ratchet weakening.",
    )
    parser.add_argument(
        "--write-baseline",
        action="store_true",
        help="Write/update config/edge-contract-ratchet.json from current state.",
    )
    args = parser.parse_args()

    inventory_data = json.loads(args.inventory.read_text(encoding="utf-8"))
    contractable = extract_contractable_inventory(inventory_data)
    contractable_keys = set(contractable.keys())

    openapi_doc = load_yaml_via_breaking(repo_root, args.openapi)
    openapi_ops = extract_openapi_operations(openapi_doc)

    covered = sorted(contractable_keys & openapi_ops)
    gateway_liveness = sorted(GATEWAY_LIVENESS_OPERATIONS & openapi_ops)
    unaccounted_openapi = sorted(openapi_ops - contractable_keys - GATEWAY_LIVENESS_OPERATIONS)
    uncovered = sorted(contractable_keys - openapi_ops)
    webmail_bound, legacy_regressions = scan_webmail_bindings(args.webmail_src, openapi_ops)

    if args.write_baseline:
        if legacy_regressions:
            print(
                "EDGE-CONTRACT-RATCHET-FAIL: cannot write baseline with legacy webmail regressions:",
                file=sys.stderr,
            )
            for item in legacy_regressions:
                print(f"  - {item}", file=sys.stderr)
            return 1
        payload = {
            "version": 1,
            "policy": (
                "Monotonic EdgeContract coverage ratchet (#561): every new non-JMAP/non-DAV "
                "HTTP route must land with a TypeSpec/OpenAPI 3.1 contract (and openapi-fetch "
                "binding when called by webmail). covered_routes_floor may only rise and "
                "legacy_uncovered_routes may only shrink."
            ),
            "total_contractable_routes": len(contractable_keys),
            "covered_routes_floor": len(covered),
            "gateway_liveness_routes": gateway_liveness,
            "total_contracted_openapi_operations": len(openapi_ops),
            "webmail_bound_routes_floor": len(webmail_bound),
            "covered_routes": covered,
            "webmail_bound_routes": sorted(webmail_bound),
            "legacy_uncovered_routes": uncovered,
        }
        args.ratchet.parent.mkdir(parents=True, exist_ok=True)
        args.ratchet.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
        print(
            f"Wrote {args.ratchet}: {len(covered)}/{len(contractable_keys)} inventory covered "
            f"(+{len(gateway_liveness)} gateway liveness = {len(openapi_ops)} contracted ops), "
            f"{len(webmail_bound)} webmail-bound, {len(uncovered)} legacy uncovered"
        )
        return 0

    if not args.ratchet.exists():
        print(f"EDGE-CONTRACT-RATCHET-FAIL: missing ratchet file {args.ratchet}", file=sys.stderr)
        return 1

    ratchet = json.loads(args.ratchet.read_text(encoding="utf-8"))
    floor = int(ratchet.get("covered_routes_floor", 0))
    webmail_floor = int(ratchet.get("webmail_bound_routes_floor", 0))
    legacy_ceiling = set(ratchet.get("legacy_uncovered_routes") or [])
    previous_covered = set(ratchet.get("covered_routes") or [])
    previous_liveness = set(ratchet.get("gateway_liveness_routes") or [])

    errors: list[str] = []

    if len(covered) < floor:
        errors.append(f"covered contractable routes regressed: {len(covered)} < floor {floor}")
    for route in sorted((previous_covered & contractable_keys) - set(covered)):
        errors.append(f"previously covered route dropped out of EdgeContract: {route}")
    for route in sorted(previous_liveness - set(gateway_liveness)):
        errors.append(f"previously contracted gateway liveness route dropped: {route}")
    for route in unaccounted_openapi:
        errors.append(
            f"OpenAPI operation not present in route-inventory.json or gateway liveness allowlist: {route}"
        )

    for route in sorted(set(uncovered) - legacy_ceiling):
        errors.append(f"new non-JMAP/non-DAV route lacks OpenAPI 3.1 EdgeContract entry: {route}")

    if len(webmail_bound) < webmail_floor:
        errors.append(
            f"webmail openapi-fetch bound routes regressed: {len(webmail_bound)} < floor {webmail_floor}"
        )
    errors.extend(legacy_regressions)

    if args.diff_base:
        try:
            verify_git_ref(repo_root, args.diff_base)
        except ValueError as exc:
            print(f"EDGE-CONTRACT-RATCHET-FAIL: {exc}", file=sys.stderr)
            return 1

        try:
            inv_rel = args.inventory.resolve().relative_to(repo_root.resolve()).as_posix()
        except ValueError:
            inv_rel = "server-rust/bins/gateway/route-inventory.json"
        touched = diff_inventory_against_git(repo_root, inv_rel, inventory_data, args.diff_base)
        for route in sorted(touched - openapi_ops):
            errors.append(
                f"route added/modified since {args.diff_base} lacks EdgeContract entry: {route}"
            )

        # Enforce monotonic ratchet file evolution against diff-base when ratchet exists on base.
        try:
            ratchet_rel = args.ratchet.resolve().relative_to(repo_root.resolve()).as_posix()
        except ValueError:
            ratchet_rel = "config/edge-contract-ratchet.json"
        base_ratchet_raw = git_show_optional(repo_root, args.diff_base, ratchet_rel)
        if base_ratchet_raw is not None:
            base_ratchet = json.loads(base_ratchet_raw)
            base_floor = int(base_ratchet.get("covered_routes_floor", 0))
            base_webmail_floor = int(base_ratchet.get("webmail_bound_routes_floor", 0))
            base_legacy = set(base_ratchet.get("legacy_uncovered_routes") or [])
            if floor < base_floor:
                errors.append(
                    f"ratchet weakened vs {args.diff_base}: covered_routes_floor {floor} < {base_floor}"
                )
            if webmail_floor < base_webmail_floor:
                errors.append(
                    f"ratchet weakened vs {args.diff_base}: webmail_bound_routes_floor {webmail_floor} < {base_webmail_floor}"
                )
            added_legacy = sorted(legacy_ceiling - base_legacy)
            if added_legacy:
                errors.append(
                    f"ratchet weakened vs {args.diff_base}: legacy_uncovered_routes expanded by {added_legacy[:5]}"
                )

    if errors:
        print(f"EDGE-CONTRACT-RATCHET-FAIL: {len(errors)} ratchet violation(s):", file=sys.stderr)
        for err in errors:
            print(f"  - {err}", file=sys.stderr)
        return 1

    print(
        f"edge-contract-ratchet: PASS "
        f"(covered={len(covered)}/{len(contractable_keys)} [floor={floor}], "
        f"gateway_liveness={len(gateway_liveness)}, "
        f"webmail_bound={len(webmail_bound)} [floor={webmail_floor}], "
        f"legacy_uncovered={len(uncovered)}/{len(legacy_ceiling)})"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
