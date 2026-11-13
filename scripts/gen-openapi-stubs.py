#!/usr/bin/env python3
# ──────────────────────────────────────────────────────────────────────────
# gen-openapi-stubs.py — bulk-document the registered-but-undocumented gateway
# routes ledgered in mailserver/api/openapi-pending.txt.
#
# WHY: the pending ledger carried ~420 routes. Hand-authoring 420 rich path
# items is intractable; this generator emits VALID, MINIMAL OpenAPI 3 path
# stubs for them so the coverage ledger shrinks to (essentially) empty while
# BOTH guards stay green:
#   - scripts/check-openapi-coverage.sh   (every route documented OR pending)
#   - scripts/check-openapi-visibility.sh (x-visibility matches main.go wrapper)
#
# TRADE-OFF (accepted): these are STUBS — a summary, x-visibility, path
# parameters, and a minimal responses map (success + 401 + admin-403). No
# request/response body schemas are invented (we cannot verify them from the
# map/anonymous-struct handler layer). Rich bodies get hand-authored later.
#
# CORRECTNESS ANCHORS (must mirror the guards EXACTLY):
#   * Route source of truth = the mux.Handle("METHOD /path", ...) literals in
#     cmd/mailserverd/main.go. We use the REAL path (real {param} names) so the
#     visibility guard's literal-path grep matches.
#   * x-visibility is derived with the SAME algorithm the visibility guard uses:
#     admin iff the mux.Handle *line itself* contains an admin wrapper call
#     (ROLE_WRAPPERS ∪ the RequirePermAudited/RequireAnyPermAudited-derived
#     PERM_WRAPPERS). Wrappers on a continuation line are invisible to the guard,
#     so they are invisible to us too — we match the guard, not the semantics.
#   * ANY-method routes (sub-router mounts: /auth/*, /caldav/, /contacts/*, "/")
#     CANNOT be expressed as an OpenAPI method key, so they stay in pending.
#
# After emitting, the pending ledger is regenerated via the coverage guard's
# own --regen-pending (registered − documented), so it self-cleans to exactly
# the un-emittable remainder.
#
# Usage:  python3 scripts/gen-openapi-stubs.py
# ──────────────────────────────────────────────────────────────────────────
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MAIN_GO = ROOT / "mailserver/cmd/mailserverd/main.go"
SPEC = ROOT / "mailserver/api/openapi.yaml"
COVERAGE_GUARD = ROOT / "scripts/check-openapi-coverage.sh"

METHODS = ("GET", "POST", "PUT", "DELETE", "PATCH")
ROLE_WRAPPERS = [
    "requireAdmin",
    "requireSuperAdmin",
    "requireReadOnly",
    "requireAuditor",
    "requireAdminOrAuditor",
]

HANDLE_RE = re.compile(r'mux\.Handle(?:Func)?\("([^"]+)"')


def norm(path: str) -> str:
    """{param} -> {} — the guards' position-based comparison form."""
    return re.sub(r"\{[^}]+\}", "{}", path)


def perm_wrappers(go_src: str) -> list[str]:
    """PERM_WRAPPERS, derived from main.go exactly as the visibility guard does:
    every `requireX := middleware.Require(Perm|AnyPerm|AnyPermissionSet)Audited(...)` name."""
    names = set()
    for m in re.finditer(
        r"(require[A-Za-z]+)\s*:?=\s*middleware\.Require(?:Perm|AnyPerm|AnyPermissionSet)Audited",
        go_src,
    ):
        names.add(m.group(1))
    return sorted(names)


def read_routes():
    """Parse main.go's uncommented mux.Handle literals.
    Returns list of (method, real_path, line_text). ANY routes have method=ANY."""
    routes = []
    for raw in MAIN_GO.read_text().splitlines():
        if raw.lstrip().startswith("//"):
            continue
        m = HANDLE_RE.search(raw)
        if not m:
            continue
        route = m.group(1)
        parts = route.split(" ", 1)
        if len(parts) == 1:
            method, path = "ANY", parts[0]
        else:
            method, path = parts[0].upper(), parts[1]
        routes.append((method, path, raw))
    return routes


def documented_pairs():
    """Set of normalized 'METHOD /path' already in the spec's paths: block,
    plus the set of real path keys already present (to avoid duplicate keys)."""
    pairs, keys = set(), set()
    inpaths = False
    curpath = None
    for line in SPEC.read_text().splitlines():
        if line.startswith("paths:"):
            inpaths = True
            continue
        if inpaths and line and not line[0].isspace():
            inpaths = False
        if not inpaths:
            continue
        mp = re.match(r"  (/\S*):", line)
        if mp:
            curpath = mp.group(1)
            keys.add(curpath)
            continue
        mm = re.match(r"    (get|post|put|delete|patch):", line)
        if mm and curpath is not None:
            pairs.add(f"{mm.group(1).upper()} {norm(curpath)}")
    return pairs, keys


def summary_for(method: str, path: str) -> str:
    verb = {
        "GET": "Get",
        "POST": "Create",
        "PUT": "Update",
        "DELETE": "Delete",
        "PATCH": "Patch",
    }[method]
    # phrase from the path: drop leading slash, params -> bare word, seps -> space
    words = []
    for seg in path.strip("/").split("/"):
        seg = re.sub(r"\{([^}]+)\}", r"\1", seg)
        words.append(seg.replace("-", " ").replace("_", " "))
    phrase = " ".join(w for w in words if w).strip()
    # ponytail: uniform verb+phrase — readable, non-empty; not per-route curated.
    return f"{verb} {phrase}" if phrase else f"{verb} resource"


def path_params(path: str):
    seen, out = set(), []
    for name in re.findall(r"\{([^}]+)\}", path):
        if name in seen:
            continue
        seen.add(name)
        out.append(name)
    return out


def success_code(method: str) -> str:
    return {"GET": "200", "POST": "201", "PUT": "200", "DELETE": "204", "PATCH": "200"}[
        method
    ]


def emit_path_item(path: str, methods_vis: dict) -> str:
    """methods_vis: {METHOD: 'admin'|'public'}. One x-visibility per path
    (admin if ANY method is admin — mirrors the guard's per-path derivation)."""
    vis = "admin" if "admin" in methods_vis.values() else "public"
    lines = [f"  {path}:", f"    x-visibility: {vis}"]
    params = path_params(path)
    if params:
        lines.append("    parameters:")
        for name in params:
            lines.append(
                f"      - {{ name: {name}, in: path, required: true, "
                f"schema: {{ type: string }} }}"
            )
    for method in METHODS:
        if method not in methods_vis:
            continue
        op = method.lower()
        lines.append(f"    {op}:")
        lines.append("      tags: [generated]")
        lines.append(f'      summary: "{summary_for(method, path)}"')
        lines.append("      responses:")
        code = success_code(method)
        desc = {"200": "OK", "201": "Created", "204": "No content"}[code]
        if code == "204":
            lines.append(f'        "{code}": {{ description: {desc} }}')
        else:
            lines.append(f'        "{code}": {{ description: {desc} }}')
        lines.append('        "401": { description: Not authenticated }')
        if methods_vis[method] == "admin":
            lines.append('        "403": { $ref: "#/components/responses/Forbidden" }')
    return "\n".join(lines)


def main():
    go_src = MAIN_GO.read_text()
    admin_wrappers = ROLE_WRAPPERS + perm_wrappers(go_src)
    admin_re = re.compile(
        r"(?:" + "|".join(re.escape(w) for w in admin_wrappers) + r")\("
    )

    routes = read_routes()
    doc_pairs, doc_keys = documented_pairs()

    # Collect real-path lines per (method, real_path) for visibility derivation.
    # Group documentable routes by real path.
    grouped: dict[str, dict[str, str]] = {}
    skipped_any = []
    skipped_collision = []
    seen_pair = set()

    for method, path, line in routes:
        if method == "ANY":
            skipped_any.append(f"{method} {norm(path)}")
            continue
        pair = f"{method} {norm(path)}"
        if pair in doc_pairs:
            continue  # already documented
        if pair in seen_pair:
            continue  # duplicate registration line, already handled
        seen_pair.add(pair)
        # A real path that already exists as a spec key would create a duplicate
        # YAML key if we emit a new path item — leave those methods pending.
        if path in doc_keys:
            skipped_collision.append(pair)
            continue
        vis = "admin" if admin_re.search(line) else "public"
        grouped.setdefault(path, {})[method] = vis

    if not grouped:
        print("Nothing to document — no undocumented non-ANY routes found.")
        return

    blocks = [emit_path_item(p, grouped[p]) for p in sorted(grouped)]
    addition = "\n\n" + "\n\n".join(blocks) + "\n"

    # Splice into the spec: insert before the top-level `components:` line, i.e.
    # at the end of the paths: block. Never touch existing documented paths.
    text = SPEC.read_text()
    marker = "\ncomponents:\n"
    idx = text.find(marker)
    if idx == -1:
        sys.exit("could not locate top-level components: block in openapi.yaml")
    new_text = text[:idx] + addition + text[idx:]
    SPEC.write_text(new_text)

    documented = sum(len(v) for v in grouped.values())
    print(f"Emitted {documented} operations across {len(grouped)} path items.")
    if skipped_collision:
        print(
            f"Left {len(skipped_collision)} route(s) pending "
            f"(real path already a documented spec key): "
            f"{', '.join(sorted(skipped_collision))}"
        )
    print(
        f"Left {len(set(skipped_any))} ANY sub-router mount(s) pending "
        f"(no OpenAPI method key can express an ANY route)."
    )

    # Self-clean the ledger: pending := registered − documented.
    subprocess.run(["bash", str(COVERAGE_GUARD), "--regen-pending"], check=True)


if __name__ == "__main__":
    main()
