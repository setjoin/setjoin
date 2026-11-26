#!/usr/bin/env python3
"""Reject cross-family deps, non-workspace paths, and capability boundary leaks."""

from __future__ import annotations

import json
import pathlib
import re
import subprocess
import sys

try:
    import tomllib  # Python 3.11+
except ModuleNotFoundError:
    try:
        import tomli as tomllib  # type: ignore[no-redef]
    except ModuleNotFoundError:
        tomllib = None  # type: ignore[assignment]

# Authorized crates that may enable privileged `setjoin-pg` Cargo features.
MINT_FEATURE_ALLOWLIST = {
    "setjoin-authz",
    "setjoin-gateway",
    "setjoin-auth",
    "setjoind",
    "setjoin-pg",
}
WORKER_POOL_FEATURE_ALLOWLIST = {
    "setjoin-gateway",
    "setjoin-auth",
    "setjoind",
    "setjoin-pg",
    "setjoin-workqueue",
}
WORKQUEUE_WORKER_ALLOWLIST = {
    "setjoin-gateway",
    "setjoind",
    "setjoin-workqueue",
}
IN_PROCESS_AUTH_ALLOWLIST = {
    "setjoin-auth",
    "setjoind",
}
IN_PROCESS_BANNED_PATTERNS = [
    (
        "ClientProof::in_process",
        re.compile(r"\bClientProof\s*::\s*in_process\b"),
    ),
    ("in_process", re.compile(r"\bin_process\b")),
]

# Hard-banned symbols in all `crates/domains/*` Rust files (src/ and tests/).
HARD_BANNED_PATTERNS = [
    (
        "setjoin_pg::mint",
        re.compile(r"\bsetjoin_pg\s*::\s*(?:mint\b|\{[^}]*\bmint\b)"),
    ),
    (
        "capability::mint",
        re.compile(r"\bcapability\s*::\s*(?:mint\b|\{[^}]*\bmint\b)"),
    ),
    ("::mint", re.compile(r"::\s*(?:mint\b|\{[^}]*\bmint\b)")),
    ("AppPool", re.compile(r"\bAppPool\b")),
    ("AdminWorkerPool", re.compile(r"\bAdminWorkerPool\b")),
    ("PreAuthReadTx", re.compile(r"\bPreAuthReadTx\b")),
    ("begin_pre_auth_read", re.compile(r"\bbegin_pre_auth_read\b")),
    ("run_pre_auth_read_contract", re.compile(r"\brun_pre_auth_read_contract\b")),
    ("run_pre_auth_read_pipelined", re.compile(r"\brun_pre_auth_read_pipelined\b")),
    ("WorkerPool", re.compile(r"\bWorkerPool\b")),
    ("WorkerTx", re.compile(r"\bWorkerTx\b")),
    ("deadpool_postgres", re.compile(r"\bdeadpool_postgres\b")),
]

# Legacy pre-Wave-1.2 entrypoints frozen to a shrinking Wave 1.8 allowlist
# inside `crates/domains/*/src/**/*.rs`. Adding any new file/symbol fails CI.
LEGACY_PATTERNS = [
    ("WorkerDatabase", re.compile(r"\bWorkerDatabase\b")),
    (
        "ScopedExecutor::from_dsn",
        re.compile(r"\bScopedExecutor\s*::\s*from_dsn(?:_with)?\b"),
    ),
    ("ScopedExecutor::new", re.compile(r"\bScopedExecutor\s*::\s*new\b")),
    ("from_authenticated_session", re.compile(r"\bfrom_authenticated_session\b")),
    ("from_authenticated_user", re.compile(r"\bfrom_authenticated_user\b")),
]

WAVE_1_8_LEGACY_ALLOWLIST = {
    "crates/domains/approvals/src/email.rs": {"from_authenticated_session"},
    "crates/domains/calendar/src/carddav.rs": {"from_authenticated_session"},
    "crates/domains/calendar/src/dav.rs": {"from_authenticated_session"},
    "crates/domains/chat/src/workers.rs": {"WorkerDatabase"},
    "crates/domains/compliance/src/chat_export.rs": {"WorkerDatabase"},
    "crates/domains/compliance/src/search.rs": {"WorkerDatabase"},
    "crates/domains/directory-sync/src/ad/runtime.rs": {"WorkerDatabase"},
    "crates/domains/directory-sync/src/catalog.rs": {"WorkerDatabase"},
    "crates/domains/directory-sync/src/ldap/engine.rs": {"WorkerDatabase"},
    "crates/domains/directory-sync/src/ldap/normalized.rs": {"WorkerDatabase"},
    "crates/domains/directory-sync/src/ldap/runtime.rs": {"WorkerDatabase"},
    "crates/domains/drive/src/lib.rs": {"from_authenticated_session"},
    "crates/domains/identity/src/login.rs": {"ScopedExecutor::from_dsn"},
    "crates/domains/identity/src/self_service.rs": {"from_authenticated_session"},
    "crates/domains/identity/src/session.rs": {"ScopedExecutor::from_dsn"},
    "crates/domains/identity/src/totp.rs": {"ScopedExecutor::from_dsn"},
    "crates/domains/identity/src/webauthn.rs": {"ScopedExecutor::from_dsn"},
    "crates/domains/mail-security/src/dlp.rs": {"from_authenticated_session"},
    "crates/domains/office/src/lib.rs": {"from_authenticated_session"},
    "crates/domains/static/src/telemetry.rs": {"WorkerDatabase"},
}


def strip_rust_comments(text: str) -> str:
    """Strip /* ... */ and // ... comments while preserving line structure."""
    text = re.sub(r"/\*.*?\*/", " ", text, flags=re.DOTALL)
    return re.sub(r"//[^\n]*", "", text)


def scan_in_process_sources(root: pathlib.Path, errors: list[str]) -> None:
    targets = [root / "crates/domains", root / "bins/gateway"]
    for base in targets:
        if not base.is_dir():
            continue
        for rs_path in sorted(base.rglob("*.rs")):
            rel = rs_path.relative_to(root).as_posix()
            if rel == "crates/domains/identity/src/issuance.rs":
                continue
            parts = rs_path.relative_to(base).parts
            if base.name == "domains":
                if len(parts) < 2 or parts[1] not in ("src", "tests"):
                    continue
            elif not parts or parts[0] not in ("src", "tests"):
                continue
            code = strip_rust_comments(
                rs_path.read_text(encoding="utf-8", errors="ignore")
            )
            for label, pattern in IN_PROCESS_BANNED_PATTERNS:
                if pattern.search(code):
                    errors.append(f"forbidden in-process auth symbol {label} in {rel}")
                    break


def scan_domain_sources(root: pathlib.Path, errors: list[str]) -> None:
    domains_dir = root / "crates/domains"
    if not domains_dir.is_dir():
        return
    for rs_path in sorted(domains_dir.rglob("*.rs")):
        rel = rs_path.relative_to(root).as_posix()
        parts = rs_path.relative_to(domains_dir).parts
        if len(parts) < 2 or parts[1] not in ("src", "tests"):
            continue
        code = strip_rust_comments(rs_path.read_text(encoding="utf-8", errors="ignore"))
        for label, pattern in HARD_BANNED_PATTERNS:
            if pattern.search(code):
                errors.append(f"forbidden capability token {label} in {rel}")
        if parts[1] == "src":
            allowed = WAVE_1_8_LEGACY_ALLOWLIST.get(rel, set())
            for label, pattern in LEGACY_PATTERNS:
                if pattern.search(code) and label not in allowed:
                    errors.append(
                        f"new legacy pg entrypoint {label} in {rel} "
                        "(not in Wave 1.8 allowlist)"
                    )


root = pathlib.Path(
    sys.argv[1]
    if len(sys.argv) > 1
    else pathlib.Path(__file__).resolve().parents[1] / "server-rust"
).resolve()
try:
    command = [
        "cargo",
        "metadata",
        "--format-version",
        "1",
        "--manifest-path",
        str(root / "Cargo.toml"),
    ]
    if (root / "Cargo.lock").exists():
        command.append("--locked")
    # Run where Cargo itself discovers .cargo/config.toml and inspect the
    # resolved graph: a registry dependency may have been patched to a path.
    metadata = json.loads(subprocess.check_output(command, cwd=root, text=True))
    members = set(metadata["workspace_members"])
    packages = [p for p in metadata["packages"] if p["id"] in members]
    workspace_paths = {
        pathlib.Path(p["manifest_path"]).resolve().parent for p in packages
    }
    domains = {}
    for package in metadata["packages"]:
        manifest = pathlib.Path(package["manifest_path"]).resolve()
        if package["id"] in members and manifest.parent.is_relative_to(
            root / "crates/domains"
        ):
            domains[manifest.parent] = package
    errors: list[str] = []
    for package in metadata["packages"]:
        if package["source"] is None and package["id"] not in members:
            errors.append(f'non-workspace path: {package["name"]}')
    if tomllib is not None:
        with (root / "Cargo.toml").open("rb") as manifest_file:
            manifest = tomllib.load(manifest_file)
        overrides = list(manifest.get("patch", {}).values()) + [
            manifest.get("replace", {})
        ]
        for group in overrides:
            for name, override in group.items():
                if isinstance(override, dict) and "path" in override:
                    errors.append(f"path override forbidden: {name}")
    else:
        # Minimal Python <3.11 fallback for [patch.*] and [replace] path overrides.
        in_override = False
        for raw_line in (root / "Cargo.toml").read_text(encoding="utf-8").splitlines():
            line = raw_line.split("#", 1)[0].strip()
            if line.startswith("[") and line.endswith("]"):
                header = line[1:-1].strip()
                in_override = header == "replace" or header.startswith("patch.")
            elif in_override and "=" in line:
                name, rhs = [part.strip() for part in line.split("=", 1)]
                if re.search(r"\bpath\s*=", rhs):
                    cleaned = name.strip("\"'")
                    errors.append(f"path override forbidden: {cleaned}")
    for package in packages:
        pkg_name = package["name"]
        pkg_manifest_dir = pathlib.Path(package["manifest_path"]).resolve().parent
        is_domain = pkg_manifest_dir.is_relative_to(root / "crates/domains")
        pg_keys = {
            dep.get("rename") or dep["name"]
            for dep in package["dependencies"]
            if dep["name"] == "setjoin-pg"
        }
        identity_keys = {
            dep.get("rename") or dep["name"]
            for dep in package["dependencies"]
            if dep["name"] == "setjoin-identity"
        }
        workqueue_keys = {
            dep.get("rename") or dep["name"]
            for dep in package["dependencies"]
            if dep["name"] == "setjoin-workqueue"
        }
        for dependency in package["dependencies"]:
            path = dependency.get("path")
            if path and pathlib.Path(path).resolve() not in workspace_paths:
                errors.append(f'non-workspace path: {pkg_name} -> {dependency["name"]}')
            dep_name = dependency["name"]
            if is_domain and dep_name in ("deadpool-postgres", "deadpool"):
                errors.append(
                    "forbidden pool dependency in domain crate: "
                    f"{pkg_name} -> {dep_name}"
                )
            if dep_name == "setjoin-pg":
                declared_features = set(dependency.get("features") or [])
                if (
                    "mint" in declared_features
                    and pkg_name not in MINT_FEATURE_ALLOWLIST
                ):
                    errors.append(f'forbidden setjoin-pg feature "mint" in {pkg_name}')
                if (
                    "worker-pool" in declared_features
                    and pkg_name not in WORKER_POOL_FEATURE_ALLOWLIST
                ):
                    errors.append(
                        f'forbidden setjoin-pg feature "worker-pool" in {pkg_name}'
                    )
            if dep_name == "setjoin-identity":
                declared_features = set(dependency.get("features") or [])
                if (
                    "in-process-authority" in declared_features
                    and pkg_name not in IN_PROCESS_AUTH_ALLOWLIST
                ):
                    errors.append(
                        'forbidden setjoin-identity feature "in-process-authority" '
                        f"in {pkg_name}"
                    )
            if dep_name == "setjoin-workqueue":
                declared_features = set(dependency.get("features") or [])
                if (
                    "worker" in declared_features
                    and pkg_name not in WORKQUEUE_WORKER_ALLOWLIST
                ):
                    errors.append(
                        'forbidden setjoin-workqueue feature "worker" '
                        f"in {pkg_name}"
                    )
        # Never allow setjoin-identity to enable in-process-authority by default.
        if pkg_name == "setjoin-identity":
            features_map = package.get("features") or {}
            seen_feats: set[str] = set()
            pending_feats = list(features_map.get("default") or [])
            while pending_feats:
                feat = pending_feats.pop()
                if feat == "in-process-authority":
                    errors.append(
                        'forbidden default feature "in-process-authority" '
                        "in setjoin-identity"
                    )
                    break
                if feat not in seen_feats and feat in features_map:
                    seen_feats.add(feat)
                    pending_feats.extend(features_map[feat])
        # Never allow setjoin-workqueue to enable worker by default.
        if pkg_name == "setjoin-workqueue":
            features_map = package.get("features") or {}
            seen_feats = set()
            pending_feats = list(features_map.get("default") or [])
            while pending_feats:
                feat = pending_feats.pop()
                if feat == "worker":
                    errors.append(
                        'forbidden default feature "worker" in setjoin-workqueue'
                    )
                    break
                if feat not in seen_feats and feat in features_map:
                    seen_feats.add(feat)
                    pending_feats.extend(features_map[feat])
        # Also reject local feature forwarding (including renamed deps).
        for feat_name, feat_deps in (package.get("features") or {}).items():
            for dep_spec in feat_deps:
                for pg_key in pg_keys:
                    if (
                        dep_spec in (f"{pg_key}/mint", f"{pg_key}?/mint")
                        and pkg_name not in MINT_FEATURE_ALLOWLIST
                    ):
                        errors.append(
                            'forbidden setjoin-pg feature "mint" '
                            f"forwarded by {pkg_name} ({feat_name})"
                        )
                    if (
                        dep_spec in (f"{pg_key}/worker-pool", f"{pg_key}?/worker-pool")
                        and pkg_name not in WORKER_POOL_FEATURE_ALLOWLIST
                    ):
                        errors.append(
                            'forbidden setjoin-pg feature "worker-pool" '
                            f"forwarded by {pkg_name} ({feat_name})"
                        )
                for id_key in identity_keys:
                    if (
                        dep_spec
                        in (
                            f"{id_key}/in-process-authority",
                            f"{id_key}?/in-process-authority",
                        )
                        and pkg_name not in IN_PROCESS_AUTH_ALLOWLIST
                    ):
                        errors.append(
                            "forbidden setjoin-identity feature "
                            '"in-process-authority" '
                            f"forwarded by {pkg_name} ({feat_name})"
                        )
                for wq_key in workqueue_keys:
                    if (
                        dep_spec
                        in (
                            f"{wq_key}/worker",
                            f"{wq_key}?/worker",
                        )
                        and pkg_name not in WORKQUEUE_WORKER_ALLOWLIST
                    ):
                        errors.append(
                            'forbidden setjoin-workqueue feature "worker" '
                            f"forwarded by {pkg_name} ({feat_name})"
                        )

    families = {package["id"]: package for package in domains.values()}
    nodes = {node["id"]: node for node in metadata["resolve"]["nodes"]}
    for origin in families:
        seen, pending = {origin}, [origin]
        while pending:
            current = pending.pop()
            for dependency in nodes[current]["deps"]:
                # Dev dependencies of dependencies are not compiled by Cargo.
                # The family's own dev dependencies still count.
                if current != origin and all(
                    kind["kind"] == "dev" for kind in dependency["dep_kinds"]
                ):
                    continue
                target = dependency["pkg"]
                if target in families and target != origin:
                    errors.append(
                        f'{families[origin]["name"]} -> {families[target]["name"]}'
                    )
                if target not in seen:
                    seen.add(target)
                    pending.append(target)

    scan_domain_sources(root, errors)
    scan_in_process_sources(root, errors)

    if errors:
        print(
            "family dependencies forbidden: " + ", ".join(sorted(set(errors))),
            file=sys.stderr,
        )
        sys.exit(1)
    print("family isolation: ok")
except (OSError, subprocess.CalledProcessError, ValueError, KeyError) as exc:
    print(f"family isolation check failed: {exc}", file=sys.stderr)
    sys.exit(1)
