#!/usr/bin/env python3
"""Reject dependencies between workspace route-family crates, including dev/build deps."""
import json
import pathlib
import subprocess
import sys
import tomllib

root = pathlib.Path(
    sys.argv[1] if len(sys.argv) > 1 else pathlib.Path(__file__).resolve().parents[1] / "server-rust"
).resolve()
try:
    command = ["cargo", "metadata", "--format-version", "1", "--manifest-path", str(root / "Cargo.toml")]
    if (root / "Cargo.lock").exists():
        command.append("--locked")
    # Run where Cargo itself discovers .cargo/config.toml and inspect the
    # resolved graph: a registry dependency may have been patched to a path.
    metadata = json.loads(subprocess.check_output(command, cwd=root, text=True))
    members = set(metadata["workspace_members"])
    packages = [p for p in metadata["packages"] if p["id"] in members]
    workspace_paths = {pathlib.Path(p["manifest_path"]).resolve().parent for p in packages}
    domains = {}
    for package in metadata["packages"]:
        manifest = pathlib.Path(package["manifest_path"]).resolve()
        if package["id"] in members and manifest.parent.is_relative_to(root / "crates/domains"):
            domains[manifest.parent] = package
    errors = []
    for package in metadata["packages"]:
        if package["source"] is None and package["id"] not in members:
            errors.append(f'non-workspace path: {package["name"]}')
    with (root / "Cargo.toml").open("rb") as manifest_file:
        manifest = tomllib.load(manifest_file)
    overrides = list(manifest.get("patch", {}).values()) + [manifest.get("replace", {})]
    for group in overrides:
        for name, override in group.items():
            if isinstance(override, dict) and "path" in override:
                errors.append(f"path override forbidden: {name}")
    for package in packages:
        for dependency in package["dependencies"]:
            path = dependency.get("path")
            if path and pathlib.Path(path).resolve() not in workspace_paths:
                errors.append(f'non-workspace path: {package["name"]} -> {dependency["name"]}')
    families = {package["id"]: package for package in domains.values()}
    nodes = {node["id"]: node for node in metadata["resolve"]["nodes"]}
    for origin in families:
        seen, pending = {origin}, [origin]
        while pending:
            current = pending.pop()
            for dependency in nodes[current]["deps"]:
                # Dev dependencies of dependencies are not compiled by Cargo.
                # The family's own dev dependencies still count.
                if current != origin and all(kind["kind"] == "dev" for kind in dependency["dep_kinds"]):
                    continue
                target = dependency["pkg"]
                if target in families and target != origin:
                    errors.append(f'{families[origin]["name"]} -> {families[target]["name"]}')
                if target not in seen:
                    seen.add(target)
                    pending.append(target)
    if errors:
        print("family dependencies forbidden: " + ", ".join(sorted(set(errors))), file=sys.stderr)
        sys.exit(1)
    print("family isolation: ok")
except (OSError, subprocess.CalledProcessError, ValueError, KeyError) as exc:
    print(f"family isolation check failed: {exc}", file=sys.stderr)
    sys.exit(1)
