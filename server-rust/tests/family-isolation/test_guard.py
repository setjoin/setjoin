#!/usr/bin/env python3
"""Black-box fixture for the family isolation workspace check."""

import pathlib
import subprocess
import tempfile
import unittest

GUARD = (
    pathlib.Path(__file__).resolve().parents[3]
    / "scripts/check-rust-family-isolation.py"
)


class FamilyIsolation(unittest.TestCase):
    def test_cross_family_dependency_is_rejected(self):
        with tempfile.TemporaryDirectory(prefix="gofree-t1-family-") as tmp:
            root = pathlib.Path(tmp)
            for name in ("alpha", "beta"):
                crate = root / "crates/domains" / name
                (crate / "src").mkdir(parents=True)
                (crate / "src/lib.rs").write_text("")
                dependency = (
                    '\n[dependencies]\nbeta = { path = "../beta" }\n'
                    if name == "alpha"
                    else ""
                )
                (crate / "Cargo.toml").write_text(
                    f'[package]\nname = "{name}"\nversion = "0.1.0"\n{dependency}'
                )
            (root / "Cargo.toml").write_text(
                '[workspace]\nresolver = "2"\nmembers = ["crates/domains/*"]\n'
            )
            result = subprocess.run(
                ["python3", str(GUARD), str(root)],
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("alpha -> beta", result.stderr)

    def test_cross_family_dependencies_in_all_cargo_dependency_kinds_are_rejected(self):
        tables = (
            "dev-dependencies",
            "build-dependencies",
            "target.'cfg(unix)'.dependencies",
        )
        for table in tables:
            with (
                self.subTest(table=table),
                tempfile.TemporaryDirectory(prefix="gofree-t1-family-kind-") as tmp,
            ):
                root = pathlib.Path(tmp)
                for name in ("alpha", "beta"):
                    crate = root / "crates/domains" / name
                    (crate / "src").mkdir(parents=True)
                    (crate / "src/lib.rs").write_text("")
                    dependency = (
                        f'\n[{table}]\nalias = {{ package = "beta", '
                        'path = "../beta" }\n'
                        if name == "alpha"
                        else ""
                    )
                    (crate / "Cargo.toml").write_text(
                        f'[package]\nname = "{name}"\nversion = "0.1.0"\n{dependency}'
                    )
                (root / "Cargo.toml").write_text(
                    '[workspace]\nresolver = "2"\nmembers = ["crates/domains/*"]\n'
                )
                result = subprocess.run(
                    ["python3", str(GUARD), str(root)],
                    capture_output=True,
                    text=True,
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("alpha -> beta", result.stderr)

    def test_foundation_cannot_hide_a_cross_family_dependency(self):
        with tempfile.TemporaryDirectory(prefix="gofree-t1-transitive-family-") as tmp:
            root = pathlib.Path(tmp)
            specs = (
                (
                    "crates/domains/alpha",
                    "alpha",
                    'foundation = { path = "../../foundation" }',
                ),
                (
                    "crates/foundation",
                    "foundation",
                    'beta = { path = "../domains/beta" }',
                ),
                ("crates/domains/beta", "beta", ""),
            )
            for relative, name, dependency in specs:
                crate = root / relative
                (crate / "src").mkdir(parents=True)
                (crate / "src/lib.rs").write_text("")
                (crate / "Cargo.toml").write_text(
                    f'[package]\nname = "{name}"\nversion = "0.1.0"\n'
                    f"[dependencies]\n{dependency}\n"
                )
            (root / "Cargo.toml").write_text(
                '[workspace]\nresolver = "2"\n'
                'members = ["crates/domains/*", "crates/foundation"]\n'
            )
            result = subprocess.run(
                ["python3", str(GUARD), str(root)],
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("alpha -> beta", result.stderr)

    def test_an_intermediate_crates_test_only_dependency_does_not_couple_families(self):
        with tempfile.TemporaryDirectory(prefix="gofree-t1-intermediate-dev-") as tmp:
            root = pathlib.Path(tmp)
            specs = (
                (
                    "crates/domains/alpha",
                    "alpha",
                    '[dependencies]\nfoundation = { path = "../../foundation" }',
                ),
                (
                    "crates/foundation",
                    "foundation",
                    '[dev-dependencies]\nbeta = { path = "../domains/beta" }',
                ),
                ("crates/domains/beta", "beta", ""),
            )
            for relative, name, dependency in specs:
                crate = root / relative
                (crate / "src").mkdir(parents=True)
                (crate / "src/lib.rs").write_text("")
                (crate / "Cargo.toml").write_text(
                    f'[package]\nname = "{name}"\nversion = "0.1.0"\n{dependency}\n'
                )
            (root / "Cargo.toml").write_text(
                '[workspace]\nresolver = "2"\n'
                'members = ["crates/domains/*", "crates/foundation"]\n'
            )
            result = subprocess.run(
                ["python3", str(GUARD), str(root)],
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_non_workspace_path_dependency_is_rejected(self):
        with tempfile.TemporaryDirectory(prefix="gofree-t1-source-") as tmp:
            root = pathlib.Path(tmp)
            workspace = root / "workspace"
            for directory, name in [
                (workspace, "app"),
                (root / "external", "external"),
            ]:
                (directory / "src").mkdir(parents=True)
                (directory / "src/lib.rs").write_text("")
                (directory / "Cargo.toml").write_text(
                    f'[package]\nname = "{name}"\nversion = "0.1.0"\n'
                )
            with (workspace / "Cargo.toml").open("a") as manifest:
                manifest.write(
                    '[workspace]\n[dependencies]\nexternal = { path = "../external" }\n'
                )
            result = subprocess.run(
                ["python3", str(GUARD), str(workspace)],
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("non-workspace path", result.stderr)

    def test_path_patch_is_rejected(self):
        with tempfile.TemporaryDirectory(prefix="gofree-t1-patch-") as tmp:
            root = pathlib.Path(tmp)
            for name in ("app", "external"):
                (root / name / "src").mkdir(parents=True)
                (root / name / "src/lib.rs").write_text("")
                (root / name / "Cargo.toml").write_text(
                    f'[package]\nname = "{name}"\nversion = "0.1.0"\n'
                )
            (root / "Cargo.toml").write_text(
                '[workspace]\nmembers = ["app"]\nexclude = ["external"]\n'
                '[patch.crates-io]\nexternal = { path = "external" }\n'
            )
            result = subprocess.run(
                ["python3", str(GUARD), str(root)],
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("path override", result.stderr)

    def test_cargo_config_cannot_replace_a_registry_crate_with_a_local_path(self):
        with tempfile.TemporaryDirectory(prefix="gofree-t1-config-patch-") as tmp:
            root = pathlib.Path(tmp)
            workspace = root / "workspace"
            specs = [
                (workspace, "app", "0.1.0"),
                (root / "external", "serde", "1.0.228"),
            ]
            for directory, name, version in specs:
                (directory / "src").mkdir(parents=True)
                (directory / "src/lib.rs").write_text("")
                (directory / "Cargo.toml").write_text(
                    f'[package]\nname = "{name}"\nversion = "{version}"\n'
                )
            with (workspace / "Cargo.toml").open("a") as manifest:
                manifest.write('[workspace]\n[dependencies]\nserde = "=1.0.228"\n')
            (workspace / ".cargo").mkdir()
            (workspace / ".cargo/config.toml").write_text(
                '[patch.crates-io]\nserde = { path = "../external" }\n'
            )
            result = subprocess.run(
                ["python3", str(GUARD), str(workspace)],
                cwd=workspace,
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("non-workspace path", result.stderr)

    def test_cargo_config_cannot_hide_a_cross_family_dependency(self):
        with tempfile.TemporaryDirectory(prefix="gofree-t1-config-family-") as tmp:
            root = pathlib.Path(tmp)
            for name in ("alpha", "beta"):
                crate = root / "crates/domains" / name
                (crate / "src").mkdir(parents=True)
                (crate / "src/lib.rs").write_text("")
                dependency = (
                    '\n[dependencies]\nbeta = "=0.1.0"\n' if name == "alpha" else ""
                )
                (crate / "Cargo.toml").write_text(
                    f'[package]\nname = "{name}"\nversion = "0.1.0"\n{dependency}'
                )
            (root / "Cargo.toml").write_text(
                '[workspace]\nresolver = "2"\nmembers = ["crates/domains/*"]\n'
            )
            (root / ".cargo").mkdir()
            (root / ".cargo/config.toml").write_text(
                '[patch.crates-io]\nbeta = { path = "crates/domains/beta" }\n'
            )
            result = subprocess.run(
                ["python3", str(GUARD), str(root)],
                cwd=root,
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("alpha -> beta", result.stderr)

    def test_domain_crate_cannot_enable_setjoin_pg_mint_or_worker_pool_features(self):
        for feature in ("mint", "worker-pool"):
            with (
                self.subTest(feature=feature),
                tempfile.TemporaryDirectory(prefix="gofree-t1-pg-feat-") as tmp,
            ):
                root = pathlib.Path(tmp)
                pg = root / "crates/pg"
                (pg / "src").mkdir(parents=True)
                (pg / "src/lib.rs").write_text("")
                (pg / "Cargo.toml").write_text(
                    '[package]\nname = "setjoin-pg"\nversion = "0.1.0"\n'
                    "[features]\nmint = []\nworker-pool = []\n"
                )
                dom = root / "crates/domains/alpha"
                (dom / "src").mkdir(parents=True)
                (dom / "src/lib.rs").write_text("")
                (dom / "Cargo.toml").write_text(
                    '[package]\nname = "alpha"\nversion = "0.1.0"\n'
                    "[dependencies]\n"
                    f'setjoin-pg = {{ path = "../../pg", features = ["{feature}"] }}\n'
                )
                (root / "Cargo.toml").write_text(
                    '[workspace]\nresolver = "2"\n'
                    'members = ["crates/pg", "crates/domains/alpha"]\n'
                )
                result = subprocess.run(
                    ["python3", str(GUARD), str(root)],
                    capture_output=True,
                    text=True,
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(
                    f'forbidden setjoin-pg feature "{feature}" in alpha',
                    result.stderr,
                )

    def test_renamed_setjoin_pg_feature_forwarding_is_rejected(self):
        cases = [
            ("mint", 'sneak = ["pg_alias/mint"]'),
            ("worker-pool", 'sneak = ["pg_alias?/worker-pool"]'),
        ]
        for feature, feat_line in cases:
            with (
                self.subTest(feature=feature),
                tempfile.TemporaryDirectory(prefix="gofree-t1-pg-rename-") as tmp,
            ):
                root = pathlib.Path(tmp)
                pg = root / "crates/pg"
                (pg / "src").mkdir(parents=True)
                (pg / "src/lib.rs").write_text("")
                (pg / "Cargo.toml").write_text(
                    '[package]\nname = "setjoin-pg"\nversion = "0.1.0"\n'
                    "[features]\nmint = []\nworker-pool = []\n"
                )
                dom = root / "crates/domains/alpha"
                (dom / "src").mkdir(parents=True)
                (dom / "src/lib.rs").write_text("")
                (dom / "Cargo.toml").write_text(
                    '[package]\nname = "alpha"\nversion = "0.1.0"\n'
                    f"[features]\n{feat_line}\n"
                    "[dependencies]\n"
                    'pg_alias = { package = "setjoin-pg", path = "../../pg", '
                    "optional = true }\n"
                )
                (root / "Cargo.toml").write_text(
                    '[workspace]\nresolver = "2"\n'
                    'members = ["crates/pg", "crates/domains/alpha"]\n'
                )
                result = subprocess.run(
                    ["python3", str(GUARD), str(root)],
                    capture_output=True,
                    text=True,
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(
                    f'forbidden setjoin-pg feature "{feature}" forwarded by alpha',
                    result.stderr,
                )

    def test_authorized_crates_may_enable_setjoin_pg_features(self):
        with tempfile.TemporaryDirectory(prefix="gofree-t1-pg-ok-") as tmp:
            root = pathlib.Path(tmp)
            pg = root / "crates/pg"
            (pg / "src").mkdir(parents=True)
            (pg / "src/lib.rs").write_text("")
            (pg / "Cargo.toml").write_text(
                '[package]\nname = "setjoin-pg"\nversion = "0.1.0"\n'
                "[features]\nmint = []\nworker-pool = []\n"
            )
            authz = root / "crates/authz"
            (authz / "src").mkdir(parents=True)
            (authz / "src/lib.rs").write_text("")
            (authz / "Cargo.toml").write_text(
                '[package]\nname = "setjoin-authz"\nversion = "0.1.0"\n'
                "[dependencies]\n"
                'setjoin-pg = { path = "../pg", features = ["mint"] }\n'
            )
            gw = root / "bins/gateway"
            (gw / "src").mkdir(parents=True)
            (gw / "src/lib.rs").write_text("")
            (gw / "Cargo.toml").write_text(
                '[package]\nname = "setjoin-gateway"\nversion = "0.1.0"\n'
                "[dependencies]\n"
                'setjoin-pg = { path = "../../crates/pg", '
                'features = ["mint", "worker-pool"] }\n'
            )
            (root / "Cargo.toml").write_text(
                '[workspace]\nresolver = "2"\n'
                'members = ["crates/pg", "crates/authz", "bins/gateway"]\n'
            )
            result = subprocess.run(
                ["python3", str(GUARD), str(root)],
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_domain_source_bans_mint_pools_and_new_legacy_entrypoints(self):
        cases = [
            ("setjoin_pg::mint", "fn f() { let _ = setjoin_pg::mint::user; }"),
            ("capability::mint", "fn f() { let _ = capability::mint::user; }"),
            ("::mint", "fn f() { let _ = pg_alias::mint::user; }"),
            ("::mint", "use pg_alias::{mint};"),
            ("AppPool", "fn f(_p: &AppPool) {}"),
            ("WorkerPool", "fn f(_p: &WorkerPool) {}"),
            ("WorkerTx", "fn f(_tx: &mut WorkerTx) {}"),
            ("deadpool_postgres", "use deadpool_postgres::Pool;"),
            ("WorkerDatabase", "fn f(_db: &WorkerDatabase) {}"),
            (
                "ScopedExecutor::from_dsn",
                'fn f() { let _ = ScopedExecutor::from_dsn("", 1); }',
            ),
            ("ScopedExecutor::new", "fn f(p: ()) { let _ = ScopedExecutor::new(p); }"),
            (
                "from_authenticated_session",
                "fn f() { let _ = MailboxAuthContext::from_authenticated_session(); }",
            ),
        ]
        for expected, source in cases:
            with (
                self.subTest(expected=expected),
                tempfile.TemporaryDirectory(prefix="gofree-t1-src-") as tmp,
            ):
                root = pathlib.Path(tmp)
                dom = root / "crates/domains/alpha"
                (dom / "src").mkdir(parents=True)
                (dom / "src/lib.rs").write_text(source)
                (dom / "Cargo.toml").write_text(
                    '[package]\nname = "alpha"\nversion = "0.1.0"\n'
                )
                (root / "Cargo.toml").write_text(
                    '[workspace]\nresolver = "2"\nmembers = ["crates/domains/alpha"]\n'
                )
                result = subprocess.run(
                    ["python3", str(GUARD), str(root)],
                    capture_output=True,
                    text=True,
                )
                self.assertNotEqual(
                    result.returncode, 0, f"expected failure for {expected}"
                )
                self.assertIn(expected, result.stderr)

    def test_in_process_authority_feature_restricted_to_allowlist(self):
        for pkg_dir, pkg_name, allowed in (
            ("bins/auth", "setjoin-auth", True),
            ("bins/setjoind", "setjoind", True),
            ("bins/gateway", "setjoin-gateway", False),
            ("crates/domains/alpha", "alpha", False),
        ):
            with (
                self.subTest(pkg=pkg_name),
                tempfile.TemporaryDirectory(prefix="gofree-t1-inproc-feat-") as tmp,
            ):
                root = pathlib.Path(tmp)
                ident = root / "crates/domains/identity"
                (ident / "src").mkdir(parents=True)
                (ident / "src/lib.rs").write_text("")
                (ident / "Cargo.toml").write_text(
                    '[package]\nname = "setjoin-identity"\nversion = "0.1.0"\n'
                    "[features]\nin-process-authority = []\n"
                )
                pkg = root / pkg_dir
                (pkg / "src").mkdir(parents=True)
                (pkg / "src/lib.rs").write_text("")
                rel_ident = (
                    "../identity"
                    if pkg_dir.startswith("crates/domains/")
                    else "../../crates/domains/identity"
                )
                (pkg / "Cargo.toml").write_text(
                    f'[package]\nname = "{pkg_name}"\nversion = "0.1.0"\n'
                    "[dependencies]\n"
                    f'setjoin-identity = {{ path = "{rel_ident}", '
                    'features = ["in-process-authority"] }\n'
                )
                (root / "Cargo.toml").write_text(
                    '[workspace]\nresolver = "2"\n'
                    f'members = ["crates/domains/identity", "{pkg_dir}"]\n'
                )
                result = subprocess.run(
                    ["python3", str(GUARD), str(root)],
                    capture_output=True,
                    text=True,
                )
                if allowed:
                    self.assertEqual(result.returncode, 0, result.stderr)
                else:
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn(
                        'forbidden setjoin-identity feature "in-process-authority"',
                        result.stderr,
                    )

    def test_renamed_in_process_authority_feature_forwarding_is_rejected(self):
        for feat_line in (
            'sneak = ["id_alias/in-process-authority"]',
            'sneak = ["id_alias?/in-process-authority"]',
        ):
            with (
                self.subTest(feat_line=feat_line),
                tempfile.TemporaryDirectory(prefix="gofree-t1-inproc-fwd-") as tmp,
            ):
                root = pathlib.Path(tmp)
                ident = root / "crates/domains/identity"
                (ident / "src").mkdir(parents=True)
                (ident / "src/lib.rs").write_text("")
                (ident / "Cargo.toml").write_text(
                    '[package]\nname = "setjoin-identity"\nversion = "0.1.0"\n'
                    "[features]\nin-process-authority = []\n"
                )
                gw = root / "bins/gateway"
                (gw / "src").mkdir(parents=True)
                (gw / "src/lib.rs").write_text("")
                (gw / "Cargo.toml").write_text(
                    '[package]\nname = "setjoin-gateway"\nversion = "0.1.0"\n'
                    f"[features]\n{feat_line}\n"
                    "[dependencies]\n"
                    'id_alias = { package = "setjoin-identity", '
                    'path = "../../crates/domains/identity", optional = true }\n'
                )
                (root / "Cargo.toml").write_text(
                    '[workspace]\nresolver = "2"\n'
                    'members = ["crates/domains/identity", "bins/gateway"]\n'
                )
                result = subprocess.run(
                    ["python3", str(GUARD), str(root)],
                    capture_output=True,
                    text=True,
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(
                    'forbidden setjoin-identity feature "in-process-authority" '
                    "forwarded by setjoin-gateway",
                    result.stderr,
                )

    def test_in_process_source_ban_covers_domains_and_gateway_but_allows_issuance(self):
        bad_cases = [
            (
                "crates/domains/alpha",
                "alpha",
                "src/lib.rs",
                "fn f() { let _ = ClientProof::in_process(); }",
                "ClientProof::in_process",
            ),
            (
                "crates/domains/identity",
                "setjoin-identity",
                "src/other.rs",
                "fn f() { let _ = in_process(); }",
                "in_process",
            ),
            (
                "bins/gateway",
                "setjoin-gateway",
                "src/lib.rs",
                "fn f() { let _ = ClientProof::in_process(); }",
                "ClientProof::in_process",
            ),
        ]
        for crate_dir, pkg_name, rel_file, source, expected in bad_cases:
            with (
                self.subTest(crate=crate_dir, file=rel_file),
                tempfile.TemporaryDirectory(prefix="gofree-t1-inproc-src-") as tmp,
            ):
                root = pathlib.Path(tmp)
                crate = root / crate_dir
                (crate / "src").mkdir(parents=True)
                (crate / "src/lib.rs").write_text("")
                (crate / rel_file).write_text(source)
                (crate / "Cargo.toml").write_text(
                    f'[package]\nname = "{pkg_name}"\nversion = "0.1.0"\n'
                )
                (root / "Cargo.toml").write_text(
                    f'[workspace]\nresolver = "2"\nmembers = ["{crate_dir}"]\n'
                )
                result = subprocess.run(
                    ["python3", str(GUARD), str(root)],
                    capture_output=True,
                    text=True,
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(expected, result.stderr)

        # Defining pub fn in_process() inside identity/src/issuance.rs is allowed,
        # and is_in_process() in gateway is allowed.
        with tempfile.TemporaryDirectory(prefix="gofree-t1-inproc-ok-") as tmp:
            root = pathlib.Path(tmp)
            ident = root / "crates/domains/identity"
            (ident / "src").mkdir(parents=True)
            (ident / "src/lib.rs").write_text("")
            (ident / "src/issuance.rs").write_text("pub fn in_process() {}")
            (ident / "Cargo.toml").write_text(
                '[package]\nname = "setjoin-identity"\nversion = "0.1.0"\n'
            )
            gw = root / "bins/gateway"
            (gw / "src").mkdir(parents=True)
            (gw / "src/lib.rs").write_text("pub fn check() -> bool { is_in_process() }")
            (gw / "Cargo.toml").write_text(
                '[package]\nname = "setjoin-gateway"\nversion = "0.1.0"\n'
            )
            (root / "Cargo.toml").write_text(
                '[workspace]\nresolver = "2"\n'
                'members = ["crates/domains/identity", "bins/gateway"]\n'
            )
            result = subprocess.run(
                ["python3", str(GUARD), str(root)],
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_setjoin_identity_default_feature_cannot_enable_in_process_authority(self):
        for features_toml in (
            'default = ["in-process-authority"]\nin-process-authority = []\n',
            'default = ["alias"]\nalias = ["in-process-authority"]\n'
            "in-process-authority = []\n",
        ):
            with (
                self.subTest(features_toml=features_toml),
                tempfile.TemporaryDirectory(prefix="gofree-t1-inproc-def-") as tmp,
            ):
                root = pathlib.Path(tmp)
                ident = root / "crates/domains/identity"
                (ident / "src").mkdir(parents=True)
                (ident / "src/lib.rs").write_text("")
                (ident / "Cargo.toml").write_text(
                    '[package]\nname = "setjoin-identity"\nversion = "0.1.0"\n'
                    f"[features]\n{features_toml}"
                )
                (root / "Cargo.toml").write_text(
                    '[workspace]\nresolver = "2"\n'
                    'members = ["crates/domains/identity"]\n'
                )
                result = subprocess.run(
                    ["python3", str(GUARD), str(root)],
                    capture_output=True,
                    text=True,
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(
                    'forbidden default feature "in-process-authority" '
                    "in setjoin-identity",
                    result.stderr,
                )

    def test_workqueue_worker_feature_restricted_and_never_default(self):
        with tempfile.TemporaryDirectory(prefix="gofree-t1-wq-dom-") as tmp:
            root = pathlib.Path(tmp)
            wq = root / "crates/workqueue"
            (wq / "src").mkdir(parents=True)
            (wq / "src/lib.rs").write_text("")
            (wq / "Cargo.toml").write_text(
                '[package]\nname = "setjoin-workqueue"\nversion = "0.1.0"\n'
                "[features]\nworker = []\n"
            )
            dom = root / "crates/domains/alpha"
            (dom / "src").mkdir(parents=True)
            (dom / "src/lib.rs").write_text("")
            (dom / "Cargo.toml").write_text(
                '[package]\nname = "alpha"\nversion = "0.1.0"\n'
                "[dependencies]\n"
                'setjoin-workqueue = { path = "../../workqueue", features = ["worker"] }\n'
            )
            (root / "Cargo.toml").write_text(
                '[workspace]\nresolver = "2"\n'
                'members = ["crates/workqueue", "crates/domains/alpha"]\n'
            )
            result = subprocess.run(
                ["python3", str(GUARD), str(root)],
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(
                'forbidden setjoin-workqueue feature "worker" in alpha',
                result.stderr,
            )

        for features_toml in (
            'default = ["worker"]\nworker = []\n',
            'default = ["alias"]\nalias = ["worker"]\nworker = []\n',
        ):
            with (
                self.subTest(features_toml=features_toml),
                tempfile.TemporaryDirectory(prefix="gofree-t1-wq-def-") as tmp,
            ):
                root = pathlib.Path(tmp)
                wq = root / "crates/workqueue"
                (wq / "src").mkdir(parents=True)
                (wq / "src/lib.rs").write_text("")
                (wq / "Cargo.toml").write_text(
                    '[package]\nname = "setjoin-workqueue"\nversion = "0.1.0"\n'
                    f"[features]\n{features_toml}"
                )
                (root / "Cargo.toml").write_text(
                    '[workspace]\nresolver = "2"\n'
                    'members = ["crates/workqueue"]\n'
                )
                result = subprocess.run(
                    ["python3", str(GUARD), str(root)],
                    capture_output=True,
                    text=True,
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(
                    'forbidden default feature "worker" in setjoin-workqueue',
                    result.stderr,
                )

    def test_domain_crates_cannot_reference_admin_worker_or_pre_auth_seams(self):
        cases = (
            ("AdminWorkerPool", "pub fn leak(_p: &AdminWorkerPool) {}\n"),
            ("PreAuthReadTx", "pub fn leak(_t: &PreAuthReadTx) {}\n"),
            (
                "begin_pre_auth_read",
                "pub fn leak(g: &G) { g.begin_pre_auth_read(); }\n",
            ),
            (
                "run_pre_auth_read_contract",
                "pub fn leak(g: &G) { g.run_pre_auth_read_contract(); }\n",
            ),
            (
                "run_pre_auth_read_pipelined",
                "pub fn leak(p: &P) { p.run_pre_auth_read_pipelined(); }\n",
            ),
        )
        for token, source in cases:
            with (
                self.subTest(token=token),
                tempfile.TemporaryDirectory(prefix="gofree-t1-preauth-") as tmp,
            ):
                root = pathlib.Path(tmp)
                dom = root / "crates/domains/sample"
                (dom / "src").mkdir(parents=True)
                (dom / "src/lib.rs").write_text(source)
                (dom / "Cargo.toml").write_text(
                    '[package]\nname = "setjoin-sample"\nversion = "0.1.0"\n'
                )
                (root / "Cargo.toml").write_text(
                    '[workspace]\nresolver = "2"\nmembers = ["crates/domains/sample"]\n'
                )
                result = subprocess.run(
                    ["python3", str(GUARD), str(root)],
                    capture_output=True,
                    text=True,
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(
                    f"forbidden capability token {token} in "
                    "crates/domains/sample/src/lib.rs",
                    result.stderr,
                )

    def test_domain_crates_cannot_reference_scoped_executor_in_src_or_tests(self):
        cases = (
            ("src/lib.rs", "ScopedExecutor", "use setjoin_pg::ScopedExecutor;\n"),
            ("src/lib.rs", "ScopedExecutor", "pub fn leak(_exec: &ScopedExecutor) {}\n"),
            ("tests/integration.rs", "ScopedExecutor", "use setjoin_pg::ScopedExecutor;\n"),
            (
                "tests/integration.rs",
                "ScopedExecutor",
                "fn helper() { let _ = ScopedExecutor::from_dsn(\"\", 1); }\n",
            ),
            ("src/lib.rs", "WorkerDatabase", "use setjoin_pg::workers::WorkerDatabase;\n"),
            ("src/lib.rs", "WorkerDatabase", "pub fn leak(_db: &WorkerDatabase) {}\n"),
            (
                "tests/integration.rs",
                "WorkerDatabase",
                "use setjoin_pg::workers::WorkerDatabase;\n",
            ),
            (
                "tests/integration.rs",
                "WorkerDatabase",
                "fn helper() { let _ = WorkerDatabase::from_dsns(\"\", None); }\n",
            ),
        )
        for rel_file, expected_token, source in cases:
            with (
                self.subTest(rel_file=rel_file, token=expected_token, source=source.strip()),
                tempfile.TemporaryDirectory(prefix="gofree-t1-scoped-exec-") as tmp,
            ):
                root = pathlib.Path(tmp)
                dom = root / "crates/domains/sample"
                (dom / "src").mkdir(parents=True)
                (dom / "tests").mkdir(parents=True)
                (dom / "src/lib.rs").write_text("")
                (dom / rel_file).write_text(source)
                (dom / "Cargo.toml").write_text(
                    '[package]\nname = "setjoin-sample"\nversion = "0.1.0"\n'
                )
                (root / "Cargo.toml").write_text(
                    '[workspace]\nresolver = "2"\nmembers = ["crates/domains/sample"]\n'
                )
                result = subprocess.run(
                    ["python3", str(GUARD), str(root)],
                    capture_output=True,
                    text=True,
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(
                    f"forbidden capability token {expected_token} in "
                    f"crates/domains/sample/{rel_file}",
                    result.stderr,
                )


if __name__ == "__main__":
    unittest.main()
