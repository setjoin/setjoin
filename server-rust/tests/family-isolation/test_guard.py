#!/usr/bin/env python3
"""Black-box fixture for the family isolation workspace check."""
import pathlib
import subprocess
import tempfile
import unittest

GUARD = pathlib.Path(__file__).resolve().parents[3] / "scripts/check-rust-family-isolation.py"


class FamilyIsolation(unittest.TestCase):
    def test_cross_family_dependency_is_rejected(self):
        with tempfile.TemporaryDirectory(prefix="gofree-t1-family-") as tmp:
            root = pathlib.Path(tmp)
            for name in ("alpha", "beta"):
                crate = root / "crates/domains" / name
                (crate / "src").mkdir(parents=True)
                (crate / "src/lib.rs").write_text("")
                dependency = '\n[dependencies]\nbeta = { path = "../beta" }\n' if name == "alpha" else ""
                (crate / "Cargo.toml").write_text(f'[package]\nname = "{name}"\nversion = "0.1.0"\n{dependency}')
            (root / "Cargo.toml").write_text('[workspace]\nresolver = "2"\nmembers = ["crates/domains/*"]\n')
            result = subprocess.run(["python3", str(GUARD), str(root)], capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("alpha -> beta", result.stderr)

    def test_cross_family_dependencies_in_all_cargo_dependency_kinds_are_rejected(self):
        for table in ("dev-dependencies", "build-dependencies", "target.'cfg(unix)'.dependencies"):
            with self.subTest(table=table), tempfile.TemporaryDirectory(prefix="gofree-t1-family-kind-") as tmp:
                root = pathlib.Path(tmp)
                for name in ("alpha", "beta"):
                    crate = root / "crates/domains" / name
                    (crate / "src").mkdir(parents=True)
                    (crate / "src/lib.rs").write_text("")
                    dependency = f'\n[{table}]\nalias = {{ package = "beta", path = "../beta" }}\n' if name == "alpha" else ""
                    (crate / "Cargo.toml").write_text(
                        f'[package]\nname = "{name}"\nversion = "0.1.0"\n{dependency}'
                    )
                (root / "Cargo.toml").write_text(
                    '[workspace]\nresolver = "2"\nmembers = ["crates/domains/*"]\n'
                )
                result = subprocess.run(["python3", str(GUARD), str(root)], capture_output=True, text=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("alpha -> beta", result.stderr)

    def test_foundation_cannot_hide_a_cross_family_dependency(self):
        with tempfile.TemporaryDirectory(prefix="gofree-t1-transitive-family-") as tmp:
            root = pathlib.Path(tmp)
            for relative, name, dependency in (
                ("crates/domains/alpha", "alpha", 'foundation = { path = "../../foundation" }'),
                ("crates/foundation", "foundation", 'beta = { path = "../domains/beta" }'),
                ("crates/domains/beta", "beta", ""),
            ):
                crate = root / relative
                (crate / "src").mkdir(parents=True)
                (crate / "src/lib.rs").write_text("")
                (crate / "Cargo.toml").write_text(
                    f'[package]\nname = "{name}"\nversion = "0.1.0"\n[dependencies]\n{dependency}\n'
                )
            (root / "Cargo.toml").write_text(
                '[workspace]\nresolver = "2"\nmembers = ["crates/domains/*", "crates/foundation"]\n'
            )
            result = subprocess.run(["python3", str(GUARD), str(root)], capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("alpha -> beta", result.stderr)

    def test_an_intermediate_crates_test_only_dependency_does_not_couple_families(self):
        with tempfile.TemporaryDirectory(prefix="gofree-t1-intermediate-dev-") as tmp:
            root = pathlib.Path(tmp)
            for relative, name, dependency in (
                ("crates/domains/alpha", "alpha", '[dependencies]\nfoundation = { path = "../../foundation" }'),
                ("crates/foundation", "foundation", '[dev-dependencies]\nbeta = { path = "../domains/beta" }'),
                ("crates/domains/beta", "beta", ""),
            ):
                crate = root / relative
                (crate / "src").mkdir(parents=True)
                (crate / "src/lib.rs").write_text("")
                (crate / "Cargo.toml").write_text(
                    f'[package]\nname = "{name}"\nversion = "0.1.0"\n{dependency}\n'
                )
            (root / "Cargo.toml").write_text(
                '[workspace]\nresolver = "2"\nmembers = ["crates/domains/*", "crates/foundation"]\n'
            )
            result = subprocess.run(["python3", str(GUARD), str(root)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_non_workspace_path_dependency_is_rejected(self):
        with tempfile.TemporaryDirectory(prefix="gofree-t1-source-") as tmp:
            root = pathlib.Path(tmp)
            workspace = root / "workspace"
            for directory, name in [(workspace, "app"), (root / "external", "external")]:
                (directory / "src").mkdir(parents=True)
                (directory / "src/lib.rs").write_text("")
                (directory / "Cargo.toml").write_text(f'[package]\nname = "{name}"\nversion = "0.1.0"\n')
            with (workspace / "Cargo.toml").open("a") as manifest:
                manifest.write('[workspace]\n[dependencies]\nexternal = { path = "../external" }\n')
            result = subprocess.run(["python3", str(GUARD), str(workspace)], capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("non-workspace path", result.stderr)

    def test_path_patch_is_rejected(self):
        with tempfile.TemporaryDirectory(prefix="gofree-t1-patch-") as tmp:
            root = pathlib.Path(tmp)
            for name in ("app", "external"):
                (root / name / "src").mkdir(parents=True)
                (root / name / "src/lib.rs").write_text("")
                (root / name / "Cargo.toml").write_text(f'[package]\nname = "{name}"\nversion = "0.1.0"\n')
            (root / "Cargo.toml").write_text('[workspace]\nmembers = ["app"]\nexclude = ["external"]\n[patch.crates-io]\nexternal = { path = "external" }\n')
            result = subprocess.run(["python3", str(GUARD), str(root)], capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("path override", result.stderr)

    def test_cargo_config_cannot_replace_a_registry_crate_with_a_local_path(self):
        with tempfile.TemporaryDirectory(prefix="gofree-t1-config-patch-") as tmp:
            root = pathlib.Path(tmp)
            workspace = root / "workspace"
            for directory, name, version in [(workspace, "app", "0.1.0"), (root / "external", "serde", "1.0.228")]:
                (directory / "src").mkdir(parents=True)
                (directory / "src/lib.rs").write_text("")
                (directory / "Cargo.toml").write_text(f'[package]\nname = "{name}"\nversion = "{version}"\n')
            with (workspace / "Cargo.toml").open("a") as manifest:
                manifest.write('[workspace]\n[dependencies]\nserde = "=1.0.228"\n')
            (workspace / ".cargo").mkdir()
            (workspace / ".cargo/config.toml").write_text('[patch.crates-io]\nserde = { path = "../external" }\n')
            result = subprocess.run(["python3", str(GUARD), str(workspace)], cwd=workspace, capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("non-workspace path", result.stderr)

    def test_cargo_config_cannot_hide_a_cross_family_dependency(self):
        with tempfile.TemporaryDirectory(prefix="gofree-t1-config-family-") as tmp:
            root = pathlib.Path(tmp)
            for name in ("alpha", "beta"):
                crate = root / "crates/domains" / name
                (crate / "src").mkdir(parents=True)
                (crate / "src/lib.rs").write_text("")
                dependency = '\n[dependencies]\nbeta = "=0.1.0"\n' if name == "alpha" else ""
                (crate / "Cargo.toml").write_text(f'[package]\nname = "{name}"\nversion = "0.1.0"\n{dependency}')
            (root / "Cargo.toml").write_text('[workspace]\nresolver = "2"\nmembers = ["crates/domains/*"]\n')
            (root / ".cargo").mkdir()
            (root / ".cargo/config.toml").write_text('[patch.crates-io]\nbeta = { path = "crates/domains/beta" }\n')
            result = subprocess.run(["python3", str(GUARD), str(root)], cwd=root, capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("alpha -> beta", result.stderr)


if __name__ == "__main__":
    unittest.main()
