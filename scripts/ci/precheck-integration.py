#!/usr/bin/env python3
"""Integration-test selection for the PR pre-check (.github/workflows/pr-precheck.yml, job `integration`).

  precheck-integration.py plan OUTDIR [BASE]  diff BASE...HEAD (default origin/main) against `cargo metadata`;
                                              writes OUTDIR/integration-select.txt (cargo selection args for
                                              SERVER_RUST_NEXTEST_SELECT; empty = nothing to run),
                                              OUTDIR/integration-filter.txt (nextest `-E` expression for
                                              SERVER_RUST_NEXTEST_FILTER; empty = run all selected binaries),
                                              and OUTDIR/integration-plan.md (what was selected and why)
  precheck-integration.py selftest            fixture checks of the selection rule (no cargo, no git)

Rule (owner decision 2026-11-16):
  * Only changed server/ files that are not *.md count; none -> nothing runs (fast path).
  * server/Cargo.toml, Cargo.lock or rust-toolchain* changed -> nothing runs, noted: a
    workspace-wide change is the merge queue's job.
  * Changed packages = workspace members owning a changed file (longest manifest-dir prefix).
  * Reverse dependents: per changed package, its transitive NORMAL/BUILD reverse dependents
    (dev-dependency edges do not count) join only when there are at most MAX_RDEPS of them;
    otherwise only the changed package itself runs, noted (pg, db, contracts, authz, ...).
  * A selected package runs ALL its integration test targets (tests/*.rs), except a HEAVY one
    (setjoin-gateway; setjoin-auth) that selects at submodule granularity inside consolidated
    `tests/suite_*.rs` binaries (`#[path = "<file>.rs"] mod <stem>;`) and whole standalone
    targets, running only the units
      exact       whose own tests/<name>.rs changed (or whose suite_*.rs root changed),
      referenced  whose tests/<name>.rs names a changed tests/<dir>/ (for golden/fixtures/testdata:
                  the changed file's basename),
      matched     whose name holds a token of a changed path (or of a changed dependency crate) as
                  whole `_` words, e.g. src/chat_compliance.rs -> chat_compliance_recorded;
    over HEAVY[pkg] expanded units (a whole consolidated suite counts as its submodule count) it
    keeps exact+referenced, then exact only, then defers that package to the merge queue.
  * Over MAX_TOTAL_UNITS expanded units across all selected packages -> nothing runs, noted: a
    workspace-wide refactor is the merge queue's job (the 8-shard full lane).
  * Everything not selected stays the merge queue full lane's job.
"""
import json
import os
import re
import subprocess
import sys

MAX_RDEPS = 5
MAX_TOTAL_UNITS = 60
HEAVY = {"setjoin-gateway": 30, "setjoin-auth": 20}
WORKSPACE_WIDE = ("server/Cargo.toml", "server/Cargo.lock")
GENERIC = {"src", "tests", "lib", "main", "mod", "common", "fixtures", "golden", "goldens", "testdata",
           "support", "util", "utils", "helpers", "build", "benches", "examples", "setjoin", "crates",
           "domains", "bins", "protocols", "cargo"}
CONTAINERS = {"golden", "goldens", "fixtures", "testdata"}
SUFFIXES = ("_oracle", "_recorded", "_golden", "_goldens", "_lifetime")
NAME = re.compile(r"^[A-Za-z0-9_-]+$")
SUITE_MOD = re.compile(r'#\[path\s*=\s*"([A-Za-z0-9_-]+\.rs)"\]\s*(?:pub(?:\([^)]*\))?\s+)?mod\s+([A-Za-z0-9_]+)\s*;')


def norm(part):
    s = os.path.splitext(part)[0].replace("-", "_").lower()
    for suf in SUFFIXES:
        if s.endswith(suf) and len(s) > len(suf):
            s = s[: -len(suf)]
    return s


def tokens(parts):
    return {t for t in (norm(p) for p in parts) if len(t) >= 3 and t not in GENERIC}


def matches(target, token):
    words, want = target.split("_"), token.split("_")
    return any(words[i:i + len(want)] == want for i in range(len(words) - len(want) + 1))


def code_files(changed):
    """-> (code files, note or None); a note means nothing runs."""
    code = [f for f in changed if f.startswith("server/") and not f.endswith(".md")]
    if not code:
        return code, "no server-rust code change: no integration test selected"
    wide = sorted(f for f in code if f in WORKSPACE_WIDE or f.startswith("server/rust-toolchain"))
    if wide:
        return code, f"workspace-wide change ({', '.join(wide)}): integration tests run in the merge queue only"
    return code, None


def load(meta, root):
    pkgs = {}
    for p in meta["packages"]:
        tests = {t["name"]: os.path.relpath(t["src_path"], root) for t in p["targets"] if "test" in t["kind"]}
        deps = {d["name"] for d in p.get("dependencies", []) if d.get("path") and d.get("kind") in (None, "build")}
        pkgs[p["name"]] = {"dir": os.path.relpath(os.path.dirname(p["manifest_path"]), root), "tests": tests, "deps": deps}
    return pkgs


def expand_units(pkg_dir, tests, read):
    """Expand consolidated `suite_*` targets into (target, mod_stem, src_path) units;
    standalone targets become (target, None, src_path). Also returns {suite_target: submodule_count}."""
    units = []
    suite_weights = {}
    for target, src in sorted(tests.items()):
        if target.startswith("suite_"):
            subs = SUITE_MOD.findall(read(src))
            if subs:
                suite_weights[target] = len(subs)
                for rel_file, mod_stem in subs:
                    units.append((target, mod_stem, f"{pkg_dir}/tests/{rel_file}"))
                continue
        units.append((target, None, src))
    return units, suite_weights


def unit_weight(picked, suite_weights):
    """Count expanded test-file units: a whole consolidated suite counts as its submodule count."""
    return sum(suite_weights.get(t, 1) if m is None else 1 for t, m in picked)


def normalize_units(picked):
    """If a whole suite (target, None) is selected, drop redundant (target, mod) entries."""
    whole = {t for t, m in picked if m is None}
    return sorted({(t, m) for t, m in picked if m is None or t not in whole},
                  key=lambda item: (item[0], "" if item[1] is None else item[1]))


def select(changed, pkgs, read, heavy=None, max_total_units=None):
    """-> ({package: [(target, mod_stem_or_None)]}, [notes])"""
    heavy = HEAVY if heavy is None else heavy
    max_total = MAX_TOTAL_UNITS if max_total_units is None else max_total_units
    code, note = code_files(changed)
    if note:
        return {}, [note]
    notes = []
    owned = {}
    for f in code:
        hits = [n for n, p in pkgs.items() if f.startswith(p["dir"] + "/")]
        if hits:
            owned.setdefault(max(hits, key=lambda n: len(pkgs[n]["dir"])), []).append(f)
    rev = {}
    for n, p in pkgs.items():
        for d in p["deps"]:
            rev.setdefault(d, set()).add(n)
    chosen = {n: set() for n in owned}  # package -> tokens contributed by changed dependencies
    for c in sorted(owned):
        seen, stack = set(), [c]
        while stack:
            for r in rev.get(stack.pop(), ()):
                if r not in seen:
                    seen.add(r)
                    stack.append(r)
        seen.discard(c)
        if len(seen) > MAX_RDEPS:
            notes.append(f"{c}: {len(seen)} reverse dependents (over {MAX_RDEPS}): only {c}'s own integration tests run; the merge queue covers its dependents")
            continue
        tok = tokens([os.path.basename(pkgs[c]["dir"]), c.removeprefix("setjoin-")])
        for f in owned[c]:
            tok |= tokens(f[len(pkgs[c]["dir"]) + 1:].split("/"))
        for r in seen:
            chosen.setdefault(r, set()).update(tok)
    sel = {}
    pkg_weights = {}
    for n in sorted(chosen):
        tests = pkgs[n]["tests"]
        if not tests:
            continue
        units, suite_weights = expand_units(pkgs[n]["dir"], tests, read)
        pkg_weights[n] = suite_weights
        cap = heavy.get(n)
        if cap is None:
            sel[n] = [(t, None) for t in sorted(tests)]
            continue
        by_name = {}
        for t, m, _ in units:
            by_name.setdefault(m or t, []).append((t, m))
        exact, referenced, tok = set(), set(), set(chosen[n])
        for f in owned.get(n, []):
            rel = f[len(pkgs[n]["dir"]) + 1:].split("/")
            if rel[0] != "tests" or len(rel) < 2:
                tok |= tokens(rel)
                continue
            stem = os.path.splitext(rel[1])[0]
            if len(rel) == 2 and rel[1].endswith(".rs"):
                if stem in suite_weights:
                    exact.add((stem, None))
                elif stem in by_name:
                    exact.update(by_name[stem])
                continue
            if len(rel) > 2 and rel[1] in by_name:
                exact.update(by_name[rel[1]])
            needle = rel[-1] if (rel[1] in CONTAINERS or len(rel) == 2) else rel[1]
            pat = re.compile(r"(?<![A-Za-z0-9_.-])" + re.escape(needle) + r"(?![A-Za-z0-9_-])")
            referenced |= {(t, m) for t, m, src in units if pat.search(read(src))}
        matched = {(t, m) for t, m, _ in units if any(matches(m or t, k) for k in tok)}
        picked = normalize_units(exact | referenced | matched)
        w = unit_weight(picked, suite_weights)
        if w > cap:
            notes.append(f"{n}: {w} targets selected (over {cap}): kept only changed or referencing test files")
            picked = normalize_units(exact | referenced)
            w = unit_weight(picked, suite_weights)
            if w > cap:
                notes.append(f"{n}: {w} test files reference the changed test helpers (over {cap}): kept only the changed test files")
                picked = normalize_units(exact)
                w = unit_weight(picked, suite_weights)
                if w > cap:
                    notes.append(f"{n}: {w} changed test file(s) (over {cap}): deferred to the merge queue full lane")
                    picked = []
        if picked:
            sel[n] = picked
        elif not any(note.startswith(f"{n}:") for note in notes):
            notes.append(f"{n}: the change names no integration test target; the merge queue covers it")
    total_units = sum(unit_weight(units, pkg_weights[n]) for n, units in sel.items())
    if sel and total_units > max_total:
        pkg_count = len(sel)
        sel = {}
        notes.append(
            f"workspace-wide selection ({total_units} expanded test unit(s) across {pkg_count} package(s), over {max_total}): "
            "integration tests run in the merge queue only"
        )
    return sel, notes


def _validate_sel(sel):
    names = list(sel)
    for units in sel.values():
        for t, m in units:
            names.append(t)
            if m is not None:
                names.append(m)
    bad = [x for x in names if not NAME.match(x)]
    if bad:
        raise SystemExit(f"precheck-integration: unsafe package or target name(s): {bad}")


def cargo_args(sel):
    _validate_sel(sel)
    targets = sorted({t for units in sel.values() for t, _ in units})
    return " ".join([f"-p {n}" for n in sorted(sel)] + [f"--test {t}" for t in targets])


def nextest_filter(sel):
    """Build a nextest `-E` filter restricting consolidated suites to matched submodules
    (and preventing cross-package target-name collisions like `suite_misc`). Returns ''
    when a single package runs only whole binaries."""
    _validate_sel(sel)
    if not sel:
        return ""
    has_submod = any(m is not None for units in sel.values() for _, m in units)
    if not has_submod and len(sel) == 1:
        return ""
    clauses = []
    for pkg in sorted(sel):
        by_target = {}
        for t, m in sel[pkg]:
            by_target.setdefault(t, []).append(m)
        for t in sorted(by_target):
            mods = by_target[t]
            bid = f"binary_id(={pkg}::{t})"
            if None in mods:
                clauses.append(bid)
            else:
                mod_terms = [f"test(/^{m}::/)" for m in sorted(set(mods))]
                if len(mod_terms) == 1:
                    clauses.append(f"({bid} & {mod_terms[0]})")
                else:
                    clauses.append(f"({bid} & ({' | '.join(mod_terms)}))")
    return " | ".join(clauses)


def format_unit(unit):
    t, m = unit
    return f"{t}::{m}" if m is not None else t


def plan(outdir, base):
    root = os.getcwd()
    changed = subprocess.run(["git", "diff", "--name-only", f"{base}...HEAD"], check=True,
                             capture_output=True, text=True).stdout.splitlines()
    sel, notes = {}, []
    _, note = code_files(changed)
    if note:
        notes.append(note)
    else:
        meta = json.loads(subprocess.run(
            ["cargo", "metadata", "--locked", "--no-deps", "--format-version", "1", "--manifest-path", "server/Cargo.toml"],
            check=True, capture_output=True, text=True).stdout)

        def read(src):
            with open(os.path.join(root, src), encoding="utf-8", errors="replace") as fh:
                return fh.read()
        sel, notes = select(changed, load(meta, root), read)
    os.makedirs(outdir, exist_ok=True)
    with open(os.path.join(outdir, "integration-select.txt"), "w") as fh:
        fh.write(cargo_args(sel) + "\n" if sel else "")
    flt = nextest_filter(sel)
    with open(os.path.join(outdir, "integration-filter.txt"), "w") as fh:
        fh.write(flt + "\n" if flt else "")
    lines = [f"- integration selection: {sum(len(v) for v in sel.values())} test unit(s) in {len(sel)} package(s)"]
    for n, units in sel.items():
        labels = [format_unit(u) for u in units]
        lines.append(f"  - `{n}`: {len(units)} unit(s): {', '.join(labels[:40])}{' ...' if len(labels) > 40 else ''}")
    if flt:
        lines.append(f"- nextest filter: `{flt}`")
    lines += [f"- NOTE: {x}" for x in notes]
    with open(os.path.join(outdir, "integration-plan.md"), "w") as fh:
        fh.write("\n".join(lines) + "\n")
    print("\n".join(lines))


def selftest():
    def pkg(name, d, tests=(), deps=(), dev=()):
        return {"name": name, "manifest_path": f"/r/server/{d}/Cargo.toml",
                "targets": [{"name": "x", "kind": ["lib"], "src_path": f"/r/server/{d}/src/lib.rs"}]
                + [{"name": t, "kind": ["test"], "src_path": f"/r/server/{d}/tests/{t}.rs"} for t in tests],
                "dependencies": [{"name": x, "kind": None, "path": "p"} for x in deps]
                + [{"name": x, "kind": "dev", "path": "p"} for x in dev]}
    gw_suites = ["suite_chat", "suite_static", "suite_misc", "platform_dns"]
    meta = {"packages": [
        pkg("setjoin-pg", "crates/pg", ["suite_misc"]),
        pkg("setjoin-static", "crates/domains/static", [], ["setjoin-pg"]),
        pkg("setjoin-identity", "crates/domains/identity", ["suite_misc", "saml_acs"], ["setjoin-pg"]),
        pkg("setjoin-gateway", "bins/gateway", gw_suites, ["setjoin-pg", "setjoin-static", "setjoin-identity"]),
        pkg("setjoin-auth", "bins/auth", ["suite_auth_catalog", "suite_misc"], ["setjoin-pg", "setjoin-identity"], ["setjoin-gateway"]),
        pkg("setjoin-a", "crates/a", [], ["setjoin-pg"]), pkg("setjoin-b", "crates/b", [], ["setjoin-pg"]),
        pkg("setjoin-c", "crates/c", [], ["setjoin-pg"]),
    ]}
    pkgs = load(meta, "/r")
    gw_dir = "server/bins/gateway/tests/"
    auth_dir = "server/bins/auth/tests/"
    srcs = {
        gw_dir + "suite_chat.rs": (
            'pub mod common;\n'
            '#[path = "chat_compliance_recorded.rs"]\nmod chat_compliance_recorded;\n'
            '#[path = "compliance_recorded.rs"]\nmod compliance_recorded;\n'
        ),
        gw_dir + "suite_static.rs": (
            'pub mod common;\n'
            '#[path = "static_recorded.rs"]\nmod static_recorded;\n'
            '#[path = "identity_self_service.rs"]\nmod identity_self_service;\n'
        ),
        gw_dir + "suite_misc.rs": (
            'pub mod common;\n'
            '#[path = "golden_user.rs"]\nmod golden_user;\n'
            '#[path = "startup.rs"]\nmod startup;\n'
        ),
        gw_dir + "platform_dns.rs": "mod common;\n",
        gw_dir + "chat_compliance_recorded.rs": "use crate::common;\n",
        gw_dir + "compliance_recorded.rs": "use crate::common;\n",
        gw_dir + "static_recorded.rs": 'use crate::common;\nconst D: &str = "tests/static_oracle/cases.rs";\n',
        gw_dir + "identity_self_service.rs": "use crate::common;\n",
        gw_dir + "golden_user.rs": 'include_str!("golden/go-list-1.json");\n',
        gw_dir + "startup.rs": "use crate::common;\n",
        auth_dir + "suite_auth_catalog.rs": '#[path = "guest_invite_oracle.rs"]\nmod guest_invite_oracle;\n',
        auth_dir + "suite_misc.rs": '#[path = "startup.rs"]\nmod startup;\n',
        auth_dir + "guest_invite_oracle.rs": "use crate::common;\n",
        auth_dir + "startup.rs": "use crate::common;\n",
    }
    read = lambda src: srcs.get(src, "")
    gw = "server/bins/gateway/"
    cases = [
        ("docs-only", ["server/DOX.md", ".github/workflows/x.yml", "docs/a.md"], {}, "no server-rust code change"),
        ("workspace-wide", ["server/Cargo.lock", gw + "src/static.rs"], {}, "workspace-wide change"),
        ("domain-crate-to-gateway", ["server/crates/domains/static/src/lib.rs"],
         {"setjoin-gateway": [("suite_static", "static_recorded")]}, None),
        ("gateway-src-no-dev-edge", [gw + "src/chat_compliance.rs"],
         {"setjoin-gateway": [("suite_chat", "chat_compliance_recorded")]}, None),
        ("word-match", [gw + "src/compliance/mod.rs"],
         {"setjoin-gateway": [("suite_chat", "chat_compliance_recorded"), ("suite_chat", "compliance_recorded")]}, None),
        ("light-rdep-runs-whole", ["server/crates/domains/identity/src/login.rs"],
         {"setjoin-gateway": [("suite_static", "identity_self_service")],
          "setjoin-identity": [("saml_acs", None), ("suite_misc", None)]},
         "setjoin-auth: the change names no integration test target"),
        ("auth-heavy-path-match", ["server/crates/domains/identity/src/guest_invite.rs"],
         {"setjoin-auth": [("suite_auth_catalog", "guest_invite_oracle")],
          "setjoin-gateway": [("suite_static", "identity_self_service")],
          "setjoin-identity": [("saml_acs", None), ("suite_misc", None)]}, None),
        ("rdep-cap", ["server/crates/pg/src/lib.rs"], {"setjoin-pg": [("suite_misc", None)]}, "reverse dependents (over 5)"),
        ("exact-submod-file", [gw + "tests/startup.rs"], {"setjoin-gateway": [("suite_misc", "startup")]}, None),
        ("exact-suite-root", [gw + "tests/suite_chat.rs"], {"setjoin-gateway": [("suite_chat", None)]}, None),
        ("exact-standalone-file", [gw + "tests/platform_dns.rs"], {"setjoin-gateway": [("platform_dns", None)]}, None),
        ("referenced-dir", [gw + "tests/static_oracle/cases.rs"], {"setjoin-gateway": [("suite_static", "static_recorded")]}, None),
        ("referenced-golden", [gw + "tests/golden/go-list-1.json"], {"setjoin-gateway": [("suite_misc", "golden_user")]}, None),
        ("no-target-named", [gw + "src/lib.rs"], {}, "names no integration test target"),
        ("shared-helper-cap", [gw + "tests/common/mod.rs", gw + "tests/startup.rs"],
         {"setjoin-gateway": [("suite_misc", "startup")]}, "kept only the changed test files"),
        ("whole-suite-weight-cap", [gw + "tests/suite_chat.rs", gw + "tests/suite_static.rs"],
         {}, "deferred to the merge queue full lane"),
        ("total-units-cap", [gw + "tests/suite_chat.rs", "server/crates/domains/identity/src/login.rs"],
         {}, "workspace-wide selection"),
    ]
    fails = 0
    for name, changed, want, note in cases:
        kw = {}
        if name in ("shared-helper-cap", "whole-suite-weight-cap"):
            kw["heavy"] = {"setjoin-gateway": 3}
        if name == "total-units-cap":
            kw["max_total_units"] = 3
        got, notes = select(changed, pkgs, read, **kw)
        ok = got == want and (note is None or any(note in n for n in notes))
        print(("ok   " if ok else "FAIL ") + name + ("" if ok else f": got {got} notes {notes}"))
        fails += not ok
    args = cargo_args({"setjoin-gateway": [("suite_static", "static_recorded")], "setjoin-auth": [("suite_misc", "startup")]})
    ok = args == "-p setjoin-auth -p setjoin-gateway --test suite_misc --test suite_static"
    print(("ok   " if ok else "FAIL ") + "cargo-args" + ("" if ok else f": {args}"))
    fails += not ok
    flt_cases = [
        ("filter-single-submod",
         {"setjoin-gateway": [("suite_chat", "chat_compliance_recorded")]},
         "(binary_id(=setjoin-gateway::suite_chat) & test(/^chat_compliance_recorded::/))"),
        ("filter-multi-submod",
         {"setjoin-gateway": [("suite_chat", "chat_compliance_recorded"), ("suite_chat", "compliance_recorded")]},
         "(binary_id(=setjoin-gateway::suite_chat) & (test(/^chat_compliance_recorded::/) | test(/^compliance_recorded::/)))"),
        ("filter-cross-pkg-and-whole",
         {"setjoin-auth": [("suite_misc", "startup")], "setjoin-identity": [("saml_acs", None), ("suite_misc", None)]},
         "(binary_id(=setjoin-auth::suite_misc) & test(/^startup::/)) | binary_id(=setjoin-identity::saml_acs) | binary_id(=setjoin-identity::suite_misc)"),
        ("filter-single-pkg-whole-empty",
         {"setjoin-pg": [("suite_misc", None)]},
         ""),
    ]
    for name, sel_in, want_flt in flt_cases:
        got_flt = nextest_filter(sel_in)
        ok = got_flt == want_flt
        print(("ok   " if ok else "FAIL ") + name + ("" if ok else f": got {got_flt!r} want {want_flt!r}"))
        fails += not ok
    for bad_sel in ({"setjoin-gateway": [("x; rm -rf /", None)]}, {"setjoin-gateway": [("suite_chat", "bad;mod")]}):
        try:
            cargo_args(bad_sel)
            print(f"FAIL unsafe-name accepted: {bad_sel}")
            fails += 1
        except SystemExit:
            print("ok   unsafe-name rejected")
    return 1 if fails else 0


if __name__ == "__main__":
    if sys.argv[1:2] == ["selftest"]:
        sys.exit(selftest())
    if sys.argv[1:2] == ["plan"] and len(sys.argv) in (3, 4):
        plan(sys.argv[2], sys.argv[3] if len(sys.argv) == 4 else "origin/main")
        sys.exit(0)
    print("usage: precheck-integration.py plan OUTDIR [BASE] | selftest", file=sys.stderr)
    sys.exit(2)
