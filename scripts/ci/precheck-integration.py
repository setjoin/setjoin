#!/usr/bin/env python3
"""Integration-test selection for the PR pre-check (.github/workflows/pr-precheck.yml, job `integration`).

  precheck-integration.py plan OUTDIR [BASE]  diff BASE...HEAD (default origin/main) against `cargo metadata`;
                                              writes OUTDIR/integration-select.txt (cargo selection args for
                                              SERVER_RUST_NEXTEST_SELECT; empty = nothing to run) and
                                              OUTDIR/integration-plan.md (what was selected and why)
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
    (setjoin-gateway: ~234 targets, ~214 test-minutes; setjoin-auth: ~41 targets, a domain-crate change
    selecting all of them overran the 22-minute cap on #437) that runs only the targets
      exact       whose own tests/<name>.rs changed,
      referenced  whose tests/<name>.rs names a changed tests/<dir>/ (for golden/fixtures/testdata:
                  the changed file's basename),
      matched     whose name holds a token of a changed path (or of a changed dependency crate) as
                  whole `_` words, e.g. src/chat_compliance.rs -> chat_compliance_recorded;
    over HEAVY[pkg] targets it keeps exact+referenced, then exact only, noted.
  * Everything not selected stays the merge queue full lane's job.
"""
import json
import os
import re
import subprocess
import sys

MAX_RDEPS = 5
HEAVY = {"setjoin-gateway": 30, "setjoin-auth": 20}
WORKSPACE_WIDE = ("server/Cargo.toml", "server/Cargo.lock")
GENERIC = {"src", "tests", "lib", "main", "mod", "common", "fixtures", "golden", "goldens", "testdata",
           "support", "util", "utils", "helpers", "build", "benches", "examples", "setjoin", "crates",
           "domains", "bins", "protocols", "cargo"}
CONTAINERS = {"golden", "goldens", "fixtures", "testdata"}
SUFFIXES = ("_oracle", "_recorded", "_golden", "_goldens", "_lifetime")
NAME = re.compile(r"^[A-Za-z0-9_-]+$")


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


def select(changed, pkgs, read, heavy=None):
    """-> ({package: [test targets]}, [notes])"""
    heavy = HEAVY if heavy is None else heavy
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
    for n in sorted(chosen):
        tests = pkgs[n]["tests"]
        if not tests:
            continue
        cap = heavy.get(n)
        if cap is None:
            sel[n] = sorted(tests)
            continue
        exact, referenced, tok = set(), set(), set(chosen[n])
        for f in owned.get(n, []):
            rel = f[len(pkgs[n]["dir"]) + 1:].split("/")
            if rel[0] != "tests" or len(rel) < 2:
                tok |= tokens(rel)
                continue
            stem = os.path.splitext(rel[1])[0]
            if len(rel) == 2 and rel[1].endswith(".rs"):
                if stem in tests:
                    exact.add(stem)
                continue
            if len(rel) > 2 and rel[1] in tests:
                exact.add(rel[1])
            needle = rel[-1] if (rel[1] in CONTAINERS or len(rel) == 2) else rel[1]
            pat = re.compile(r"(?<![A-Za-z0-9_.-])" + re.escape(needle) + r"(?![A-Za-z0-9_-])")
            referenced |= {t for t, src in tests.items() if pat.search(read(src))}
        matched = {t for t in tests if any(matches(t, k) for k in tok)}
        picked = exact | referenced | matched
        if len(picked) > cap:
            notes.append(f"{n}: {len(picked)} targets selected (over {cap}): kept only changed or referencing test files")
            picked = exact | referenced
            if len(picked) > cap:
                notes.append(f"{n}: {len(picked)} test files reference the changed test helpers (over {cap}): kept only the changed test files")
                picked = exact
        if picked:
            sel[n] = sorted(picked)
        else:
            notes.append(f"{n}: the change names no integration test target; the merge queue covers it")
    return sel, notes


def cargo_args(sel):
    names = list(sel) + [t for ts in sel.values() for t in ts]
    bad = [x for x in names if not NAME.match(x)]
    if bad:
        raise SystemExit(f"precheck-integration: unsafe package or target name(s): {bad}")
    targets = sorted({t for ts in sel.values() for t in ts})
    return " ".join([f"-p {n}" for n in sorted(sel)] + [f"--test {t}" for t in targets])


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
    lines = [f"- integration selection: {sum(len(v) for v in sel.values())} test target(s) in {len(sel)} package(s)"]
    lines += [f"  - `{n}`: {len(ts)} target(s): {', '.join(ts[:40])}{' ...' if len(ts) > 40 else ''}" for n, ts in sel.items()]
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
    gw_tests = ["static_recorded", "chat_compliance_recorded", "compliance_recorded", "platform_dns",
                "identity_self_service", "golden_user", "startup"]
    meta = {"packages": [
        pkg("setjoin-pg", "crates/pg", ["pg_db"]),
        pkg("setjoin-static", "crates/domains/static", [], ["setjoin-pg"]),
        pkg("setjoin-identity", "crates/domains/identity", ["login_flow"], ["setjoin-pg"]),
        pkg("setjoin-gateway", "bins/gateway", gw_tests, ["setjoin-pg", "setjoin-static", "setjoin-identity"]),
        pkg("setjoin-auth", "bins/auth", ["guest_invite_oracle", "startup"], ["setjoin-pg", "setjoin-identity"], ["setjoin-gateway"]),
        pkg("setjoin-a", "crates/a", [], ["setjoin-pg"]), pkg("setjoin-b", "crates/b", [], ["setjoin-pg"]),
        pkg("setjoin-c", "crates/c", [], ["setjoin-pg"]),
    ]}
    pkgs = load(meta, "/r")
    srcs = {f"server/bins/gateway/tests/{t}.rs": "mod common;\n" for t in gw_tests}
    srcs["server/bins/gateway/tests/static_recorded.rs"] += 'const D: &str = "tests/static_oracle/cases.rs";\n'
    srcs["server/bins/gateway/tests/golden_user.rs"] = 'include_str!("golden/go-list-1.json");\n'
    read = lambda src: srcs.get(src, "")
    gw = "server/bins/gateway/"
    cases = [
        ("docs-only", ["server/DOX.md", ".github/workflows/x.yml", "docs/a.md"], {}, "no server-rust code change"),
        ("workspace-wide", ["server/Cargo.lock", gw + "src/static.rs"], {}, "workspace-wide change"),
        ("domain-crate-to-gateway", ["server/crates/domains/static/src/lib.rs"], {"setjoin-gateway": ["static_recorded"]}, None),
        ("gateway-src-no-dev-edge", [gw + "src/chat_compliance.rs"], {"setjoin-gateway": ["chat_compliance_recorded"]}, None),
        ("word-match", [gw + "src/compliance/mod.rs"], {"setjoin-gateway": ["chat_compliance_recorded", "compliance_recorded"]}, None),
        ("light-rdep-runs-whole", ["server/crates/domains/identity/src/login.rs"],
         {"setjoin-gateway": ["identity_self_service"], "setjoin-identity": ["login_flow"]}, "setjoin-auth: the change names no integration test target"),
        ("auth-heavy-path-match", ["server/crates/domains/identity/src/guest_invite.rs"],
         {"setjoin-auth": ["guest_invite_oracle"], "setjoin-gateway": ["identity_self_service"], "setjoin-identity": ["login_flow"]}, None),
        ("rdep-cap", ["server/crates/pg/src/lib.rs"], {"setjoin-pg": ["pg_db"]}, "reverse dependents (over 5)"),
        ("exact-test-file", [gw + "tests/startup.rs"], {"setjoin-gateway": ["startup"]}, None),
        ("referenced-dir", [gw + "tests/static_oracle/cases.rs"], {"setjoin-gateway": ["static_recorded"]}, None),
        ("referenced-golden", [gw + "tests/golden/go-list-1.json"], {"setjoin-gateway": ["golden_user"]}, None),
        ("no-target-named", [gw + "src/lib.rs"], {}, "names no integration test target"),
        ("shared-helper-cap", [gw + "tests/common/mod.rs", gw + "tests/startup.rs"], {"setjoin-gateway": ["startup"]}, "kept only the changed test files"),
    ]
    fails = 0
    for name, changed, want, note in cases:
        got, notes = select(changed, pkgs, read, heavy={"setjoin-gateway": 3} if name == "shared-helper-cap" else None)
        ok = got == want and (note is None or any(note in n for n in notes))
        print(("ok   " if ok else "FAIL ") + name + ("" if ok else f": got {got} notes {notes}"))
        fails += not ok
    args = cargo_args({"setjoin-gateway": ["static_recorded"], "setjoin-auth": ["startup"]})
    ok = args == "-p setjoin-auth -p setjoin-gateway --test startup --test static_recorded"
    print(("ok   " if ok else "FAIL ") + "cargo-args" + ("" if ok else f": {args}"))
    fails += not ok
    try:
        cargo_args({"setjoin-gateway": ["x; rm -rf /"]})
        print("FAIL unsafe-name accepted")
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
