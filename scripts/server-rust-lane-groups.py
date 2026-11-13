#!/usr/bin/env python3
"""Emit the nextest serial test-group config for the server-rust parallel lane (#550).

Every test runs in its own process with its own cloned database, so DB state is isolated.
What nextest cannot isolate is host state: fixed loopback ports, fixed docker container
names, host-network containers, fixed /tmp file names, /dev/shm fixtures and the pebble ACME
ports. This script scans every test target (following `mod x;` / `#[path]` modules and the
python/shell helpers a test names), records which host resources each binary touches, and
joins binaries that share a resource: connected components become test groups with
max-threads = 1 across all their binaries. Binaries that share nothing run in parallel.
Resources: every fixed TCP/UDP port (host-wide, whatever the address), every fixed /tmp file
name, fixed docker container names (`docker-name:<prefix>`), `shm` and `pebble`.

Docker is NOT one shared resource. A container only collides with another through its
name (or a fixed host port, which the port scan already sees), so a file that starts containers is
classified by how it names them: a literal `"--name", "gofree-x-y"` is the resource
`docker-name:gofree-x` (same prefix = same resource); a name built from the process id, a
clock reading, a counter or a free port is unique per nextest process (one process per
test) and shares nothing; a file that starts containers but shows neither is the
conservative resource `docker-unverified`, shared by all such files and by every fixed-name
file (an unresolved name could equal a fixed one). Uniqueness evidence must sit in the call that
builds the name (`format!`/f-string), not merely somewhere in the file. Splitting this way
moved ~50 mostly record-against-Go binaries out of the one serial group; daemon load and
host-network ephemeral-port picks are the residual risk the lane accepts.

Usage: server-rust-lane-groups.py [--root server-rust] [--list] > groups.toml
"""
import argparse
import json
import os
import re
import subprocess
import sys

ADDR = r'(?:127\.\d+\.\d+\.\d+|0\.0\.0\.0|localhost|\[::1?\]|::)'
PORT_RES = [
    # "127.0.0.77:53" literals, also consts
    re.compile(r'"' + ADDR + r':([1-9][0-9]{1,4})"'),
    # bind(("127.0.0.1", 7890)) / SocketAddr::from(([127,0,0,1], 7890)) / ("host", 7890)
    re.compile(r'\(\s*"?' + ADDR + r'"?\s*,\s*([1-9][0-9]{2,4})\s*\)'),
    re.compile(r'\[[0-9, ]+\]\s*,\s*([1-9][0-9]{2,4})\s*\)'),
    # bind("[::]:5071")
    re.compile(r'bind\(\s*"[^"]*:([1-9][0-9]{1,4})"'),
    # const FOO_PORT: u16 = 7880
    re.compile(r'\b(?:const|static)\s+[A-Z_]*PORT[A-Z_]*\s*:\s*u16\s*=\s*([1-9][0-9]{3,4})\b'),
]
TMP_RES = [
    re.compile(r'(/tmp/gofree[A-Za-z0-9_.-]*[A-Za-z0-9_.])(?![A-Za-z0-9_.X-]*X{6})'),
    re.compile(r'temp_dir\(\)\s*\.join\("([^"]*)"\)'),
    # fixed host paths in the checkout: result/evidence dirs, per-task tool dirs, build outputs
    re.compile(r'(test-results/gofree-[A-Za-z0-9_.-]*[A-Za-z0-9_])(?![A-Za-z0-9_.{*-])'),
    re.compile(r'(target/gofree-[A-Za-z0-9_.-]*[A-Za-z0-9_])(?![A-Za-z0-9_.{*-])'),
    re.compile(r'CARGO_TARGET_TMPDIR"\)\)?\s*\.join\("([^"{}]+)"\)'),
    # `go build -o out` / `go test -c -o out`: a fixed output file is one shared artifact
    re.compile(r'"-o"\s*,\s*"([^"{}]+)"'),
    re.compile(r'\bgo\s+(?:build|test)\b[^"\n]*?\s-o\s+([^\s"{}$]+)'),
]
SIMPLE = {
    "shm": re.compile(r'/dev/shm|GOFREE_AIRGAP_FIXTURE_ROOT'),
    "pebble": re.compile(r'PEBBLE_BIN'),
}
DOCKER = re.compile(r'"docker"|Command::new\("docker')
# the argument after `--name` (container) or `-t` (image tag): captured up to the next top-level
# comma/bracket by `arg_after`
NAME_FLAG = re.compile(r'"(?:--name|-t)"(?:\.into\(\)|\.to_string\(\)|\.to_owned\(\))?\s*,\s*')
# Per-process uniqueness evidence in the expression that builds one name: a pid, or a clock
# reading / uuid. A counter (`fetch_add`, COUNTER, NEXT) only repeats within one process, so it
# counts only together with one of those.
PID = re.compile(r'process::id\(\)|os\.getpid\(\)|\{pid\}|\$\$')
CLOCK = re.compile(r'SystemTime|as_nanos|Instant::now|Uuid::|uuid4|time\.time\(\)|time_ns\(\)')


def arg_after(text, pos):
    depth, i = 0, pos
    in_str = False
    while i < len(text):
        c = text[i]
        if in_str:
            if c == "\\":
                i += 1
            elif c == '"':
                in_str = False
        elif c == '"':
            in_str = True
        elif c in "([{":
            depth += 1
        elif c in ")]}":
            if depth == 0:
                break
            depth -= 1
        elif c == "," and depth == 0:
            break
        i += 1
    return text[pos:i].strip()


def assigned(text, ident, before=None):
    """Right-hand sides assigned to `ident` (`let name = ...;`, `name = f"..."`) as (start, rhs)."""
    rx = re.compile(r'\b' + re.escape(ident) + r'\s*(?::[^=;,(){}]+)?=\s*([^;]{0,500})(?:;|\n\s*\n)', re.S)
    return [(m.start(), m.group(1)) for m in rx.finditer(text) if before is None or m.start() < before]


IDENT = re.compile(r'\{([A-Za-z_]\w*)\}|(?<![\w."\'])([A-Za-z_]\w*)\b(?!\s*[(:!])')
SKIP = {"format", "self", "mut", "let", "into", "to_string", "to_owned", "as_str", "clone"}


def expression_unique(expr, text, at, depth=0):
    """`expr` (found at offset `at`) carries per-process evidence itself or through the binding
    each name in it had at that point: the LAST assignment before `at` wins, so a later
    `let name = "fixed"` shadows an earlier unique one (and is itself judged)."""
    if PID.search(expr) or CLOCK.search(expr):
        return True
    if depth < 2:
        # a name or image tag built from other bound names (`{prefix}-...`, `&image.0`)
        for a, b in IDENT.findall(expr):
            ident = a or b
            if ident in SKIP:
                continue
            binds = assigned(text, ident, before=at)
            if binds:
                start, rhs = binds[-1]
                if rhs.strip() != expr and expression_unique(rhs, text, start, depth + 1):
                    return True
    return False


def docker_names(text):
    """(literal fixed names, True when every non-literal name carries per-process evidence)."""
    literal, verified = [], True
    # a `--name` the matcher cannot read (`.arg("--name").arg(..)`) is unverified, not ignored
    if len(re.findall(r'"--name"', text)) > len([m for m in NAME_FLAG.finditer(text) if m.group(0).startswith('"--name"')]):
        verified = False
    for m in NAME_FLAG.finditer(text):
        expr = arg_after(text, m.end())
        if expr.strip('"').isdigit():  # `docker stop -t 10`
            continue
        lit = re.fullmatch(r'&?"([A-Za-z0-9][A-Za-z0-9._-]*)"', expr)
        if lit:
            literal.append(lit.group(1))
        elif not expression_unique(expr, text, m.start()):
            # an image tag that is a helper's parameter: its origin is the `Image(format!(..))`
            # constructors the tests build, each of which must carry the evidence
            ctors = re.findall(r'Image\(\s*format!\(([^;]*?)\)\s*\)', text)
            if not (m.group(0).startswith('"-t"') and re.fullmatch(r'&?[A-Za-z_]\w*', expr)
                    and not assigned(text, expr.lstrip("&"), before=m.start()) and ctors
                    and all(PID.search(c) or CLOCK.search(c) for c in ctors)):
                verified = False
    return literal, verified


SCRIPT = re.compile(r'([A-Za-z0-9_.-]+\.(?:py|sh))\b')
MOD = re.compile(r'(?:#\[path\s*=\s*"([^"]+)"\]\s*)?(?:pub(?:\([a-z]+\))?\s+)?mod\s+([A-Za-z0-9_]+)\s*;')


def sources(entry):
    """Entry file plus every file it pulls in through `mod x;` declarations."""
    seen, todo = set(), [entry]
    while todo:
        path = todo.pop()
        if path in seen or not os.path.isfile(path):
            continue
        seen.add(path)
        text = open(path, errors="replace").read()
        base, name = os.path.dirname(path), os.path.basename(path)
        root_like = name in ("mod.rs", "lib.rs", "main.rs") or path == entry
        moddir = base if root_like else os.path.join(base, name[:-3])
        for rel, mod in MOD.findall(text):
            if rel:
                todo.append(os.path.normpath(os.path.join(base, rel)))
            else:
                todo += [os.path.join(moddir, mod + ".rs"), os.path.join(moddir, mod, "mod.rs")]
    return seen


def with_scripts(paths, index):
    """Python/shell helpers a Rust test names (`foo.py`) run in the same process tree."""
    out = set(paths)
    for path in paths:
        for name in SCRIPT.findall(open(path, errors="replace").read()):
            out |= index.get(name, set())
    return out


def binary_id(pkg, kind, name):
    if kind == "lib":
        return pkg
    return f"{pkg}::{name}" if kind == "test" else f"{pkg}::bin/{name}"


def resources_of(paths):
    found = set()
    for path in paths:
        text = open(path, errors="replace").read()
        for label, rx in SIMPLE.items():
            if rx.search(text):
                found.add(label)
        # the shared `common/` helpers start docker only when recording against Go
        if DOCKER.search(text) and "/tests/common/" not in path:
            literal, verified = docker_names(text)
            for name in literal:
                found.add("docker-name:" + "-".join(name.split("-")[:2]))
            if literal or not verified:
                # A fixed name, or a name without per-process evidence: also the shared resource
                # of every other such file, so an unresolved name can never run beside a fixed one.
                found.add("docker-unverified")
        for rx in PORT_RES:
            found |= {f"port:{p}" for p in rx.findall(text)}
        for rx in TMP_RES:
            found |= {f"tmp:{n}" for n in rx.findall(text)}
    return found


def components(hits):
    """Union binaries that share a resource; returns a list of sorted binary-id lists."""
    parent = {}

    def find(x):
        parent.setdefault(x, x)
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    for key, res in hits.items():
        for r in res:
            parent[find(key)] = find("res:" + r)
    groups = {}
    for key in hits:
        groups.setdefault(find(key), []).append(key)
    return sorted((sorted(v) for v in groups.values()), key=lambda v: v[0])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "server-rust"))
    ap.add_argument("--list", action="store_true", help="print the groups instead of TOML")
    args = ap.parse_args()
    meta = json.loads(subprocess.check_output(
        ["cargo", "metadata", "--locked", "--offline", "--no-deps", "--format-version", "1"],
        cwd=args.root, text=True))
    index = {}
    for dirpath, dirs, files in os.walk(args.root):
        dirs[:] = [d for d in dirs if d not in ("target", ".git", "node_modules")]
        for name in files:
            if name.endswith((".py", ".sh")):
                index.setdefault(name, set()).add(os.path.join(dirpath, name))
    hits = {}
    for pkg in meta["packages"]:
        for target in pkg["targets"]:
            kind = target["kind"][0]
            if kind not in ("lib", "bin", "test"):
                continue
            res = resources_of(with_scripts(sources(target["src_path"]), index))
            if res:
                hits[binary_id(pkg["name"], kind, target["name"])] = res
    groups = components(hits)
    if args.list:
        for i, group in enumerate(groups):
            res = sorted(set().union(*(hits[k] for k in group)))
            print(f"group host-{i:02d} binaries={len(group)} resources={','.join(res)[:200]}")
            for key in group:
                print(f"   {key} {','.join(sorted(hits[key]))[:160]}")
        return 0
    print("# Generated by scripts/server-rust-lane-groups.py. Do not edit.")
    for i, group in enumerate(groups):
        name = f"host-{i:02d}"
        terms = " | ".join(f"binary_id(={key})" for key in group)
        print(f'[test-groups."@tool:lane:{name}"]')
        print("max-threads = 1")
        print()
        print("[[profile.lane.overrides]]")
        print(f"filter = '{terms}'")
        print(f"test-group = '@tool:lane:{name}'")
        print()
    print(f"# {len(hits)} binaries in {len(groups)} groups", file=sys.stderr)
    return 0


sys.exit(main())
