"""Bound every first-party instruction rail and each root-to-leaf read chain."""

import os
import sys
import tempfile
from pathlib import Path

ROOT_LIMIT, CHILD_LIMIT, CHAIN_LIMIT = 10000, 16000, 32000
# Reserved generated/dependency/cache names, not .gitignore-based exclusions.
EXCLUDED = {
    '.git', '.hg', '.svn', 'node_modules', 'vendor', 'build', 'dist', 'target',
    'test-results', 'coverage', '.cache', '__pycache__',
    '.pytest_cache', '.mypy_cache', '.ruff_cache', '.venv', 'venv', '.tox',
    '.svelte-kit', '.next', '.nuxt', '.turbo', '.gradle', '.build', 'Pods',
}
EXCLUDED_TREES = {Path('.claude/worktrees'), Path('.codex/worktrees')}  # local agent checkouts, never tracked


def audit(root):
    root = root.resolve()
    errors = []
    candidates = {Path('AGENTS.md'), Path('docs/AGENTS.md')}

    def walk_error(error):
        raise error

    try:
        for base, directories, files in os.walk(root, followlinks=False, onerror=walk_error):
            directory = Path(base)
            directories[:] = sorted(
                name for name in directories if name not in EXCLUDED
                and (directory / name).relative_to(root) not in EXCLUDED_TREES
                and not (directory / name).is_symlink()
            )
            if 'AGENTS.md' in files:
                candidates.add((directory / 'AGENTS.md').relative_to(root))
    except OSError as error:
        errors.append(f'cannot discover rails: {error}')

    def size_of(relative):
        path = root / relative
        try:
            if not path.is_file():
                errors.append(f'missing or not a regular file: {str(relative)!r}')
                return None
            try:
                path.resolve(strict=True).relative_to(root)
            except ValueError:
                errors.append(f'instruction file escapes context root: {str(relative)!r}')
                return None
            return path.stat().st_size
        except OSError as error:
            errors.append(f'cannot inspect {str(relative)!r}: {error}')
            return None

    sizes = {}
    for relative in sorted(candidates):
        size = size_of(relative)
        if size is None:
            continue
        sizes[relative] = size
        limit = ROOT_LIMIT if relative == Path('AGENTS.md') else CHILD_LIMIT
        if size > limit:
            errors.append(f'{str(relative)!r} is {size} bytes; limit is {limit}')
    largest = (0, 'AGENTS.md')
    for relative in sorted(sizes):
        directory = relative.parent
        chain = []
        while True:
            ancestor = directory / 'AGENTS.md'
            if ancestor in sizes:
                chain.append(ancestor)
            if directory == Path('.'):
                break
            directory = directory.parent
        chain.reverse()
        total = sum(sizes[item] for item in chain)
        if total > largest[0]:
            largest = (total, str(relative))
        if total > CHAIN_LIMIT:
            errors.append(f'ancestor chain ending at {str(relative)!r} is {total} bytes; '
                          f'limit is {CHAIN_LIMIT}: ' + ' -> '.join(map(str, chain)))
    return errors, len(sizes), largest


def self_test():
    # One task-owned temporary tree, cleaned on success and failure.
    with tempfile.TemporaryDirectory(prefix='sj-agent-context-budget-') as temp:
        parent = Path(temp)
        count = 0

        def case(name, sizes=None, missing=(), expected=None, prepare=None):
            nonlocal count
            count += 1
            root = parent / f'{count:02d}-{name}'
            fixtures = {'AGENTS.md': 1, 'docs/AGENTS.md': 1}
            fixtures.update(sizes or {})
            for relative, size in fixtures.items():
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b'x' * size)
            for relative in missing:
                (root / relative).unlink()
            if prepare:
                prepare(root)
            errors, _, _ = audit(root)
            if expected is None and errors:
                raise RuntimeError(f'{name}: unexpected errors: {errors}')
            if expected is not None and not any(expected in e for e in errors):
                raise RuntimeError(f'{name}: expected {expected!r}, got {errors}')

        case('baseline')
        for relative, limit in [('AGENTS.md', ROOT_LIMIT), ('docs/AGENTS.md', CHILD_LIMIT),
                                ('new/AGENTS.md', CHILD_LIMIT)]:
            case('exact-file', {relative: limit})
            case('over-file', {relative: limit + 1}, expected=relative)
        chain = {'AGENTS.md': ROOT_LIMIT, 'parent/AGENTS.md': CHILD_LIMIT,
                 'parent/gap/leaf/AGENTS.md': 6000}
        case('exact-chain', chain)
        case('over-chain', {**chain, 'parent/gap/leaf/AGENTS.md': 6001}, expected='ancestor chain')
        case('siblings', {'AGENTS.md': ROOT_LIMIT, 'left/AGENTS.md': CHILD_LIMIT,
                          'right/AGENTS.md': CHILD_LIMIT})
        for name in ['.codex', 'not-in-git', 'space and\ttab']:
            case('discovery', {f'{name}/AGENTS.md': CHILD_LIMIT + 1}, expected='limit is 16000')
        excluded = {f'nested/{name}/AGENTS.md': CHILD_LIMIT + 1 for name in EXCLUDED}
        excluded.update({f'{tree}/child/AGENTS.md': CHILD_LIMIT + 1 for tree in EXCLUDED_TREES})
        case('excluded', excluded)
        for relative in ['AGENTS.md', 'docs/AGENTS.md']:
            case('missing', missing=[relative], expected=relative)

        def internal_alias(root):
            target = root / 'shared-rail.txt'
            target.write_bytes(b'x' * (CHILD_LIMIT + 1))
            (root / 'alias').mkdir()
            (root / 'alias/AGENTS.md').symlink_to(target)

        case('internal-alias', prepare=internal_alias, expected='alias/AGENTS.md')
        outside = parent / 'external.txt'
        outside.write_bytes(b'x')

        def external_alias(root):
            (root / 'alias').mkdir()
            (root / 'alias/AGENTS.md').symlink_to(outside)

        case('external-alias', prepare=external_alias, expected='escapes context root')
        case('directory-alias', prepare=lambda root: (root / 'tool-alias').symlink_to(parent))
    print(f'agent-context-budget self-test: PASS ({count} cases)')


def main():
    if sys.argv[1:] == ['--self-test']:
        self_test()
        return 0
    if sys.argv[1:]:
        print('usage: check-agent-context-budget.sh [--self-test]', file=sys.stderr)
        return 2
    root = Path(os.environ.get('CONTEXT_BUDGET_ROOT') or Path(__file__).resolve().parent.parent)
    errors, count, largest = audit(root)
    if errors:
        for error in errors:
            print(f'agent-context-budget: {error}', file=sys.stderr)
        return 1
    print(f'agent-context-budget: {count} rails; largest chain {largest[0]} / {CHAIN_LIMIT} bytes ({largest[1]})')
    print('agent-context-budget: PASS')
    return 0


if __name__ == '__main__':
    sys.exit(main())
