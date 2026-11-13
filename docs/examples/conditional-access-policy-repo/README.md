# setjoin Conditional Access — Example Policy Repo

This directory is a skeleton for managing setjoin CA policies as code.

## Structure

```
.policy/
  cookbook.json          # production-ready policy document (schemaVersion: 1)
.ci/
  conditional-access.yml # CI workflow (GitHub Actions / Gitea Actions)
.pre-commit-hooks.yaml   # pre-commit hook definitions
.gitignore
README.md
```

## Getting started

```bash
# 1. Validate the policy document offline
mailctl ca validate .policy/cookbook.json

# 2. Format it canonically
mailctl ca fmt .policy/cookbook.json > .policy/cookbook.json

# 3. Diff against your live server
mailctl ca diff -f .policy/cookbook.json

# 4. Apply (idempotent, replace mode)
mailctl ca apply -f .policy/cookbook.json

# 5. Check coverage and doctor
mailctl ca coverage --fail-on-gap
mailctl ca doctor
```

## CI/CD

Copy `.ci/conditional-access.yml` to `.github/workflows/` (GitHub) or
`.gitea/workflows/` (Gitea). Set the following secrets in your repo:

| Secret | Value |
|--------|-------|
| `MAILCTL_SERVER` | `https://mail.corp.example` |
| `MAILCTL_TOKEN` | Admin JWT from `mailctl login` |

## Pre-commit hooks

```bash
pip install pre-commit
pre-commit install
```

The hooks run `mailctl ca validate --strict` and a format-check on every
staged `.policy/*.json` file.

## Full documentation

See `docs/conditional-access.md` in the setjoin repository for:
- Concepts (named locations, auth strengths, grant types, condition keys)
- Cookbook (production-ready policy patterns)
- Safe-rollout guide (break-glass → report_only → promote)
- 等保三级 / 三权分立 compliance mapping
- Error reference (BZ080–BZ094)
