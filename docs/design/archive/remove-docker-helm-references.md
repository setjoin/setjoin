# Remove Docker Deployment & Helm References — Design Spec

**Goal:** Remove all Docker-as-deployment and Helm/Kubernetes references from docs and code, keeping only Docker test infrastructure used for E2E protocol testing.

**Principle:** The project deploys via systemd only. Docker exists solely as a test-fixture package manager (Dovecot, Postfix, OpenLDAP containers for E2E tests).

---

## Files to Delete (17 files, 2 directories)

### Docker deployment files
- `mailserver/deploy/Dockerfile.gateway` — multi-stage Alpine build for gateway
- `mailserver/deploy/Dockerfile.postgres` — custom Postgres image
- `mailserver/deploy/docker-compose.yml` — full local dev stack
- `mailserver/deploy/docker-compose.prod.yml` — production compose override
- `mailserver/deploy/docker/initdb/01-run-migrations.sh` — Docker init migration runner
- `mailserver/deploy/docker/initdb/02-seed.sql` — Docker test seed data
- `mailserver/deploy/docker/gateway-entrypoint.sh` — TLS cert generator entrypoint
- `authserver/deploy/Dockerfile` — authserver multi-stage Alpine build
- `authserver/deploy/docker-compose-auth.yaml` — standalone auth + shared PG

### Empty placeholder
- `mailserver/deploy/helm/` — empty directory, remove entirely

### Cleanup after deletion
- `mailserver/deploy/docker/initdb/` — remove empty dir
- `mailserver/deploy/docker/` — keep (still contains test-imap/, test-smtp/, test-ldap/)

---

## Files to Edit (~22 files)

### CLAUDE.md
- Line 187: Remove "Helm chart pending" from Phase 15 status

### docs/architecture.md
- Lines 133-134: Replace deployment table rows — remove Docker Compose and Kubernetes+Helm rows; systemd is the only deployment method
- Lines 358-363: Remove Dockerfile/compose/helm lines from directory tree diagram

### docs/phases.md
- Line 49: "same Docker" → "same PostgreSQL cluster"
- Line 238: Remove ClamAV docker-compose reference
- Lines 280-281: Remove Dockerfile/docker-compose phase items (H.4, H.5)
- Lines 885-886: Remove authserver Docker artifacts (31.7.1, 31.7.2)
- Line 1272: "same Docker" → "same PostgreSQL cluster"
- Line 1322: Remove "docker-compose" from prerequisites
- Lines 1366-1368: Remove docker-compose-ha.yml task (37.2.3)
- Line 1391: Remove "docker-compose" from prerequisites

### docs/specs/SECURITY.md
- Line 193: Reword ClamAV setup from Docker to systemd instructions

### docs/specs/CRASH_RECOVERY.md
- Lines 38-39: Remove Docker and Kubernetes restart policy lines; keep systemd

### docs/specs/DEPENDENCIES.md
- Lines 12-13: Remove Docker builder/runtime rows
- Lines 79-81, 100: Remove Docker Image Versions section

### docs/specs/SELLING_POINTS.md
- Line 20: Remove "scalable to 500+ with Kubernetes"
- Lines 224-225: Keep single-binary message, remove "No Docker Compose complexity" (redundant)

### docs/adr/ARCH-002-shared-db-architecture.md
- Line 52: Remove `docker compose up -d` reference

### docs/audit/benchmarks.md
- Line 37: Remove "Docker Test Infra" section header

### docs/audit/architecture-review.md
- Lines 187, 193: Remove Docker Test Infra TODO section

### scripts/dev.sh
- Rewrite to use systemd/pg_ctl/background processes instead of `docker compose up`

### mailserver/gateway/internal/config/config.go
- Line 12: Change "Docker env files, or Kubernetes secrets" → "or environment files"

### mailserver/webmail/src/routes/admin/system/+page.svelte
- Line 60: Change "Docker/systemd restarts it" → "systemd restarts it"

### mailserver/webmail/playwright.config.ts
- Line 13: Remove "Docker" from comment

### docs/design/
- Lines 51-53: Remove the "remove Docker references" TODO since this is it

---

## What Stays (test infrastructure)

These files are test fixtures, not deployment artifacts:

- `mailserver/deploy/docker-compose.test.yml`
- `mailserver/deploy/test.sh`
- `mailserver/deploy/docker/test-imap/*` (5 files)
- `mailserver/deploy/docker/test-smtp/*` (5 files)
- `mailserver/deploy/docker/test-ldap/*` (5 files)
- `mailserver/gateway/internal/testutil/docker.go`
- `mailserver/gateway/internal/testutil/docker_test.go`
- `mailserver/gateway/internal/migration/imap_client_docker_test.go`
- All `//go:build docker` or `//go:build e2e` tagged test files

---

## Verification

After changes:
1. `grep -r "docker\|Docker" docs/` should return only test-infra references
2. `grep -r "helm\|Helm" docs/ CLAUDE.md` should return zero results
3. `grep -r "kubernetes\|k8s\|Kubernetes" docs/` should return zero results
4. `bash scripts/dev.sh` should work without Docker
5. Go build: `cd mailserver/gateway && go build ./...`
6. Webmail check: `cd mailserver/webmail && npm run check`
