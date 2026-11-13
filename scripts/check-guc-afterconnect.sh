#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────────
# check-guc-afterconnect.sh — PERMANENT guard for the app.encryption_key
# AfterConnect wiring (Queue B item 4 — _enc GUC regression guard,
# retired-docs:superpowers/plans/archive/2026-07-04-queue-b-combined.md §4).
#
# WHY THIS EXISTS. Every `_enc` column family — S/MIME private keys
# (mailserver/internal/jmap/mail_decrypt.go), TOTP secrets
# (authserver/internal/authn/totp.go), SAML IdP certs
# (authserver/internal/federation/saml_sp.go), push tokens
# (authserver/internal/authn/push.go) — relies on ONE choke point:
# shared/pgxutil.OpenPool's AfterConnect hook, which sets app.encryption_key as
# a session GUC on every new backend connection (both mailserverd and
# authserverd call this same function; internal/db.NewPool's OWN AfterConnect
# copy is dead code, unused anywhere — the real wiring is pgxutil's alone).
# Per-family regression tests (mail_decrypt_db_test.go, totp_db_integration_test.go,
# saml_sp_guc_test.go, push_guc_test.go) prove pgp_sym_decrypt fails closed when
# the GUC is missing/wrong for each family — but none of them would explain WHY
# if the shared hook itself regressed; you'd chase it through four packages.
#
# THE GAP THIS CLOSES. shared/'s own `go test` stage only runs in the opt-in
# RACE=1 lane of scripts/test.sh ("shared/ and mailctl/ have no stage in the
# default run") — so a change that silently drops/bypasses the AfterConnect
# assignment in shared/pgxutil/pool.go would pass the DEFAULT gate undetected.
# This script runs the wiring's own regression test
# (TestOpenPool_AfterConnect_SetsEncryptionKeyGUC, shared/pgxutil/pool_test.go)
# unconditionally, via run-guards.sh's auto-discovered check-*.sh manifest —
# same enforcement path as every other structural guard in this repo.
#
# Self-test: check-guc-afterconnect-selftest.sh proves this guard actually
# FIRES by copying shared/ to a scratch dir, neutering the AfterConnect
# assignment there, and asserting the copy's test goes red — never mutates the
# real tree.
#
# guard-requires: db
# ──────────────────────────────────────────────────────────────────────────
source "$(dirname "$0")/_base.sh"

export DB_DSN="${DB_DSN:-postgres://mail@127.0.0.1:5432/mailserver_test?sslmode=disable}"
export REQUIRE_DB=1

echo "==> app.encryption_key AfterConnect guard (shared/pgxutil.OpenPool)"
(cd "$ROOT/shared" && go test ./pgxutil/... -run '^TestOpenPool_AfterConnect_SetsEncryptionKeyGUC$' -v -count=1)
