package mdm

// L2-C1 (astra-proposal-c1-mdm-r5) — ResolveMAMPolicy fail-closed suite.
//
// Binding contract (manifest r3 audit spec as corrected by r4 item 4): on ANY
// group-load, query, rows-scan or iteration error the resolution ABORTS — the
// caller gets (nil, error) and the affected enforcement/check-in fails closed.
// A restrictive layer is never skipped and an empty map is never substituted
// for a failed load (the two formerly-swallowed paths: `continue` on the group
// layer and `perDevice = map[string]string{}` on the per-device layer). The
// slog.Warn abort telemetry is explicitly UNOBSERVABLE best-effort — the
// binding outcome is the (nil, error) return itself, proven here with a
// failing sink.
//
// Error injection uses shadow schemas (search_path pointed at per-test fixture
// tables/views), the same technique the admin package's list-scan tests use:
// real queries run against hostile shapes, so query/scan/iteration failures
// are the genuine pgx paths, not mocks.

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// openMAMPolicyFixturePool creates a per-test shadow schema holding setupSQL
// and returns a pool whose connections default to it (public stays visible
// behind it, so users/domains resolve if a fixture needs them).
//
// FIXTURE SHAPE CONTRACT: the shadow device_policy / device_policy_groups
// relations must mirror the production relations' columns that loadPolicyLayer
// touches — including updated_at, which D-MAILSERVER-INTERNAL-MDM-011's
// deterministic dedup orders every layer by (updated_at DESC, id DESC). A
// shadow shape missing it fails the layer query with SQLSTATE 42703 BEFORE the
// planted failure can fire, turning every fixture into an accidental
// query-error test.
func openMAMPolicyFixturePool(t *testing.T, setupSQL string) *pgxpool.Pool {
	t.Helper()
	dsn := mdmScopeTestDSN(t)

	adminPool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatalf("pgxpool.New (fixture admin pool): %v", err)
	}
	t.Cleanup(adminPool.Close)

	schema := fmt.Sprintf("mam_policy_test_%d", time.Now().UnixNano())
	if _, err := adminPool.Exec(context.Background(), `CREATE SCHEMA `+schema); err != nil {
		t.Fatalf("create fixture schema: %v", err)
	}
	t.Cleanup(func() {
		_, _ = adminPool.Exec(context.Background(), `DROP SCHEMA IF EXISTS `+schema+` CASCADE`)
	})

	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatalf("parse DSN: %v", err)
	}
	cfg.MaxConns = 1
	cfg.AfterConnect = func(ctx context.Context, conn *pgx.Conn) error {
		_, err := conn.Exec(ctx, `SET search_path=`+schema+`,public`)
		return err
	}
	shadowPool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatalf("open fixture pool: %v", err)
	}
	t.Cleanup(shadowPool.Close)

	if _, err := adminPool.Exec(context.Background(), strings.ReplaceAll(setupSQL, "__SCHEMA__", schema)); err != nil {
		t.Fatalf("create policy fixture: %v", err)
	}
	return shadowPool
}

// mamFailingSink is a slog handler whose sink ALWAYS fails — the honest model
// of unobservable telemetry: the resolver cannot detect it and must not
// change its outcome because of it.
type mamFailingSink struct{}

func (mamFailingSink) Enabled(context.Context, slog.Level) bool { return true }
func (mamFailingSink) Handle(context.Context, slog.Record) error {
	return errors.New("planted sink failure")
}
func (s mamFailingSink) WithAttrs([]slog.Attr) slog.Handler { return s }
func (s mamFailingSink) WithGroup(string) slog.Handler      { return s }

// withFailingSlogSink installs mamFailingSink as the default logger for the
// test and restores the previous default on cleanup.
func withFailingSlogSink(t *testing.T) {
	t.Helper()
	prev := slog.Default()
	slog.SetDefault(slog.New(mamFailingSink{}))
	t.Cleanup(func() { slog.SetDefault(prev) })
}

// TestResolveMAMPolicy_QueryErrorAbortsClosed: a query error on the first
// layer aborts with (nil, error) — a closed pool is the genuine query-failure
// path (pgx.ErrClosedPool), no mocks.
func TestResolveMAMPolicy_QueryErrorAbortsClosed(t *testing.T) {
	pool := mdmScopeTestPool(t)
	pool.Close()

	policy, err := ResolveMAMPolicy(context.Background(), pool, 1, nil)
	if err == nil {
		t.Fatal("query error returned a nil error — resolution did not abort")
	}
	if policy != nil {
		t.Fatalf("query error returned a policy %+v — the caller would enforce a weaker-but-successful policy", policy)
	}
}

// TestResolveMAMPolicy_GroupLoadErrorAbortsClosed is THE regression: a group
// layer failure (a device_policy_groups view whose scan raises — query error
// and iteration error in one genuine path) used to be `continue`d, dropping
// every group restriction and returning a weaker-but-successful policy. It
// must now abort with (nil, error).
func TestResolveMAMPolicy_GroupLoadErrorAbortsClosed(t *testing.T) {
	shadowPool := openMAMPolicyFixturePool(t, `
		CREATE TABLE __SCHEMA__.device_policy(
			id bigint, device_id bigint, policy_key text, policy_value text,
			updated_at timestamptz DEFAULT now());
		INSERT INTO __SCHEMA__.device_policy VALUES(1, NULL, 'global_pin', 'true', now());
		CREATE FUNCTION __SCHEMA__.mam_group_failure() RETURNS text
		LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'planted group failure'; END $$;
		CREATE VIEW __SCHEMA__.device_policy_groups AS
			SELECT __SCHEMA__.mam_group_failure() AS policy_key,
			       'x' AS policy_value,
			       'department' AS group_type,
			       1::bigint AS group_id,
			       1::bigint AS id,
			       now() AS updated_at;`)

	policy, err := ResolveMAMPolicy(context.Background(), shadowPool, 42, map[string]int64{"department": 1})
	if err == nil {
		t.Fatal("group-load error returned a nil error — the restrictive group layer was skipped")
	}
	if policy != nil {
		t.Fatalf("group-load error returned a policy %+v — weaker-but-successful", policy)
	}
	if !strings.Contains(err.Error(), "planted group failure") {
		t.Errorf("abort error = %v, want the underlying group-load failure", err)
	}
}

// TestResolveMAMPolicy_GroupLoadErrorAbortsClosed_FailingSink proves the
// BINDING outcome contract: with the telemetry sink itself failing (slog
// cannot report its own failure), the resolver STILL returns (nil, error).
func TestResolveMAMPolicy_GroupLoadErrorAbortsClosed_FailingSink(t *testing.T) {
	withFailingSlogSink(t)

	shadowPool := openMAMPolicyFixturePool(t, `
		CREATE TABLE __SCHEMA__.device_policy(
			id bigint, device_id bigint, policy_key text, policy_value text,
			updated_at timestamptz DEFAULT now());
		INSERT INTO __SCHEMA__.device_policy VALUES(1, NULL, 'global_pin', 'true', now());
		CREATE FUNCTION __SCHEMA__.mam_group_failure() RETURNS text
		LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'planted group failure'; END $$;
		CREATE VIEW __SCHEMA__.device_policy_groups AS
			SELECT __SCHEMA__.mam_group_failure() AS policy_key,
			       'x' AS policy_value,
			       'department' AS group_type,
			       1::bigint AS group_id,
			       1::bigint AS id,
			       now() AS updated_at;`)

	policy, err := ResolveMAMPolicy(context.Background(), shadowPool, 42, map[string]int64{"department": 1})
	if err == nil || policy != nil {
		t.Fatalf("failing sink downgraded the abort outcome: policy=%v err=%v, want (nil, error)", policy, err)
	}
}

// TestResolveMAMPolicy_ScanErrorAbortsClosed: a rows-scan error (policy_value
// of a type pgx cannot scan into string) aborts the global layer with
// (nil, error).
func TestResolveMAMPolicy_ScanErrorAbortsClosed(t *testing.T) {
	shadowPool := openMAMPolicyFixturePool(t, `
		CREATE TABLE __SCHEMA__.device_policy(
			id bigint, device_id bigint, policy_key text, policy_value integer[],
			updated_at timestamptz DEFAULT now());
		INSERT INTO __SCHEMA__.device_policy VALUES(1, NULL, 'global_pin', '{1,2}', now());`)

	policy, err := ResolveMAMPolicy(context.Background(), shadowPool, 1, nil)
	if err == nil {
		t.Fatal("scan error returned a nil error — resolution did not abort")
	}
	if policy != nil {
		t.Fatalf("scan error returned a policy %+v", policy)
	}
}

// TestResolveMAMPolicy_PerDeviceErrorAbortsClosed proves the per-device layer
// no longer substitutes an EMPTY map for a failed load: the global layer
// succeeds (no global rows → no scan contact with the hostile column), the
// per-device row (device_id = 42) fails to scan, and the resolution must
// abort instead of returning the global layer as a weaker-but-successful
// policy.
func TestResolveMAMPolicy_PerDeviceErrorAbortsClosed(t *testing.T) {
	shadowPool := openMAMPolicyFixturePool(t, `
		CREATE TABLE __SCHEMA__.device_policy(
			id bigint, device_id bigint, policy_key text, policy_value integer[],
			updated_at timestamptz DEFAULT now());
		INSERT INTO __SCHEMA__.device_policy VALUES(1, 42, 'device_pin', '{1,2}', now());`)

	policy, err := ResolveMAMPolicy(context.Background(), shadowPool, 42, nil)
	if err == nil {
		t.Fatal("per-device load error returned a nil error — an empty map was substituted for the failed layer")
	}
	if policy != nil {
		t.Fatalf("per-device load error returned a policy %+v — weaker-but-successful", policy)
	}
}

// TestResolveMAMPolicy_IterationErrorAbortsClosed: a global-layer view whose
// scan raises (the genuine rows.Err() iteration failure path) aborts closed.
func TestResolveMAMPolicy_IterationErrorAbortsClosed(t *testing.T) {
	shadowPool := openMAMPolicyFixturePool(t, `
		CREATE FUNCTION __SCHEMA__.mam_global_failure() RETURNS text
		LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'planted iteration failure'; END $$;
		CREATE VIEW __SCHEMA__.device_policy AS
			SELECT __SCHEMA__.mam_global_failure() AS policy_key,
			       'x' AS policy_value,
			       NULL::bigint AS device_id,
			       1::bigint AS id,
			       now() AS updated_at;`)

	policy, err := ResolveMAMPolicy(context.Background(), shadowPool, 1, nil)
	if err == nil {
		t.Fatal("iteration error returned a nil error — resolution did not abort")
	}
	if policy != nil {
		t.Fatalf("iteration error returned a policy %+v", policy)
	}
}

// TestResolveMAMPolicy_PositiveResolution is the required positive arm: with
// global, group AND per-device layers present, resolution succeeds and the
// merge precedence is per-device > group > global, with the version equal to
// the summed layer counts.
func TestResolveMAMPolicy_PositiveResolution(t *testing.T) {
	shadowPool := openMAMPolicyFixturePool(t, `
		CREATE TABLE __SCHEMA__.device_policy(
			id bigint, device_id bigint, policy_key text, policy_value text,
			updated_at timestamptz DEFAULT now());
		INSERT INTO __SCHEMA__.device_policy VALUES
			(1, NULL, 'global_pin', 'true', now()),
			(2, NULL, 'shared',     'global', now());
		CREATE TABLE __SCHEMA__.device_policy_groups(
			id bigint, policy_key text, policy_value text, group_type text, group_id bigint,
			updated_at timestamptz DEFAULT now());
		INSERT INTO __SCHEMA__.device_policy_groups VALUES
			(1, 'group_pin', 'eight', 'department', 5, now()),
			(2, 'shared',    'group', 'department', 5, now());
		INSERT INTO __SCHEMA__.device_policy VALUES
			(3, 77, 'shared',     'device', now()),
			(4, 77, 'device_only', '1', now());`)

	policy, err := ResolveMAMPolicy(context.Background(), shadowPool, 77, map[string]int64{"department": 5})
	if err != nil {
		t.Fatalf("positive resolution failed: %v", err)
	}
	if policy == nil {
		t.Fatal("positive resolution returned a nil policy")
	}
	want := map[string]string{
		"global_pin":  "true",
		"group_pin":   "eight",
		"shared":      "device", // per-device overrides group overrides global
		"device_only": "1",
	}
	for k, v := range want {
		if got := policy.Policies[k]; got != v {
			t.Errorf("merged policy %q = %q, want %q", k, got, v)
		}
	}
	if len(policy.Policies) != len(want) {
		t.Errorf("merged policy has %d entries, want %d: %+v", len(policy.Policies), len(want), policy.Policies)
	}
	if policy.Version != 6 { // 2 global + 2 group + 2 per-device rows
		t.Errorf("policy version = %d, want 6 (summed layer counts)", policy.Version)
	}
}
