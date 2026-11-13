package updater

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"setjoin.com/shared/release"
)

func TestParseIntentAcceptsSanitizedReadAndClaimShapes(t *testing.T) {
	t.Parallel()
	read := `{
      "intentId":"42","installationId":"11111111-1111-4111-8111-111111111111",
      "releaseId":"release-1","manifestDigest":"` + strings.Repeat("a", 64) + `",
      "state":"approved","stateGeneration":"7","requestedByUserId":"9",
      "approvedByUserId":null,"approvalRequestId":null,"reason":"test reason",
      "scheduleAt":null,"expiresAt":"2026-08-02T00:00:00Z","executorId":null,
      "claimedAt":null,"cancelRequestedAt":null,"completedAt":null,"result":null,
      "createdAt":"2026-08-01T00:00:00Z","updatedAt":"2026-08-01T00:00:00Z","events":[]
    }`
	intent, err := parseIntent([]byte(read))
	if err != nil {
		t.Fatal(err)
	}
	if intent.ID != "42" || intent.StateGeneration != 7 || intent.State != StateApproved {
		t.Fatalf("unexpected intent: %#v", intent)
	}
	claim := `{"intentId":"42","state":"claimed","stateGeneration":"8",` +
		`"releaseId":"release-1","manifestDigest":"` + strings.Repeat("a", 64) + `",` +
		`"recoverySetId":"11111111-1111-4111-8111-111111111111","recoverySetDigest":"` + strings.Repeat("b", 64) + `",` +
		`"leaseId":"11111111-1111-4111-8111-111111111111","replayed":false}`
	intent, err = parseIntent([]byte(claim))
	if err != nil {
		t.Fatal(err)
	}
	if intent.State != StateClaimed || intent.LeaseID == "" {
		t.Fatalf("unexpected claim: %#v", intent)
	}
}

func TestParseIntentRejectsUnknownStateFieldAndNonCanonicalID(t *testing.T) {
	t.Parallel()
	for _, raw := range []string{
		`{"intentId":"01","state":"approved","stateGeneration":"1"}`,
		`{"intentId":"1","state":"future","stateGeneration":"1"}`,
		`{"intentId":"1","state":"approved","stateGeneration":"1","credential":"secret"}`,
		`{"intentId":"1","state":"approved","stateGeneration":"1","releaseId":"bad/release"}`,
		`{"intentId":"1","state":"approved","stateGeneration":"1","manifestDigest":"` + strings.Repeat("A", 64) + `"}`,
		`{"intentId":"1","state":"approved","stateGeneration":"1","recoverySetId":"not-a-uuid","recoverySetDigest":"` + strings.Repeat("a", 64) + `"}`,
		`{"intentId":"1","state":"claimed","stateGeneration":"1","leaseId":"not-a-uuid"}`,
	} {
		if _, err := parseIntent([]byte(raw)); err == nil {
			t.Fatalf("invalid intent accepted: %s", raw)
		}
	}
}

func updaterTestDSN(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("DB_DSN")
	if dsn == "" {
		if os.Getenv("REQUIRE_DB") != "" {
			t.Fatal("DB_DSN is unset while REQUIRE_DB is set")
		}
		t.Skip("DB_DSN not set")
	}
	return dsn
}

func seedUpgradeIntent(t *testing.T, conn *pgx.Conn, state State, generation int64, executor string, lease uuid.UUID) int64 {
	t.Helper()
	ctx := context.Background()
	suffix := strings.ToLower(strings.ReplaceAll(uuid.NewString(), "-", ""))
	releaseID := "go-updater-" + suffix
	challengeID := uuid.New()
	elevationID := uuid.New()
	requestID := uuid.New()
	var userID int64
	if err := conn.QueryRow(ctx, `SELECT id FROM public.users ORDER BY id LIMIT 1`).Scan(&userID); err != nil {
		t.Fatal(err)
	}
	var installationID, timelineID uuid.UUID
	var catalogGeneration, policyGeneration int64
	if err := conn.QueryRow(ctx, `SELECT installation_id,timeline_id,catalog_generation,policy_generation FROM public.upgrade_control_state WHERE singleton`).Scan(&installationID, &timelineID, &catalogGeneration, &policyGeneration); err != nil {
		t.Fatal(err)
	}
	digest := suffix + suffix
	recoverySetID := uuid.New()
	if _, err := conn.Exec(ctx, `INSERT INTO public.upgrade_release_catalog(
		release_id,version,channel,platform,architecture,manifest_digest,manifest,
		metadata_version,catalog_generation,verified_by_key_ids,verified_at,metadata_expires_at
	) VALUES($1,'2.1.0','community','linux','amd64',decode($2,'hex'),'{}',1,$3,ARRAY['test-key'],statement_timestamp(),statement_timestamp()+interval '1 day')`, releaseID, digest, catalogGeneration); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(ctx, `INSERT INTO public.upgrade_readiness(
		release_id,manifest_digest,readiness_generation,status,source_version,
		source_schema_version,target_schema_version,checks,blocker_count,expires_at,checked_by_user_id
	) VALUES($1,decode($2,'hex'),1,'ready','2.0.0',178,178,'{}',0,statement_timestamp()+interval '1 day',$3)`, releaseID, digest, userID); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(ctx, `INSERT INTO public.upgrade_recovery_sets(
		recovery_set_id,installation_id,timeline_id,source_release_id,schema_version,
		manifest_digest,status,checks,created_at,expires_at,recorded_by_user_id
	) VALUES($1,$2,$3,$4,178,decode($5,'hex'),'verified',
		'{"database":true,"databaseRestoreList":true,"blobs":true,"configuration":true,"protectedKey":true,"featureToggles":true,"hmac":true}',
		statement_timestamp(),statement_timestamp()+interval '23 hours',$6)`,
		recoverySetID, installationID, timelineID, releaseID, digest, userID); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(ctx, `INSERT INTO public.upgrade_challenges(
		id,actor_user_id,release_id,preview_digest,readiness_generation,policy_generation,
		expires_at,completed_at,elevation_id,idempotency_key,request_digest
	) VALUES($1,$2,$3,decode($4,'hex'),1,$5,statement_timestamp()+interval '4 minutes',statement_timestamp(),$6,$7,decode($4,'hex'))`, challengeID, userID, releaseID, digest, policyGeneration, elevationID, requestID); err == nil {
		t.Fatal("cyclic challenge unexpectedly inserted before elevation")
	}
	if _, err := conn.Exec(ctx, `INSERT INTO public.upgrade_challenges(
		id,actor_user_id,release_id,preview_digest,readiness_generation,policy_generation,
		expires_at,idempotency_key,request_digest
	) VALUES($1,$2,$3,decode($4,'hex'),1,$5,statement_timestamp()+interval '4 minutes',$6,decode($4,'hex'))`, challengeID, userID, releaseID, digest, policyGeneration, requestID); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(ctx, `INSERT INTO public.upgrade_elevations(
		id,actor_user_id,challenge_id,release_id,preview_digest,readiness_generation,
		policy_generation,session_digest,factor_digest,amr,acr,expires_at,request_digest
	) VALUES($1,$2,$3,$4,decode($5,'hex'),1,$6,decode($5,'hex'),decode($5,'hex'),ARRAY['pwd','totp'],'urn:setjoin:aal2',statement_timestamp()+interval '4 minutes',decode($5,'hex'))`, elevationID, userID, challengeID, releaseID, digest, policyGeneration); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(ctx, `UPDATE public.upgrade_challenges SET completed_at=statement_timestamp(),elevation_id=$2 WHERE id=$1`, challengeID, elevationID); err != nil {
		t.Fatal(err)
	}
	var intentID int64
	if err := conn.QueryRow(ctx, `INSERT INTO public.upgrade_intents(
		installation_id,release_id,manifest_digest,catalog_generation,readiness_generation,
		policy_generation,preview_digest,state,state_generation,requested_by_user_id,
		requester_elevation_id,approved_by_user_id,reason,expires_at,idempotency_key,
		request_digest,recovery_set_id,recovery_set_digest,executor_id,lease_id,claimed_at
	) VALUES($1,$2,decode($3,'hex'),$4,1,$5,decode($3,'hex'),$6,$7,$8,$9,$8,
		'integration updater execution',$10,$11,decode($3,'hex'),$12,decode($3,'hex'),NULLIF($13,''),$14,
		CASE WHEN $13='' THEN NULL ELSE statement_timestamp() END) RETURNING id`,
		installationID, releaseID, digest, catalogGeneration, policyGeneration, state,
		generation, userID, elevationID, time.Now().Add(time.Hour), uuid.New(), recoverySetID, executor,
		func() any {
			if executor == "" {
				return nil
			}
			return lease
		}()).Scan(&intentID); err != nil {
		t.Fatal(err)
	}
	return intentID
}

func TestPGControlPlaneTransactionLifecycleAndReplay(t *testing.T) {
	dsn := updaterTestDSN(t)
	ctx := context.Background()
	admin, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close(ctx)
	if _, err := admin.Exec(ctx, `UPDATE public.upgrade_intents
		SET state='failed',completed_at=statement_timestamp(),result='{"testCleanup":true}'::jsonb
		WHERE release_id LIKE 'go-updater-%'
		  AND state NOT IN ('verified','rolled_back','failed','recovery_required','cancelled','expired')`); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Exec(ctx, `UPDATE public.feature_toggles SET enabled=true WHERE key='feature.transactional_upgrades_execution'`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = admin.Exec(context.Background(), `UPDATE public.feature_toggles SET enabled=false WHERE key='feature.transactional_upgrades_execution'`)
	})

	id := seedUpgradeIntent(t, admin, StateApproved, 1, "", uuid.Nil)
	control, err := OpenPGControlPlane(ctx, "  "+dsn+"  ")
	if err != nil {
		t.Fatal(err)
	}
	defer control.Close(ctx)
	if err := control.TryInstallationLock(ctx); err != nil {
		t.Fatal(err)
	}
	if err := control.TryInstallationLock(ctx); err != nil {
		t.Fatal(err)
	}
	second, err := OpenPGControlPlane(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close(ctx)
	if err := second.TryInstallationLock(ctx); !errors.Is(err, ErrInstallationLocked) {
		t.Fatalf("second lock=%v", err)
	}

	intent, err := control.ReadLatest(ctx)
	if err != nil || intent == nil || intent.ID != stringID(id) {
		t.Fatalf("intent=%#v err=%v", intent, err)
	}
	identity, err := control.RecoveryIdentity(ctx)
	if err != nil || identity.InstallationID == "" || identity.TimelineID == "" {
		t.Fatalf("recovery identity=%#v err=%v", identity, err)
	}
	var wantInstallation, wantTimeline string
	if err := admin.QueryRow(ctx, `SELECT installation_id::text,timeline_id::text FROM public.upgrade_control_state WHERE singleton`).Scan(&wantInstallation, &wantTimeline); err != nil {
		t.Fatal(err)
	}
	if identity.InstallationID != wantInstallation || identity.TimelineID != wantTimeline {
		t.Fatalf("recovery identity=%#v want installation=%s timeline=%s", identity, wantInstallation, wantTimeline)
	}
	lease := uuid.New()
	claimed, err := control.Claim(ctx, intent, "go-updater", lease.String())
	if err != nil || claimed.State != StateClaimed || claimed.StateGeneration != 2 {
		t.Fatalf("claim=%#v err=%v", claimed, err)
	}
	replayedClaim, err := control.Claim(ctx, intent, "go-updater", lease.String())
	if err != nil || replayedClaim.ReleaseID != intent.ReleaseID ||
		replayedClaim.ManifestDigest != intent.ManifestDigest ||
		replayedClaim.RecoverySetID != intent.RecoverySetID ||
		replayedClaim.RecoverySetDigest != intent.RecoverySetDigest {
		t.Fatalf("claim replay authority=%#v err=%v", replayedClaim, err)
	}
	tampered := *intent
	tampered.ReleaseID = "different-valid-release"
	if _, err := control.Claim(ctx, &tampered, "go-updater", lease.String()); err == nil {
		t.Fatal("claim response mismatch was hidden by caller-owned authority")
	}
	progress := Event{IntentID: claimed.ID, ReleaseID: claimed.ReleaseID, ManifestDigest: claimed.ManifestDigest, ExecutorID: "go-updater", LeaseID: lease.String(), State: StatePreflight, StateGeneration: 3, Evidence: json.RawMessage(`{"probe":"ok"}`)}
	progress.Hash = strings.Repeat("b", 64)
	generation, replayed, err := control.Progress(ctx, progress, StatePreflight, progress.Evidence)
	if err != nil || replayed || generation != 3 {
		t.Fatalf("progress=%d,%t,%v", generation, replayed, err)
	}
	generation, replayed, err = control.Progress(ctx, progress, StatePreflight, progress.Evidence)
	if err != nil || !replayed || generation != 3 {
		t.Fatalf("progress replay=%d,%t,%v", generation, replayed, err)
	}
	terminal := Event{IntentID: claimed.ID, ReleaseID: claimed.ReleaseID, ManifestDigest: claimed.ManifestDigest, ExecutorID: "go-updater", LeaseID: lease.String(), State: StateFailed, StateGeneration: 4, Evidence: json.RawMessage(`{"summary":"fixture"}`)}
	terminal.Hash = strings.Repeat("c", 64)
	generation, replayed, err = control.Complete(ctx, terminal, StateFailed, terminal.Evidence)
	if err != nil || replayed || generation != 4 {
		t.Fatalf("complete=%d,%t,%v", generation, replayed, err)
	}

	if _, err := admin.Exec(ctx, `UPDATE public.upgrade_intents SET state='recovery_required',state_generation=5,completed_at=NULL,result=NULL WHERE id=$1`, id); err != nil {
		t.Fatal(err)
	}
	recovery := Event{IntentID: claimed.ID, ReleaseID: claimed.ReleaseID, ManifestDigest: claimed.ManifestDigest, ExecutorID: "go-updater", LeaseID: lease.String(), State: StateRolledBack, StateGeneration: 6, Evidence: json.RawMessage(`{"recovery":"verified"}`)}
	recovery.Hash = strings.Repeat("d", 64)
	generation, replayed, err = control.Recover(ctx, recovery, recovery.Evidence)
	if err != nil || replayed || generation != 6 {
		t.Fatalf("recover=%d,%t,%v", generation, replayed, err)
	}
	generation, replayed, err = control.Recover(ctx, recovery, recovery.Evidence)
	if err != nil || !replayed || generation != 6 {
		t.Fatalf("recover replay=%d,%t,%v", generation, replayed, err)
	}
}

func TestPGControlPlaneInputAndConnectionFailures(t *testing.T) {
	ctx := context.Background()
	if _, err := OpenPGControlPlane(ctx, "postgres://127.0.0.1:1/nope?connect_timeout=1"); !errors.Is(err, ErrControlPlaneUnavailable) {
		t.Fatalf("connect error=%v", err)
	}
	var nilControl *PGControlPlane
	if err := nilControl.Close(ctx); err != nil {
		t.Fatal(err)
	}
	control := &PGControlPlane{}
	badIntent := &Intent{ID: "01", StateGeneration: 1}
	if _, err := control.Claim(ctx, badIntent, "executor", uuid.NewString()); err == nil {
		t.Fatal("bad intent id accepted")
	}
	badIntent.ID = "1"
	if _, err := control.Claim(ctx, badIntent, "executor", "not-uuid"); err == nil {
		t.Fatal("bad lease accepted")
	}
	for _, event := range []Event{
		{IntentID: "01", LeaseID: uuid.NewString(), StateGeneration: 2},
		{IntentID: "1", LeaseID: "bad", StateGeneration: 2},
		{IntentID: "1", LeaseID: uuid.NewString(), StateGeneration: 1},
	} {
		if _, _, err := control.Progress(ctx, event, StatePreflight, json.RawMessage(`{}`)); err == nil {
			t.Fatal("bad progress event accepted")
		}
		if _, _, err := control.Recover(ctx, event, json.RawMessage(`{}`)); err == nil {
			t.Fatal("bad recovery event accepted")
		}
	}
	if _, err := parseIntent([]byte(`null`)); err == nil {
		t.Fatal("null intent accepted by parser")
	}
	for _, value := range []string{"", "0", "-1", "01", "x"} {
		if _, err := positiveInt64(value); err == nil {
			t.Fatalf("identifier %q accepted", value)
		}
	}
	for _, value := range []int64{0, -1} {
		if _, err := generationFromDatabase(value); err == nil {
			t.Fatalf("database generation %d accepted", value)
		}
	}
	if value, err := generationFromDatabase(1<<63 - 1); err != nil || value != maxStateGeneration {
		t.Fatalf("max database generation=%d err=%v", value, err)
	}
	for _, value := range []uint64{0, maxStateGeneration + 1} {
		if _, err := generationForDatabase(value); err == nil {
			t.Fatalf("journal generation %d accepted", value)
		}
	}
	if value, err := generationForDatabase(maxStateGeneration); err != nil || value != 1<<63-1 {
		t.Fatalf("max journal generation=%d err=%v", value, err)
	}
}

func stringID(id int64) string { return fmt.Sprintf("%d", id) }

func TestPGMigrationConnectionAppliesAndReadsEvidence(t *testing.T) {
	dsn := updaterTestDSN(t)
	ctx := context.Background()
	db, err := OpenPGMigrationConnection(ctx, "  "+dsn+"  ")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close(ctx)
	version, err := db.CurrentVersion(ctx)
	if err != nil || version < 178 {
		t.Fatalf("version=%d err=%v", version, err)
	}
	if evidence, err := db.Evidence(ctx, version+1000); err != nil || evidence != nil {
		t.Fatalf("evidence=%#v err=%v", evidence, err)
	}
	next := version + 1
	migration := release.Migration{ID: "go-migration-" + uuid.NewString(), FromSchema: version, ToSchema: next, SHA256: strings.Repeat("b", 64)}
	evidence := MigrationEvidence{Version: next, ReleaseID: "go-release", ManifestDigest: strings.Repeat("a", 64), MigrationID: migration.ID, SHA256: migration.SHA256}
	badEvidence := evidence
	badEvidence.ReleaseID = "/"
	sql := fmt.Sprintf(`INSERT INTO public.schema_migrations (version,applied_at) VALUES (%d,now())`, next)
	if err := db.Apply(ctx, migration, sql, badEvidence); err == nil {
		t.Fatal("invalid evidence insert accepted")
	}
	if got, _ := db.CurrentVersion(ctx); got != version {
		t.Fatalf("failed apply leaked version %d", got)
	}
	if err := db.Apply(ctx, migration, `SELECT 1`, evidence); err == nil {
		t.Fatal("version mismatch accepted")
	}
	if err := db.Apply(ctx, migration, `SELECT * FROM definitely_missing_upgrade_relation`, evidence); err == nil {
		t.Fatal("invalid SQL accepted")
	}
	if err := db.Apply(ctx, migration, sql, evidence); err != nil {
		t.Fatal(err)
	}
	got, err := db.Evidence(ctx, next)
	if err != nil || got == nil || *got != evidence {
		t.Fatalf("evidence=%#v err=%v", got, err)
	}
	admin, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close(ctx)
	if _, err := admin.Exec(ctx, `DELETE FROM public.upgrade_schema_migration_evidence WHERE schema_version=$1`, next); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Exec(ctx, `DELETE FROM public.schema_migrations WHERE version=$1`, next); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := db.CurrentVersion(ctx); err == nil {
		t.Fatal("closed migration connection remained usable")
	}
	var nilMigration *PGMigrationConnection
	if err := nilMigration.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenPGMigrationConnection(ctx, "postgres://127.0.0.1:1/nope?connect_timeout=1"); err == nil {
		t.Fatal("unreachable migration database opened")
	}
}
