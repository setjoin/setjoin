\set ON_ERROR_STOP on
\pset pager off
\timing off

BEGIN;
SET LOCAL statement_timeout = '120s';
SET LOCAL lock_timeout = '10s';

CREATE TEMP TABLE drive_acl_benchmark_results (
  metric text NOT NULL,
  sample integer NOT NULL,
  elapsed_ms double precision NOT NULL,
  PRIMARY KEY (metric, sample)
) ON COMMIT DROP;

SELECT mk_account('drive-acl-bench-owner') AS owner_mailbox_id \gset
SELECT user_id AS owner_user_id FROM mailboxes WHERE id = :owner_mailbox_id \gset
SELECT drive_space_create(:owner_user_id, 'Drive ACL benchmark', 'regular') AS space_id \gset
SELECT drive_node_create(:owner_user_id, :space_id, NULL, 'folder', 'source') AS source_id \gset
SELECT drive_node_create(:owner_user_id, :space_id, NULL, 'folder', 'destination') AS destination_id \gset

-- A 10k-node flat subtree exercises the closure rewrite without spending the
-- benchmark on fixture construction through 10k audited API calls.
CREATE TEMP TABLE drive_acl_benchmark_nodes(id bigint PRIMARY KEY) ON COMMIT DROP;
WITH inserted AS (
  INSERT INTO drive_nodes(space_id,parent_id,kind,name,created_by)
  SELECT :space_id, :source_id, 'folder', 'bench-child-' || lpad(g::text,5,'0'), :owner_user_id
    FROM generate_series(1,10000) AS g
  RETURNING id
)
INSERT INTO drive_acl_benchmark_nodes SELECT id FROM inserted;
INSERT INTO drive_node_closure(space_id,ancestor_id,descendant_id,depth)
SELECT :space_id,id,id,0 FROM drive_acl_benchmark_nodes;
INSERT INTO drive_node_closure(space_id,ancestor_id,descendant_id,depth)
SELECT :space_id,:source_id,id,1 FROM drive_acl_benchmark_nodes;
CREATE TEMP TABLE drive_acl_benchmark_fixture ON COMMIT DROP AS
SELECT :owner_user_id::bigint AS owner_user_id,
       :space_id::bigint AS space_id,
       :source_id::bigint AS source_id,
       :destination_id::bigint AS destination_id,
       min(id)::bigint AS target_id
  FROM drive_acl_benchmark_nodes;
ANALYZE drive_nodes;
ANALYZE drive_node_closure;

UPDATE feature_toggles SET enabled=true
 WHERE key IN ('feature.drive_node_acl_reads','feature.drive_node_acl_writes');

-- Twenty same-fixture samples per read path. The legacy/root-role sample is the
-- pre-cutover comparison; canonical ACL is the post-cutover sample.
DO $bench$
DECLARE
  v_i integer;
  v_start timestamptz;
  v_owner bigint;
  v_space bigint;
  v_source bigint;
  v_target bigint;
BEGIN
  SELECT owner_user_id,space_id,source_id,target_id
    INTO v_owner,v_space,v_source,v_target FROM drive_acl_benchmark_fixture;
  UPDATE drive_spaces SET acl_mode='legacy' WHERE id=v_space;
  FOR v_i IN 1..20 LOOP
    v_start:=clock_timestamp();
    PERFORM drive_runtime_has_node_capability(v_owner,v_target,'read_metadata');
    INSERT INTO drive_acl_benchmark_results VALUES
      ('exact_auth_legacy',v_i,extract(epoch FROM clock_timestamp()-v_start)*1000);
  END LOOP;

  UPDATE drive_spaces SET acl_mode='acl' WHERE id=v_space;
  FOR v_i IN 1..20 LOOP
    v_start:=clock_timestamp();
    PERFORM drive_runtime_has_node_capability(v_owner,v_target,'read_metadata');
    INSERT INTO drive_acl_benchmark_results VALUES
      ('exact_auth_acl',v_i,extract(epoch FROM clock_timestamp()-v_start)*1000);

    v_start:=clock_timestamp();
    PERFORM count(*) FROM drive_visible_children(v_owner,v_space,v_source,0,200);
    INSERT INTO drive_acl_benchmark_results VALUES
      ('visible_children_200',v_i,extract(epoch FROM clock_timestamp()-v_start)*1000);

    v_start:=clock_timestamp();
    PERFORM drive_search_nodes(v_owner,v_space,'bench-child-099',100);
    INSERT INTO drive_acl_benchmark_results VALUES
      ('search',v_i,extract(epoch FROM clock_timestamp()-v_start)*1000);

    v_start:=clock_timestamp();
    PERFORM drive_access_invalidation_page(v_owner,v_space,NULL,200);
    INSERT INTO drive_acl_benchmark_results VALUES
      ('sync_page',v_i,extract(epoch FROM clock_timestamp()-v_start)*1000);
  END LOOP;
END
$bench$;

CREATE TEMP TABLE drive_acl_benchmark_users(
  sample integer PRIMARY KEY,
  user_id bigint NOT NULL UNIQUE
) ON COMMIT DROP;
DO $bench$
DECLARE
  v_i integer;
  v_mailbox bigint;
BEGIN
  FOR v_i IN 1..20 LOOP
    v_mailbox:=mk_account('drive-acl-bench-subject-' || v_i::text);
    INSERT INTO drive_acl_benchmark_users
    SELECT v_i,user_id FROM mailboxes WHERE id=v_mailbox;
  END LOOP;
END
$bench$;

DO $bench$
DECLARE
  v_i integer;
  v_start timestamptz;
  v_epoch bigint;
  v_subject bigint;
  v_owner bigint;
  v_space bigint;
  v_source bigint;
  v_destination bigint;
BEGIN
  SELECT owner_user_id,space_id,source_id,destination_id
    INTO v_owner,v_space,v_source,v_destination FROM drive_acl_benchmark_fixture;
  FOR v_i IN 1..20 LOOP
    SELECT epoch INTO v_epoch FROM drive_acl_generations WHERE space_id=v_space;
    SELECT user_id INTO v_subject FROM drive_acl_benchmark_users WHERE sample=v_i;
    v_start:=clock_timestamp();
    PERFORM drive_acl_grant(
      v_owner,v_source,'user',v_subject,'viewer',NULL,'subtree',
      NULL,NULL,NULL,'A9 benchmark',v_epoch,'drive-acl-bench-' || v_i::text
    );
    INSERT INTO drive_acl_benchmark_results VALUES
      ('acl_mutation',v_i,extract(epoch FROM clock_timestamp()-v_start)*1000);
  END LOOP;

  FOR v_i IN 1..20 LOOP
    v_start:=clock_timestamp();
    PERFORM drive_node_move(
      v_owner,v_source,
      CASE WHEN v_i % 2 = 1 THEN v_destination ELSE NULL END
    );
    INSERT INTO drive_acl_benchmark_results VALUES
      ('move_10k_subtree',v_i,extract(epoch FROM clock_timestamp()-v_start)*1000);
  END LOOP;
END
$bench$;

\echo 'Drive ACL 20-sample latency summary (milliseconds)'
SELECT metric,
       round(percentile_cont(0.50) WITHIN GROUP (ORDER BY elapsed_ms)::numeric,3) AS p50_ms,
       round(percentile_cont(0.95) WITHIN GROUP (ORDER BY elapsed_ms)::numeric,3) AS p95_ms,
       round(max(elapsed_ms)::numeric,3) AS max_ms
  FROM drive_acl_benchmark_results
 GROUP BY metric
 ORDER BY metric;

\echo 'Plan evidence: exact authorization'
EXPLAIN (ANALYZE, BUFFERS, COSTS OFF)
SELECT drive_runtime_has_node_capability(
  :owner_user_id,(SELECT min(id) FROM drive_acl_benchmark_nodes),'read_metadata');
\echo 'Plan evidence: visible 200-child page'
EXPLAIN (ANALYZE, BUFFERS, COSTS OFF)
SELECT count(*) FROM drive_visible_children(:owner_user_id,:space_id,:source_id,0,200);
\echo 'Plan evidence: search'
EXPLAIN (ANALYZE, BUFFERS, COSTS OFF)
SELECT drive_search_nodes(:owner_user_id,:space_id,'bench-child-099',100);
\echo 'Plan evidence: sync page'
EXPLAIN (ANALYZE, BUFFERS, COSTS OFF)
SELECT drive_access_invalidation_page(:owner_user_id,:space_id,NULL,200);

DO $bench$
DECLARE
  v_exact double precision;
  v_page double precision;
  v_mutation double precision;
  v_move double precision;
BEGIN
  SELECT percentile_cont(0.95) WITHIN GROUP (ORDER BY elapsed_ms)
    INTO v_exact FROM drive_acl_benchmark_results WHERE metric='exact_auth_acl';
  SELECT percentile_cont(0.95) WITHIN GROUP (ORDER BY elapsed_ms)
    INTO v_page FROM drive_acl_benchmark_results WHERE metric='visible_children_200';
  SELECT percentile_cont(0.95) WITHIN GROUP (ORDER BY elapsed_ms)
    INTO v_mutation FROM drive_acl_benchmark_results WHERE metric='acl_mutation';
  SELECT percentile_cont(0.95) WITHIN GROUP (ORDER BY elapsed_ms)
    INTO v_move FROM drive_acl_benchmark_results WHERE metric='move_10k_subtree';
  IF v_exact > 10 OR v_page > 50 OR v_mutation > 100 OR v_move > 2000 THEN
    RAISE EXCEPTION 'Drive ACL performance budget failed: exact=% page=% mutation=% move=% ms',
      round(v_exact::numeric,3),round(v_page::numeric,3),
      round(v_mutation::numeric,3),round(v_move::numeric,3);
  END IF;
END
$bench$;

ROLLBACK;
\echo 'Drive ACL performance budgets: PASS (fixture rolled back)'
