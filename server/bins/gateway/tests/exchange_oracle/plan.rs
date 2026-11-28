use crate::common::BoxError;
use serde_json::json;
use setjoin_conformance::fixture::{self, Account};
use tokio_postgres::Client;

pub const BUNDLE: &str = "gofree Exchange bundle\n{\"items\":[1,2,3],\"schema\":\"v1\"}";
pub const KEY: &str = "ab294000-0000-4000-8000-000000000001";
pub const PERMS: [&str; 7] = [
    "exchange.assessment.read",
    "exchange.assessment.run",
    "exchange.assessment.decide",
    "exchange.assessment.attest",
    "exchange.assessment.audit",
    "exchange.assessment.publish",
    "exchange.assessment.delete",
];
pub struct Fx {
    pub a: Account,
    pub b: Account,
    pub role: i64,
    pub pa: i64,
    pub pb: i64,
    pub ra: i64,
    pub rb: i64,
    pub spec: serde_json::Value,
    pub reason_areas: Vec<String>,
    pub enabled: bool,
    pub symbols: std::sync::Mutex<Vec<(String, i64, String)>>,
    pub pub_digest: String,
    pub profile: String,
    pub installation: String,
    pub inserted_upgrade: bool,
    pub storage: std::sync::Mutex<Option<std::net::SocketAddr>>,
    pub objects: std::sync::Mutex<Vec<(String, String)>>,
    pub crypto_literals: std::sync::Mutex<Vec<(String, String)>>,
    pub object_digests: std::sync::Mutex<Vec<String>>,
    pub digests: std::sync::Mutex<Vec<String>>,
}
impl Fx {
    pub async fn build(c: &Client, action: &str, kind: &str) -> Result<Self, BoxError> {
        let a = fixture::account(c, "mbox3-admin").await?;
        let b = fixture::account(c, "mbox3-other").await?;
        let reason_areas: Vec<String> = c
            .query_one(
                "SELECT reason_required_areas FROM audit_policy WHERE id=1",
                &[],
            )
            .await?
            .get(0);
        if kind == "reason-required" {
            c.execute(
                "UPDATE audit_policy SET reason_required_areas=ARRAY['exchange'] WHERE id=1",
                &[],
            )
            .await?;
        }
        let enabled:bool=c.query_one("SELECT enabled FROM feature_toggles WHERE key='feature.exchange_replacement_assessment'",&[]).await?.get(0);
        c.execute("UPDATE feature_toggles SET enabled=true WHERE key='feature.exchange_replacement_assessment'",&[]).await?;
        let perm = permission(action);
        let perms = vec![if kind == "denied" { "users.read" } else { perm }.to_string()];
        let scope = matches!(kind, "foreign" | "group-scope").then_some(a.domain);
        let domain_override = (kind == "foreign").then_some(a.domain);
        let role:i64=c.query_one("INSERT INTO admin_role_groups(name,permissions,domain_scope) VALUES ($1,$2,$3) RETURNING id",&[&format!("mbox3-role-{}",a.user),&perms,&scope]).await?.get(0);
        c.execute("INSERT INTO admin_role_assignments(user_id,role_group_id,granted_by,domain_override) VALUES ($1,$2,$1,$3)",&[&a.user,&role,&domain_override]).await?;
        let mut ps = vec![];
        let mut rs = vec![];
        for (acct, name) in [(&a, "Project A"), (&b, "Project B")] {
            let p:i64=c.query_one("INSERT INTO exchange_assessment_projects(domain_id,name,created_by,created_at,updated_at) VALUES ($1,$2,$3,'2026-01-01','2026-01-01') RETURNING id",&[&acct.domain,&name,&acct.user]).await?.get(0);
            let r:i64=c.query_one("INSERT INTO exchange_assessment_runs(project_id,state,support_cell_id,support_cell_digest,registry_version,registry_digest,catalog_version,collector_version,created_by,created_at,updated_at) SELECT $1,'created',cell->>'id',cell->>'digest',registry_version,source_digest,(cell->>'catalogVersion')::integer,cell->>'collectorVersion',$2,'2026-01-01','2026-01-01' FROM exchange_registry_snapshots CROSS JOIN LATERAL jsonb_array_elements(projection->'supportCells') cell ORDER BY registry_version DESC LIMIT 1 RETURNING id",&[&p,&b.user]).await?.get(0);
            ps.push(p);
            rs.push(r);
        }
        if action == "transition" && kind == "generation-clash" {
            c.execute("INSERT INTO exchange_assessment_runs(project_id,generation,state,support_cell_id,support_cell_digest,registry_version,registry_digest,catalog_version,collector_version,created_by,created_at,updated_at) SELECT project_id,2,'created',support_cell_id,support_cell_digest,registry_version,registry_digest,catalog_version,collector_version,created_by,'2026-01-01','2026-01-01' FROM exchange_assessment_runs WHERE id=$1",&[&rs[0]]).await?;
        }
        if action == "decision" {
            c.execute(
                "UPDATE exchange_assessment_runs SET state='partial' WHERE id=ANY($1)",
                &[&rs],
            )
            .await?;
            c.execute("INSERT INTO exchange_assessment_claim_snapshots(run_id,run_generation,registry_digest,support_cell_digest,projection,projection_digest,resolved_by) SELECT id,generation,registry_digest,support_cell_digest,'{\"rows\":[]}'::jsonb,repeat('c',64),$2 FROM exchange_assessment_runs WHERE id=$1",&[&rs[0],&b.user]).await?;
        }
        if action == "bundle" && kind == "bad-state" {
            c.execute(
                "UPDATE exchange_assessment_runs SET state='ready' WHERE id=$1",
                &[&rs[0]],
            )
            .await?;
        }
        if action == "audit" {
            for run in &rs {
                c.execute("INSERT INTO exchange_assessment_claim_snapshots(run_id,run_generation,registry_digest,support_cell_digest,projection,projection_digest,resolved_by,resolved_at) SELECT id,generation,registry_digest,support_cell_digest,'{\"rows\":[]}'::jsonb,repeat('c',64),$2,'2026-01-01' FROM exchange_assessment_runs WHERE id=$1",&[&run,&b.user]).await?;
                c.execute("INSERT INTO exchange_assessment_attestations(run_id,kind,subject_digest,statement,actor_id,issued_at) VALUES ($1,'handling',repeat('b',64),'{\"basis\":\"seed\"}',$2,'2026-01-01')",&[&run,&b.user]).await?;
                let artifact:i64=c.query_one("INSERT INTO exchange_assessment_artifacts(run_id,kind,object_key,sha256,crypto_profile,key_id,created_at) VALUES ($1,'report_json','exchange-fixture/report',repeat('e',64),'standard','fixture-key','2026-01-01') RETURNING id",&[&run]).await?.get(0);
                c.execute("INSERT INTO exchange_assessment_evidence(run_id,capability_id,tier,artifact_id,support_cell_digest,case_ids,captured_at,expires_at,created_at) SELECT id,'EX-CALENDAR-VISIBILITY','T1',$2,support_cell_digest,ARRAY['EX-T1-CALENDAR'],'2026-01-01','2036-01-01','2026-01-01' FROM exchange_assessment_runs WHERE id=$1",&[&run,&artifact]).await?;
                let receipt:i64=c.query_one("INSERT INTO exchange_assessment_artifacts(run_id,kind,object_key,sha256,crypto_profile,key_id,created_at) VALUES ($1,'receipt','exchange-fixture/receipt',repeat('f',64),'standard','fixture-key','2026-01-01') RETURNING id",&[&run]).await?.get(0);
                c.execute("INSERT INTO exchange_assessment_publications(run_id,projection_digest,receipt_artifact_id,published_by,published_at) VALUES ($1,repeat('c',64),$2,$3,'2026-01-01')",&[&run,&receipt,&b.user]).await?;
            }
        }
        let mut pub_digest = String::new();
        if action == "publish" {
            c.execute(
                "UPDATE exchange_assessment_runs SET state=$2 WHERE id=$1",
                &[
                    &rs[0],
                    &if kind == "bad-state" {
                        "partial"
                    } else {
                        "ready"
                    },
                ],
            )
            .await?;
            let projection=json!({"schemaVersion":"setjoin.exchange.claim-projection/v1","runId":rs[0],"runGeneration":1,"supportCellStale":kind=="stale-cell","rows":[{"capabilityId":"EX-CALENDAR-VISIBILITY","claimState":if kind=="unassessed"{"unassessed"}else{"supported"},"outcomeMapping":"native"}]}).to_string();
            pub_digest=c.query_one("INSERT INTO exchange_assessment_claim_snapshots(run_id,run_generation,registry_digest,support_cell_digest,projection,projection_digest,resolved_by) SELECT id,generation,registry_digest,support_cell_digest,$2::text::jsonb,encode(digest(($2::text::jsonb)::text,'sha256'),'hex'),$3 FROM exchange_assessment_runs WHERE id=$1 RETURNING projection_digest",&[&rs[0],&projection,&b.user]).await?.get(0);
        }
        let mut inserted_upgrade = false;
        let mut installation = String::new();
        if matches!(action, "bundle" | "publish") {
            let row = c
                .query_opt(
                    "SELECT installation_id::text FROM upgrade_control_state WHERE singleton",
                    &[],
                )
                .await?;
            installation = if let Some(row) = row {
                row.get(0)
            } else {
                inserted_upgrade = true;
                let id = "00000000-0000-4000-8000-000000000294";
                c.execute("INSERT INTO upgrade_control_state(singleton,installation_id) VALUES (true,$1::text::uuid)",&[&id]).await?;
                id.into()
            };
        }
        let spec:String=c.query_one("SELECT jsonb_build_object('supportCellId',support_cell_id,'supportCellDigest',support_cell_digest,'registryVersion',registry_version,'registryDigest',registry_digest,'catalogVersion',catalog_version,'collectorVersion',collector_version)::text FROM exchange_assessment_runs WHERE id=$1",&[&rs[0]]).await?.get(0);
        Ok(Self {
            a,
            b,
            role,
            pa: ps[0],
            pb: ps[1],
            ra: rs[0],
            rb: rs[1],
            spec: serde_json::from_str(&spec)?,
            reason_areas,
            enabled,
            symbols: std::sync::Mutex::new(Vec::new()),
            profile: if matches!(kind, "smx" | "hybrid") {
                kind.into()
            } else {
                "standard".into()
            },
            pub_digest,
            installation,
            inserted_upgrade,
            storage: std::sync::Mutex::new(None),
            objects: std::sync::Mutex::new(Vec::new()),
            object_digests: std::sync::Mutex::new(Vec::new()),
            crypto_literals: std::sync::Mutex::new(Vec::new()),
            digests: std::sync::Mutex::new(Vec::new()),
        })
    }
    pub async fn remove(&self, c: &Client) -> Result<(), BoxError> {
        // Child-first, exact assigned project/actor scope; all FK triggers stay active.
        for table in [
            "exchange_assessment_idempotency",
            "exchange_assessment_receipts",
            "exchange_assessment_deletion_requests",
            "exchange_assessment_publications",
            "exchange_assessment_claim_snapshots",
            "exchange_assessment_decisions",
            "exchange_assessment_attestations",
            "exchange_assessment_evidence",
            "exchange_assessment_probe_results",
            "exchange_assessment_uploads",
            "exchange_assessment_tombstones",
            "exchange_assessment_artifacts",
            "exchange_assessment_runs",
            "exchange_assessment_projects",
        ] {
            let predicate=match table {"exchange_assessment_idempotency"=>format!("actor_id IN ({},{})",self.a.user,self.b.user),"exchange_assessment_receipts"=>format!("created_by IN ({},{})",self.a.user,self.b.user),"exchange_assessment_projects"=>format!("domain_id IN ({},{})",self.a.domain,self.b.domain),"exchange_assessment_runs"|"exchange_assessment_deletion_requests"=>format!("project_id IN (SELECT id FROM exchange_assessment_projects WHERE domain_id IN ({},{}))",self.a.domain,self.b.domain),_=>format!("run_id IN (SELECT r.id FROM exchange_assessment_runs r JOIN exchange_assessment_projects p ON p.id=r.project_id WHERE p.domain_id IN ({},{}))",self.a.domain,self.b.domain)};
            c.batch_execute(&format!("DELETE FROM {table} WHERE {predicate}"))
                .await?;
        }
        c.execute(
            "DELETE FROM admin_role_assignments WHERE user_id=$1",
            &[&self.a.user],
        )
        .await?;
        c.execute("DELETE FROM admin_role_groups WHERE id=$1", &[&self.role])
            .await?;
        c.execute("UPDATE feature_toggles SET enabled=$1 WHERE key='feature.exchange_replacement_assessment'",&[&self.enabled]).await?;
        c.execute(
            "UPDATE audit_policy SET reason_required_areas=$1 WHERE id=1",
            &[&self.reason_areas],
        )
        .await?;
        if self.inserted_upgrade {
            c.execute(
                "DELETE FROM upgrade_control_state WHERE installation_id=$1::text::uuid",
                &[&self.installation],
            )
            .await?;
        }
        fixture::remove(c, &self.a).await?;
        fixture::remove(c, &self.b).await?;
        Ok(())
    }
    pub fn names(&self, s: &str) -> String {
        s.replace(&format!("/projects/{}", self.pa), "/projects/<project-a>")
            .replace(&format!("/projects/{}", self.pb), "/projects/<project-b>")
            .replace(&format!("/runs/{}", self.ra), "/runs/<run-a>")
            .replace(&format!("/runs/{}", self.rb), "/runs/<run-b>")
    }
}
pub fn permission(action: &str) -> &'static str {
    match action {
        "registry" | "projects" | "runs" => PERMS[0],
        "decision" => PERMS[2],
        "attestation" => PERMS[3],
        "resolve" | "audit" => PERMS[4],
        "publish" => PERMS[5],
        "delete" => PERMS[6],
        _ => PERMS[1],
    }
}
pub struct Plan {
    pub method: &'static str,
    pub pattern: &'static str,
    pub path: String,
    pub body: String,
}
pub fn plan(action: &str, kind: &str, fx: &Fx) -> Plan {
    let (method, pattern, body) = match action {
        "registry" => ("GET", "/admin/exchange-replacement/registry", json!(null)),
        "projects" => ("GET", "/admin/exchange-replacement/projects", json!(null)),
        "runs" => (
            "GET",
            "/admin/exchange-replacement/projects/{projectId}/runs",
            json!(null),
        ),
        "create-project" => (
            "POST",
            "/admin/exchange-replacement/projects",
            json!({"domainId":if matches!(kind,"foreign"|"group-scope") {fx.b.domain}else{fx.a.domain},"name":if matches!(kind,"invalid"|"locale-invalid") {""}else{"Created Project"},"retentionUntil":null}),
        ),
        "create-run" => {
            let mut body = fx.spec.clone();
            if kind == "invalid" {
                body["catalogVersion"] = json!(0);
            }
            (
                "POST",
                "/admin/exchange-replacement/projects/{projectId}/runs",
                body,
            )
        }
        "transition" => (
            "POST",
            "/admin/exchange-replacement/runs/{runId}/transition",
            json!({"expectedGeneration":1,"state":if kind=="invalid"{"ready"}else{"preflight"},"errorCode":null}),
        ),
        "attestation" => (
            "POST",
            "/admin/exchange-replacement/runs/{runId}/attestations",
            json!({"kind":if kind=="invalid"{"wrong"}else{"handling"},"subjectDigest":"b".repeat(64),"statement":{"basis":"independent review","count":1}}),
        ),
        "decision" => (
            "POST",
            "/admin/exchange-replacement/runs/{runId}/decisions",
            json!({"expectedGeneration":1,"capabilityId":"EX-CALENDAR-VISIBILITY","outcomeMapping":"native","decision":if kind=="invalid"{"wrong"}else{"accepted"},"reason":"reviewed migration","waiverExpiresAt":null}),
        ),
        "resolve" => (
            "POST",
            "/admin/exchange-replacement/runs/{runId}/claims/resolve",
            json!({"expectedGeneration":if kind=="invalid"{0}else{1}}),
        ),
        "delete" => (
            "POST",
            "/admin/exchange-replacement/projects/{projectId}/deletions",
            json!({"scope":if kind=="invalid"{"wrong"}else{"project"},"runId":null,"artifactId":null,"reason":"retention expired"}),
        ),
        "audit" => (
            "GET",
            "/admin/exchange-replacement/runs/{runId}/audit",
            json!(null),
        ),
        "publish" => (
            "POST",
            "/admin/exchange-replacement/runs/{runId}/publications",
            json!({"projectionDigest":if kind=="invalid"{"bad".to_string()}else if kind=="missing-snapshot"{"c".repeat(64)}else{fx.pub_digest.clone()}}),
        ),
        "bundle" => (
            "PUT",
            "/admin/exchange-replacement/runs/{runId}/bundle",
            json!(null),
        ),
        _ => panic!("unknown action {action}"),
    };
    let project = if kind == "foreign" { fx.pb } else { fx.pa };
    let run = if kind == "foreign" { fx.rb } else { fx.ra };
    let mut path = pattern
        .replace("{projectId}", &project.to_string())
        .replace("{runId}", &run.to_string());
    if kind == "invalid" && method == "GET" {
        if action == "audit" {
            path = pattern.replace("{runId}", "bad");
        } else if action == "runs" {
            path = pattern.replace("{projectId}", "bad");
        } else {
            path += "?limit=invalid";
        }
    }
    let mut body = body;
    if kind == "unknown-field" {
        body["unexpected"] = json!(true);
    }
    Plan {
        method: if kind == "head" { "HEAD" } else { method },
        pattern,
        path,
        body: if kind=="top-array"{"[]".into()}else if kind=="top-scalar"{"true".into()}else if kind=="wrong-version"{"{\"registryVersion\":\"bad\"}".into()}else if kind == "malformed-body" {
            "{\"domainId\":?}".into()
        } else if kind == "empty-body" {
            String::new()
        } else if kind == "type-error" {
            "{\"domainId\":\"wrong\"}".into()
        } else if kind == "extra-body" {
            "{} {}".into()
        } else if action == "bundle" {
            if kind == "empty" {
                String::new()
            } else {
                BUNDLE.into()
            }
        } else if body.is_null() {
            String::new()
        } else {
            body.to_string()
        },
    }
}
