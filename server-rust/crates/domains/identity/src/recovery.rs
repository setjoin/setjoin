//! Public account recovery resolves credentials server-side; identity fields never supply authority.
use setjoin_contracts::ids::{ActorId, OperationId};
use setjoin_pg::{CommandOutcome, ScopedExecutor, StatementFailure, Type};
pub struct Principal {
    user: i64,
    email: String,
    totp: bool,
}
impl Principal {
    pub async fn resolve(exec: &ScopedExecutor, email: &str) -> Option<Self> {
        // Preserve CredentialStore's full enabled snapshot, including its ancillary reads.
        let rows=exec.read("SELECT u.id,u.email,COALESCE(u.totp_enabled,FALSE),COALESCE(u.push_mfa_enabled,FALSE),EXISTS(SELECT 1 FROM passkey_credentials pc WHERE pc.user_id=u.id AND pc.revoked_at IS NULL),COALESCE(array_length(u.totp_backup_codes_enc,1),0)>0 FROM users u WHERE lower(u.email)=lower($1) AND u.enabled=TRUE",&[(&email,Type::TEXT)]).await.ok()?;
        let row = rows.first()?;
        let totp: bool = row.get(2);
        let push: bool = row.get(3);
        if !totp && !push {
            return None;
        }
        Some(Self {
            user: row.get(0),
            email: email.to_owned(),
            totp,
        })
    }
    pub fn method(&self) -> &'static str {
        if self.totp {
            "totp"
        } else {
            "push"
        }
    }
    pub async fn budget_refused(
        &self,
        worker: Option<&ScopedExecutor>,
        request: &ScopedExecutor,
        ip: &str,
    ) -> bool {
        let Some(worker) = worker else {
            return true;
        };
        let Ok(actor) = ActorId::new(self.user) else {
            return true;
        };
        let worker = worker
            .clone()
            .with_user_receipt(setjoin_pg::ReceiptCommand {
                family: "F21",
                command: "mfa-recovery-budget",
            });
        let outcome = worker
            .run_user_command(
                actor,
                OperationId(*uuid::Uuid::new_v4().as_bytes()),
                "SELECT rust_identity_recovery_budget($1)::text",
                &[(&self.user, Type::INT8)],
                |rows| {
                    Ok(
                        serde_json::from_str::<serde_json::Value>(&rows[0].get::<_, String>(0))
                            .expect("budget JSON"),
                    )
                },
            )
            .await;
        let CommandOutcome::Committed(value) = outcome else {
            return true;
        };
        if value["refused"] == true && value["first"] == true {
            let notes="forgot-password recovery budget exhausted: 30 attempts within the 15-minute window";
            let _=request.run_user_command(actor,OperationId(*uuid::Uuid::new_v4().as_bytes()),"INSERT INTO admin_audit_log(user_id,ip,action,target_type,target_id,notes) VALUES($1,$2::text::inet,'recovery_budget_exhausted','user',$1,$3)",&[(&self.user,Type::INT8),(&ip,Type::TEXT),(&notes,Type::TEXT)],|_|Ok(())).await;
        }
        value["refused"] != false
    }
    pub async fn challenge(
        &self,
        exec: &ScopedExecutor,
    ) -> CommandOutcome<super::push::Generated, StatementFailure> {
        super::push::generate_for(exec, self.user, "forgot-password").await
    }
}

/// Only a committed factor verification constructs a reset-token principal.
pub struct ResetProof {
    user: i64,
    email: String,
}
pub enum Verification {
    Accepted(ResetProof),
    Invalid,
    Locked,
    Bookkeeping,
}
impl ResetProof {
    pub fn claims(&self, issuer: &str, now: i64, jti: &str) -> serde_json::Value {
        serde_json::json!({"uid":self.user,"email":self.email,"typ":"password_reset","jti":jti,"iss":issuer,"sub":self.user.to_string(),"aud":["mailserver-gateway"],"nbf":now,"iat":now,"exp":now+300})
    }
}
impl Principal {
    pub async fn verify_totp(
        &self,
        exec: &ScopedExecutor,
        code: &str,
    ) -> CommandOutcome<Verification, StatementFailure> {
        match super::totp::cycle_for(exec, self.user, code).await {
            CommandOutcome::Committed(outcome) => {
                CommandOutcome::Committed(match outcome.as_str() {
                    "accepted" => Verification::Accepted(ResetProof {
                        user: self.user,
                        email: self.email.clone(),
                    }),
                    "locked" => Verification::Locked,
                    "invalid" => Verification::Invalid,
                    _ => Verification::Bookkeeping,
                })
            }
            CommandOutcome::Unknown { operation } => CommandOutcome::Unknown { operation },
            CommandOutcome::RolledBack(reason) => CommandOutcome::RolledBack(reason),
        }
    }
}

impl Principal {
    pub async fn verify_push(
        &self,
        worker: Option<&ScopedExecutor>,
        nonce: &str,
        answer: &str,
    ) -> CommandOutcome<Verification, StatementFailure> {
        use setjoin_pg::ProvenStatement;
        use subtle::ConstantTimeEq;
        let Some(worker) = worker else {
            return CommandOutcome::Committed(Verification::Invalid);
        };
        let Ok(nonce) = data_encoding::HEXLOWER.decode(nonce.to_ascii_lowercase().as_bytes())
        else {
            return CommandOutcome::Committed(Verification::Invalid);
        };
        let Ok(actor) = ActorId::new(self.user) else {
            return CommandOutcome::Committed(Verification::Invalid);
        };
        let worker = worker
            .clone()
            .with_user_receipt(setjoin_pg::ReceiptCommand {
                family: "F21",
                command: "mfa-recovery-push",
            });
        let result = worker
            .run_user_proof_command(
                actor,
                OperationId(*uuid::Uuid::new_v4().as_bytes()),
                "SELECT rust_identity_recovery_push_read($1,$2)::text",
                &[(&self.user, Type::INT8), (&nonce, Type::BYTEA)],
                |rows| {
                    let value: serde_json::Value =
                        serde_json::from_str(&rows[0].get::<_, String>(0)).expect("push JSON");
                    if value["status"] != "ready" {
                        return Ok(ProvenStatement::new("SELECT $1::text").bind(
                            value["status"].as_str().unwrap_or("invalid").to_owned(),
                            Type::TEXT,
                        ));
                    }
                    let valid = bool::from(
                        value["code"]
                            .as_str()
                            .unwrap_or("")
                            .as_bytes()
                            .ct_eq(answer.as_bytes()),
                    );
                    Ok(
                        ProvenStatement::new("SELECT rust_identity_recovery_push_finish($1,$2,$3)")
                            .bind(self.user, Type::INT8)
                            .bind(value["id"].as_i64().expect("challenge id"), Type::INT8)
                            .bind(valid, Type::BOOL),
                    )
                },
                |rows| Ok(rows[0].get::<_, String>(0)),
            )
            .await;
        match result {
            CommandOutcome::Committed(status) => CommandOutcome::Committed(match status.as_str() {
                "accepted" => Verification::Accepted(ResetProof {
                    user: self.user,
                    email: self.email.clone(),
                }),
                "locked" => Verification::Locked,
                _ => Verification::Invalid,
            }),
            CommandOutcome::Unknown { operation } => CommandOutcome::Unknown { operation },
            CommandOutcome::RolledBack(_) => CommandOutcome::Committed(Verification::Invalid),
        }
    }
}
