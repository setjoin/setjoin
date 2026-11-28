//! Public account recovery resolves credentials server-side; identity fields never supply authority.
use setjoin_contracts::ids::{ActorId, OperationId};
use setjoin_pg::{AuthDb, CommandOutcome, StatementFailure, Type};
pub struct Principal {
    user: i64,
    email: String,
    totp: bool,
}
impl Principal {
    /// A query error or a missing row is Ok(None). An unreadable column is a decode
    /// failure, reported as Err so the caller can answer with the same non-enumerating reply.
    pub async fn resolve(exec: &AuthDb, email: &str) -> Result<Option<Self>, StatementFailure> {
        // Preserve CredentialStore's full enabled snapshot, including its ancillary reads.
        let Ok(rows) = exec
            .read_contract(&crate::sql::RECOVERY_L14, &[(&email, Type::TEXT)])
            .await
        else {
            return Ok(None);
        };
        let Some(row) = rows.first() else {
            return Ok(None);
        };
        let bad = || StatementFailure {
            sqlstate: None,
            hint: None,
            message: "recovery principal row".into(),
        };
        let totp: bool = row.try_get(2).map_err(|_| bad())?;
        let push: bool = row.try_get(3).map_err(|_| bad())?;
        if !totp && !push {
            return Ok(None);
        }
        Ok(Some(Self {
            user: row.try_get(0).map_err(|_| bad())?,
            email: email.to_owned(),
            totp,
        }))
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
        worker: Option<&AuthDb>,
        request: &AuthDb,
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
            .run_user_command_contract(
                actor,
                OperationId(*uuid::Uuid::new_v4().as_bytes()),
                &crate::sql::RECOVERY_L65,
                &[(&self.user, Type::INT8)],
                |rows| {
                    rows.first()
                        .and_then(|r| r.try_get::<_, String>(0).ok())
                        .and_then(|raw| serde_json::from_str::<serde_json::Value>(&raw).ok())
                        .ok_or_else(|| StatementFailure {
                            sqlstate: None,
                            hint: None,
                            message: "budget JSON row".into(),
                        })
                },
            )
            .await;
        let CommandOutcome::Committed(value) = outcome else {
            return true;
        };
        if value["refused"] == true && value["first"] == true {
            let notes="forgot-password recovery budget exhausted: 30 attempts within the 15-minute window";
            let action = "recovery_budget_exhausted";
            let _ = request
                .run_user_command_contract(
                    actor,
                    OperationId(*uuid::Uuid::new_v4().as_bytes()),
                    &crate::sql::ADMIN_AUDIT_WRITE_USER,
                    &[
                        (&self.user, Type::INT8),
                        (&ip, Type::TEXT),
                        (&action, Type::TEXT),
                        (&notes, Type::TEXT),
                    ],
                    |_| Ok(()),
                )
                .await;
        }
        value["refused"] != false
    }
    pub async fn challenge(
        &self,
        exec: &AuthDb,
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
        exec: &AuthDb,
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
        worker: Option<&AuthDb>,
        nonce: &str,
        answer: &str,
    ) -> CommandOutcome<Verification, StatementFailure> {
        use setjoin_pg::ProvenContract;
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
            .run_user_proof_command_contract(
                actor,
                OperationId(*uuid::Uuid::new_v4().as_bytes()),
                &crate::sql::RECOVERY_L165,
                &[(&self.user, Type::INT8), (&nonce, Type::BYTEA)],
                |rows| {
                    let value: serde_json::Value = rows
                        .first()
                        .and_then(|r| r.try_get::<_, String>(0).ok())
                        .and_then(|raw| serde_json::from_str::<serde_json::Value>(&raw).ok())
                        .ok_or_else(|| StatementFailure {
                            sqlstate: None,
                            hint: None,
                            message: "push JSON row".into(),
                        })?;
                    if value["status"] != "ready" {
                        return Ok(ProvenContract::new(&crate::sql::ECHO_TEXT).bind(
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
                    Ok(ProvenContract::new(&crate::sql::RECOVERY_L191)
                        .bind(self.user, Type::INT8)
                        .bind(
                            value["id"].as_i64().ok_or_else(|| StatementFailure {
                                sqlstate: None,
                                hint: None,
                                message: "push challenge id".into(),
                            })?,
                            Type::INT8,
                        )
                        .bind(valid, Type::BOOL))
                },
                |rows| {
                    rows.first()
                        .and_then(|r| r.try_get::<_, String>(0).ok())
                        .ok_or_else(|| StatementFailure {
                            sqlstate: None,
                            hint: None,
                            message: "push finish row".into(),
                        })
                },
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
