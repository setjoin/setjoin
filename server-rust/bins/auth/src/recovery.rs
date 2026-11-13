//! Frozen public recovery responses and enumeration controls.
use super::*;
use setjoin_identity::recovery;
const GENERIC:&str="If an account with that email exists and has multi-factor authentication enabled, a verification challenge has been sent.";
impl AuthServer {
    fn recovery_json(status: u16, value: Value) -> Response<Body> {
        Self::wire_json(status, value.to_string() + "\n")
    }
    fn recovery_absent() -> Response<Body> {
        Response::builder()
            .status(404)
            .header("content-type", "text/plain; charset=utf-8")
            .header("x-content-type-options", "nosniff")
            .body(body("404 page not found\n"))
            .unwrap()
    }
    async fn recovery_floor(start: std::time::Instant) {
        let floor = std::time::Duration::from_millis(100);
        if start.elapsed() < floor {
            tokio::time::sleep(floor - start.elapsed()).await;
        }
    }
    pub(super) async fn recovery_begin(&self, req: Request<Body>) -> Response<Body> {
        if !self.forgot_password {
            return Self::recovery_absent();
        }
        let req = match self.totp_ingress(req).await {
            Ok(v) => v,
            Err(reply) => return reply,
        };
        let start = std::time::Instant::now();
        let ip = self.client_ip(&req).to_string();
        if !self.recovery_ip.allow(&ip) {
            return Self::recovery_json(
                429,
                json!({"error":"too many requests, please wait and try again"}),
            );
        }
        let Some(fields) = req
            .into_body()
            .collect()
            .await
            .ok()
            .and_then(|v| ingress::fields(&v.to_bytes(), &["email"]).ok())
        else {
            return Self::recovery_json(400, json!({"error":"invalid JSON"}));
        };
        let email = fields.get("email").map_or("", String::as_str);
        if email.is_empty() {
            return Self::recovery_json(400, json!({"error":"email is required"}));
        }
        let decoy = json!({"method":"totp","message":GENERIC});
        let Some(principal) = recovery::Principal::resolve(&self.exec, email).await else {
            Self::recovery_floor(start).await;
            return Self::recovery_json(200, decoy);
        };
        if principal
            .budget_refused(self.recovery_worker.as_ref(), &self.exec, &ip)
            .await
        {
            Self::recovery_floor(start).await;
            return Self::recovery_json(200, decoy);
        }
        let mut response = json!({"method":principal.method(),"message":GENERIC});
        if principal.method() == "push" && !self.config.vapid_private_key.is_empty() {
            match principal.challenge(&self.exec).await {
                setjoin_pg::CommandOutcome::Committed(
                    setjoin_identity::push::Generated::Created(challenge),
                ) => {
                    response["nonce"] = json!(challenge.nonce());
                    self.native_push.enqueue(self.exec.clone(), challenge);
                }
                _ => {
                    Self::recovery_floor(start).await;
                    return Self::recovery_json(200, decoy);
                }
            }
        }
        Self::recovery_floor(start).await;
        Self::recovery_json(200, response)
    }
}

impl AuthServer {
    pub(super) async fn recovery_verify(&self, req: Request<Body>) -> Response<Body> {
        use setjoin_pg::CommandOutcome;
        if !self.forgot_password {
            return Self::recovery_absent();
        }
        let req = match self.totp_ingress(req).await {
            Ok(v) => v,
            Err(reply) => return reply,
        };
        let ip = self.client_ip(&req).to_string();
        if !self.recovery_ip.allow(&ip) {
            return Self::recovery_json(
                429,
                json!({"error":"too many requests, please wait and try again"}),
            );
        }
        let Some(fields) = Limited::new(req.into_body(), body_cap()).collect().await.ok().and_then(|v| {
            ingress::fields(&v.to_bytes(), &["email", "code", "nonce", "answer"]).ok()
        }) else {
            return Self::recovery_json(400, json!({"error":"invalid JSON"}));
        };
        let get = |key| fields.get(key).map_or("", String::as_str);
        if get("email").is_empty() {
            return Self::recovery_json(400, json!({"error":"email is required"}));
        }
        let invalid = || Self::recovery_json(401, json!({"error":"invalid verification code"}));
        let Some(principal) = recovery::Principal::resolve(&self.exec, get("email")).await else {
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            return invalid();
        };
        if principal
            .budget_refused(self.recovery_worker.as_ref(), &self.exec, &ip)
            .await
        {
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            return invalid();
        }
        let outcome = if !get("nonce").is_empty() && !self.config.vapid_private_key.is_empty() {
            principal
                .verify_push(self.recovery_worker.as_ref(), get("nonce"), get("answer"))
                .await
        } else if !get("code").is_empty() {
            principal.verify_totp(&self.exec, get("code")).await
        } else {
            CommandOutcome::Committed(recovery::Verification::Invalid)
        };
        match outcome {
            CommandOutcome::Committed(recovery::Verification::Accepted(proof)) => {
                let (Ok(first), Ok(second)) = (login::random_jti(), login::random_jti()) else {
                    return Self::recovery_json(500, json!({"error":"internal error"}));
                };
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs() as i64;
                match self.sign(&proof.claims(
                    &self.config.issuer,
                    now,
                    &format!("{first}{second}"),
                )) {
                    Ok(token) => Self::recovery_json(200, json!({"reset_token":token})),
                    Err(_) => Self::recovery_json(500, json!({"error":"internal error"})),
                }
            }
            CommandOutcome::Committed(recovery::Verification::Locked) => {
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                Self::recovery_json(
                    429,
                    json!({"error":"account locked due to too many verification attempts"}),
                )
            }
            CommandOutcome::Committed(recovery::Verification::Invalid) => {
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                invalid()
            }
            CommandOutcome::Unknown { operation } => {
                let mut reply = Self::recovery_json(503, json!({"error":"internal error"}));
                reply.headers_mut().insert(
                    "x-operation-id",
                    uuid::Uuid::from_bytes(operation.0)
                        .to_string()
                        .parse()
                        .unwrap(),
                );
                reply
            }
            _ => Self::recovery_json(500, json!({"error":"internal error"})),
        }
    }
}
