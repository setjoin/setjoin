//! Durable request capabilities. Construction is limited to owned DB reads.
use super::*;
use setjoin_pg::{CommandOutcome, StatementFailure};
pub struct Authorization {
    pub(super) id: String,
    pub(super) client: String,
    pub(super) redirect: String,
    pub(super) state: String,
    pub(super) nonce: String,
    pub(super) challenge: String,
    pub(super) scopes: Vec<String>,
    pub(super) user: Option<i64>,
    pub(super) done: bool,
    pub(super) auth_time: std::time::SystemTime,
    pub(super) acr: String,
    pub(super) amr: Vec<String>,
}
impl Authorization {
    pub fn id(&self) -> &str {
        &self.id
    }
    pub fn client(&self) -> &str {
        &self.client
    }
    pub fn redirect(&self) -> &str {
        &self.redirect
    }
    pub fn state(&self) -> &str {
        &self.state
    }
    pub fn scopes(&self) -> &[String] {
        &self.scopes
    }
    /// The user the completing session bound, if any.
    pub fn user(&self) -> Option<i64> {
        self.user
    }
    pub fn done(&self) -> bool {
        self.done
    }
    pub(super) fn decode(row: &setjoin_pg::Row) -> Result<Self, StatementFailure> {
        let invalid = || StatementFailure {
            sqlstate: None,
            hint: None,
            message: "stored authorization request cannot be decoded".into(),
        };
        macro_rules! g {
            ($i:expr) => {
                row.try_get($i).map_err(|_| invalid())?
            };
        }
        Ok(Self {
            id: g!(0),
            client: g!(1),
            redirect: g!(2),
            state: g!(3),
            nonce: g!(4),
            challenge: g!(5),
            scopes: g!(6),
            user: g!(7),
            done: g!(8),
            auth_time: g!(9),
            acr: g!(10),
            amr: g!(11),
        })
    }
}
pub async fn request(exec: &AuthDb, id: &str) -> Result<Option<Authorization>, StatementFailure> {
    let rows = exec
        .read_contract(&crate::sql::OIDC_REQUESTS_L72, &[(&id, Type::TEXT)])
        .await?;
    rows.first().map(Authorization::decode).transpose()
}
pub async fn bind_code(
    exec: &AuthDb,
    request: &Authorization,
    code: &str,
    operation: setjoin_contracts::ids::OperationId,
) -> CommandOutcome<bool, StatementFailure> {
    use sha2::{Digest, Sha256};
    let Some(user) = request.user.filter(|u| *u > 0) else {
        return CommandOutcome::RolledBack(setjoin_pg::Rejection::Unavailable);
    };
    let actor = setjoin_contracts::ids::ActorId::new(user).expect("positive stored user");
    let hash = Sha256::digest(code.as_bytes()).to_vec();
    exec.clone()
        .with_user_receipt(setjoin_pg::ReceiptCommand {
            family: "F21",
            command: "oidc-code",
        })
        .run_user_command_contract(
            actor,
            operation,
            &crate::sql::OIDC_REQUESTS_L88,
            &[
                (&request.id, Type::TEXT),
                (&user, Type::INT8),
                (&hash, Type::BYTEA),
            ],
            |rows| Ok(rows.len() == 1),
        )
        .await
}
