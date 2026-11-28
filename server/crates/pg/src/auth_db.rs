//! Contract-gated database handle for the `setjoin-identity` auth authority.
//!
//! Splits post-authentication user-scoped operations (`AppPool` / `setjoin_app`,
//! `NOBYPASSRLS` with `SET LOCAL app.current_user_id`) from pre-authentication
//! credential proofs and cross-tenant identity transitions (`WorkerPool` /
//! `setjoin_worker`, `BYPASSRLS`) strictly by [`SqlContract::scope`].
//!
//! Construction is gated behind the `mint` Cargo feature so domain crates
//! (`crates/domains/*`) can hold `&AuthDb` without being able to mint or
//! substitute raw pools or `ScopedExecutor`s.
#![forbid(unsafe_code)]

use crate::{
    CommandOutcome, Param, ProvenStatement, ReceiptCommand, Rejection, Row, ScopedExecutor,
    SqlContract, SqlScope, StatementFailure, ToSql, Type,
};
use setjoin_contracts::ids::{ActorId, OperationId};
use std::future::Future;

/// Typed follow-up statement produced inside a locked proof transaction.
///
/// Mirrors [`ProvenStatement`] but accepts only a statically cataloged
/// [`SqlContract`], ensuring zero uncataloged inline SQL in `crates/domains/*`.
pub struct ProvenContract {
    contract: &'static SqlContract,
    params: Vec<(Box<dyn ToSql + Sync + Send>, Type)>,
}

impl ProvenContract {
    /// Start binding parameters to a statically cataloged [`SqlContract`].
    pub fn new(contract: &'static SqlContract) -> Self {
        Self {
            contract,
            params: Vec::with_capacity(contract.params.len()),
        }
    }

    /// Bind the next positional parameter with its declared PostgreSQL [`Type`].
    pub fn bind<T: ToSql + Sync + Send + 'static>(mut self, value: T, ty: Type) -> Self {
        self.params.push((Box::new(value), ty));
        self
    }

    fn into_statement(self, parent_scope: SqlScope) -> Result<ProvenStatement, StatementFailure> {
        let allowed = match parent_scope {
            SqlScope::UserScoped => self.contract.scope == SqlScope::UserScoped,
            SqlScope::WorkerBypass => {
                matches!(
                    self.contract.scope,
                    SqlScope::WorkerBypass | SqlScope::UserScoped
                )
            }
            _ => false,
        };
        if !allowed {
            return Err(StatementFailure::refused_owned(format!(
                "proven contract '{}' scope {} incompatible with parent scope {}",
                self.contract.id,
                self.contract.scope.as_str(),
                parent_scope.as_str(),
            )));
        }
        if self.params.len() != self.contract.params.len() {
            return Err(StatementFailure::refused_owned(format!(
                "proven contract '{}' expects {} params, got {}",
                self.contract.id,
                self.contract.params.len(),
                self.params.len(),
            )));
        }
        for (idx, ((_, got), expected)) in self
            .params
            .iter()
            .zip(self.contract.params.iter())
            .enumerate()
        {
            if got != expected {
                return Err(StatementFailure::refused_owned(format!(
                    "proven contract '{}' param ${} expects {}, got {}",
                    self.contract.id,
                    idx + 1,
                    expected,
                    got,
                )));
            }
        }
        let mut stmt = ProvenStatement::new(self.contract.sql);
        for (val, ty) in self.params {
            stmt = stmt.bind_boxed(val, ty);
        }
        Ok(stmt)
    }
}

fn validate_params(
    contract: &'static SqlContract,
    params: &[Param<'_>],
) -> Result<(), StatementFailure> {
    if params.len() != contract.params.len() {
        return Err(StatementFailure::refused_owned(format!(
            "contract '{}' expects {} params, got {}",
            contract.id,
            contract.params.len(),
            params.len(),
        )));
    }
    for (idx, ((_, got), expected)) in params.iter().zip(contract.params.iter()).enumerate() {
        if got != expected {
            return Err(StatementFailure::refused_owned(format!(
                "contract '{}' param ${} expects {}, got {}",
                contract.id,
                idx + 1,
                expected,
                got,
            )));
        }
    }
    Ok(())
}

/// Dual-pool contract-gated database authority for `setjoin-identity`.
///
/// - [`SqlScope::UserScoped`] runs exclusively on the `setjoin_app` pool
///   (`NOBYPASSRLS`) with `SET LOCAL app.current_user_id`.
/// - [`SqlScope::AuthPreScope`] and [`SqlScope::WorkerBypass`] run exclusively
///   on the private `setjoin_worker` pool (`BYPASSRLS`).
#[derive(Clone)]
pub struct AuthDb {
    app: ScopedExecutor,
    worker: ScopedExecutor,
}

impl AuthDb {
    /// Construct an [`AuthDb`] from explicit request (`setjoin_app`) and
    /// private pre-auth/worker (`setjoin_worker`) executors.
    #[cfg(feature = "mint")]
    pub fn from_executors(app: ScopedExecutor, worker: ScopedExecutor) -> Self {
        Self { app, worker }
    }

    /// Attach trusted deployment encryption/audit GUC keys to both pools.
    #[cfg(feature = "mint")]
    pub fn with_audit_keys(self, encryption_key: String, audit_hmac_key: String) -> Self {
        Self {
            app: self
                .app
                .with_audit_keys(encryption_key.clone(), audit_hmac_key.clone()),
            worker: self.worker.with_audit_keys(encryption_key, audit_hmac_key),
        }
    }

    /// Attach code-owned commit receipt metadata to subsequent user commands.
    pub fn with_user_receipt(&self, command: ReceiptCommand) -> Self {
        Self {
            app: self.app.clone().with_user_receipt(command),
            worker: self.worker.clone().with_user_receipt(command),
        }
    }

    fn select_user_pool(
        &self,
        contract: &'static SqlContract,
    ) -> Result<&ScopedExecutor, StatementFailure> {
        match contract.scope {
            SqlScope::UserScoped => Ok(&self.app),
            SqlScope::WorkerBypass => Ok(&self.worker),
            other => Err(StatementFailure::refused_owned(format!(
                "contract '{}' scope {} is not allowed for user commands",
                contract.id,
                other.as_str(),
            ))),
        }
    }

    fn select_pre_auth_pool(
        &self,
        contract: &'static SqlContract,
    ) -> Result<&ScopedExecutor, StatementFailure> {
        match contract.scope {
            SqlScope::AuthPreScope | SqlScope::WorkerBypass => Ok(&self.worker),
            other => Err(StatementFailure::refused_owned(format!(
                "contract '{}' scope {} is not allowed for pre-auth reads",
                contract.id,
                other.as_str(),
            ))),
        }
    }

    /// Run a pre-auth or worker `BEGIN READ ONLY` `SELECT` [`SqlContract`] on
    /// the private worker credential (`setjoin_worker`).
    pub async fn read_contract(
        &self,
        contract: &'static SqlContract,
        params: &[Param<'_>],
    ) -> Result<Vec<Row>, StatementFailure> {
        validate_params(contract, params)?;
        let pool = self.select_pre_auth_pool(contract)?;
        pool.read_tx_read_only(contract.sql, params).await
    }

    /// Run a pre-auth or worker `BEGIN READ ONLY` `SELECT` [`SqlContract`] with
    /// Go-compatible deferred-iteration semantics on the private worker credential.
    pub async fn read_iterated_contract(
        &self,
        contract: &'static SqlContract,
        params: &[Param<'_>],
    ) -> Result<Vec<Row>, StatementFailure> {
        validate_params(contract, params)?;
        let pool = self.select_pre_auth_pool(contract)?;
        pool.read_tx_read_only_iterated(contract.sql, params).await
    }

    /// Run an actor-scoped read-only `SELECT` [`SqlContract`] with
    /// `SET LOCAL app.current_user_id = actor` on `setjoin_app` (for
    /// `UserScoped`) or `setjoin_worker` (for `WorkerBypass`).
    pub async fn read_user_scoped_contract(
        &self,
        actor: ActorId,
        contract: &'static SqlContract,
        params: &[Param<'_>],
    ) -> Result<Vec<Row>, StatementFailure> {
        validate_params(contract, params)?;
        let pool = self.select_user_pool(contract)?;
        pool.read_user_scoped(actor, contract.sql, params).await
    }

    /// Run an actor-scoped `SELECT` [`SqlContract`] with Go-compatible
    /// deferred-iteration semantics and `SET LOCAL app.current_user_id = actor`.
    pub async fn read_user_scoped_iterated_contract(
        &self,
        actor: ActorId,
        contract: &'static SqlContract,
        params: &[Param<'_>],
    ) -> Result<Vec<Row>, StatementFailure> {
        validate_params(contract, params)?;
        let pool = self.select_user_pool(contract)?;
        pool.read_user_scoped_iterated(actor, contract.sql, params)
            .await
    }

    /// Run an autocommit worker/pre-auth [`SqlContract`] returning rows.
    pub async fn protocol_query_contract(
        &self,
        contract: &'static SqlContract,
        params: &[Param<'_>],
    ) -> Result<Vec<Row>, StatementFailure> {
        validate_params(contract, params)?;
        if contract.scope != SqlScope::WorkerBypass {
            return Err(StatementFailure::refused_owned(format!(
                "contract '{}' scope {} requires WorkerBypass for protocol_query",
                contract.id,
                contract.scope.as_str(),
            )));
        }
        self.worker.protocol_query(contract.sql, params).await
    }

    /// Run an autocommit worker/pre-auth [`SqlContract`] discarding rows.
    pub async fn protocol_statement_contract(
        &self,
        contract: &'static SqlContract,
        params: &[Param<'_>],
    ) -> Result<(), StatementFailure> {
        validate_params(contract, params)?;
        if contract.scope != SqlScope::WorkerBypass {
            return Err(StatementFailure::refused_owned(format!(
                "contract '{}' scope {} requires WorkerBypass for protocol_statement",
                contract.id,
                contract.scope.as_str(),
            )));
        }
        self.worker.protocol_statement(contract.sql, params).await
    }

    /// Run a scoped user command [`SqlContract`] (`UserScoped` -> `setjoin_app`;
    /// `WorkerBypass` -> `setjoin_worker`).
    pub async fn run_user_command_contract<T, D>(
        &self,
        user: ActorId,
        operation: OperationId,
        contract: &'static SqlContract,
        params: &[Param<'_>],
        decode: D,
    ) -> CommandOutcome<T, StatementFailure>
    where
        D: FnOnce(&[Row]) -> Result<T, StatementFailure>,
    {
        if let Err(e) = validate_params(contract, params) {
            return CommandOutcome::RolledBack(Rejection::Statement(e));
        }
        let pool = match self.select_user_pool(contract) {
            Ok(p) => p,
            Err(e) => return CommandOutcome::RolledBack(Rejection::Statement(e)),
        };
        pool.run_user_command(user, operation, contract.sql, params, decode)
            .await
    }

    /// Run a scoped user command [`SqlContract`] with a pre-COMMIT tail hook.
    #[allow(clippy::too_many_arguments)]
    pub async fn run_user_command_contract_with_tail<T, D, F, Fut>(
        &self,
        user: ActorId,
        operation: OperationId,
        contract: &'static SqlContract,
        params: &[Param<'_>],
        decode: D,
        tail: F,
    ) -> CommandOutcome<T, StatementFailure>
    where
        D: FnOnce(&[Row]) -> Result<T, StatementFailure>,
        F: FnOnce(&T) -> Fut,
        Fut: Future<Output = ()>,
    {
        if let Err(e) = validate_params(contract, params) {
            return CommandOutcome::RolledBack(Rejection::Statement(e));
        }
        let pool = match self.select_user_pool(contract) {
            Ok(p) => p,
            Err(e) => return CommandOutcome::RolledBack(Rejection::Statement(e)),
        };
        pool.run_user_command_with_tail(user, operation, contract.sql, params, decode, tail)
            .await
    }

    /// Run a locked read-then-prove-then-write command using cataloged
    /// [`SqlContract`]s for both the lock read and the proven follow-up write.
    #[allow(clippy::too_many_arguments)]
    pub async fn run_user_proof_command_contract<T, P, D>(
        &self,
        user: ActorId,
        operation: OperationId,
        proof_contract: &'static SqlContract,
        params: &[Param<'_>],
        prove: P,
        decode: D,
    ) -> CommandOutcome<T, StatementFailure>
    where
        P: FnOnce(&[Row]) -> Result<ProvenContract, StatementFailure>,
        D: FnOnce(&[Row]) -> Result<T, StatementFailure>,
    {
        if let Err(e) = validate_params(proof_contract, params) {
            return CommandOutcome::RolledBack(Rejection::Statement(e));
        }
        let pool = match self.select_user_pool(proof_contract) {
            Ok(p) => p,
            Err(e) => return CommandOutcome::RolledBack(Rejection::Statement(e)),
        };
        let parent_scope = proof_contract.scope;
        pool.run_user_proof_command(
            user,
            operation,
            proof_contract.sql,
            params,
            |rows| prove(rows)?.into_statement(parent_scope),
            decode,
        )
        .await
    }

    /// Run a locked async proof command with a pre-COMMIT tail hook using
    /// cataloged [`SqlContract`]s.
    #[allow(clippy::too_many_arguments)]
    pub async fn run_user_async_proof_command_contract_with_tail<T, P, PF, D, F, Fut>(
        &self,
        user: ActorId,
        operation: OperationId,
        proof_contract: &'static SqlContract,
        params: &[Param<'_>],
        prove: P,
        decode: D,
        tail: F,
    ) -> CommandOutcome<T, StatementFailure>
    where
        P: FnOnce(&[Row]) -> PF,
        PF: Future<Output = Result<ProvenContract, StatementFailure>>,
        D: FnOnce(&[Row]) -> Result<T, StatementFailure>,
        F: FnOnce(&T) -> Fut,
        Fut: Future<Output = ()>,
    {
        if let Err(e) = validate_params(proof_contract, params) {
            return CommandOutcome::RolledBack(Rejection::Statement(e));
        }
        let pool = match self.select_user_pool(proof_contract) {
            Ok(p) => p,
            Err(e) => return CommandOutcome::RolledBack(Rejection::Statement(e)),
        };
        let parent_scope = proof_contract.scope;
        pool.run_user_async_proof_command_with_tail(
            user,
            operation,
            proof_contract.sql,
            params,
            |rows| {
                let fut = prove(rows);
                async move { fut.await?.into_statement(parent_scope) }
            },
            decode,
            tail,
        )
        .await
    }

    /// Like [`Self::run_user_async_proof_command_contract_with_tail`], with a
    /// dedicated bound for the CPU-heavy `prove` callback while SQL statements
    /// remain under `Timeouts::statement` (#383).
    #[allow(clippy::too_many_arguments)]
    pub async fn run_user_async_proof_command_contract_with_proof_timeout_and_tail<
        T,
        P,
        PF,
        D,
        F,
        Fut,
    >(
        &self,
        user: ActorId,
        operation: OperationId,
        proof_contract: &'static SqlContract,
        params: &[Param<'_>],
        proof_timeout: std::time::Duration,
        prove: P,
        decode: D,
        tail: F,
    ) -> CommandOutcome<T, StatementFailure>
    where
        P: FnOnce(&[Row]) -> PF,
        PF: Future<Output = Result<ProvenContract, StatementFailure>>,
        D: FnOnce(&[Row]) -> Result<T, StatementFailure>,
        F: FnOnce(&T) -> Fut,
        Fut: Future<Output = ()>,
    {
        if let Err(e) = validate_params(proof_contract, params) {
            return CommandOutcome::RolledBack(Rejection::Statement(e));
        }
        let pool = match self.select_user_pool(proof_contract) {
            Ok(p) => p,
            Err(e) => return CommandOutcome::RolledBack(Rejection::Statement(e)),
        };
        let parent_scope = proof_contract.scope;
        pool.run_user_async_proof_command_with_proof_timeout_and_tail(
            user,
            operation,
            proof_contract.sql,
            params,
            proof_timeout,
            |rows| {
                let fut = prove(rows);
                async move { fut.await?.into_statement(parent_scope) }
            },
            decode,
            tail,
        )
        .await
    }

    /// Run an acknowledged anonymous protocol command (`WorkerBypass`).
    pub async fn run_protocol_command_contract<T, D>(
        &self,
        scope: &str,
        operation: OperationId,
        command: ReceiptCommand,
        contract: &'static SqlContract,
        params: &[Param<'_>],
        decode: D,
    ) -> CommandOutcome<T, StatementFailure>
    where
        D: FnOnce(&[Row]) -> Result<T, StatementFailure>,
    {
        if let Err(e) = validate_params(contract, params) {
            return CommandOutcome::RolledBack(Rejection::Statement(e));
        }
        if contract.scope != SqlScope::WorkerBypass {
            return CommandOutcome::RolledBack(Rejection::Statement(
                StatementFailure::refused_owned(format!(
                    "contract '{}' scope {} requires WorkerBypass for protocol commands",
                    contract.id,
                    contract.scope.as_str(),
                )),
            ));
        }
        self.worker
            .run_protocol_command(scope, operation, command, contract.sql, params, decode)
            .await
    }

    /// Run an acknowledged receipt-free anonymous protocol transaction (`WorkerBypass`, #473).
    pub async fn run_protocol_tx_contract<T, D>(
        &self,
        contract: &'static SqlContract,
        params: &[Param<'_>],
        decode: D,
    ) -> Result<T, StatementFailure>
    where
        D: FnOnce(&[Row]) -> Result<T, StatementFailure>,
    {
        validate_params(contract, params)?;
        if contract.scope != SqlScope::WorkerBypass {
            return Err(StatementFailure::refused_owned(format!(
                "contract '{}' scope {} requires WorkerBypass for protocol transactions",
                contract.id,
                contract.scope.as_str(),
            )));
        }
        self.worker
            .run_protocol_tx(contract.sql, params, decode)
            .await
    }

    /// Look up an anonymous protocol operation receipt on the worker pool.
    pub async fn lookup_protocol_operation(
        &self,
        scope: &str,
        operation: OperationId,
        command: ReceiptCommand,
    ) -> Result<bool, StatementFailure> {
        self.worker
            .lookup_protocol_operation(scope, operation, command)
            .await
    }
}
