//! Pure mapping from driver observations to `setjoin-db` lifecycle observations
//! and `setjoin-contracts` recovery. No I/O here, so every branch is unit-tested.
use setjoin_contracts::{
    command::{recover, CommitObservation, RecoveryAction},
    ids::OperationId,
};
use setjoin_db::lifecycle::LifecycleError;

/// SQLSTATE classes whose ErrorResponse to COMMIT proves PostgreSQL itself
/// aborted the transaction: integrity (deferred constraint), data exception,
/// invalid transaction state, transaction rollback (serialization/deadlock),
/// PL/pgSQL raise (deferred trigger) and the project's `BZ` business codes.
const DEFINITE_ABORT_CLASSES: [&str; 6] = ["23", "22", "25", "40", "P0", "BZ"];

/// Observation for a COMMIT that did not return success.
///
/// `None` means no server response arrived (I/O error, closed connection,
/// cancelled future): the transaction may or may not have committed, so the
/// answer is `Unknown`. An ErrorResponse counts as a rollback only for the
/// classes in [`DEFINITE_ABORT_CLASSES`]; any other class (connection
/// exception `08`, operator intervention `57`, system `58`, internal `XX`,
/// resources `53`, or an error synthesised by PgBouncer) stays `Unknown`.
pub fn commit_failure_observation(sqlstate: Option<&str>) -> CommitObservation {
    match sqlstate {
        Some(code)
            if code.len() == 5 && DEFINITE_ABORT_CLASSES.iter().any(|c| code.starts_with(c)) =>
        {
            CommitObservation::RolledBack
        }
        _ => CommitObservation::Unknown,
    }
}

/// Why a command is known not to have committed.
#[derive(Debug)]
pub enum Rejection<E> {
    /// No pooled connection or BEGIN failed before any statement ran.
    Unavailable,
    /// Envelope/authority/deadline check refused by the lifecycle core.
    Authority(LifecycleError),
    /// A statement failed; the whole transaction was rolled back.
    Statement(StatementFailure),
    /// The command body aborted and the rollback was acknowledged.
    Body(E),
    /// PostgreSQL refused COMMIT with a definite-abort SQLSTATE.
    CommitRefused(String),
}

/// What a log line may say about a failure: its SQLSTATE, never its text.
pub trait FailureCode {
    fn sqlstate(&self) -> Option<&str>;
}

impl FailureCode for StatementFailure {
    fn sqlstate(&self) -> Option<&str> {
        self.sqlstate.as_deref()
    }
}

impl<E: FailureCode> Rejection<E> {
    /// The log form of a rejection: its kind plus SQLSTATE (or the lifecycle
    /// reason). PostgreSQL's message text, which can quote row values
    /// (`Key (col)=(value)`), and any detail are never included; log it with
    /// the operation ID to correlate.
    pub fn log_summary(&self) -> String {
        let code = |c: Option<&str>| format!("sqlstate={}", c.unwrap_or("none"));
        match self {
            Self::Unavailable => "unavailable".into(),
            Self::Authority(LifecycleError::DeadlineElapsed) => "authority deadline-elapsed".into(),
            Self::Authority(LifecycleError::InvalidTransition) => {
                "authority invalid-transition".into()
            }
            // ContractError is a field-less enum: its name carries no data.
            Self::Authority(LifecycleError::Contract(e)) => format!("authority contract={e:?}"),
            Self::Statement(f) => format!("statement {}", code(f.sqlstate())),
            Self::Body(e) => format!("body {}", code(e.sqlstate())),
            Self::CommitRefused(c) => format!("commit-refused {}", code(Some(c))),
        }
    }
}

/// A failed statement and its untrusted server message. Adapters may expose
/// that message only for an explicit allowlist of business SQLSTATEs whose
/// frozen Go contract passes it through. Unknown SQL text never reaches clients.
/// Logs use [`Rejection::log_summary`], never the message (it may quote row data).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StatementFailure {
    pub sqlstate: Option<String>,
    pub message: String,
    /// Untrusted server HINT, retained only for typed frozen-Go projections.
    pub hint: Option<String>,
}

/// The executor's answer. `Unknown` carries the operation ID for lookup and
/// is never a success.
#[derive(Debug)]
pub enum CommandOutcome<T, E> {
    Committed(T),
    RolledBack(Rejection<E>),
    Unknown { operation: OperationId },
}

impl<T, E> CommandOutcome<T, E> {
    pub fn observation(&self) -> CommitObservation {
        match self {
            Self::Committed(_) => CommitObservation::Committed,
            Self::RolledBack(_) => CommitObservation::RolledBack,
            Self::Unknown { .. } => CommitObservation::Unknown,
        }
    }

    /// `setjoin-contracts` recovery for this outcome.
    pub fn recovery(&self) -> RecoveryAction {
        recover(self.observation())
    }
}
