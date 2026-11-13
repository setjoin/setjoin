use thiserror::Error;

#[derive(Debug, Error, uniffi::Error)]
#[uniffi(flat_error)]
pub enum GuardError {
    #[error("invalid uri: {0}")]
    InvalidUri(String),
    #[error("database: {0}")]
    Database(String),
    #[error("crypto: {0}")]
    Crypto(String),
    #[error("not found")]
    NotFound,
    #[error("wrong passphrase")]
    WrongPassphrase,
    /// Secure-store KEK invalidated (biometric enrolment changed) — open fell back to device-unlock; UI should offer re-enrol.
    #[error("secure store invalidated")]
    BiometricInvalidated,
    /// User cancelled the biometric prompt.
    #[error("unlock cancelled")]
    BiometricCancelled,
    /// The requested tier's hardware isn't usable (no biometric enrolled / no TPM / off-domain). Distinct from Failed (SR8).
    #[error("secure store unavailable")]
    SecureStoreUnavailable,
    /// The vault is remote-wiped (durable latch) — needs reprovision, not a normal open. Distinct from NotFound.
    #[error("vault wiped")]
    Wiped,
}

impl From<rusqlite::Error> for GuardError {
    fn from(e: rusqlite::Error) -> Self {
        GuardError::Database(e.to_string())
    }
}

impl From<crate::securestore::SecureStoreError> for GuardError {
    fn from(e: crate::securestore::SecureStoreError) -> Self {
        use crate::securestore::SecureStoreError as S;
        match e {
            S::Invalidated => GuardError::BiometricInvalidated,
            S::Cancelled => GuardError::BiometricCancelled,
            S::Unavailable => GuardError::SecureStoreUnavailable,
            S::Failed(_) => GuardError::Crypto("secure store backend error".into()), // no key/inner leak
        }
    }
}
