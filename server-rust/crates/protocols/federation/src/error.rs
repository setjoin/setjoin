use std::fmt;

/// Federation failures. The first four mirror Go's sentinel errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FedError {
    /// feature.federation is OFF (a no-op, not a wire failure).
    Disabled,
    AnchorMismatch(String),
    DomainMismatch(String),
    NotAuthorized(String),
    Other(String),
}

impl FedError {
    pub fn other(m: impl Into<String>) -> Self {
        FedError::Other(m.into())
    }
    /// The text a rustls verifier carries across the handshake boundary.
    pub(crate) fn to_wire_tag(&self) -> String {
        match self {
            FedError::AnchorMismatch(m) => format!("anchor-mismatch:{m}"),
            FedError::DomainMismatch(m) => format!("domain-mismatch:{m}"),
            other => other.to_string(),
        }
    }
    pub(crate) fn from_wire_tag(m: &str) -> Option<FedError> {
        if let Some(x) = m.strip_prefix("anchor-mismatch:") {
            Some(FedError::AnchorMismatch(x.to_string()))
        } else {
            m.strip_prefix("domain-mismatch:")
                .map(|x| FedError::DomainMismatch(x.to_string()))
        }
    }
}

impl fmt::Display for FedError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FedError::Disabled => f.write_str("federation: feature.federation is OFF"),
            FedError::AnchorMismatch(m) | FedError::DomainMismatch(m) | FedError::Other(m) => {
                f.write_str(m)
            }
            FedError::NotAuthorized(m) => write!(
                f,
                "federation: peer not locally allow-listed/enabled for the requested scope: {m}"
            ),
        }
    }
}
impl std::error::Error for FedError {}
