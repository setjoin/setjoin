// Parse otpauth:// URIs — RFC compliant (TOTP and HOTP).
use crate::GuardError;
use totp_rs::TOTP;

pub struct ParsedTotp {
    pub label: String,
    pub issuer: String,
    pub totp: TOTP,
}

pub fn parse_otpauth_uri(uri: &str) -> Result<ParsedTotp, GuardError> {
    let totp = TOTP::from_url(uri).map_err(|e| GuardError::InvalidUri(e.to_string()))?;

    // totp-rs splits the label path into issuer + account_name.
    // Reconstruct the full label as "Issuer:AccountName".
    let issuer = totp.issuer.clone().unwrap_or_default();
    let account = &totp.account_name;
    let label = if issuer.is_empty() {
        account.clone()
    } else {
        format!("{}:{}", issuer, account)
    };

    Ok(ParsedTotp {
        label,
        issuer,
        totp,
    })
}
