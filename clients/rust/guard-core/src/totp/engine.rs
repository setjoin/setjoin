use crate::{GuardError, TotpCode};
use totp_rs::TOTP;

pub fn generate(totp: &TOTP) -> Result<TotpCode, GuardError> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| GuardError::Crypto(e.to_string()))?
        .as_secs();
    let code = totp.generate(now);
    let step = totp.step;
    let valid_until = ((now / step) + 1) * step;
    Ok(TotpCode {
        code,
        valid_until: valid_until as i64,
        period: step as u32,
    })
}
