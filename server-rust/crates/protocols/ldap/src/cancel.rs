//! RFC 3909 request value. BER parsing stays in the unmodified codec library;
//! the protocol errors retain frozen Go's messages for recorded invalid forms.
use ldap3_lber::{common::TagClass, parse::Parser, structure::PL};
pub const OID: &str = "1.3.6.1.1.8";
pub fn target(value: Option<&[u8]>) -> Result<i64, String> {
    let value = value.ok_or_else(|| "cancel request: missing requestValue".to_string())?;
    let decode_error = || {
        "cancel request: failed to decode requestValue: asn1: syntax error: sequence truncated"
            .to_string()
    };
    let (rest, tag) = Parser::new(4).parse(value).map_err(|_| decode_error())?;
    if !rest.is_empty() {
        return Err("cancel request: trailing data after requestValue".into());
    }
    if tag.class != TagClass::Universal || tag.id != 16 {
        return Err(decode_error());
    }
    let PL::C(children) = tag.payload else {
        return Err(decode_error());
    };
    let Some(integer) = children.first() else {
        return Err(decode_error());
    };
    if integer.class != TagClass::Universal || integer.id != 2 {
        return Err(decode_error());
    }
    let PL::P(bytes) = &integer.payload else {
        return Err(decode_error());
    };
    if bytes.is_empty() || bytes.len() > 8 {
        return Err(decode_error());
    }
    let mut id = if bytes[0] & 0x80 == 0 { 0i64 } else { -1i64 };
    for byte in bytes {
        id = (id << 8) | i64::from(*byte)
    }
    if id < 1 {
        return Err(format!("cancel request: invalid cancelID {id}"));
    }
    Ok(id)
}

use ldap3_proto::proto::{LdapMsg, LdapOp, LdapResultCode};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};
#[derive(Default)]
pub struct Registry(Mutex<HashMap<i32, (bool, tokio::sync::watch::Sender<bool>)>>);
pub struct Registration {
    registry: Arc<Registry>,
    id: i32,
}
impl Drop for Registration {
    fn drop(&mut self) {
        self.registry.0.lock().unwrap().remove(&self.id);
    }
}
impl Registry {
    pub fn register(
        self: &Arc<Self>,
        message: &LdapMsg,
    ) -> (Registration, tokio::sync::watch::Receiver<bool>) {
        let noncancelable = matches!(
            message.op,
            LdapOp::BindRequest(_) | LdapOp::AbandonRequest(_)
        ) || matches!(&message.op,LdapOp::ExtendedRequest(r) if r.name==OID||r.name=="1.3.6.1.4.1.1466.20037");
        let (sender, receiver) = tokio::sync::watch::channel(false);
        self.0
            .lock()
            .unwrap()
            .insert(message.msgid, (noncancelable, sender));
        (
            Registration {
                registry: self.clone(),
                id: message.msgid,
            },
            receiver,
        )
    }
    pub fn cancel(&self, id: i64) -> LdapResultCode {
        let Ok(id) = i32::try_from(id) else {
            return LdapResultCode::NoSuchOperation;
        };
        let entries = self.0.lock().unwrap();
        let Some((noncancelable, sender)) = entries.get(&id) else {
            return LdapResultCode::NoSuchOperation;
        };
        if *noncancelable {
            return LdapResultCode::CannotCancel;
        }
        let _ = sender.send(true);
        LdapResultCode::Canceled
    }
}
