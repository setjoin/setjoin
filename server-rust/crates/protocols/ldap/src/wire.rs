//! Frozen vjeantet/ldapserver emits a universal SEQUENCE for its generic
//! responses, rather than an LDAP application tag. Preserve those exact BER
//! bytes without changing the upstream codec. Only serialization is adapted.
use bytes::BytesMut;
use ldap3_lber::{
    common::TagClass,
    structure::{StructureTag, PL},
};
use ldap3_proto::{proto::LdapMsg, LdapCodec};
use std::io;
use tokio_util::codec::{Decoder, Encoder};
pub struct Codec(pub LdapCodec);
pub struct Response {
    pub message: LdapMsg,
    pub generic: bool,
}
impl Decoder for Codec {
    type Item = LdapMsg;
    type Error = io::Error;
    fn decode(&mut self, b: &mut BytesMut) -> io::Result<Option<LdapMsg>> {
        // Go's admissionConn refuses attacker-declared lengths before reading
        // or allocating the body. The upstream codec's buffer cap alone waits
        // for payload bytes, so check the small BER frame header first.
        if let Some(&tag) = b.first() {
            if tag != 0x30 {
                return Err(io::Error::other("LDAP frame must be a sequence"));
            }
        }
        if b.len() >= 2 {
            let lead = b[1];
            let count = if lead & 0x80 == 0 {
                0
            } else {
                usize::from(lead & 0x7f)
            };
            if lead & 0x80 != 0 && (count == 0 || count > 4) {
                return Err(io::Error::other("unsupported LDAP length"));
            }
            if b.len() >= 2 + count {
                let length = if count == 0 {
                    usize::from(lead)
                } else {
                    b[2..2 + count]
                        .iter()
                        .fold(0usize, |n, x| n * 256 + usize::from(*x))
                };
                if length > 1 << 20 {
                    return Err(io::Error::other("LDAP frame exceeds limit"));
                }
            }
        }
        self.0.decode(b)
    }
}
impl Encoder<Response> for Codec {
    type Error = io::Error;
    fn encode(&mut self, response: Response, b: &mut BytesMut) -> io::Result<()> {
        if !response.generic {
            return self.0.encode(response.message, b);
        }
        let mut tag: StructureTag = response.message.into();
        if let PL::C(parts) = &mut tag.payload {
            parts[1].class = TagClass::Universal;
            parts[1].id = 16;
        }
        ldap3_lber::write::encode_into(b, tag)
    }
}
