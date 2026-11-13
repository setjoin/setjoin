//! In-process fake DNS server (RFC 1035 subset) for the AD discovery oracle
//! (#381): answers `SRV` questions from a small zone and `NXDOMAIN` for every
//! other name, over UDP. Shared by the frozen-Go recorder (the Go container
//! gets a `resolv.conf` naming it) and the Rust replay. Test support only.
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use tokio::net::UdpSocket;

/// One SRV record: priority, weight, port, target.
pub type Srv = (u16, u16, u16, String);

pub struct FakeDns {
    pub addr: SocketAddr,
    log: Arc<Mutex<Vec<String>>>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for FakeDns {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn labels(name: &str) -> Vec<u8> {
    let mut out = vec![];
    for label in name
        .trim_end_matches('.')
        .split('.')
        .filter(|l| !l.is_empty())
    {
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    out
}

/// Question name (lower case, no trailing dot), type, and the question bytes.
fn question(packet: &[u8]) -> Option<(String, u16, &[u8])> {
    if packet.len() < 12 {
        return None;
    }
    let mut at = 12;
    let mut name = vec![];
    loop {
        let len = *packet.get(at)? as usize;
        at += 1;
        if len == 0 {
            break;
        }
        name.push(String::from_utf8_lossy(packet.get(at..at + len)?).to_lowercase());
        at += len;
    }
    let qtype = u16::from_be_bytes([*packet.get(at)?, *packet.get(at + 1)?]);
    Some((name.join("."), qtype, packet.get(12..at + 4)?))
}

fn reply(
    packet: &[u8],
    zone: &HashMap<String, Vec<Srv>>,
    log: &Mutex<Vec<String>>,
) -> Option<Vec<u8>> {
    let (name, qtype, question) = question(packet)?;
    log.lock()
        .unwrap()
        .push(format!("dns type={qtype} name={name}"));
    let answers: &[Srv] = if qtype == 33 {
        zone.get(&name).map(Vec::as_slice).unwrap_or(&[])
    } else {
        &[]
    };
    let known = zone.contains_key(&name);
    // QR, RD copied, RA; NXDOMAIN (3) unless the name exists in the zone.
    let rcode: u8 = if known { 0 } else { 3 };
    let mut out = vec![
        packet[0],
        packet[1],
        0x81 | (packet[2] & 0x01),
        0x80 | rcode,
    ];
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&(answers.len() as u16).to_be_bytes());
    out.extend_from_slice(&[0, 0, 0, 0]);
    out.extend_from_slice(question);
    for (priority, weight, port, target) in answers {
        out.extend_from_slice(&[0xc0, 0x0c, 0, 33, 0, 1, 0, 0, 0, 0]);
        let target = labels(target);
        out.extend_from_slice(&((6 + target.len()) as u16).to_be_bytes());
        out.extend_from_slice(&priority.to_be_bytes());
        out.extend_from_slice(&weight.to_be_bytes());
        out.extend_from_slice(&port.to_be_bytes());
        out.extend_from_slice(&target);
    }
    Some(out)
}

impl FakeDns {
    /// Bind `bind` and serve `zone` (lower-case owner names, no trailing dot).
    pub async fn start(bind: SocketAddr, zone: Vec<(String, Vec<Srv>)>) -> std::io::Result<Self> {
        let socket = UdpSocket::bind(bind).await?;
        let addr = socket.local_addr()?;
        let zone: HashMap<String, Vec<Srv>> = zone.into_iter().collect();
        let log = Arc::new(Mutex::new(vec![]));
        let seen = log.clone();
        let task = tokio::spawn(async move {
            let mut buffer = [0u8; 512];
            loop {
                let Ok((n, peer)) = socket.recv_from(&mut buffer).await else {
                    return;
                };
                if let Some(answer) = reply(&buffer[..n], &zone, &seen) {
                    let _ = socket.send_to(&answer, peer).await;
                }
            }
        });
        Ok(Self { addr, log, task })
    }

    /// Questions received so far (`dns type=33 name=_ldap._tcp.x`).
    pub fn log(&self) -> Vec<String> {
        self.log.lock().unwrap().clone()
    }
    pub fn clear_log(&self) {
        self.log.lock().unwrap().clear();
    }
}
