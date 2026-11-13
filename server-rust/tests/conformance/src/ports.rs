//! Loopback ports for tests that hand a port to a child process (#472).
//!
//! The old pattern, `bind("127.0.0.1:0")`, read the port and drop the listener, races two ways:
//! the kernel can give the freed port to another test's `:0` bind before the child binds it, and
//! two such tests can pick the same one. A request then lands in a stranger's server. Ports here
//! come from 20000..32000, below the ephemeral range (32768+), so `:0` binds never receive them,
//! and each is claimed with an exclusive lock file that lives as long as the process, so no other
//! test process of the same run receives it either.
use std::fs::File;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Mutex;

const FIRST: u32 = 20_000;
const SPAN: u32 = 12_000;

static HELD: Mutex<Vec<File>> = Mutex::new(Vec::new());
static NEXT: AtomicU32 = AtomicU32::new(0);

/// Claims a port: lock file first, then a bind to prove it is free right now.
fn claim() -> std::net::TcpListener {
    let dir = std::env::temp_dir().join("setjoin-test-ports");
    let _ = std::fs::create_dir_all(&dir);
    let seed = std::process::id().wrapping_mul(2_654_435_761);
    for _ in 0..SPAN * 2 {
        let step = NEXT.fetch_add(1, Ordering::SeqCst);
        let port = (FIRST + seed.wrapping_add(step.wrapping_mul(37)) % SPAN) as u16;
        let Ok(lock) = File::options().create(true).write(true).truncate(false).open(dir.join(format!("{port}.lock"))) else {
            continue;
        };
        if lock.try_lock().is_err() {
            continue;
        }
        if let Ok(listener) = std::net::TcpListener::bind(("127.0.0.1", port)) {
            HELD.lock().unwrap_or_else(|e| e.into_inner()).push(lock);
            return listener;
        }
    }
    panic!("no free test port in {FIRST}..{}", FIRST + SPAN);
}

/// A bound std listener on a reserved port (callers read `local_addr()` and drop it before the
/// child binds, exactly as with the old `:0` pattern).
pub fn std_listener() -> std::net::TcpListener {
    claim()
}

/// The same as a tokio listener.
pub async fn listener() -> tokio::net::TcpListener {
    let std = claim();
    std.set_nonblocking(true).expect("nonblocking");
    tokio::net::TcpListener::from_std(std).expect("tokio listener")
}

/// A reserved address with the listener already dropped.
pub fn address() -> SocketAddr {
    claim().local_addr().expect("local addr")
}

/// Whether process `pid` holds the listening IPv4 TCP socket on `addr` (via /proc), so a connect
/// that succeeds against a stranger that took the port is not mistaken for the child being ready.
pub fn listens_here(pid: u32, addr: SocketAddr) -> bool {
    let std::net::IpAddr::V4(ip) = addr.ip() else { return false };
    let o = ip.octets();
    let local = format!("{:02X}{:02X}{:02X}{:02X}:{:04X}", o[3], o[2], o[1], o[0], addr.port());
    let Ok(table) = std::fs::read_to_string("/proc/net/tcp") else { return false };
    let inodes: Vec<&str> = table
        .lines()
        .skip(1)
        .filter_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            (f.get(1) == Some(&local.as_str()) && f.get(3) == Some(&"0A")).then(|| f[9])
        })
        .collect();
    let Ok(fds) = std::fs::read_dir(format!("/proc/{pid}/fd")) else { return false };
    fds.flatten().any(|fd| {
        std::fs::read_link(fd.path()).is_ok_and(|t| {
            let t = t.to_string_lossy();
            inodes.iter().any(|i| t == format!("socket:[{i}]"))
        })
    })
}
