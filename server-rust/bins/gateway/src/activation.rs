//! systemd socket activation (`LISTEN_PID`/`LISTEN_FDS`/`LISTEN_FDNAMES`) and
//! `sd_notify` (`NOTIFY_SOCKET`) readiness signaling (#264, #345, #501, #543).
//!
//! The server takes ownership only of listening TCP stream sockets systemd
//! passes to it. One unnamed descriptor is the HTTP front door. With names
//! (`FileDescriptorName=`), `http` (plus systemd's default unit names
//! `setjoin-gateway` / `setjoin-server` / `setjoind`), `https`, `auth`, `imap`,
//! `imaps`, `federation`, `smtp`, `smtps`, and `submission` are
//! mapped explicitly; any unknown descriptor name (including the retired `acme`
//! socket unit, #560) or duplicate slot is refused fail-closed.
//!
//! Every inherited descriptor in `FIRST_FD..FIRST_FD+count` is atomically
//! wrapped in `OwnedFd` with `FD_CLOEXEC` set **before** any fallible
//! validation, so any refusal drops the `Vec<OwnedFd>` and closes every
//! inherited descriptor with zero `accept()` calls.

use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::net::UnixDatagram;
use tokio::net::TcpListener;

/// The first descriptor systemd passes (`SD_LISTEN_FDS_START`).
const FIRST_FD: i32 = 3;

/// Maximum number of socket-activated listeners accepted in one process.
pub const MAX_LISTEN_FDS: usize = 9;

/// Guardrail against corrupted `LISTEN_FDS` values when wrapping raw FDs.
const MAX_CAPTURE_FDS: usize = 64;

#[derive(Debug, Default)]
pub struct Activated {
    pub http: Option<TcpListener>,
    /// Native HTTPS front door (#413), descriptor named `https`.
    pub https: Option<TcpListener>,
    /// Standalone / internal auth listener (#543), descriptor named `auth`.
    pub auth: Option<TcpListener>,
    pub imap: Option<TcpListener>,
    pub imaps: Option<TcpListener>,
    /// Federation s2s TLS, whole-listener ownership (#347).
    pub federation: Option<TcpListener>,
    /// SMTP: inbound :25, the implicit-TLS variant and submission (#501).
    pub smtp: Option<TcpListener>,
    pub smtps: Option<TcpListener>,
    pub submission: Option<TcpListener>,
}

impl Activated {
    /// Refuse any inherited listener whose owning subsystem is disabled.
    /// Dropping `self` on error closes every inherited FD with zero `accept()`
    /// calls.
    pub fn validate_for_subsystems(
        &self,
        subsystems: setjoin_boot::Subsystems,
    ) -> Result<(), String> {
        let checks: [(&str, bool, &str, bool); 9] = [
            ("http", self.http.is_some(), "http", subsystems.http),
            ("https", self.https.is_some(), "http", subsystems.http),
            ("auth", self.auth.is_some(), "auth", subsystems.auth),
            (
                "imap",
                self.imap.is_some(),
                "protocols",
                subsystems.protocols,
            ),
            (
                "imaps",
                self.imaps.is_some(),
                "protocols",
                subsystems.protocols,
            ),
            (
                "federation",
                self.federation.is_some(),
                "protocols",
                subsystems.protocols,
            ),
            (
                "smtp",
                self.smtp.is_some(),
                "protocols",
                subsystems.protocols,
            ),
            (
                "smtps",
                self.smtps.is_some(),
                "protocols",
                subsystems.protocols,
            ),
            (
                "submission",
                self.submission.is_some(),
                "protocols",
                subsystems.protocols,
            ),
        ];
        for (slot, present, subsystem, enabled) in checks {
            if present && !enabled {
                return Err(format!(
                    "socket activation: descriptor `{slot}` is not allowed when subsystem `{subsystem}` is disabled"
                ));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Slot {
    Http,
    Https,
    Auth,
    Imap,
    Imaps,
    Federation,
    Smtp,
    Smtps,
    Submission,
}

/// Map descriptor count and `LISTEN_FDNAMES` to one slot per descriptor.
///
/// Wildcard fallback is strictly restricted to single-FD unnamed activation.
/// Known systemd default unit names (`setjoin-gateway`, `setjoin-server`,
/// `setjoind`, and their `.socket` forms) map to [`Slot::Http`]; `auth` /
/// `setjoin-auth` map to [`Slot::Auth`]; any unknown name (e.g. `"authh"`) is
/// refused fail-closed.
pub fn plan(count: usize, names: Option<&str>) -> Result<Vec<Slot>, String> {
    if count == 0 || count > MAX_LISTEN_FDS {
        return Err(format!(
            "socket activation supports 1..={MAX_LISTEN_FDS} listeners (got {count})"
        ));
    }
    let names: Vec<&str> = match names.filter(|n| !n.is_empty()) {
        Some(names) => names.split(':').collect(),
        None => {
            if count != 1 {
                return Err("socket activation requires exactly one listener".into());
            }
            return Ok(vec![Slot::Http]);
        }
    };
    if names.len() != count {
        return Err("socket activation: LISTEN_FDNAMES does not match LISTEN_FDS".into());
    }
    let mut slots = Vec::with_capacity(count);
    for name in names {
        let slot = match name {
            "http"
            | "setjoin-gateway"
            | "setjoin-gateway.socket"
            | "setjoin-server"
            | "setjoin-server.socket"
            | "setjoind"
            | "setjoind.socket" => Slot::Http,
            "https" => Slot::Https,
            "auth" | "setjoin-auth" | "setjoin-auth.socket" => Slot::Auth,
            "imap" => Slot::Imap,
            "imaps" => Slot::Imaps,
            "acme" => {
                return Err(
                    "socket activation: descriptor `acme` (setjoin-acme.socket) was retired in Release N+1 (#560); remove setjoin-acme.socket and migrate to an edge TLS/ACME terminator (see docs/guides/EDGE_TLS_ACME_MIGRATION.md)"
                        .into(),
                );
            }
            "federation" => Slot::Federation,
            "smtp" => Slot::Smtp,
            "smtps" => Slot::Smtps,
            "submission" => Slot::Submission,
            other => {
                return Err(format!(
                    "socket activation: unknown descriptor name {other:?}"
                ));
            }
        };
        if slots.contains(&slot) {
            return Err(format!(
                "socket activation: more than one {slot:?} descriptor ({name})"
            ));
        }
        slots.push(slot);
    }
    Ok(slots)
}

/// Atomically take ownership of open descriptors `first_fd..first_fd+count` and
/// mark every captured descriptor `FD_CLOEXEC` before any fallible validation.
fn capture_and_cloexec(first_fd: i32, count: usize) -> Result<Vec<OwnedFd>, String> {
    let capture = count.min(MAX_CAPTURE_FDS);
    let mut owned = Vec::with_capacity(capture);
    let mut missing = false;
    let mut cloexec_err: Option<String> = None;

    for offset in 0..capture {
        let fd = first_fd + offset as i32;
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        if flags < 0 {
            missing = true;
            continue;
        }
        // SAFETY: systemd transferred ownership of `fd` to this process (verified open above).
        // Wrap immediately in OwnedFd so any later error closes every captured descriptor.
        let guard = unsafe { OwnedFd::from_raw_fd(fd) };
        if unsafe { libc::fcntl(guard.as_raw_fd(), libc::F_SETFD, flags | libc::FD_CLOEXEC) } < 0
            && cloexec_err.is_none()
        {
            cloexec_err = Some(format!(
                "socket activation: {}",
                std::io::Error::last_os_error()
            ));
        }
        owned.push(guard);
    }

    if let Some(err) = cloexec_err {
        drop(owned);
        return Err(err);
    }
    if count > MAX_CAPTURE_FDS {
        drop(owned);
        return Err(format!(
            "socket activation supports 1..={MAX_LISTEN_FDS} listeners (got {count})"
        ));
    }
    if missing || owned.len() != count {
        drop(owned);
        return Err("socket activation descriptor is not open".into());
    }
    Ok(owned)
}

fn is_listening_stream_socket(fd: i32) -> bool {
    let mut kind: libc::c_int = 0;
    let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    let is_stream = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_TYPE,
            (&mut kind as *mut libc::c_int).cast(),
            &mut len,
        ) == 0
            && kind == libc::SOCK_STREAM
    };
    if !is_stream {
        return false;
    }
    let mut accepting: libc::c_int = 0;
    len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_ACCEPTCONN,
            (&mut accepting as *mut libc::c_int).cast(),
            &mut len,
        )
    } == 0
    {
        return accepting != 0;
    }
    // Darwin defines SO_ACCEPTCONN in headers but returns ENOPROTOOPT at runtime.
    // Fall back to verifying the stream socket is not connected (getpeername -> ENOTCONN);
    // local_addr() below verifies it is bound to a TCP endpoint.
    #[cfg(target_os = "macos")]
    if std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOPROTOOPT) {
        let mut peer: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
        let mut peer_len = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
        let peer_res = unsafe {
            libc::getpeername(
                fd,
                (&mut peer as *mut libc::sockaddr_storage).cast(),
                &mut peer_len,
            )
        };
        return peer_res < 0
            && std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOTCONN);
    }
    false
}

/// Inherited systemd descriptors captured and validated synchronously BEFORE
/// constructing a Tokio runtime (so `capture_and_cloexec` never touches
/// Tokio's own epoll/eventfd descriptors on Linux when systemd did not pass
/// `SD_LISTEN_FDS_START`).
#[derive(Debug, Default)]
pub struct CapturedActivation {
    listeners: Vec<(Slot, std::net::TcpListener)>,
}

impl CapturedActivation {
    /// Refuse any inherited listener whose owning subsystem is disabled.
    /// Dropping `self` on error closes every inherited FD with zero `accept()`
    /// calls.
    pub fn validate_for_subsystems(
        &self,
        subsystems: setjoin_boot::Subsystems,
    ) -> Result<(), String> {
        for (slot, _) in &self.listeners {
            let (name, subsystem, enabled) = match slot {
                Slot::Http => ("http", "http", subsystems.http),
                Slot::Https => ("https", "http", subsystems.http),
                Slot::Auth => ("auth", "auth", subsystems.auth),
                Slot::Imap => ("imap", "protocols", subsystems.protocols),
                Slot::Imaps => ("imaps", "protocols", subsystems.protocols),
                Slot::Federation => ("federation", "protocols", subsystems.protocols),
                Slot::Smtp => ("smtp", "protocols", subsystems.protocols),
                Slot::Smtps => ("smtps", "protocols", subsystems.protocols),
                Slot::Submission => ("submission", "protocols", subsystems.protocols),
            };
            if !enabled {
                return Err(format!(
                    "socket activation: descriptor `{name}` is not allowed when subsystem `{subsystem}` is disabled"
                ));
            }
        }
        Ok(())
    }

    /// Convert captured standard listeners into Tokio [`TcpListener`]s inside an
    /// active Tokio runtime.
    pub fn into_activated(self) -> Result<Activated, String> {
        let mut out = Activated::default();
        for (slot, std_listener) in self.listeners {
            let listener = TcpListener::from_std(std_listener)
                .map_err(|e| format!("socket activation: {e}"))?;
            match slot {
                Slot::Http => out.http = Some(listener),
                Slot::Https => out.https = Some(listener),
                Slot::Auth => out.auth = Some(listener),
                Slot::Imap => out.imap = Some(listener),
                Slot::Imaps => out.imaps = Some(listener),
                Slot::Federation => out.federation = Some(listener),
                Slot::Smtp => out.smtp = Some(listener),
                Slot::Smtps => out.smtps = Some(listener),
                Slot::Submission => out.submission = Some(listener),
            }
        }
        Ok(out)
    }
}

/// Validate and convert an already-owned, `FD_CLOEXEC` descriptor into a
/// nonblocking [`std::net::TcpListener`]. On any error, `owned` is dropped and
/// closed immediately.
fn adopt_std(owned: OwnedFd) -> Result<std::net::TcpListener, String> {
    if !is_listening_stream_socket(owned.as_raw_fd()) {
        return Err("socket activation descriptor is not a listening stream socket".into());
    }
    let listener = std::net::TcpListener::from(owned);
    listener
        .local_addr()
        .map_err(|e| format!("socket activation requires TCP: {e}"))?;
    listener
        .set_nonblocking(true)
        .map_err(|e| format!("socket activation: {e}"))?;
    Ok(listener)
}

fn capture_planned(fds: Vec<OwnedFd>, names: Option<&str>) -> Result<CapturedActivation, String> {
    let count = fds.len();
    if count > 1 && names.is_none_or(str::is_empty) {
        return Err("socket activation requires exactly one listener".into());
    }
    let slots = plan(count, names)?;
    let mut listeners = Vec::with_capacity(count);
    for (owned, slot) in fds.into_iter().zip(slots) {
        listeners.push((slot, adopt_std(owned)?));
    }
    Ok(CapturedActivation { listeners })
}

#[cfg(test)]
fn adopt_planned(fds: Vec<OwnedFd>, names: Option<&str>) -> Result<Activated, String> {
    capture_planned(fds, names)?.into_activated()
}

/// Synchronously capture what systemd passed to this process BEFORE building a
/// Tokio runtime.
///
/// Captures and sets `FD_CLOEXEC` on all inherited descriptors **before** any
/// fallible check so every descriptor is closed cleanly on error.
pub fn capture_from_env() -> Result<CapturedActivation, String> {
    if std::env::var("LISTEN_PID").ok().as_deref() != Some(&std::process::id().to_string()) {
        return Ok(CapturedActivation::default());
    }
    let fds = std::env::var("LISTEN_FDS").unwrap_or_default();
    let names = std::env::var("LISTEN_FDNAMES").ok();
    std::env::remove_var("LISTEN_PID");
    std::env::remove_var("LISTEN_FDS");
    std::env::remove_var("LISTEN_FDNAMES");
    if fds == "0" {
        return Ok(CapturedActivation::default());
    }
    let raw_count: usize = fds
        .parse()
        .map_err(|_| "socket activation requires exactly one listener".to_string())?;
    if raw_count == 0 {
        return Ok(CapturedActivation::default());
    }
    // Atomically own + FD_CLOEXEC all descriptors BEFORE validating count/names/sockets.
    let owned = capture_and_cloexec(FIRST_FD, raw_count)?;
    if !(1..=MAX_LISTEN_FDS).contains(&raw_count) {
        return Err(format!(
            "socket activation supports 1..={MAX_LISTEN_FDS} listeners (got {raw_count})"
        ));
    }
    capture_planned(owned, names.as_deref())
}

/// Take what systemd passed to this process, if anything.
///
/// Prefer calling [`capture_from_env`] before building a Tokio runtime and then
/// [`CapturedActivation::into_activated`] inside the runtime.
pub fn take_from_env() -> Result<Activated, String> {
    capture_from_env()?.into_activated()
}

/// Zero-dependency systemd `sd_notify` Unix datagram helper.
///
/// Captures `NOTIFY_SOCKET` once at startup and immediately scrubs it from the
/// process environment so spawned child processes cannot forge readiness or
/// stopping signals.
#[derive(Clone, Debug, Default)]
pub struct SdNotify {
    socket: Option<String>,
}

impl SdNotify {
    /// Capture `NOTIFY_SOCKET` from the environment and immediately remove it.
    pub fn from_env_and_scrub() -> Self {
        let socket = std::env::var("NOTIFY_SOCKET")
            .ok()
            .filter(|s| !s.is_empty());
        std::env::remove_var("NOTIFY_SOCKET");
        Self { socket }
    }

    /// Construct directly from an optional socket address (for tests).
    pub fn from_socket(socket: Option<String>) -> Self {
        Self {
            socket: socket.filter(|s| !s.is_empty()),
        }
    }

    /// True when a systemd notify socket was captured.
    pub fn is_configured(&self) -> bool {
        self.socket.is_some()
    }

    /// Send a raw `sd_notify` payload (e.g. `READY=1`, `STOPPING=1`).
    /// Returns `Ok(false)` when no `NOTIFY_SOCKET` was configured.
    pub fn notify(&self, state: &str) -> std::io::Result<bool> {
        let Some(target) = self.socket.as_deref() else {
            return Ok(false);
        };
        let sock = UnixDatagram::unbound()?;
        #[cfg(target_os = "linux")]
        if let Some(abstract_name) = target.strip_prefix('@') {
            use std::os::linux::net::SocketAddrExt;
            let addr = std::os::unix::net::SocketAddr::from_abstract_name(abstract_name)?;
            sock.send_to_addr(state.as_bytes(), &addr)?;
            return Ok(true);
        }
        sock.send_to(state.as_bytes(), target)?;
        Ok(true)
    }

    /// Signal systemd that startup and pre-bind checks completed (`READY=1`).
    pub fn notify_ready(&self) -> std::io::Result<bool> {
        self.notify("READY=1")
    }

    /// Signal systemd that graceful drain has begun (`STOPPING=1`).
    pub fn notify_stopping(&self) -> std::io::Result<bool> {
        self.notify("STOPPING=1")
    }

    /// Signal systemd that live reload is in progress (`RELOADING=1`).
    pub fn notify_reloading(&self) -> std::io::Result<bool> {
        self.notify("RELOADING=1")
    }

    /// Ping systemd's service watchdog (`WATCHDOG=1`).
    pub fn notify_watchdog(&self) -> std::io::Result<bool> {
        self.notify("WATCHDOG=1")
    }

    /// Publish a single-line human-readable systemd status (`STATUS=...`).
    /// Embedded `\r`/`\n` bytes are stripped so callers cannot inject extra
    /// `sd_notify` fields.
    pub fn notify_status(&self, status: &str) -> std::io::Result<bool> {
        let sanitized: String = status
            .chars()
            .filter(|c| !matches!(c, '\r' | '\n'))
            .collect();
        self.notify(&format!("STATUS={sanitized}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_unnamed_descriptor_is_http_and_unnamed_pairs_are_refused() {
        assert_eq!(plan(1, None).unwrap(), vec![Slot::Http]);
        assert_eq!(plan(1, Some("")).unwrap(), vec![Slot::Http]);
        assert!(plan(2, None).unwrap_err().contains("exactly one listener"));
    }

    #[test]
    fn names_select_all_nine_slots_and_default_unit_names_map_to_http() {
        assert_eq!(
            plan(3, Some("setjoin-gateway:imap:imaps")).unwrap(),
            vec![Slot::Http, Slot::Imap, Slot::Imaps]
        );
        assert_eq!(plan(1, Some("setjoin-server")).unwrap(), vec![Slot::Http]);
        assert_eq!(plan(1, Some("setjoind")).unwrap(), vec![Slot::Http]);
        assert_eq!(plan(1, Some("imaps")).unwrap(), vec![Slot::Imaps]);
        assert_eq!(plan(1, Some("auth")).unwrap(), vec![Slot::Auth]);
        assert_eq!(
            plan(2, Some("imap:http")).unwrap(),
            vec![Slot::Imap, Slot::Http]
        );
        assert_eq!(
            plan(
                9,
                Some("http:https:auth:imap:imaps:federation:smtp:smtps:submission")
            )
            .unwrap(),
            vec![
                Slot::Http,
                Slot::Https,
                Slot::Auth,
                Slot::Imap,
                Slot::Imaps,
                Slot::Federation,
                Slot::Smtp,
                Slot::Smtps,
                Slot::Submission,
            ]
        );
        let acme_err = plan(1, Some("acme")).unwrap_err();
        assert!(
            acme_err.contains("retired")
                && acme_err.contains("#560")
                && acme_err.contains("docs/guides/EDGE_TLS_ACME_MIGRATION.md"),
            "{acme_err}"
        );
        assert!(plan(
            10,
            Some("http:https:auth:imap:imaps:federation:smtp:smtps:submission:extra")
        )
        .is_err());
    }

    #[test]
    fn names_select_the_smtp_listeners() {
        assert_eq!(
            plan(4, Some("http:smtp:smtps:submission")).unwrap(),
            vec![Slot::Http, Slot::Smtp, Slot::Smtps, Slot::Submission]
        );
        assert!(plan(2, Some("smtp:smtp"))
            .unwrap_err()
            .contains("more than one"));
    }

    #[test]
    fn unknown_mismatched_or_duplicate_descriptors_are_refused_fail_closed() {
        assert!(plan(2, Some("imap"))
            .unwrap_err()
            .contains("does not match"));
        assert!(plan(2, Some("imap:imap"))
            .unwrap_err()
            .contains("more than one"));
        assert!(plan(1, Some("authh"))
            .unwrap_err()
            .contains("unknown descriptor name"));
        assert!(plan(2, Some("http:authh"))
            .unwrap_err()
            .contains("unknown descriptor name"));
        assert!(plan(2, Some("a:b"))
            .unwrap_err()
            .contains("unknown descriptor name"));
    }

    #[tokio::test]
    async fn validate_for_subsystems_refuses_disabled_slots() {
        use setjoin_boot::Subsystems;
        let l1 = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let l2 = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let activated = Activated {
            http: Some(l1),
            auth: Some(l2),
            ..Activated::default()
        };
        assert!(activated
            .validate_for_subsystems(Subsystems {
                http: true,
                auth: true,
                protocols: false,
                workers: false,
            })
            .is_ok());
        let err = activated
            .validate_for_subsystems(Subsystems {
                http: true,
                auth: false,
                protocols: false,
                workers: false,
            })
            .unwrap_err();
        assert!(err.contains("`auth`") && err.contains("disabled"));
    }

    #[tokio::test]
    async fn failed_validation_atomically_closes_every_owned_fd() {
        use std::io::Read;
        use std::os::unix::net::UnixStream;

        // Use socket pairs and verify EOF on the retained peers instead of probing
        // raw integer FD numbers with fcntl(F_GETFD), which races with parallel
        // test threads reusing the closed FD numbers in the same process.
        let (a1, mut peer1) = UnixStream::pair().unwrap();
        let (a2, mut peer2) = UnixStream::pair().unwrap();
        peer1
            .set_read_timeout(Some(std::time::Duration::from_secs(2)))
            .unwrap();
        peer2
            .set_read_timeout(Some(std::time::Duration::from_secs(2)))
            .unwrap();
        let owned1 = OwnedFd::from(a1);
        let owned2 = OwnedFd::from(a2);

        // Typo name "authh" fails validation; BOTH FDs must be closed on return.
        let err = adopt_planned(vec![owned1, owned2], Some("http:authh")).unwrap_err();
        assert!(err.contains("unknown descriptor name"));
        let mut buf = [0u8; 1];
        assert_eq!(peer1.read(&mut buf).unwrap(), 0);
        assert_eq!(peer2.read(&mut buf).unwrap(), 0);
    }

    #[test]
    fn sd_notify_sends_ready_and_stopping_and_scrubs_env() {
        let dir = tempfile::tempdir().unwrap();
        let sock_path = dir.path().join("notify.sock");
        let server = UnixDatagram::bind(&sock_path).unwrap();
        server
            .set_read_timeout(Some(std::time::Duration::from_secs(2)))
            .unwrap();

        std::env::set_var("NOTIFY_SOCKET", &sock_path);
        let notify = SdNotify::from_env_and_scrub();
        assert!(notify.is_configured());
        assert!(std::env::var("NOTIFY_SOCKET").is_err());

        assert!(notify.notify_ready().unwrap());
        let mut buf = [0u8; 64];
        let n = server.recv(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"READY=1");

        assert!(notify.notify_stopping().unwrap());
        let n = server.recv(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"STOPPING=1");

        assert!(notify.notify_watchdog().unwrap());
        let n = server.recv(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"WATCHDOG=1");

        assert!(notify.notify_status("serving\nREADY=1\r").unwrap());
        let n = server.recv(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"STATUS=servingREADY=1");

        let noop = SdNotify::from_socket(None);
        assert!(!noop.notify_ready().unwrap());
    }
}
