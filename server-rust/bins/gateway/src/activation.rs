//! systemd socket activation (`LISTEN_PID`/`LISTEN_FDS`/`LISTEN_FDNAMES`).
//!
//! The gateway takes ownership only of listening TCP streams systemd passes to
//! it. One unnamed descriptor is the HTTP front door (#264). With names
//! (`FileDescriptorName=`), `imap` and `imaps` are the IMAP listeners (#345),
//! `smtp` (:25), `smtps` (implicit TLS) and `submission` (:587) are the SMTP
//! listeners (#501) and any other single name (systemd's default is the unit name) is HTTP; a
//! duplicate name or a second HTTP descriptor is refused.
use std::os::fd::FromRawFd;
use tokio::net::TcpListener;

/// The first descriptor systemd passes.
const FIRST_FD: i32 = 3;

#[derive(Debug, Default)]
pub struct Activated {
    pub http: Option<TcpListener>,
    /// Native HTTPS front door (#413), descriptor named `https`.
    pub https: Option<TcpListener>,
    pub imap: Option<TcpListener>,
    pub imaps: Option<TcpListener>,
    /// The :80 descriptor named `acme` (#305): HTTP-01 answers and the https redirect.
    pub acme: Option<TcpListener>,
    /// Federation s2s TLS, whole-listener ownership (#347).
    pub federation: Option<TcpListener>,
    /// SMTP: inbound :25, the implicit-TLS variant and submission (#501).
    pub smtp: Option<TcpListener>,
    pub smtps: Option<TcpListener>,
    pub submission: Option<TcpListener>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Slot {
    Http,
    Https,
    Imap,
    Imaps,
    Acme,
    Federation,
    Smtp,
    Smtps,
    Submission,
}

/// Map descriptor count and `LISTEN_FDNAMES` to one slot per descriptor.
pub fn plan(count: usize, names: Option<&str>) -> Result<Vec<Slot>, String> {
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
            "https" => Slot::Https,
            "imap" => Slot::Imap,
            "imaps" => Slot::Imaps,
            "acme" => Slot::Acme,
            "federation" => Slot::Federation,
            "smtp" => Slot::Smtp,
            "smtps" => Slot::Smtps,
            "submission" => Slot::Submission,
            _ => Slot::Http,
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

/// Take descriptor `fd` after checking it is an open listening stream socket.
fn adopt(fd: i32) -> Result<TcpListener, String> {
    let mut kind: libc::c_int = 0;
    let mut accepting: libc::c_int = 0;
    let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    // getsockopt validates that the descriptor is an open listening stream
    // socket before from_raw_fd transfers its ownership to Rust.
    let valid = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_TYPE,
            (&mut kind as *mut libc::c_int).cast(),
            &mut len,
        ) == 0
            && kind == libc::SOCK_STREAM
            && libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_ACCEPTCONN,
                (&mut accepting as *mut libc::c_int).cast(),
                &mut len,
            ) == 0
            && accepting != 0
    };
    if !valid {
        return Err("socket activation descriptor is not a listening stream socket".into());
    }
    // Do not leak the activated socket to any subsequently spawned process.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) } < 0 {
        return Err(format!(
            "socket activation: {}",
            std::io::Error::last_os_error()
        ));
    }
    // SAFETY: systemd transfers ownership of the descriptor, validated above.
    let listener = unsafe { std::net::TcpListener::from_raw_fd(fd) };
    listener
        .local_addr()
        .map_err(|e| format!("socket activation requires TCP: {e}"))?;
    listener
        .set_nonblocking(true)
        .map_err(|e| format!("socket activation: {e}"))?;
    TcpListener::from_std(listener).map_err(|e| format!("socket activation: {e}"))
}

/// Take what systemd passed to this process, if anything.
pub fn take_from_env() -> Result<Activated, String> {
    let mut out = Activated::default();
    if std::env::var("LISTEN_PID").ok().as_deref() != Some(&std::process::id().to_string()) {
        return Ok(out);
    }
    let fds = std::env::var("LISTEN_FDS").unwrap_or_default();
    let names = std::env::var("LISTEN_FDNAMES").ok();
    std::env::remove_var("LISTEN_PID");
    std::env::remove_var("LISTEN_FDS");
    std::env::remove_var("LISTEN_FDNAMES");
    if fds == "0" {
        return Ok(out);
    }
    let count: usize = match fds.as_str() {
        "1" => 1,
        other => other
            .parse()
            .ok()
            .filter(|n| (2..=9).contains(n) && names.as_deref().is_some_and(|n| !n.is_empty()))
            .ok_or("socket activation requires exactly one listener")?,
    };
    let slots = plan(count, names.as_deref())?;
    for (offset, slot) in slots.into_iter().enumerate() {
        let listener = adopt(FIRST_FD + offset as i32)?;
        match slot {
            Slot::Http => out.http = Some(listener),
            Slot::Https => out.https = Some(listener),
            Slot::Imap => out.imap = Some(listener),
            Slot::Imaps => out.imaps = Some(listener),
            Slot::Acme => out.acme = Some(listener),
            Slot::Federation => out.federation = Some(listener),
            Slot::Smtp => out.smtp = Some(listener),
            Slot::Smtps => out.smtps = Some(listener),
            Slot::Submission => out.submission = Some(listener),
        }
    }
    Ok(out)
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
    fn names_select_the_imap_listeners_and_the_default_unit_name_is_http() {
        assert_eq!(
            plan(3, Some("setjoin-gateway:imap:imaps")).unwrap(),
            vec![Slot::Http, Slot::Imap, Slot::Imaps]
        );
        assert_eq!(plan(1, Some("imaps")).unwrap(), vec![Slot::Imaps]);
        assert_eq!(
            plan(2, Some("imap:http")).unwrap(),
            vec![Slot::Imap, Slot::Http]
        );
    }

    #[test]
    fn names_select_the_smtp_listeners() {
        assert_eq!(
            plan(4, Some("http:smtp:smtps:submission")).unwrap(),
            vec![Slot::Http, Slot::Smtp, Slot::Smtps, Slot::Submission]
        );
        assert!(plan(2, Some("smtp:smtp")).unwrap_err().contains("more than one"));
    }

    #[test]
    fn mismatched_or_duplicate_descriptors_are_refused() {
        assert!(plan(2, Some("imap"))
            .unwrap_err()
            .contains("does not match"));
        assert!(plan(2, Some("imap:imap"))
            .unwrap_err()
            .contains("more than one"));
        assert!(plan(2, Some("a:b")).unwrap_err().contains("more than one"));
    }
}
