//! A scripted IMAP source for the migration runner tests: LOGIN, LIST, EXAMINE/SELECT,
//! UID FETCH (RFC822 FLAGS), LOGOUT. Responses follow Dovecot's wording. Both the
//! frozen Go runner (record) and the Rust runner (replay) read the same fixtures.
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Notify;

#[derive(Clone)]
pub struct Message {
    pub uid: u32,
    pub raw: Vec<u8>,
    pub flags: Vec<&'static str>,
}

#[derive(Clone)]
pub struct Folder {
    pub name: String,
    pub attrs: Vec<&'static str>,
    pub uid_validity: u32,
    pub uid_next: u32,
    pub messages: Vec<Message>,
}

pub struct State {
    pub user: String,
    pub password: String,
    pub folders: Vec<Folder>,
    /// While set, `UID FETCH` waits for a release (a job parked mid-fetch).
    pub gate: Mutex<Option<Arc<Notify>>>,
    pub commands: Mutex<Vec<String>>,
    pub reached_fetch: Notify,
}

pub struct FakeImap {
    pub address: SocketAddr,
    pub state: Arc<State>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for FakeImap {
    fn drop(&mut self) {
        self.task.abort();
    }
}

pub fn message(uid: u32, subject: &str, body: &str) -> Message {
    Message {
        uid,
        raw: format!(
            "From: Alice <alice@example.org>\r\nTo: bob@example.com\r\nSubject: {subject}\r\nMessage-ID: <m{uid}-{}@example.org>\r\nDate: Mon, 02 Jan 2006 15:04:05 +0000\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n{body}\r\n",
            subject.len()
        )
        .into_bytes(),
        flags: vec![],
    }
}

/// A message without a Message-ID header (the importer invents one).
pub fn message_without_id(uid: u32, subject: &str, body: &str) -> Message {
    Message {
        uid,
        raw: format!("From: Carol <carol@example.org>\r\nSubject: {subject}\r\n\r\n{body}\r\n")
            .into_bytes(),
        flags: vec!["\\Seen"],
    }
}

pub fn folder(name: &str, attrs: &[&'static str], validity: u32, messages: Vec<Message>) -> Folder {
    let next = messages.iter().map(|m| m.uid).max().unwrap_or(0) + 1;
    Folder {
        name: name.into(),
        attrs: attrs.to_vec(),
        uid_validity: validity,
        uid_next: next,
        messages,
    }
}

impl FakeImap {
    /// Serve on `bind` (the address both oracles can reach).
    pub async fn start(
        bind: &str,
        user: &str,
        password: &str,
        folders: Vec<Folder>,
    ) -> std::io::Result<FakeImap> {
        let listener = TcpListener::bind(bind).await?;
        let address = listener.local_addr()?;
        let state = Arc::new(State {
            user: user.into(),
            password: password.into(),
            folders,
            gate: Mutex::new(None),
            commands: Mutex::new(vec![]),
            reached_fetch: Notify::new(),
        });
        let shared = state.clone();
        let task = tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                tokio::spawn(serve(stream, shared.clone()));
            }
        });
        Ok(FakeImap {
            address,
            state,
            task,
        })
    }

    /// Hold every `UID FETCH` until `release` is called.
    pub fn hold_fetches(&self) -> Arc<Notify> {
        let gate = Arc::new(Notify::new());
        *self.state.gate.lock().unwrap() = Some(gate.clone());
        gate
    }

    pub fn release(&self) {
        if let Some(gate) = self.state.gate.lock().unwrap().take() {
            gate.notify_waiters();
            gate.notify_one();
        }
    }
}

async fn serve(mut stream: TcpStream, state: Arc<State>) {
    let _ = stream
        .write_all(b"* OK [CAPABILITY IMAP4rev1 LITERAL+ ID ENABLE] Dovecot ready.\r\n")
        .await;
    let mut buffer = Vec::new();
    let mut selected: Option<usize> = None;
    loop {
        let line = loop {
            if let Some(at) = buffer.windows(2).position(|w| w == b"\r\n") {
                let line: Vec<u8> = buffer.drain(..at + 2).collect();
                break String::from_utf8_lossy(&line[..line.len() - 2]).into_owned();
            }
            let mut chunk = [0u8; 4096];
            match stream.read(&mut chunk).await {
                Ok(0) | Err(_) => return,
                Ok(n) => buffer.extend_from_slice(&chunk[..n]),
            }
        };
        let mut parts = line.splitn(2, ' ');
        let tag = parts.next().unwrap_or("").to_owned();
        let rest = parts.next().unwrap_or("").to_owned();
        state.commands.lock().unwrap().push(rest.clone());
        let upper = rest.to_ascii_uppercase();
        let reply: Vec<u8> = if upper.starts_with("LOGIN ") {
            let args = quoted_args(&rest[6..]);
            if args.first().map(String::as_str) == Some(state.user.as_str())
                && args.get(1).map(String::as_str) == Some(state.password.as_str())
            {
                format!("{tag} OK [CAPABILITY IMAP4rev1] Logged in\r\n").into_bytes()
            } else {
                format!("{tag} NO [AUTHENTICATIONFAILED] Authentication failed.\r\n").into_bytes()
            }
        } else if upper.starts_with("LIST ") {
            let mut out = String::new();
            for f in &state.folders {
                let attrs = f.attrs.join(" ");
                out.push_str(&format!("* LIST ({attrs}) \"/\" \"{}\"\r\n", f.name));
            }
            out.push_str(&format!("{tag} OK List completed.\r\n"));
            out.into_bytes()
        } else if upper.starts_with("EXAMINE ") || upper.starts_with("SELECT ") {
            let name = quoted_args(rest.split_once(' ').map_or("", |x| x.1))
                .first()
                .cloned()
                .unwrap_or_default();
            match state.folders.iter().position(|f| f.name == name) {
                Some(i) => {
                    selected = Some(i);
                    let f = &state.folders[i];
                    format!(
                        "* FLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft)\r\n* {} EXISTS\r\n* 0 RECENT\r\n* OK [UIDVALIDITY {}] UIDs valid\r\n* OK [UIDNEXT {}] Predicted next UID\r\n{tag} OK [READ-ONLY] Examine completed (0.001 + 0.000 secs).\r\n",
                        f.messages.len(), f.uid_validity, f.uid_next
                    )
                    .into_bytes()
                }
                None => {
                    format!("{tag} NO [NONEXISTENT] Mailbox doesn't exist: {name}\r\n").into_bytes()
                }
            }
        } else if upper.starts_with("UID FETCH ") {
            state.reached_fetch.notify_one();
            let gate = state.gate.lock().unwrap().clone();
            if let Some(gate) = gate {
                gate.notified().await;
            }
            let range = rest[10..].split(' ').next().unwrap_or("");
            let (lo, hi) = range.split_once(':').map_or((0, u32::MAX), |(a, b)| {
                (a.parse().unwrap_or(0), b.parse().unwrap_or(u32::MAX))
            });
            let mut out = Vec::new();
            if let Some(i) = selected {
                for (seq, m) in state.folders[i].messages.iter().enumerate() {
                    if m.uid >= lo && m.uid <= hi {
                        out.extend_from_slice(
                            format!(
                                "* {} FETCH (UID {} FLAGS ({}) RFC822 {{{}}}\r\n",
                                seq + 1,
                                m.uid,
                                m.flags.join(" "),
                                m.raw.len()
                            )
                            .as_bytes(),
                        );
                        out.extend_from_slice(&m.raw);
                        out.extend_from_slice(b")\r\n");
                    }
                }
            }
            out.extend_from_slice(format!("{tag} OK Fetch completed.\r\n").as_bytes());
            out
        } else if upper == "LOGOUT" {
            let _ = stream
                .write_all(
                    format!("* BYE Logging out\r\n{tag} OK Logout completed.\r\n").as_bytes(),
                )
                .await;
            return;
        } else {
            format!("{tag} OK done\r\n").into_bytes()
        };
        if stream.write_all(&reply).await.is_err() {
            return;
        }
    }
}

/// Quoted or bare arguments of a command line.
fn quoted_args(text: &str) -> Vec<String> {
    let mut out = vec![];
    let mut chars = text.chars().peekable();
    while let Some(&c) = chars.peek() {
        if c == ' ' {
            chars.next();
        } else if c == '"' {
            chars.next();
            let mut s = String::new();
            while let Some(c) = chars.next() {
                match c {
                    '\\' => s.extend(chars.next()),
                    '"' => break,
                    c => s.push(c),
                }
            }
            out.push(s);
        } else {
            let mut s = String::new();
            while let Some(&c) = chars.peek() {
                if c == ' ' {
                    break;
                }
                s.push(c);
                chars.next();
            }
            out.push(s);
        }
    }
    out
}
