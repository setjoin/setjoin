//! Transport with Go's `readLineLimited` framing: a command line is capped at
//! 64 KiB including its newline, and each line read is bounded by 30 minutes.
use std::{io, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};
use tokio_rustls::server::TlsStream;

pub(crate) const MAX_LINE: usize = 64 * 1024;
pub(crate) const READ_TIMEOUT: Duration = Duration::from_secs(30 * 60);

pub(crate) enum Io {
    Plain(TcpStream),
    Tls(Box<TlsStream<TcpStream>>),
    /// Transient state while a STARTTLS upgrade owns the socket.
    Upgrading,
}

pub(crate) enum LineError {
    TooLong,
    Closed,
}

pub(crate) struct Conn {
    pub(crate) io: Io,
    buf: Vec<u8>,
}

impl Conn {
    pub(crate) fn new(io: Io) -> Self {
        Self {
            io,
            buf: Vec::new(),
        }
    }

    /// Bytes buffered behind the previous command are dropped on a TLS upgrade,
    /// as frozen Go abandons its old bufio.Reader.
    pub(crate) fn discard_buffered(&mut self) {
        self.buf.clear();
    }

    async fn read_some(&mut self) -> io::Result<usize> {
        let mut chunk = [0u8; 4096];
        let n = match &mut self.io {
            Io::Plain(s) => s.read(&mut chunk).await?,
            Io::Tls(s) => s.read(&mut chunk).await?,
            Io::Upgrading => return Err(io::ErrorKind::NotConnected.into()),
        };
        self.buf.extend_from_slice(&chunk[..n]);
        Ok(n)
    }

    /// One `\n`-terminated line, newline kept. A partial line at EOF is an error.
    pub(crate) async fn read_line(&mut self) -> Result<Vec<u8>, LineError> {
        loop {
            let scan = self.buf.len().min(MAX_LINE);
            if let Some(i) = self.buf[..scan].iter().position(|b| *b == b'\n') {
                return Ok(self.buf.drain(..=i).collect());
            }
            if self.buf.len() >= MAX_LINE {
                // Go consumed exactly the capped bytes; the rest stays queued.
                self.buf.drain(..MAX_LINE);
                return Err(LineError::TooLong);
            }
            match self.read_some().await {
                Ok(0) | Err(_) => return Err(LineError::Closed),
                Ok(_) => {}
            }
        }
    }

    /// Exactly `n` bytes (Go's `io.ReadFull`); EOF before that is an error.
    pub(crate) async fn read_exact(&mut self, n: usize) -> Result<Vec<u8>, LineError> {
        while self.buf.len() < n {
            match self.read_some().await {
                Ok(0) | Err(_) => return Err(LineError::Closed),
                Ok(_) => {}
            }
        }
        Ok(self.buf.drain(..n).collect())
    }

    pub(crate) async fn write_all(&mut self, bytes: &[u8]) -> io::Result<()> {
        match &mut self.io {
            Io::Plain(s) => {
                s.write_all(bytes).await?;
                s.flush().await
            }
            Io::Tls(s) => {
                s.write_all(bytes).await?;
                s.flush().await
            }
            Io::Upgrading => Err(io::ErrorKind::NotConnected.into()),
        }
    }
}
