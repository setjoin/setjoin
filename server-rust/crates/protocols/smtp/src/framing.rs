//! Go bufio.ReadLine semantics with the same 4096-byte command cap.
use tokio::io::{self, AsyncBufRead, AsyncBufReadExt};
pub enum Line {
    Bytes(Vec<u8>),
    TooLong,
    Eof,
}
pub async fn command<R: AsyncBufRead + Unpin>(reader: &mut R) -> io::Result<Line> {
    let mut line = Vec::new();
    let mut overflow = false;
    loop {
        let buf = reader.fill_buf().await?;
        if buf.is_empty() {
            return Ok(if overflow || line.len() > 4096 {
                Line::TooLong
            } else if line.is_empty() {
                Line::Eof
            } else {
                Line::Bytes(line)
            });
        }
        let end = buf.iter().position(|&b| b == b'\n').map(|p| p + 1);
        let n = end.unwrap_or(buf.len());
        let keep = n.min(4098usize.saturating_sub(line.len()));
        line.extend_from_slice(&buf[..keep]);
        overflow |= keep < n;
        reader.consume(n);
        if end.is_some() {
            if !overflow {
                line.pop();
                if line.last() == Some(&b'\r') {
                    line.pop();
                }
            }
            return Ok(if overflow || line.len() > 4096 {
                Line::TooLong
            } else {
                Line::Bytes(line)
            });
        }
    }
}

pub const MAX_MESSAGE: usize = 157286400;
const SPILL: usize = 1 << 20;
pub struct Body {
    pub bytes: Vec<u8>,
    _large: Option<tokio::sync::OwnedSemaphorePermit>,
}
pub enum DataError {
    BareLf,
    Io,
    Saturated,
}
#[derive(Clone, Copy)]
enum DotState {
    Begin,
    Dot,
    DotCr,
    Cr,
    Data,
}
/// Frozen Go strictDotReader + spooledRead. Notably a short unexpected EOF is
/// accepted by Go's initial io.ReadFull branch; a spilled message tempfails.
pub async fn data<R: AsyncBufRead + Unpin>(
    reader: &mut R,
    large: std::sync::Arc<tokio::sync::Semaphore>,
) -> Result<Body, DataError> {
    let mut bytes = Vec::new();
    let mut state = DotState::Begin;
    let mut permit = None;
    loop {
        let buf = reader.fill_buf().await.map_err(|_| DataError::Io)?;
        if buf.is_empty() {
            // The terminator never arrived. Delivering the prefix would acknowledge
            // a truncated message (frozen Go accepted any such prefix below 1 MiB;
            // security fix 2026-11-05, #488).
            return if crate::mutants::on("smtp-accept-short-eof") && bytes.len() < SPILL {
                Ok(Body {
                    bytes,
                    _large: permit,
                })
            } else {
                Err(DataError::Io)
            };
        }
        let mut consumed = 0;
        let mut end = false;
        let mut error = false;
        for &c in buf {
            consumed += 1;
            let mut emit = |v| bytes.push(v);
            match state {
                DotState::Begin => match c {
                    b'.' => state = DotState::Dot,
                    b'\r' => state = DotState::Cr,
                    _ => {
                        state = DotState::Data;
                        emit(c)
                    }
                },
                DotState::Dot => match c {
                    b'\r' => state = DotState::DotCr,
                    b'\n' => {
                        error = true;
                        break;
                    }
                    _ => {
                        state = DotState::Data;
                        emit(c)
                    }
                },
                DotState::DotCr | DotState::Cr => {
                    if c == b'\n' {
                        if matches!(state, DotState::DotCr) {
                            end = true;
                            break;
                        }
                        state = DotState::Begin;
                        emit(b'\n');
                    } else {
                        emit(b'\r');
                        if c == b'\r' {
                            state = DotState::Cr
                        } else {
                            state = DotState::Data;
                            emit(c)
                        }
                    }
                }
                DotState::Data => match c {
                    b'\r' => state = DotState::Cr,
                    b'\n' => {
                        state = DotState::Begin;
                        emit(c)
                    }
                    _ => emit(c),
                },
            }
            if bytes.len() >= SPILL && permit.is_none() {
                break;
            }
            if bytes.len() > MAX_MESSAGE {
                break;
            }
        }
        reader.consume(consumed);
        if error {
            return Err(DataError::BareLf);
        }
        if bytes.len() >= SPILL && permit.is_none() {
            permit = Some(
                tokio::time::timeout(
                    std::time::Duration::from_secs(30),
                    large.clone().acquire_owned(),
                )
                .await
                .map_err(|_| DataError::Saturated)?
                .map_err(|_| DataError::Saturated)?,
            );
        }
        if end || bytes.len() > MAX_MESSAGE {
            return Ok(Body {
                bytes,
                _large: permit,
            });
        }
    }
}

pub fn long_line(bytes: &[u8]) -> Option<String> {
    for (i, line) in bytes.split(|&c| c == b'\n').enumerate() {
        let len = line.strip_suffix(b"\r").unwrap_or(line).len();
        if len > 998 {
            return Some(format!(
                "550 Line too long: line {} exceeds 998 characters ({len})\r\n",
                i + 1
            ));
        }
    }
    None
}
