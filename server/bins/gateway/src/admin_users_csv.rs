//! A faithful port of Go's `encoding/csv.Reader` with its default settings
//! (comma `,`, no comment, strict quotes, field count fixed by the first record),
//! which the user import route reads with. A record that fails to parse, or whose
//! field count differs from the header's, is an error for that record only and the
//! reader resumes on the next line, exactly as Go's.

#[derive(Debug, PartialEq, Eq)]
pub enum Record {
    Fields(Vec<String>),
    /// `ParseError` or `ErrFieldCount`: Go returns it with the (ignored) partial record.
    Error,
    Eof,
}

pub struct Reader<'a> {
    data: &'a [u8],
    at: usize,
    fields_per_record: usize,
}

impl<'a> Reader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            at: 0,
            fields_per_record: 0,
        }
    }

    /// Go's `readLine`: the next line with a trailing `\n` (`\r\n` normalized),
    /// or `None` at end of input. A final `\r` before EOF is dropped.
    fn line(&mut self) -> Option<Vec<u8>> {
        if self.at >= self.data.len() {
            return None;
        }
        let rest = &self.data[self.at..];
        let mut line = match rest.iter().position(|b| *b == b'\n') {
            Some(i) => {
                self.at += i + 1;
                rest[..=i].to_vec()
            }
            None => {
                self.at = self.data.len();
                let mut l = rest.to_vec();
                if l.last() == Some(&b'\r') {
                    l.pop();
                }
                l
            }
        };
        let n = line.len();
        if n >= 2 && line[n - 2] == b'\r' && line[n - 1] == b'\n' {
            line[n - 2] = b'\n';
            line.pop();
        }
        Some(line)
    }

    /// Go's `readRecord`.
    pub fn read(&mut self) -> Record {
        // Skip empty lines.
        let mut line = loop {
            match self.line() {
                None => return Record::Eof,
                Some(l) if l.len() == nl(&l) => continue,
                Some(l) => break l,
            }
        };
        let mut buffer: Vec<u8> = Vec::new();
        let mut ends: Vec<usize> = Vec::new();
        let mut failed = false;
        let mut off = 0usize; // consumed prefix of `line`
        'field: loop {
            let cur = &line[off..];
            if cur.is_empty() || cur[0] != b'"' {
                // Non-quoted field.
                let i = cur.iter().position(|b| *b == b',');
                let field = match i {
                    Some(i) => &cur[..i],
                    None => &cur[..cur.len() - nl(cur)],
                };
                if field.contains(&b'"') {
                    failed = true;
                    break 'field;
                }
                buffer.extend_from_slice(field);
                ends.push(buffer.len());
                match i {
                    Some(i) => {
                        off += i + 1;
                        continue 'field;
                    }
                    None => break 'field,
                }
            }
            // Quoted field.
            off += 1;
            loop {
                let cur = &line[off..];
                if let Some(i) = cur.iter().position(|b| *b == b'"') {
                    buffer.extend_from_slice(&cur[..i]);
                    off += i + 1;
                    let after = &line[off..];
                    if after.first() == Some(&b'"') {
                        buffer.push(b'"');
                        off += 1;
                    } else if after.first() == Some(&b',') {
                        off += 1;
                        ends.push(buffer.len());
                        continue 'field;
                    } else if after.len() == nl(after) {
                        ends.push(buffer.len());
                        break 'field;
                    } else {
                        failed = true;
                        break 'field;
                    }
                } else if !cur.is_empty() {
                    // End of line inside quotes: keep everything, read on.
                    buffer.extend_from_slice(cur);
                    match self.line() {
                        Some(next) => {
                            line = next;
                            off = 0;
                        }
                        None => {
                            line = Vec::new();
                            off = 0;
                        }
                    }
                } else {
                    // Abrupt end of input inside a quoted field.
                    failed = true;
                    break 'field;
                }
            }
        }
        let mut fields = Vec::with_capacity(ends.len());
        let mut previous = 0;
        for end in &ends {
            fields.push(String::from_utf8_lossy(&buffer[previous..*end]).into_owned());
            previous = *end;
        }
        if self.fields_per_record > 0 {
            if fields.len() != self.fields_per_record && !failed {
                failed = true;
            }
        } else {
            self.fields_per_record = fields.len();
        }
        if failed {
            Record::Error
        } else {
            Record::Fields(fields)
        }
    }
}

fn nl(b: &[u8]) -> usize {
    usize::from(b.last() == Some(&b'\n'))
}

/// Go's `strconv.ParseBool`.
pub fn parse_bool(text: &str) -> Option<bool> {
    match text {
        "1" | "t" | "T" | "TRUE" | "true" | "True" => Some(true),
        "0" | "f" | "F" | "FALSE" | "false" | "False" => Some(false),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn all(text: &str) -> Vec<Record> {
        let mut r = Reader::new(text.as_bytes());
        let mut out = vec![];
        loop {
            match r.read() {
                Record::Eof => return out,
                x => out.push(x),
            }
        }
    }
    fn f(xs: &[&str]) -> Record {
        Record::Fields(xs.iter().map(|s| (*s).to_owned()).collect())
    }

    #[test]
    fn plain_quoted_and_blank_lines() {
        assert_eq!(
            all("a,b\r\n\r\n\"x,1\",\"he said \"\"hi\"\"\"\nlast,"),
            vec![
                f(&["a", "b"]),
                f(&["x,1", "he said \"hi\""]),
                f(&["last", ""])
            ]
        );
    }

    #[test]
    fn count_mismatch_and_bare_quote_are_row_errors_and_reading_resumes() {
        assert_eq!(
            all("a,b\nonly\nx\"y,z\n\"ok\",fine\n"),
            vec![
                f(&["a", "b"]),
                Record::Error,
                Record::Error,
                f(&["ok", "fine"])
            ]
        );
    }

    #[test]
    fn multiline_quotes_and_unterminated_quote() {
        assert_eq!(
            all("a,b\n\"one\ntwo\",3\n\"open,4"),
            vec![f(&["a", "b"]), f(&["one\ntwo", "3"]), Record::Error]
        );
    }

    #[test]
    fn junk_after_closing_quote_is_an_error() {
        assert_eq!(
            all("a\n\"x\"y\nz\n"),
            vec![f(&["a"]), Record::Error, f(&["z"])]
        );
    }

    #[test]
    fn parse_bool_matches_go() {
        assert_eq!(parse_bool("T"), Some(true));
        assert_eq!(parse_bool("yes"), None);
        assert_eq!(parse_bool("False"), Some(false));
    }
}
