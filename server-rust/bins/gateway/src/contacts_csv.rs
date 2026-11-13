//! The contacts CSV dialect of frozen Go: `encoding/csv` with `FieldsPerRecord = -1`
//! (reader and its error texts), the default writer, the column auto-mapping and the
//! row to vCard projection (`internal/migration/csv_*.go`).
use crate::contacts_vcard::{VCard, Value};

/// Go's `*csv.ParseError` text.
#[derive(Debug, PartialEq, Eq)]
pub struct ParseError {
    start_line: usize,
    line: usize,
    column: usize,
    quote: bool,
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let what = if self.quote {
            "extraneous or missing \" in quoted-field"
        } else {
            "bare \" in non-quoted-field"
        };
        if self.start_line != self.line {
            write!(
                f,
                "record on line {}; parse error on line {}, column {}: {what}",
                self.start_line, self.line, self.column
            )
        } else {
            write!(
                f,
                "parse error on line {}, column {}: {what}",
                self.line, self.column
            )
        }
    }
}

/// Go's `csv.Reader` (comma, strict quotes, no comments, `FieldsPerRecord = -1`).
pub struct Reader<'a> {
    data: &'a [u8],
    at: usize,
    num_line: usize,
}

/// One record; fields are the raw bytes Go's strings hold.
pub type Record = Vec<Vec<u8>>;

fn nl(b: &[u8]) -> usize {
    usize::from(b.last() == Some(&b'\n'))
}

impl<'a> Reader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            at: 0,
            num_line: 0,
        }
    }

    /// Go's `readLine`: `(line, at_eof)`; `at_eof` is set only when nothing was read.
    fn line(&mut self) -> (Vec<u8>, bool) {
        self.num_line += 1;
        if self.at >= self.data.len() {
            return (Vec::new(), true);
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
        (line, false)
    }

    /// Go's `readRecord`: `Ok(None)` is `io.EOF`.
    pub fn read(&mut self) -> Result<Option<Record>, ParseError> {
        let mut line = loop {
            let (line, eof) = self.line();
            if eof {
                return Ok(None);
            }
            if line.len() == nl(&line) {
                continue;
            }
            break line;
        };
        let rec_line = self.num_line;
        let mut buffer: Vec<u8> = Vec::new();
        let mut ends: Vec<usize> = Vec::new();
        let (mut pos_line, mut pos_col) = (self.num_line, 1usize);
        let mut off = 0usize;
        'field: loop {
            let cur = &line[off..];
            if cur.is_empty() || cur[0] != b'"' {
                let i = cur.iter().position(|b| *b == b',');
                let field = match i {
                    Some(i) => &cur[..i],
                    None => &cur[..cur.len() - nl(cur)],
                };
                if let Some(j) = field.iter().position(|b| *b == b'"') {
                    return Err(ParseError {
                        start_line: rec_line,
                        line: self.num_line,
                        column: pos_col + j,
                        quote: false,
                    });
                }
                buffer.extend_from_slice(field);
                ends.push(buffer.len());
                match i {
                    Some(i) => {
                        off += i + 1;
                        pos_col += i + 1;
                        continue 'field;
                    }
                    None => break 'field,
                }
            }
            off += 1;
            pos_col += 1;
            loop {
                let cur = &line[off..];
                if let Some(i) = cur.iter().position(|b| *b == b'"') {
                    buffer.extend_from_slice(&cur[..i]);
                    off += i + 1;
                    pos_col += i + 1;
                    let after = &line[off..];
                    if after.first() == Some(&b'"') {
                        buffer.push(b'"');
                        off += 1;
                        pos_col += 1;
                    } else if after.first() == Some(&b',') {
                        off += 1;
                        pos_col += 1;
                        ends.push(buffer.len());
                        continue 'field;
                    } else if after.len() == nl(after) {
                        ends.push(buffer.len());
                        break 'field;
                    } else {
                        return Err(ParseError {
                            start_line: rec_line,
                            line: self.num_line,
                            column: pos_col - 1,
                            quote: true,
                        });
                    }
                } else if !cur.is_empty() {
                    buffer.extend_from_slice(cur);
                    pos_col += cur.len();
                    let (next, _) = self.line();
                    if !next.is_empty() {
                        pos_line += 1;
                        pos_col = 1;
                    }
                    line = next;
                    off = 0;
                } else {
                    // Abrupt end of input inside a quoted field.
                    return Err(ParseError {
                        start_line: rec_line,
                        line: pos_line,
                        column: pos_col,
                        quote: true,
                    });
                }
            }
        }
        let mut fields = Vec::with_capacity(ends.len());
        let mut previous = 0;
        for end in &ends {
            fields.push(buffer[previous..*end].to_vec());
            previous = *end;
        }
        Ok(Some(fields))
    }

    /// Go's `ReadAll`.
    pub fn read_all(&mut self) -> Result<Vec<Record>, ParseError> {
        let mut out = Vec::new();
        while let Some(record) = self.read()? {
            out.push(record);
        }
        Ok(out)
    }
}

pub fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// Go's `csv.Writer.fieldNeedsQuotes` with comma `,`.
fn needs_quotes(field: &str) -> bool {
    if field.is_empty() {
        return false;
    }
    if field == "\\." {
        return true;
    }
    if field
        .bytes()
        .any(|c| matches!(c, b'\n' | b'\r' | b'"' | b','))
    {
        return true;
    }
    field.chars().next().is_some_and(char::is_whitespace)
}

pub fn write_record(out: &mut String, fields: &[String]) {
    for (n, field) in fields.iter().enumerate() {
        if n > 0 {
            out.push(',');
        }
        if !needs_quotes(field) {
            out.push_str(field);
            continue;
        }
        out.push('"');
        out.push_str(&field.replace('"', "\"\""));
        out.push('"');
    }
    out.push('\n');
}

/// Go's `EscapeCSVCell` (CWE-1236 neutralization).
pub fn escape_cell(s: &str) -> String {
    match s.as_bytes().first() {
        Some(b'=' | b'+' | b'-' | b'@' | b'\t' | b'\r' | b'\'') => format!("'{s}"),
        _ => s.to_owned(),
    }
}

/// Go's `UnescapeCSVCell`.
pub fn unescape_cell(s: &str) -> String {
    s.strip_prefix('\'').unwrap_or(s).to_owned()
}

pub const EXPORT_HEADER: [&str; 8] = [
    "First Name",
    "Last Name",
    "Display Name",
    "E-mail Address",
    "Company",
    "Job Title",
    "Mobile Phone",
    "Notes",
];

/// Go's `Mapping`; `-1` is an absent column.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Mapping {
    pub full_name: i64,
    pub first_name: i64,
    pub last_name: i64,
    pub email: i64,
    pub company: i64,
    pub job_title: i64,
    pub phone: i64,
    pub notes: i64,
}

impl Mapping {
    pub fn empty() -> Self {
        Self {
            full_name: -1,
            first_name: -1,
            last_name: -1,
            email: -1,
            company: -1,
            job_title: -1,
            phone: -1,
            notes: -1,
        }
    }

    pub fn json(&self) -> String {
        format!(
            "{{\"fullName\":{},\"firstName\":{},\"lastName\":{},\"email\":{},\"company\":{},\"jobTitle\":{},\"phone\":{},\"notes\":{}}}",
            self.full_name,
            self.first_name,
            self.last_name,
            self.email,
            self.company,
            self.job_title,
            self.phone,
            self.notes
        )
    }
}

const FULL_NAME: &[&str] = &["name", "display name", "full name"];
const FIRST_NAME: &[&str] = &["first name", "given name", "firstname"];
const LAST_NAME: &[&str] = &["last name", "family name", "surname", "lastname"];
const EMAIL: &[&str] = &[
    "e-mail address",
    "email",
    "e-mail 1 - value",
    "email address",
    "primary email",
    "e-mail",
];
const COMPANY: &[&str] = &[
    "company",
    "organization",
    "organization 1 - name",
    "organisation",
];
const JOB_TITLE: &[&str] = &["job title", "title", "organization 1 - title"];
const PHONE: &[&str] = &[
    "mobile phone",
    "phone",
    "primary phone",
    "phone 1 - value",
    "telephone",
    "mobile",
];
const NOTES: &[&str] = &["notes", "note"];

/// Go's `DetectMapping`: the first column of each alias set wins.
pub fn detect_mapping(headers: &[String]) -> Mapping {
    let mut m = Mapping::empty();
    for (i, header) in headers.iter().enumerate() {
        let norm = header.trim().to_lowercase();
        let i = i as i64;
        let is = |set: &[&str]| set.contains(&norm.as_str());
        if m.full_name < 0 && is(FULL_NAME) {
            m.full_name = i;
        } else if m.first_name < 0 && is(FIRST_NAME) {
            m.first_name = i;
        } else if m.last_name < 0 && is(LAST_NAME) {
            m.last_name = i;
        } else if m.email < 0 && is(EMAIL) {
            m.email = i;
        } else if m.company < 0 && is(COMPANY) {
            m.company = i;
        } else if m.job_title < 0 && is(JOB_TITLE) {
            m.job_title = i;
        } else if m.phone < 0 && is(PHONE) {
            m.phone = i;
        } else if m.notes < 0 && is(NOTES) {
            m.notes = i;
        }
    }
    m
}

fn cell(row: &[String], idx: i64) -> String {
    if idx < 0 || idx as usize >= row.len() {
        return String::new();
    }
    row[idx as usize].trim().to_owned()
}

/// Go's `strings.TrimSpace` for a lone cell.
pub fn trimmed(row: &[String], idx: i64) -> String {
    cell(row, idx)
}

fn identity_uid(book: i64, kind: &str, value: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"setjoin-csv-contact-v1");
    h.update([0]);
    h.update(book.to_string().as_bytes());
    h.update([0]);
    h.update(kind.as_bytes());
    h.update([0]);
    h.update(value.as_bytes());
    let digest = h.finalize();
    let mut hex = String::from("csv-");
    for b in digest {
        hex.push_str(&format!("{b:02x}"));
    }
    hex
}

/// Go's `Mapping.RowToVCard`. The UID is the derived, namespaced identity hash;
/// `canonical` is Go's `identity.CanonicalizeAddress`.
pub fn row_to_vcard(
    m: &Mapping,
    row: &[String],
    book: i64,
    canonical: &dyn Fn(&str) -> String,
) -> VCard {
    let first = cell(row, m.first_name);
    let last = cell(row, m.last_name);
    let full = cell(row, m.full_name);
    let fn_ = if full.is_empty() {
        format!("{first} {last}").trim().to_owned()
    } else {
        full
    };
    let mut vc = VCard {
        fn_: fn_.clone(),
        n: format!("{last};{first};;;"),
        org: cell(row, m.company),
        title: cell(row, m.job_title),
        note: cell(row, m.notes),
        ..VCard::default()
    };
    let email = cell(row, m.email);
    if !email.is_empty() {
        vc.emails.push(Value {
            kind: "work".into(),
            value: email.clone(),
        });
        vc.uid = identity_uid(book, "email", &canonical(&email));
    }
    let phone = cell(row, m.phone);
    if !phone.is_empty() {
        vc.phones.push(Value {
            kind: "work".into(),
            value: phone,
        });
    }
    if vc.uid.is_empty() {
        let key = canonical(&fn_);
        if !key.is_empty() {
            vc.uid = identity_uid(book, "name", &key);
        }
    }
    vc
}

#[cfg(test)]
mod tests {
    use super::*;

    fn all(text: &str) -> Result<Vec<Vec<String>>, String> {
        Reader::new(text.as_bytes())
            .read_all()
            .map(|rows| {
                rows.iter()
                    .map(|r| r.iter().map(|f| super::text(f)).collect())
                    .collect()
            })
            .map_err(|e| e.to_string())
    }

    #[test]
    fn go_reader_errors() {
        assert_eq!(
            all("a,b\nx\"y,z\n").unwrap_err(),
            "parse error on line 2, column 2: bare \" in non-quoted-field"
        );
        assert_eq!(
            all("a\n\"x\"y\n").unwrap_err(),
            "parse error on line 2, column 3: extraneous or missing \" in quoted-field"
        );
        assert_eq!(
            all("a\n\"open,4").unwrap_err(),
            "parse error on line 2, column 8: extraneous or missing \" in quoted-field"
        );
    }

    #[test]
    fn ragged_rows_and_blank_lines() {
        assert_eq!(
            all("a,b\r\n\r\nx\n\"q,1\",\"he said \"\"hi\"\"\",z").unwrap(),
            vec![
                vec!["a", "b"],
                vec!["x"],
                vec!["q,1", "he said \"hi\"", "z"]
            ]
        );
    }

    #[test]
    fn writer_quotes_like_go() {
        let mut out = String::new();
        write_record(
            &mut out,
            &[
                "a b".into(),
                " lead".into(),
                "q\"x".into(),
                "".into(),
                "\\.".into(),
                "c,d".into(),
            ],
        );
        assert_eq!(out, "a b,\" lead\",\"q\"\"x\",,\"\\.\",\"c,d\"\n");
    }

    #[test]
    fn mapping_prefers_first_alias_column() {
        let h = |xs: &[&str]| xs.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();
        let m = detect_mapping(&h(&["Name", "E-mail", "Title", "email", "Phone"]));
        assert_eq!((m.full_name, m.email, m.job_title, m.phone), (0, 1, 2, 4));
    }
}
