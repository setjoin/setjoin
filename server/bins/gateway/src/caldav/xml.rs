//! Go encoding/xml wire order, whitespace, escaping and empty-element form.
//! CalDAV's response catalog deliberately retains Go's omitted empty markers.
pub const CAL: &str = dav_server::caldav::NS_CALDAV_URI;
pub const HEADER: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n";
#[derive(Clone)]
pub struct Element {
    pub name: String,
    pub attrs: Vec<(String, String)>,
    pub text: String,
    pub children: Vec<Element>,
    pub raw: Option<String>,
}
pub fn text(name: &str, value: impl Into<String>) -> Element {
    Element {
        name: name.into(),
        attrs: vec![],
        text: value.into(),
        children: vec![],
        raw: None,
    }
}
pub fn node(name: &str, children: Vec<Element>) -> Element {
    let mut e = text(name, "");
    e.children = children;
    e
}
impl Element {
    pub fn attr(mut self, name: &str, value: &str) -> Self {
        self.attrs.push((name.into(), value.into()));
        self
    }
    pub fn cal(self) -> Self {
        self.attr("xmlns", CAL)
    }
    fn write(&self, depth: usize, out: &mut String) {
        let indent = "  ".repeat(depth);
        out.push_str(&indent);
        out.push('<');
        out.push_str(&self.name);
        for (k, v) in &self.attrs {
            out.push(' ');
            out.push_str(k);
            out.push_str("=\"");
            out.push_str(&escape(v));
            out.push('"');
        }
        out.push('>');
        out.push_str(&escape(&self.text));
        if let Some(raw) = &self.raw {
            out.push_str(raw);
        }
        if !self.children.is_empty() {
            out.push('\n');
            for c in &self.children {
                c.write(depth + 1, out);
                out.push('\n');
            }
            out.push_str(&indent);
        }
        out.push_str("</");
        out.push_str(&self.name);
        out.push('>');
    }
    pub fn document(&self) -> String {
        let mut s = HEADER.to_owned();
        self.write(0, &mut s);
        s
    }
}
pub fn escape(value: &str) -> String {
    let mut s = String::new();
    for c in value.chars() {
        match c {
            '&' => s.push_str("&amp;"),
            '<' => s.push_str("&lt;"),
            '>' => s.push_str("&gt;"),
            '"' => s.push_str("&#34;"),
            '\'' => s.push_str("&#39;"),
            '\t' => s.push_str("&#x9;"),
            '\n' => s.push_str("&#xA;"),
            '\r' => s.push_str("&#xD;"),
            c if c < ' ' || matches!(c, '\u{fffe}' | '\u{ffff}') => s.push('\u{fffd}'),
            c => s.push(c),
        }
    }
    s
}
pub fn response(href: &str, present: Vec<Element>, missing: Vec<Element>, all: bool) -> Element {
    let mut children = vec![text("href", href)];
    for (props, status, include) in [
        (present, "HTTP/1.1 200 OK", all),
        (missing, "HTTP/1.1 404 Not Found", false),
    ] {
        if include || !props.is_empty() {
            children.push(node(
                "propstat",
                vec![node("prop", props), text("status", status)],
            ));
        }
    }
    node("response", children)
}
pub fn multistatus(responses: Vec<Element>, token: Option<&str>) -> String {
    let mut children = responses;
    if let Some(t) = token {
        children.push(text("sync-token", t));
    }
    node("multistatus", children)
        .attr("xmlns", "DAV:")
        .attr("xmlns:C", CAL)
        .document()
}
pub fn components() -> Element {
    use dav_server::caldav::CalendarComponentType::{VEvent, VTodo};
    node(
        "supported-calendar-component-set",
        [VEvent, VTodo]
            .iter()
            .map(|t| text("comp", "").cal().attr("name", t.as_str()))
            .collect(),
    )
    .cal()
}

// Namespace-aware request tree: strict XML, no DTD/entity expansion, and the
// first document only (encoding/xml.Decoder.Decode ignores trailing documents).
#[derive(Default)]
pub struct Input {
    pub name: String,
    pub ns: String,
    pub text: String,
    pub attrs: Vec<(String, String)>,
    pub children: Vec<Input>,
}
impl Input {
    pub fn child(&self, name: &str) -> Option<&Input> {
        self.children.iter().find(|c| c.name == name)
    }
    pub fn attr(&self, name: &str) -> &str {
        self.attrs
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
            .unwrap_or("")
    }
}
pub fn parse(bytes: &[u8]) -> Result<Input, ()> {
    use quick_xml::{events::Event, name::ResolveResult, NsReader};
    let source = std::str::from_utf8(bytes).map_err(|_| ())?;
    let mut reader = NsReader::from_str(source);
    reader.config_mut().expand_empty_elements = true;
    let mut stack: Vec<Input> = vec![];
    loop {
        match reader.read_event().map_err(|_| ())? {
            Event::Start(e) => {
                let (ns, name) = reader.resolver().resolve_element(e.name());
                let ns = match ns {
                    ResolveResult::Bound(n) => String::from_utf8_lossy(n.as_ref()).into_owned(),
                    ResolveResult::Unknown(n) => String::from_utf8_lossy(&n).into_owned(),
                    ResolveResult::Unbound => String::new(),
                };
                let attrs = e
                    .attributes()
                    .map(|a| {
                        let a = a.map_err(|_| ())?;
                        Ok((
                            String::from_utf8_lossy(a.key.local_name().as_ref()).into_owned(),
                            a.decoded_and_normalized_value(
                                quick_xml::XmlVersion::Implicit1_0,
                                reader.decoder(),
                            )
                            .map_err(|_| ())?
                            .into_owned(),
                        ))
                    })
                    .collect::<Result<_, ()>>()?;
                stack.push(Input {
                    name: String::from_utf8_lossy(name.as_ref()).into_owned(),
                    ns,
                    attrs,
                    ..Input::default()
                });
            }
            Event::End(_) => {
                let node = stack.pop().ok_or(())?;
                if let Some(parent) = stack.last_mut() {
                    parent.children.push(node)
                } else {
                    return Ok(node);
                }
            }
            Event::Text(e) => {
                let s = e.xml10_content().map_err(|_| ())?;
                if let Some(parent) = stack.last_mut() {
                    parent.text.push_str(&s)
                } else if !s.trim().is_empty() {
                    return Err(());
                }
            }
            Event::GeneralRef(e) => {
                let s = e.decode().map_err(|_| ())?;
                let value = if let Some(c) = e.resolve_char_ref().map_err(|_| ())? {
                    c.to_string()
                } else {
                    quick_xml::escape::resolve_predefined_entity(&s)
                        .ok_or(())?
                        .into()
                };
                if let Some(p) = stack.last_mut() {
                    p.text.push_str(&value)
                } else {
                    return Err(());
                }
            }
            Event::CData(e) => {
                if let Some(p) = stack.last_mut() {
                    p.text.push_str(&e.xml10_content().map_err(|_| ())?)
                } else {
                    return Err(());
                }
            }
            Event::Eof => return Err(()),
            Event::DocType(_) => {} // Go ignores the declaration, never fetches it.
            _ => {}
        }
    }
}
pub const PROPERTIES: &[&str] = &[
    "resourcetype",
    "displayname",
    "getetag",
    "getcontenttype",
    "getcontentlength",
    "calendar-data",
    "calendar-home-set",
    "calendar-user-address-set",
    "principal-URL",
    "current-user-principal",
    "supported-report-set",
    "supported-calendar-component-set",
    "calendar-timezone",
    "schedule-inbox-URL",
    "schedule-outbox-URL",
];
pub const ALL: &[&str] = &[
    "resourcetype",
    "displayname",
    "getetag",
    "getcontenttype",
    "getcontentlength",
    "supported-calendar-component-set",
];
pub fn is_cal(name: &str) -> bool {
    matches!(
        name,
        "calendar-data"
            | "calendar-home-set"
            | "calendar-user-address-set"
            | "supported-calendar-component-set"
            | "calendar-timezone"
            | "schedule-inbox-URL"
            | "schedule-outbox-URL"
    )
}
pub fn requested(root: Option<&Input>) -> Option<Vec<&'static str>> {
    let props = root?.child("prop")?;
    Some(
        PROPERTIES
            .iter()
            .copied()
            .filter(|name| {
                props
                    .children
                    .iter()
                    .any(|p| p.name == *name && (!is_cal(name) || p.ns == CAL))
            })
            .collect(),
    )
}
pub fn property(name: &str, value: impl Into<String>) -> Element {
    let e = text(name, value);
    if is_cal(name) {
        e.cal()
    } else {
        e
    }
}
pub fn properties(
    href: &str,
    req: Option<&[&str]>,
    lookup: impl Fn(&str) -> Option<Option<Element>>,
) -> Element {
    let mut present = vec![];
    let mut missing = vec![];
    let mut omitted_present = false;
    for &name in req.unwrap_or(ALL) {
        match lookup(name) {
            Some(Some(value)) => present.push(value),
            Some(None) => omitted_present = true,
            None if req.is_some() => missing.push(property(name, "")),
            None => {}
        }
    }
    response(href, present, missing, req.is_none() || omitted_present)
}
pub fn reports() -> Element {
    let names = [
        "calendar-query",
        "calendar-multiget",
        "free-busy-query",
        "sync-collection",
    ];
    node(
        "supported-report-set",
        names
            .iter()
            .map(|name| {
                let inner = if *name == "sync-collection" {
                    "<sync-collection xmlns=\"DAV:\"/>".into()
                } else {
                    format!("<CALENDAR:{name} xmlns=\"{CAL}\"/>")
                };
                let mut report = text("report", "");
                report.raw = Some(inner);
                node("supported-report", vec![report])
            })
            .collect(),
    )
}
