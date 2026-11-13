//! CardDAV property catalog, sharing Go-compatible XML encoding with CalDAV.
pub(super) use crate::caldav::xml::{node, parse, text, Element, Input};
pub const CARD: &str = "urn:ietf:params:xml:ns:carddav";
const PROPERTIES: &[&str] = &[
    "resourcetype",
    "displayname",
    "getetag",
    "getcontenttype",
    "getcontentlength",
    "address-data",
    "addressbook-home-set",
    "addressbook-description",
    "supported-address-data",
    "principal-URL",
    "current-user-principal",
    "supported-report-set",
];
const ALL: &[&str] = &[
    "resourcetype",
    "displayname",
    "getetag",
    "getcontenttype",
    "getcontentlength",
    "supported-address-data",
];
fn card(name: &str) -> bool {
    matches!(
        name,
        "address-data"
            | "addressbook-home-set"
            | "addressbook-description"
            | "supported-address-data"
    )
}
pub fn property(name: &str, value: impl Into<String>) -> Element {
    let e = text(name, value);
    if card(name) {
        e.attr("xmlns", CARD)
    } else {
        e
    }
}
pub fn requested(root: Option<&Input>) -> Option<Vec<&'static str>> {
    let prop = root?.child("prop")?;
    Some(
        PROPERTIES
            .iter()
            .copied()
            .filter(|name| {
                prop.children
                    .iter()
                    .any(|p| p.name == *name && (!card(name) || p.ns == CARD))
            })
            .collect(),
    )
}
pub fn properties(
    href: &str,
    req: Option<&[&str]>,
    lookup: impl Fn(&str) -> Option<Option<Element>>,
) -> Element {
    let (mut present, mut missing, mut omitted) = (vec![], vec![], false);
    for &name in req.unwrap_or(ALL) {
        match lookup(name) {
            Some(Some(value)) => present.push(value),
            Some(None) => omitted = true,
            None if req.is_some() => missing.push(property(name, "")),
            None => {}
        }
    }
    crate::caldav::xml::response(href, present, missing, req.is_none() || omitted)
}
pub fn multistatus(responses: Vec<Element>, token: Option<&str>) -> String {
    let mut children = responses;
    if let Some(token) = token {
        children.push(text("sync-token", token));
    }
    node("multistatus", children)
        .attr("xmlns", "DAV:")
        .attr("xmlns:C", CARD)
        .document()
}
pub fn supported_data() -> Element {
    node(
        "supported-address-data",
        vec![text("address-data-type", "")
            .attr("xmlns", CARD)
            .attr("content-type", "text/vcard")
            .attr("version", "3.0")],
    )
    .attr("xmlns", CARD)
}
pub fn reports() -> Element {
    node(
        "supported-report-set",
        [
            "addressbook-query",
            "addressbook-multiget",
            "sync-collection",
        ]
        .iter()
        .map(|name| {
            let mut report = text("report", "");
            report.raw = Some(if *name == "sync-collection" {
                "<sync-collection xmlns=\"DAV:\"/>".into()
            } else {
                format!("<ADDRESSBOOK:{name} xmlns=\"{CARD}\"/>")
            });
            node("supported-report", vec![report])
        })
        .collect(),
    )
}
