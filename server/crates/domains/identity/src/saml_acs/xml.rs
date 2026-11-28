//! Inbound SAML XML admission: size, depth and node caps, no DTD and therefore no
//! entities, unique IDs, and an element-for-element cross-check between the two
//! parsers that touch a message (roxmltree for structure, uppsala for C14N).
use super::Fail;
use bergshamra_xml::uppsala;
use roxmltree::{Document, Node, NodeType, ParsingOptions};
use std::collections::HashMap;

/// A SAMLResponse never legitimately approaches this size (#546).
pub const MAX_XML: usize = 1 << 20;
/// Deepest element nesting accepted; a real Response nests under ten.
pub const MAX_DEPTH: usize = 32;
const MAX_NODES: u32 = 20_000;
pub const DS: &str = "http://www.w3.org/2000/09/xmldsig#";
pub const SAMLP: &str = "urn:oasis:names:tc:SAML:2.0:protocol";
pub const SAML: &str = "urn:oasis:names:tc:SAML:2.0:assertion";
pub const EXC: &str = "http://www.w3.org/2001/10/xml-exc-c14n#";

/// Parse with the caps. A DTD is refused by roxmltree (`allow_dtd: false`), so no
/// entity is ever declared or expanded.
pub fn parse(text: &str) -> Result<Document<'_>, Fail> {
    if text.len() > MAX_XML && !crate::mutants::on("saml-xml-uncapped") {
        return Err(Fail::new("oversize", "XML exceeds the size cap"));
    }
    let options = ParsingOptions {
        allow_dtd: crate::mutants::on("saml-dtd-allowed"),
        nodes_limit: MAX_NODES,
        entity_resolver: None,
    };
    let doc = Document::parse_with_options(text, options)
        .map_err(|_| Fail::new("malformed", "XML is not well-formed or declares a DTD"))?;
    if !crate::mutants::on("saml-depth-uncapped") && depth(&doc) > MAX_DEPTH {
        return Err(Fail::new("malformed", "XML nests too deeply"));
    }
    Ok(doc)
}

fn depth(doc: &Document<'_>) -> usize {
    // Element count is capped at MAX_NODES and roxmltree bounds its own nesting,
    // so the ancestor walk is bounded.
    doc.descendants()
        .filter(Node::is_element)
        .map(|n| n.ancestors().filter(Node::is_element).count())
        .max()
        .unwrap_or(0)
}

/// No comment or processing instruction anywhere (CVE-2017-11427 class: a comment
/// splits a text node, so first-text-node readers truncate the NameID). The consumed
/// bytes are canonical and comment-free regardless; this refuses the shape outright.
pub fn refuse_comments(doc: &Document<'_>) -> Result<(), Fail> {
    if crate::mutants::on("saml-comment-truncation") {
        return Ok(());
    }
    if doc
        .descendants()
        .any(|n| matches!(n.node_type(), NodeType::Comment | NodeType::PI))
    {
        return Err(Fail::new(
            "malformed",
            "comments and processing instructions are not accepted",
        ));
    }
    Ok(())
}

const ID_ATTRS: [&str; 3] = ["ID", "Id", "id"];

/// Every ID-typed attribute value, refusing any duplicate across the whole message.
pub fn ids<'a, 'i>(doc: &'a Document<'i>) -> Result<HashMap<&'a str, Node<'a, 'i>>, Fail> {
    let mut map: HashMap<&str, Node> = HashMap::new();
    for node in doc.descendants().filter(Node::is_element) {
        for attribute in node.attributes() {
            if attribute.namespace().is_none() && ID_ATTRS.contains(&attribute.name()) {
                let previous = map.insert(attribute.value(), node);
                if previous.is_some() && !crate::mutants::on("saml-duplicate-ids") {
                    return Err(Fail::new("structure", "duplicate ID"));
                }
            }
        }
    }
    Ok(map)
}

pub fn is_el(node: Node<'_, '_>, ns: &str, local: &str) -> bool {
    node.is_element() && node.tag_name().namespace() == Some(ns) && node.tag_name().name() == local
}

pub fn child_els<'a, 'i>(
    node: Node<'a, 'i>,
    ns: &'a str,
    local: &'a str,
) -> impl Iterator<Item = Node<'a, 'i>> {
    node.children().filter(move |c| is_el(*c, ns, local))
}

/// All element text, concatenated: never the first text node alone.
pub fn text_of(node: Node<'_, '_>) -> String {
    if crate::mutants::on("saml-comment-truncation") {
        return node.text().unwrap_or("").to_owned();
    }
    node.children()
        .filter(|c| c.is_text())
        .filter_map(|c| c.text())
        .collect()
}

/// Same element sequence (name, namespace, attributes) in both parsers, or the
/// document is refused: element ordinals then address the same node in either.
pub struct Twin<'a> {
    pub udoc: uppsala::Document<'a>,
    elements: Vec<uppsala::NodeId>,
}
impl<'a> Twin<'a> {
    pub fn new(text: &'a str, r: &Document<'_>) -> Result<Self, Fail> {
        let mismatch = || Fail::new("structure", "parsers disagree about the document");
        let udoc = uppsala::Parser::new()
            .with_max_depth(MAX_DEPTH as u32 + 2)
            .with_forbid_dtd(true)
            .parse(text)
            .map_err(|_| mismatch())?;
        let elements: Vec<_> = udoc
            .descendants(udoc.root())
            .into_iter()
            .filter(|id| udoc.element(*id).is_some())
            .collect();
        let relements: Vec<_> = r.descendants().filter(Node::is_element).collect();
        if elements.len() != relements.len() {
            return Err(mismatch());
        }
        for (id, rn) in elements.iter().zip(&relements) {
            let u = udoc.element(*id).ok_or_else(mismatch)?;
            if &*u.name.local_name != rn.tag_name().name()
                || u.name.namespace_uri.as_deref().filter(|s| !s.is_empty())
                    != rn.tag_name().namespace().filter(|s| !s.is_empty())
            {
                return Err(mismatch());
            }
            let mut ua: Vec<(Option<&str>, &str, &str)> = u
                .attributes
                .iter()
                .filter(|a| {
                    a.name.prefix.as_deref() != Some("xmlns") && &*a.name.local_name != "xmlns"
                })
                .map(|a| {
                    (
                        a.name.namespace_uri.as_deref(),
                        &*a.name.local_name,
                        &*a.value,
                    )
                })
                .collect();
            let mut ra: Vec<(Option<&str>, &str, &str)> = rn
                .attributes()
                .map(|a| (a.namespace(), a.name(), a.value()))
                .collect();
            ua.sort();
            ra.sort();
            if ua != ra {
                return Err(mismatch());
            }
        }
        Ok(Self { udoc, elements })
    }
    /// The uppsala node at the same document-order element position.
    pub fn node(&self, r: &Document<'_>, rn: Node<'_, '_>) -> Option<uppsala::NodeId> {
        let ordinal = r
            .descendants()
            .filter(Node::is_element)
            .position(|n| n == rn)?;
        self.elements.get(ordinal).copied()
    }
}
