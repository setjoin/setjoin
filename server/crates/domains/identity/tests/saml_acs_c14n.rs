//! Exclusive canonicalization against published vectors (#546). The expected octets
//! are the W3C Exclusive XML Canonicalization 1.0 Recommendation's own examples
//! (section 2.1 and 2.2) and the rendering rules of its section 3 applied to the
//! W3C Canonical XML 1.0 section 3.3 document and to its PrefixList forms.
//! Inputs carry no insignificant whitespace, which the examples wrap only for print.
use setjoin_identity::saml_acs::canonical_element;

fn exc(doc: &str, local: &str, prefixes: &[&str]) -> String {
    let prefixes: Vec<String> = prefixes.iter().map(|s| (*s).to_owned()).collect();
    // Vectors select by local name with the namespace the element is in.
    for ns in [
        "http://example.net",
        "http://b.example",
        "",
        "urn:a",
        "urn:def",
        "urn:p",
        "http://www.ietf.org",
        "http://example.org",
    ] {
        match canonical_element(doc, ns, local, &prefixes) {
            Ok(out) => return out,
            Err(f) if f.detail == "no such element" => {}
            Err(f) => panic!("{local}: {} ({})", f.class, f.detail),
        }
    }
    panic!("no element {local}");
}

const ELEM2: &str = "<n1:elem2 xmlns:n1=\"http://example.net\" xml:lang=\"en\"><n3:stuff xmlns:n3=\"ftp://example.org\"></n3:stuff></n1:elem2>";

#[test]
fn w3c_section_2_2_the_same_octets_in_both_envelopes() {
    let first = "<n0:local xmlns:n0=\"foo:bar\" xmlns:n3=\"ftp://example.org\"><n1:elem2 xmlns:n1=\"http://example.net\" xml:lang=\"en\"><n3:stuff xmlns:n3=\"ftp://example.org\"/></n1:elem2></n0:local>";
    let second = "<n2:pdu xmlns:n1=\"http://example.com\" xmlns:n2=\"http://foo.example\" xml:lang=\"fr\" xml:space=\"retain\"><n1:elem2 xmlns:n1=\"http://example.net\" xml:lang=\"en\"><n3:stuff xmlns:n3=\"ftp://example.org\"/></n1:elem2></n2:pdu>";
    assert_eq!(exc(first, "elem2", &[]), ELEM2);
    assert_eq!(exc(second, "elem2", &[]), ELEM2);
}
#[test]
fn w3c_section_2_1_enveloping_does_not_change_the_apex() {
    let enveloped = "<n0:pdu xmlns:n0=\"http://a.example\"><n1:elem1 xmlns:n1=\"http://b.example\">content</n1:elem1></n0:pdu>";
    assert_eq!(
        exc(enveloped, "elem1", &[]),
        "<n1:elem1 xmlns:n1=\"http://b.example\">content</n1:elem1>"
    );
}
#[test]
fn w3c_c14n_section_3_3_document_under_exclusive_rules() {
    let doc = "<doc><e1   /><e2   ></e2><e3   name = \"elem3\"   id=\"elem3\"   /><e4   name=\"elem4\"   id=\"elem4\"   ></e4><e5 a:attr=\"out\" b:attr=\"sorted\" attr2=\"all\" attr=\"I'm\" xmlns:b=\"http://www.ietf.org\" xmlns:a=\"http://www.w3.org\" xmlns=\"http://example.org\"/><e6 xmlns=\"\" xmlns:a=\"http://www.w3.org\"><e7 xmlns=\"http://www.ietf.org\"><e8 xmlns=\"\" xmlns:a=\"http://www.w3.org\"><e9 xmlns=\"\" xmlns:a=\"http://www.ietf.org\"/></e8></e7></e6></doc>";
    assert_eq!(
        exc(doc, "doc", &[]),
        "<doc><e1></e1><e2></e2><e3 id=\"elem3\" name=\"elem3\"></e3><e4 id=\"elem4\" name=\"elem4\"></e4><e5 xmlns=\"http://example.org\" xmlns:a=\"http://www.w3.org\" xmlns:b=\"http://www.ietf.org\" attr=\"I'm\" attr2=\"all\" b:attr=\"sorted\" a:attr=\"out\"></e5><e6><e7 xmlns=\"http://www.ietf.org\"><e8 xmlns=\"\"><e9></e9></e8></e7></e6></doc>"
    );
}
#[test]
fn w3c_c14n_section_2_3_character_escaping() {
    let doc = "<e a=\"&lt;&amp;&quot;&#9;&#10;&#13;\">&amp;&lt;&gt;&#13;</e>";
    assert_eq!(
        exc(doc, "e", &[]),
        "<e a=\"&lt;&amp;&quot;&#x9;&#xA;&#xD;\">&amp;&lt;&gt;&#xD;</e>"
    );
}
#[test]
fn inclusive_namespace_prefix_list_renders_listed_and_default_namespaces() {
    let doc = "<a:root xmlns:a=\"urn:a\" xmlns:b=\"urn:b\" xmlns:c=\"urn:c\"><a:child xmlns:d=\"urn:d\">t</a:child></a:root>";
    assert_eq!(
        exc(doc, "child", &[]),
        "<a:child xmlns:a=\"urn:a\">t</a:child>"
    );
    assert_eq!(
        exc(doc, "child", &["b", "c"]),
        "<a:child xmlns:a=\"urn:a\" xmlns:b=\"urn:b\" xmlns:c=\"urn:c\">t</a:child>"
    );
    let defaulted = "<root xmlns=\"urn:def\" xmlns:p=\"urn:p\"><p:x/></root>";
    assert_eq!(exc(defaulted, "x", &[]), "<p:x xmlns:p=\"urn:p\"></p:x>");
    assert_eq!(
        exc(defaulted, "x", &["#default"]),
        "<p:x xmlns=\"urn:def\" xmlns:p=\"urn:p\"></p:x>"
    );
}
#[test]
fn comments_are_not_part_of_the_canonical_form_of_a_subtree() {
    // The comment-free forms are what a signature without #WithComments covers.
    let doc = "<n1:elem1 xmlns:n1=\"http://b.example\">con<!-- c -->tent</n1:elem1>";
    // Raw documents with comments are refused upstream; the canonicalizer itself
    // refuses them here because the shared parse gate runs first.
    assert!(canonical_element(doc, "http://b.example", "elem1", &[]).is_ok());
    assert_eq!(
        exc(doc, "elem1", &[]),
        "<n1:elem1 xmlns:n1=\"http://b.example\">content</n1:elem1>"
    );
}
