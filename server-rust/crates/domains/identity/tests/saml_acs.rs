//! Verified SAML ACS (#546): signature, wrapping, canonicalization and assertion
//! checks, one red-green slice per check. Mutant ids (`SETJOIN_SAMLACS_MUTANT`, with
//! the `oracle-mutants` feature) restore each check's absence; see
//! `scripts/test-samlacs-mutants.py`.
#[path = "saml_acs/support.rs"]
mod support;
use setjoin_identity::saml_acs::{process, Claims, Fail};
use support::*;

fn auds() -> Vec<String> {
    vec![AUD.to_owned(), "https://sp.example.test".to_owned()]
}
fn run(xml: &str, idp: &Idp) -> Result<Claims, Fail> {
    let auds = auds();
    process(xml.as_bytes(), &pins(idp), &expect(&auds))
}
fn run_with(
    xml: &str,
    idp: &Idp,
    mutate: impl FnOnce(&mut setjoin_identity::saml_acs::Expect<'_>),
) -> Result<Claims, Fail> {
    let auds = auds();
    let mut e = expect(&auds);
    mutate(&mut e);
    process(xml.as_bytes(), &pins(idp), &e)
}
fn class(r: Result<Claims, Fail>) -> &'static str {
    match r {
        Ok(c) => panic!(
            "accepted a message that must be refused (NameID {})",
            c.name_id
        ),
        Err(f) => f.class,
    }
}
fn ok(r: Result<Claims, Fail>) -> Claims {
    r.unwrap_or_else(|f| panic!("refused a valid message: {} ({})", f.class, f.detail))
}

// ---- accepted shapes ----------------------------------------------------------

#[test]
fn signed_assertion_is_accepted() {
    let idp = rsa_idp();
    let c = ok(run(
        &signed_assertion(&Opts::default(), &SigSpec::new(idp)),
        idp,
    ));
    assert_eq!(c.name_id, "alice-subject-1");
    assert_eq!(c.assertion_id, "_assertion1");
    assert_eq!(c.in_response_to.as_deref(), Some(REQUEST));
    assert_eq!(c.attributes["email"], ["alice@example.test"]);
    assert_eq!(c.attributes["memberOf"], ["staff", "admins"]);
}
#[test]
fn signed_response_with_unsigned_assertion_is_accepted() {
    let idp = rsa_idp();
    let c = ok(run(
        &signed_response(&Opts::default(), &SigSpec::new(idp)),
        idp,
    ));
    assert_eq!(c.name_id, "alice-subject-1");
}
#[test]
fn both_signed_is_accepted() {
    let idp = rsa_idp();
    ok(run(&both_signed(&Opts::default(), &SigSpec::new(idp)), idp));
}
#[test]
fn ecdsa_and_other_sha2_profiles_are_accepted() {
    for idp in [ec256(), ec384()] {
        ok(run(
            &signed_assertion(&Opts::default(), &SigSpec::new(idp)),
            idp,
        ));
    }
    for (sig, dig) in [(Sig::Rsa384, Dig::S384), (Sig::Rsa512, Dig::S512)] {
        let idp = rsa_idp();
        let mut spec = SigSpec::new(idp);
        spec.sig = sig;
        spec.dig = dig;
        ok(run(&signed_response(&Opts::default(), &spec), idp));
    }
}
#[test]
fn inclusive_namespace_prefix_lists_are_honoured() {
    let idp = rsa_idp();
    let mut spec = SigSpec::new(idp);
    spec.c14n_prefixes = "saml";
    ok(run(&signed_assertion(&Opts::default(), &spec), idp));
}
#[test]
fn certificate_bundle_with_a_rotated_key_verifies_either() {
    let idp = rsa_idp();
    let bundle = format!("{}{}", rsa_attacker().cert_pem, idp.cert_pem);
    let pins = setjoin_identity::saml_acs::parse_pins(&bundle);
    assert_eq!(pins.len(), 2);
    let auds = auds();
    process(
        signed_assertion(&Opts::default(), &SigSpec::new(idp)).as_bytes(),
        &pins,
        &expect(&auds),
    )
    .unwrap();
}

// ---- signature: pinned key, algorithms ----------------------------------------

#[test]
fn an_unsigned_message_is_refused() {
    assert_eq!(
        class(run(&unsigned(&Opts::default()), rsa_idp())),
        "unsigned"
    );
}
#[test]
fn a_signature_by_another_key_is_refused_even_when_keyinfo_carries_that_key() {
    let attacker = rsa_attacker();
    // The attacker signs and embeds their own certificate in KeyInfo.
    let xml = signed_assertion(&Opts::default(), &SigSpec::new(attacker));
    assert_eq!(class(run(&xml, rsa_idp())), "signature");
}
#[test]
fn a_garbled_signature_value_is_refused() {
    let idp = rsa_idp();
    let xml = signed_assertion(&Opts::default(), &SigSpec::new(idp));
    let start = xml.find("<ds:SignatureValue>").unwrap() + "<ds:SignatureValue>".len();
    let mut bytes = xml.into_bytes();
    bytes[start + 10] = if bytes[start + 10] == b'A' {
        b'B'
    } else {
        b'A'
    };
    assert_eq!(
        class(run(&String::from_utf8(bytes).unwrap(), idp)),
        "signature"
    );
}
#[test]
fn content_changed_after_signing_fails_the_digest() {
    let idp = rsa_idp();
    let xml = signed_assertion(&Opts::default(), &SigSpec::new(idp))
        .replace("alice-subject-1", "mallory-subject");
    assert_eq!(class(run(&xml, idp)), "signature");
}
#[test]
fn sha1_digest_and_signature_algorithms_are_refused() {
    let idp = rsa_idp();
    let mut spec = SigSpec::new(idp);
    spec.dig = Dig::S1;
    assert_eq!(
        class(run(&signed_assertion(&Opts::default(), &spec), idp)),
        "algorithm"
    );
    let mut spec = SigSpec::new(idp);
    spec.sig = Sig::RsaSha1;
    assert_eq!(
        class(run(&signed_assertion(&Opts::default(), &spec), idp)),
        "algorithm"
    );
}
#[test]
fn rsa_below_2048_bits_is_never_pinned() {
    let weak = rsa1024();
    assert!(pins(weak).is_empty());
    let xml = signed_assertion(&Opts::default(), &SigSpec::new(weak));
    assert_eq!(class(run(&xml, weak)), "no_pinned_key");
}
#[test]
fn a_registration_without_a_usable_pin_refuses_everything() {
    let idp = rsa_idp();
    let auds = auds();
    let xml = signed_assertion(&Opts::default(), &SigSpec::new(idp));
    let r = process(
        xml.as_bytes(),
        &setjoin_identity::saml_acs::parse_pins("unused-cert"),
        &expect(&auds),
    );
    assert_eq!(class(r), "no_pinned_key");
}
#[test]
fn a_key_of_the_wrong_type_does_not_verify() {
    // ECDSA-signed message against a pinned RSA key (and the reverse).
    let xml = signed_assertion(&Opts::default(), &SigSpec::new(ec256()));
    assert_eq!(class(run(&xml, rsa_idp())), "signature");
    let xml = signed_assertion(&Opts::default(), &SigSpec::new(rsa_idp()));
    assert_eq!(class(run(&xml, ec256())), "signature");
}

// ---- wrapping (XSW1-8), reference and ID discipline ----------------------------

fn evil() -> Opts {
    Opts {
        name_id: "victim-subject".into(),
        assertion_id: "_evil".into(),
        ..Opts::default()
    }
}
#[test]
fn xsw_variants_1_to_8_are_refused() {
    let idp = rsa_idp();
    let spec = SigSpec::new(idp);
    let o = Opts::default();
    let legit_assertion_signed = {
        let a = assertion(&o, &template(1, &o.assertion_id, &spec));
        sign(&a_in_response(&o, &a), 1, &spec)
    };
    // The legit signed Assertion and Response, as strings to rearrange.
    let signed_a = extract(
        &legit_assertion_signed,
        "<saml:Assertion",
        "</saml:Assertion>",
    );
    let legit_response_signed = signed_response(&o, &spec);
    let signed_r = legit_response_signed.clone();
    let evil_a = assertion(&evil(), "");
    let evil_sig_a = {
        // Evil assertion that carries the legit Signature element verbatim.
        let sig = extract(&signed_a, "<ds:Signature", "</ds:Signature>");
        assertion(&evil(), &sig)
    };
    let shell = |inner: &str| response(&o, "", inner);
    let cases: Vec<(&str, String)> = vec![
        // XSW1: signed Response cloned into an evil Response (as Extensions content).
        ("xsw1", response(&evil(), "", &format!("<samlp:Extensions>{signed_r}</samlp:Extensions>{evil_a}"))),
        // XSW2: legit signed Response placed before the evil assertion, inside the evil Response.
        ("xsw2", format!("{}", response(&evil(), "", &format!("{evil_a}<samlp:Extensions>{signed_r}</samlp:Extensions>")))),
        // XSW3: evil assertion first, legit signed assertion kept after it.
        ("xsw3", shell(&format!("{evil_a}{signed_a}"))),
        // XSW4: legit signed assertion nested inside the evil assertion.
        ("xsw4", shell(&assertion_with_child(&evil(), &signed_a))),
        // XSW5: evil assertion carrying the legit signature, legit (unsigned copy) alongside.
        ("xsw5", shell(&format!("{evil_sig_a}{}", assertion(&o, "")))),
        // XSW6: evil assertion carrying the legit signature, wrapping the legit signed one.
        ("xsw6", shell(&assertion_with_child(&evil(), &format!("{signed_a}")).replace("<saml:Subject>", &format!("{}<saml:Subject>", extract(&signed_a, "<ds:Signature", "</ds:Signature>"))))),
        // XSW7: legit signed assertion in Extensions, evil assertion at the real position.
        ("xsw7", shell(&format!("<samlp:Extensions>{signed_a}</samlp:Extensions>{evil_a}"))),
        // XSW8: legit signed assertion inside the Signature's Object, evil at the real position.
        ("xsw8", shell(&evil_a.replacen("</saml:Issuer>", &format!("</saml:Issuer><ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><ds:Object>{signed_a}</ds:Object></ds:Signature>"), 1))),
        // Appended: legit signed assertion first, evil unsigned assertion after it.
        ("append", shell(&format!("{signed_a}{evil_a}"))),
    ];
    for (name, xml) in cases {
        let r = run(&xml, idp);
        assert!(
            r.is_err(),
            "{name} was accepted: NameID {:?}",
            r.as_ref().ok().map(|c| c.name_id.clone())
        );
        let fail = r.err().unwrap();
        println!("{name}: {} ({})", fail.class, fail.detail);
        // A fixture that is merely malformed would prove nothing.
        assert!(
            matches!(fail.class, "structure" | "signature" | "unsigned"),
            "{name}: {} ({})",
            fail.class,
            fail.detail
        );
    }
    let _ = legit_assertion_signed;
}
fn a_in_response(o: &Opts, a: &str) -> String {
    response(o, "", a)
}
fn assertion_with_child(o: &Opts, child: &str) -> String {
    assertion(o, "").replace("<saml:Subject>", &format!("{child}<saml:Subject>"))
}
fn extract(s: &str, start: &str, end: &str) -> String {
    let a = s.find(start).unwrap();
    let b = s[a..].find(end).unwrap() + a + end.len();
    s[a..b].to_owned()
}
#[test]
fn the_reference_must_name_the_enveloping_element() {
    // The Signature sits in the Response but is a correct signature over the Assertion.
    let idp = rsa_idp();
    let spec = SigSpec::new(idp);
    let o = Opts::default();
    let xml = sign(
        &response(&o, &template(1, &o.assertion_id, &spec), &assertion(&o, "")),
        1,
        &spec,
    );
    assert_eq!(class(run(&xml, idp)), "structure");
}
#[test]
fn duplicate_ids_are_refused() {
    let idp = rsa_idp();
    let spec = SigSpec::new(idp);
    let o = Opts {
        response_id: "_assertion1".into(),
        ..Opts::default()
    };
    let xml = signed_assertion(&o, &spec);
    assert_eq!(class(run(&xml, idp)), "structure");
}
#[test]
fn a_second_assertion_beside_the_signed_one_is_refused() {
    let idp = rsa_idp();
    let spec = SigSpec::new(idp);
    let o = Opts::default();
    let a = assertion(&o, &template(1, &o.assertion_id, &spec));
    let xml = sign(
        &response(&o, "", &format!("{a}{}", assertion(&evil(), ""))),
        1,
        &spec,
    );
    assert_eq!(class(run(&xml, idp)), "structure");
}
#[test]
fn a_signature_that_does_not_verify_fails_closed_even_beside_a_valid_one() {
    // Response signature valid; the Assertion's own signature is broken: refuse.
    let idp = rsa_idp();
    let spec = SigSpec::new(idp);
    let xml = both_signed(&Opts::default(), &spec);
    let first = xml.find("<ds:SignatureValue>").unwrap();
    let second = xml[first + 10..].find("<ds:SignatureValue>").unwrap()
        + first
        + 10
        + "<ds:SignatureValue>".len();
    let mut bytes = xml.into_bytes();
    bytes[second + 12] = if bytes[second + 12] == b'A' {
        b'B'
    } else {
        b'A'
    };
    let r = run(&String::from_utf8(bytes).unwrap(), idp);
    assert!(matches!(class(r), "signature"));
}
#[test]
fn a_signed_assertion_under_an_unsigned_response_that_contradicts_it_is_refused() {
    let idp = rsa_idp();
    let o = Opts {
        destination: "https://evil.example/acs".into(),
        ..Opts::default()
    };
    let o2 = Opts::default();
    // Assertion is correct for this ACS; the unsigned wrapper names another destination.
    let a = assertion(&o2, &template(1, &o2.assertion_id, &SigSpec::new(idp)));
    let xml = sign(&response(&o, "", &a), 1, &SigSpec::new(idp));
    assert_eq!(class(run(&xml, idp)), "destination");
}

// ---- comments (CVE-2017-11427 class) -------------------------------------------

#[test]
fn a_comment_inside_the_nameid_cannot_truncate_the_subject() {
    let idp = rsa_idp();
    let spec = SigSpec::new(idp);
    // The IdP signs a NameID that its user chose: victim@example.test<!---->.evil.test
    let o = Opts {
        name_id: "victim@example.test".into(),
        ..Opts::default()
    };
    let a = assertion(&o, &template(1, &o.assertion_id, &spec)).replace(
        "victim@example.test",
        "victim@example.test<!---->.evil.test",
    );
    let xml = sign(&response(&o, "", &a), 1, &spec);
    match run(&xml, idp) {
        Ok(c) => assert_ne!(
            c.name_id, "victim@example.test",
            "NameID truncated at the comment"
        ),
        Err(f) => assert_eq!(f.class, "malformed"),
    }
}
#[test]
fn comments_and_processing_instructions_are_refused() {
    let idp = rsa_idp();
    let xml = signed_assertion(&Opts::default(), &SigSpec::new(idp));
    for inject in ["<!-- x -->", "<?pi data?>"] {
        let with = xml.replacen("<saml:Subject>", &format!("<saml:Subject>{inject}"), 1);
        assert_eq!(class(run(&with, idp)), "malformed", "{inject}");
    }
}

// ---- parser limits ---------------------------------------------------------------

#[test]
fn a_dtd_or_entity_is_refused() {
    let idp = rsa_idp();
    let xml = signed_assertion(&Opts::default(), &SigSpec::new(idp));
    let with =
        format!("<!DOCTYPE r [<!ENTITY x \"boom\">]>{xml}").replace("alice@example.test", "&x;");
    assert_eq!(class(run(&with, idp)), "malformed");
    let bare = format!("<!DOCTYPE samlp:Response SYSTEM \"http://127.0.0.1/x.dtd\">{xml}");
    assert_eq!(class(run(&bare, idp)), "malformed");
}
#[test]
fn xml_over_one_mebibyte_is_refused() {
    let idp = rsa_idp();
    let o = Opts {
        attrs: vec![("pad".into(), vec!["x".repeat(4000); 300])],
        ..Opts::default()
    };
    let xml = signed_assertion(&o, &SigSpec::new(idp));
    assert!(
        xml.len() > 1 << 20,
        "fixture must exceed the cap, got {}",
        xml.len()
    );
    assert_eq!(class(run(&xml, idp)), "oversize");
}
#[test]
fn nesting_beyond_the_depth_cap_is_refused() {
    let idp = rsa_idp();
    let xml = signed_assertion(&Opts::default(), &SigSpec::new(idp));
    let deep = format!("{}{}", "<a>".repeat(40), "</a>".repeat(40));
    let with = xml.replacen("<saml:Subject>", &format!("<saml:Subject>{deep}"), 1);
    assert_eq!(class(run(&with, idp)), "malformed");
}
#[test]
fn malformed_xml_and_encodings_are_refused() {
    let auds = auds();
    let pins = pins(rsa_idp());
    for bad in [&b"<a><b></a>"[..], b"", b"\xff\xfe\x00<", b"not xml"] {
        let r = process(bad, &pins, &expect(&auds));
        assert!(matches!(class(r), "malformed"));
    }
}

// ---- assertion checks --------------------------------------------------------------

fn signed(o: &Opts) -> String {
    signed_assertion(o, &SigSpec::new(rsa_idp()))
}
#[test]
fn issuer_must_be_the_registered_idp() {
    let o = Opts {
        issuer: "https://other.example/idp".into(),
        ..Opts::default()
    };
    assert_eq!(class(run(&signed(&o), rsa_idp())), "issuer");
    // A signed Response's Issuer is checked too.
    let spec = SigSpec::new(rsa_idp());
    let x = sign(
        &response(
            &o,
            &template(1, "_response1", &spec),
            &assertion(&Opts::default(), ""),
        ),
        1,
        &spec,
    );
    assert_eq!(class(run(&x, rsa_idp())), "issuer");
}
#[test]
fn audience_must_be_this_sp() {
    let o = Opts {
        audience: "https://another-sp.example/metadata".into(),
        ..Opts::default()
    };
    assert_eq!(class(run(&signed(&o), rsa_idp())), "audience");
    // The SP's entity ID is accepted too.
    ok(run(
        &signed(&Opts {
            audience: "https://sp.example.test".into(),
            ..Opts::default()
        }),
        rsa_idp(),
    ));
}
#[test]
fn a_missing_audience_restriction_is_refused() {
    let idp = rsa_idp();
    let spec = SigSpec::new(idp);
    let o = Opts::default();
    let a = assertion(&o, &template(1, &o.assertion_id, &spec));
    let a = extract(&a, "<saml:Assertion", "</saml:Assertion>");
    let stripped = a.replace(&format!("<saml:AudienceRestriction><saml:Audience>{AUD}</saml:Audience></saml:AudienceRestriction>"), "");
    let xml = sign(&response(&o, "", &stripped), 1, &spec);
    assert_eq!(class(run(&xml, idp)), "audience");
}
#[test]
fn destination_must_be_this_acs_on_a_signed_response() {
    let idp = rsa_idp();
    let spec = SigSpec::new(idp);
    let o = Opts {
        destination: "https://sp.example.test/auth/saml/other/acs".into(),
        ..Opts::default()
    };
    let xml = sign(
        &response(&o, &template(1, &o.response_id, &spec), &assertion(&o, "")),
        1,
        &spec,
    );
    assert_eq!(class(run(&xml, idp)), "destination");
}
#[test]
fn recipient_must_be_this_acs() {
    let o = Opts {
        recipient: "https://sp.example.test/auth/saml/other/acs".into(),
        ..Opts::default()
    };
    assert_eq!(class(run(&signed(&o), rsa_idp())), "recipient");
}
#[test]
fn the_confirmation_must_be_bearer() {
    let o = Opts {
        bearer: false,
        ..Opts::default()
    };
    assert_eq!(class(run(&signed(&o), rsa_idp())), "subject");
}
#[test]
fn an_expired_assertion_is_refused_within_a_bounded_skew() {
    let idp = rsa_idp();
    let end = NOW - 10 * 60;
    let o = Opts {
        not_on_or_after: end,
        scd_not_on_or_after: end,
        not_before: end - 600,
        ..Opts::default()
    };
    assert_eq!(class(run(&signed(&o), idp)), "conditions");
    // Inside the 120 s skew it still verifies; just past it, it does not.
    let inside = Opts {
        not_on_or_after: NOW - 100,
        scd_not_on_or_after: NOW - 100,
        ..Opts::default()
    };
    ok(run(&signed(&inside), idp));
    let past = Opts {
        not_on_or_after: NOW - 130,
        scd_not_on_or_after: NOW - 130,
        ..Opts::default()
    };
    assert_eq!(class(run(&signed(&past), idp)), "conditions");
    assert!(setjoin_identity::saml_acs::SKEW <= 180);
}
#[test]
fn a_confirmation_that_outlives_its_window_is_refused_on_its_own() {
    // Conditions still valid, SubjectConfirmationData expired.
    let o = Opts {
        scd_not_on_or_after: NOW - 600,
        ..Opts::default()
    };
    assert_eq!(class(run(&signed(&o), rsa_idp())), "conditions");
}
#[test]
fn an_assertion_valid_for_more_than_a_day_is_refused() {
    let far = NOW + 48 * 3600;
    let o = Opts {
        not_on_or_after: far,
        scd_not_on_or_after: far,
        ..Opts::default()
    };
    assert_eq!(class(run(&signed(&o), rsa_idp())), "conditions");
    let day = NOW + 23 * 3600;
    ok(run(
        &signed(&Opts {
            not_on_or_after: day,
            scd_not_on_or_after: day,
            ..Opts::default()
        }),
        rsa_idp(),
    ));
}
#[test]
fn an_assertion_not_yet_valid_is_refused() {
    let o = Opts {
        not_before: NOW + 600,
        ..Opts::default()
    };
    assert_eq!(class(run(&signed(&o), rsa_idp())), "conditions");
}
#[test]
fn in_response_to_must_match_the_login() {
    let o = Opts {
        irt: Some("id-someone-elses".into()),
        ..Opts::default()
    };
    assert_eq!(class(run(&signed(&o), rsa_idp())), "inresponseto");
    // Unsolicited (no InResponseTo) while a request was expected.
    let o = Opts {
        irt: None,
        ..Opts::default()
    };
    assert_eq!(class(run(&signed(&o), rsa_idp())), "inresponseto");
    // An answer while none was expected (IdP-initiated slot).
    let r = run_with(&signed(&Opts::default()), rsa_idp(), |e| {
        e.in_response_to = None
    });
    assert_eq!(class(r), "inresponseto");
    // IdP-initiated: no InResponseTo and none expected.
    let o = Opts {
        irt: None,
        ..Opts::default()
    };
    ok(run_with(&signed(&o), rsa_idp(), |e| {
        e.in_response_to = None
    }));
}
#[test]
fn a_transient_nameid_is_not_a_stable_subject() {
    let o = Opts {
        name_id_format: Some("urn:oasis:names:tc:SAML:2.0:nameid-format:transient".into()),
        ..Opts::default()
    };
    assert_eq!(class(run(&signed(&o), rsa_idp())), "nameid");
}
#[test]
fn nameid_must_be_present_bounded_and_clean() {
    for bad in ["".to_owned(), "x".repeat(1025), "a\tb".to_owned()] {
        let o = Opts {
            name_id: bad,
            ..Opts::default()
        };
        assert_eq!(class(run(&signed(&o), rsa_idp())), "nameid");
    }
}

#[test]
fn a_failure_status_beside_a_signed_assertion_is_refused() {
    let idp = rsa_idp();
    let xml = signed_assertion(&Opts::default(), &SigSpec::new(idp))
        .replace("status:Success", "status:Responder");
    assert_eq!(class(run(&xml, idp)), "status");
}
#[test]
fn signed_info_must_read_the_same_in_the_signed_bytes() {
    use setjoin_identity::saml_acs::{canonical_element, signed_info_agreement};
    let idp = rsa_idp();
    let xml = signed_assertion(&Opts::default(), &SigSpec::new(idp));
    let canonical = canonical_element(&xml, "http://www.w3.org/2000/09/xmldsig#", "SignedInfo", &[]).unwrap();
    signed_info_agreement(&xml, &canonical).expect("the genuine pair agrees");
    // A digest value, an algorithm or a Reference that differs in the covered bytes.
    let start = canonical.find("<ds:DigestValue>").unwrap() + "<ds:DigestValue>".len();
    let mut digest = canonical.clone().into_bytes();
    digest[start] = if digest[start] == b'A' { b'B' } else { b'A' };
    for changed in [
        String::from_utf8(digest).unwrap(),
        canonical.replace("rsa-sha256", "rsa-sha512"),
        canonical.replace("URI=\"#_assertion1\"", "URI=\"#_response1\""),
    ] {
        assert_eq!(signed_info_agreement(&xml, &changed).unwrap_err().class, "structure");
    }
}
