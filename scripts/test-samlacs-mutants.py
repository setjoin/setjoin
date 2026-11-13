#!/usr/bin/env python3
"""Restore each SAML ACS check's absence (#546, owner-approved feature 2026-11-08, #534) in an
explicit test-only build and require the test that pins the check to reject it; then require
the same build without a mutant, and the ordinary build, to pass them.

Mutants live behind the `oracle-mutants` feature and are selected with
SETJOIN_SAMLACS_MUTANT=<id> (read by setjoin_identity::mutants::on). Library mutants run
`setjoin-identity --test saml_acs`; HTTP-level mutants run `setjoin-auth --test saml_acs`
against the assigned disposable database.

Needs REQUIRE_DB=1 and the assigned disposable DSNs (TEST_DB_DSN, DB_DSN, DB_APP_DSN...).
Optional argv: mutant ids to rerun.
"""
import os
from pathlib import Path
import subprocess
import sys

repo = Path(__file__).resolve().parents[1]
root = repo / "server-rust"
if os.environ.get("REQUIRE_DB") != "1":
    sys.exit("REQUIRE_DB=1 and the assigned disposable DSNs are required")

LIB = ("setjoin-identity", "saml_acs")
HTTP = ("setjoin-auth", "saml_acs")
# mutant id -> (package/test target, test name filter)
MUTANTS = {
    # Parsing limits
    "saml-xml-uncapped": (LIB, "xml_over_one_mebibyte_is_refused"),
    "saml-dtd-allowed": (LIB, "a_dtd_or_entity_is_refused"),
    "saml-depth-uncapped": (LIB, "nesting_beyond_the_depth_cap_is_refused"),
    "saml-comment-truncation": (LIB, "comments_and_processing_instructions_are_refused"),
    # Signature scope and wrapping
    "saml-duplicate-ids": (LIB, "duplicate_ids_are_refused"),
    "saml-wrapping": (LIB, "xsw_variants_1_to_8_are_refused"),
    "saml-reference-uri": (LIB, "the_reference_must_name_the_enveloping_element"),
    "saml-unsigned-ok": (LIB, "an_unsigned_message_is_refused"),
    # Pinned key and algorithms
    "saml-keyinfo-trusted": (LIB, "a_signature_by_another_key_is_refused_even_when_keyinfo_carries_that_key"),
    "saml-signature-unchecked": (LIB, "a_garbled_signature_value_is_refused"),
    "saml-digest-unchecked": (LIB, "content_changed_after_signing_fails_the_digest"),
    "saml-sha1": (LIB, "sha1_digest_and_signature_algorithms_are_refused"),
    "saml-weak-rsa": (LIB, "rsa_below_2048_bits_is_never_pinned"),
    # Assertion checks
    "saml-issuer": (LIB, "issuer_must_be_the_registered_idp"),
    "saml-audience": (LIB, "audience_must_be_this_sp"),
    "saml-destination": (LIB, "destination_must_be_this_acs_on_a_signed_response"),
    "saml-recipient": (LIB, "recipient_must_be_this_acs"),
    "saml-bearer": (LIB, "the_confirmation_must_be_bearer"),
    "saml-expiry": (LIB, "an_expired_assertion_is_refused_within_a_bounded_skew"),
    "saml-skew": (LIB, "an_expired_assertion_is_refused_within_a_bounded_skew"),
    "saml-not-before": (LIB, "an_assertion_not_yet_valid_is_refused"),
    "saml-lifetime": (LIB, "an_assertion_valid_for_more_than_a_day_is_refused"),
    "saml-in-response-to": (LIB, "in_response_to_must_match_the_login"),
    "saml-status": (LIB, "a_failure_status_beside_a_signed_assertion_is_refused"),
    "saml-signedinfo-raw": (LIB, "signed_info_must_read_the_same_in_the_signed_bytes"),
    "saml-transient-nameid": (LIB, "a_transient_nameid_is_not_a_stable_subject"),
    # Flow, replay, provisioning (HTTP, database)
    "saml-tracking-unsigned": (HTTP, "a_forged_tracking_cookie_is_not_a_login"),
    "saml-replay-ignored": (HTTP, "replays_of_an_assertion_or_of_its_request_are_refused_and_audited"),
    "saml-idp-initiated-default": (HTTP, "idp_initiated_sso_is_off_by_default"),
    "saml-relay-open": (HTTP, "idp_initiated_sso_works_when_the_registration_enables_it_and_relay_state_is_allow_listed"),
    "saml-link-purpose-mints": (HTTP, "a_link_purpose_acs_without_the_strict_cookies_links_and_never_logs_in"),
    "saml-purpose-unbound": (HTTP, "a_link_purpose_acs_without_the_strict_cookies_links_and_never_logs_in"),
    "saml-jit-collision": (HTTP, "saml_jit_refuses_an_address_another_user_already_holds"),
    "saml-link-by-email": (HTTP, "an_unlinked_nameid_is_never_matched_by_email_and_jit_off_refuses"),
    "saml-jit-always": (HTTP, "an_unlinked_nameid_is_never_matched_by_email_and_jit_off_refuses"),
    # IdP metadata fetch
    "saml-metadata-http": (HTTP, "metadata_is_fetched_over_https_only"),
    "saml-metadata-ssrf": (HTTP, "metadata_fetch_refuses_private_literals_before_any_transport"),
    "saml-metadata-uncapped": (HTTP, "metadata_response_over_one_mebibyte_is_refused"),
}


def cargo(spec, name, env_extra, features):
    package, target = spec
    cmd = ["cargo", "test", "--locked", "-p", package]
    if features:
        cmd += ["--features", "oracle-mutants"]
    cmd += ["--test", target, name, "--", "--test-threads=1"]
    return subprocess.run(
        cmd, cwd=root, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        env={**os.environ, **env_extra},
    )


only = set(sys.argv[1:])
chosen = {m: t for m, t in MUTANTS.items() if not only or m in only}
unknown = only - set(MUTANTS)
if unknown:
    sys.exit(f"unknown mutant ids: {sorted(unknown)}")
for mutant, (spec, name) in chosen.items():
    result = cargo(spec, name, {"SETJOIN_SAMLACS_MUTANT": mutant}, True)
    if result.returncode != 101 or "test result: FAILED." not in result.stdout:
        print(result.stdout[-3000:])
        sys.exit(f"mutant survived (not rejected): {mutant}")
    why = [l for l in result.stdout.splitlines() if "panicked at" in l or l.startswith(("accepted", "refused", "assertion", "mutant"))]
    print(f"MUTANT-REJECTED: {mutant} ({' | '.join(l.strip() for l in why[:2])[:200]})", flush=True)
# The same build without a mutant selected, then the ordinary build, must pass.
for spec, name in sorted(set(chosen.values()), key=lambda x: (x[0][0], x[1])):
    for features in (True, False):
        result = cargo(spec, name, {}, features)
        if result.returncode:
            print(result.stdout[-3000:])
            sys.exit(f"secure test failed without a mutant (features={features}): {spec[1]}::{name}")
print(f"SAMLACS mutants: PASS ({len(chosen)} rejected; ordinary builds green)")
