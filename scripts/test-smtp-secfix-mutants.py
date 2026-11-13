#!/usr/bin/env python3
"""Restore each fixed SMTP/mail-security bug (owner-approved security fixes 2026-11-05,
#492 #493 #500 #488 #465) in an explicit test-only build and require the
secure-behaviour test to reject it; then require the ordinary build to pass them.

Needs REQUIRE_DB=1 and the assigned disposable DSNs (TEST_DB_DSN, DB_DSN, ...).
"""
import os
from pathlib import Path
import subprocess
import sys

root = Path(__file__).resolve().parents[1] / "server-rust"
if os.environ.get("REQUIRE_DB") != "1":
    sys.exit("REQUIRE_DB=1 and the assigned disposable DSNs are required")

SMTP = ("setjoin-smtp", "SETJOIN_SMTP_MUTANT")
MAILSEC = ("setjoin-gateway", "SETJOIN_MAILSEC_MUTANT")
# (crate, env var, mutant id, test target, test name)
MUTANTS = [
    (*SMTP, "dkim-ignore-expiry", "secfix_inbound", "dkim_honours_signature_expiry"),
    (*SMTP, "dkim-sign-legacy-columns", "secfix_inbound", "outbound_signing_emits_a_complete_verifiable_dkim_signature"),
    (*SMTP, "dkim-sign-bare-header", "secfix_inbound", "outbound_signing_emits_a_complete_verifiable_dkim_signature"),
    (*SMTP, "dkim-sign-forwards", "secfix_inbound", "outbound_signing_emits_a_complete_verifiable_dkim_signature"),
    (*SMTP, "dkim-sign-foreign-from", "secfix_inbound", "outbound_signing_emits_a_complete_verifiable_dkim_signature"),
    (*SMTP, "arc-seal-with-from-domain", "secfix_inbound", "arc_seal_authenticates_the_incoming_chain"),
    (*SMTP, "arc-trust-presence", "secfix_inbound", "arc_seal_authenticates_the_incoming_chain"),
    (*SMTP, "dmarc-org-last-two-labels", "secfix_inbound", "dmarc_uses_the_public_suffix_list"),
    (*SMTP, "dmarc-default-strict", "secfix_inbound", "dmarc_uses_the_public_suffix_list"),
    (*SMTP, "dmarc-concatenate-records", "secfix_inbound", "dmarc_uses_the_public_suffix_list"),
    (*SMTP, "dmarc-ignore-subdomain-policy", "secfix_inbound", "dmarc_uses_the_public_suffix_list"),
    (*SMTP, "spf-errors-are-non-matches", "secfix_inbound", "spf_errors_and_syntax"),
    (*SMTP, "spf-unknown-mechanism-ignored", "secfix_inbound", "spf_errors_and_syntax"),
    (*SMTP, "spf-ip4-accepts-ipv6", "secfix_inbound", "spf_errors_and_syntax"),
    (*SMTP, "smtp-inline-refusal", "secfix_inbound", "a_stalled_implicit_tls_refusal"),
    (*SMTP, "smtp-data-without-recipients", "secfix_inbound", "mail_is_never_acknowledged"),
    (*SMTP, "smtp-accept-short-eof", "secfix_inbound", "mail_is_never_acknowledged"),
    (*SMTP, "smtp-lookup-failure-permanent", "secfix_inbound", "a_recipient_lookup_outage"),
    (*SMTP, "dane-ee-requires-pkix", "transport", "dane_certificate_decisions_require_chain_linkage"),
    (*SMTP, "dane-ca-without-linkage", "transport", "dane_certificate_decisions_require_chain_linkage"),
    (*SMTP, "dane-pool-trusts-label", "transport", "dane_certificate_decisions_require_chain_linkage"),
    (*MAILSEC, "smime-no-reconnect-reload", "smime_trust_reconnect", "removed_anchor_stops_being_trusted"),
    (*MAILSEC, "smime-cache-while-deaf", "smime_trust_reconnect", "removed_anchor_stops_being_trusted"),
]


def cargo(crate, target, name, env_extra, features):
    cmd = ["cargo", "test", "-p", crate]
    if features:
        cmd += ["--features", "oracle-mutants"]
    cmd += ["--test", target, name, "--", "--test-threads=1"]
    return subprocess.run(
        cmd, cwd=root, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        env={**os.environ, **env_extra},
    )


only = set(sys.argv[1:])  # optional: rerun just these mutant ids
for crate, var, mutant, target, name in MUTANTS:
    if only and mutant not in only:
        continue
    result = cargo(crate, target, name, {var: mutant}, True)
    if result.returncode != 101 or "test result: FAILED." not in result.stdout:
        print(result.stdout[-3000:])
        sys.exit(f"mutant survived (not rejected): {mutant}")
    print(f"MUTANT-REJECTED: {mutant}")
# The same build without a mutant selected, then the ordinary build, must pass.
tests = sorted({(crate, target, name) for crate, _, m, target, name in MUTANTS if not only or m in only})
for crate, target, name in tests:
    for features in (True, False):
        result = cargo(crate, target, name, {}, features)
        if result.returncode:
            print(result.stdout[-3000:])
            sys.exit(f"secure test failed without a mutant (features={features}): {target}::{name}")
print(f"SMTP/mail-security security-fix mutants: PASS ({len(only) or len(MUTANTS)} rejected; ordinary builds green)")
