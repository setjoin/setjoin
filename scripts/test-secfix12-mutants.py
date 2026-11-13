#!/usr/bin/env python3
"""Restore each fixed bug (owner-approved security fixes 2026-11-05, #544: iMIP recipient-bound
attendee, iMIP revocation, S/MIME trailing unsigned parts, anti-phish 550) in an explicit
test-only build and require the secure-behaviour tests to reject it; then require the same
build without a mutant, and the ordinary build, to pass them.

Mutants: feature `oracle-mutants` of setjoin-smtp, selected by SETJOIN_SMTP_MUTANT
(src/mutants.rs); the preamble mutant restores the line-based boundary pick. Needs REQUIRE_DB=1 and the assigned disposable DSNs (TEST_DB_DSN, DB_DSN,
DB_APP_DSN, ...). Optional argv: mutant ids to rerun. The SQL gate itself has no bypass: its
mutant makes Rust name the first body attendee as the envelope recipient.
"""
import os
from pathlib import Path
import subprocess
import sys

root = Path(__file__).resolve().parents[1] / "server-rust"
if os.environ.get("REQUIRE_DB") != "1":
    sys.exit("REQUIRE_DB=1 and the assigned disposable DSNs are required")

SESSION = ["--test", "session"]
LIB = ["--lib"]
# mutant id -> [(cargo target args, test name)]
MUTANTS = {
    "inbound-imip-body-attendee": [(SESSION, "secfix12_imip_request_binds_attendee_to_envelope_recipient")],
    "inbound-imip-ignore-revocation": [(SESSION, "secfix12_imip_stops_for_a_revoked_signer")],
    "smime-trailing-parts-ignored": [
        (LIB, "nothing_unsigned_may_ride_on_a_valid_signature"),
        (SESSION, "secfix12_trailing_unsigned_part_is_not_fully_signed"),
    ],
    "smime-line-boundary": [
        (LIB, "an_unsigned_part_cannot_hide_behind_a_second_content_type_or_the_preamble"),
        (SESSION, "secfix12_preamble_part_cannot_hide_behind_a_signed_message"),
    ],
    "smtp-phish-silent-drop": [(SESSION, "secfix12_anti_phish_rejection_is_refused_not_silently_dropped")],
}


def cargo(target, name, mutant, features):
    cmd = ["cargo", "test", "--locked", "-p", "setjoin-smtp"]
    if features:
        cmd += ["--features", "oracle-mutants"]
    cmd += target + [name, "--", "--test-threads=1"]
    env = {**os.environ}
    env.pop("SETJOIN_SMTP_MUTANT", None)
    if mutant:
        env["SETJOIN_SMTP_MUTANT"] = mutant
    return subprocess.run(cmd, cwd=root, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=env)


only = set(sys.argv[1:])
chosen = {m: t for m, t in MUTANTS.items() if not only or m in only}
for mutant, tests in chosen.items():
    for target, name in tests:
        result = cargo(target, name, mutant, True)
        if result.returncode != 101 or "test result: FAILED." not in result.stdout:
            print(result.stdout[-3000:])
            sys.exit(f"mutant survived (not rejected): {mutant} by {name}")
        why = [l for l in result.stdout.splitlines() if "panicked at" in l or l.startswith(("assertion", "left", "right"))]
        print(f"MUTANT-REJECTED: {mutant} by {name} ({' | '.join(l.strip() for l in why[:2])[:200]})", flush=True)
# The same build without a mutant selected, then the ordinary build, must pass.
seen = sorted({(tuple(target), name) for tests in chosen.values() for target, name in tests})
for target, name in seen:
    for features in (True, False):
        result = cargo(list(target), name, None, features)
        if result.returncode:
            print(result.stdout[-3000:])
            sys.exit(f"secure test failed without a mutant (features={features}): {name}")
print(f"SECFIX12 security-fix mutants: PASS ({len(chosen)} rejected; ordinary builds green)")
