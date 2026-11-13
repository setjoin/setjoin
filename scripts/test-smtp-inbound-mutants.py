#!/usr/bin/env python3
"""Prove the toggle-ON inbound socket oracle rejects missing security stages (#526)."""
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1] / 'server-rust'
MUTANTS = [
    ('inbound-imip-lossy-signed-content', 'enabled_imip_signed_bytes_match_frozen_go'),
    ('inbound-no-imip', 'enabled_imip_requests_match_frozen_go'),
    ('inbound-imip-ignore-role', 'enabled_imip_roles_match_frozen_go'),
    ('inbound-imip-ignore-scope', 'enabled_imip_smime_matches_frozen_go'),
    ('inbound-imip-ignore-signed-scope', 'enabled_imip_smime_matches_frozen_go'),
    ('inbound-no-link-qp-admission', 'enabled_link_encoding_edges_match_frozen_go'),
    ('inbound-link-ignore-signature', 'enabled_link_pipeline_composition_matches_frozen_go'),
    ('inbound-no-link', 'enabled_link_protection_matches_frozen_go'),
    ('inbound-no-link-html', 'enabled_link_protection_matches_frozen_go'),
    ('inbound-no-link-cte', 'enabled_link_protection_matches_frozen_go'),
    ('inbound-link-wrong-mailbox', 'enabled_link_protection_matches_frozen_go'),
    ('inbound-link-wrong-version', 'enabled_link_protection_matches_frozen_go'),
    ('inbound-no-mime-condemnation', 'enabled_link_protection_matches_frozen_go'),
    ('inbound-no-smime', 'enabled_smime_matches_frozen_go'),
    ('inbound-no-smime-harvest', 'enabled_smime_matches_frozen_go'),
    ('inbound-smime-ignore-integrity', 'enabled_smime_matches_frozen_go'),
    ('inbound-smime-ignore-trust', 'enabled_smime_matches_frozen_go'),
    ('inbound-smime-ignore-from', 'enabled_smime_matches_frozen_go'),
    ('inbound-smime-ignore-revocation', 'enabled_smime_matches_frozen_go'),
    ('inbound-smime-mutate-valid', 'enabled_smime_mutation_order_matches_frozen_go'),
    ('inbound-no-moderation', 'enabled_group_moderation_matches_frozen_go'),
    ('inbound-no-sandbox', 'enabled_sandbox_matches_frozen_go'),
    ('inbound-no-av', 'enabled_av_and_atomic_condemnation_match_frozen_go'),
    ('inbound-no-condemnation', 'enabled_av_and_atomic_condemnation_match_frozen_go'),
    ('inbound-no-phish-warning', 'enabled_anti_phish_matches_frozen_go'),
    ('inbound-no-anti-phish', 'enabled_anti_phish_matches_frozen_go'),
    ('inbound-no-ftrl', 'enabled_ftrl_matches_frozen_go'),
    ('inbound-no-rbl', 'enabled_rbl_matches_frozen_go'),
    ('inbound-no-ml-detectors', 'enabled_ml_detectors_match_frozen_go'),
    ('inbound-no-sender-warning', 'enabled_sender_and_spam_pipeline_matches_frozen_go'),
    ('inbound-no-spam-score', 'enabled_sender_and_spam_pipeline_matches_frozen_go'),
]
if os.environ.get('REQUIRE_DB') != '1':
    sys.exit('REQUIRE_DB=1 and the assigned disposable DSNs are required')
selected = set(sys.argv[1:])
if selected - {m for m, _ in MUTANTS}:
    sys.exit('unknown mutant selector')
baselines = set()
for mutant, test in MUTANTS:
    if selected and mutant not in selected:
        continue
    command = ['cargo', 'test', '--locked', '-p', 'setjoin-smtp', '--features', 'oracle-mutants',
               '--test', 'session', test, '--', '--exact', '--test-threads=1']
    if test not in baselines:
        baseline = subprocess.run(command, cwd=ROOT, capture_output=True, text=True,
                                  env={k: v for k, v in os.environ.items() if k != 'SETJOIN_SMTP_MUTANT'})
        if baseline.returncode:
            sys.exit(baseline.stdout[-4000:] + baseline.stderr[-2000:])
        baselines.add(test)
    markers = ('security effects', 'stored raw bytes', 'delivery effects', 'committed notifications', 'pipeline effects', 'pipeline I/O', 'iMIP effects')
    if mutant == 'inbound-no-anti-phish':
        # #544: the rejection is now a visible 550 reply, so the oracle rejects this at the reply.
        markers += ('failed: "phish-exact-rejected"',)
    broken = subprocess.run(command, cwd=ROOT, capture_output=True, text=True,
                            env=dict(os.environ, SETJOIN_SMTP_MUTANT=mutant))
    if broken.returncode != 101 or 'test result: FAILED.' not in broken.stdout or not any(marker in broken.stdout for marker in markers):
        sys.exit(f'{mutant} survived or failed outside the oracle\n{broken.stdout[-4000:]}\n{broken.stderr[-2000:]}')
    print(f'MUTANT-REJECTED SMTP inbound :: {mutant}', flush=True)
