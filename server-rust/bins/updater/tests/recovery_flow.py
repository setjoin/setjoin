"""Authored recovery process seam; imported by the existing complete install fixture."""
import json
import os
from pathlib import Path
import subprocess
import re
import tempfile
import time


def run(root, install, env, binary, go, pg, sql, rid, stack):
    case = os.environ['REL3_RECOVERY_CASE']
    env = env | dict(REL3_INSTALL_ROOT=str(install), REL3_JOURNAL_DIR=str(root/'state'),
          REL3_EVIDENCE_DIR=str(root/'evidence'), REL3_DSN_FILE=str(root/'dsn'))
    def recover(*args):
        prefix = [os.environ['REL3_GO_RECOVERY']] if go else [binary, 'recover',
            '--install-root', str(install), '--state-dir', str(root/'state'),
            '--evidence-dir', str(root/'evidence'), '--dsn-file', str(root/'dsn')]
        return subprocess.run(prefix + list(args), input='', env=env, capture_output=True,
                              text=True, timeout=35)
    def status():
        p = recover('status', '--json')
        assert p.returncode == 0, p.stderr
        value = json.loads(p.stdout)
        value['intent_id'] = '<intent>'
        assert len(value['journal_hash']) == 64
        value['journal_hash'] = '<journal-hash>'
        return json.loads(json.dumps(value).replace(rid, '<release>'))
    initial = status()
    assert initial['recovery_required']
    (root/'host.log').write_text('')
    notifications = tempfile.TemporaryFile(mode='w+t')
    listener = subprocess.Popen(['psql','-XAtq'],env=pg,stdin=subprocess.PIPE,
        stdout=notifications,stderr=subprocess.PIPE,text=True)
    def stop_listener():
        if listener.poll() is None:
            listener.stdin.write('\\q\n'); listener.stdin.flush()
        listener.communicate(timeout=10)
        notifications.close()
    stack.callback(stop_listener)
    def wait_text(marker):
        deadline=time.monotonic()+10
        while time.monotonic()<deadline:
            notifications.seek(0); value=notifications.read()
            if marker in value: return value
            assert listener.poll() is None, listener.stderr.read()
            time.sleep(0.02)
        raise AssertionError('notification listener did not reach '+marker)
    listener.stdin.write("LISTEN upgrade_intent_changed; SELECT 'gofree-rel3-ready';\n"); listener.stdin.flush()
    wait_text('gofree-rel3-ready')
    pending = None
    if case == 'response-loss':
        from pg_cut import Cut
        cut = Cut()
        original_dsn = (root/'dsn').read_text()
        try:
            (root/'dsn').write_text(original_dsn.replace(':55452/', ':'+str(cut.port)+'/')+'?sslmode=disable')
            first = recover('activate-previous', '--reason', 'operator verified rollback')
            assert first.returncode == 1, first.stderr
            assert cut.fired.is_set(), first.stderr
            pending = status()
            assert pending['database_reconciliation_required'], pending
            assert json.loads(sql('SELECT upgrade_intent_read(NULL)'))['state'] == 'rolled_back'
        finally:
            cut.close()
            (root/'dsn').write_text(original_dsn)
    p = recover('activate-previous', '--reason', 'operator verified rollback')
    assert p.returncode == 0, p.stderr
    assert p.stdout.startswith('previous release verified; evidence=')
    result = json.loads(sql('SELECT upgrade_intent_read(NULL)'))
    assert result['state'] == 'rolled_back', result
    assert (install/'current').readlink() == Path('releases/old')
    assert (install/'previous').readlink() == Path('releases')/rid
    final = status()
    assert not final['database_reconciliation_required']
    generation = result['stateGeneration']
    host = (root/'host.log').read_text().splitlines()
    repeated = recover('activate-previous', '--reason', 'operator verified rollback')
    assert repeated.returncode == 0, repeated.stderr
    if case != 'response-loss': assert repeated.stdout == p.stdout
    else: assert result['result']['evidence_file'] in repeated.stdout
    assert json.loads(sql('SELECT upgrade_intent_read(NULL)'))['stateGeneration'] == generation
    assert (root/'host.log').read_text().splitlines() == host + ['start setjoin-updater']
    evidence = []
    for path in (root/'evidence').glob('*.json'):
        assert path.stat().st_mode & 0o777 == 0o600
        e = json.loads(path.read_text()); e['recorded_at'] = '<time>'
        e['status']['intent_id'] = '<intent>'; e['status']['journal_hash'] = '<journal-hash>'
        evidence.append(json.loads(json.dumps(e).replace(rid, '<release>')))
    evidence.sort(key=lambda e:(e['phase'], e['status']['database_reconciliation_required']))
    recovery = result['result']
    evidence_path = root/'evidence'/recovery['evidence_file']
    assert evidence_path.is_file()
    recovery['evidence_file'] = '<evidence-file>'
    audit = sql("SELECT count(*) FROM admin_audit_log WHERE action='upgrade_intent_recovery_reconciled' AND target_id="+result['intentId'])
    assert audit == '1', audit
    observed = dict(initial=initial, final=final, result=recovery,
        states=[e['to'] for e in result['events']], host=host, evidence=evidence, recovery_audits=1)
    if pending is not None: observed['pending'] = pending
    listener.stdin.write("SELECT 'gofree-rel3-flushed';\n"); listener.stdin.flush()
    messages = wait_text('gofree-rel3-flushed')
    notices = [json.loads(payload) for payload in re.findall(r'Asynchronous notification "upgrade_intent_changed" with payload "(.*)" received',messages)]
    assert len(notices)==1 and notices[0]['state']=='rolled_back', messages
    assert str(notices[0]['intent_id']) == result['intentId']
    assert str(notices[0]['generation']) == result['stateGeneration']
    notices[0]['intent_id']='<intent>'
    effects=dict(notifications=notices, audit_action='upgrade_intent_recovery_reconciled', audit_count=1)
    effects_name='recovery-'+case+'-effects.json'
    if go:
        with (Path(os.environ['REL3_RECORD_DIR'])/effects_name).open('x') as f:
            json.dump(dict(go_source=os.environ['GOFREE_GO_SOURCE'],observed=effects),f,indent=2);f.write('\n')
    else:
        assert effects == json.loads((Path(__file__).with_name('goldens')/effects_name).read_text())['observed'], effects
    name = 'recovery-'+case+'.json'
    if go:
        with (Path(os.environ['REL3_RECORD_DIR'])/name).open('x') as f:
            json.dump(dict(go_source=os.environ['GOFREE_GO_SOURCE'], observed=observed), f, indent=2); f.write('\n')
    else:
        expected = json.loads((Path(__file__).with_name('goldens')/name).read_text())['observed']
        assert observed == expected, observed
    print('REL3 authored '+case+': Go recovery/DB/evidence/repeat parity passed')
