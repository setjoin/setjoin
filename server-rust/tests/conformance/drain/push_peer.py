"""Owned loopback push/OAuth peer for the #408 drain oracle. Reuses the mailctl
fake (HTTP/2 APNs with client-certificate check, RFC 8291 Web Push decryption,
VAPID/RS256 verification, CONNECT-proxied FCM/HMS) and adds per-device outcomes
chosen by the device token: a token starting `gone` is reported unregistered,
one starting `fail` is a retryable provider failure. Nothing is forwarded.

usage: push_peer.py <state-dir>   (writes ready.json, appends requests.jsonl)
"""
import json
import signal
import sys
import threading
import urllib.parse
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE / '../../../bins/mailctl/tests'))
from push_service import Service  # noqa: E402


def token_of(path, raw):
    parsed = urllib.parse.urlparse(path)
    if parsed.path.startswith('/3/device/'):
        return parsed.path.rsplit('/', 1)[1]
    if parsed.path == '/webpush/capability':
        return urllib.parse.parse_qs(parsed.query).get('d', [''])[0]
    try:
        message = json.loads(raw)['message']
    except Exception:
        return ''
    token = message.get('token', '')
    return token[0] if isinstance(token, list) else token


class Peer(Service):
    def __init__(self, log):
        super().__init__({})
        self.log = log
        self.lock = threading.Lock()

    def handle(self, headers, path, raw, client_cert):
        with self.lock:
            status, data = super().handle(headers, path, raw, client_cert)
            row = self.requests[-1]
            parsed = urllib.parse.urlparse(path)
            token = token_of(path, raw)
            send = parsed.path.endswith('messages:send') or parsed.path.startswith(('/3/device/', '/webpush/'))
            if send and token.startswith(('gone', 'fail')):
                gone = token.startswith('gone')
                if parsed.path.startswith('/3/device/'):
                    status, body = (410, {'reason': 'Unregistered'}) if gone else (500, {'reason': 'InternalServerError'})
                elif parsed.path.startswith('/webpush/'):
                    status, body = (410 if gone else 500), {}
                elif parsed.path.startswith('/v3/'):
                    status, body = 200, {'code': '80300007' if gone else '80200001'}
                else:
                    status, body = (404 if gone else 500), {}
                data = json.dumps(body, separators=(',', ':')).encode()
            if send:
                row['status'] = status
            with open(self.log, 'a') as out:
                out.write(json.dumps(row, default=str) + '\n')
            return status, data


def main():
    state = Path(sys.argv[1])
    log = state / 'requests.jsonl'
    log.write_text('')
    service = Peer(log)
    service.thread.start()
    (state / 'ready.json').write_text(json.dumps({'url': service.url, 'port': service.server.server_address[1]}))
    done = threading.Event()
    signal.signal(signal.SIGTERM, lambda *a: done.set())
    signal.signal(signal.SIGINT, lambda *a: done.set())
    done.wait()
    service.finish()


main()
