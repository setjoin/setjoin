"""Drop a committed recovery response at the PostgreSQL wire seam, once."""
import socket
import socketserver
import struct
import threading


def exact(sock, count):
    raw = b''
    while len(raw) < count:
        chunk = sock.recv(count-len(raw))
        if not chunk:
            raise EOFError()
        raw += chunk
    return raw


class Cut:
    def __init__(self):
        self.fired = threading.Event()
        parent = self
        class Handler(socketserver.BaseRequestHandler):
            def handle(self):
                backend = socket.create_connection(('127.0.0.1', 55452), timeout=10)
                backend.settimeout(30)
                armed = threading.Event()
                def upstream():
                    tail = b''
                    try:
                        while data := self.request.recv(65536):
                            tail = (tail+data)[-65536:]
                            if b'upgrade_intent_recover' in tail:
                                armed.set()
                            backend.sendall(data)
                    except OSError:
                        pass
                sender = threading.Thread(target=upstream, daemon=True)
                sender.start()
                withheld = False
                try:
                    while True:
                        kind = exact(backend, 1)
                        length = exact(backend, 4)
                        size = struct.unpack('!I', length)[0]
                        assert 4 <= size <= 1 << 20
                        payload = exact(backend, size-4)
                        if kind == b'D' and armed.is_set() and b'rolled_back' in payload and b'intentId' in payload:
                            withheld = True
                        if withheld:
                            if kind == b'Z':
                                parent.fired.set()
                                return  # ReadyForQuery proves implicit COMMIT already completed.
                        else:
                            self.request.sendall(kind+length+payload)
                except (OSError, EOFError):
                    pass
                finally:
                    for sock in (backend, self.request):
                        try: sock.shutdown(socket.SHUT_RDWR)
                        except OSError: pass
                        sock.close()
                    sender.join(timeout=5)
        class Server(socketserver.ThreadingTCPServer):
            allow_reuse_address = True
            daemon_threads = True
        self.server = Server(('127.0.0.1', 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.port = self.server.server_address[1]
    def close(self):
        self.server.shutdown(); self.server.server_close(); self.thread.join(timeout=5)
