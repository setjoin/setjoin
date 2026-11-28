"""Independent ZIP observation for GET /messages/{id}/attachments.zip (#469).
Reads the response body on stdin and prints one JSON listing: every entry's
name, method, size and content digest, verified by decompressing (CRC checked).
Nothing is extracted to disk. Compressed bytes are never compared: Go's
compress/flate and Rust's deflate legitimately differ."""
import hashlib
import io
import json
import sys
import zipfile

raw = sys.stdin.buffer.read()
if not raw.startswith(b'PK\x03\x04'):
    raise ValueError('response is not a zip with a first local header: %r' % raw[:120])
archive = zipfile.ZipFile(io.BytesIO(raw))
entries = []
for entry in archive.infolist():
    data = archive.read(entry)
    entries.append({'name': entry.filename, 'method': entry.compress_type,
                    'size': len(data), 'sha256': hashlib.sha256(data).hexdigest()})
print(json.dumps({'entries': entries}, separators=(',', ':')))
