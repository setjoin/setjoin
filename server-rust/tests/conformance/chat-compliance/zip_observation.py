"""Independent ZIP/CRC/content-digest oracle. No files are extracted to disk."""
import base64
import hashlib
import io
import json
import sys
import zipfile

raw = sys.stdin.buffer.read()
if not raw:
    print(json.dumps({'complete': False, 'files': [], 'started': False}))
    sys.exit(0)
if not raw.startswith(b'PK\x03\x04'):
    raise ValueError('ZIP response lacks its first local header')
try:
    archive = zipfile.ZipFile(io.BytesIO(raw))
except zipfile.BadZipFile:
    # Go deliberately abandons midstream without a central directory/manifest.
    print(json.dumps({'complete': False, 'files': [], 'started': True}))
    sys.exit(0)
files = []
contents = {}
for entry in archive.infolist():
    data = archive.read(entry)  # verifies CRC32 while decompressing
    contents[entry.filename] = data
    files.append({'name': entry.filename, 'method': entry.compress_type,
                  'base64': base64.b64encode(data).decode('ascii')})
if not files or files[-1]['name'] != 'manifest.json':
    raise ValueError('manifest must be the final ZIP entry')
manifest = json.loads(contents['manifest.json'])
if manifest['messagesSha256'] != hashlib.sha256(contents['messages.jsonl']).hexdigest():
    raise ValueError('messages.jsonl digest differs from manifest')
for name, data in contents.items():
    if name.startswith('attachments/') and name.split('/', 1)[1] != hashlib.sha256(data).hexdigest():
        raise ValueError('attachment bytes differ from content-addressed filename')
print(json.dumps({'complete': True, 'files': files}))
