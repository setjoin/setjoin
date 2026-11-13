#!/usr/bin/env python3
"""F21 federation ownership is a public route-inventory contract (#339)."""
import json
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
inv = json.loads((ROOT / 'server-rust/bins/gateway/route-inventory.json').read_text())
op = {'/.well-known/', '/.well-known/openid-configuration', '/.well-known/oauth-authorization-server',
      '/authorize', '/authorize/', '/authorize/callback', '/oauth', '/oauth/', '/oauth/token',
      '/oauth/introspect', '/userinfo', '/keys', '/end_session', '/revoke', '/auth/oidc/op/complete'}
seen = set()
count = 0
for row in inv['routes']:
    if row['family'] != 'F21':
        continue
    path = row['path']
    expected = ('federation-op' if path in op else 'federation-saml' if '/saml' in path or path.startswith('/auth/identity-links')
                else 'federation-rp' if '/oidc' in path else None)
    if expected:
        assert row['slice'] == expected, (row['listener'], row['method'], path, row['slice'], expected)
        assert row['state']=='ON' and row['upstream'] in {'rust-auth','local-rust'}, row
        count += 1
        seen.add(expected)
assert seen == {'federation-op', 'federation-rp', 'federation-saml'}, seen
assert count == 38, count
print('IDFED3: all 38 federation registrations ON in Rust (#339/#340/#341)')
