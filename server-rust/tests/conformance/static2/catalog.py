"""Merge supplemental HTTP cases without rewriting other owners' qualification."""
import json
from pathlib import Path
root = Path(__file__).resolve().parents[4]
path = root / 'server-rust/tests/conformance/route-catalog.json'
catalog = json.loads(path.read_text())
for route_path, target, cases, sources in [
    ('/api/discover', 'static2_discovery', [('srv','discovery_srv_matches_frozen_go'),('mx','discovery_mx_matches_frozen_go'),('compressed','discovery_compressed_matches_frozen_go')]+[(name,'discovery_'+name.replace('-','_')+'_matches_frozen_go') for name in ['private','numeric','no-jmap','oversize','redirect','cache']], ['discovery.rs']),
    ('/health', 'static2_health', [(name,'health_'+name+'_http_matches_frozen_go') for name in ['none','sfu','egress','asr']], ['platform.rs','meet_livekit.rs','health_alerts.rs']),
]:
    suite = next(s for s in catalog['routes'] if s['listener']=='gateway' and s['method']=='GET' and s['path']==route_path and not s.get('command'))
    suite['handler_sources'] = list(dict.fromkeys(suite.get('handler_sources',[])+['server-rust/bins/gateway/src/'+s for s in sources]))
    for name, test in cases:
        golden = f'server-rust/tests/conformance/static2/{"discovery" if route_path=="/api/discover" else "health-http"}-{name}.json'
        entry = next((c for c in suite['cases'] if c['golden']==golden), None)
        if entry is None:
            entry = dict(kind='static2-'+name,golden=golden)
            suite['cases'].append(entry)
        entry['replay'] = dict(package='setjoin-gateway',target=target,test=test)
path.write_text(json.dumps(catalog,indent=2)+'\n')
