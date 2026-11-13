#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
collector="$ROOT/scripts/exchange-assessment/Collect-SetjoinExchangeAssessment.ps1"
if rg -n -i 'Invoke-Expression|Invoke-Command|Start-Process' "$collector"; then
  echo "Exchange collector contains dynamic execution" >&2
  exit 1
fi
node - "$ROOT" "$collector" <<'NODE'
const fs=require('fs'); const root=process.argv[2], collector=fs.readFileSync(process.argv[3],'utf8');
const registry=JSON.parse(fs.readFileSync(root+'/config/exchange-replacement/generated/exchange-replacement-v1.json'));
const ids=[...collector.matchAll(/Invoke-AssessmentProbe '([^']+)'/g)].map(x=>x[1]).sort();
const want=registry.capabilities.map(x=>x.id).sort();
if(JSON.stringify(ids)!==JSON.stringify(want)) throw new Error(`collector capability drift: got ${ids.length}, want ${want.length}`);
const commands=new Set([...collector.matchAll(/\b(Get-[A-Za-z0-9]+)/g)].map(x=>x[1]));
const allowed=new Set([...registry.probes.map(x=>x.command),...registry.roots.map(x=>x.enumerator)]);
for(const command of commands) if(!allowed.has(command)) throw new Error(`collector command not in registry: ${command}`);
console.log(`exchange_collector_ok capabilities=${ids.length} commands=${commands.size}`);
NODE
