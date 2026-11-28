import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';

// Exercise ordinary import in a fresh process, including hostile CLI arguments.
// Guards are local to that process; the socket regression suite needs no globals
// changed merely to import the production proxy.
const harness = new URL('./run-connectivity-e6-harness.mjs', import.meta.url).href;
for (const argument of ['--help', '--internal-smoke-target', '--internal-member-simulator']) {
  const script = `
    import fs from 'node:fs';
    import crypto from 'node:crypto';
    import http from 'node:http';
    import childProcess from 'node:child_process';
    import { syncBuiltinESMExports } from 'node:module';
    const forbid = name => () => { throw new Error('unexpected import effect: ' + name); };
    const readFile = fs.readFileSync;
    let sourceReads = 0;
    fs.readFileSync = (...args) => {
      // Node 26's ESM loader reads the module itself once. Everything beyond
      // that normal loading read is a runtime effect.
      if (++sourceReads > 1) throw new Error('unexpected import effect: extra readFileSync');
      return readFile(...args);
    };
    fs.writeFileSync = forbid('writeFileSync');
    crypto.createHash = forbid('createHash');
    http.Server.prototype.listen = forbid('listen');
    childProcess.spawn = forbid('spawn');
    childProcess.spawnSync = forbid('spawnSync');
    globalThis.setTimeout = forbid('setTimeout');
    globalThis.setInterval = forbid('setInterval');
    syncBuiltinESMExports();
    const before = [...process.argv];
    const module = await import(${JSON.stringify(harness)});
    if (typeof module.FaultProxy !== 'function') throw new Error('missing production proxy');
    if (JSON.stringify(process.argv) !== JSON.stringify(before)) throw new Error('argv mutated');
  `;
  const result = spawnSync(process.execPath, ['--input-type=module', '-e', script, '--', argument], {
    encoding: 'utf8', timeout: 5_000,
  });
  assert.equal(result.error, undefined, result.error?.message);
  assert.equal(result.status, 0, `${argument}: ${result.stderr}`);
  assert.equal(result.stdout, '', 'import must not produce CLI output');
  assert.equal(result.stderr, '', 'import must not produce diagnostics');
}
console.log('E6 inert import: PASS (no CLI dispatch, extra file I/O, hashing, listeners, children or timers)');
