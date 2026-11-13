// Packaged-binary fuse read-back gate (ADR-013 invariant 1, C1 cutover follow-up).
//
// Runs in the release CI job AFTER electron-builder packages (afterPack has
// already flipped the fuses). Reads the real fuse wire off the packaged binary
// with `@electron/fuses` getCurrentFuseWire and fails the build on ANY drift
// from the locked FUSE_CONFIG in dist/security/fuses.js — the same truth table
// flip-fuses.mjs writes, so flip + verify share one source of truth.
//
// Usage: node scripts/verify-fuses.mjs <path-to-packaged-electron-binary>
//   mac:   release/mac-arm64/SetJoin.app/Contents/MacOS/SetJoin
//   win:   release/win-unpacked/SetJoin.exe
//   linux: release/linux-unpacked/setjoin
import { getCurrentFuseWire, FuseV1Options, FuseState } from '@electron/fuses';
import { FUSE_CONFIG } from '../dist/security/fuses.js';

const binary = process.argv[2];
if (!binary) {
	console.error('verify-fuses: missing packaged-binary path argument');
	process.exit(2);
}

// getCurrentFuseWire → { <fuseIndex>: FuseState } (48=DISABLE, 49=ENABLE, ...).
const wire = await getCurrentFuseWire(binary);

// FUSE_CONFIG is keyed by the numeric FuseV1Options index → expected boolean,
// plus non-fuse bookkeeping keys we skip. Map each expected boolean to the
// FuseState the read-back reports.
const skip = new Set(['version', 'resetAdHocDarwinSignature']);
const nameOf = Object.fromEntries(
	Object.entries(FuseV1Options).map(([k, v]) => [String(v), k]),
);

let drift = 0;
for (const [key, expected] of Object.entries(FUSE_CONFIG)) {
	if (skip.has(key)) continue;
	const want = expected ? FuseState.ENABLE : FuseState.DISABLE;
	const actual = wire[key];
	if (actual !== want) {
		const state = FuseState[actual] ?? actual;
		drift++;
		console.error(
			`FUSE DRIFT: ${nameOf[key] ?? key} = ${state}, expected ${expected ? 'ENABLE' : 'DISABLE'}`,
		);
	}
}

if (drift > 0) {
	console.error(`verify-fuses: ${drift} fuse(s) drifted from the locked set — FAIL`);
	process.exit(1);
}
console.log('verify-fuses: packaged binary matches the locked fuse set — OK');
