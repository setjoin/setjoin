// P2 Task 11: esbuild bundle for the Electron main/preload processes. Replaces
// the old per-file `tsc -p tsconfig.build.json` emit — main.ts now imports the
// shared cross-package sync engine (mailserver/webmail/src/lib/drive/sync/),
// which tsc's own emit can't reach across the package boundary; esbuild
// resolves + inlines it directly. `tsc --noEmit` (tsconfig.json's "bundler"
// resolution) remains the strict typecheck gate — this script only emits.
//
// Four entry points, each bundled standalone (not just main+preload): the two
// existing electron-builder/CI scripts (flip-fuses.mjs, verify-fuses.mjs,
// check-electron-patch-cadence.mjs) import dist/security/fuses.js and
// dist/security/patch-cadence.js directly, independent of main.js — those
// output paths must keep existing or packaging breaks.
import * as esbuild from 'esbuild';

const common = {
	bundle: true,
	platform: 'node',
	format: 'cjs',
	target: 'node22',
	sourcemap: true,
	logLevel: 'info',
	// electron is provided by the runtime; @parcel/watcher ships its own native
	// .node binding and must stay a real require, not be inlined.
	external: ['electron', '@parcel/watcher'],
};

await Promise.all([
	esbuild.build({ ...common, entryPoints: ['src/main.ts'], outfile: 'dist/main.js' }),
	esbuild.build({ ...common, entryPoints: ['src/preload.ts'], outfile: 'dist/preload.js' }),
	esbuild.build({ ...common, entryPoints: ['src/security/fuses.ts'], outfile: 'dist/security/fuses.js' }),
	esbuild.build({
		...common,
		entryPoints: ['src/security/patch-cadence.ts'],
		outfile: 'dist/security/patch-cadence.js',
	}),
]);
