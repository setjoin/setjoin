// CI gate (ADR-013 invariant 5): fail the build if the pinned Electron major is
// more than N-2 behind the latest stable. Graceful skip-not-fail on a network
// error. Reads the pinned major from package.json; live-fetches latest.
import { readFileSync } from 'node:fs';
import {
	isSupportedMajor,
	parseMajor,
	fetchLatestElectronMajor,
} from '../dist/security/patch-cadence.js';

const pkg = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'));
const pinned = parseMajor(pkg.devDependencies.electron);

const latest = await fetchLatestElectronMajor();
if (latest == null) {
	console.warn('patch-cadence: could not fetch latest Electron major — skipping (not failing).');
	process.exit(0);
}
if (!isSupportedMajor(pinned, latest)) {
	console.error(
		`patch-cadence FAIL: pinned Electron major ${pinned} is more than N-2 behind latest ${latest}. Bump it.`,
	);
	process.exit(1);
}
console.log(`patch-cadence OK: pinned ${pinned}, latest stable ${latest}.`);
