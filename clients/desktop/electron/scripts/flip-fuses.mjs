// electron-builder `afterPack` hook — flips the locked Electron fuse set on the
// packaged binary (ADR-013 invariant 1). Runs only in real packaging (dist must
// be built first); the CI read-back (`@electron/fuses` getCurrentFuseWire) is the
// gate that fails the build on drift. Not exercised in the sandbox (no packaging).
import path from 'node:path';
import { flipAppFuses } from '../dist/security/fuses.js';

export default async function afterPack(context) {
	const { appOutDir, electronPlatformName, packager } = context;
	const name = packager.appInfo.productFilename;
	const binary = {
		darwin: path.join(appOutDir, `${name}.app`, 'Contents', 'MacOS', name),
		win32: path.join(appOutDir, `${name}.exe`),
		linux: path.join(appOutDir, name),
	}[electronPlatformName];
	if (!binary) throw new Error(`flip-fuses: unknown platform ${electronPlatformName}`);
	await flipAppFuses(binary);
}
