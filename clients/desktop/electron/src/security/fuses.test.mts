import { describe, it, expect } from 'vitest';
import { FuseV1Options, FuseVersion } from '@electron/fuses';
import { FUSE_CONFIG } from './fuses';

describe('Electron fuse truth table (ADR-013 invariant 1)', () => {
	it('disables the dangerous fuses', () => {
		expect(FUSE_CONFIG[FuseV1Options.RunAsNode]).toBe(false);
		expect(FUSE_CONFIG[FuseV1Options.EnableNodeOptionsEnvironmentVariable]).toBe(false);
		expect(FUSE_CONFIG[FuseV1Options.EnableNodeCliInspectArguments]).toBe(false);
		expect(FUSE_CONFIG[FuseV1Options.GrantFileProtocolExtraPrivileges]).toBe(false);
	});

	it('enables integrity + only-load-from-asar together, cookie encryption, per-process snapshot', () => {
		expect(FUSE_CONFIG[FuseV1Options.EnableEmbeddedAsarIntegrityValidation]).toBe(true);
		expect(FUSE_CONFIG[FuseV1Options.OnlyLoadAppFromAsar]).toBe(true);
		expect(FUSE_CONFIG[FuseV1Options.EnableCookieEncryption]).toBe(true);
		expect(FUSE_CONFIG[FuseV1Options.LoadBrowserProcessSpecificV8Snapshot]).toBe(true);
	});

	it('targets fuse wire V1', () => {
		expect(FUSE_CONFIG.version).toBe(FuseVersion.V1);
	});
});
