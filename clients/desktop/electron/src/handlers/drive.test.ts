import { describe, it, expect, vi, afterAll } from 'vitest';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import {
	DEFAULT_DRIVE_CONFINEMENT,
	isPathInsideRoots,
	isUrlApproved,
	makeDriveHandlers,
	sanitizeMirrorSpaceFolder,
} from './drive';
import type { DriveTokenOwner } from './drive';
import type { NativeBinding } from '../native';

function fakeNative(over: Partial<NativeBinding> = {}): NativeBinding {
	return {
		vaultUnlock: () => true,
		vaultIsUnlocked: () => true,
		vaultListTotp: () => [],
		vaultGenerateTotp: () => '000000',
		secureStoreGet: () => null,
		secureStoreSet: () => {},
		secureStoreRemove: () => {},
		dbOpen: () => {},
		dbIsOpen: () => true,
		dbExec: () => 0,
		dbExecSchemaInit: () => 0,
		dbTransactionBatch: () => 0,
		dbMigrateStore: () => '{"version":2}',
		dbQuery: () => '[]',
		dbWipe: () => {},
		driveImportFile: vi.fn(async () => '{"contentSha256":"abc","size":1,"chunks":[]}'),
		driveFetchChunk: vi.fn(async () => {}),
		drivePushChunk: vi.fn(async () => 201),
		driveHasChunk: vi.fn(() => true),
		driveDeleteChunks: vi.fn(() => 2),
		driveSetConfinement: vi.fn(),
		driveServeStart: vi.fn(async () => '{"port":54321}'),
		driveServeGrant: vi.fn(() => '/t/deadbeef'),
		driveServeRevoke: vi.fn(),
		driveServeStop: vi.fn(),
		mamStoreDeviceId: () => {},
		mamStorePolicy: () => {},
		mamGetPolicy: () => null,
		mamMarkWiped: () => {},
		mamIsWiped: () => false,
		mamClearWiped: () => {},
		...over,
	};
}

function fakeTokenOwner(token: string | null): DriveTokenOwner {
	return { getBearer: vi.fn(async () => token) };
}

// ── temp mirror-like import root ─────────────────────────────────────────────
const tmpRoots: string[] = [];
function makeImportRoot(): { root: string; file: string } {
	const root = fs.mkdtempSync(path.join(os.tmpdir(), 'drive-confinement-'));
	tmpRoots.push(root);
	const file = path.join(root, 'report.docx');
	fs.writeFileSync(file, 'mirror file bytes');
	return { root, file };
}
afterAll(() => {
	for (const root of tmpRoots) fs.rmSync(root, { recursive: true, force: true });
});

const APPROVED = 'https://drive.gateway.example';

/** Confinement for a single import root with a trusted mirror-index checker. */
function confinementFor(root: string, registered: (p: string) => boolean) {
	return {
		importRoots: [root],
		approvedOrigins: [] as string[],
		isTrustedMirrorFile: async (p: string) => registered(p),
	};
}

describe('drive handlers (window.setjoinNative.drive)', () => {
	it('hard-binds every call to the drive appKey regardless of renderer input', async () => {
		const { root, file } = makeImportRoot();
		const native = fakeNative();
		const owner = fakeTokenOwner('owner-token');
		const h = makeDriveHandlers(
			native,
			{
				importRoots: [root],
				approvedOrigins: [APPROVED],
				isTrustedMirrorFile: async () => true,
			},
			owner,
		);

		await h.drive_import_file(file);
		expect(native.driveImportFile).toHaveBeenCalledWith('drive', file);

		// The renderer-supplied bearer ('renderer-bearer') is IGNORED — the
		// owner's token credentials the native call (bearer ownership in main).
		await h.drive_fetch_chunk(`${APPROVED}/api/drive/chunks/x`, 'renderer-bearer', 'deadbeef', 4096);
		expect(native.driveFetchChunk).toHaveBeenCalledWith(
			'drive',
			`${APPROVED}/api/drive/chunks/x`,
			'owner-token',
			'deadbeef',
			4096,
		);

		await h.drive_push_chunk(`${APPROVED}/api/drive/chunks/x`, 'renderer-bearer', 'deadbeef');
		expect(native.drivePushChunk).toHaveBeenCalledWith('drive', `${APPROVED}/api/drive/chunks/x`, 'owner-token', 'deadbeef');

		h.drive_has_chunk('deadbeef');
		expect(native.driveHasChunk).toHaveBeenCalledWith('drive', 'deadbeef');

		await h.drive_serve_start();
		expect(native.driveServeStart).toHaveBeenCalledWith('drive');

		h.drive_serve_grant({ size: 0, chunks: [] });
		expect(native.driveServeGrant).toHaveBeenCalledWith('drive', '{"size":0,"chunks":[]}');

		h.drive_serve_revoke('/t/abc');
		expect(native.driveServeRevoke).toHaveBeenCalledWith('drive', '/t/abc');
	});

	it('drive_delete_chunks JSON-stringifies the sha256 array (empty array on undefined)', () => {
		const native = fakeNative();
		const h = makeDriveHandlers(native);
		h.drive_delete_chunks(['a', 'b']);
		expect(native.driveDeleteChunks).toHaveBeenCalledWith('drive', '["a","b"]');
		h.drive_delete_chunks(undefined);
		expect(native.driveDeleteChunks).toHaveBeenCalledWith('drive', '[]');
	});

	it('drive_import_file / drive_serve_start JSON-parse the native async result', async () => {
		const { root, file } = makeImportRoot();
		const native = fakeNative();
		const h = makeDriveHandlers(
			native,
			confinementFor(root, (p) => p === file),
		);
		expect(await h.drive_import_file(file)).toEqual({ contentSha256: 'abc', size: 1, chunks: [] });
		expect(await h.drive_serve_start()).toEqual({ port: 54321 });
	});
});

describe('drive FILE confinement — drive_import_file rejects non-mirror src_path', () => {
	it('fail-closed default: no import roots configured → every import rejected before invoke', async () => {
		const { file } = makeImportRoot();
		const native = fakeNative();
		const h = makeDriveHandlers(native); // DEFAULT_DRIVE_CONFINEMENT
		await expect(h.drive_import_file(file)).rejects.toThrow(/not an importable mirrored file/);
		expect(native.driveImportFile).not.toHaveBeenCalled();
	});

	it('configured roots WITHOUT a trusted mirror-index checker import nothing (fail-closed)', async () => {
		const { root, file } = makeImportRoot();
		const native = fakeNative();
		const h = makeDriveHandlers(native, { importRoots: [root], approvedOrigins: [] });
		await expect(h.drive_import_file(file)).rejects.toThrow(/no trusted mirror-index membership checker/);
		expect(native.driveImportFile).not.toHaveBeenCalled();
	});

	it('rejects root escapes (paths outside every import root)', async () => {
		const { root } = makeImportRoot();
		const other = makeImportRoot();
		const native = fakeNative();
		const h = makeDriveHandlers(
			native,
			confinementFor(root, () => true), // even a fully-trusting index cannot widen the root
		);
		await expect(h.drive_import_file('/etc/passwd')).rejects.toThrow(/not an importable mirrored file/);
		await expect(h.drive_import_file(other.file)).rejects.toThrow(/not an importable mirrored file/);
		expect(native.driveImportFile).not.toHaveBeenCalled();
	});

	it('rejects absolute-escape and relative shapes (..-traversal resolving outside, relative path)', async () => {
		const { root } = makeImportRoot();
		const native = fakeNative();
		const h = makeDriveHandlers(native, confinementFor(root, () => true));
		await expect(h.drive_import_file(`${root}/nowhere/../../etc/passwd`)).rejects.toThrow(
			/not an importable mirrored file/,
		);
		await expect(h.drive_import_file('relative/report.docx')).rejects.toThrow(/not an importable mirrored file/);
		expect(native.driveImportFile).not.toHaveBeenCalled();
	});

	it('rejects a symlink inside the root that points outside it', async () => {
		const { root } = makeImportRoot();
		const link = path.join(root, 'escape.link');
		fs.symlinkSync('/etc/passwd', link);
		const native = fakeNative();
		const h = makeDriveHandlers(native, confinementFor(root, () => true));
		await expect(h.drive_import_file(link)).rejects.toThrow(/not an importable mirrored file/);
		expect(native.driveImportFile).not.toHaveBeenCalled();
	});

	it('rejects missing files and directories', async () => {
		const { root } = makeImportRoot();
		const native = fakeNative();
		const h = makeDriveHandlers(native, confinementFor(root, () => true));
		await expect(h.drive_import_file(path.join(root, 'missing.docx'))).rejects.toThrow(
			/not an importable mirrored file/,
		);
		await expect(h.drive_import_file(root)).rejects.toThrow(/not an importable mirrored file/);
		expect(native.driveImportFile).not.toHaveBeenCalled();
	});

	it('rejects an UNINDEXED file inside the root (directory membership is not the boundary)', async () => {
		const { root, file } = makeImportRoot();
		const native = fakeNative();
		// The file sits inside the root, but the mirror index does not know it.
		const h = makeDriveHandlers(native, confinementFor(root, () => false));
		await expect(h.drive_import_file(file)).rejects.toThrow(/not a registered mirrored file/);
		expect(native.driveImportFile).not.toHaveBeenCalled();
	});

	it('accepts a registered mirrored file, including through an ancestor symlink of the root', async () => {
		const { root, file } = makeImportRoot();
		const native = fakeNative();
		const h = makeDriveHandlers(
			native,
			confinementFor(root, (p) => {
				// The checker (composition-root-backed mirror index) trusts exactly
				// this file, resolved through realpath — ancestor symlinks (macOS
				// /tmp → /private/var/...) resolve on the checker's side too.
				return fs.realpathSync(p) === fs.realpathSync(file);
			}),
		);
		await expect(h.drive_import_file(file)).resolves.toEqual({ contentSha256: 'abc', size: 1, chunks: [] });
		expect(native.driveImportFile).toHaveBeenCalledWith('drive', file);
	});

	it('isPathInsideRoots unit matrix (pure helper)', () => {
		const { root, file } = makeImportRoot();
		expect(isPathInsideRoots(file, [root])).toBe(true);
		expect(isPathInsideRoots('/etc/passwd', [root])).toBe(false);
		expect(isPathInsideRoots('relative', [root])).toBe(false);
		expect(isPathInsideRoots(file, [])).toBe(false);
		expect(isPathInsideRoots(file, [path.join(root, 'does-not-exist')])).toBe(false);
	});

	it('sanitizeMirrorSpaceFolder mirrors the service space-folder mapping', () => {
		expect(sanitizeMirrorSpaceFolder('Team Space')).toBe('Team Space');
		expect(sanitizeMirrorSpaceFolder('weird:name*here?')).toBe('weird_name_here_');
		expect(sanitizeMirrorSpaceFolder('///')).toBe('___'); // separators become underscores…
		expect(sanitizeMirrorSpaceFolder('  ')).toBe('space'); // …but blank names collapse to 'space'
	});
});

describe('drive NETWORK confinement — chunk URLs outside approved origins rejected before invoke', () => {
	const url = (o: string) => `${o}/api/drive/chunks/deadbeef?space=1`;
	const owner = () => fakeTokenOwner('owner-token');

	it('fail-closed default: no approved origins → fetch and push rejected before invoke', async () => {
		const native = fakeNative();
		const h = makeDriveHandlers(native, DEFAULT_DRIVE_CONFINEMENT, owner());
		await expect(h.drive_fetch_chunk(url('https://drive.gateway.example'), 'tok', 'aa', 1)).rejects.toThrow(
			/url origin is not approved/,
		);
		await expect(h.drive_push_chunk(url('https://drive.gateway.example'), 'tok', 'aa')).rejects.toThrow(
			/url origin is not approved/,
		);
		expect(native.driveFetchChunk).not.toHaveBeenCalled();
		expect(native.drivePushChunk).not.toHaveBeenCalled();
	});

	it('rejects non-approved origins, lookalike ports, and scheme downgrades', async () => {
		const native = fakeNative();
		const h = makeDriveHandlers(
			native,
			{ importRoots: [], approvedOrigins: [APPROVED] },
			owner(),
		);
		for (const bad of [
			url('https://evil.example'),
			url('http://drive.gateway.example'), // scheme downgrade: parsed origin differs
			url('https://drive.gateway.example:8443'), // port-exact origin equality
			url('https://drive.gateway.example.attacker.example'),
			'/api/drive/chunks/deadbeef', // relative path — would fail natively too, but fails closed here first
			'file:///etc/passwd',
			'ftp://drive.gateway.example/x',
			'not a url',
		]) {
			await expect(h.drive_fetch_chunk(bad, 'tok', 'aa', 1)).rejects.toThrow(/url origin is not approved/);
			await expect(h.drive_push_chunk(bad, 'tok', 'aa')).rejects.toThrow(/url origin is not approved/);
		}
		expect(native.driveFetchChunk).not.toHaveBeenCalled();
		expect(native.drivePushChunk).not.toHaveBeenCalled();
	});

	it('approves the exact configured origin and a second listed origin', async () => {
		const native = fakeNative();
		const h = makeDriveHandlers(
			native,
			{
				importRoots: [],
				approvedOrigins: [APPROVED, 'https://mirror.setjoin.local:8443'],
			},
			owner(),
		);
		await expect(h.drive_fetch_chunk(url(APPROVED), 'renderer', 'aa', 1)).resolves.toBeUndefined();
		await expect(h.drive_push_chunk(url('https://mirror.setjoin.local:8443/x'), 'renderer', 'aa')).resolves.toBe(201);
		expect(native.driveFetchChunk).toHaveBeenCalledTimes(1);
		expect(native.drivePushChunk).toHaveBeenCalledTimes(1);
	});

	it('isUrlApproved unit matrix (pure helper)', () => {
		expect(isUrlApproved(url(APPROVED), [APPROVED])).toBe(true);
		expect(isUrlApproved(url('https://drive.gateway.example:8443'), [APPROVED])).toBe(false);
		expect(isUrlApproved('file:///etc/passwd', [APPROVED])).toBe(false);
		expect(isUrlApproved('/relative/path', [APPROVED])).toBe(false);
		expect(isUrlApproved(url(APPROVED), ['not a url'])).toBe(false);
		expect(isUrlApproved(url(APPROVED), DEFAULT_DRIVE_CONFINEMENT.approvedOrigins)).toBe(false);
	});
});

describe('drive BEARER ownership — the renderer never credentials chunk transfers', () => {
	const APPROVED_URL = `${APPROVED}/api/drive/chunks/deadbeef`;

	it('no token owner configured → fetch and push rejected (fail-closed)', async () => {
		const native = fakeNative();
		const h = makeDriveHandlers(native, { importRoots: [], approvedOrigins: [APPROVED] });
		await expect(h.drive_fetch_chunk(APPROVED_URL, 'renderer-bearer', 'aa', 1)).rejects.toThrow(
			/no drive bearer is available from the main-process token owner/,
		);
		await expect(h.drive_push_chunk(APPROVED_URL, 'renderer-bearer', 'aa')).rejects.toThrow(
			/no drive bearer is available from the main-process token owner/,
		);
		expect(native.driveFetchChunk).not.toHaveBeenCalled();
		expect(native.drivePushChunk).not.toHaveBeenCalled();
	});

	it('token owner holding no token (revoked/expired) → rejected, never the renderer bearer', async () => {
		const native = fakeNative();
		const h = makeDriveHandlers(
			native,
			{ importRoots: [], approvedOrigins: [APPROVED] },
			fakeTokenOwner(null),
		);
		await expect(h.drive_fetch_chunk(APPROVED_URL, 'renderer-bearer', 'aa', 1)).rejects.toThrow(
			/no drive bearer is available/,
		);
		expect(native.driveFetchChunk).not.toHaveBeenCalled();
	});

	it('the owner token wins over the renderer-supplied argument on every call', async () => {
		const native = fakeNative();
		const owner = fakeTokenOwner('slid-owner-token');
		const h = makeDriveHandlers(native, { importRoots: [], approvedOrigins: [APPROVED] }, owner);
		await h.drive_fetch_chunk(APPROVED_URL, 'renderer-bearer', 'aa', 1);
		await h.drive_push_chunk(APPROVED_URL, 'renderer-bearer', 'aa');
		expect(owner.getBearer).toHaveBeenCalledTimes(2);
		expect(native.driveFetchChunk).toHaveBeenCalledWith('drive', APPROVED_URL, 'slid-owner-token', 'aa', 1);
		expect(native.drivePushChunk).toHaveBeenCalledWith('drive', APPROVED_URL, 'slid-owner-token', 'aa');
	});
});

describe('confinement provider — the composition root widens policy after registration', () => {
	it('consults the provider per call: origin configured late still gates correctly', async () => {
		const { root, file } = makeImportRoot();
		const native = fakeNative();
		let current = DEFAULT_DRIVE_CONFINEMENT; // registered before mirror configure
		const h = makeDriveHandlers(native, () => current, fakeTokenOwner('owner-token'));

		// Before configure: even a root-listed file is denied (no checker yet).
		await expect(h.drive_import_file(file)).rejects.toThrow(/not an importable mirrored file/);

		// drive_mirror_configure arrives: widen with the trusted wiring.
		current = {
			importRoots: [root],
			approvedOrigins: [APPROVED],
			isTrustedMirrorFile: async (p) => fs.realpathSync(p) === fs.realpathSync(file),
		};
		await expect(h.drive_import_file(file)).resolves.toEqual({ contentSha256: 'abc', size: 1, chunks: [] });
		await expect(h.drive_fetch_chunk(`${APPROVED}/x`, 'r', 'aa', 1)).resolves.toBeUndefined();
		expect(native.driveFetchChunk).toHaveBeenCalledWith('drive', `${APPROVED}/x`, 'owner-token', 'aa', 1);
	});
});
