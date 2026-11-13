import { describe, it, expect, vi } from 'vitest';
import { externalUrlAllowed, mimeForFile, makeOsHandlers, type PickedFile } from './os';
import * as fs from 'node:fs/promises';
import * as os from 'node:os';
import * as path from 'node:path';

describe('external_url_allowed (ported from bridge.rs)', () => {
	it('allows web + mailto, case-insensitive', () => {
		expect(externalUrlAllowed('https://example.com/x?y=1')).toBe(true);
		expect(externalUrlAllowed('http://example.com')).toBe(true);
		expect(externalUrlAllowed('mailto:a@b.com?subject=hi')).toBe(true);
		expect(externalUrlAllowed('HTTPS://EXAMPLE.COM')).toBe(true);
	});
	it('rejects dangerous or schemeless URLs', () => {
		expect(externalUrlAllowed('file:///etc/passwd')).toBe(false);
		expect(externalUrlAllowed('smb://host/share')).toBe(false);
		expect(externalUrlAllowed('javascript:alert(1)')).toBe(false);
		expect(externalUrlAllowed('ms-excel:ofe|u|https://x')).toBe(false);
		expect(externalUrlAllowed('/no/scheme')).toBe(false);
		expect(externalUrlAllowed('')).toBe(false);
	});
});

describe('os handlers', () => {
	it('open_external gates on the scheme allowlist', async () => {
		const openExternalUrl = vi.fn(async () => {});
		const h = makeOsHandlers({
			showNotification: () => {},
			pickFilePath: async () => null,
			openExternalUrl,
		});
		await h.open_external('https://ok.example');
		expect(openExternalUrl).toHaveBeenCalledWith('https://ok.example');
		await expect(h.open_external('file:///etc/passwd')).rejects.toThrow(/not allowed/);
		expect(openExternalUrl).toHaveBeenCalledTimes(1);
	});

	it('notify forwards title/body to the injected effect', () => {
		const showNotification = vi.fn();
		const h = makeOsHandlers({ showNotification, pickFilePath: async () => null, openExternalUrl: async () => {} });
		h.notify('Title', 'Body');
		expect(showNotification).toHaveBeenCalledWith('Title', 'Body');
		h.notify('Title', undefined);
		expect(showNotification).toHaveBeenCalledWith('Title', '');
	});

	it('pick_file returns {name,type,dataBase64} the renderer reconstructs; null on cancel', async () => {
		const tmp = path.join(os.tmpdir(), `sj-pick-${Date.now()}.txt`);
		await fs.writeFile(tmp, 'hello');
		const h = makeOsHandlers({
			showNotification: () => {},
			pickFilePath: async () => tmp,
			openExternalUrl: async () => {},
		});
		const res = (await h.pick_file()) as PickedFile;
		expect(res.name).toBe(path.basename(tmp));
		expect(res.type).toBe('text/plain');
		expect(Buffer.from(res.dataBase64, 'base64').toString()).toBe('hello');
		await fs.rm(tmp);

		const cancelH = makeOsHandlers({
			showNotification: () => {},
			pickFilePath: async () => null,
			openExternalUrl: async () => {},
		});
		expect(await cancelH.pick_file()).toBeNull();
	});

	it('mimeForFile maps common extensions', () => {
		expect(mimeForFile('a.pdf')).toBe('application/pdf');
		expect(mimeForFile('a.unknownext')).toBe('application/octet-stream');
	});
});
