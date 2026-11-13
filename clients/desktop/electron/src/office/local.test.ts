import { describe, expect, it, vi } from 'vitest';
import { createLocalOfficeLauncher } from './local.js';

describe('local Office application routing', () => {
	it.each([
		['report.docx', 'Microsoft Word'],
		['budget.xlsx', 'Microsoft Excel'],
		['briefing.pptx', 'Microsoft PowerPoint'],
	] as const)('routes %s to its matching Microsoft macOS application', async (file, app) => {
		const launches: Array<[string, string[]]> = [];
		const launcher = createLocalOfficeLauncher(
			'darwin',
			async (pathname) => pathname === `/Applications/${app}.app`,
			async (command, args) => { launches.push([command, args]); },
		);
		await launcher.open('microsoft-office', `/mirror/${file}`);
		expect(launches).toEqual([['/usr/bin/open', ['-a', app, `/mirror/${file}`]]]);
	});

	it('routes Windows presentations to POWERPNT rather than Word', async () => {
		const run = vi.fn(async () => undefined);
		const launcher = createLocalOfficeLauncher(
			'win32',
			async (pathname) => pathname.endsWith('POWERPNT.EXE'),
			run,
		);
		await launcher.open('microsoft-office', 'C:\\mirror\\briefing.pptx');
		expect(run).toHaveBeenCalledWith(expect.stringMatching(/POWERPNT\.EXE$/), ['C:\\mirror\\briefing.pptx']);
	});

	it('does not invoke a generic application for a non-Office extension', async () => {
		const run = vi.fn(async () => undefined);
		const launcher = createLocalOfficeLauncher('linux', async () => true, run);
		await expect(launcher.open('libreoffice', '/mirror/readme.txt')).rejects.toThrow('unsupported Office file family');
		expect(run).not.toHaveBeenCalled();
	});
});
