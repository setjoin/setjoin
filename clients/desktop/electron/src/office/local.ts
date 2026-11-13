import { constants as fsConstants } from 'node:fs';
import * as fsp from 'node:fs/promises';
import * as path from 'node:path';
import { spawn } from 'node:child_process';

export type LocalOfficeAppId = 'microsoft-office' | 'wps-office' | 'libreoffice' | 'collabora-office';

export interface LocalOfficeApp {
	id: LocalOfficeAppId;
	label: string;
}

interface Candidate {
	id: LocalOfficeAppId;
	label: string;
	executables: Partial<Record<OfficeFamily | 'all', string[]>>;
	macApps?: Partial<Record<OfficeFamily | 'all', string>>;
}

type OfficeFamily = 'word' | 'sheet' | 'presentation';

const MICROSOFT_ROOTS = [
	'C:\\Program Files\\Microsoft Office\\root\\Office16',
	'C:\\Program Files (x86)\\Microsoft Office\\root\\Office16',
];

const CANDIDATES: Candidate[] = [
	{
		id: 'microsoft-office', label: 'Microsoft Office',
		macApps: { word: 'Microsoft Word', sheet: 'Microsoft Excel', presentation: 'Microsoft PowerPoint' },
		executables: {
			word: MICROSOFT_ROOTS.map((root) => path.win32.join(root, 'WINWORD.EXE')),
			sheet: MICROSOFT_ROOTS.map((root) => path.win32.join(root, 'EXCEL.EXE')),
			presentation: MICROSOFT_ROOTS.map((root) => path.win32.join(root, 'POWERPNT.EXE')),
		},
	},
	{
		id: 'wps-office', label: 'WPS Office', macApps: { all: 'wpsoffice' },
		executables: { all: [
			'C:\\Program Files\\Kingsoft\\WPS Office\\ksolaunch.exe',
			'C:\\Program Files (x86)\\Kingsoft\\WPS Office\\ksolaunch.exe',
			'/usr/bin/wps', '/usr/bin/et', '/usr/bin/wpp',
		] },
	},
	{
		id: 'libreoffice', label: 'LibreOffice', macApps: { all: 'LibreOffice' },
		executables: { all: ['/usr/bin/libreoffice', '/usr/local/bin/libreoffice'] },
	},
	{
		id: 'collabora-office', label: 'Collabora Office', macApps: { all: 'Collabora Office' },
		executables: { all: ['/usr/bin/collaboraoffice', '/usr/local/bin/collaboraoffice'] },
	},
];

export interface LocalOfficeLauncher {
	available(): Promise<LocalOfficeApp[]>;
	open(appId: LocalOfficeAppId, filePath: string): Promise<void>;
}

async function executable(pathname: string): Promise<boolean> {
	try {
		await fsp.access(pathname, fsConstants.X_OK);
		return true;
	} catch {
		return false;
	}
}

function launch(command: string, args: string[]): Promise<void> {
	return new Promise((resolve, reject) => {
		const child = spawn(command, args, { detached: true, shell: false, stdio: 'ignore' });
		child.once('error', reject);
		child.once('spawn', () => {
			child.unref();
			resolve();
		});
	});
}

function officeFamily(filePath: string): OfficeFamily | null {
	const extension = path.extname(filePath).toLowerCase();
	if (['.doc', '.docx', '.odt', '.rtf'].includes(extension)) return 'word';
	if (['.xls', '.xlsx', '.ods', '.csv'].includes(extension)) return 'sheet';
	if (['.ppt', '.pptx', '.odp'].includes(extension)) return 'presentation';
	return null;
}

export function createLocalOfficeLauncher(
	platform: NodeJS.Platform = process.platform,
	canExecute: (pathname: string) => Promise<boolean> = executable,
	run: (command: string, args: string[]) => Promise<void> = launch,
): LocalOfficeLauncher {
	async function target(candidate: Candidate, family?: OfficeFamily): Promise<{ command: string; prefix: string[] } | null> {
		if (platform === 'darwin') {
			const app = (family && candidate.macApps?.[family]) ?? candidate.macApps?.all;
			if (app && await canExecute(path.join('/Applications', `${app}.app`))) {
				return { command: '/usr/bin/open', prefix: ['-a', app] };
			}
			if (!family && candidate.macApps) {
				for (const candidateApp of Object.values(candidate.macApps)) {
					if (candidateApp && await canExecute(path.join('/Applications', `${candidateApp}.app`))) {
						return { command: '/usr/bin/open', prefix: ['-a', candidateApp] };
					}
				}
			}
		}
		const executableGroups = family
			? [candidate.executables[family] ?? [], candidate.executables.all ?? []]
			: Object.values(candidate.executables);
		for (const group of executableGroups) {
			for (const pathname of group) {
				if (await canExecute(pathname)) return { command: pathname, prefix: [] };
			}
		}
		return null;
	}

	return {
		async available() {
			const found: LocalOfficeApp[] = [];
			for (const candidate of CANDIDATES) {
				if (await target(candidate)) found.push({ id: candidate.id, label: candidate.label });
			}
			return found;
		},
		async open(appId, filePath) {
			const candidate = CANDIDATES.find((item) => item.id === appId);
			if (!candidate) throw new Error('office-local: unsupported application');
			const family = officeFamily(filePath);
			if (!family) throw new Error('office-local: unsupported Office file family');
			const resolved = await target(candidate, family);
			if (!resolved) throw new Error('office-local: application is not installed');
			await run(resolved.command, [...resolved.prefix, filePath]);
		},
	};
}
