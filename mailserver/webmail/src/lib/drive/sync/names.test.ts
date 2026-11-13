// @vitest-environment node
import { describe, it, expect } from 'vitest';
import { branchSiblingName, conflictSiblingName, dedupeName, splitExt, isIgnoredName } from './names.js';

describe('G4 naming', () => {
	it('splits extension conservatively', () => {
		expect(splitExt('a.txt')).toEqual(['a', '.txt']);
		expect(splitExt('archive.tar.gz')).toEqual(['archive.tar', '.gz']);
		expect(splitExt('README')).toEqual(['README', '']);
		expect(splitExt('.gitignore')).toEqual(['.gitignore', '']); // leading-dot = no ext
	});
	it('builds the locked conflict-sibling pattern', () => {
		expect(conflictSiblingName('Report.xlsx', 'bobs-laptop', '2026-07-09')).toBe(
			'Report (conflict bobs-laptop 2026-07-09).xlsx'
		);
	});
	it('dedupes with " -2"/" -3" BEFORE the extension, case-insensitively', () => {
		const taken = new Set(['report.xlsx', 'report -2.xlsx']); // lowercase = CI store
		const exists = (n: string) => taken.has(n.toLowerCase());
		expect(dedupeName('Report.xlsx', exists)).toBe('Report -3.xlsx');
		expect(dedupeName('Fresh.xlsx', exists)).toBe('Fresh.xlsx');
	});
	it('dedupes the conflict name itself on repeat conflicts', () => {
		const exists = (n: string) => n.toLowerCase() === 'r (conflict d 2026-07-09).txt'.toLowerCase();
		expect(dedupeName(conflictSiblingName('R.txt', 'd', '2026-07-09'), exists)).toBe(
			'R (conflict d 2026-07-09) -2.txt'
		);
	});
	it('builds the P4 branch-sibling pattern, G4-deduped case-insensitively (Task 17)', () => {
		expect(branchSiblingName('Report.xlsx', 'budget-redo')).toBe('Report (branch budget-redo).xlsx');
		const taken = new Set(['report (branch budget-redo).xlsx']);
		const exists = (n: string) => taken.has(n.toLowerCase());
		expect(dedupeName(branchSiblingName('Report.xlsx', 'budget-redo'), exists)).toBe(
			'Report (branch budget-redo) -2.xlsx'
		);
	});
	it('matches the LOCKED ignore set case-insensitively', () => {
		for (const n of ['x.tmp', 'X.TMP', '~$budget.docx', '.DS_Store', '.setjoin-tmp-a1b2', '.SETJOIN-TMP-Z']) {
			expect(isIgnoredName(n)).toBe(true);
		}
		for (const n of ['tmp.doc', 'a~$b.docx', 'DS_Store', 'setjoin-tmp']) {
			expect(isIgnoredName(n)).toBe(false);
		}
	});
});
