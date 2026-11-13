import { describe, it, expect } from 'vitest';
import { groupByCategory, diffPerms } from './permissionMeta';

describe('permissionMeta', () => {
	it('groups catalog entries by category', () => {
		const cat = [
			{ key: 'users.read', category: 'Users', description: '', isSensitive: false },
			{ key: 'users.delete', category: 'Users', description: '', isSensitive: true },
			{ key: 'audit.read', category: 'Audit', description: '', isSensitive: false },
		];
		const g = groupByCategory(cat);
		expect(Object.keys(g).sort()).toEqual(['Audit', 'Users']);
		expect(g['Users'].map((p) => p.key)).toEqual(['users.read', 'users.delete']);
	});

	it('diffs two permission sets', () => {
		expect(diffPerms(['a', 'b'], ['b', 'c'])).toEqual({ added: ['c'], removed: ['a'] });
	});
});
