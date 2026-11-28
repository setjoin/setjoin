import { describe, it, expect } from 'vitest';
import { featureOperatorWarnings, groupLabel, sortFeatureToggles } from './featureHelpers';

describe('groupLabel', () => {
	it('strips feature. prefix and replaces underscores with spaces', () => {
		expect(groupLabel('feature.imap')).toBe('imap');
		expect(groupLabel('feature.smtp_inbound')).toBe('smtp inbound');
		expect(groupLabel('feature.spam_scoring')).toBe('spam scoring');
		expect(groupLabel('feature.dmarc_reporting')).toBe('dmarc reporting');
	});

	it('returns key as-is when it does not start with "feature."', () => {
		expect(groupLabel('some_other_key')).toBe('some other key');
		expect(groupLabel('plain')).toBe('plain');
	});
});

describe('featureOperatorWarnings', () => {
	it('derives disconnect, drain, confirmation, and unmet dependencies only from API metadata', () => {
		const target = {
			key: 'feature.meet_recording',
			changeMode: 'disconnect-live-clients' as const,
			disableBehavior: 'stop-admission-drain-existing' as const,
			dependencies: ['feature.meet'],
			confirmationRequired: true
		};
		expect(featureOperatorWarnings(target, false, [])).toEqual([
			{ kind: 'disconnect' },
			{ kind: 'drain' },
			{ kind: 'confirmation' }
		]);
		expect(featureOperatorWarnings(target, true, [])).toEqual([
			{ kind: 'dependencies', keys: ['feature.meet'] },
			{ kind: 'confirmation' }
		]);
	});

	it('emits no warning for unknown or known rows without metadata', () => {
		expect(featureOperatorWarnings({ key: 'legacy.unknown' }, false, [])).toEqual([]);
		expect(featureOperatorWarnings({ key: 'feature.spf', dependencies: [] }, true, [])).toEqual([]);
	});

	it('does not warn when every dependency is effectively enabled', () => {
		expect(featureOperatorWarnings(
			{ key: 'feature.meet_recording', dependencies: ['feature.meet'] },
			true,
			[{ key: 'feature.meet', storedEnabled: true, defaultEnabled: false }]
		)).toEqual([]);
	});
});

describe('sortFeatureToggles', () => {
	function toggle(key: string) {
		return { key, enabled: false, description: '' };
	}

	it('places a known sub-toggle immediately after its parent feature.<app> row', () => {
		// Alphabetical ORDER BY key would put 'feature.imap' before both,
		// scattering meet.guest_access two pages away from feature.meet.
		const raw = [toggle('feature.imap'), toggle('feature.meet'), toggle('meet.guest_access'), toggle('feature.spf')];
		const sorted = sortFeatureToggles(raw).map((t) => t.key);
		const meetIdx = sorted.indexOf('feature.meet');
		expect(sorted[meetIdx + 1]).toBe('meet.guest_access');
	});

	it('leaves toggles with no known sub-toggle relationship in their original relative order', () => {
		const raw = [toggle('feature.spf'), toggle('feature.dkim'), toggle('feature.imap')];
		expect(sortFeatureToggles(raw).map((t) => t.key)).toEqual(['feature.spf', 'feature.dkim', 'feature.imap']);
	});

	it('leaves a sub-toggle whose parent is absent from the list in its normal position (no crash, no drop)', () => {
		const raw = [toggle('approval.rbac'), toggle('feature.imap')];
		expect(sortFeatureToggles(raw).map((t) => t.key)).toEqual(['approval.rbac', 'feature.imap']);
	});

	it('groups multiple sub-toggles under the same parent', () => {
		const raw = [toggle('chat.channel_creation'), toggle('feature.chat'), toggle('chat.push'), toggle('feature.drive')];
		const sorted = sortFeatureToggles(raw).map((t) => t.key);
		expect(sorted).toEqual(['feature.chat', 'chat.channel_creation', 'chat.push', 'feature.drive']);
	});

	it('stable-partitions unknown registry rows before known parent groups', () => {
		const raw = [
			{ ...toggle('feature.chat'), classification: 'known' as const },
			{ ...toggle('legacy.second'), classification: 'unknown' as const },
			{ ...toggle('chat.push'), classification: 'known' as const },
			{ ...toggle('legacy.first'), classification: 'unknown' as const }
		];
		expect(sortFeatureToggles(raw).map((t) => t.key)).toEqual([
			'legacy.second',
			'legacy.first',
			'feature.chat',
			'chat.push'
		]);
	});
});
