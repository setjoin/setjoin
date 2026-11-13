/** Feature toggle helper functions used by the admin Features page. */

export type FeatureOperatorProjection = {
	key: string;
	storedEnabled?: boolean | null;
	defaultEnabled?: boolean;
	changeMode?: 'live' | 'disconnect-live-clients' | '';
	disableBehavior?: 'immediate' | 'stop-admission-drain-existing' | '';
	dependencies?: string[];
	confirmationRequired?: boolean;
};

export type FeatureOperatorWarning =
	| { kind: 'disconnect' }
	| { kind: 'drain' }
	| { kind: 'dependencies'; keys: string[] }
	| { kind: 'confirmation' };

/**
 * Strip the "feature." prefix and replace underscores with spaces
 * for a human-readable label.
 */
export function groupLabel(key: string): string {
	if (key.startsWith('feature.')) return key.slice(8).replace(/_/g, ' ');
	return key.replace(/_/g, ' ');
}

export function featureOperatorWarnings(
	target: FeatureOperatorProjection,
	desired: boolean,
	all: FeatureOperatorProjection[]
): FeatureOperatorWarning[] {
	const warnings: FeatureOperatorWarning[] = [];
	if (!desired && target.changeMode === 'disconnect-live-clients') {
		warnings.push({ kind: 'disconnect' });
	}
	if (!desired && target.disableBehavior === 'stop-admission-drain-existing') {
		warnings.push({ kind: 'drain' });
	}
	if (desired && target.dependencies?.length) {
		const byKey = new Map(all.map((feature) => [feature.key, feature]));
		const unmet = target.dependencies.filter((key) => {
			const dependency = byKey.get(key);
			return !dependency || !(dependency.storedEnabled ?? dependency.defaultEnabled ?? false);
		});
		if (unmet.length) warnings.push({ kind: 'dependencies', keys: unmet });
	}
	if (target.confirmationRequired) warnings.push({ kind: 'confirmation' });
	return warnings;
}

/**
 * Meet B1 Task 16 (CEO #10): the Features page lists every feature_toggles
 * row plain-alphabetically (the query is `ORDER BY key`), which sorts a
 * sub-toggle like `meet.guest_access` pages away from its parent
 * `feature.meet` row — the org-level guest kill switch a host needs to find
 * fast ends up buried. This re-sorts so a known sub-toggle (`meet.*`,
 * `chat.*`, `drive.*`, `approval.*`) immediately follows its parent
 * `feature.<app>` row; everything else keeps its existing relative order.
 * Unknown registry rows are stable-partitioned ahead of known rows because
 * they block enforcement and require operator review.
 */
const SUB_TOGGLE_PARENT_PREFIXES = ['meet.', 'chat.', 'drive.', 'approval.'];

function parentKeyFor(key: string): string | null {
	const prefix = SUB_TOGGLE_PARENT_PREFIXES.find((p) => key.startsWith(p));
	if (!prefix) return null;
	return `feature.${prefix.slice(0, -1)}`;
}

export function sortFeatureToggles<T extends { key: string; classification?: 'known' | 'unknown' }>(toggles: T[]): T[] {
	const byKey = new Map(toggles.map((t) => [t.key, t]));
	const placed = new Set<string>();
	const result: T[] = [];
	for (const t of toggles) {
		if (placed.has(t.key)) continue;
		const parentKey = parentKeyFor(t.key);
		// A sub-toggle whose parent isn't in this list (or already placed as
		// someone else's child — can't happen, parents are never sub-toggles
		// themselves) falls through to its normal position below.
		if (parentKey && byKey.has(parentKey) && !placed.has(parentKey)) continue;
		result.push(t);
		placed.add(t.key);
		if (!parentKey) {
			// t is (possibly) a parent — pull its known children in right after it.
			for (const other of toggles) {
				if (placed.has(other.key)) continue;
				if (parentKeyFor(other.key) === t.key) {
					result.push(other);
					placed.add(other.key);
				}
			}
		}
	}
	return [
		...result.filter((toggle) => toggle.classification === 'unknown'),
		...result.filter((toggle) => toggle.classification !== 'unknown')
	];
}
