// channels.svelte.ts — pure display helpers shared by the channel table and
// the per-channel sheet (Chat A4a Task 12, verify C3): chat_channels.name is
// NULL for dm/group_dm, so without a participant-derived label a DM row is
// unidentifiable to the operator who must hold/override/classify it.
//
// Also the shared channel-identity cache (A4b design-review finding I1):
// CaseHoldsPanel and EDiscoveryPanel both render raw #id everywhere a
// channel or a user (custodian/author/editor) shows up, which is useless to
// an operator staring at a hold table or a search-hit list. Chat has no
// user-directory lookup route (never invent one here — same posture as
// Drive's MembersSheet numeric-id gap), so identity is resolved best-effort
// from whatever adminListChatChannels() responses either panel has already
// seen (its own mount-time prefetch, its own channel search, or the other
// panel's fetch — `byId` is a single module-scoped cache, not per-panel). An
// id never seen in a channel's participant projection still falls back to a
// bare #id.
import { t } from '$lib/i18n';
import type { ChatChannelRow, ChatChannelParticipant } from '$lib/admin/client';

export function channelDisplayName(c: Pick<ChatChannelRow, 'name' | 'participants'>): string {
	if (c.name) return c.name;
	if (c.participants.length > 0) {
		return c.participants.map((p) => p.displayName || p.email).join(' ↔ ');
	}
	return '';
}

/**
 * The retention-days label is TWO different labels by classification (Global
 * Constraints, mandatory copy): a 'regular' channel's number is a DESTROY
 * CEILING, a 'gxp' channel's is a WORM KEEP-FLOOR. Never "retain for" / a
 * bare day count for either — a mistranslated label here destroys customer
 * data or promises immutability that isn't there.
 */
export function retentionLabel(c: Pick<ChatChannelRow, 'classification' | 'effectiveRetentionDays'>): string {
	if (c.effectiveRetentionDays == null) return t('admin.chatCompliance.retention.none');
	const key =
		c.classification === 'gxp'
			? 'admin.chatCompliance.retention.wormFloor'
			: 'admin.chatCompliance.retention.destroyCeiling';
	return t(key, { n: String(c.effectiveRetentionDays) });
}

class ChannelCache {
	byId = $state(new Map<number, ChatChannelRow>());

	remember(rows: ChatChannelRow[]) {
		for (const c of rows) this.byId.set(c.id, c);
		this.byId = new Map(this.byId);
	}

	/** Test-only: drop everything so one test's fetched channels don't leak
	 *  identity into the next (this cache is a module singleton). */
	reset() {
		this.byId = new Map();
	}

	/** "Name (#id)" once the channel has been seen; a bare "#id" otherwise. */
	label(id: number): string {
		const c = this.byId.get(id);
		if (!c) return `#${id}`;
		const name = channelDisplayName(c);
		return name ? `${name} (#${id})` : `#${id}`;
	}

	resolveParticipant(userId: number): ChatChannelParticipant | undefined {
		for (const c of this.byId.values()) {
			const p = c.participants.find((p) => p.userId === userId);
			if (p) return p;
		}
		return undefined;
	}

	/** A resolved participant's "Name (#id)", or a bare "#id" fallback when no
	 *  seen channel has that participant. The id suffix stays even when the
	 *  name resolves — two same-named custodians must stay distinguishable in
	 *  a legal holds table. */
	participantLabel(userId: number): string {
		const p = this.resolveParticipant(userId);
		const name = p ? p.displayName || p.email : '';
		return name ? `${name} (#${userId})` : `#${userId}`;
	}
}

export const channelCache = new ChannelCache();
