<svelte:options runes={true} />

<script lang="ts">
	// MessageBodyCall — the `call` msg_type genre (Meet B1 Task 16, spec
	// §3.3's no-ring launch, receiver side), split out of MessageRow.svelte
	// (whole-pipeline review arch #9 — MessageRow's per-genre body renderers
	// were all inline; this is the one self-contained "call card" block).
	// Design #14: `/meet?slug=…` is the ONE canonical in-app deep-link shape.
	// Ended state: a click first resolves the slug — a BZ190 (already ended)
	// or BZ185 (404/anti-oracle) swaps this card's body to "Meeting ended" in
	// place instead of navigating into a dead join, so a 3-day-old card never
	// offers a Join that can't work. Not persisted across a reload (ponytail:
	// an ephemeral, best-effort hint — the next render re-checks on click,
	// same cost as any other stale-card read).
	import { goto } from '$app/navigation';
	import * as meetApi from '$lib/meet/api';
	import Icon from '$lib/components/Icon.svelte';
	import { t } from '$lib/i18n';
	import { effectiveCaps } from '$lib/stores/session';
	import type { StoreMessage } from '$lib/chat/store.svelte';

	let { message }: { message: StoreMessage } = $props();

	let callPayload = $derived(message.payload as { meetingId?: number; slug?: string; title?: string } | null | undefined);
	let callEnded = $state(false);
	// [UX #4, pipeline review] Join dead-ends into the Mail app when
	// feature.meet is OFF (the /meet route guard bounces to $firstEnabledApp
	// with no explanation) — same enabledApps signal MeetApp itself gates on.
	let meetEnabled = $derived($effectiveCaps.enabledApps.includes('meet'));

	async function joinCall(): Promise<void> {
		const slug = callPayload?.slug;
		if (!slug) return;
		try {
			await meetApi.resolveSlug(slug);
			await goto(`/meet?slug=${encodeURIComponent(slug)}`);
		} catch (err) {
			if (err instanceof meetApi.MeetError && (err.code === 'BZ190' || err.code === 'BZ185')) {
				callEnded = true;
				return;
			}
			await goto(`/meet?slug=${encodeURIComponent(slug)}`); // any other error — let MeetApp itself surface it
		}
	}
</script>

<div class="mrow__call" data-testid="call-card">
	<Icon name="Video" size={18} />
	{#if callEnded}
		<span class="mrow__call-title mrow__call-title--ended">{t('meet.waiting.ended')}</span>
	{:else if !meetEnabled}
		<span class="mrow__call-title">{message.body}</span>
		<span class="mrow__call-title mrow__call-title--ended">{t('chat.call.unavailable')}</span>
	{:else}
		<span class="mrow__call-title">{message.body}</span>
		<button type="button" class="mrow__btn" onclick={joinCall}>{t('meet.app.join')}</button>
	{/if}
</div>

<style>
	.mrow__call {
		flex-basis: 100%;
		display: flex;
		align-items: center;
		gap: var(--space-2);
		padding: var(--space-2);
		border: 1px solid var(--border-default);
		border-radius: var(--radius-md);
	}
	.mrow__call-title {
		flex: 1;
		min-width: 0;
		font-size: var(--text-sm);
		font-weight: 600;
		color: var(--text-primary);
	}
	.mrow__call-title--ended {
		font-weight: 400;
		font-style: italic;
		color: var(--text-caption);
	}
	.mrow__btn {
		display: inline-flex;
		align-items: center;
		gap: 4px;
		min-height: 44px;
		justify-content: center;
		border: 1px solid var(--border-default);
		background: transparent;
		border-radius: var(--radius-sm);
		color: var(--text-secondary);
		cursor: pointer;
		font-size: var(--text-xs);
		padding: 0 var(--space-2);
	}
	.mrow__btn:hover {
		background: var(--surface-hover);
	}
</style>
