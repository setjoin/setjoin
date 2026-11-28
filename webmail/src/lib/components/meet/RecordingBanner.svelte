<svelte:options runes={true} />

<script lang="ts">
	// Meet B2 §8.1: the consent banner is SERVER state (recording_state push +
	// the join/read envelope), never local state, and has no dismiss
	// affordance by design — non-skippable is the inherited requirement (a).
	// D-5: the live-region CONTAINER is always mounted and the content
	// toggles inside it — a region inserted into the DOM pre-populated is
	// not announced by screen readers.
	import Icon from '$lib/components/Icon.svelte';
	import { t } from '$lib/i18n';

	let { active, stopping = false }: { active: boolean; stopping?: boolean } = $props();
</script>

<div class="recording-banner" class:recording-banner--active={active} role="status" aria-live="polite">
	{#if active}
		<Icon name="Video" size={14} aria-hidden="true" />
		<span>{stopping ? t('meet.recording.stopping') : t('meet.recording.banner')}</span>
	{/if}
</div>

<style>
	.recording-banner {
		display: flex;
		align-items: center;
		gap: var(--space-2);
		font-size: var(--text-sm);
		justify-content: center;
	}
	.recording-banner--active {
		padding: var(--space-1) var(--space-3);
		background: var(--danger-bg);
		color: var(--danger-fg);
	}
</style>
