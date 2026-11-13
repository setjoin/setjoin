<svelte:options runes={true} />

<script lang="ts">
	// PresentationRail — MEET plan M3. The presenter-only side rail:
	// thumbnails (jump-to-page) and speaker notes. Presenter-gated by the
	// CALLER (MeetApp renders it only for the current presenter) AND by the
	// store (loadNotes refuses without the gate) — notes never render for
	// attendees and never enter any shared payload. Desktop docks it beside
	// the canvas; narrow viewports collapse it to an overlay sheet (the
	// responsive contract: tablet bottom sheet, notes remain presenter-only).
	import { Button, IconButton } from '$lib/components/ui';
	import Icon from '$lib/components/Icon.svelte';
	import { t } from '$lib/i18n';
	import type { PresentationStore } from '$lib/meet/presentationStore.svelte';

	let { presentation }: { presentation: PresentationStore } = $props();

	function thumbClass(active: boolean): string {
		return active ? 'pres-rail__thumb pres-rail__thumb--active' : 'pres-rail__thumb';
	}
</script>

<aside class="pres-rail" aria-label={t('meet.presentation.rail.label')} data-testid="presentation-rail">
	<div class="pres-rail__tabs" role="tablist" aria-label={t('meet.presentation.rail.label')}>
		<button
			type="button"
			role="tab"
			aria-selected={presentation.railMode === 'thumbnails'}
			class="pres-rail__tab"
			onclick={() => presentation.openRail('thumbnails')}
		>
			{t('meet.presentation.rail.thumbnails')}
		</button>
		<button
			type="button"
			role="tab"
			aria-selected={presentation.railMode === 'notes'}
			class="pres-rail__tab"
			onclick={() => presentation.openRail('notes')}
		>
			{t('meet.presentation.rail.notes')}
		</button>
		<IconButton label={t('meet.presentation.rail.close')} onclick={() => presentation.closeRail()}>
			<Icon name="X" size={14} />
		</IconButton>
	</div>

	{#if presentation.railMode === 'thumbnails'}
		<div class="pres-rail__body pres-rail__thumbs" data-testid="rail-thumbnails">
			{#each presentation.manifest?.pages ?? [] as page (page.id)}
				<button
					type="button"
					class={thumbClass(page.index === presentation.pageIndex)}
					aria-label={t('meet.presentation.stage.pageOf', {
						n: String(page.index + 1),
						total: String(presentation.pageCount),
					})}
					aria-current={page.index === presentation.pageIndex}
					onclick={() => void presentation.changePage(page.index)}
				>
					<img src={page.thumbnail.path} alt="" loading="lazy" />
					<span class="pres-rail__thumb-n">{page.index + 1}</span>
				</button>
			{/each}
		</div>
	{:else}
		<div class="pres-rail__body pres-rail__notes" data-testid="rail-notes">
			<p class="pres-rail__notes-hint">{t('meet.presentation.rail.notesPrivate')}</p>
			{#if presentation.notesState === 'loading'}
				<p class="pres-rail__notes-status">{t('meet.presentation.rail.notesLoading')}</p>
			{:else if presentation.notesState === 'unavailable' || presentation.notesText === null}
				<p class="pres-rail__notes-status">{t('meet.presentation.rail.notesUnavailable')}</p>
			{:else}
				<div class="pres-rail__notes-text">{presentation.notesText}</div>
			{/if}
		</div>
	{/if}

	{#if presentation.railMode === 'notes' && presentation.notesState === 'ready'}
		<div class="pres-rail__notes-actions">
			<Button variant="ghost" size="sm" onclick={() => presentation.closeRail()}>{t('common.close')}</Button>
		</div>
	{/if}
</aside>

<style>
	.pres-rail {
		display: flex;
		flex-direction: column;
		width: 220px;
		flex: none;
		border-left: 1px solid var(--border-subtle);
		background: var(--surface-card);
		min-height: 0;
	}
	.pres-rail__tabs {
		display: flex;
		align-items: center;
		border-bottom: 1px solid var(--border-subtle);
		flex: none;
	}
	.pres-rail__tab {
		flex: 1;
		display: flex;
		align-items: center;
		justify-content: center;
		min-height: 44px;
		border: none;
		background: none;
		color: var(--text-secondary);
		font-size: var(--text-xs);
		cursor: pointer;
	}
	.pres-rail__tab[aria-selected='true'] {
		color: var(--accent);
		background: var(--surface-selected);
	}
	.pres-rail__body {
		flex: 1;
		min-height: 0;
		overflow-y: auto;
		padding: var(--space-2);
	}
	.pres-rail__thumbs {
		display: grid;
		grid-template-columns: repeat(2, 1fr);
		gap: var(--space-2);
		align-content: start;
	}
	.pres-rail__thumb {
		position: relative;
		display: flex;
		flex-direction: column;
		border: 1px solid var(--border-subtle);
		border-radius: var(--radius-sm);
		background: var(--surface-base);
		padding: 2px;
		cursor: pointer;
		min-height: 44px;
	}
	.pres-rail__thumb--active {
		border-color: var(--accent);
		border-width: 2px;
	}
	.pres-rail__thumb img {
		width: 100%;
		height: auto;
		display: block;
		border-radius: 2px;
	}
	.pres-rail__thumb-n {
		position: absolute;
		bottom: 2px;
		right: 2px;
		background: var(--surface-raised);
		color: var(--text-secondary);
		font-size: 9px;
		font-family: var(--font-mono);
		border-radius: var(--radius-full);
		padding: 0 4px;
	}
	.pres-rail__notes {
		display: flex;
		flex-direction: column;
		gap: var(--space-2);
	}
	.pres-rail__notes-hint {
		margin: 0;
		font-size: var(--text-xs);
		color: var(--text-caption);
	}
	.pres-rail__notes-status {
		margin: 0;
		font-size: var(--text-sm);
		color: var(--text-secondary);
	}
	.pres-rail__notes-text {
		white-space: pre-wrap;
		font-size: var(--text-sm);
		color: var(--text-primary);
	}
	.pres-rail__notes-actions {
		flex: none;
		display: flex;
		justify-content: flex-end;
		border-top: 1px solid var(--border-subtle);
	}
	/* Responsive contract: narrow viewports collapse the rail to an overlay
	   bottom sheet; notes remain presenter-only in every layout. */
	@media (max-width: 1023px) {
		.pres-rail {
			position: absolute;
			bottom: 0;
			left: 0;
			right: 0;
			width: auto;
			max-height: 45%;
			border-left: none;
			border-top: 1px solid var(--border-subtle);
			z-index: 15;
		}
		.pres-rail__thumbs {
			grid-template-columns: repeat(4, 1fr);
		}
	}
</style>
