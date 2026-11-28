<svelte:options runes={true} />

<script lang="ts">
	import type { Mailbox } from '$lib/types/jmap';
	import type { SearchIntent, SearchIntentFilter } from '$lib/search/searchIntent';
	import { compileSearchIntent, intentFromTypedSearch } from '$lib/search/searchIntent';
	import { t } from '$lib/i18n';

	let {
		intent,
		mailboxes,
		onEdit,
		onApply,
		zeroResults = false,
	}: {
		intent: SearchIntent;
		mailboxes: Mailbox[];
		onEdit: (raw: string) => void;
		onApply: (raw: string) => void;
		zeroResults?: boolean;
	} = $props();

	let editing = $state<number | null>(null);
	let editValue = $state('');
	let error = $state('');
	let canonical = $derived(compileSearchIntent(intent, mailboxes));

	function oneFilterRaw(filter: SearchIntentFilter): string {
		return compileSearchIntent({ version: 1, filters: [filter], source: 'typed', confidence: 'exact' }, mailboxes);
	}

	function startEdit(index: number) {
		editing = index;
		editValue = oneFilterRaw(intent.filters[index]);
		error = '';
	}

	function saveEdit(index: number) {
		try {
			const replacement = intentFromTypedSearch(editValue, mailboxes).filters;
			if (replacement.length !== 1) throw new Error('one filter required');
			const filters = [...intent.filters];
			filters.splice(index, 1, replacement[0]);
			onEdit(compileSearchIntent({ ...intent, filters, source: 'typed', confidence: 'exact' }, mailboxes));
			editing = null;
			error = '';
		} catch {
			error = t('inbox.search_intent.edit_filter');
		}
	}

	function remove(index: number) {
		const filters = intent.filters.filter((_, candidate) => candidate !== index);
		onEdit(compileSearchIntent({ ...intent, filters, source: 'typed', confidence: 'exact' }, mailboxes));
	}
</script>

{#if intent.filters.length > 0}
	<div class="sj-search-intent" role="region" aria-label={t('inbox.search_intent.preview')}>
		<div class="sj-search-intent__chips">
			{#each intent.filters as filter, index (index)}
				{#if editing === index}
					<input
						class="sj-search-intent__editor"
						aria-label={t('inbox.search_intent.edit_filter')}
						bind:value={editValue}
						onkeydown={(event) => {
							if (event.key === 'Enter') saveEdit(index);
							if (event.key === 'Escape') { editing = null; error = ''; }
						}}
					/>
					<button type="button" class="sj-search-intent__small" onclick={() => saveEdit(index)}>{t('common.save')}</button>
					<button type="button" class="sj-search-intent__small" onclick={() => { editing = null; error = ''; }}>{t('common.cancel')}</button>
				{:else}
					<span class="sj-search-intent__chip">
						<button type="button" class="sj-search-intent__label" onclick={() => startEdit(index)} aria-label={`${t('inbox.search_intent.edit_filter')}: ${oneFilterRaw(filter)}`}>
							{oneFilterRaw(filter)}
						</button>
						<button type="button" class="sj-search-intent__remove" onclick={() => remove(index)} aria-label={`${t('inbox.search_intent.remove_filter')}: ${oneFilterRaw(filter)}`}>×</button>
					</span>
				{/if}
			{/each}
		</div>
		<div class="sj-search-intent__actions">
			<button type="button" class="sj-search-intent__text" onclick={() => onEdit(canonical)}>{t('inbox.search_intent.edit_text')}</button>
			<button type="button" class="sj-search-intent__apply" onclick={() => onApply(canonical)}>{t('inbox.search_intent.apply')}</button>
		</div>
		{#if error}<span class="sj-search-intent__error" role="alert">{error}</span>{/if}
		{#if zeroResults}<span class="sj-search-intent__empty" role="status">{t('inbox.search_intent.zero_results')}</span>{/if}
	</div>
{/if}

<style>
	.sj-search-intent { display:flex; align-items:center; gap:var(--space-2); min-height:40px; padding:var(--space-1) var(--space-3); border-bottom:1px solid var(--border-default); background:var(--surface-sunken); }
	.sj-search-intent__chips { display:flex; flex:1; flex-wrap:wrap; gap:var(--space-1); min-width:0; }
	.sj-search-intent__chip { display:inline-flex; align-items:center; border:1px solid var(--border-default); border-radius:var(--radius-full); background:var(--surface-default); overflow:hidden; }
	.sj-search-intent button { font:inherit; color:inherit; }
	.sj-search-intent__label,.sj-search-intent__remove,.sj-search-intent__small,.sj-search-intent__text,.sj-search-intent__apply { border:0; background:transparent; cursor:pointer; min-height:32px; }
	.sj-search-intent__label { padding:0 var(--space-2); font-family:var(--font-mono); font-size:var(--text-xs); }
	.sj-search-intent__remove { width:32px; color:var(--text-secondary); border-left:1px solid var(--border-default); }
	.sj-search-intent__editor { min-height:32px; min-width:180px; border:1px solid var(--border-focus); border-radius:var(--radius-sm); background:var(--surface-default); color:var(--text-primary); padding:0 var(--space-2); }
	.sj-search-intent__actions { display:flex; gap:var(--space-1); margin-left:auto; white-space:nowrap; }
	.sj-search-intent__text,.sj-search-intent__small { padding:0 var(--space-2); color:var(--text-secondary); }
	.sj-search-intent__apply { padding:0 var(--space-3); border-radius:var(--radius-sm); background:var(--accent); color:var(--text-inverse); }
	.sj-search-intent__error { color:var(--text-danger); font-size:var(--text-xs); }
	.sj-search-intent__empty { color:var(--text-caption); font-size:var(--text-xs); }
	button:focus-visible,input:focus-visible { outline:2px solid var(--border-focus); outline-offset:2px; }

	@media (max-width:767px) { .sj-search-intent { align-items:flex-start; flex-direction:column; } .sj-search-intent__actions { width:100%; justify-content:flex-end; } }
</style>
