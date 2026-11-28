<svelte:options runes={true} />
<script lang="ts">
	import Input from '$lib/components/ui/Input.svelte';
	import Table from '$lib/components/ui/Table.svelte';
	import type { TableColumn } from '$lib/components/ui/table';

	let { rawText }: { rawText: string } = $props();

	interface HeaderRow extends Record<string, unknown> {
		name: string;
		value: string;
	}

	const columns: TableColumn[] = [
		{ key: 'name', label: 'Header', mono: true, width: '200px' },
		{ key: 'value', label: 'Value', mono: true },
	];

	function parseHeaders(text: string): HeaderRow[] {
		// Extract the header block (before the first blank line)
		const blankLineIdx = text.indexOf('\r\n\r\n');
		const blankLineIdx2 = text.indexOf('\n\n');
		let headerBlock: string;
		if (blankLineIdx !== -1) {
			headerBlock = text.slice(0, blankLineIdx);
		} else if (blankLineIdx2 !== -1) {
			headerBlock = text.slice(0, blankLineIdx2);
		} else {
			headerBlock = text;
		}

		// Unfold header lines (CRLF/LF followed by whitespace = continuation)
		const unfolded = headerBlock.replace(/\r?\n([ \t])/g, ' ');

		const rows: HeaderRow[] = [];
		for (const line of unfolded.split(/\r?\n/)) {
			const colonIdx = line.indexOf(':');
			if (colonIdx > 0) {
				rows.push({
					name: line.slice(0, colonIdx).trim(),
					value: line.slice(colonIdx + 1).trim(),
				});
			}
		}
		return rows;
	}

	let filter = $state('');

	const allHeaders = $derived(parseHeaders(rawText));
	const visibleHeaders = $derived(
		filter.trim() === ''
			? allHeaders
			: allHeaders.filter((h) => {
					const q = filter.toLowerCase();
					return h.name.toLowerCase().includes(q) || h.value.toLowerCase().includes(q);
				})
	);
</script>

<div class="header-explorer">
	<div class="header-explorer__filter">
		<Input
			placeholder="Filter headers…"
			bind:value={filter}
			aria-label="Filter headers"
		/>
	</div>
	{#if visibleHeaders.length > 0}
		<Table columns={columns} rows={visibleHeaders} />
	{:else}
		<p class="header-explorer__empty">No headers match your filter.</p>
	{/if}
</div>

<style>
	.header-explorer {
		display: flex;
		flex-direction: column;
		gap: var(--space-3);
		padding-block: var(--space-3);
	}

	.header-explorer__filter {
		max-width: 360px;
	}

	.header-explorer__empty {
		font-size: var(--text-sm);
		color: var(--text-secondary);
		margin: 0;
	}
</style>
