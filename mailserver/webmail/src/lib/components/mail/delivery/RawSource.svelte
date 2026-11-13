<svelte:options runes={true} />
<script lang="ts">
	let { rawText }: { rawText: string } = $props();

	let showBody = $state(false);

	// Split into header block and body
	function findBlankLine(text: string): { idx: number; skip: number } | null {
		const crlfIdx = text.indexOf('\r\n\r\n');
		const lfIdx = text.indexOf('\n\n');
		if (crlfIdx !== -1) return { idx: crlfIdx, skip: 4 };
		if (lfIdx !== -1) return { idx: lfIdx, skip: 2 };
		return null;
	}

	const blankLine = $derived(findBlankLine(rawText));
	const headerBlock = $derived(blankLine ? rawText.slice(0, blankLine.idx) : rawText);
	const bodyBlock = $derived(blankLine ? rawText.slice(blankLine.idx + blankLine.skip) : '');
</script>

<div class="raw-source">
	<pre class="raw-source__pre">{headerBlock}</pre>

	{#if bodyBlock}
		{#if showBody}
			<pre class="raw-source__pre raw-source__pre--body">{bodyBlock}</pre>
			<button type="button" class="raw-source__toggle" onclick={() => (showBody = false)}>
				Hide body
			</button>
		{:else}
			<button type="button" class="raw-source__toggle" onclick={() => (showBody = true)}>
				Show body ({bodyBlock.length.toLocaleString()} chars)
			</button>
		{/if}
	{/if}
</div>

<style>
	.raw-source {
		display: flex;
		flex-direction: column;
		gap: var(--space-2);
		padding-block: var(--space-3);
	}

	.raw-source__pre {
		font-family: var(--font-mono);
		font-size: var(--text-2xs);
		line-height: var(--leading-relaxed);
		color: var(--text-primary);
		background: var(--surface-sunken);
		border-radius: var(--radius-sm);
		padding: var(--space-3);
		white-space: pre-wrap;
		word-break: break-all;
		margin: 0;
		overflow: auto;
		max-height: 400px;
	}

	.raw-source__pre--body {
		max-height: 300px;
	}

	.raw-source__toggle {
		all: unset;
		cursor: pointer;
		font-size: var(--text-sm);
		color: var(--text-accent);
		text-decoration: underline;
		text-underline-offset: 2px;
	}

	.raw-source__toggle:hover {
		color: var(--accent-hover);
	}

	.raw-source__toggle:focus-visible {
		box-shadow: var(--focus-ring);
		border-radius: var(--radius-sm);
	}
</style>
