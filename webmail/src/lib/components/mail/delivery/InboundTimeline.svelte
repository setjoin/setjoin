<svelte:options runes={true} />
<script lang="ts">
	import type { Hop } from '$lib/types/delivery';

	let { hops, slowestHopIndex = null }: { hops: Hop[]; slowestHopIndex?: number | null } = $props();
	let openIdx = $state<number | null>(null);
	const n = $derived(hops.length);

	function delayLabel(h: Hop): string {
		if (h.delayMs == null) return 'delay unknown';
		if (h.delayMs < 0) return `clock skew ${(h.delayMs / 1000).toFixed(0)}s`;
		if (h.delayMs >= 60000) return `${Math.round(h.delayMs / 60000)} minutes`;
		return `${(h.delayMs / 1000).toFixed(1)} seconds`;
	}

	function barClass(h: Hop): string {
		if (h.delayMs == null) return 'bar bar--unknown';
		if (h.delayMs > 120000) return 'bar bar--warn';
		return 'bar';
	}

	function barHeight(ms: number | null): string {
		if (ms == null) return '8px';
		const capped = Math.min(ms, 3_600_000);
		return `${Math.round(8 + 38 * (Math.log10(capped + 1) / Math.log10(3_600_001)))}px`;
	}

	function hostLabel(h: Hop): string {
		return h.byHost || h.fromHost || 'unknown host';
	}
</script>

<ol class="timeline" role="list">
	{#each hops as hop, i (hop.index)}
		{#if hop.isOurInfra && (i === 0 || !hops[i - 1].isOurInfra)}
			<li class="divider">
				<span class="divider__heading">Setjoin received the message here</span>
				<span class="divider__caption">Earlier hops were written by outside mail servers and can be forged.</span>
			</li>
		{/if}
		<li class="hop" class:hop--ours={hop.isOurInfra} class:hop--bottleneck={i === slowestHopIndex}>
			{#if i > 0}
				{#if hop.delayMs != null && hop.delayMs < 0}
					<div class="skew-marker" aria-hidden="true" data-testid="skew-marker"></div>
					<span class="delay">{delayLabel(hop)}</span>
				{:else}
					<div class={barClass(hop)} aria-hidden="true" style:height={barHeight(hop.delayMs)}></div>
					<span class="delay">{delayLabel(hop)}</span>
				{/if}
			{/if}
			<button
				type="button"
				class="hop__btn"
				aria-expanded={openIdx === i}
				aria-label={`Hop ${i + 1} of ${n}, ${hostLabel(hop)}, ${delayLabel(hop)}, ${hop.tlsActive ? 'TLS' : 'no TLS'}, ${hop.isOurInfra ? 'our infrastructure' : 'external'}`}
				onclick={() => (openIdx = openIdx === i ? null : i)}
			>
				<span class="hop__host">{hostLabel(hop)}</span>
				{#if hop.ip}<span class="hop__ip">{hop.ip}</span>{/if}
			</button>
			{#if openIdx === i}
				<div class="hop__detail">
					{#if hop.fromHost}<div class="hop__row"><span class="hop__label">from</span><span class="hop__val">{hop.fromHost}</span></div>{/if}
					{#if hop.byHost}<div class="hop__row"><span class="hop__label">by</span><span class="hop__val">{hop.byHost}</span></div>{/if}
					{#if hop.withProtocol}<div class="hop__row"><span class="hop__label">with</span><span class="hop__val">{hop.withProtocol}</span></div>{/if}
					{#if hop.ip}<div class="hop__row"><span class="hop__label">IP</span><span class="hop__val">{hop.ip}</span></div>{/if}
					{#if hop.rdns}<div class="hop__row"><span class="hop__label">rDNS</span><span class="hop__val">{hop.rdns}</span></div>{/if}
					{#if hop.timestamp}<div class="hop__row"><span class="hop__label">time</span><span class="hop__val">{hop.timestamp}</span></div>{/if}
				</div>
			{/if}
		</li>
	{/each}
</ol>

<style>
	.timeline {
		list-style: none;
		margin: 0;
		padding: 0;
		display: flex;
		flex-direction: column;
		gap: 0;
	}

	/* Trust divider */
	.divider {
		display: flex;
		flex-direction: column;
		gap: var(--space-1);
		padding: var(--space-2) var(--space-3);
		border-top: 2px solid var(--accent);
		border-bottom: 1px solid var(--border-default);
		margin-block: var(--space-2);
	}

	.divider__heading {
		font-size: var(--text-sm);
		font-weight: 600;
		color: var(--text-primary);
	}

	.divider__caption {
		font-size: var(--text-caption);
		color: var(--text-secondary);
	}

	/* Hop items */
	.hop {
		display: flex;
		flex-direction: column;
		gap: 0;
	}

	.hop--bottleneck .hop__btn {
		outline: 2px solid var(--warning-solid);
		outline-offset: -2px;
		border-radius: var(--radius-sm);
	}

	.hop__btn {
		all: unset;
		cursor: pointer;
		display: flex;
		align-items: center;
		gap: var(--space-2);
		padding: var(--space-2) var(--space-3);
		border-radius: var(--radius-sm);
		width: 100%;
		box-sizing: border-box;
		font-size: var(--text-sm);
		color: var(--text-primary);
	}

	.hop__btn:hover {
		background: var(--surface-hover);
	}

	.hop__btn:focus-visible {
		box-shadow: 0 0 0 2px var(--accent);
	}

	.hop__host {
		font-family: var(--font-mono);
		font-size: var(--text-caption);
		color: var(--text-primary);
		flex: 1;
		min-width: 0;
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
	}

	.hop__ip {
		font-family: var(--font-mono);
		font-size: var(--text-caption);
		color: var(--text-secondary);
		flex-shrink: 0;
	}

	.hop--ours .hop__host {
		color: var(--accent);
	}

	/* Latency bar connector */
	.bar {
		width: 2px; /* 2px connector stroke — structural constant, no token */
		min-height: 8px;
		margin-left: var(--space-4);
		background: var(--success-solid);
		border-radius: 1px;
	}

	.bar--warn {
		background: var(--warning-solid);
	}

	.bar--unknown {
		background: var(--gray-300);
		opacity: 0.5;
	}

	/* Clock-skew hatch marker — inline, no bar height */
	.skew-marker {
		width: 2px; /* 2px connector stroke — structural constant, no token */
		height: 8px;
		margin-left: var(--space-4);
		background: repeating-linear-gradient(
			45deg,
			var(--gray-300),
			var(--gray-300) 2px,
			transparent 2px,
			transparent 6px
		);
		border-radius: 1px;
	}

	.delay {
		font-size: var(--text-caption);
		color: var(--text-secondary);
		margin-left: var(--space-4);
		padding-left: var(--space-2);
	}

	/* Expanded detail panel */
	.hop__detail {
		background: var(--surface-sunken);
		border-radius: var(--radius-sm);
		margin: var(--space-1) var(--space-3) var(--space-2);
		padding: var(--space-2) var(--space-3);
		display: flex;
		flex-direction: column;
		gap: var(--space-1);
	}

	.hop__row {
		display: flex;
		gap: var(--space-2);
		font-size: var(--text-caption);
	}

	.hop__label {
		font-family: var(--font-mono);
		color: var(--text-secondary);
		flex-shrink: 0;
		width: var(--space-12);
	}

	.hop__val {
		font-family: var(--font-mono);
		color: var(--text-primary);
		word-break: break-all;
	}
</style>
