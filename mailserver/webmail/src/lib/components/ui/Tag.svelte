<script lang="ts">
	import { TAG_COLORS, splitTagPath, type TagColor } from './tag';

	interface Props {
		label: string;
		color?: TagColor;
		size?: 'sm' | 'md';
		dot?: boolean;
		onclick?: () => void;
		onremove?: () => void;
	}

	let { label, color = 'gray', size = 'md', dot = true, onclick, onremove }: Props = $props();

	const segments = $derived(splitTagPath(label));
	// Runtime whitelist before the style interpolation: the type system already
	// casts `color` as TagColor, but nothing stops an untyped caller from
	// passing anything — an off-whitelist value degrades to the neutral 'gray'
	// hue instead of reaching the style attribute.
	const safeColor = $derived(
		(TAG_COLORS as readonly string[]).includes(color) ? color : 'gray'
	);
</script>

{#snippet body()}
	{#if dot}<span class="tag__dot" style="background: var(--tag-{safeColor}-dot);"></span>{/if}
	<span class="tag__text">
		{#each segments as segment, i (i)}
			{#if i > 0}<span class="tag__sep" aria-hidden="true">/</span>{/if}{segment}
		{/each}
	</span>
{/snippet}

<span
	class="tag"
	class:tag--sm={size === 'sm'}
	class:tag--clickable={onclick !== undefined}
	style="background: var(--tag-{safeColor}-bg); color: var(--tag-{safeColor}-fg);"
>
	{#if onclick}
		<button type="button" class="tag__body" {onclick}>
			{@render body()}
		</button>
	{:else}
		{@render body()}
	{/if}
	{#if onremove}
		<button type="button" class="tag__x" aria-label="Remove tag {label}" onclick={onremove}>
			<svg width="9" height="9" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3">
				<path d="M18 6 6 18M6 6l12 12" />
			</svg>
		</button>
	{/if}
</span>

<style>
	.tag {
		display: inline-flex;
		align-items: center;
		gap: 6px;
		height: 22px;
		padding: 0 8px;
		border-radius: var(--radius-sm);
		font-family: var(--font-sans);
		font-size: var(--text-xs);
		font-weight: var(--weight-medium);
		white-space: nowrap;
		border: none;
	}
	.tag--sm {
		height: 18px;
		padding: 0 6px;
		font-size: var(--text-2xs);
		gap: 5px;
	}
	.tag__dot {
		width: 7px;
		height: 7px;
		border-radius: var(--radius-full);
		flex: none;
	}
	.tag--sm .tag__dot {
		width: 6px;
		height: 6px;
	}
	.tag__body {
		display: inline-flex;
		align-items: center;
		gap: 6px;
		border: none;
		background: transparent;
		color: inherit;
		font: inherit;
		padding: 0;
		cursor: pointer;
	}
	.tag--sm .tag__body {
		gap: 5px;
	}
	.tag__sep {
		opacity: 0.5;
		margin: 0 2px;
	}
	.tag__x {
		display: inline-flex;
		align-items: center;
		justify-content: center;
		width: 14px;
		height: 14px;
		margin-right: -3px;
		border: none;
		background: transparent;
		color: inherit;
		opacity: 0.55;
		cursor: pointer;
		border-radius: var(--radius-xs);
		padding: 0;
	}
	.tag__x:hover {
		opacity: 1;
		background: rgb(20, 21, 29, 0.08);
	}
	.tag--clickable {
		cursor: pointer;
	}
	.tag--clickable:hover {
		filter: brightness(0.96);
	}
	.tag__body:focus-visible,
	.tag__x:focus-visible {
		outline: none;
		box-shadow: var(--focus-ring);
	}
</style>
