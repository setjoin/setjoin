<!-- mailserver/webmail/src/lib/components/ui/Tooltip.svelte -->
<svelte:options runes={true} />

<script lang="ts">
	import type { Snippet } from 'svelte';

	interface Props {
		text: string;
		children: Snippet;
	}

	let { text, children }: Props = $props();

	const uid = $props.id();
	const tipId = `${uid}-tip`;

	let visible = $state(false);
	let placement = $state<'above' | 'below'>('above');
	let wrap = $state<HTMLSpanElement | null>(null);
	let tipEl = $state<HTMLDivElement | null>(null);
	let timer: ReturnType<typeof setTimeout> | undefined;

	function show(immediate: boolean) {
		clearTimeout(timer);
		if (immediate) visible = true;
		else timer = setTimeout(() => (visible = true), 500);
	}

	function hide() {
		clearTimeout(timer);
		visible = false;
	}

	// Wire the wrapped trigger to the tooltip for screen readers.
	$effect(() => {
		wrap?.firstElementChild?.setAttribute('aria-describedby', tipId);
	});

	// While visible: pick a side (above with 6px gap, below when no room) and listen for Escape.
	$effect(() => {
		if (!visible) return;
		const rect = wrap?.getBoundingClientRect();
		const tipHeight = tipEl?.offsetHeight ?? 0;
		placement = rect && rect.top >= tipHeight + 6 ? 'above' : 'below';
		function onKeydown(e: KeyboardEvent) {
			if (e.key === 'Escape') hide();
		}
		window.addEventListener('keydown', onKeydown);
		return () => window.removeEventListener('keydown', onKeydown);
	});

	// Never leak the pending-show timer.
	$effect(() => {
		return () => clearTimeout(timer);
	});
</script>

<!-- svelte-ignore a11y_no_static_element_interactions -->
<span
	class="tooltip-root"
	bind:this={wrap}
	onmouseenter={() => show(false)}
	onmouseleave={hide}
	onfocusin={() => show(true)}
	onfocusout={hide}
>
	{@render children()}
	{#if visible}
		<div class="tooltip" id={tipId} role="tooltip" data-placement={placement} bind:this={tipEl}>
			{text}
		</div>
	{/if}
</span>

<style>
	.tooltip-root {
		position: relative;
		display: inline-flex;
	}
	.tooltip {
		position: absolute;
		left: 50%;
		transform: translateX(-50%);
		z-index: 60;
		width: max-content;
		max-width: 240px;
		padding: 4px 8px;
		background: var(--surface-inverse);
		color: var(--text-inverse);
		font-family: var(--font-sans);
		font-size: var(--text-2xs); /* 11px */
		line-height: 1.4;
		border-radius: var(--radius-sm); /* 4px */
		box-shadow: var(--shadow-md);
		pointer-events: none;
		white-space: normal;
	}
	.tooltip[data-placement='above'] {
		bottom: calc(100% + 6px); /* 6px gap above the trigger */
	}
	.tooltip[data-placement='below'] {
		top: calc(100% + 6px); /* flipped: 6px gap below */
	}
</style>
