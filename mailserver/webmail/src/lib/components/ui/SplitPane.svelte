<!-- mailserver/webmail/src/lib/components/ui/SplitPane.svelte -->
<svelte:options runes={true} />

<script lang="ts">
	import type { Snippet } from 'svelte';
	import Resizer from './Resizer.svelte';
	import { dragSize, paneLimits, ratioFor, resolveSplit, stepSize } from './splitMath';

	interface Props {
		/** localStorage key for the persisted ratio (pane A share of usable width, 0..1). */
		storageKey: string;
		/** Ratio used when nothing valid is persisted, and the double-click reset target. */
		defaultRatio?: number;
		/** Pane A min width (px). */
		minA: number;
		/** Pane B min width (px). */
		minB: number;
		/** Optional pane A max width (px). */
		maxA?: number;
		/** Optional pane B max width (px). */
		maxB?: number;
		/** Accessible name for the divider. */
		label?: string;
		/** Fires once each time the container becomes too narrow for minA + minB. */
		onCollapse?: () => void;
		a: Snippet;
		b: Snippet;
	}

	let {
		storageKey,
		defaultRatio = 0.5,
		minA,
		minB,
		maxA,
		maxB,
		label = 'Resize panes',
		onCollapse,
		a,
		b
	}: Props = $props();

	function loadRatio(): number {
		try {
			const raw = localStorage.getItem(storageKey);
			const r = raw == null ? NaN : parseFloat(raw);
			return Number.isFinite(r) && r > 0 && r < 1 ? r : defaultRatio;
		} catch {
			return defaultRatio;
		}
	}

	let containerEl = $state<HTMLDivElement | null>(null);
	let width = $state(0); // 0 = not yet measured
	let ratio = $state(loadRatio());
	let dragStartA = 0;
	let wasCollapsed = false;

	const split = $derived(resolveSplit({ total: width, ratio, minA, minB, maxA, maxB }));
	const limits = $derived(paneLimits({ total: width, minA, minB, maxA, maxB }));
	const measured = $derived(width > 0);
	const collapsed = $derived(measured && split.collapsed);

	function measure() {
		if (containerEl) width = containerEl.clientWidth;
	}

	$effect(() => {
		if (!containerEl) return;
		measure();
		if (typeof ResizeObserver !== 'undefined') {
			const ro = new ResizeObserver(measure);
			ro.observe(containerEl);
			return () => ro.disconnect();
		}
		window.addEventListener('resize', measure);
		return () => window.removeEventListener('resize', measure);
	});

	$effect(() => {
		if (collapsed && !wasCollapsed) onCollapse?.();
		wasCollapsed = collapsed;
	});

	function persist() {
		try {
			localStorage.setItem(storageKey, String(ratio));
		} catch {
			// storage unavailable (private mode) — resizing still works, just not persisted
		}
	}

	function handleDragStart() {
		dragStartA = split.a;
	}

	function handleDrag(dx: number) {
		ratio = ratioFor(dragSize(dragStartA, 0, dx, limits.min, limits.max), limits.usable);
	}

	function handleStep(delta: number) {
		ratio = ratioFor(stepSize(split.a, delta, limits.min, limits.max), limits.usable);
		persist();
	}

	function handleReset() {
		ratio = defaultRatio;
		persist();
	}
</script>

<div class="split" bind:this={containerEl}>
	<div
		class="split__pane"
		class:split__pane--fill={!measured || collapsed}
		style:width={measured && !collapsed ? `${split.a}px` : undefined}
	>
		{@render a()}
	</div>
	{#if measured && !collapsed}
		<Resizer
			{label}
			valueNow={split.a}
			valueMin={limits.min}
			valueMax={limits.max}
			onDragStart={handleDragStart}
			onDrag={handleDrag}
			onDragEnd={persist}
			onStep={handleStep}
			onReset={handleReset}
		/>
	{/if}
	<!-- keep-alive: stays mounted while collapsed so scroll/selection/form state survive -->
	<div class="split__pane split__pane--b" hidden={collapsed}>
		{@render b()}
	</div>
</div>

<style>
	.split {
		display: flex;
		align-items: stretch;
		width: 100%;
		height: 100%;
		min-width: 0;
	}
	.split__pane {
		flex: 0 0 auto;
		min-width: 0;
		overflow: hidden;
	}
	.split__pane--b,
	.split__pane--fill {
		flex: 1 1 auto;
	}
	.split__pane[hidden] {
		display: none;
	}
</style>
