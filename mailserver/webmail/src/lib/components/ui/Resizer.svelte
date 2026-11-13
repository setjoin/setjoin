<!-- mailserver/webmail/src/lib/components/ui/Resizer.svelte -->
<svelte:options runes={true} />

<script lang="ts">
	import { KEYBOARD_STEP_PX } from './splitMath';

	interface Props {
		/** Accessible name, e.g. "Resize sidebar". */
		label: string;
		/** Current/min/max pane size for separator value semantics (px). */
		valueNow?: number;
		valueMin?: number;
		valueMax?: number;
		/** Arrow keys: called with ±KEYBOARD_STEP_PX (16). */
		onStep?: (delta: number) => void;
		/** Pointer drag lifecycle; dx is travel since pointerdown. */
		onDragStart?: () => void;
		onDrag?: (dx: number) => void;
		onDragEnd?: () => void;
		/** Double-click reset. */
		onReset?: () => void;
	}

	let {
		label,
		valueNow,
		valueMin,
		valueMax,
		onStep,
		onDragStart,
		onDrag,
		onDragEnd,
		onReset
	}: Props = $props();

	let dragging = $state(false);
	let startX = 0;

	function handlePointerDown(e: PointerEvent) {
		dragging = true;
		startX = e.clientX;
		try {
			(e.currentTarget as HTMLElement).setPointerCapture?.(e.pointerId);
		} catch {
			// jsdom / untrusted events have no active pointer — capture is best-effort
		}
		onDragStart?.();
	}

	function handlePointerMove(e: PointerEvent) {
		if (!dragging) return;
		onDrag?.(e.clientX - startX);
	}

	function endDrag() {
		if (!dragging) return;
		dragging = false;
		onDragEnd?.();
	}

	function handleKeydown(e: KeyboardEvent) {
		if (e.key === 'ArrowLeft') {
			e.preventDefault();
			onStep?.(-KEYBOARD_STEP_PX);
		} else if (e.key === 'ArrowRight') {
			e.preventDefault();
			onStep?.(KEYBOARD_STEP_PX);
		}
	}
</script>

<!-- WAI-ARIA window-splitter pattern: a focusable separator IS interactive. -->
<!-- svelte-ignore a11y_no_noninteractive_element_interactions -->
<!-- svelte-ignore a11y_no_noninteractive_tabindex -->
<div
	class="resizer"
	class:resizer--dragging={dragging}
	role="separator"
	aria-orientation="vertical"
	aria-label={label}
	aria-valuenow={valueNow}
	aria-valuemin={valueMin}
	aria-valuemax={valueMax}
	tabindex="0"
	onpointerdown={handlePointerDown}
	onpointermove={handlePointerMove}
	onpointerup={endDrag}
	onpointercancel={endDrag}
	ondblclick={onReset}
	onkeydown={handleKeydown}
></div>

<style>
	.resizer {
		position: relative;
		flex: none;
		width: 1px; /* hairline — layout width matches splitMath DIVIDER_PX */
		background: var(--border-default);
		cursor: col-resize;
		touch-action: none; /* required for pointer-event dragging on touch */
		transition: background var(--duration-fast) var(--ease-out);
	}
	.resizer::after {
		/* 6px hit area centered on the 1px hairline */
		content: '';
		position: absolute;
		inset: 0 -3px;
		cursor: col-resize;
		z-index: 1;
	}
	.resizer:hover,
	.resizer--dragging {
		background: var(--accent);
	}
	.resizer:focus-visible {
		outline: none;
		box-shadow: var(--focus-ring);
		background: var(--accent);
	}
</style>
