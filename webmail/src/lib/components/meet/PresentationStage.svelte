<svelte:options runes={true} />

<script lang="ts">
	// PresentationStage — MEET plan M3: the main-stage presentation canvas
	// shared by the presenter and attendee layouts (the plan's own
	// information hierarchy): main page canvas, compact bottom controls,
	// presenter-only rail (thumbnails/notes, via PresentationRail), local
	// zoom, ephemeral pointer/ink, handoff/takeover, and the ordinary
	// screen-share fallback.
	//
	// State coverage the plan pins on this surface:
	//  - loading: canvas skeleton with audio untouched; page switches show
	//    a bounded spinner over the last validated page, never a blank OK.
	//  - partial/degraded: last validated page stays visible, marked stale,
	//    controls disabled until resync; DEGRADED names the renderer state.
	//  - keyboard: ArrowLeft/Right change pages ONLY while the stage region
	//    owns focus (typing in notes/chat/captions never navigates); every
	//    control is a real button with an accessible name and visible focus.
	//  - screen reader: polite live region for page changes/handoff/zoom,
	//    assertive for revocation/end; zoom copy says it is local.
	//  - touch: 44px minimum control targets; pointer/ink draw from pointer
	//    events normalized against the canvas rect (no device pixels ever
	//    leave the client).
	//  - temporary ink is visibly temporary: the tool's accessible name and
	//    first-use notice say it is never saved to the document or a replay.
	import type { PresentationStore } from '$lib/meet/presentationStore.svelte';
	import PresentationRail from './PresentationRail.svelte';
	import { Button, Dialog, IconButton, Spinner } from '$lib/components/ui';
	import Icon from '$lib/components/Icon.svelte';
	import { t } from '$lib/i18n';

	let {
		presentation,
		presenterLabel = '',
		handoffTargets = [],
		onFallback,
	}: {
		presentation: PresentationStore;
		/** Display name of the CURRENT presenter, when the caller can resolve
		 *  one; falls back to the checkpoint's presenter participant id. */
		presenterLabel?: string;
		/** Handoff targets (meeting_attendee participant ids + names) — the
		 *  M2 wire targets presenter grants by participant id. Empty gives
		 *  the dialog's explanatory empty state; takeover (self-target,
		 *  server-fenced) stays available regardless. */
		handoffTargets?: { participantId: number; displayName: string }[];
		/** The ordinary screen-share fallback (existing mechanism) — the
		 *  stage's fidelity escape hatch, reachable in two interactions. */
		onFallback: () => void;
	} = $props();

	let canvasEl = $state<HTMLElement | undefined>();
	let showHandoff = $state(false);
	// In-progress local ink draft (normalized flat x,y pairs) — committed to
	// the store's ephemeral plane on pointerup, never persisted anywhere.
	let draftPoints = $state<number[]>([]);
	let drawing = $state(false);

	const isPresenter = $derived(presentation.amPresenter);
	const cp = $derived(presentation.checkpoint);
	const page = $derived(presentation.currentPage);
	const controlsDisabled = $derived(presentation.pageState === 'stale' || presentation.resyncing);
	const presenterName = $derived(
		presenterLabel !== '' ? presenterLabel : String(cp?.presenterParticipantId ?? ''),
	);
	const degraded = $derived(cp?.status === 'DEGRADED');

	function isTypingTarget(el: EventTarget | null): boolean {
		if (!(el instanceof HTMLElement)) return false;
		const tag = el.tagName;
		return tag === 'INPUT' || tag === 'TEXTAREA' || el.isContentEditable;
	}

	/** Arrow keys change pages only while the presentation canvas owns
	 *  focus — the handler lives on the stage region, never on window, so
	 *  typing anywhere else is unaffected by construction. */
	function handleKeydown(e: KeyboardEvent): void {
		if (isTypingTarget(e.target)) return;
		if (e.key === 'ArrowLeft' && isPresenter) {
			e.preventDefault();
			presentation.navigate(-1);
		} else if (e.key === 'ArrowRight' && isPresenter) {
			e.preventDefault();
			presentation.navigate(1);
		}
	}

	function normalizedPoint(e: PointerEvent): { x: number; y: number } | null {
		const el = canvasEl;
		if (!el) return null;
		const rect = el.getBoundingClientRect();
		if (rect.width === 0 || rect.height === 0) return null;
		return {
			x: (e.clientX - rect.left) / rect.width,
			y: (e.clientY - rect.top) / rect.height,
		};
	}

	function handlePointerMove(e: PointerEvent): void {
		if (!isPresenter) return;
		const p = normalizedPoint(e);
		if (!p) return;
		if (presentation.pointerTool) presentation.sendPointer(p.x, p.y);
		if (drawing && presentation.inkTool && draftPoints.length < 1024) draftPoints.push(p.x, p.y);
	}

	function handlePointerDown(e: PointerEvent): void {
		if (!isPresenter || !presentation.inkTool) return;
		const p = normalizedPoint(e);
		if (!p) return;
		drawing = true;
		draftPoints = [p.x, p.y];
	}

	function handlePointerUp(): void {
		if (!drawing) return;
		drawing = false;
		const points = draftPoints;
		draftPoints = [];
		if (points.length >= 4) presentation.commitInk(points);
	}

	function toggleInk(): void {
		const next = !presentation.inkTool;
		presentation.inkTool = next;
		drawing = false;
		draftPoints = [];
		if (!next) presentation.clearInk(); // putting the pen away clears your ink
	}

	function toSvgPoints(points: number[]): string {
		// The overlay SVG is a 0..100 viewBox with preserveAspectRatio="none",
		// so normalized coordinates scale by 100 — strokes track the page at
		// every canvas size without device-pixel coupling.
		const out: string[] = [];
		for (let i = 0; i + 1 < points.length; i += 2) {
			out.push(`${(points[i] * 100).toFixed(2)},${(points[i + 1] * 100).toFixed(2)}`);
		}
		return out.join(' ');
	}

	const pageAlt = $derived(
		t('meet.presentation.stage.pageOf', { n: String(presentation.pageIndex + 1), total: String(presentation.pageCount) }),
	);
</script>

<!-- The stage region is deliberately focusable + key-interactive: the plan's
     keyboard contract ("arrow keys change pages only while presentation
     canvas owns focus") needs a focus owner that is NOT window-level, so
     typing in notes/chat/captions can never navigate. -->
<!-- svelte-ignore a11y_no_noninteractive_tabindex -->
<!-- svelte-ignore a11y_no_noninteractive_element_interactions -->
<div
	class="pres-stage"
	role="region"
	aria-label={t('meet.presentation.a11y.stageLabel')}
	tabindex="0"
	onkeydown={handleKeydown}
	data-testid="presentation-stage"
>
	<!-- Live regions: polite for page changes/handoff/local zoom; assertive
	     for revocation/end (recording stays the banner's own surfaces). -->
	<div class="sr-only" role="status" aria-live="polite">{presentation.politeMessage}</div>
	<div class="sr-only" role="alert" aria-live="assertive">{presentation.assertiveMessage}</div>

	<div class="pres-stage__main">
		{#if presentation.pageState === 'stale'}
			<!-- partial/degraded truth: last validated page stays visible,
			     controls disabled until resync succeeds -->
			<div class="pres-stage__banner" role="status" data-testid="stage-stale">
				<span>{t('meet.presentation.stage.stale')}</span>
				<Button variant="secondary" size="sm" disabled={presentation.resyncing} onclick={() => void presentation.resync()}>
					{t('meet.presentation.stage.resync')}
				</Button>
			</div>
		{:else if degraded}
			<div class="pres-stage__banner" role="status">{t('meet.presentation.stage.degraded')}</div>
		{/if}

		<!-- The canvas surface is an interactive drawing plane when the
		     temporary-ink tool is on (presenter-gated); role="application"
		     marks it as a focusable widget region, not document content. -->
		<!-- svelte-ignore a11y_no_static_element_interactions -->
		<div
			class="pres-stage__canvas-wrap"
			role="application"
			aria-roledescription={t('meet.presentation.a11y.stageLabel')}
			bind:this={canvasEl}
			onpointerdown={handlePointerDown}
			onpointermove={handlePointerMove}
			onpointerup={handlePointerUp}
			onpointercancel={handlePointerUp}
			onpointerleave={handlePointerUp}
		>
			{#if page}
				<img
					class="pres-stage__page"
					class:pres-stage__page--stale={presentation.pageState === 'stale'}
					style:transform="scale({presentation.zoom})"
					src={page.fullPage.path}
					alt={pageAlt}
					data-testid="stage-page"
				/>
				{#if presentation.pageState === 'loading'}
					<div class="pres-stage__page-loading"><Spinner /></div>
				{/if}
			{:else}
				<!-- loading skeleton (audio untouched — media lives outside) -->
				<div class="pres-stage__skeleton">
					<Spinner />
					<span>{t('meet.presentation.stage.loading')}</span>
				</div>
			{/if}

			<!-- ephemeral overlay: temporary ink + remote pointers -->
			<svg class="pres-stage__overlay" viewBox="0 0 100 100" preserveAspectRatio="none" aria-hidden="true">
				{#each presentation.inkStrokes as stroke (stroke.id)}
					<polyline class="pres-stage__ink" points={toSvgPoints(stroke.points)} fill="none" stroke-linecap="round" stroke-linejoin="round" />
				{/each}
				{#if draftPoints.length >= 4}
					<polyline class="pres-stage__ink" points={toSvgPoints(draftPoints)} fill="none" stroke-linecap="round" stroke-linejoin="round" />
				{/if}
			</svg>
			{#each presentation.remotePointers as p (p.identity)}
				<div
					class="pres-stage__pointer"
					style:left="{p.x * 100}%"
					style:top="{p.y * 100}%"
					role="presentation"
				></div>
			{/each}

			{#if presentation.readingView}
				<!-- linear reading view: never changes the shared page -->
				<div class="pres-stage__reading" data-testid="stage-reading">
					<p class="pres-stage__reading-head">{t('meet.presentation.stage.reading')}</p>
					{#if presentation.readingState === 'loading'}
						<p class="pres-stage__reading-status">{t('meet.presentation.stage.loading')}</p>
					{:else if presentation.readingState === 'unavailable' || presentation.readingText === null}
						<p class="pres-stage__reading-status">{t('meet.presentation.stage.readingUnavailable')}</p>
					{:else}
						<div class="pres-stage__reading-text">{presentation.readingText}</div>
					{/if}
				</div>
			{/if}
		</div>

		<!-- compact controls -->
		<div class="pres-stage__controls" role="toolbar" aria-label={t('meet.presentation.a11y.controlsLabel')}>
			<div class="pres-stage__group">
				{#if isPresenter}
					<IconButton label={t('meet.presentation.stage.prev')} disabled={controlsDisabled} onclick={() => presentation.navigate(-1)} data-testid="stage-prev">
						<Icon name="ChevronLeft" size={16} />
					</IconButton>
				{/if}
				<span class="pres-stage__page-indicator" data-testid="stage-page-indicator">{pageAlt}</span>
				{#if isPresenter}
					<IconButton label={t('meet.presentation.stage.next')} disabled={controlsDisabled} onclick={() => presentation.navigate(1)} data-testid="stage-next">
						<Icon name="ChevronRight" size={16} />
					</IconButton>
				{/if}
			</div>

			<div class="pres-stage__group">
				<span class="pres-stage__presenter" data-testid="stage-presenter">
					{isPresenter ? t('meet.presentation.stage.presenterYou') : t('meet.presentation.stage.presenterLabel', { name: presenterName })}
				</span>
			</div>

			<div class="pres-stage__group">
				{#if isPresenter}
					<IconButton
						label={t('meet.presentation.stage.pointer')}
						active={presentation.pointerTool}
						aria-pressed={presentation.pointerTool}
						disabled={controlsDisabled}
						onclick={() => (presentation.pointerTool = !presentation.pointerTool)}
						data-testid="stage-pointer"
					>
						<Icon name="MapPin" size={16} />
					</IconButton>
					<IconButton
						label={t('meet.presentation.stage.ink')}
						tooltip={t('meet.presentation.stage.inkNotice')}
						active={presentation.inkTool}
						aria-pressed={presentation.inkTool}
						disabled={controlsDisabled}
						onclick={toggleInk}
						data-testid="stage-ink"
					>
						<Icon name="PenLine" size={16} />
					</IconButton>
				{/if}
				<IconButton label={t('meet.presentation.stage.zoomOut')} disabled={controlsDisabled} onclick={() => presentation.zoomOut()} data-testid="stage-zoom-out">
					<Icon name="Minus" size={16} />
				</IconButton>
				<IconButton label={t('meet.presentation.stage.zoomIn')} disabled={controlsDisabled} onclick={() => presentation.zoomIn()} data-testid="stage-zoom-in">
					<Icon name="Plus" size={16} />
				</IconButton>
				<IconButton label={t('meet.presentation.stage.reading')} active={presentation.readingView} aria-pressed={presentation.readingView} onclick={() => presentation.toggleReading()} data-testid="stage-reading">
					<Icon name="ScrollText" size={16} />
				</IconButton>
				{#if isPresenter}
					<IconButton
						label={t('meet.presentation.rail.thumbnails')}
						active={presentation.railOpen && presentation.railMode === 'thumbnails'}
						disabled={controlsDisabled}
						onclick={() => (presentation.railOpen && presentation.railMode === 'thumbnails' ? presentation.closeRail() : presentation.openRail('thumbnails'))}
						data-testid="stage-rail-thumbs"
					>
						<Icon name="LayoutGrid" size={16} />
					</IconButton>
					<IconButton
						label={t('meet.presentation.rail.notes')}
						title={t('meet.presentation.rail.notesPrivate')}
						active={presentation.railOpen && presentation.railMode === 'notes'}
						disabled={controlsDisabled}
						onclick={() => (presentation.railOpen && presentation.railMode === 'notes' ? presentation.closeRail() : presentation.openRail('notes'))}
						data-testid="stage-rail-notes"
					>
						<Icon name="ScrollText" size={16} />
					</IconButton>
					<IconButton label={t('meet.presentation.stage.handoff')} disabled={controlsDisabled} onclick={() => (showHandoff = true)} data-testid="stage-handoff">
						<Icon name="Forward" size={16} />
					</IconButton>
					<Button variant="secondary" size="sm" onclick={() => void presentation.end()} data-testid="stage-end">
						{t('meet.presentation.stage.end')}
					</Button>
				{:else}
					<!-- the authorized takeover affordance: always reachable for a
					     non-presenter (the departing-presenter rescue), server-
					     fenced by the reducer's verb-specific authority — never a
					     self-grant -->
					<Button variant="secondary" size="sm" disabled={presentation.pendingGrant !== null} onclick={() => void presentation.takeoverPresenter()} data-testid="stage-takeover">
						{t('meet.presentation.stage.takeover')}
					</Button>
				{/if}
				<Button variant="ghost" size="sm" onclick={onFallback} data-testid="stage-fallback">{t('meet.presentation.stage.fallback')}</Button>
			</div>
		</div>
		{#if presentation.inkTool}
			<p class="pres-stage__ink-notice" role="note">{t('meet.presentation.stage.inkNotice')}</p>
		{/if}
	</div>

	{#if isPresenter && presentation.railOpen}
		<PresentationRail {presentation} />
	{/if}
</div>

{#if showHandoff}
	<Dialog open={true} title={t('meet.presentation.stage.handoffTitle')} onClose={() => (showHandoff = false)}>
		{#snippet children()}
			<div class="pres-stage__handoff">
				{#if presentation.handoffReason}
					<p class="pres-stage__handoff-reason" role="alert" data-testid="handoff-reason">{presentation.handoffReason}</p>
				{/if}
				{#if handoffTargets.length === 0}
					<p class="pres-stage__handoff-empty" data-testid="handoff-empty">{t('meet.presentation.stage.handoffEmpty')}</p>
				{:else}
					<ul class="pres-stage__handoff-list" role="list">
						{#each handoffTargets as p (p.participantId)}
							<li class="pres-stage__handoff-row">
								<span>{p.displayName}</span>
								<Button
									variant="secondary"
									size="sm"
									disabled={presentation.pendingGrant !== null}
									data-testid="handoff-grant-{p.participantId}"
									onclick={() => void presentation.grantPresenter(p.participantId)}
								>
									{presentation.pendingGrant === p.participantId ? t('meet.presentation.stage.handoffPending') : t('meet.presentation.stage.handoff')}
								</Button>
							</li>
						{/each}
					</ul>
				{/if}
			</div>
		{/snippet}
		{#snippet footer()}
			<Button variant="secondary" onclick={() => (showHandoff = false)}>{t('common.close')}</Button>
		{/snippet}
	</Dialog>
{/if}

<style>
	.pres-stage {
		display: flex;
		flex: 1;
		min-height: 0;
		min-width: 0;
		background: var(--surface-base);
		position: relative;
	}
	.pres-stage__main {
		flex: 1;
		display: flex;
		flex-direction: column;
		min-width: 0;
		min-height: 0;
		position: relative;
	}
	.pres-stage__banner {
		display: flex;
		align-items: center;
		justify-content: center;
		gap: var(--space-3);
		padding: var(--space-1) var(--space-3);
		font-size: var(--text-sm);
		color: var(--text-secondary);
		background: var(--surface-sunken);
		flex: none;
	}
	.pres-stage__canvas-wrap {
		position: relative;
		flex: 1;
		min-height: 0;
		overflow: hidden;
		display: flex;
		align-items: center;
		justify-content: center;
		background: var(--surface-sunken);
		touch-action: none;
	}
	.pres-stage__page {
		max-width: 100%;
		max-height: 100%;
		object-fit: contain;
		transform-origin: center center;
	}
	.pres-stage__page--stale {
		opacity: 0.7;
	}
	.pres-stage__page-loading {
		position: absolute;
		inset: 0;
		display: flex;
		align-items: center;
		justify-content: center;
		pointer-events: none;
	}
	.pres-stage__skeleton {
		display: flex;
		flex-direction: column;
		align-items: center;
		justify-content: center;
		gap: var(--space-2);
		color: var(--text-secondary);
		font-size: var(--text-sm);
		width: 100%;
		height: 100%;
	}
	.pres-stage__overlay {
		position: absolute;
		inset: 0;
		width: 100%;
		height: 100%;
		pointer-events: none;
	}
	.pres-stage__ink {
		stroke: var(--accent);
		stroke-width: 0.6;
		vector-effect: non-scaling-stroke;
	}
	.pres-stage__pointer {
		position: absolute;
		width: 12px;
		height: 12px;
		border-radius: var(--radius-full);
		background: var(--accent);
		border: 2px solid var(--surface-base);
		transform: translate(-50%, -50%);
		pointer-events: none;
	}
	.pres-stage__reading {
		position: absolute;
		top: 0;
		right: 0;
		bottom: 0;
		width: min(340px, 45%);
		background: var(--surface-card);
		border-left: 1px solid var(--border-subtle);
		padding: var(--space-3);
		overflow-y: auto;
	}
	.pres-stage__reading-head {
		margin: 0 0 var(--space-2);
		font-size: var(--text-xs);
		font-weight: 600;
		color: var(--text-secondary);
	}
	.pres-stage__reading-status {
		margin: 0;
		font-size: var(--text-sm);
		color: var(--text-secondary);
	}
	.pres-stage__reading-text {
		white-space: pre-wrap;
		font-size: var(--text-sm);
		color: var(--text-primary);
	}
	.pres-stage__controls {
		display: flex;
		align-items: center;
		justify-content: space-between;
		gap: var(--space-2);
		padding: var(--space-1) var(--space-2);
		border-top: 1px solid var(--border-subtle);
		background: var(--surface-raised);
		flex-wrap: wrap;
		flex: none;
	}
	.pres-stage__group {
		display: flex;
		align-items: center;
		gap: var(--space-1);
		min-width: 0;
	}
	.pres-stage__page-indicator {
		font-size: var(--text-xs);
		color: var(--text-secondary);
		font-variant-numeric: tabular-nums;
		white-space: nowrap;
	}
	.pres-stage__presenter {
		font-size: var(--text-xs);
		color: var(--text-secondary);
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
		max-width: 200px;
	}
	.pres-stage__ink-notice {
		margin: 0;
		padding: 0 var(--space-3) var(--space-1);
		font-size: var(--text-xs);
		color: var(--text-caption);
		text-align: center;
		flex: none;
	}
	.pres-stage__handoff-list {
		list-style: none;
		margin: 0;
		padding: 0;
	}
	.pres-stage__handoff-row {
		display: flex;
		align-items: center;
		justify-content: space-between;
		gap: var(--space-2);
		padding: var(--space-2) 0;
		border-bottom: 1px solid var(--border-subtle);
	}
	.pres-stage__handoff-empty,
	.pres-stage__handoff-reason {
		margin: 0;
		font-size: var(--text-sm);
		color: var(--text-secondary);
	}
	/* Viewport-bounded controls: at short heights the secondary tools wrap
	   (flex-wrap above) while mic/leave/recording stay reachable — the stage
	   never pushes the meeting's own ControlsBar below the fold because the
	   stage itself is height-bounded by its flex parent. */
	@media (max-height: 480px) {
		.pres-stage__reading {
			position: static;
			width: auto;
			max-height: 40%;
			border-left: none;
			border-top: 1px solid var(--border-subtle);
		}
	}
</style>
