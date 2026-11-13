<svelte:options runes={true} />

<script lang="ts">
	import { Dialog, Button, Spinner } from '$lib/components/ui';
	import { t } from '$lib/i18n';
	import { goto } from '$app/navigation';

	interface Tou {
		id: number;
		name: string;
		version: number;
		body_md: string;
		require_scroll: boolean;
	}

	let {
		pending,
		onAllAccepted = () => {}
	}: {
		pending: Tou[];
		onAllAccepted?: () => void;
	} = $props();

	let idx = $state(0);
	let scrolledToEnd = $state(false);
	let progress = $state(0);
	let submitting = $state(false);
	let error = $state('');
	let declineOpen = $state(false);
	// ponytail: $state ref — Svelte 5 bind:this gives the DOM node; used for End-key scroll + short-doc latch.
	let bodyEl = $state<HTMLDivElement | null>(null);
	let announce = $state(''); // aria-live="polite" async-outcome announcer

	const tou = $derived(pending[idx]);
	const canAccept = $derived(scrolledToEnd && !submitting);

	// Reset scroll latch per document; non-scrollable docs latch immediately via queueMicrotask.
	// Guard scrollHeight > 0: jsdom defaults to 0, which would latch even in tests — defeat the gate.
	// ponytail: use a local `latch` var to avoid reading $state `scrolledToEnd` inside the $effect
	// (reading it would make $effect depend on it, causing it to re-run and reset the latch whenever
	// the scroll handler sets scrolledToEnd=true — a circular dependency bug).
	$effect(() => {
		void idx; // explicit tracking (tou is $derived from idx but belt-and-suspenders)
		const latch = !tou.require_scroll;
		scrolledToEnd = latch;
		progress = latch ? 100 : 0;
		error = '';
		queueMicrotask(() => {
			if (bodyEl && bodyEl.scrollHeight > 0 && bodyEl.scrollHeight <= bodyEl.clientHeight + 1) {
				scrolledToEnd = true;
				progress = 100;
			}
		});
	});

	function onScroll(e: Event) {
		const el = e.currentTarget as HTMLElement;
		const range = el.scrollHeight - el.clientHeight;
		// Short/non-scrollable doc: range ≤ 1 → latch immediately.
		if (range <= 1) {
			scrolledToEnd = true;
			progress = 100;
			return;
		}
		progress = Math.min(100, Math.round((el.scrollTop / range) * 100));
		// Within 2px of the bottom → latch (never un-latches).
		if (el.scrollTop + el.clientHeight >= el.scrollHeight - 2) scrolledToEnd = true;
	}

	// End key → jump to bottom (SR/keyboard escape hatch for a long doc);
	// the native scroll fires onScroll which latches scrolledToEnd.
	// Esc is a no-op here — the legal gate has no ESC exit (handled by passing no onClose to Dialog).
	// ponytail: scrollTop assignment is wrapped in try-catch — jsdom marks it read-only in tests.
	// In a real browser the assignment fires a scroll event which calls onScroll and latches the latch.
	// The test fires an explicit scroll event after keyDown End, covering both paths.
	function onBodyKey(e: KeyboardEvent) {
		if (e.key === 'End' && bodyEl) {
			try { bodyEl.scrollTop = bodyEl.scrollHeight; } catch { /* jsdom: scrollTop read-only */ }
		}
	}

	async function accept() {
		if (!canAccept) return;
		submitting = true;
		error = '';
		try {
			const res = await fetch('/terms/accept', {
				method: 'POST',
				headers: { 'Content-Type': 'application/json' },
				body: JSON.stringify({ tou_id: tou.id, version: tou.version })
			});
			if (!res.ok) {
				error = t('tou.error_stale');
				return;
			}
			if (idx + 1 < pending.length) {
				idx += 1;
				announce = t('tou.advanced_announce', {
					current: String(idx + 1),
					total: String(pending.length)
				});
			} else {
				announce = t('tou.all_accepted_announce');
				onAllAccepted();
			}
		} catch {
			error = t('tou.error_stale');
		} finally {
			submitting = false;
		}
	}

	async function signOut() {
		try {
			await fetch('/auth/logout', { method: 'POST' });
		} finally {
			goto('/login');
		}
	}
</script>

<!--
  No onClose passed → no ✕ button, ESC is a no-op (focusTrap calls onClose?.() which is undefined).
  This is the legal-gate dismiss override: the only exits are Accept and Decline.
  ponytail: body_md rendered as pre-wrap plain text (no XSS surface); swap to the shared
  sanitized markdown renderer when a marked/remark dependency is available.
-->
<Dialog open title={tou.name} titleHtmlAttr={tou.name} wide>
	{#snippet children()}
		<!-- Visually-hidden polite live region: announces queue advance + final acceptance. -->
		<div class="sr-only" aria-live="polite">{announce}</div>

		{#if pending.length > 1}
			<p class="tou-queue">
				{t('tou.queue_position', { current: String(idx + 1), total: String(pending.length) })}
			</p>
		{/if}
		<p class="tou-version">{t('tou.version_line', { v: String(tou.version) })}</p>

		<!-- Scroll region: tabindex for keyboard focus; body of the ToU doc.
		     svelte-ignore: this IS interactive — it receives scroll + End key for the consent widget. -->
		<!-- svelte-ignore a11y_no_noninteractive_tabindex -->
		<!-- svelte-ignore a11y_no_noninteractive_element_interactions -->
		<div
			class="tou-body"
			data-testid="tou-body"
			tabindex="0"
			role="region"
			aria-label={tou.name}
			bind:this={bodyEl}
			onscroll={onScroll}
			onkeydown={onBodyKey}
		>{tou.body_md}</div>

		{#if tou.require_scroll && !scrolledToEnd}
			<div class="tou-progress">
				<div class="tou-progress__hint" id="tou-scroll-hint">
					{t('tou.scroll_to_accept')}
				</div>
				<div
					class="tou-progress__track"
					role="progressbar"
					aria-valuenow={progress}
					aria-valuemin={0}
					aria-valuemax={100}
					aria-label={t('tou.scroll_progress')}
				>
					<div class="tou-progress__fill" style="width:{progress}%"></div>
				</div>
			</div>
		{/if}

		{#if error}
			<div class="tou-error" role="alert">
				<span>{error}</span>
				<Button variant="ghost" size="sm" onclick={() => location.reload()}>
					{t('tou.reload')}
				</Button>
			</div>
		{/if}
	{/snippet}

	{#snippet footer()}
		<!-- ponytail: row-reverse puts Accept first in tab order (DOM first) while keeping
		     Decline left / Accept right visually. column-reverse on mobile stacks Decline-above-Accept. -->
		<div class="tou-footer-btns">
			<Button
				variant="primary"
				size="lg"
				onclick={accept}
				disabled={!canAccept}
				aria-describedby={!scrolledToEnd ? 'tou-scroll-hint' : undefined}
			>
				{#if submitting}<Spinner size={16} />{:else}{t('tou.accept')}{/if}
			</Button>
			<Button
				variant="ghost"
				size="lg"
				onclick={() => (declineOpen = true)}
				disabled={submitting}
			>
				{t('tou.decline')}
			</Button>
		</div>
	{/snippet}
</Dialog>

<!-- Decline confirm dialog — ESC = Back here (onClose wired, unlike the gate above). -->
<Dialog open={declineOpen} title={t('tou.decline_title')} onClose={() => (declineOpen = false)}>
	{#snippet children()}
		<p>{t('tou.decline_body')}</p>
	{/snippet}
	{#snippet footer()}
		<Button variant="ghost" onclick={() => (declineOpen = false)}>
			{t('tou.decline_cancel')}
		</Button>
		<Button variant="danger" onclick={signOut}>
			{t('tou.decline_confirm')}
		</Button>
	{/snippet}
</Dialog>

<style>
	.tou-queue {
		margin: 0 0 var(--space-1);
		font-size: var(--text-xs);
		color: var(--text-tertiary);
		font-weight: var(--weight-medium);
	}
	.tou-version {
		margin: 0 0 var(--space-2);
		font-size: var(--text-xs);
		color: var(--text-tertiary);
	}
	.tou-body {
		max-height: 52vh;
		overflow-y: auto;
		padding: var(--space-3);
		background: var(--surface-sunken);
		border: 1px solid var(--border-subtle);
		border-radius: var(--radius-md);
		white-space: pre-wrap;
		font-size: var(--text-sm);
		color: var(--text-primary);
		line-height: var(--leading-relaxed);
	}
	.tou-body:focus-visible {
		outline: none;
		box-shadow: var(--focus-ring);
	}
	.tou-progress {
		margin-top: var(--space-2);
	}
	.tou-progress__hint {
		font-size: var(--text-xs);
		color: var(--text-secondary);
		margin-bottom: var(--space-1);
	}
	.tou-progress__track {
		height: 4px;
		background: var(--surface-hover);
		border-radius: var(--radius-full);
		overflow: hidden;
	}
	.tou-progress__fill {
		height: 100%;
		background: var(--accent);
		transition: width var(--duration-fast) var(--ease-out);
	}
	.tou-error {
		display: flex;
		align-items: center;
		justify-content: space-between;
		gap: var(--space-2);
		margin-top: var(--space-2);
		padding: var(--space-2) var(--space-3);
		background: var(--danger-bg);
		color: var(--danger-fg);
		border-radius: var(--radius-sm);
		font-size: var(--text-sm);
	}
	.sr-only {
		position: absolute;
		width: 1px;
		height: 1px;
		overflow: hidden;
		clip-path: inset(50%);
		white-space: nowrap;
	}
	/* Tab order: row-reverse gives Accept→Decline keyboard order (Accept first in DOM)
	   while the visual order remains [Decline][Accept] (justify-content:flex-end on footer). */
	.tou-footer-btns {
		display: flex;
		flex-direction: row-reverse;
		align-items: center;
		gap: 8px;
		width: 100%;
	}

	@media (max-width: 640px) {
		/* Full-bleed gate on mobile / WebView shell. */
		.tou-body {
			max-height: 60vh;
		}
		/* Stack Decline-above-Accept so the primary action is thumb-reachable at the bottom.
		   column-reverse: Accept (first in DOM) goes to bottom, Decline goes to top. */
		.tou-footer-btns {
			flex-direction: column-reverse;
			padding-bottom: env(safe-area-inset-bottom, 0);
		}
		.tou-footer-btns :global(.sj-btn) {
			width: 100%;
			justify-content: center;
		}
	}

	@media (prefers-reduced-motion: reduce) {
		.tou-progress__fill {
			transition: none;
		}
	}
</style>
