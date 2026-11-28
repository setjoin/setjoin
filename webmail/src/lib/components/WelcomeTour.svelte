<svelte:options runes={true} />

<script lang="ts">
	import { onMount, tick } from 'svelte';
	import { t } from '$lib/i18n';
	import { Button, showToast } from '$lib/components/ui';
	import { TOUR_STEPS, resolveVisibleSteps, resolveTarget } from '$lib/onboarding/steps';
	import {
		createTourRun,
		tourRequest,
		consumeRequest,
		hasSeenTour,
	} from '$lib/onboarding/tour.svelte';
	import {
		isEditableElement,
		isSoftwareKeyboardOpen,
		positionCoachmark,
		visualViewportRect,
		type CoachmarkPlacement,
	} from '$lib/onboarding/geometry';
	import type { InboxReadiness } from '$lib/onboarding/host';

	let {
		userEmail,
		pathname,
		hostBlocked = false,
		escapeAllowed = true,
		inboxReadiness = 'inactive',
	}: {
		userEmail: string;
		pathname: string;
		hostBlocked?: boolean;
		escapeAllowed?: boolean;
		inboxReadiness?: InboxReadiness;
	} = $props();

	const run = createTourRun();
	let rect = $state<DOMRect | null>(null);
	let tipEl = $state<HTMLDivElement | undefined>(undefined);
	let tipSize = $state({ width: 312, height: 190 });
	let settled = $state(false);
	let lastActivityAt = $state(0);
	let suspendedByHost = $state(false);
	let suspendedByRoute = $state(false);
	let suspendedByKeyboard = $state(false);
	let focusPending = $state(false);
	let targetLossTimer: ReturnType<typeof setTimeout> | undefined;

	const current = $derived(run.current);
	const isActive = $derived(run.state.phase === 'active');
	const isFirst = $derived(run.isFirst);
	const isLast = $derived(run.isLast);

	function now(): number {
		return typeof performance !== 'undefined' ? performance.now() : Date.now();
	}

	function focusPrimaryAction() {
		focusPending = true;
		void tick().then(() => {
			const action = tipEl?.querySelector<HTMLButtonElement>('.sj-tour-actions button:last-child');
			if (!action) return;
			action.focus();
			focusPending = false;
		});
	}

	function tryResume() {
		if (
			run.state.phase === 'suspended' &&
			!hostBlocked &&
			!suspendedByKeyboard &&
			pathname.startsWith('/inbox')
		) {
			suspendedByHost = false;
			suspendedByRoute = false;
			run.resume();
		}
	}

	function skipUnavailableStep() {
		if (run.state.phase !== 'active') return;
		if (run.isLast) run.cancelResolution();
		else run.next();
	}

	// Resolve a fixed logical run. Loaded inbox state distinguishes a genuine
	// empty mailbox from a slow one; the hard cap degrades to the three stable
	// shell steps without claiming Organize was shown.
	$effect(() => {
		if (!tourRequest.pending) return;
		const force = tourRequest.force;
		const trigger = tourRequest.trigger;
		if (!force && hasSeenTour(userEmail)) {
			consumeRequest();
			return;
		}

		run.beginResolving(force ? 'replay' : 'auto', trigger);
		const startedAt = now();
		let frame = 0;
		let previousSignature = '';
		let stableSince = startedAt;

		const poll = () => {
			const elapsed = now() - startedAt;
			const visible = resolveVisibleSteps();
			const signature = visible.map((step) => step.id).join(',');
			if (signature !== previousSignature) {
				previousSignature = signature;
				stableSince = now();
			}
			const coreReady = ['apps', 'compose', 'search'].every((id) =>
				visible.some((step) => step.id === id),
			);
			const dataSettled =
				inboxReadiness === 'loaded-empty' || inboxReadiness === 'loaded-populated';
			const timedOut = elapsed >= 3000;
			const quiet = force || now() - lastActivityAt >= 700;
			const eligible = pathname.startsWith('/inbox') && !hostBlocked;
			const anchorsStable = now() - stableSince >= 150;

			if (eligible && coreReady && anchorsStable && quiet && (dataSettled || timedOut)) {
				const steps =
					dataSettled && inboxReadiness === 'loaded-populated'
						? visible
						: visible.filter((step) => step.id !== 'organize');
				consumeRequest();
				if (steps.length === 0) {
					run.cancelResolution();
					return;
				}
				run.start({ userEmail, pathname, steps });
				if (force) focusPrimaryAction();
				return;
			}

			frame = requestAnimationFrame(poll);
		};

		frame = requestAnimationFrame(poll);
		return () => cancelAnimationFrame(frame);
	});

	// Explicit shell state has dismissal priority. Opening a real surface through
	// the highlighted control completes this step for the current session.
	$effect(() => {
		if (hostBlocked && run.state.phase === 'active') {
			suspendedByHost = true;
			run.suspend(true);
		} else if (!hostBlocked && suspendedByHost) {
			tryResume();
		}
	});

	$effect(() => {
		if (!pathname.startsWith('/inbox') && run.state.phase === 'active') {
			suspendedByRoute = true;
			run.suspend(true);
		} else if (pathname.startsWith('/inbox') && suspendedByRoute) {
			tryResume();
		}
	});

	// Measure the current target and attach its accessible description. All
	// invalidations coalesce into one rAF and all listeners are step-scoped.
	$effect(() => {
		if (!isActive || !current) return;
		const target = resolveTarget(current.target);
		if (!target) {
			targetLossTimer = setTimeout(skipUnavailableStep, 300);
			return () => {
				if (targetLossTimer) clearTimeout(targetLossTimer);
			};
		}

		const descriptionId = 'sj-tour-body';
		const priorDescription = target.getAttribute('aria-describedby');
		const descriptions = new Set((priorDescription ?? '').split(/\s+/).filter(Boolean));
		descriptions.add(descriptionId);
		target.setAttribute('aria-describedby', [...descriptions].join(' '));

		let frame = 0;
		let pending = false;
		let previousRect = '';
		let identicalRects = 0;
		const schedule = () => {
			if (pending) return;
			pending = true;
			frame = requestAnimationFrame(() => {
				pending = false;
				try {
					const nextTarget = resolveTarget(current.target);
					if (!nextTarget) {
						rect = null;
						settled = false;
						if (!targetLossTimer) targetLossTimer = setTimeout(skipUnavailableStep, 300);
						return;
					}
					if (targetLossTimer) {
						clearTimeout(targetLossTimer);
						targetLossTimer = undefined;
					}
					const next = nextTarget.getBoundingClientRect();
					const signature = [next.top, next.right, next.bottom, next.left, next.width, next.height].join(':');
					identicalRects = signature === previousRect ? identicalRects + 1 : 0;
					previousRect = signature;
					rect = next;
					settled = identicalRects >= 1;
					if (!settled) schedule();
				} catch {
					run.failSafe();
				}
			});
		};

		const ancestors: HTMLElement[] = [];
		let ancestor = target.parentElement;
		while (ancestor) {
			const style = getComputedStyle(ancestor);
			if (/(auto|scroll|overlay)/.test(`${style.overflow}${style.overflowX}${style.overflowY}`)) {
				ancestors.push(ancestor);
				ancestor.addEventListener('scroll', schedule, { passive: true });
			}
			ancestor = ancestor.parentElement;
		}

		window.addEventListener('resize', schedule, { passive: true });
		window.visualViewport?.addEventListener('resize', schedule, { passive: true });
		window.visualViewport?.addEventListener('scroll', schedule, { passive: true });
		let resizeObserver: ResizeObserver | undefined;
		if (typeof ResizeObserver !== 'undefined') {
			resizeObserver = new ResizeObserver(schedule);
			resizeObserver.observe(target);
		}
		schedule();

		return () => {
			cancelAnimationFrame(frame);
			if (targetLossTimer) {
				clearTimeout(targetLossTimer);
				targetLossTimer = undefined;
			}
			window.removeEventListener('resize', schedule);
			window.visualViewport?.removeEventListener('resize', schedule);
			window.visualViewport?.removeEventListener('scroll', schedule);
			for (const item of ancestors) item.removeEventListener('scroll', schedule);
			resizeObserver?.disconnect();
			if (priorDescription) target.setAttribute('aria-describedby', priorDescription);
			else target.removeAttribute('aria-describedby');
			rect = null;
			settled = false;
		};
	});

	$effect(() => {
		if (!isActive) return;
		void run.state.index;
		void rect;
		void tick().then(() => {
			if (!tipEl) return;
			const measured = tipEl.getBoundingClientRect();
			tipSize = {
				width: measured.width || 312,
				height: measured.height || 190,
			};
		});
	});

	$effect(() => {
		if (!isActive || !tipEl || !focusPending) return;
		focusPrimaryAction();
	});

	const position = $derived.by(() => {
		if (!rect || typeof window === 'undefined') return null;
		const viewport = visualViewportRect(window.visualViewport, {
			width: window.innerWidth,
			height: window.innerHeight,
		});
		const narrow = viewport.width < 768;
		return positionCoachmark(rect, tipSize, viewport, {
			preferred: current?.placement as CoachmarkPlacement | undefined,
			allowed: narrow ? ['bottom', 'top'] : undefined,
		});
	});

	const ringStyle = $derived(
		rect
			? `top:${rect.top - 6}px;left:${rect.left - 6}px;width:${rect.width + 12}px;height:${rect.height + 12}px;`
			: '',
	);
	const tipStyle = $derived(position ? `top:${position.top}px;left:${position.left}px;` : '');

	function advance() {
		if (isLast) {
			run.complete();
			showToast(t('onboarding.complete_toast'), { durationMs: 4000, variant: 'success' });
			return;
		}
		run.next();
		focusPrimaryAction();
	}

	function back() {
		run.back();
		focusPrimaryAction();
	}

	function skip() {
		run.skip();
	}

	onMount(() => {
		lastActivityAt = now();
		const recordActivity = () => {
			lastActivityAt = now();
		};
		const checkKeyboard = () => {
			const open = isSoftwareKeyboardOpen({
				layoutHeight: window.innerHeight,
				visualHeight: window.visualViewport?.height ?? window.innerHeight,
				editableFocused: isEditableElement(document.activeElement),
			});
			if (open && run.state.phase === 'active') {
				suspendedByKeyboard = true;
				run.suspend(false);
			} else if (!open && suspendedByKeyboard) {
				suspendedByKeyboard = false;
				tryResume();
			}
		};
		const handleKeydown = (event: KeyboardEvent) => {
			recordActivity();
			if (event.key === 'Escape' && run.state.phase === 'active' && escapeAllowed) {
				event.preventDefault();
				event.stopPropagation();
				skip();
			}
		};

		document.addEventListener('pointerdown', recordActivity, true);
		document.addEventListener('keydown', handleKeydown, true);
		document.addEventListener('scroll', recordActivity, true);
		document.addEventListener('touchstart', recordActivity, true);
		window.visualViewport?.addEventListener('resize', checkKeyboard);

		return () => {
			document.removeEventListener('pointerdown', recordActivity, true);
			document.removeEventListener('keydown', handleKeydown, true);
			document.removeEventListener('scroll', recordActivity, true);
			document.removeEventListener('touchstart', recordActivity, true);
			window.visualViewport?.removeEventListener('resize', checkKeyboard);
			run.reset();
		};
	});
</script>

{#if isActive && current && rect && position}
	{#key current.id}
		<div class="sj-tour-ring" style={ringStyle} aria-hidden="true"></div>
	{/key}
	<div
		class="sj-tour-tip sj-tour-tip--{position.placement}"
		bind:this={tipEl}
		style={tipStyle}
		role="region"
		aria-labelledby="sj-tour-title"
		aria-describedby="sj-tour-body"
		data-tour-step={current.id}
		data-tour-total={run.state.steps.length}
		data-tour-state={settled ? 'settled' : 'measuring'}
	>
		<button class="sj-tour-skip" onclick={skip}>{t('onboarding.skip')}</button>
		<h2 class="sj-tour-tip__title" id="sj-tour-title">{t(current.titleKey)}</h2>
		<p class="sj-tour-tip__body" id="sj-tour-body">{t(current.bodyKey)}</p>
		{#if current.hintKey}
			<p class="sj-tour-tip__hint">{t(current.hintKey)}</p>
		{/if}
		<div class="sj-tour-announcement sr-only" aria-live="polite" aria-atomic="true">
			{t(current.titleKey)}.
			{t('onboarding.progress', {
				current: String(run.state.index + 1),
				total: String(run.state.steps.length),
			})}
		</div>
		<div class="sj-tour-tip__foot">
			<span class="sj-tour-progress">
				{t('onboarding.progress', {
					current: String(run.state.index + 1),
					total: String(run.state.steps.length),
				})}
			</span>
			<div class="sj-tour-dots" aria-hidden="true">
				{#each run.state.steps as _, i (i)}
					<span class="sj-tour-dot" class:sj-tour-dot--on={i === run.state.index}></span>
				{/each}
			</div>
			<div class="sj-tour-actions">
				{#if !isFirst}
					<Button variant="ghost" onclick={back}>{t('onboarding.back')}</Button>
				{/if}
				<Button onclick={advance}>
					{isLast
						? t('onboarding.done')
						: current.forwardKey
							? t(current.forwardKey)
							: t('onboarding.next')}
				</Button>
			</div>
		</div>
	</div>
{/if}

<style>
	.sj-tour-ring {
		position: fixed;
		z-index: 899;
		border: 2px solid var(--accent);
		border-radius: var(--radius-md);
		background: transparent;
		pointer-events: none;
		animation: sj-tour-ring-in 600ms var(--ease-out) both;
	}

	.sj-tour-tip {
		position: fixed;
		z-index: 900;
		width: 312px;
		max-width: calc(100vw - 16px);
		padding: 16px;
		background: var(--surface-card);
		border: 1px solid var(--border-default);
		border-radius: var(--radius-lg);
		box-shadow: var(--shadow-lg);
		pointer-events: auto;
	}

	.sj-tour-tip::before {
		content: '';
		position: absolute;
		width: 10px;
		height: 10px;
		background: var(--surface-card);
		border: solid var(--border-default);
		transform: rotate(45deg);
	}

	.sj-tour-tip--top::before {
		left: calc(50% - 5px);
		bottom: -6px;
		border-width: 0 1px 1px 0;
	}

	.sj-tour-tip--bottom::before {
		left: calc(50% - 5px);
		top: -6px;
		border-width: 1px 0 0 1px;
	}

	.sj-tour-tip--left::before {
		right: -6px;
		top: calc(50% - 5px);
		border-width: 1px 1px 0 0;
	}

	.sj-tour-tip--right::before {
		left: -6px;
		top: calc(50% - 5px);
		border-width: 0 0 1px 1px;
	}

	.sj-tour-skip {
		position: absolute;
		top: 10px;
		right: 12px;
		border: none;
		background: none;
		cursor: pointer;
		color: var(--text-caption);
		font-size: var(--text-sm);
		border-radius: var(--radius-sm);
	}

	.sj-tour-skip:focus-visible {
		outline: none;
		box-shadow: var(--focus-ring);
	}

	.sj-tour-tip__title {
		margin: 0 52px 6px 0;
		font-size: var(--text-lg);
		font-weight: 600;
		color: var(--text-primary);
	}

	.sj-tour-tip__body,
	.sj-tour-tip__hint {
		margin: 0 0 10px;
		font-size: var(--text-sm);
		color: var(--text-secondary);
		line-height: 1.5;
	}

	.sj-tour-tip__hint {
		color: var(--text-caption);
	}

	.sj-tour-tip__foot {
		display: flex;
		flex-direction: column;
		gap: 10px;
	}

	.sj-tour-progress {
		font-size: var(--text-sm);
		color: var(--text-caption);
	}

	.sj-tour-dots {
		display: flex;
		gap: 6px;
	}

	.sj-tour-dot {
		width: 6px;
		height: 6px;
		border-radius: var(--radius-full);
		background: var(--border-default);
	}

	.sj-tour-dot--on {
		background: var(--accent);
	}

	.sj-tour-actions {
		display: flex;
		justify-content: flex-end;
		gap: 8px;
	}

	@keyframes sj-tour-ring-in {
		from { opacity: 0; }
		to { opacity: 1; }
	}

	@media (max-width: 767px) {
		.sj-tour-tip {
			width: min(304px, calc(100vw - 16px));
		}
		.sj-tour-actions :global(button) {
			min-height: 44px;
		}
	}

	@media (prefers-reduced-motion: reduce) {
		.sj-tour-ring {
			animation: none;
		}
	}
</style>
