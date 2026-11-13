<svelte:options runes={true} />

<!--
	/book/[slug] — the PUBLIC self-service booking page (feature #6). Standalone:
	no app shell, no session/JMAP fetch — only /api/public/booking/* (see
	+layout.svelte's auth guard exemption for /book/*). Renders open slots in
	the BOOKER'S browser timezone (Intl.DateTimeFormat) while noting the page's
	own timezone; picking a slot reveals the details form (honeypot "website"
	field hidden but present for every real browser); submit sends a
	double-opt-in verification email — no calendar event exists yet.
-->

<script lang="ts">
	import { onMount } from 'svelte';
	import { page } from '$app/state';
	import { Card, Button, Input, Textarea } from '$lib/components/ui';
	import { t } from '$lib/i18n';
	import {
		getBookingPage,
		getBookingSlots,
		submitBooking,
		BookingNotFoundError,
		BookingSlotGoneError,
		type PublicBookingMeta,
		type BookingSlot
	} from '$lib/api/publicBooking';

	const slug = $derived(page.params.slug ?? '');
	const browserTz = Intl.DateTimeFormat().resolvedOptions().timeZone;

	let meta = $state<PublicBookingMeta | null>(null);
	let notFound = $state(false);
	let loading = $state(true);
	let loadError = $state(false);
	let slots = $state<BookingSlot[]>([]);
	let weekOffset = $state(0); // in 7-day increments from today
	let selectedSlot = $state<BookingSlot | null>(null);
	let email = $state('');
	let name = $state('');
	let answers = $state<Record<string, string>>({});
	let website = $state(''); // honeypot
	let submitting = $state(false);
	let submitted = $state(false);
	let submitError = $state('');
	let liveAnnounce = $state('');

	onMount(loadMeta);

	async function loadMeta() {
		loading = true;
		notFound = false;
		loadError = false;
		try {
			meta = await getBookingPage(slug);
			await loadSlots();
		} catch (e) {
			if (e instanceof BookingNotFoundError) notFound = true;
			else loadError = true;
		} finally {
			loading = false;
		}
	}

	// ponytail: from/to are plain UTC calendar dates for a 7-day window — the
	// server groups/caps by ITS page timezone regardless, so a booker exactly
	// at a UTC-day boundary might see one fewer slot at either edge of the
	// window; not a correctness or security issue, just a display nicety.
	// Upgrade to timezone-exact windowing if a customer reports it.
	function weekRange(offset: number): { from: string; to: string } {
		const start = new Date();
		start.setUTCDate(start.getUTCDate() + offset * 7);
		const end = new Date(start);
		end.setUTCDate(end.getUTCDate() + 6);
		const fmt = (d: Date) => d.toISOString().slice(0, 10);
		return { from: fmt(start), to: fmt(end) };
	}

	async function loadSlots() {
		const { from, to } = weekRange(weekOffset);
		slots = await getBookingSlots(slug, from, to);
	}

	async function changeWeek(delta: number) {
		const previousOffset = weekOffset;
		weekOffset += delta;
		selectedSlot = null;
		loading = true;
		loadError = false;
		try {
			await loadSlots();
		} catch {
			weekOffset = previousOffset;
			loadError = true;
		} finally {
			loading = false;
		}
	}

	// Group slots by the BOOKER's local calendar day for display.
	const slotsByDay = $derived.by(() => {
		const groups = new Map<string, BookingSlot[]>();
		for (const s of slots) {
			const day = new Date(s.start).toLocaleDateString(undefined, {
				weekday: 'long',
				month: 'short',
				day: 'numeric'
			});
			if (!groups.has(day)) groups.set(day, []);
			groups.get(day)!.push(s);
		}
		return groups;
	});

	function slotLabel(s: BookingSlot): string {
		return new Date(s.start).toLocaleTimeString(undefined, { hour: 'numeric', minute: '2-digit' });
	}

	function slotAriaLabel(s: BookingSlot): string {
		return new Date(s.start).toLocaleString(undefined, {
			weekday: 'long',
			month: 'long',
			day: 'numeric',
			hour: 'numeric',
			minute: '2-digit'
		});
	}

	function pick(s: BookingSlot) {
		selectedSlot = s;
	}

	async function submit(e: Event) {
		e.preventDefault();
		if (!selectedSlot || submitting) return;
		submitting = true;
		submitError = '';
		try {
			await submitBooking(slug, { start: selectedSlot.start, email, name, answers, website });
			submitted = true;
		} catch (e2) {
			if (e2 instanceof BookingSlotGoneError) {
				liveAnnounce = t('booking.public.slotGone');
				selectedSlot = null;
				loading = true;
				try {
					await loadSlots();
				} catch {
					loadError = true;
				} finally {
					loading = false;
				}
			} else {
				submitError = e2 instanceof Error ? e2.message : String(e2);
			}
		} finally {
			submitting = false;
		}
	}
</script>

<svelte:head><title>{meta ? meta.title : t('booking.public.pickSlot')} · setjoin</title></svelte:head>

<div class="sj-book-page">
	<div class="sj-book-inner">
		<div class="sj-book-live" role="status" aria-live="assertive" aria-atomic="true">{liveAnnounce}</div>

		{#if loading}
			<p class="sj-book-loading">{t('common.loading')}</p>
		{:else if notFound}
			<Card><p class="sj-book-empty">{t('booking.public.notFound')}</p></Card>
		{:else if loadError}
			<Card>
				<p class="sj-book-empty" role="alert">{t('booking.public.loadError')}</p>
				<Button onclick={loadMeta}>{t('common.retry')}</Button>
			</Card>
		{:else if meta}
			<Card>
				<h1 class="sj-book-title">{meta.title}</h1>
				{#if meta.ownerName}<p class="sj-book-owner">{meta.ownerName}</p>{/if}
				{#if meta.description}<p class="sj-book-description">{meta.description}</p>{/if}
				<p class="sj-book-duration">{meta.durationMinutes} min</p>
				<p class="sj-book-tz-note">{t('booking.public.timezoneNote', { tz: browserTz })}</p>
			</Card>

			{#if submitted}
				<Card>
					<p class="sj-book-check-email">{t('booking.public.checkEmail', { email })}</p>
				</Card>
			{:else if !selectedSlot}
				<Card title={t('booking.public.pickSlot')}>
					<div class="sj-book-week-nav">
						<Button variant="ghost" size="sm" aria-label={t('booking.public.prevWeek')} disabled={weekOffset === 0} onclick={() => changeWeek(-1)}>
							←
						</Button>
						<Button variant="ghost" size="sm" aria-label={t('booking.public.nextWeek')} onclick={() => changeWeek(1)}>→</Button>
					</div>
					{#if slots.length === 0}
						<p class="sj-book-empty">{t('booking.public.slotGone')}</p>
					{:else}
						{#each [...slotsByDay.entries()] as [day, daySlots] (day)}
							<div class="sj-book-day-group">
								<h2 class="sj-book-day-heading">{day}</h2>
								<div class="sj-book-slot-grid">
									{#each daySlots as s (s.start)}
										<button type="button" class="sj-book-slot" aria-label={slotAriaLabel(s)} onclick={() => pick(s)}>
											{slotLabel(s)}
										</button>
									{/each}
								</div>
							</div>
						{/each}
					{/if}
				</Card>
			{:else}
				<Card title={t('booking.public.yourDetails')}>
					<p class="sj-book-selected">{slotAriaLabel(selectedSlot)}</p>
					<form class="sj-book-form" onsubmit={submit}>
						<Input label={t('booking.public.name')} bind:value={name} autocomplete="name" />
						<Input label={t('booking.public.email')} type="email" required bind:value={email} autocomplete="email" />
						{#each meta.questions as q (q.id)}
							<Textarea
								label={q.label}
								required={q.required}
								value={answers[q.id] ?? ''}
								oninput={(e2) => (answers[q.id] = e2.currentTarget.value)}
							/>
						{/each}
						<!-- Honeypot: hidden from sighted/keyboard users, present in the DOM
						     for bots that fill every field blindly. Never focusable, never
						     announced. -->
						<div class="sj-book-honeypot" aria-hidden="true">
							<label for="booking-website">Website</label>
							<input id="booking-website" name="website" type="text" tabindex="-1" autocomplete="off" bind:value={website} />
						</div>
						{#if submitError}<p class="sj-book-error" role="alert">{submitError}</p>{/if}
						<div class="sj-book-form-actions">
							<Button type="submit" variant="primary" disabled={submitting || !email}>{t('booking.public.book')}</Button>
							<Button type="button" variant="ghost" onclick={() => (selectedSlot = null)}>{t('common.cancel')}</Button>
						</div>
					</form>
				</Card>
			{/if}
		{/if}
	</div>
</div>

<style>
	.sj-book-page {
		min-height: 100vh;
		background: var(--surface-page);
	}
	.sj-book-inner {
		max-width: 560px;
		margin: 0 auto;
		padding: clamp(16px, 4vw, 32px) clamp(12px, 4vw, 20px) 48px;
		display: flex;
		flex-direction: column;
		gap: 16px;
	}
	.sj-book-live {
		position: absolute;
		width: 1px;
		height: 1px;
		overflow: hidden;
		clip-path: inset(50%);
		white-space: nowrap;
	}
	.sj-book-loading,
	.sj-book-empty {
		color: var(--text-secondary);
	}
	.sj-book-title {
		font-size: clamp(20px, 16px + 1.2vw, 24px);
		font-weight: 600;
		margin: 0;
		color: var(--text-primary);
	}
	.sj-book-owner,
	.sj-book-description {
		margin: 4px 0 0;
		color: var(--text-secondary);
		font-size: var(--text-sm);
	}
	.sj-book-duration {
		margin: 8px 0 0;
		color: var(--text-primary);
		font-weight: 500;
	}
	.sj-book-tz-note {
		margin: 4px 0 0;
		font-size: var(--text-xs);
		color: var(--text-caption);
	}
	.sj-book-week-nav {
		display: flex;
		justify-content: space-between;
		margin-bottom: var(--space-2);
	}
	.sj-book-day-group {
		margin-bottom: var(--space-3);
	}
	.sj-book-day-heading {
		font-size: var(--text-sm);
		font-weight: 600;
		color: var(--text-secondary);
		margin: 0 0 var(--space-1);
	}
	.sj-book-slot-grid {
		display: grid;
		grid-template-columns: repeat(auto-fill, minmax(88px, 1fr));
		gap: var(--space-1);
	}
	.sj-book-slot {
		padding: 8px 4px;
		border: 1px solid var(--border-default);
		border-radius: var(--radius-sm);
		background: var(--surface-elevated);
		color: var(--text-primary);
		cursor: pointer;
	}
	.sj-book-slot:hover,
	.sj-book-slot:focus-visible {
		border-color: var(--focus-ring);
		outline: none;
	}
	.sj-book-selected {
		font-weight: 500;
		color: var(--text-primary);
	}
	.sj-book-form {
		display: flex;
		flex-direction: column;
		gap: var(--space-3);
		margin-top: var(--space-2);
	}
	.sj-book-honeypot {
		position: absolute;
		width: 1px;
		height: 1px;
		overflow: hidden;
		clip-path: inset(50%);
		white-space: nowrap;
	}
	.sj-book-error {
		color: var(--danger-fg);
		font-size: var(--text-sm);
		margin: 0;
	}
	.sj-book-form-actions {
		display: flex;
		gap: var(--space-2);
	}
	.sj-book-check-email {
		color: var(--text-primary);
	}
</style>
