<svelte:options runes={true} />

<!--
	/settings/booking — owner config for self-service booking pages (feature #6,
	feature.booking_pages). List existing pages + create/edit form. A 404 on the
	list call means the feature is disabled by the admin (BookingFeatureOffError)
	— shown as a plain notice, not a load-fail retry (there's nothing to retry).
-->

<script lang="ts">
	import { onMount } from 'svelte';
	import { Card, Button, Input, Textarea, Switch, showToast } from '$lib/components/ui';
	import { t } from '$lib/i18n';
	import {
		listBookingPages,
		upsertBookingPage,
		deleteBookingPage,
		BookingFeatureOffError,
		type BookingPage,
		type BookingAvailabilityWindow
	} from '$lib/api/booking';
	import { parseError } from '$lib/errors';

	const DOW_LABELS = ['sun', 'mon', 'tue', 'wed', 'thu', 'fri', 'sat'] as const;
	const DEFAULT_WINDOW = { start: '09:00', end: '17:00' };

	type DayRow = { enabled: boolean; start: string; end: string };

	function emptyDays(): DayRow[] {
		return DOW_LABELS.map((_, i) => ({
			enabled: i >= 1 && i <= 5, // Mon-Fri, matches the server-side default
			start: DEFAULT_WINDOW.start,
			end: DEFAULT_WINDOW.end
		}));
	}

	function daysFromAvailability(av: BookingAvailabilityWindow[]): DayRow[] {
		const days = DOW_LABELS.map(() => ({ enabled: false, start: DEFAULT_WINDOW.start, end: DEFAULT_WINDOW.end }));
		for (const w of av) {
			if (w.dow >= 0 && w.dow <= 6) days[w.dow] = { enabled: true, start: w.start, end: w.end };
		}
		return days;
	}

	function availabilityFromDays(days: DayRow[]): BookingAvailabilityWindow[] {
		return days
			.map((d, dow) => ({ dow, start: d.start, end: d.end, enabled: d.enabled }))
			.filter((d) => d.enabled)
			.map(({ dow, start, end }) => ({ dow, start, end }));
	}

	function emptyForm(): BookingPage {
		return {
			slug: '',
			title: '',
			description: '',
			durationMinutes: 30,
			bufferMinutes: 0,
			maxPerDay: 8,
			minNoticeMinutes: 120,
			maxAdvanceDays: 60,
			availability: [],
			questions: [],
			timezone: Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC',
			enabled: true
		};
	}

	let pages = $state<BookingPage[]>([]);
	let loading = $state(true);
	let featureOff = $state(false);
	let loadError = $state('');
	let saving = $state(false);
	let announce = $state('');
	let editing = $state<BookingPage | null>(null);
	let days = $state<DayRow[]>(emptyDays());

	onMount(load);

	async function load() {
		loading = true;
		loadError = '';
		featureOff = false;
		try {
			pages = await listBookingPages();
		} catch (e) {
			if (e instanceof BookingFeatureOffError) {
				featureOff = true;
			} else {
				loadError = parseError(e).message;
			}
		} finally {
			loading = false;
		}
	}

	function startCreate() {
		editing = emptyForm();
		days = emptyDays();
	}

	function startEdit(page: BookingPage) {
		editing = { ...page, questions: [...page.questions] };
		days = daysFromAvailability(page.availability);
	}

	function cancelEdit() {
		editing = null;
	}

	function addQuestion() {
		if (!editing) return;
		editing.questions = [...editing.questions, { id: `q${Date.now()}`, label: '', required: false }];
	}

	function removeQuestion(id: string) {
		if (!editing) return;
		editing.questions = editing.questions.filter((q) => q.id !== id);
	}

	function randomizeSlug() {
		if (!editing) return;
		editing.slug = `book-${Math.random().toString(36).slice(2, 8)}`;
	}

	async function save() {
		if (!editing || saving) return;
		saving = true;
		try {
			const payload = { ...editing, availability: availabilityFromDays(days) };
			await upsertBookingPage(payload);
			announce = t('booking.settings.saved');
			editing = null;
			await load();
		} catch (e) {
			loadError = parseError(e).message;
		} finally {
			saving = false;
		}
	}

	async function remove(page: BookingPage) {
		if (!page.id || saving) return;
		// Destructive-confirm parity (S19): rules/storage/security gate their
		// deletes; a booking-page delete (users' live /book/ links stop working)
		// must not fire on a single click.
		if (typeof window !== 'undefined' && !window.confirm(t('common.confirm_delete_message'))) return;
		saving = true;
		try {
			await deleteBookingPage(page.id);
			await load();
		} catch (e) {
			loadError = parseError(e).message;
		} finally {
			saving = false;
		}
	}

	async function copyLink(slug: string) {
		const link = `${location.origin}/book/${slug}`;
		try {
			await navigator.clipboard.writeText(link);
			announce = t('booking.settings.copyLink') + ': ' + link;
			showToast(t('booking.settings.copyLink'));
		} catch {
			/* clipboard unavailable — the link is still shown in the row */
		}
	}
</script>

<svelte:head><title>{t('booking.settings.title')} · setjoin</title></svelte:head>

<div class="sj-booking-page">
	<div class="sj-booking-inner">
		<h1 class="sj-page-title">{t('booking.settings.title')}</h1>
		<p class="sj-booking-subtitle">{t('booking.settings.description')}</p>

		<div class="sj-booking-announce" role="status" aria-live="polite" aria-atomic="true">{announce}</div>

		{#if loading}
			<Card><p class="sj-booking-empty">{t('common.loading')}</p></Card>
		{:else if featureOff}
			<Card><p class="sj-booking-empty">{t('booking.settings.featureOff')}</p></Card>
		{:else}
			{#if loadError}
				<Card><p class="sj-booking-error" role="alert">{loadError}</p></Card>
			{/if}

			{#if editing}
				<Card title={editing.id ? editing.title : t('booking.settings.newPage')}>
					<div class="sj-booking-form">
						<Input label={t('booking.settings.pageTitle')} bind:value={editing.title} />
						<div class="sj-booking-slug-row">
							<Input label={t('booking.settings.slug')} hint={t('booking.settings.slugHint')} bind:value={editing.slug} />
							<Button variant="ghost" size="sm" onclick={randomizeSlug}>{t('booking.settings.randomize')}</Button>
						</div>
						<Textarea label={t('booking.settings.pageDescription')} bind:value={editing.description} />

						<div class="sj-booking-grid">
							<Input
								type="number"
								label={t('booking.settings.duration')}
								value={String(editing.durationMinutes)}
								oninput={(e) => (editing!.durationMinutes = Number(e.currentTarget.value) || 30)}
							/>
							<Input
								type="number"
								label={t('booking.settings.buffer')}
								value={String(editing.bufferMinutes)}
								oninput={(e) => (editing!.bufferMinutes = Number(e.currentTarget.value) || 0)}
							/>
							<Input
								type="number"
								label={t('booking.settings.maxPerDay')}
								value={String(editing.maxPerDay)}
								oninput={(e) => (editing!.maxPerDay = Number(e.currentTarget.value) || 1)}
							/>
							<Input
								type="number"
								label={t('booking.settings.minNotice')}
								value={String(editing.minNoticeMinutes)}
								oninput={(e) => (editing!.minNoticeMinutes = Number(e.currentTarget.value) || 0)}
							/>
							<Input
								type="number"
								label={t('booking.settings.maxAdvance')}
								value={String(editing.maxAdvanceDays)}
								oninput={(e) => (editing!.maxAdvanceDays = Number(e.currentTarget.value) || 1)}
							/>
						</div>

						<Switch label={t('booking.settings.enabled')} bind:checked={editing.enabled} />

						<fieldset class="sj-booking-availability">
							<legend>{t('booking.settings.availability')}</legend>
							{#each days as day, i (i)}
								<div class="sj-booking-day-row">
									<Switch label={t(`booking.settings.dow.${DOW_LABELS[i]}`)} bind:checked={day.enabled} />
									{#if day.enabled}
										<label class="sj-booking-time-label">
											<span class="sj-sr-only">{t('booking.settings.dayStart')}</span>
											<input type="time" bind:value={day.start} />
										</label>
										<span aria-hidden="true">–</span>
										<label class="sj-booking-time-label">
											<span class="sj-sr-only">{t('booking.settings.dayEnd')}</span>
											<input type="time" bind:value={day.end} />
										</label>
									{/if}
								</div>
							{/each}
						</fieldset>

						<fieldset class="sj-booking-questions">
							<legend>{t('booking.settings.questions')}</legend>
							{#each editing.questions as q (q.id)}
								<div class="sj-booking-question-row">
									<Input
										label={t('booking.settings.questionLabel')}
										value={q.label}
										oninput={(e) => (q.label = e.currentTarget.value)}
									/>
									<Switch label={t('booking.settings.questionRequired')} bind:checked={q.required} />
									<Button variant="ghost" size="sm" onclick={() => removeQuestion(q.id)}>
										{t('common.remove')}
									</Button>
								</div>
							{/each}
							<Button variant="secondary" size="sm" onclick={addQuestion}>
								{t('booking.settings.addQuestion')}
							</Button>
						</fieldset>

						<div class="sj-booking-form-actions">
							<Button variant="primary" disabled={saving || !editing.slug || !editing.title} onclick={save}>
								{t('common.save')}
							</Button>
							<Button variant="ghost" onclick={cancelEdit}>{t('common.cancel')}</Button>
						</div>
					</div>
				</Card>
			{:else}
				<Card title={t('booking.settings.title')}>
					{#if pages.length === 0}
						<p class="sj-booking-empty">{t('booking.settings.noPages')}</p>
					{:else}
						<ul class="sj-booking-list">
							{#each pages as page (page.id)}
								<li class="sj-booking-row">
									<div class="sj-booking-who">
										<span class="sj-booking-name">{page.title}</span>
										<span class="sj-booking-slug">/book/{page.slug}{page.enabled ? '' : ` (${t('booking.settings.disabled')})`}</span>
									</div>
									<div class="sj-booking-row-actions">
										<Button variant="ghost" size="sm" onclick={() => copyLink(page.slug)}>
											{t('booking.settings.copyLink')}
										</Button>
										<Button variant="ghost" size="sm" onclick={() => startEdit(page)}>{t('common.edit')}</Button>
										<Button variant="ghost" size="sm" disabled={saving} onclick={() => remove(page)}>
											{t('booking.settings.delete')}
										</Button>
									</div>
								</li>
							{/each}
						</ul>
					{/if}
					<div class="sj-booking-actions">
						<Button variant="secondary" size="sm" onclick={startCreate}>{t('booking.settings.newPage')}</Button>
					</div>
				</Card>
			{/if}
		{/if}
	</div>
</div>

<style>
	.sj-booking-page {
		height: 100%;
		overflow-y: auto;
		background: var(--surface-page);
	}
	.sj-booking-inner {
		max-width: 720px;
		margin: 0 auto;
		padding: clamp(16px, 4vw, 28px) clamp(12px, 4vw, 24px) 48px;
		display: flex;
		flex-direction: column;
		gap: 16px;
	}
	.sj-page-title {
		font-size: clamp(20px, 16px + 1.2vw, 24px);
		font-weight: 600;
		letter-spacing: var(--tracking-display);
		margin: 0;
		color: var(--text-primary);
	}
	.sj-booking-subtitle {
		font-size: var(--text-sm);
		color: var(--text-secondary);
		margin: 4px 0 0;
	}
	.sj-booking-announce {
		position: absolute;
		width: 1px;
		height: 1px;
		overflow: hidden;
		clip-path: inset(50%);
		white-space: nowrap;
	}
	.sj-booking-empty,
	.sj-booking-error {
		margin: 0;
		font-size: var(--text-sm);
		color: var(--text-secondary);
	}
	.sj-booking-error {
		color: var(--danger-fg);
	}
	.sj-booking-list {
		list-style: none;
		margin: 0;
		padding: 0;
		display: flex;
		flex-direction: column;
		gap: var(--space-1);
	}
	.sj-booking-row {
		display: flex;
		align-items: center;
		justify-content: space-between;
		padding: var(--space-2) var(--space-3);
		border: 1px solid var(--border-default);
		border-radius: var(--radius-sm);
		gap: var(--space-2);
	}
	.sj-booking-row-actions {
		display: flex;
		gap: var(--space-1);
	}
	.sj-booking-who {
		display: flex;
		flex-direction: column;
		min-width: 0;
	}
	.sj-booking-name {
		color: var(--text-primary);
	}
	.sj-booking-slug {
		font-size: var(--text-sm);
		color: var(--text-caption);
	}
	.sj-booking-actions {
		margin-top: 12px;
	}
	.sj-booking-form {
		display: flex;
		flex-direction: column;
		gap: var(--space-3);
	}
	.sj-booking-slug-row {
		display: flex;
		align-items: flex-end;
		gap: var(--space-2);
	}
	.sj-booking-grid {
		display: grid;
		grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
		gap: var(--space-2);
	}
	.sj-booking-availability,
	.sj-booking-questions {
		border: 1px solid var(--border-default);
		border-radius: var(--radius-sm);
		padding: var(--space-3);
		display: flex;
		flex-direction: column;
		gap: var(--space-2);
	}
	.sj-booking-day-row {
		display: flex;
		align-items: center;
		gap: var(--space-2);
	}
	.sj-booking-time-label input[type='time'] {
		padding: 4px 8px;
		border: 1px solid var(--border-default);
		border-radius: var(--radius-sm);
		background: var(--surface-elevated);
		color: var(--text-primary);
	}
	.sj-booking-question-row {
		display: flex;
		align-items: flex-end;
		gap: var(--space-2);
	}
	.sj-booking-form-actions {
		display: flex;
		gap: var(--space-2);
	}
	.sj-sr-only {
		position: absolute;
		width: 1px;
		height: 1px;
		overflow: hidden;
		clip-path: inset(50%);
		white-space: nowrap;
	}
</style>
