<svelte:options runes={true} />

<script lang="ts">
	import { onMount } from 'svelte';
	import { t } from '$lib/i18n';
	import { parseError } from '$lib/errors';
	import { logger } from '$lib/logger';
	import { Card, Switch, Select, Input, Textarea, Button, showToast, Toast, Spinner } from '$lib/components/ui';

	// External-audience enum — mirrors the DB CHECK + set_vacation() BZ046 allowlist
	// (all | contacts | none). Every value here is one the reducer accepts.
	type ExternalAudience = 'all' | 'contacts' | 'none';

	// Wire shape for GET/PUT /user/automatic-replies (matches Go AutoReply). Identity
	// (which mailbox) is derived server-side from the JWT — never sent in this body.
	interface AutoReplyWire {
		enabled: boolean;
		subject: string;
		body_internal: string;
		body_internal_html: string;
		body_external: string;
		body_external_html: string;
		start_date: string | null; // "2026-07-01" or null
		end_date: string | null;
		external_audience: string;
	}

	let enabled = $state(false);
	let scheduled = $state(false);
	let subject = $state('');
	let bodyInternal = $state('');
	let bodyExternal = $state('');
	let startDate = $state('');
	let endDate = $state('');
	let audience = $state<ExternalAudience>('all');

	let loading = $state(true);
	let saving = $state(false);
	let error = $state('');

	const audienceOptions = $derived([
		{ value: 'all', label: t('autoReply.audience_all') },
		{ value: 'contacts', label: t('autoReply.audience_contacts') },
		{ value: 'none', label: t('autoReply.audience_none') }
	]);

	function coerceAudience(v: string): ExternalAudience {
		return v === 'all' || v === 'contacts' || v === 'none' ? v : 'all';
	}

	onMount(async () => {
		try {
			const res = await fetch('/api/user/automatic-replies', { credentials: 'include' });
			if (res.ok) {
				const data = (await res.json()) as AutoReplyWire;
				enabled = !!data.enabled;
				subject = data.subject ?? '';
				bodyInternal = data.body_internal ?? '';
				bodyExternal = data.body_external ?? '';
				startDate = data.start_date ?? '';
				endDate = data.end_date ?? '';
				scheduled = !!(data.start_date || data.end_date);
				audience = coerceAudience(data.external_audience ?? 'all');
			}
		} catch (e) {
			error = parseError(e).message;
			logger.error('settings/automatic-replies: failed to load', e);
		}
		loading = false;
	});

	async function save() {
		error = '';

		// Client-side guard for the inverted-range case the reducer rejects (BZ047). The
		// server stays the source of truth; this just keeps an obviously-bad request local.
		if (scheduled && startDate && endDate && startDate > endDate) {
			error = t('autoReply.date_range_error');
			return;
		}

		saving = true;
		const body: AutoReplyWire = {
			enabled,
			subject,
			body_internal: bodyInternal,
			body_internal_html: '',
			body_external: bodyExternal,
			body_external_html: '',
			// Dates only travel when the scheduled window is on; otherwise null = indefinite.
			start_date: scheduled && startDate ? startDate : null,
			end_date: scheduled && endDate ? endDate : null,
			external_audience: audience
		};
		try {
			const res = await fetch('/api/user/automatic-replies', {
				method: 'PUT',
				headers: { 'Content-Type': 'application/json' },
				credentials: 'include',
				body: JSON.stringify(body)
			});
			if (res.ok) {
				showToast(t('autoReply.saved'));
			} else {
				const data = (await res.json().catch(() => ({}))) as { detail?: string };
				error = data.detail || t('autoReply.save_failed');
			}
		} catch (e) {
			error = parseError(e).message;
			logger.error('settings/automatic-replies: failed to save', e);
		}
		saving = false;
	}
</script>

<div class="sj-ar-page">
	<h1 class="sj-page-title">{t('autoReply.title')}</h1>

	<Card title={t('autoReply.card_title')}>
		{#if loading}
			<Spinner />
		{:else}
			<div class="sj-ar-stack">
				<Switch
					label={t('autoReply.enable_label')}
					description={t('autoReply.enable_desc')}
					bind:checked={enabled}
				/>

				<Switch
					label={t('autoReply.schedule_label')}
					description={t('autoReply.schedule_desc')}
					bind:checked={scheduled}
				/>

				{#if scheduled}
					<div class="sj-ar-dates">
						<Input
							type="date"
							label={t('autoReply.start_date')}
							bind:value={startDate}
						/>
						<Input
							type="date"
							label={t('autoReply.end_date')}
							bind:value={endDate}
						/>
					</div>
				{/if}

				<Input
					label={t('autoReply.subject')}
					placeholder={t('autoReply.subject_placeholder')}
					bind:value={subject}
				/>

				<Textarea
					label={t('autoReply.internal_label')}
					placeholder={t('autoReply.internal_placeholder')}
					rows={4}
					bind:value={bodyInternal}
				/>

				<Select
					label={t('autoReply.external_audience_label')}
					options={audienceOptions}
					value={audience}
					onchange={(e) => {
						audience = coerceAudience((e.currentTarget as HTMLSelectElement).value);
					}}
				/>

				{#if audience !== 'none'}
					<Textarea
						label={t('autoReply.external_label')}
						placeholder={t('autoReply.external_placeholder')}
						rows={4}
						bind:value={bodyExternal}
					/>
				{/if}

				<div class="sj-ar-actions">
					<Button
						variant="primary"
						size="sm"
						onclick={save}
						disabled={saving}
						data-testid="ar-save"
					>
						{saving ? t('autoReply.saving') : t('autoReply.save')}
					</Button>
				</div>

				{#if error}
					<p class="sj-ar-error" role="alert">{error}</p>
				{/if}
			</div>
		{/if}
	</Card>
</div>

<Toast />

<style>
	.sj-ar-page {
		max-width: 720px;
		margin: 0 auto;
		padding: clamp(16px, 4vw, 28px) clamp(12px, 4vw, 24px) 48px;
	}

	.sj-page-title {
		font-size: clamp(20px, 16px + 1.2vw, 24px);
		font-weight: 600;
		letter-spacing: var(--tracking-display);
		margin: 0 0 16px;
		color: var(--text-primary);
	}

	.sj-ar-stack {
		display: flex;
		flex-direction: column;
		gap: 16px;
	}

	.sj-ar-dates {
		display: grid;
		grid-template-columns: 1fr 1fr;
		gap: 12px;
	}

	.sj-ar-actions {
		display: flex;
		gap: 8px;
		margin-top: 4px;
	}

	.sj-ar-error {
		font-size: var(--text-sm);
		color: var(--danger-fg);
		margin: 4px 0 0;
	}

	@container (max-width: 460px) {
		.sj-ar-dates {
			grid-template-columns: 1fr;
		}
	}
</style>
