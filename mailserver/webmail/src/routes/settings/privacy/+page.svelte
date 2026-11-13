<svelte:options runes={true} />

<script lang="ts">
	import { onMount } from 'svelte';
	import { t, formatDate } from '$lib/i18n';
	import { parseError } from '$lib/errors';
	import { logger } from '$lib/logger';
	import { Card, Select, Switch, Button, EmptyState, showToast, Toast, Spinner } from '$lib/components/ui';
	import { imageTrust } from '$lib/stores/imageTrust.svelte';
	import type { ReceiptPolicy } from '$lib/mail/readReceipt';
	import { loadSessionStore } from '$lib/stores/session';
	import { createSettingsResource } from '$lib/composables/settings-resource.svelte';
	import { authedBootstrap } from '$lib/composables/authed-bootstrap.svelte';

	interface NotificationPrefs {
		device_fingerprint?: string;
		push_enabled: boolean;
		push_sound: string;
		stop_push_when_desktop_online: boolean;
		dnd_start?: string;
		dnd_end?: string;
		dnd_days: number;
		mail_notifications: string;
		calendar_reminders: boolean;
		task_reminders: boolean;
		read_receipt_policy: ReceiptPolicy;
	}

	interface NotificationPrefsResponse {
		preferences?: NotificationPrefs[];
	}

	interface ExternalSenderResponse {
		userEnabled?: boolean;
	}

	// Both settings resources run through the shared settings-resource
	// composable, which wraps the $lib/http seam (timeout/abort/401 handling,
	// typed errors) with per-instance pending/error state, supersede protection
	// and unmount abort. Save failures keep their authored display messages via
	// the seam's onError hook (never a raw server body).
	const prefsRes = createSettingsResource<NotificationPrefsResponse>({
		load: { url: '/api/user/notification-preferences', method: 'GET' },
	});
	const externalSenderRes = createSettingsResource<ExternalSenderResponse>({
		load: {
			url: '/api/settings/external-sender',
			method: 'GET',
			onError: () => t('privacy.external_labels_load_failed'),
		},
	});

	let globalPrefs: NotificationPrefs | null = $state(null);
	let policy: ReceiptPolicy = $state('ask');
	let loading = $state(true);
	let error = $state('');
	let externalLabelsEnabled = $state(true);
	let externalLabelsLoaded = $state(false);
	let externalLabelsSaving = $state(false);
	let externalLabelsError = $state('');

	// Trusted senders (WAVE-5 #5): the durable undo surface for the per-message
	// "Always load images from this sender" action. Shares the imageTrust cache
	// with the message cards, so removes reflect immediately in open threads.
	let trustError = $state('');
	let trustSettled = $state(false);
	let removing = $state<string | null>(null);

	async function removeTrusted(sender: string) {
		trustError = '';
		removing = sender;
		try {
			await imageTrust.remove(sender);
			showToast(t('privacy.trusted_senders_removed'));
		} catch (e) {
			trustError = parseError(e).message;
		} finally {
			removing = null;
		}
	}

	const policyOptions = $derived([
		{ value: 'ask', label: t('privacy.read_receipt_ask') },
		{ value: 'always', label: t('privacy.read_receipt_always') },
		{ value: 'never', label: t('privacy.read_receipt_never') },
	]);

	// WP5: authenticated mount bootstrap — the protected preference loads run
	// only after a proven session; an unproven page settles its loading state
	// and unmount aborts in-flight work (cleanup below).
	authedBootstrap(
		async (signal) => {
			imageTrust
				.ensureLoaded()
				.catch(() => {})
				.finally(() => (trustSettled = true));
			const prefsData = await prefsRes.load({ signal });
			if (prefsData) {
				const global = (prefsData.preferences ?? []).find(
					(p: NotificationPrefs) => !p.device_fingerprint
				);
				if (global) {
					globalPrefs = global;
					if (
						global.read_receipt_policy === 'ask' ||
						global.read_receipt_policy === 'always' ||
						global.read_receipt_policy === 'never'
					) {
						policy = global.read_receipt_policy;
					}
				}
			} else if (prefsRes.error) {
				error = prefsRes.error;
				logger.error('settings/privacy: failed to load', prefsRes.error);
			}
			const externalData = await externalSenderRes.load({ signal });
			if (externalData) {
				externalLabelsEnabled = externalData.userEnabled !== false;
				externalLabelsLoaded = true;
			} else if (externalSenderRes.error) {
				externalLabelsError = externalSenderRes.error;
				logger.error('settings/privacy: failed to load external-label preference', externalSenderRes.error);
			}
			loading = false;
		},
		{ onUnproven: () => { loading = false; } }
	);
	onMount(() => () => {
		prefsRes.cleanup();
		externalSenderRes.cleanup();
	});

	async function saveExternalLabels(next: boolean) {
		const prev = externalLabelsEnabled;
		externalLabelsEnabled = next;
		externalLabelsSaving = true;
		externalLabelsError = '';
		const result = await externalSenderRes.save({
			url: '/api/settings/external-sender',
			method: 'PUT',
			body: { enabled: next },
			onError: () => t('privacy.external_labels_save_failed'),
		});
		if (result.ok) {
			// Refresh the effective org-toggle ∧ user-toggle capability so open
			// message cards and compose windows update without a page reload.
			await loadSessionStore();
			showToast(t('settings.saved'));
		} else {
			externalLabelsEnabled = prev;
			externalLabelsError = externalSenderRes.saveError || t('privacy.external_labels_save_failed');
		}
		externalLabelsSaving = false;
	}

	async function savePolicy(next: ReceiptPolicy) {
		const prev = policy;
		policy = next;
		error = '';
		// Send the existing global prefs back unchanged (defaults when absent) plus the
		// new policy, so saving here never resets other notification preferences.
		const base = globalPrefs ?? {
			push_enabled: true,
			push_sound: 'default',
			stop_push_when_desktop_online: false,
			dnd_start: '',
			dnd_end: '',
			dnd_days: 127,
			mail_notifications: 'all',
			calendar_reminders: true,
			task_reminders: true,
			read_receipt_policy: 'ask' as ReceiptPolicy,
		};
		const result = await prefsRes.save({
			url: '/api/user/notification-preferences',
			method: 'PUT',
			body: {
				preferences: {
					push_enabled: base.push_enabled,
					push_sound: base.push_sound,
					stop_push_when_desktop_online: base.stop_push_when_desktop_online,
					dnd_start: base.dnd_start || null,
					dnd_end: base.dnd_end || null,
					dnd_days: base.dnd_days,
					mail_notifications: base.mail_notifications,
					calendar_reminders: base.calendar_reminders,
					task_reminders: base.task_reminders,
					read_receipt_policy: next,
				},
			},
			// Surface the backend's authored problem message; fall back to the
			// page's own display string (never a raw server body).
			onError: async (res) => {
				const data = (await res.json().catch(() => ({}))) as { error?: unknown };
				return typeof data.error === 'string' && data.error ? data.error : t('privacy.save_failed');
			},
		});
		if (result.ok) {
			globalPrefs = { ...base, device_fingerprint: undefined, read_receipt_policy: next };
			showToast(t('settings.saved'));
		} else {
			error = prefsRes.saveError;
			policy = prev;
		}
	}
</script>

<div class="sj-privacy-page">
	<h1 class="sj-page-title">{t('settings.title')}</h1>

	<Card title={t('privacy.card_title')}>
		{#if loading}
			<Spinner />
		{:else}
			<h2 class="sj-section-label">{t('privacy.external_labels_label')}</h2>
			<p class="sj-section-desc">{t('privacy.external_labels_desc')}</p>
			<Switch
				label={t('privacy.external_labels_toggle')}
				checked={externalLabelsEnabled}
				disabled={!externalLabelsLoaded || externalLabelsSaving}
				onchange={(e) => saveExternalLabels(e.currentTarget.checked)}
			/>
			{#if externalLabelsError}
				<p class="sj-error" role="alert">{externalLabelsError}</p>
			{/if}

			<div class="sj-section-divider"></div>
			<h2 class="sj-section-label">{t('privacy.read_receipt_label')}</h2>
			<p class="sj-section-desc">{t('privacy.read_receipt_desc')}</p>
			<div class="sj-policy-row">
				<label class="sj-policy-label" for="sj-read-receipt-policy">
					{t('privacy.read_receipt_label')}
				</label>
				<Select
					id="sj-read-receipt-policy"
					options={policyOptions}
					value={policy}
					onchange={(e: Event) =>
						savePolicy((e.currentTarget as HTMLSelectElement).value as ReceiptPolicy)}
				/>
			</div>
			{#if error}
				<p class="sj-error" role="alert">{error}</p>
			{/if}
		{/if}
	</Card>

	<Card title={t('privacy.trusted_senders_title')}>
		<p class="sj-section-desc">{t('privacy.trusted_senders_desc')}</p>
		{#if !trustSettled && !imageTrust.loaded}
			<Spinner />
		{:else if !imageTrust.loaded}
			<p class="sj-error" role="alert">{t('privacy.trusted_senders_load_failed')}</p>
		{:else if imageTrust.senders.length === 0}
			<EmptyState title={t('privacy.trusted_senders_empty')} />
		{:else}
			<ul class="sj-trusted-list">
				{#each imageTrust.senders as row (row.sender)}
					<li class="sj-trusted-row">
						<span class="sj-trusted-sender">{row.sender}</span>
						<span class="sj-trusted-date">{formatDate(row.createdAt)}</span>
						<Button
							size="sm"
							variant="ghost"
							disabled={removing === row.sender}
							aria-label={t('privacy.trusted_senders_remove', { sender: row.sender })}
							onclick={() => removeTrusted(row.sender)}
						>
							{t('common.remove')}
						</Button>
					</li>
				{/each}
			</ul>
		{/if}
		{#if trustError}
			<p class="sj-error" role="alert">{trustError}</p>
		{/if}
	</Card>
</div>

<Toast />

<style>
	.sj-privacy-page {
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

	.sj-section-label {
		font-size: var(--text-md);
		font-weight: 600;
		color: var(--text-primary);
		margin: 0 0 4px;
	}

	.sj-section-desc {
		font-size: var(--text-sm);
		color: var(--text-secondary);
		margin: 0 0 12px;
	}

	.sj-section-divider {
		height: 1px;
		background: var(--border-subtle);
		margin: 20px 0;
	}

	.sj-policy-row {
		display: flex;
		flex-direction: column;
		gap: 6px;
		max-width: 320px;
	}

	.sj-policy-label {
		font-size: var(--text-sm);
		font-weight: 500;
		color: var(--text-primary);
	}

	.sj-error {
		font-size: var(--text-sm);
		color: var(--danger-fg);
		margin: 12px 0 0;
	}

	.sj-trusted-list {
		list-style: none;
		margin: 0;
		padding: 0;
	}

	.sj-trusted-row {
		display: flex;
		align-items: center;
		gap: 12px;
		padding: 6px 0;
		border-bottom: 1px solid var(--border-subtle);
	}

	.sj-trusted-row:last-child {
		border-bottom: none;
	}

	.sj-trusted-sender {
		flex: 1;
		min-width: 0;
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
		font-family: var(--font-mono);
		font-size: var(--text-sm);
		color: var(--text-primary);
	}

	.sj-trusted-date {
		flex: none;
		font-size: var(--text-xs);
		color: var(--text-caption);
	}
</style>
