<svelte:options runes={true} />

<script lang="ts">
	import { onMount } from 'svelte';
	import { t } from '$lib/i18n';
	import { parseError } from '$lib/errors';
	import { logger } from '$lib/logger';
	import { Card, Switch, Select, Input, Button, showToast, Toast } from '$lib/components/ui';
	import { permissionState, enablePushNotifications, type PushPermissionState } from '$lib/push/subscribe';

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
	}

	let prefs: NotificationPrefs | null = $state(null);
	let loading = $state(true);
	let error = $state('');

	const dayNames = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'];
	const dayMasks = [1, 2, 4, 8, 16, 32, 64];

	let edit = $state({
		push_enabled: true,
		push_sound: 'default',
		stop_push_when_desktop_online: false,
		dnd_start: '',
		dnd_end: '',
		dnd_days: 127,
		mail_notifications: 'all',
		calendar_reminders: true,
		task_reminders: true,
	});

	// Browser push-subscribe state (QoL #9). Distinct from edit.push_enabled
	// above (a server-side "notify me" preference) — this is whether THIS
	// device/browser is actually subscribed to Web Push. Reading it on mount
	// is safe: permissionState() only reads Notification.permission, it never
	// prompts. The prompt fires ONLY from enablePush() below, itself only ever
	// called from the button's onclick.
	let pushState = $state<PushPermissionState>('unsupported');
	let pushBusy = $state(false);

	onMount(async () => {
		pushState = permissionState();
		try {
			const res = await fetch('/api/user/notification-preferences', { credentials: 'include' });
			if (res.ok) {
				const data = await res.json();
				const global = (data.preferences ?? []).find((p: NotificationPrefs) => !p.device_fingerprint);
				if (global) {
					prefs = global;
					edit = {
						push_enabled: global.push_enabled,
						push_sound: global.push_sound || 'default',
						stop_push_when_desktop_online: global.stop_push_when_desktop_online,
						dnd_start: global.dnd_start || '',
						dnd_end: global.dnd_end || '',
						dnd_days: global.dnd_days ?? 127,
						mail_notifications: global.mail_notifications || 'all',
						calendar_reminders: global.calendar_reminders ?? true,
						task_reminders: global.task_reminders ?? true,
					};
				}
			}
		} catch (e) {
			error = parseError(e).message;
			logger.error('settings/notifications: failed to load', e);
		}
		loading = false;
	});

	async function enablePush() {
		pushBusy = true;
		try {
			pushState = await enablePushNotifications();
			if (pushState === 'granted') showToast(t('settings.push_subscribe_enabled_toast'));
		} catch (e) {
			logger.error('settings/notifications: push subscribe failed', e);
			showToast(t('settings.push_subscribe_error'));
		} finally {
			pushBusy = false;
		}
	}

	function dayChecked(mask: number): boolean {
		return (edit.dnd_days & mask) !== 0;
	}

	function toggleDay(mask: number) {
		if (dayChecked(mask)) {
			edit.dnd_days &= ~mask;
		} else {
			edit.dnd_days |= mask;
		}
	}

	async function save() {
		error = '';
		try {
			const res = await fetch('/api/user/notification-preferences', {
				method: 'PUT',
				headers: { 'Content-Type': 'application/json' },
				credentials: 'include',
				body: JSON.stringify({
					preferences: {
						push_enabled: edit.push_enabled,
						push_sound: edit.push_sound,
						stop_push_when_desktop_online: edit.stop_push_when_desktop_online,
						dnd_start: edit.dnd_start || null,
						dnd_end: edit.dnd_end || null,
						dnd_days: edit.dnd_days,
						mail_notifications: edit.mail_notifications,
						calendar_reminders: edit.calendar_reminders,
						task_reminders: edit.task_reminders,
					},
				}),
			});
			if (res.ok) {
				prefs = { ...edit, device_fingerprint: undefined };
				showToast(t('settings.saved'));
			} else {
				const data = await res.json().catch(() => ({ error: 'Unknown error' }));
				error = data.error || 'Failed to save notification preferences.';
			}
		} catch (e) {
			error = parseError(e).message;
			logger.error('settings/notifications: failed to save', e);
		}
	}

	function resetEdit() {
		if (prefs) {
			edit = {
				push_enabled: prefs.push_enabled,
				push_sound: prefs.push_sound || 'default',
				stop_push_when_desktop_online: prefs.stop_push_when_desktop_online,
				dnd_start: prefs.dnd_start || '',
				dnd_end: prefs.dnd_end || '',
				dnd_days: prefs.dnd_days ?? 127,
				mail_notifications: prefs.mail_notifications || 'all',
				calendar_reminders: prefs.calendar_reminders ?? true,
				task_reminders: prefs.task_reminders ?? true,
			};
		}
	}
</script>

<div class="sj-notif-page">
	<h1 class="sj-page-title">{t('settings.notifications')}</h1>

	{#if loading}
		<p class="sj-loading">{t('common.loading')}</p>
	{:else if error && !prefs}
		<p class="sj-error">{error}</p>
	{:else}
		<Card title={t('settings.push_notifications')}>
			<div class="sj-form-group">
				{#if pushState === 'unsupported'}
					<p class="sj-push-hint">{t('settings.push_subscribe_unsupported')}</p>
				{:else if pushState === 'granted'}
					<p class="sj-push-hint">{t('settings.push_subscribe_granted')}</p>
				{:else if pushState === 'denied'}
					<p class="sj-push-hint sj-push-hint-warn">{t('settings.push_subscribe_denied')}</p>
				{:else}
					<Button variant="secondary" size="sm" disabled={pushBusy} onclick={enablePush}>
						{t('settings.push_subscribe_enable')}
					</Button>
				{/if}
			</div>
			<Switch label={t('settings.notif_enable_push')} checked={edit.push_enabled} onchange={(e) => { edit.push_enabled = e.currentTarget.checked; }} />
			<Switch label={t('settings.notif_stop_desktop')} checked={edit.stop_push_when_desktop_online} onchange={(e) => { edit.stop_push_when_desktop_online = e.currentTarget.checked; }} />
			<div class="sj-form-group">
				<Select
					label={t('settings.notif_sound')}
					options={[
						{ value: 'default', label: 'Default' },
						{ value: 'chime', label: 'Chime' },
						{ value: 'ping', label: 'Ping' },
						{ value: 'silent', label: 'Silent' }
					]}
					bind:value={edit.push_sound}
				/>
			</div>
		</Card>

		<Card title={t('settings.email_notifications')}>
			<div class="sj-form-group">
				<Select
					label={t('settings.notif_mail_about')}
					options={[
						{ value: 'all', label: 'All messages' },
						{ value: 'important', label: 'Important only' },
						{ value: 'off', label: 'Off' }
					]}
					bind:value={edit.mail_notifications}
				/>
			</div>
			<Switch label={t('settings.notif_calendar')} checked={edit.calendar_reminders} onchange={(e) => { edit.calendar_reminders = e.currentTarget.checked; }} />
			<Switch label={t('settings.notif_tasks')} checked={edit.task_reminders} onchange={(e) => { edit.task_reminders = e.currentTarget.checked; }} />
		</Card>

		<Card title={t('settings.dnd')}>
			<div class="sj-form-row">
				<div class="sj-form-group" style="flex:1">
					<Input label={t('settings.notif_dnd_start')} type="time" bind:value={edit.dnd_start} />
				</div>
				<div class="sj-form-group" style="flex:1">
					<Input label={t('settings.notif_dnd_end')} type="time" bind:value={edit.dnd_end} />
				</div>
			</div>

			<div class="sj-form-group">
				<span class="sj-field-label">{t('settings.notif_dnd_days')}</span>
				<div class="sj-day-chips">
					{#each dayNames as day, i}
						<button
							class="sj-chip"
							class:sj-chip-active={dayChecked(dayMasks[i])}
							onclick={() => toggleDay(dayMasks[i])}
						>
							{day}
						</button>
					{/each}
				</div>
			</div>
		</Card>

		<div class="sj-button-row">
			<Button variant="primary" size="sm" onclick={save}>{t('common.save')}</Button>
			<Button variant="secondary" size="sm" onclick={resetEdit}>{t('common.cancel')}</Button>
		</div>

		{#if error}
			<p class="sj-error">{error}</p>
		{/if}
	{/if}
</div>

<Toast />

<style>
	.sj-notif-page {
		max-width: 640px;
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

	.sj-form-group {
		margin: 4px 0 12px;
	}

	.sj-form-row {
		display: flex;
		gap: 12px;
	}

	.sj-field-label {
		display: block;
		font-size: var(--text-xs);
		font-weight: 500;
		color: var(--text-tertiary);
		text-transform: uppercase;
		letter-spacing: 0.04em;
		margin-bottom: 4px;
	}

	.sj-day-chips {
		display: flex;
		gap: 6px;
		margin-top: 4px;
		flex-wrap: wrap;
	}

	.sj-chip {
		padding: 4px 10px;
		border-radius: var(--radius-sm);
		border: 1px solid var(--border-default);
		background: var(--surface-card);
		color: var(--text-secondary);
		font-size: var(--text-sm);
		font-weight: 500;
		font-family: inherit;
		cursor: pointer;
		transition: background 0.15s ease, border-color 0.15s ease;
	}

	.sj-chip:hover { background: var(--surface-hover); }
	.sj-chip-active {
		background: var(--surface-selected);
		border-color: var(--border-accent);
		color: var(--text-accent);
	}

	.sj-button-row {
		display: flex;
		gap: 10px;
	}

	.sj-loading { color: var(--text-tertiary); }
	.sj-error { color: var(--danger-fg); font-size: var(--text-sm); }

	.sj-push-hint {
		font-size: var(--text-sm);
		color: var(--text-secondary);
		margin: 0;
	}
	.sj-push-hint-warn { color: var(--danger-fg); }
</style>
