<svelte:options runes={true} />

<script lang="ts">
	import {
		Dialog, Switch, Button, Badge,
		Spinner, showToast,
	} from '$lib/components/ui';
	import {
		adminUserAppAccess, adminUserSetAppAccess, adminFeatureList,
	} from '$lib/admin/client';
	import type { GuestApp } from '$lib/admin/guests';
	import { effectiveAccess, GLOBAL_FEATURE_MAP } from '$lib/admin/appAccess';
	import { adminPermissions, hasPermission } from '$lib/stores/auth';
	import { parseError } from '$lib/errors';
	import { t } from '$lib/i18n';

	let {
		open = false,
		userId = 0,
		userEmail = '',
		guestEntitlements = null,
		guestProfileName = '',
		embedded = false,
		onClose = () => {},
	}: {
		open?: boolean;
		userId?: number;
		userEmail?: string;
		guestEntitlements?: Record<GuestApp, boolean> | null;
		guestProfileName?: string;
		embedded?: boolean;
		onClose?: () => void;
	} = $props();

	interface AppRow {
		app: string;
		label: string;
		enabled: boolean;
		globalEnabled: boolean;
	}

	const APP_ORDER: GuestApp[] = ['mail', 'calendar', 'contacts', 'tasks', 'chat', 'drive', 'meet'];
	let isGuest = $derived(guestEntitlements !== null);

	let apps = $state<AppRow[]>([]);
	let loading = $state(true);
	let error = $state('');
	let saving = $state<string | null>(null);

	async function load() {
		if (!userId) return;
		loading = true;
		error = '';
		if (guestEntitlements) {
			apps = APP_ORDER.map((app) => ({
				app, label: t(`app.${app}`), enabled: guestEntitlements[app] === true, globalEnabled: true,
			}));
			loading = false;
			return;
		}
		try {
			let globalFeatures: Record<string, boolean> = {};
			try {
				const features = await adminFeatureList();
				for (const f of features) {
					globalFeatures[f.key] = f.enabled;
				}
			} catch {
				// Global features may fail if user lacks system console access; default to true.
			}

			const entitlements = await adminUserAppAccess(userId);
			apps = APP_ORDER.map(app => {
				const ent = entitlements.find(e => e.app === app);
				const enabled = ent ? ent.enabled : true;
				let globalEnabled = true;
				if (GLOBAL_FEATURE_MAP[app]) {
					globalEnabled = globalFeatures[GLOBAL_FEATURE_MAP[app]] !== false;
				}
				return {
					app,
					label: t(`app.${app}`),
					enabled,
					globalEnabled,
				};
			});
		} catch (e) {
			error = parseError(e).message;
		} finally {
			loading = false;
		}
	}

	async function toggleApp(row: AppRow) {
		if (isGuest) return;
		const newVal = !row.enabled;
		saving = row.app;
		try {
			await adminUserSetAppAccess(userId, row.app, newVal);
			row.enabled = newVal;
			showToast(t(newVal ? 'admin.appAccess.enabled' : 'admin.appAccess.disabled', { app: row.label }));
		} catch (e) {
			error = parseError(e).message;
		} finally {
			saving = null;
		}
	}

	$effect(() => {
		if ((open || embedded) && userId) {
			load();
		}
	});
</script>

{#snippet accessRows()}
		{#if loading}
			<div class="sj-aae-loading">
				<Spinner size={20} label={t('admin.appAccess.loading')} />
			</div>
		{:else if error}
			<div class="sj-alert-danger" role="alert">{error}</div>
		{:else if apps.length === 0}
			<p class="sj-aae-empty">{t('admin.appAccess.empty')}</p>
		{:else}
			<p class="sj-aae-hint">
				{isGuest
					? t('admin.appAccess.guestDerived', { profile: guestProfileName || t('admin.guests.noProfile') })
					: t('admin.appAccess.memberHint')}
			</p>
			<div class="sj-aae-rows">
				{#each apps as row (row.app)}
					<div class="sj-aae-row">
						<div class="sj-aae-info">
							<span class="sj-aae-label">{row.label}</span>
							{#if effectiveAccess(row.globalEnabled, row.enabled).limitedGlobally}
								<Badge variant="warning" label={t('admin.appAccess.globallyDisabled')} />
							{/if}
						</div>
						<Switch
							checked={row.enabled}
							label={row.label}
							disabled={isGuest || saving === row.app || effectiveAccess(row.globalEnabled, row.enabled).limitedGlobally || !hasPermission($adminPermissions, 'users.create')}
							onchange={() => toggleApp(row)}
						/>
					</div>
				{/each}
			</div>
		{/if}
	{/snippet}

{#if embedded}
	{@render accessRows()}
{:else}
	<Dialog {open} title={t('admin.appAccess.title', { email: userEmail })} onClose={onClose}>
	{#snippet children()}{@render accessRows()}{/snippet}
	{#snippet footer()}
		<Button variant="ghost" onclick={onClose}>{t('common.close')}</Button>
	{/snippet}
</Dialog>
{/if}

<style>
	.sj-aae-loading {
		padding: var(--space-6);
		display: flex;
		justify-content: center;
	}
	.sj-alert-danger {
		padding: var(--space-2) var(--space-3);
		border-radius: var(--radius-sm);
		margin-bottom: var(--space-2);
		font-size: var(--text-sm);
		background: var(--danger-bg);
		color: var(--danger-fg);
		border: 1px solid var(--danger-fg);
	}
	.sj-aae-empty {
		font-size: var(--text-sm);
		color: var(--text-caption);
		padding: var(--space-4) 0;
	}
	.sj-aae-hint {
		font-size: var(--text-sm);
		color: var(--text-caption);
		margin-bottom: var(--space-3);
		line-height: var(--leading-snug);
	}
	.sj-aae-rows {
		display: flex;
		flex-direction: column;
	}
	.sj-aae-row {
		display: flex;
		align-items: center;
		justify-content: space-between;
		gap: var(--space-3);
		padding: var(--space-2) 0;
		border-bottom: 1px solid var(--border-subtle);
	}
	.sj-aae-row:last-child {
		border-bottom: none;
	}
	.sj-aae-info {
		display: flex;
		align-items: center;
		gap: var(--space-2);
	}
	.sj-aae-label {
		font-size: var(--text-sm);
		font-weight: var(--weight-medium);
		color: var(--text-primary);
	}
</style>
