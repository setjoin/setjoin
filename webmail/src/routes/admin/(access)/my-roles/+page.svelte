<svelte:options runes={true} />

<script lang="ts">
	import { onMount } from 'svelte';
	import { Card, Button, Spinner, EmptyState, Tooltip, showToast } from '$lib/components/ui';
	import Icon from '$lib/components/Icon.svelte';
	import { adminConsoles } from '$lib/stores/auth';
	import {
		adminMyRoles,
		adminDeactivateRole,
		type MyRole,
		type ActivateResult,
	} from '$lib/admin/client';
	import {
		roleStatus,
		remainingMs,
		remainingMinutes,
		splitWindow,
		type JitStatus,
	} from '$lib/admin/jitStatus';
	import ActivateRoleDialog from '$lib/components/admin/ActivateRoleDialog.svelte';
	import { parseError } from '$lib/errors';
	import { t } from '$lib/i18n';

	let roles = $state<MyRole[]>([]);
	let loading = $state(true);
	let error = $state('');
	let now = $state(Date.now());
	let activateTarget = $state<MyRole | null>(null);

	// Tracks which roles were last seen active, so the expiry toast fires once.
	const wasActive = new Set<number>();

	onMount(load);

	// Live countdown tick. Drives the status flip + the polite live region.
	$effect(() => {
		const iv = setInterval(() => (now = Date.now()), 1000);
		return () => clearInterval(iv);
	});

	// One-time "window ended" toast when an active role lapses (local clock crossing).
	$effect(() => {
		const n = now;
		for (const role of roles) {
			const st = roleStatus(role, n);
			const isActive = st === 'active' || st === 'expiring';
			if (isActive) {
				wasActive.add(role.roleGroupId);
			} else if (wasActive.has(role.roleGroupId)) {
				wasActive.delete(role.roleGroupId);
				showToast(t('admin.jit.expired_toast', { name: role.name }));
			}
		}
	});

	async function load() {
		loading = true;
		error = '';
		try {
			roles = await adminMyRoles();
		} catch (e) {
			error = parseError(e).message;
		} finally {
			loading = false;
		}
	}

	function fmt(minutes: number): string {
		const w = splitWindow(minutes);
		return t(w.unit === 'hr' ? 'admin.jit.dur_hr' : 'admin.jit.dur_min', { n: String(w.n) });
	}

	function statusLabel(role: MyRole, st: JitStatus, n: number): string {
		switch (st) {
			case 'standing':
				return t('admin.jit.status.standing');
			case 'dormant':
				return t('admin.jit.status.dormant');
			default: {
				const m = remainingMinutes(role, n);
				return m < 1 ? t('admin.jit.status.active_lt') : t('admin.jit.status.active', { n: String(m) });
			}
		}
	}

	const STATUS_ICON: Record<JitStatus, string> = {
		standing: 'ShieldCheck',
		dormant: 'Moon',
		active: 'Clock',
		expiring: 'AlertTriangle',
	};

	function policyInline(role: MyRole): string {
		return t('admin.jit.policy_inline', {
			window: fmt(role.policy.maxDurationMinutes),
			justif: role.policy.requireJustification
				? t('admin.jit.justif_required')
				: t('admin.jit.justif_optional'),
		});
	}

	// Polite live region: the soonest-expiring active role, refreshed each minute.
	let liveSummary = $derived.by(() => {
		const active = roles.filter((r) => {
			const s = roleStatus(r, now);
			return s === 'active' || s === 'expiring';
		});
		if (active.length === 0) return t('admin.jit.live_none');
		const soonest = active.reduce((a, b) => (remainingMs(a, now) < remainingMs(b, now) ? a : b));
		const time = new Date(soonest.activatedUntil!).toLocaleTimeString([], {
			hour: '2-digit',
			minute: '2-digit',
		});
		return t('admin.jit.live_summary', {
			name: soonest.name,
			time,
			n: String(remainingMinutes(soonest, now)),
		});
	});

	// D10 dormant-admin gate: zero live consoles + an eligible role to activate.
	let dormantAdmin = $derived(
		$adminConsoles.length === 0 && roles.some((r) => r.eligible && roleStatus(r, now) === 'dormant')
	);
	let firstDormant = $derived(roles.find((r) => r.eligible && roleStatus(r, now) === 'dormant') ?? null);

	function onActivated(_result: ActivateResult) {
		const name = activateTarget?.name ?? '';
		activateTarget = null;
		showToast(t('admin.jit.activated_toast', { name }));
		void load();
	}

	async function deactivate(role: MyRole) {
		try {
			await adminDeactivateRole(role.roleGroupId);
			showToast(t('admin.jit.deactivated_toast', { name: role.name }));
			await load();
		} catch (e) {
			error = parseError(e).message;
		}
	}
</script>

<div class="sj-admin-page">
	<header class="sj-admin-head">
		<h1>{t('admin.jit.my_roles_title')}</h1>
		<span class="jit-sub">{t('admin.jit.my_roles_subtitle')}</span>
	</header>

	{#if error}<div class="sj-alert-danger" role="alert">{error}</div>{/if}

	{#if dormantAdmin && firstDormant}
		<div class="jit-banner">
			<Icon name="ShieldCheck" size={20} aria-hidden={true} />
			<div class="jit-banner-text">
				<strong>{t('admin.jit.banner_title')}</strong>
				<span class="jit-muted">{t('admin.jit.banner_body')}</span>
			</div>
			<Button variant="primary" onclick={() => (activateTarget = firstDormant)}>
				{t('admin.jit.banner_cta')}
			</Button>
		</div>
	{/if}

	<Card flush={true}>
		{#if loading}
			<div class="jit-loading"><Spinner size={20} label={t('common.loading')} /></div>
		{:else if roles.length === 0}
			<EmptyState title={t('admin.jit.none_body')} />
		{:else}
			<ul class="jit-rows">
				{#each roles as role (role.roleGroupId)}
					{@const st = roleStatus(role, now)}
					<li class="jit-row">
						<div class="jit-row-main">
							<div class="jit-role-name">
								<span class="jit-role">{role.name}</span>
								{#if st === 'dormant'}
									<Tooltip text={t('admin.jit.concept_tip')}>
										<button type="button" class="jit-info" aria-label={t('admin.jit.concept_aria')}>
											<Icon name="Info" size={14} aria-hidden={true} />
										</button>
									</Tooltip>
								{/if}
							</div>
							{#if role.scope}
								<span class="jit-meta">{role.scope}</span>
							{/if}
							{#if role.eligible && st === 'dormant'}
								<span class="jit-meta">{policyInline(role)}</span>
							{/if}
						</div>

						<span class="jit-status jit-status--{st}">
							<span class="jit-dot" aria-hidden="true"></span>
							<Icon name={STATUS_ICON[st] as never} size={13} aria-hidden={true} />
							{statusLabel(role, st, now)}
						</span>

						<div class="jit-action">
							{#if st === 'standing'}
								<span class="jit-muted">{t('admin.jit.always_on')}</span>
							{:else if st === 'dormant'}
								<Button variant="primary" size="sm" onclick={() => (activateTarget = role)}>
									<Icon name="Zap" size={14} aria-hidden={true} />
									{t('admin.jit.activate')}
								</Button>
							{:else if st === 'expiring'}
								<Button variant="primary" size="sm" onclick={() => (activateTarget = role)}>
									{t('admin.jit.extend')}
								</Button>
							{:else}
								<Button variant="secondary" size="sm" onclick={() => deactivate(role)}>
									<Icon name="LogOut" size={14} aria-hidden={true} />
									{t('admin.jit.deactivate')}
								</Button>
							{/if}
						</div>
					</li>
				{/each}
			</ul>
			<div class="jit-live" aria-live="polite">{liveSummary}</div>
		{/if}
	</Card>
</div>

{#if activateTarget}
	<ActivateRoleDialog
		role={activateTarget}
		onClose={() => (activateTarget = null)}
		{onActivated}
	/>
{/if}

<style>
	.sj-admin-page {
		padding: var(--space-4);
		display: flex;
		flex-direction: column;
		gap: var(--space-3);
	}
	.sj-admin-head {
		display: flex;
		justify-content: space-between;
		align-items: baseline;
		gap: var(--space-3);
		flex-wrap: wrap;
	}
	.jit-sub {
		color: var(--text-tertiary);
		font-size: var(--text-sm);
	}
	.jit-muted {
		color: var(--text-tertiary);
		font-size: var(--text-sm);
	}
	.jit-banner {
		display: flex;
		align-items: center;
		gap: var(--space-3);
		padding: var(--space-3) var(--space-4);
		background: var(--accent-subtle);
		border: 1px solid var(--accent);
		border-radius: var(--radius-md);
		color: var(--accent);
	}
	.jit-banner-text {
		flex: 1;
		display: flex;
		flex-direction: column;
		gap: 2px;
	}
	.jit-banner-text strong {
		color: var(--text-primary);
		font-size: var(--text-sm);
	}
	.jit-loading {
		display: flex;
		justify-content: center;
		padding: var(--space-5);
	}
	.jit-rows {
		list-style: none;
		margin: 0;
		padding: 0;
	}
	.jit-row {
		display: flex;
		align-items: center;
		gap: var(--space-3);
		padding: var(--space-3) var(--space-4);
		border-bottom: 1px solid var(--border-subtle);
		min-height: 44px;
	}
	.jit-row:last-child {
		border-bottom: none;
	}
	.jit-row-main {
		flex: 1;
		min-width: 0;
		display: flex;
		flex-direction: column;
		gap: 2px;
	}
	.jit-role-name {
		display: flex;
		align-items: center;
		gap: var(--space-1);
	}
	.jit-role {
		font-weight: var(--weight-semibold);
		color: var(--text-primary);
	}
	.jit-meta {
		font-size: var(--text-xs);
		color: var(--text-tertiary);
	}
	.jit-info {
		display: inline-flex;
		align-items: center;
		justify-content: center;
		width: 24px;
		height: 24px;
		background: none;
		border: none;
		cursor: help;
		color: var(--text-tertiary);
		border-radius: var(--radius-xs);
	}
	.jit-info:focus-visible {
		outline: none;
		box-shadow: var(--focus-ring);
	}
	.jit-status {
		display: inline-flex;
		align-items: center;
		gap: var(--space-1);
		font-size: var(--text-xs);
		font-weight: var(--weight-medium);
		padding: 3px var(--space-2);
		border-radius: var(--radius-full, 9999px);
		border: 1px solid transparent;
		white-space: nowrap;
		flex-shrink: 0;
	}
	.jit-dot {
		width: 7px;
		height: 7px;
		border-radius: 50%;
		background: currentcolor;
	}
	.jit-status--standing {
		background: var(--accent-subtle);
		color: var(--accent);
		border-color: var(--accent);
	}
	.jit-status--dormant {
		background: var(--surface-sunken);
		color: var(--text-secondary);
		border-color: var(--border-default);
	}
	.jit-status--active {
		background: var(--success-bg);
		color: var(--success-fg);
		border-color: var(--success-fg);
	}
	.jit-status--expiring {
		background: var(--warning-bg);
		color: var(--warning-fg);
		border-color: var(--warning-fg);
	}
	.jit-action {
		flex-shrink: 0;
		display: flex;
		align-items: center;
	}
	.jit-live {
		padding: var(--space-2) var(--space-4);
		font-size: var(--text-xs);
		color: var(--text-tertiary);
		border-top: 1px dashed var(--border-subtle);
	}
</style>
