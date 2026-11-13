<svelte:options runes={true} />

<script lang="ts">
	import { onMount } from 'svelte';
	import {
		adminOfficeAppInstall,
		adminOfficeAppsGet,
		type OfficeAppsState
	} from '$lib/admin/client';
	import { isOfficeAppOperationTerminal } from '$lib/admin/office';
	import { adminPermissions, hasPermission } from '$lib/stores/auth';
	import { t } from '$lib/i18n';
	import { Badge, Button, Card, Dialog, Input, Spinner } from '$lib/components/ui';

	let apps = $state<OfficeAppsState | null>(null);
	let loading = $state(true);
	let refreshing = $state(false);
	let error = $state('');
	let installing = $state(false);
	let dialog = $state(false);
	let profile = $state('managed-customer-proxy');
	let reason = $state('');
	let ingressHostname = $state('');
	let canManage = $derived(hasPermission($adminPermissions, 'apps.manage'));
	let canViewOffice = $derived(
		hasPermission($adminPermissions, 'office.view') || hasPermission($adminPermissions, 'office.manage')
	);
	let provider = $derived(apps?.app.providerReadiness ?? null);
	let installAllowed = $derived(apps?.app.allowedActions.includes('install') ?? false);
	let autoRefreshing = $derived(
		apps?.operations.some((operation) => !isOfficeAppOperationTerminal(operation.state)) ?? false
	);

	function errorMessage(value: unknown, fallback: string): string {
		return value instanceof Error ? value.message : fallback;
	}

	function operationVariant(state: string): 'success' | 'danger' | 'warning' {
		if (state === 'connected_inactive') return 'success';
		if (state === 'failed_terminal') return 'danger';
		return 'warning';
	}

	function openInstallDialog(): void {
		dialog = true;
		reason = '';
		error = '';
	}

	function progressValue(progress: Record<string, unknown>, key: 'step' | 'steps', fallback: number): number {
		const value = progress[key];
		return typeof value === 'number' && Number.isFinite(value) && value >= 0 ? value : fallback;
	}

	function operationError(errorValue: Record<string, unknown> | null): string {
		if (!errorValue) return '';
		for (const key of ['detail', 'code']) {
			if (typeof errorValue[key] === 'string') return errorValue[key];
		}
		return t('admin.apps.unknown_failure');
	}

	async function load(): Promise<void> {
		if (apps) refreshing = true;
		else loading = true;
		try {
			apps = await adminOfficeAppsGet();
			error = '';
		} catch (loadError) {
			error = errorMessage(loadError, t('admin.apps.load_failed'));
		} finally {
			loading = false;
			refreshing = false;
		}
	}

	async function install(): Promise<void> {
		if (!provider?.ready || !installAllowed || !reason.trim() || !ingressHostname.trim()) {
			error = t('admin.apps.required');
			return;
		}
		installing = true;
		error = '';
		try {
			await adminOfficeAppInstall({
				providerId: provider.providerId,
				expectedProviderGeneration: provider.generation,
				profile,
				ingress: { hostname: ingressHostname.trim() },
				reason: reason.trim(),
				idempotencyKey: crypto.randomUUID()
			});
			dialog = false;
			await load();
		} catch (installError) {
			error = errorMessage(installError, t('admin.apps.install_failed'));
		} finally {
			installing = false;
		}
	}

	onMount(() => {
		void load();
		const timer = window.setInterval(() => {
			if (autoRefreshing && !refreshing) {
				void load();
			}
		}, 2000);
		return () => clearInterval(timer);
	});
</script>

<div class="apps-page">
	<header><div><h1>{t('admin.apps.title')}</h1><p>{t('admin.apps.subtitle')}</p></div><Button variant="ghost" size="sm" onclick={load} disabled={refreshing}>{refreshing ? t('admin.apps.refreshing') : t('admin.common.refresh')}</Button></header>
	{#if error}<div class="sj-alert sj-alert--danger" role="alert">{error}</div>{/if}
	{#if !canManage}<div class="sj-alert sj-alert--info" role="status">{t('admin.apps.view_only')}</div>{/if}
	{#if loading && !apps}<Spinner label={t('common.loading')} />{:else if apps}
		{@const currentApps = apps}
		<div aria-busy={refreshing}>
		<Card>{#snippet children()}<div class="app-head"><div><h2>{currentApps.app.name}</h2><p>{t('admin.apps.code_description')}</p></div><Badge variant="warning" label={t('admin.apps.test_channel')} dot={true} /></div>
		<dl><div><dt>{t('admin.apps.license')}</dt><dd>MPL-2.0</dd></div><div><dt>{t('admin.apps.support')}</dt><dd>{t('admin.apps.self_supported')}</dd></div><div><dt>{t('admin.apps.runtime')}</dt><dd>Docker · 127.0.0.1:9980</dd></div></dl>
		<div class="links"><a href="https://github.com/CollaboraOnline/online.mirror" rel="noreferrer">{t('admin.apps.source_code')}</a><a href="/admin/office">{t('admin.apps.office_routing')}</a></div>
		{#if canManage && installAllowed}<Button variant="primary" onclick={openInstallDialog}>{t('admin.apps.install')}</Button>{/if}
		{#if canManage && !currentApps.app.managedDeliveryEnabled}<div class="sj-alert sj-alert--warning">{t('admin.apps.flag_required')}</div>{/if}
		{#if canManage && (!provider || !provider.ready)}<div class="sj-alert sj-alert--warning"><strong>{t('admin.apps.provider_not_ready')}</strong><p>{provider?.remedy ?? t('admin.apps.provider_required')}</p>{#if canViewOffice}<a href="/admin/office">{t('admin.apps.open_office')}</a>{:else}<span>{t('admin.apps.contact_office_admin')}</span>{/if}</div>{/if}{/snippet}</Card>
		<section><h2>{t('admin.apps.revisions')}</h2>{#if currentApps.revisions.length===0}<p>{t('admin.apps.no_revisions')}</p>{:else}<div class="table-wrap"><table><thead><tr><th>{t('admin.apps.revision')}</th><th>{t('admin.apps.provider')}</th><th>{t('admin.apps.state')}</th><th>{t('admin.apps.image_digest')}</th><th>{t('admin.apps.created')}</th></tr></thead><tbody>{#each currentApps.revisions as revision (revision.revisionId)}<tr><td>{revision.revision}</td><td>{revision.providerId}</td><td><Badge variant={revision.state === 'active' ? 'success' : 'neutral'} label={revision.state} dot={true} /></td><td class="mono digest">{revision.imageDigest}</td><td>{revision.createdAt}</td></tr>{/each}</tbody></table></div>{/if}</section>
		<section><div class="section-head"><h2>{t('admin.apps.operations')}</h2>{#if autoRefreshing}<span class="auto-refresh" role="status" aria-live="polite"><Spinner size={16} label={t('admin.apps.auto_refreshing')} />{t('admin.apps.auto_refreshing')}</span>{/if}</div>{#if currentApps.operations.length===0}<p>{t('admin.apps.no_operations')}</p>{:else}<div class="operations">{#each currentApps.operations as op (op.operationId)}<Card>{#snippet children()}<div class="app-head"><strong>{op.kind} · {op.phase}</strong><Badge variant={operationVariant(op.state)} label={op.state} dot={true} /></div><progress value={progressValue(op.progress,'step',0)} max={progressValue(op.progress,'steps',7)} aria-label={t('admin.apps.operation_progress',{phase:op.phase})}></progress><p class="mono">{op.operationId}</p>{#if op.allowedActions.length > 0}<div class="allowed-actions"><span>{t('admin.apps.allowed_actions')}</span>{#each op.allowedActions as action}<Badge variant="neutral" label={action} />{/each}</div>{/if}{#if op.error}<div class="sj-alert sj-alert--danger">{operationError(op.error)}</div>{/if}{#if op.recovery}<dl class="recovery"><div><dt>{t('admin.apps.recovery_problem')}</dt><dd>{op.recovery.problem}</dd></div><div><dt>{t('admin.apps.recovery_effect')}</dt><dd>{op.recovery.effect}</dd></div><div><dt>{t('admin.apps.recovery_remedy')}</dt><dd>{op.recovery.remedy}</dd></div></dl>{/if}{/snippet}</Card>{/each}</div>{/if}</section>
		</div>
	{/if}
</div>

<Dialog open={dialog} title={t('admin.apps.install_title')} onClose={installing?undefined:()=>dialog=false}>{#snippet children()}<div class="dialog-body"><p>{t('admin.apps.install_notice')}</p>{#if !apps?.app.managedDeliveryEnabled}<div class="sj-alert sj-alert--warning">{t('admin.apps.flag_required')}</div>{/if}{#if !provider?.ready}<div class="sj-alert sj-alert--warning">{provider?.remedy ?? t('admin.apps.provider_required')}</div>{/if}<label>{t('admin.apps.ingress_mode')}<select bind:value={profile}><option value="managed-wildcard">{t('admin.apps.ingress_wildcard')}</option><option value="managed-customer-cert">{t('admin.apps.ingress_certificate')}</option><option value="managed-customer-proxy">{t('admin.apps.ingress_proxy')}</option></select></label><Input label={t('admin.apps.hostname')} bind:value={ingressHostname} /><Input label={t('admin.office.audit_reason')} bind:value={reason} required={true} /></div>{/snippet}{#snippet footer()}<Button variant="ghost" onclick={()=>dialog=false}>{t('common.cancel')}</Button><Button variant="primary" onclick={install} disabled={installing||!apps?.app.managedDeliveryEnabled||!provider?.ready||!installAllowed}>{installing?t('admin.apps.installing'):t('admin.apps.confirm_install')}</Button>{/snippet}</Dialog>

<style>
	.apps-page{max-width:960px}header,.app-head,.links,.section-head,.auto-refresh,.allowed-actions{display:flex;align-items:center;justify-content:space-between;gap:var(--space-3)}header p,.app-head p{color:var(--text-secondary);margin:var(--space-1) 0 0}section{margin-top:var(--space-7)}dl{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:var(--space-3)}dt{color:var(--text-secondary);font-size:var(--text-sm)}dd{margin:var(--space-1) 0}.links{justify-content:flex-start;margin:var(--space-4) 0}.links a,.sj-alert a{color:var(--accent)}.sj-alert p{margin:var(--space-1) 0}.operations,.dialog-body{display:grid;gap:var(--space-4)}progress{width:100%}.mono{font-family:var(--font-mono);font-size:var(--text-xs)}.digest{max-width:260px;overflow-wrap:anywhere}.table-wrap{overflow-x:auto}table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:var(--space-3);border-bottom:1px solid var(--border-subtle);vertical-align:top}th{color:var(--text-secondary);font-size:var(--text-sm)}.recovery{grid-template-columns:1fr}.auto-refresh,.allowed-actions{justify-content:flex-start;color:var(--text-secondary);font-size:var(--text-sm)}label{display:grid;gap:var(--space-2)}select{min-height:40px;border:1px solid var(--border-default);border-radius:var(--radius-md);background:var(--surface-primary);color:var(--text-primary);padding:0 var(--space-3)}

@media(max-width:700px){header,.app-head,.section-head{align-items:flex-start;flex-direction:column}dl{grid-template-columns:1fr}.dialog-body{min-width:0}.table-wrap{margin-inline:calc(-1 * var(--space-3))}}
</style>
