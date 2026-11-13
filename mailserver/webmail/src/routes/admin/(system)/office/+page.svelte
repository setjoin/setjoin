<svelte:options runes={true} />

<script lang="ts">
	import { onMount } from 'svelte';
	import {
		adminFeatureSet,
		adminOfficeActivateProvider,
		adminOfficeConfigureProvider,
		adminOfficeGet,
		adminOfficeQualifyProvider,
		adminOfficeRemoveProvider,
		type OfficeAdminState,
		type OfficeProviderPolicy
	} from '$lib/admin/client';
	import { adminPermissions, hasPermission } from '$lib/stores/auth';
	import { t } from '$lib/i18n';
	import { Badge, Button, Card, Dialog, EmptyState, Input, Spinner, showToast } from '$lib/components/ui';

	let officeState = $state<OfficeAdminState | null>(null);
	let loading = $state(true);
	let error = $state('');
	let saving = $state(false);
	let wizard = $state(false);
	let step = $state(1);
	let provider = $state<OfficeProviderPolicy | null>(null);
	let qualificationTarget = $state<{ providerId: string; generation: number } | null>(null);
	let discoveryUrl = $state('');
	let wopiBaseUrl = $state('');
	let editorUrl = $state('');
	let buildId = $state('');
	let allowHosts = $state('');
	let allowCidrs = $state('');
	let reason = $state('');
	let receiptId = $state('');
	let mutationError = $state('');
	let activating = $state<{ provider: OfficeProviderPolicy; qualificationId: string } | null>(null);
	let removing = $state<OfficeProviderPolicy | null>(null);
	let featureChange = $state<{ key: string; enabled: boolean; label: string } | null>(null);
	let canManage = $derived(hasPermission($adminPermissions, 'office.manage'));
	let canConfigureFeatures = $derived(hasPermission($adminPermissions, 'system.config'));
	let wizardSteps = $derived([
		{ number: 1, label: t('admin.office.step_name_endpoints') },
		{ number: 2, label: t('admin.office.step_name_trust') },
		{ number: 3, label: t('admin.office.step_name_review') },
		{ number: 4, label: t('admin.office.step_name_qualification') },
		{ number: 5, label: t('admin.office.step_name_finish') }
	]);
	let featureControls = $derived([
		{ key: 'feature.drive_history', label: t('admin.office.drive_history'), on: officeState?.features.driveHistory ?? false },
		{ key: 'feature.office_editing', label: t('admin.office.web_editing'), on: officeState?.features.officeEditing ?? false },
		{ key: 'feature.office_local_open', label: t('admin.office.local_open'), on: officeState?.features.officeLocalOpen ?? false },
		{ key: 'feature.office_managed_delivery', label: t('admin.office.managed_delivery'), on: officeState?.features.officeManagedDelivery ?? false }
	]);

	function message(value: unknown, fallback: string): string {
		return value instanceof Error ? value.message : fallback;
	}

	async function load(): Promise<void> {
		loading = true;
		error = '';
		try {
			officeState = await adminOfficeGet();
		} catch (loadError) {
			error = message(loadError, t('admin.office.load_failed'));
		} finally {
			loading = false;
		}
	}

	function openWizard(existing?: OfficeProviderPolicy): void {
		provider = existing ?? null;
		qualificationTarget = existing ? { providerId: existing.providerId, generation: existing.generation } : null;
		step = 1;
		wizard = true;
		mutationError = '';
		reason = '';
		receiptId = '';
		discoveryUrl = existing?.proofDiscoveryUrl ?? '';
		wopiBaseUrl = existing?.wopiPublicBaseUrl ?? '';
		editorUrl = existing?.editorUrl ?? '';
		buildId = existing?.buildId ?? '';
		allowHosts = '';
		allowCidrs = '';
	}

	async function configure(): Promise<void> {
		if (!reason.trim()) {
			mutationError = t('admin.office.reason_required');
			return;
		}
		saving = true;
		mutationError = '';
		try {
			const configured = await adminOfficeConfigureProvider('collabora', {
				expectedGeneration: qualificationTarget?.generation ?? 0,
				profile: 'existing-provider',
				entitlementState: 'unknown',
				buildId: buildId.trim() || null,
				proofDiscoveryUrl: discoveryUrl,
				wopiPublicBaseUrl: wopiBaseUrl,
				editorUrl,
				privateAllowHosts: allowHosts.split(',').map((value) => value.trim()).filter(Boolean),
				privateAllowCidrs: allowCidrs.split(',').map((value) => value.trim()).filter(Boolean)
			}, reason.trim());
			qualificationTarget = { providerId: configured.providerId, generation: configured.generation };
			await load();
			step = 3;
		} catch (configureError) {
			mutationError = message(configureError, t('admin.office.save_failed'));
		} finally {
			saving = false;
		}
	}

	async function qualify(): Promise<void> {
		const syntheticReceiptId = Number(receiptId);
		if (!qualificationTarget || !Number.isSafeInteger(syntheticReceiptId) || syntheticReceiptId <= 0 || !reason.trim()) {
			mutationError = t('admin.office.receipt_required');
			return;
		}
		saving = true;
		mutationError = '';
		try {
			await adminOfficeQualifyProvider(
				qualificationTarget.providerId,
				{ expectedGeneration: qualificationTarget.generation, syntheticReceiptId },
				reason.trim()
			);
			await load();
			step = 5;
		} catch (qualifyError) {
			mutationError = message(qualifyError, t('admin.office.qualify_failed'));
		} finally {
			saving = false;
		}
	}

	async function activate(): Promise<void> {
		if (!activating || !reason.trim()) {
			mutationError = t('admin.office.reason_required');
			return;
		}
		saving = true;
		mutationError = '';
		try {
			await adminOfficeActivateProvider(
				activating.provider.providerId,
				{
					expectedGeneration: activating.provider.generation,
					qualificationId: activating.qualificationId,
					scope: { type: 'all' }
				},
				reason.trim()
			);
			activating = null;
			await load();
			showToast(t('admin.office.activated'));
		} catch (activateError) {
			mutationError = message(activateError, t('admin.office.activate_failed'));
		} finally {
			saving = false;
		}
	}

	async function removeProvider(): Promise<void> {
		if (!removing || !reason.trim()) return;
		saving = true;
		try {
			await adminOfficeRemoveProvider(removing.providerId, reason.trim());
			removing = null;
			await load();
		} catch (removeError) {
			mutationError = message(removeError, t('admin.office.remove_failed'));
		} finally {
			saving = false;
		}
	}

	function setFeature(key: string, enabled: boolean, label: string): void {
		featureChange = { key, enabled, label };
		reason = '';
		mutationError = '';
	}

	async function saveFeature(): Promise<void> {
		if (!featureChange || !reason.trim()) {
			mutationError = t('admin.office.reason_required');
			return;
		}
		saving = true;
		mutationError = '';
		try {
			await adminFeatureSet(featureChange.key, featureChange.enabled, reason.trim());
			featureChange = null;
			await load();
		} catch (featureError) {
			mutationError = message(featureError, t('admin.office.save_failed'));
		} finally {
			saving = false;
		}
	}

	function latestQualification(candidate: OfficeProviderPolicy): OfficeAdminState['qualifications'][number] | undefined {
		return officeState?.qualifications.find(
			(qualification) => qualification.providerId === candidate.providerId &&
				qualification.providerGeneration === candidate.generation &&
				qualification.status === 'passed'
		);
	}

	onMount(() => void load());
</script>

<div class="office-page">
	<header class="page-head"><div><h1>{t('admin.office.title')}</h1><p>{t('admin.office.subtitle')}</p></div><Button variant="ghost" size="sm" onclick={load}>{t('admin.common.refresh')}</Button></header>
	{#if error}<div class="sj-alert sj-alert--danger" role="alert">{error}</div>{/if}
	{#if !canManage}<div class="sj-alert sj-alert--info" role="status">{t('admin.office.view_only')}</div>{/if}
	{#if loading && !officeState}<Spinner label={t('common.loading')} />{:else if officeState}
		{@const current = officeState}
		<section><h2>{t('admin.office.availability')}</h2><Card>{#snippet children()}<div class="status-row"><div><strong>{current.providers.some(p => p.routeState === 'active_for_scope') ? t('admin.office.available') : t('admin.office.preview_only')}</strong><p>{t('admin.office.drive_authority')}</p></div><Badge variant={current.providers.some(p => p.routeState === 'active_for_scope') ? 'success' : 'neutral'} label={current.providers.some(p => p.routeState === 'active_for_scope') ? t('admin.office.active') : t('admin.office.inactive')} dot={true} /></div>{/snippet}</Card></section>
		<section><div class="section-head"><div><h2>{t('admin.office.providers')}</h2><p>{t('admin.office.providers_help')}</p></div>{#if canManage}<div class="actions"><Button size="sm" variant="primary" onclick={() => openWizard()}>{t('admin.office.connect_existing')}</Button><a class="app-link" href="/admin/apps">{t('admin.office.install_test_editor')}</a></div>{/if}</div>
		{#if officeState.providers.length === 0}<EmptyState title={t('admin.office.empty')} />{:else}<div class="provider-list">{#each officeState.providers as p (p.providerId)}<Card>{#snippet children()}<div class="status-row"><div><h3>{p.providerId}</h3><p>{p.buildId ?? t('admin.office.build_unknown')}</p></div><Badge variant={p.routeState === 'active_for_scope' ? 'success' : 'neutral'} label={p.routeState} dot={true} /></div><dl><div><dt>{t('admin.office.generation')}</dt><dd>{p.generation}</dd></div><div><dt>{t('admin.office.qualification')}</dt><dd>{latestQualification(p)?.status ?? t('admin.office.not_qualified')}</dd></div><div><dt>{t('admin.office.config_digest')}</dt><dd class="mono">{p.configSha256}</dd></div></dl>{#if canManage}<div class="actions"><Button size="sm" variant="secondary" onclick={() => openWizard(p)}>{t('admin.office.configure')}</Button>{#if latestQualification(p) && p.routeState !== 'active_for_scope'}<Button size="sm" variant="primary" onclick={() => { activating = { provider: p, qualificationId: latestQualification(p)!.qualificationId }; reason = ''; mutationError = ''; }}>{t('admin.office.activate')}</Button>{/if}<Button size="sm" variant="danger" onclick={() => { removing = p; reason = ''; mutationError = ''; }}>{t('admin.office.remove')}</Button></div>{/if}{/snippet}</Card>{/each}</div>{/if}</section>
		<section><h2>{t('admin.office.release_controls')}</h2>{#if !canConfigureFeatures}<div class="sj-alert sj-alert--info" role="status">{t('admin.office.feature_view_only')}</div>{/if}<div class="flag-grid">{#each featureControls as f}<Card>{#snippet children()}<div class="status-row"><span>{f.label}</span><Badge variant={f.on?'success':'neutral'} label={f.on?t('admin.office.on'):t('admin.office.off')} /></div>{#if canConfigureFeatures}<Button size="sm" variant="secondary" onclick={() => setFeature(f.key,!f.on,f.label)}>{f.on?t('admin.office.disable_feature'):t('admin.office.enable_feature')}</Button>{/if}{/snippet}</Card>{/each}</div></section>
	{/if}
</div>

<Dialog open={wizard} title={t('admin.office.connect_title')} onClose={saving ? undefined : () => (wizard=false)}>{#snippet children()}<div class="dialog-body"><ol class="steps" aria-label={t('admin.office.wizard_progress')}>{#each wizardSteps as item}<li class:current={step===item.number} aria-current={step===item.number?'step':undefined}><span>{item.number}</span><small>{item.label}</small></li>{/each}</ol>{#if step===1}<h3>{t('admin.office.step_name_endpoints')}</h3><p>{t('admin.office.step_endpoint')}</p><Input label={t('admin.office.proof_discovery_url')} bind:value={discoveryUrl} /><Input label={t('admin.office.wopi_public_base_url')} bind:value={wopiBaseUrl} /><Input label={t('admin.office.editor_url')} bind:value={editorUrl} /><Input label={t('admin.office.build_id')} bind:value={buildId} />{:else if step===2}<h3>{t('admin.office.step_name_trust')}</h3><p>{t('admin.office.step_trust')}</p><Input label={t('admin.office.private_allow_hosts')} bind:value={allowHosts} /><Input label={t('admin.office.private_allow_cidrs')} bind:value={allowCidrs} /><Input label={t('admin.office.audit_reason')} bind:value={reason} required={true} />{:else if step===3}<h3>{t('admin.office.step_name_review')}</h3><p>{t('admin.office.step_discovery')}</p><dl><div><dt>Discovery</dt><dd>{discoveryUrl}</dd></div><div><dt>WOPI</dt><dd>{wopiBaseUrl}</dd></div></dl>{:else if step===4}<h3>{t('admin.office.step_name_qualification')}</h3><p>{t('admin.office.step_save')}</p><div class="sj-alert sj-alert--info" role="status">{t('admin.office.synthetic_explanation')}</div><Input label={t('admin.office.synthetic_receipt')} bind:value={receiptId} /><Input label={t('admin.office.audit_reason')} bind:value={reason} required={true} />{:else}<h3>{t('admin.office.step_name_finish')}</h3><p>{t('admin.office.step_route')}</p><div class="sj-alert sj-alert--success" role="status"><strong>{t('admin.office.qualification_complete')}</strong><p>{t('admin.office.qualified_inactive')}</p></div>{/if}{#if mutationError}<div class="sj-alert sj-alert--danger" role="alert">{mutationError}</div>{/if}</div>{/snippet}{#snippet footer()}<Button variant="ghost" onclick={() => (wizard=false)} disabled={saving}>{t('common.cancel')}</Button>{#if step===1}<Button variant="primary" onclick={() => (step=2)}>{t('onboarding.next')}</Button>{:else if step===2}<Button variant="primary" onclick={configure} disabled={saving}>{t('admin.office.configure')}</Button>{:else if step===3}<Button variant="primary" onclick={() => (step=4)}>{t('onboarding.next')}</Button>{:else if step===4}<Button variant="primary" onclick={qualify} disabled={saving}>{t('admin.office.qualify')}</Button>{:else}<Button variant="primary" onclick={() => (wizard=false)}>{t('onboarding.done')}</Button>{/if}{/snippet}</Dialog>

<Dialog open={!!activating} title={t('admin.office.activate_title')} onClose={() => (activating=null)}>{#snippet children()}<div class="dialog-body"><p>{t('admin.office.activate_warning')}</p><Input label={t('admin.office.audit_reason')} bind:value={reason} required={true} />{#if mutationError}<div class="sj-alert sj-alert--danger" role="alert">{mutationError}</div>{/if}</div>{/snippet}{#snippet footer()}<Button variant="ghost" onclick={() => (activating=null)}>{t('common.cancel')}</Button><Button variant="primary" onclick={activate} disabled={saving}>{t('admin.office.activate')}</Button>{/snippet}</Dialog>
<Dialog open={!!removing} title={t('admin.office.remove_title')} onClose={() => (removing=null)}>{#snippet children()}<div class="dialog-body"><p>{t('admin.office.remove_body',{provider:removing?.providerId??''})}</p><Input label={t('admin.office.audit_reason')} bind:value={reason} required={true} />{#if mutationError}<div class="sj-alert sj-alert--danger" role="alert">{mutationError}</div>{/if}</div>{/snippet}{#snippet footer()}<Button variant="ghost" onclick={() => (removing=null)}>{t('common.cancel')}</Button><Button variant="danger" onclick={removeProvider} disabled={saving||!reason.trim()}>{t('admin.office.remove')}</Button>{/snippet}</Dialog>
<Dialog open={!!featureChange} title={t('admin.office.release_controls')} onClose={saving ? undefined : () => (featureChange=null)}>{#snippet children()}<div class="dialog-body"><p>{featureChange?.label}</p><Input label={t('admin.office.audit_reason')} bind:value={reason} required={true} />{#if mutationError}<div class="sj-alert sj-alert--danger" role="alert">{mutationError}</div>{/if}</div>{/snippet}{#snippet footer()}<Button variant="ghost" onclick={() => (featureChange=null)} disabled={saving}>{t('common.cancel')}</Button><Button variant="primary" onclick={saveFeature} disabled={saving||!reason.trim()}>{featureChange?.enabled?t('admin.office.enable_feature'):t('admin.office.disable_feature')}</Button>{/snippet}</Dialog>

<style>
	.office-page{max-width:1040px}.page-head,.section-head,.status-row,.actions{display:flex;align-items:center;justify-content:space-between;gap:var(--space-3)}.page-head p,.section-head p,.status-row p{color:var(--text-secondary);margin:var(--space-1) 0 0}section{margin-top:var(--space-7)}.provider-list{display:grid;gap:var(--space-4)}h3{margin:0}.flag-grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:var(--space-3);margin-top:var(--space-3)}dl{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:var(--space-3)}dt{color:var(--text-secondary);font-size:var(--text-sm)}dd{margin:var(--space-1) 0 0;overflow-wrap:anywhere}.mono{font-family:var(--font-mono);font-size:var(--text-xs)}.app-link{color:var(--accent);font-weight:600}.dialog-body{display:grid;gap:var(--space-4);width:min(600px,80vw)}.dialog-body>.sj-alert p{margin:var(--space-1) 0 0}.steps{display:grid;grid-template-columns:repeat(5,minmax(0,1fr));list-style:none;padding:0;margin:0}.steps li{display:grid;gap:var(--space-1);text-align:center;border-top:2px solid var(--border-subtle);padding-top:var(--space-2);color:var(--text-secondary)}.steps li.current{border-color:var(--accent);color:var(--text-primary);font-weight:700}.steps small{font-size:var(--text-xs)}

@media(max-width:760px){.page-head,.section-head{align-items:flex-start;flex-direction:column}.flag-grid,dl{grid-template-columns:1fr}.actions{flex-wrap:wrap}.dialog-body{width:min(520px,78vw)}.steps small{position:absolute;width:1px;height:1px;padding:0;margin:-1px;overflow:hidden;clip-path:inset(50%);white-space:nowrap;border:0}.steps li.current small{position:static;width:auto;height:auto;margin:0;overflow:visible;clip-path:none;white-space:normal}}
</style>
