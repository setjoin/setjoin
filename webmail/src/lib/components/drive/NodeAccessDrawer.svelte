<svelte:options runes={true} />

<script lang="ts">
	import * as api from '$lib/drive/api';
	import type { DriveACLGrant, DriveACLSubject, DriveNode, DriveNodeAccess, DrivePreset } from '$lib/drive/api';
	import { user } from '$lib/stores/auth';
	import { Badge, Button, ConfirmDestructive, IconButton, Input, Spinner } from '$lib/components/ui';
	import Icon from '$lib/components/Icon.svelte';
	import { driveErrorMessage } from '$lib/drive/errors';
	import { focusTrap } from '$lib/actions/focusTrap';
	import { t } from '$lib/i18n';

	let { node, onClose, onChanged }: {
		node: DriveNode;
		onClose: () => void;
		onChanged?: () => void;
	} = $props();

	let access = $state<DriveNodeAccess | null>(null);
	let loading = $state(true);
	let error = $state('');
	let addOpen = $state(false);
	let query = $state('');
	let subjects = $state<DriveACLSubject[]>([]);
	let selected = $state<DriveACLSubject | null>(null);
	let searching = $state(false);
	let searchError = $state('');
	let searchGeneration = 0;
	let preset = $state<DrivePreset>('viewer');
	let scope = $state<'self' | 'subtree'>('subtree');
	let grantStage = $state<'edit' | 'review'>('edit');
	let saving = $state(false);
	let mutationError = $state('');
	let announce = $state('');
	let explainOpen = $state(false);
	let revokeTarget = $state<DriveACLGrant | null>(null);
	let revokeBusy = $state(false);
	let inheritancePreview = $state<api.DriveInheritancePreview | null>(null);
	let inheritanceBusy = $state(false);
	let inheritanceError = $state('');
	let requestOpen = $state(false);
	let requestReason = $state('');
	let requesting = $state(false);

	const direct = $derived(access?.grants.filter((g) => g.relation === 'direct') ?? []);
	const inherited = $derived(access?.grants.filter((g) => g.relation === 'inherited') ?? []);
	const effectivePreset = $derived.by(() => {
		const first = direct[0] ?? inherited[0];
		return first?.preset ?? null;
	});

	/** The drawer is non-modal on wide screens, but becomes an overlay below
	 * 1280px. Activate modal semantics and the shared focus trap only there. */
	function responsiveDrawer(nodeElement: HTMLElement) {
		if (typeof window.matchMedia !== 'function') return {};
		const query = window.matchMedia('(max-width: 1279px)');
		let trap: ReturnType<typeof focusTrap> | null = null;
		function sync() {
			if (query.matches && !trap) {
				nodeElement.setAttribute('aria-modal', 'true');
				trap = focusTrap(nodeElement, { onEscape: onClose });
			} else if (!query.matches && trap) {
				trap.destroy();
				trap = null;
				nodeElement.removeAttribute('aria-modal');
			}
		}
		sync();
		query.addEventListener('change', sync);
		return { destroy() { query.removeEventListener('change', sync); trap?.destroy(); } };
	}

	async function load(keepDraft = false) {
		loading = true;
		error = '';
		try {
			access = await api.getNodeAccess(node.id);
			if (!keepDraft) resetGrant();
		} catch (e) {
			error = driveErrorMessage(e);
		} finally {
			loading = false;
		}
	}

	$effect(() => {
		void node.id;
		void load();
	});

	function resetGrant() {
		searchGeneration += 1;
		query = '';
		subjects = [];
		selected = null;
		searching = false;
		searchError = '';
		preset = 'viewer';
		scope = 'subtree';
		grantStage = 'edit';
		mutationError = '';
	}

	async function search() {
		selected = null;
		grantStage = 'edit';
		const generation = ++searchGeneration;
		const value = query.trim();
		if (value.length < 2) {
			subjects = [];
			searching = false;
			searchError = '';
			return;
		}
		searching = true;
		searchError = '';
		try {
			const found = await api.searchACLSubjects(node.id, value);
			if (generation === searchGeneration) subjects = found;
		} catch {
			if (generation === searchGeneration) searchError = t('drive.access.searchFailed');
		} finally {
			if (generation === searchGeneration) searching = false;
		}
	}

	function pickSubject(subject: DriveACLSubject) {
		searchGeneration += 1;
		selected = subject;
		query = '';
		subjects = [];
		searchError = '';
	}

	function grantInput(): api.DriveGrantInput | null {
		if (!selected) return null;
		return { subjectKind: selected.kind, subjectId: selected.id, preset, scope };
	}

	async function reviewGrant() {
		const body = grantInput();
		if (!body) return;
		saving = true;
		mutationError = '';
		try {
			await api.previewNodeGrant(node.id, body);
			grantStage = 'review';
		} catch (e) {
			mutationError = driveErrorMessage(e);
		} finally {
			saving = false;
		}
	}

	async function submitGrant() {
		const body = grantInput();
		if (!body || !access) return;
		saving = true;
		mutationError = '';
		try {
			await api.grantNodeAccess(node.id, {
				...body, expectedEpoch: access.epoch, idempotencyKey: crypto.randomUUID(),
			});
			announce = t('drive.access.grantSuccess', { name: selected?.label ?? '' });
			addOpen = false;
			await load();
			onChanged?.();
		} catch (e) {
			const message = driveErrorMessage(e);
			if (e instanceof api.DriveError && e.status === 409) {
				await load(true);
				grantStage = 'edit';
				mutationError = t('drive.access.changedWhileEditing');
			} else mutationError = message;
		} finally {
			saving = false;
		}
	}

	async function revoke() {
		if (!revokeTarget || !access) return;
		revokeBusy = true;
		mutationError = '';
		try {
			await api.revokeNodeGrant(revokeTarget.grantId, access.epoch, t('drive.access.revokeReason'));
			announce = t('drive.access.revokeSuccess', { name: revokeTarget.subjectLabel });
			revokeTarget = null;
			await load();
			onChanged?.();
		} catch (e) {
			if (e instanceof api.DriveError && e.status === 409) {
				await load(true);
				mutationError = t('drive.access.changedWhileEditing');
			} else mutationError = driveErrorMessage(e);
		} finally {
			revokeBusy = false;
		}
	}

	async function previewInheritance(value: boolean) {
		inheritanceBusy = true;
		inheritanceError = '';
		try {
			inheritancePreview = await api.previewNodeInheritance(node.id, value);
		} catch (e) {
			inheritanceError = driveErrorMessage(e);
		} finally {
			inheritanceBusy = false;
		}
	}

	async function applyInheritance() {
		const preview = inheritancePreview;
		if (!preview) return;
		inheritanceBusy = true;
		inheritanceError = '';
		try {
			await api.setNodeInheritance(node.id, preview.requestedBreak, preview.epoch);
			announce = preview.requestedBreak
				? t('drive.access.inheritanceStopped') : t('drive.access.inheritanceResumed');
			inheritancePreview = null;
			await load();
			onChanged?.();
		} catch (e) {
			if (e instanceof api.DriveError && e.status === 409) {
				const requestedBreak = preview.requestedBreak;
				await load(true);
				try {
					inheritancePreview = await api.previewNodeInheritance(node.id, requestedBreak);
				} catch {
					inheritancePreview = null;
				}
				inheritanceError = t('drive.access.changedWhileEditing');
			} else inheritanceError = driveErrorMessage(e);
		} finally {
			inheritanceBusy = false;
		}
	}

	async function submitRequest() {
		if (!access || !$user?.userId || requestReason.trim().length < 8) return;
		requesting = true;
		mutationError = '';
		try {
			const body: api.DriveAccessRequestInput = {
				subjectKind: 'user', subjectId: String($user.userId),
				capabilities: ['download'], propagation: 'self', durationMinutes: 60,
				reason: requestReason.trim(),
			};
			const preview = await api.previewDriveAccessRequest(node.id, body);
			if (preview.requestable !== true) throw new Error(t('drive.access.notRequestable'));
			await api.createDriveAccessRequest(node.id, { ...body, idempotencyKey: crypto.randomUUID() });
			requestOpen = false;
			requestReason = '';
			announce = t('drive.access.requestSubmitted');
		} catch (e) {
			mutationError = driveErrorMessage(e);
		} finally {
			requesting = false;
		}
	}
</script>

<div class="nad" role="dialog" tabindex="-1" aria-label={t('drive.access.title')} use:responsiveDrawer>
	<header class="nad__header">
		<Icon name="Lock" size={18} />
		<div class="nad__heading">
			<strong>{node.name}</strong>
			<span>{effectivePreset ? t(`drive.access.preset.${effectivePreset}.label`) : t('drive.access.effectiveSummary')}</span>
		</div>
		<IconButton label={t('common.close')} onclick={onClose}><Icon name="X" size={16} /></IconButton>
	</header>

	<div class="nad__announce" aria-live="polite">{announce}</div>
	{#if loading}
		<div class="nad__loading"><Spinner /></div>
	{:else if error}
		<div class="nad__error" role="alert"><p>{error}</p><Button variant="secondary" onclick={() => load()}>{t('common.retry')}</Button></div>
	{:else if access}
		<div class="nad__scroll">
			<section class="nad__section">
				<div class="nad__section-head"><h3>{t('drive.access.people')}</h3><Badge variant={access.inheritanceBroken ? 'warning' : 'neutral'} dot label={access.inheritanceBroken ? t('drive.access.notInheriting') : t('drive.access.inheriting')} /></div>
				{#if access.grants.length === 0}
					<p class="nad__empty">{t('drive.access.noCustom')}</p>
				{:else}
					{#if direct.length > 0}<h4>{t('drive.access.direct')}</h4>{/if}
					{#each direct as grant (grant.grantId)}
						<div class="nad-grant">
							<Icon name="Users" size={16} />
							<div><strong>{grant.subjectLabel}</strong><span>{t(`drive.access.preset.${grant.preset}.label`)} · {t(`drive.access.scope.${grant.propagation}`)}</span></div>
							{#if access.canManage && access.writesEnabled}<IconButton label={t('drive.access.remove')} size="sm" onclick={() => (revokeTarget = grant)}><Icon name="X" size={14} /></IconButton>{/if}
						</div>
					{/each}
					{#if inherited.length > 0}<h4>{t('drive.access.inheritedCount', { n: String(inherited.length) })}</h4>{/if}
					{#each inherited as grant (grant.grantId)}
						<div class="nad-grant nad-grant--inherited">
							<Icon name="ChevronRight" size={16} />
							<div><strong>{grant.subjectLabel}</strong><span>{grant.anchorName} · {t(`drive.access.preset.${grant.preset}.label`)}</span></div>
						</div>
					{/each}
				{/if}
			</section>

			{#if access.canManage && access.writesEnabled}
				<section class="nad__section">
					<Button variant="secondary" onclick={() => { addOpen = !addOpen; if (!addOpen) resetGrant(); }}><Icon name="UserPlus" size={14} />{t('drive.access.addPeople')}</Button>
					{#if addOpen}
						<div class="nad-form">
							{#if selected}
								<div class="nad-selection"><span><strong>{selected.label}</strong><small>{selected.secondary ?? t(`drive.access.subject.${selected.kind}`)}</small></span><Button variant="ghost" size="sm" onclick={() => { selected = null; grantStage = 'edit'; }}>{t('drive.members.change')}</Button></div>
							{:else}
								<Input label={t('drive.access.person')} placeholder={t('drive.access.searchPlaceholder')} autocomplete="off" bind:value={query} oninput={() => void search()} role="combobox" aria-expanded={subjects.length > 0} aria-controls="drive-access-subjects" />
								<div class="nad__status" aria-live="polite">{searching ? t('drive.members.searching') : searchError}</div>
								{#if subjects.length > 0}<ul id="drive-access-subjects" class="nad-results" role="listbox">{#each subjects as subject (subject.kind + subject.id)}<li role="option" aria-selected="false"><button type="button" onclick={() => pickSubject(subject)}><strong>{subject.label}</strong><small>{subject.secondary ?? t(`drive.access.subject.${subject.kind}`)}</small></button></li>{/each}</ul>{/if}
							{/if}

							<fieldset><legend>{t('drive.access.permission')}</legend>{#each access.presets as option}<label class="nad-choice"><input type="radio" name="drive-preset" value={option} checked={preset === option} onchange={() => { preset = option; grantStage = 'edit'; }} /><span><strong>{t(`drive.access.preset.${option}.label`)}</strong><small>{t(`drive.access.preset.${option}.description`)}</small></span></label>{/each}</fieldset>
							<fieldset><legend>{t('drive.access.scopeLabel')}</legend>{#each ['self','subtree'] as option}<label class="nad-choice"><input type="radio" name="drive-scope" value={option} checked={scope === option} onchange={() => { scope = option as 'self' | 'subtree'; grantStage = 'edit'; }} /><span><strong>{t(`drive.access.scope.${option}`)}</strong></span></label>{/each}</fieldset>
							{#if grantStage === 'review' && selected}<p class="nad-review" role="status">{t('drive.access.reviewSentence', { name: selected.label, preset: t(`drive.access.preset.${preset}.label`), scope: t(`drive.access.scope.${scope}`) })}</p>{/if}
							{#if mutationError}<p class="nad__error-text" role="alert">{mutationError}</p>{/if}
							<div class="nad__buttons">{#if grantStage === 'edit'}<Button variant="primary" disabled={!selected || saving} onclick={reviewGrant}>{saving ? t('common.loading') : t('drive.access.reviewGrant')}</Button>{:else}<Button variant="primary" disabled={saving} onclick={submitGrant}>{saving ? t('common.loading') : t('drive.access.grant')}</Button><Button variant="secondary" disabled={saving} onclick={() => (grantStage = 'edit')}>{t('common.back')}</Button>{/if}</div>
						</div>
					{/if}
				</section>
			{/if}

			<section class="nad__section nad__actions">
				<Button variant="ghost" onclick={() => (explainOpen = !explainOpen)}><Icon name="Info" size={14} />{t('drive.access.why')}</Button>
				{#if access.canManage && access.writesEnabled}<Button variant="ghost" disabled={inheritanceBusy} onclick={() => previewInheritance(!(access?.inheritanceBroken ?? false))}><Icon name={access.inheritanceBroken ? 'ShieldCheck' : 'Shield'} size={14} />{access.inheritanceBroken ? t('drive.access.resumeInheritance') : t('drive.access.stopInheritance')}</Button>{/if}
				{#if access.governanceEnabled && $user?.userId != null}<Button variant="ghost" onclick={() => { requestOpen = !requestOpen; mutationError = ''; }}><Icon name="Inbox" size={14} />{t('drive.access.request')}</Button>{/if}
				{#if explainOpen}<div class="nad-explain">{#if access.sources.length === 0}<p>{t('drive.access.noSource')}</p>{:else}<ul>{#each access.sources as source}<li><strong>{t(`drive.access.capability.${source.capability}`)}</strong><span>{t(`drive.access.source.${source.sourceKind}`)}</span></li>{/each}</ul>{/if}</div>{/if}
				{#if requestOpen}<div class="nad-form"><Input label={t('drive.access.requestReason')} bind:value={requestReason} minlength={8} maxlength={1000} />{#if mutationError}<p class="nad__error-text" role="alert">{mutationError}</p>{/if}<Button variant="primary" disabled={requesting || requestReason.trim().length < 8} onclick={submitRequest}>{requesting ? t('common.loading') : t('drive.access.submitRequest')}</Button></div>{/if}
			</section>
		</div>
	{/if}
</div>

<ConfirmDestructive open={revokeTarget !== null} title={t('drive.access.remove')} message={revokeTarget ? t('drive.access.revokeConfirm', { name: revokeTarget.subjectLabel }) : ''} confirmWord={revokeTarget?.subjectLabel ?? ''} confirmLabel={t('drive.access.remove')} busy={revokeBusy} error={mutationError} onConfirm={revoke} onCancel={() => (revokeTarget = null)} />
<ConfirmDestructive open={inheritancePreview !== null} title={inheritancePreview?.requestedBreak ? t('drive.access.stopInheritance') : t('drive.access.resumeInheritance')} message={inheritancePreview ? t('drive.access.inheritanceImpact', { nodes: String(inheritancePreview.affectedNodeCount), people: String(inheritancePreview.affectedPrincipalCount), offline: inheritancePreview.mayRemoveOfflineContent ? t('drive.access.offlineRemoval') : '' }) : ''} confirmWord={node.name} confirmLabel={inheritancePreview?.requestedBreak ? t('drive.access.stopInheritance') : t('drive.access.resumeInheritance')} busy={inheritanceBusy} error={inheritanceError} onConfirm={applyInheritance} onCancel={() => (inheritancePreview = null)} />

<style>
	.nad { width: 384px; flex: 0 0 384px; min-width: 0; border-left: 1px solid var(--border-default); background: var(--surface-card); display: flex; flex-direction: column; height: 100%; }
	.nad__header { display: flex; align-items: center; gap: var(--space-2); padding: var(--space-3); border-bottom: 1px solid var(--border-subtle); }
	.nad__heading { min-width: 0; flex: 1; display: flex; flex-direction: column; }
	.nad__heading strong { font-size: var(--text-sm); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
	.nad__heading span,.nad-grant span,.nad-selection small,.nad-results small,.nad-choice small { display: block; font-size: var(--text-xs); color: var(--text-caption); }
	.nad__announce { min-height: 0; font-size: var(--text-xs); color: var(--text-secondary); padding: 0 var(--space-3); }
	.nad__loading,.nad__error { padding: var(--space-6); text-align: center; }
	.nad__scroll { overflow-y: auto; }
	.nad__section { padding: var(--space-3); border-bottom: 1px solid var(--border-subtle); }
	.nad__section h3,.nad__section h4 { margin: 0; font-size: var(--text-sm); }
	.nad__section h4 { margin-top: var(--space-3); color: var(--text-secondary); }
	.nad__section-head { display: flex; justify-content: space-between; align-items: center; gap: var(--space-2); }
	.nad__empty,.nad__status,.nad__error-text { font-size: var(--text-sm); color: var(--text-caption); }
	.nad__error-text { color: var(--text-danger); }
	.nad-grant { display: flex; align-items: center; gap: var(--space-2); padding: var(--space-2) 0; }
	.nad-grant > div { flex: 1; min-width: 0; }
	.nad-grant strong { display: block; font-size: var(--text-sm); }
	.nad-grant--inherited { color: var(--text-secondary); }
	.nad-form { display: flex; flex-direction: column; gap: var(--space-3); margin-top: var(--space-3); }
	.nad-selection { display: flex; align-items: center; justify-content: space-between; gap: var(--space-2); padding: var(--space-2); border: 1px solid var(--border-default); border-radius: var(--radius-sm); }
	.nad-selection > span { min-width: 0; }
	.nad-results { list-style: none; padding: 0; margin: 0; border: 1px solid var(--border-default); border-radius: var(--radius-sm); max-height: 180px; overflow-y: auto; }
	.nad-results button { width: 100%; border: 0; background: transparent; text-align: left; padding: var(--space-2); color: var(--text-primary); }
	.nad-results button:hover,.nad-results button:focus-visible { background: var(--surface-hover); }
	.nad fieldset { border: 0; padding: 0; margin: 0; }
	.nad legend { font-size: var(--text-sm); font-weight: 600; margin-bottom: var(--space-2); }
	.nad-choice { display: flex; align-items: flex-start; gap: var(--space-2); padding: var(--space-2); border: 1px solid var(--border-subtle); border-radius: var(--radius-sm); margin-bottom: var(--space-1); }
	.nad-choice:has(input:checked) { border-color: var(--accent); background: var(--surface-selected); }
	.nad-review { font-size: var(--text-sm); color: var(--text-primary); padding: var(--space-2); border-left: 3px solid var(--accent); background: var(--surface-selected); }
	.nad__buttons,.nad__actions { display: flex; flex-wrap: wrap; gap: var(--space-2); }
	.nad-explain { width: 100%; font-size: var(--text-sm); }
	.nad-explain ul { list-style: none; margin: 0; padding: 0; }
	.nad-explain li { display: flex; justify-content: space-between; gap: var(--space-2); padding: var(--space-1) 0; }
	.nad-explain span { color: var(--text-caption); }

	@media (max-width: 1279px) { .nad { position: absolute; z-index: 12; inset: 0 0 0 auto; width: 360px; box-shadow: var(--shadow-lg); } }

	@media (max-width: 767px) { .nad { position: fixed; z-index: 30; inset: 0; width: 100%; height: 100dvh; } .nad__header { min-height: 44px; } .nad button,.nad input { min-height: 44px; } }
</style>
