<svelte:options runes={true} />

<!--
	Admin federation allow-list/anchor console (Pillar C1 Task 8).
	Gate: federation.manage (both read and write — unlike approvals, there is
	no separate view-only role for cross-org trust anchors).
	NOT toggle-gated: the console must be usable to prep an allow-list before
	feature.federation ever flips ON (Global Constraints).

	The anchor PEM is NEVER round-tripped from the server (List/GET never
	sends it back) — the enable/disable toggle in the table posts a BLANK
	anchorPem, which the backend carries forward unchanged (the DES-011
	fast-disable affordance: an admin killing a peer's live stream should
	never have to re-paste a certificate first). The Edit dialog is for
	changing the domain's anchor/scope, and requires a fresh paste.
-->

<script lang="ts">
	import { onMount } from 'svelte';
	import { adminPermissions, hasPermission } from '$lib/stores/auth';
	import { Card, Button, Spinner, Dialog, Select, Switch, showToast } from '$lib/components/ui';
	import Icon from '$lib/components/Icon.svelte';
	import {
		adminListFederationPeers,
		adminUpsertFederationPeer,
		adminDeleteFederationPeer,
		type FederationPeer,
	} from '$lib/admin/client';
	import { parseError } from '$lib/errors';
	import { t } from '$lib/i18n';

	let peers = $state<FederationPeer[]>([]);
	let loading = $state(false);
	let error = $state('');

	let canManage = $derived(hasPermission($adminPermissions, 'federation.manage'));

	// add/edit dialog
	let editorOpen = $state(false);
	let editTarget = $state<FederationPeer | null>(null);
	let formDomain = $state('');
	let formAnchorPem = $state('');
	let formScope = $state<'dm' | 'room'>('dm');
	let formEnabled = $state(false);
	let formError = $state('');
	let saving = $state(false);

	// inline delete confirmation (delete-disabled-only, mirrors the reducer's
	// own disable-before-delete lifecycle — the button is simply absent for
	// an enabled peer, see the table below)
	let deleteTarget = $state<FederationPeer | null>(null);
	let deleting = $state(false);
	let deleteError = $state('');

	// per-row enable/disable toggle in flight (disables the switch during the request)
	let togglingDomain = $state<string | null>(null);

	onMount(load);

	async function load() {
		loading = true;
		error = '';
		try {
			peers = await adminListFederationPeers();
		} catch (e) {
			error = parseError(e).message;
		} finally {
			loading = false;
		}
	}

	function openAdd() {
		editTarget = null;
		formDomain = '';
		formAnchorPem = '';
		formScope = 'dm';
		formEnabled = false;
		formError = '';
		editorOpen = true;
	}

	function openEdit(p: FederationPeer) {
		editTarget = p;
		formDomain = p.peerDomain;
		formAnchorPem = ''; // never round-tripped — leave blank to keep the existing anchor
		formScope = p.scope;
		formEnabled = p.enabled;
		formError = '';
		editorOpen = true;
	}

	async function submit() {
		const domain = formDomain.trim();
		if (domain === '') {
			formError = t('admin.federation.editor.domain_required');
			return;
		}
		if (!editTarget && formAnchorPem.trim() === '') {
			formError = t('admin.federation.editor.anchor_required');
			return;
		}
		saving = true;
		formError = '';
		try {
			await adminUpsertFederationPeer({
				domain,
				anchorPem: formAnchorPem,
				scope: formScope,
				enabled: formEnabled,
			});
			editorOpen = false;
			showToast(t('admin.federation.saved'));
			await load();
		} catch (e) {
			formError = parseError(e).message;
		} finally {
			saving = false;
		}
	}

	async function toggleEnabled(p: FederationPeer) {
		togglingDomain = p.peerDomain;
		error = '';
		try {
			await adminUpsertFederationPeer({
				domain: p.peerDomain,
				anchorPem: '', // blank — the backend carries the existing anchor forward
				scope: p.scope,
				enabled: !p.enabled,
			});
			await load();
		} catch (e) {
			error = parseError(e).message;
		} finally {
			togglingDomain = null;
		}
	}

	function confirmDelete(p: FederationPeer) {
		deleteTarget = p;
		deleteError = '';
	}

	async function doDelete() {
		if (!deleteTarget) return;
		deleting = true;
		deleteError = '';
		try {
			await adminDeleteFederationPeer(deleteTarget.peerDomain);
			showToast(t('admin.federation.deleted'));
			deleteTarget = null;
			await load();
		} catch (e) {
			deleteError = parseError(e).message;
		} finally {
			deleting = false;
		}
	}

	function healthLabel(p: FederationPeer): string {
		if (p.unackedDepth == null || p.lastAckAgeSeconds == null) {
			return t('admin.federation.health.none');
		}
		const ageMin = Math.round(p.lastAckAgeSeconds / 60);
		return t('admin.federation.health.summary')
			.replace('{depth}', String(p.unackedDepth))
			.replace('{ageMin}', String(ageMin));
	}
</script>

<svelte:head><title>{t('admin.federation.title')} · setjoin</title></svelte:head>

<div class="fed-page">
	<div class="fed-header">
		<div>
			<h1 class="fed-title">{t('admin.federation.title')}</h1>
			<p class="fed-subtitle">{t('admin.federation.subtitle')}</p>
		</div>
		{#if canManage}
			<Button variant="primary" onclick={openAdd}>
				<Icon name="Plus" size={16} />
				{t('admin.federation.add_peer')}
			</Button>
		{/if}
	</div>

	{#if error}
		<p class="fed-error" role="alert">{error}</p>
	{/if}

	{#if loading}
		<div class="fed-loading"><Spinner /></div>
	{:else if peers.length === 0}
		<Card>
			<div class="fed-empty">
				<p class="fed-empty__title">{t('admin.federation.empty_title')}</p>
				<p class="fed-empty__body">{t('admin.federation.empty_body')}</p>
				{#if canManage}
					<Button variant="primary" onclick={openAdd}>{t('admin.federation.add_peer')}</Button>
				{/if}
			</div>
		</Card>
	{:else}
		<Card flush>
			<table class="fed-table">
				<thead>
					<tr>
						<th>{t('admin.federation.col_domain')}</th>
						<th>{t('admin.federation.col_scope')}</th>
						<th>{t('admin.federation.col_enabled')}</th>
						<th>{t('admin.federation.col_health')}</th>
						<th class="fed-th-actions">{t('admin.federation.col_actions')}</th>
					</tr>
				</thead>
				<tbody>
					{#each peers as peer (peer.peerDomain)}
						<tr class="fed-row">
							<td class="fed-mono">{peer.peerDomain}</td>
							<td>{peer.scope}</td>
							<td>
								<Switch
									checked={peer.enabled}
									disabled={!canManage || togglingDomain === peer.peerDomain}
									onchange={() => toggleEnabled(peer)}
								/>
							</td>
							<td class="fed-health">{healthLabel(peer)}</td>
							<td class="fed-td-actions">
								{#if canManage}
									<button
										type="button"
										class="fed-icon-btn"
										aria-label={t('admin.federation.edit')}
										onclick={() => openEdit(peer)}
									>
										<Icon name="Pencil" size={16} />
									</button>
									{#if !peer.enabled}
										<button
											type="button"
											class="fed-icon-btn fed-icon-btn--danger"
											aria-label={t('admin.federation.delete')}
											onclick={() => confirmDelete(peer)}
										>
											<Icon name="Trash2" size={16} />
										</button>
									{/if}
								{/if}
							</td>
						</tr>
					{/each}
				</tbody>
			</table>
		</Card>
	{/if}
</div>

<!-- Add/edit dialog -->
<Dialog
	open={editorOpen}
	title={editTarget ? t('admin.federation.editor.title_edit') : t('admin.federation.editor.title_create')}
	onClose={() => (editorOpen = false)}
>
	<form
		class="fed-form"
		onsubmit={(e) => {
			e.preventDefault();
			submit();
		}}
	>
		<div class="fed-field">
			<span class="fed-label">{t('admin.federation.editor.domain_label')}</span>
			<input
				class="fed-input"
				type="text"
				bind:value={formDomain}
				disabled={!!editTarget}
				placeholder="bravo.example.com"
			/>
		</div>

		<div class="fed-field">
			<span class="fed-label">{t('admin.federation.editor.anchor_label')}</span>
			<textarea
				class="fed-textarea"
				rows={6}
				bind:value={formAnchorPem}
				placeholder={editTarget
					? t('admin.federation.editor.anchor_placeholder_edit')
					: t('admin.federation.editor.anchor_placeholder_create')}
			></textarea>
			<p class="fed-hint">{t('admin.federation.editor.anchor_hint')}</p>
		</div>

		<div class="fed-field">
			<Select
				label={t('admin.federation.editor.scope_label')}
				bind:value={formScope}
				options={[
					{ value: 'dm', label: t('admin.federation.scope.dm') },
					{ value: 'room', label: t('admin.federation.scope.room') },
				]}
			/>
		</div>

		<div class="fed-field fed-field--row">
			<span class="fed-label">{t('admin.federation.editor.enabled_label')}</span>
			<Switch bind:checked={formEnabled} />
		</div>

		{#if formError}
			<p class="fed-error" role="alert">{formError}</p>
		{/if}

		<div class="fed-actions">
			<Button variant="ghost" type="button" onclick={() => (editorOpen = false)} disabled={saving}>
				{t('admin.federation.editor.cancel')}
			</Button>
			<Button variant="primary" type="submit" disabled={saving}>
				{#if saving}<Spinner />{/if}
				{t('admin.federation.editor.save')}
			</Button>
		</div>
	</form>
</Dialog>

<!-- Inline delete confirmation -->
{#if deleteTarget}
	<div
		class="fed-confirm-overlay"
		role="dialog"
		aria-modal="true"
		aria-label={t('admin.federation.delete')}
		tabindex="-1"
		onkeydown={(e) => {
			if (e.key === 'Escape' && !deleting) deleteTarget = null;
		}}
	>
		<Card>
			<p class="fed-confirm-msg">
				{t('admin.federation.delete_confirm').replace('{domain}', deleteTarget.peerDomain)}
			</p>
			{#if deleteError}
				<p class="fed-error" role="alert">{deleteError}</p>
			{/if}
			<div class="fed-confirm-actions">
				<Button variant="ghost" onclick={() => (deleteTarget = null)} disabled={deleting}>
					{t('admin.federation.editor.cancel')}
				</Button>
				<Button variant="danger" onclick={doDelete} disabled={deleting} autofocus>
					{#if deleting}<Spinner />{/if}
					{t('admin.federation.delete')}
				</Button>
			</div>
		</Card>
	</div>
{/if}

<style>
	.fed-page {
		display: flex;
		flex-direction: column;
		gap: var(--space-4);
		padding: var(--space-6);
		max-width: 900px;
	}
	.fed-header {
		display: flex;
		align-items: flex-start;
		justify-content: space-between;
		gap: var(--space-4);
	}
	.fed-title {
		font-size: var(--text-xl);
		font-weight: var(--weight-semibold);
		color: var(--text-primary);
		margin: 0;
	}
	.fed-subtitle {
		font-size: var(--text-sm);
		color: var(--text-secondary);
		margin: var(--space-1) 0 0;
	}
	.fed-error {
		font-size: var(--text-sm);
		color: var(--text-danger);
	}
	.fed-loading {
		display: flex;
		align-items: center;
		gap: var(--space-2);
		padding: var(--space-6);
		color: var(--text-secondary);
		font-size: var(--text-sm);
	}
	.fed-empty {
		display: flex;
		flex-direction: column;
		align-items: center;
		gap: var(--space-3);
		padding: var(--space-8);
		text-align: center;
	}
	.fed-empty__title {
		font-size: var(--text-base);
		font-weight: var(--weight-medium);
		color: var(--text-primary);
		margin: 0;
	}
	.fed-empty__body {
		font-size: var(--text-sm);
		color: var(--text-secondary);
		margin: 0;
	}
	.fed-table {
		width: 100%;
		border-collapse: collapse;
		font-size: var(--text-sm);
	}
	.fed-table th {
		text-align: left;
		padding: var(--space-2) var(--space-3);
		font-weight: var(--weight-medium);
		color: var(--text-secondary);
		border-bottom: 1px solid var(--border-default);
		white-space: nowrap;
	}
	.fed-th-actions {
		width: 100px;
	}
	.fed-row td {
		padding: var(--space-3);
		border-bottom: 1px solid var(--border-subtle);
		vertical-align: middle;
	}
	.fed-row:last-child td {
		border-bottom: none;
	}
	.fed-mono {
		font-family: var(--font-mono);
	}
	.fed-health {
		color: var(--text-secondary);
		font-size: var(--text-xs);
	}
	.fed-td-actions {
		display: flex;
		align-items: center;
		gap: 4px;
	}
	.fed-icon-btn {
		display: flex;
		align-items: center;
		justify-content: center;
		min-width: 44px;
		min-height: 44px;
		border: none;
		background: transparent;
		border-radius: var(--radius-md);
		cursor: pointer;
		color: var(--text-secondary);
	}
	.fed-icon-btn:hover:not(:disabled) {
		background: var(--surface-hover);
		color: var(--text-primary);
	}
	.fed-icon-btn--danger:hover:not(:disabled) {
		background: var(--red-50);
		color: var(--text-danger);
	}
	.fed-form {
		display: flex;
		flex-direction: column;
		gap: var(--space-4);
		min-width: 420px;
	}
	.fed-field {
		display: flex;
		flex-direction: column;
		gap: var(--space-1);
	}
	.fed-field--row {
		flex-direction: row;
		align-items: center;
		justify-content: space-between;
	}
	.fed-label {
		font-size: var(--text-sm);
		font-weight: var(--weight-medium);
		color: var(--text-secondary);
	}
	.fed-input {
		height: 32px;
		padding: 0 var(--space-2);
		border: 1px solid var(--border-default);
		border-radius: var(--radius-sm);
		background: var(--surface-primary);
		color: var(--text-primary);
		font-size: var(--text-sm);
	}
	.fed-input:disabled {
		opacity: 0.6;
	}
	.fed-textarea {
		width: 100%;
		padding: var(--space-2);
		border: 1px solid var(--border-default);
		border-radius: var(--radius-sm);
		background: var(--surface-primary);
		color: var(--text-primary);
		font-family: var(--font-mono);
		font-size: var(--text-xs);
		resize: vertical;
	}
	.fed-hint {
		font-size: var(--text-xs);
		color: var(--text-tertiary);
		margin: 0;
	}
	.fed-actions {
		display: flex;
		justify-content: flex-end;
		gap: var(--space-2);
	}
	.fed-confirm-overlay {
		position: fixed;
		inset: 0;
		background: rgb(0, 0, 0, 0.4);
		display: flex;
		align-items: center;
		justify-content: center;
		z-index: 50;
	}
	.fed-confirm-msg {
		font-size: var(--text-sm);
		color: var(--text-primary);
		margin: 0 0 var(--space-4);
	}
	.fed-confirm-actions {
		display: flex;
		justify-content: flex-end;
		gap: var(--space-2);
	}
</style>
