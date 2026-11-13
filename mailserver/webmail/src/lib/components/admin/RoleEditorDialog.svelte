<svelte:options runes={true} />

<script lang="ts">
	import { Dialog, Input, Textarea, Checkbox, Badge, Select, Button, Spinner, showToast } from '$lib/components/ui';
	import {
		adminCreateRole,
		adminUpdateRole,
		adminPermissionCatalog,
		type AdminRole,
		type PermissionCatalogEntry
	} from '$lib/admin/roles';
	import { seedEditorForm } from '$lib/rbac/roleEditor';
	import { groupByCategory } from '$lib/admin/permissionMeta';
	import SensitiveGrantConfirm from '$lib/components/admin/SensitiveGrantConfirm.svelte';
	import ReasonPrompt from '$lib/components/admin/ReasonPrompt.svelte';
	import { getAuditPolicy } from '$lib/admin/client';
	import { parseError } from '$lib/errors';
	import { t } from '$lib/i18n';

	let {
		open = false,
		role = null,
		mode = 'create',
		domains = [],
		onClose = () => {},
		onSaved = () => {}
	}: {
		open?: boolean;
		role?: AdminRole | null;
		mode?: 'create' | 'edit' | 'clone';
		domains?: { id: number; name: string }[];
		onClose?: () => void;
		onSaved?: () => void;
	} = $props();

	let catalog = $state<PermissionCatalogEntry[]>([]);
	let name = $state('');
	let description = $state('');
	let selected = $state<Set<string>>(new Set());
	// Select uses bind:value (string), so we keep a string representation for the native select.
	let domainScopeStr = $state('');
	let loading = $state(true);
	let saving = $state(false);
	let error = $state('');
	let sensitiveConfirmOpen = $state(false);
	let pendingPayload = $state<{ name: string; description: string; permissions: string[]; domainScope: number | null } | null>(null);

	// ── Audit policy: reason-required gate ──
	// ponytail: fetched once on open; false = no prompt (default policy)
	let rolesReasonRequired = $state(false);
	let reasonPromptOpen = $state(false);

	let grouped = $derived(groupByCategory(catalog));

	$effect(() => {
		if (!open) return;
		void init();
	});

	async function init() {
		loading = true;
		error = '';
		try {
			// ponytail: fire both in parallel; audit policy failure is non-fatal
			const [entries] = await Promise.allSettled([
				catalog.length === 0 ? adminPermissionCatalog() : Promise.resolve(catalog),
				getAuditPolicy().then((p) => {
					rolesReasonRequired = p.reasonRequiredAreas.includes('roles');
				}).catch(() => { /* non-fatal: default = no prompt */ }),
			]);
			if (entries.status === 'fulfilled') catalog = entries.value;
			// Clone copies perms but blanks the name; edit loads everything.
			const seed = seedEditorForm(mode, role);
			name = seed.name;
			description = seed.description;
			selected = seed.selected;
			const scope = role?.domainScope ?? null;
			domainScopeStr = scope === null || scope === undefined ? '' : String(scope);
		} catch (e) {
			error = parseError(e).message;
		} finally {
			loading = false;
		}
	}

	function toggle(key: string) {
		const next = new Set(selected);
		next.has(key) ? next.delete(key) : next.add(key);
		selected = next;
	}

	/** Permission keys that are sensitive (from the catalog). */
	let sensitiveKeys = $derived(
		catalog.filter((p) => p.isSensitive && selected.has(p.key)).map((p) => p.key)
	);

	/**
	 * Require typed-confirmation when the grant includes high-risk permissions
	 * or when global scope (no domain restriction) and any sensitive perm is selected.
	 */
	let requireType = $derived(
		sensitiveKeys.some((k) => ['roles.manage', 'system.config', 'system.upgrade', 'system.recovery'].includes(k)) ||
			(domainScopeStr === '' && sensitiveKeys.length > 0)
	);

	async function save() {
		if (!name.trim()) {
			error = t('admin.roles.name_required');
			return;
		}
		if (selected.size === 0) {
			error = t('admin.roles.perm_required');
			return;
		}
		error = '';
		const domainScope = domainScopeStr === '' ? null : Number(domainScopeStr);
		const payload = { name: name.trim(), description, permissions: [...selected], domainScope };

		// If any sensitive permissions are selected, show the confirmation dialog first.
		if (sensitiveKeys.length > 0) {
			pendingPayload = payload;
			sensitiveConfirmOpen = true;
			return;
		}

		// If reason is required, open the reason prompt first.
		if (rolesReasonRequired) {
			pendingPayload = payload;
			reasonPromptOpen = true;
			return;
		}

		await doSave(payload);
	}

	async function doSave(payload: { name: string; description: string; permissions: string[]; domainScope: number | null }, reason?: string) {
		saving = true;
		error = '';
		try {
			if (mode === 'edit' && role) {
				await adminUpdateRole(role.id, payload, reason);
			} else {
				await adminCreateRole(payload, reason);
			}
			showToast(t('admin.roles.saved'));
			onSaved();
			onClose();
		} catch (e) {
			error = parseError(e).message;
		} finally {
			saving = false;
		}
	}

	async function onSensitiveConfirm() {
		sensitiveConfirmOpen = false;
		if (pendingPayload) {
			// After sensitive confirm, check if reason is also required.
			if (rolesReasonRequired) {
				reasonPromptOpen = true;
				// pendingPayload is kept for the reason step
			} else {
				await doSave(pendingPayload);
				pendingPayload = null;
			}
		}
	}

	function onSensitiveCancel() {
		sensitiveConfirmOpen = false;
		pendingPayload = null;
	}

	async function onReasonSubmit(reason: string) {
		reasonPromptOpen = false;
		if (pendingPayload) {
			await doSave(pendingPayload, reason);
			pendingPayload = null;
		}
	}

	function onReasonCancel() {
		reasonPromptOpen = false;
		pendingPayload = null;
	}

	let title = $derived(
		mode === 'create'
			? t('admin.roles.create_title')
			: mode === 'clone'
				? t('admin.roles.clone_title')
				: t('admin.roles.edit_title')
	);

	// Build domain options for the Select component's options prop.
	let domainOptions = $derived([
		{ value: '', label: t('admin.roles.scope_global') },
		...domains.map((d) => ({ value: String(d.id), label: d.name }))
	]);
</script>

<Dialog {open} {title} wide={true} onClose={onClose}>
	{#snippet children()}
		{#if loading}
			<div class="sj-red-loading">
				<Spinner size={20} label={t('common.loading')} />
			</div>
		{:else}
			{#if error}<div class="sj-alert-danger" role="alert">{error}</div>{/if}
			<div class="sj-role-form">
				<Input
					label={t('admin.roles.name')}
					bind:value={name}
					maxlength={64}
					required={true}
				/>
				<Textarea
					label={t('admin.roles.description')}
					bind:value={description}
					maxlength={256}
				/>
				<Select
					label={t('admin.roles.domain_scope')}
					options={domainOptions}
					bind:value={domainScopeStr}
				/>

				{#each Object.keys(grouped).sort() as category (category)}
					<fieldset class="sj-perm-group">
						<legend class="sj-perm-legend">{category}</legend>
						{#each grouped[category] as p (p.key)}
							<div class="sj-perm-row">
								<Checkbox
									checked={selected.has(p.key)}
									label={p.key}
									onchange={() => toggle(p.key)}
								/>
								{#if p.isSensitive}
									<Badge variant="warning" label={t('admin.roles.sensitive')} />
								{/if}
								<span class="sj-perm-desc">{p.description}</span>
							</div>
						{/each}
					</fieldset>
				{/each}
			</div>
		{/if}
	{/snippet}
	{#snippet footer()}
		<Button variant="primary" disabled={saving || loading} onclick={save}>{t('common.save')}</Button>
		<Button variant="ghost" onclick={onClose}>{t('common.cancel')}</Button>
	{/snippet}
</Dialog>

{#if sensitiveConfirmOpen}
	<SensitiveGrantConfirm
		open={sensitiveConfirmOpen}
		roleName={name.trim()}
		{sensitiveKeys}
		{requireType}
		onConfirm={onSensitiveConfirm}
		onCancel={onSensitiveCancel}
	/>
{/if}

{#if reasonPromptOpen}
	<!-- ponytail: reason prompt only when policy requires it for 'roles' area -->
	<Dialog open={reasonPromptOpen} title={t('admin.audit.reason.dialog_title')} onClose={onReasonCancel}>
		{#snippet children()}
			<ReasonPrompt
				area="roles"
				onSubmit={onReasonSubmit}
				onCancel={onReasonCancel}
				submitLabel={t('common.save')}
			/>
		{/snippet}
	</Dialog>
{/if}

<style>
	.sj-red-loading {
		padding: 24px;
		display: flex;
		justify-content: center;
	}
	.sj-role-form {
		display: flex;
		flex-direction: column;
		gap: var(--space-2);
	}
	.sj-perm-group {
		border: 1px solid var(--border-default);
		border-radius: var(--radius-md);
		padding: var(--space-3);
		margin-top: var(--space-3);
	}
	.sj-perm-legend {
		font-size: var(--text-sm);
		font-weight: 600;
		padding: 0 var(--space-2);
		color: var(--text-primary);
	}
	.sj-perm-row {
		display: flex;
		align-items: center;
		gap: var(--space-2);
		padding: var(--space-1) 0;
	}
	.sj-perm-desc {
		color: var(--text-tertiary);
		font-size: var(--text-sm);
	}
</style>
