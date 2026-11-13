<svelte:options runes={true} />

<script lang="ts">
	import {
		Dialog, Table, Button, Input, Select,
		Badge, EmptyState, Spinner, showToast, IconButton,
		type TableColumn,
	} from '$lib/components/ui';
	import { listIPRules, createIPRule, deleteIPRule, type IPRule, type IPRuleCreateRequest } from '$lib/admin/client';
	import { adminPermissions, hasPermission } from '$lib/stores/auth';
	import { parseError } from '$lib/errors';
	import Icon from '$lib/components/Icon.svelte';

	let {
		open = false,
		onClose = () => {},
	}: {
		open?: boolean;
		onClose?: () => void;
	} = $props();

	const RULE_COLUMNS: TableColumn[] = [
		{ key: 'cidr',        label: 'CIDR',        sortable: false, mono: true },
		{ key: 'action',      label: 'Action',      sortable: false },
		{ key: 'description', label: 'Description', sortable: false },
		{ key: 'expiresAt',   label: 'Expires',     sortable: false, mono: true },
		{ key: 'actions',     label: '',            sortable: false },
	];

	let rules = $state<IPRule[]>([]);
	let loading = $state(true);
	let error = $state('');
	let showForm = $state(false);

	let newCidr = $state('');
	let newAction = $state<'allow' | 'block'>('block');
	let newDesc = $state('');
	let newExpires = $state('');
	let saving = $state(false);
	let formError = $state('');
	let deleteConfirmId = $state<number | null>(null);

	async function load() {
		loading = true;
		error = '';
		try {
			const data = await listIPRules(200, 0);
			rules = data.rows || [];
		} catch (e) {
			error = parseError(e).message;
		} finally {
			loading = false;
		}
	}

	$effect(() => {
		if (open) load();
	});

	function formatExpires(iso: string | null): string {
		if (!iso) return '—';
		try {
			const d = new Date(iso);
			if (isNaN(d.getTime())) return iso;
			return d.toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' });
		} catch {
			return iso;
		}
	}

	async function onAdd() {
		formError = '';
		const cidr = newCidr.trim();
		if (!cidr.includes('/')) {
			formError = 'CIDR must include a prefix, e.g. 192.168.1.0/24';
			return;
		}
		saving = true;
		try {
			const body: IPRuleCreateRequest = {
				cidr,
				action: newAction,
				description: newDesc.trim(),
			};
			if (newExpires) body.expiresAt = newExpires;
			await createIPRule(body);
			showToast(`IP rule added: ${cidr}`);
			newCidr = '';
			newAction = 'block';
			newDesc = '';
			newExpires = '';
			showForm = false;
			await load();
		} catch (e) {
			formError = parseError(e).message;
		} finally {
			saving = false;
		}
	}

	async function onDelete(id: number) {
		if (deleteConfirmId === id) {
			// Confirm — capture rule data before deletion for undo
			const deletedRule = rules.find(r => r.id === id);
			try {
				await deleteIPRule(id);
					if (deletedRule) {
						showToast(`IP rule deleted: ${deletedRule.cidr}`, {
							actionLabel: 'Undo',
							onAction: async () => {
								try {
									// Undo fidelity: recreate the rule exactly as it was —
									// restoring expiresAt keeps a time-bounded rule from
									// silently becoming permanent (the create path sets it
									// only when present, mirroring onAdd).
									const body: IPRuleCreateRequest = {
										cidr: deletedRule.cidr,
										action: deletedRule.action,
										description: deletedRule.description,
									};
									if (deletedRule.expiresAt) body.expiresAt = deletedRule.expiresAt;
									await createIPRule(body);
								} catch { /* ignore */ }
								await load();
							},
						});
					} else {
					showToast('IP rule deleted');
				}
				deleteConfirmId = null;
				await load();
			} catch (e) {
				error = parseError(e).message;
				deleteConfirmId = null;
			}
		} else {
			deleteConfirmId = id;
		}
	}

	function actionBadgeVariant(action: string): 'success' | 'danger' | 'neutral' {
		return action === 'allow' ? 'success' : 'danger';
	}
</script>

<Dialog open={open} title="IP Rules" wide={true} {onClose}>
	{#snippet children()}
		<div class="iprules-body">
			<div class="iprules-toolbar">
				<Button variant="primary" size="sm" onclick={() => { showForm = !showForm; formError = ''; }} disabled={!hasPermission($adminPermissions, 'security.write')}>
					<Icon name={showForm ? 'X' : 'Plus'} size={14} strokeWidth={1.75} />
					{showForm ? 'Cancel' : 'Add rule'}
				</Button>
			</div>

			{#if showForm}
				<div class="iprules-form">
					<div class="form-row">
						<div class="form-field">
							<label class="form-label" for="ipr-cidr">CIDR</label>
							<Input
								id="ipr-cidr"
								type="text"
								placeholder="192.168.1.0/24"
								mono={true}
								bind:value={newCidr}
							/>
						</div>
						<div class="form-field">
							<label class="form-label" for="ipr-action">Action</label>
							<Select
								id="ipr-action"
								bind:value={newAction}
								options={[
									{ value: 'block', label: 'Block' },
									{ value: 'allow', label: 'Allow' },
								]}
							/>
						</div>
					</div>
					<div class="form-field">
						<label class="form-label" for="ipr-desc">Description</label>
						<Input
							id="ipr-desc"
							type="text"
							placeholder="Reason for this rule"
							bind:value={newDesc}
						/>
					</div>
					<div class="form-field">
						<label class="form-label" for="ipr-expires">Expires (optional)</label>
						<Input
							id="ipr-expires"
							type="datetime-local"
							bind:value={newExpires}
						/>
					</div>
					{#if formError}
						<div class="form-error">{formError}</div>
					{/if}
					<div class="form-actions">
						<Button variant="primary" size="sm" onclick={onAdd} disabled={saving || !newCidr.trim() || !hasPermission($adminPermissions, 'security.write')}>
							{saving ? 'Adding...' : 'Add rule'}
						</Button>
					</div>
				</div>
			{/if}

			{#if loading}
				<div class="iprules-loading">
					<Spinner size={20} />
					<div>Loading rules...</div>
				</div>
			{:else if error}
				<div class="iprules-error">{error}</div>
			{:else if rules.length === 0}
				<EmptyState title="No IP rules configured" watermark={false} />
			{:else}
				<div class="iprules-table">
					<Table
						columns={RULE_COLUMNS}
						rows={rules.map((r) => ({
							cidr: r.cidr,
							action: r.action,
							description: r.description || '—',
							expiresAt: formatExpires(r.expiresAt),
							actions: r.id,
						})) as unknown as Record<string, unknown>[]}
					>
						{#snippet cell(row, col)}
							{#if col.key === 'cidr'}
								{String(row['cidr'])}
							{:else if col.key === 'action'}
								<Badge variant={actionBadgeVariant(String(row['action']))} label={String(row['action'])} />
							{:else if col.key === 'description'}
								{String(row['description'])}
							{:else if col.key === 'expiresAt'}
								{String(row['expiresAt'])}
							{:else if col.key === 'actions'}
								{@const id = Number(row['actions'])}
								{#if deleteConfirmId === id}
									<div class="delete-confirm">
										<span class="delete-prompt">Delete?</span>
										<Button variant="primary" size="sm" onclick={() => onDelete(id)} disabled={!hasPermission($adminPermissions, 'security.write')}>
											Yes, delete
										</Button>
										<Button variant="ghost" size="sm" onclick={() => { deleteConfirmId = null; }}>
											Cancel
										</Button>
									</div>
								{:else}
									<IconButton
										variant="ghost"
										size="sm"
										label="Delete rule"
										onclick={() => onDelete(id)}
										disabled={!hasPermission($adminPermissions, 'security.write')}
									>
										<Icon name="Trash2" size={14} strokeWidth={1.75} />
									</IconButton>
								{/if}
							{/if}
						{/snippet}
					</Table>
				</div>
			{/if}
		</div>
	{/snippet}
</Dialog>

<style>
	.iprules-body {
		display: flex;
		flex-direction: column;
		gap: 12px;
		min-height: 200px;
	}

	.iprules-toolbar {
		display: flex;
		justify-content: flex-end;
		gap: 8px;
	}

	.iprules-form {
		display: flex;
		flex-direction: column;
		gap: 10px;
		padding: 12px;
		background: var(--surface-sunken);
		border: 1px solid var(--border-default);
		border-radius: var(--radius-sm);
	}

	.form-row {
		display: flex;
		gap: 10px;
	}

	.form-field {
		display: flex;
		flex-direction: column;
		gap: 4px;
		flex: 1;
		min-width: 0;
	}

	.form-label {
		font-family: var(--font-sans);
		font-size: var(--text-xs);
		font-weight: var(--weight-medium);
		color: var(--text-secondary);
	}

	.form-error {
		font-family: var(--font-sans);
		font-size: var(--text-xs);
		color: var(--danger-fg);
		background: var(--danger-bg);
		padding: 6px 10px;
		border-radius: var(--radius-sm);
		border: 1px solid color-mix(in srgb, var(--danger-solid) 15%, transparent);
	}

	.form-actions {
		display: flex;
		gap: 8px;
		padding-top: 4px;
	}

	.iprules-table {
		min-height: 100px;
	}

	.delete-confirm {
		display: flex;
		align-items: center;
		gap: 6px;
	}

	.delete-prompt {
		font-family: var(--font-sans);
		font-size: var(--text-xs);
		color: var(--danger-fg);
		white-space: nowrap;
	}

	.iprules-loading {
		display: flex;
		flex-direction: column;
		align-items: center;
		gap: 12px;
		padding: 32px 16px;
		color: var(--text-secondary);
		font-family: var(--font-sans);
		font-size: var(--text-sm);
	}

	.iprules-error {
		font-family: var(--font-sans);
		font-size: var(--text-sm);
		color: var(--danger-fg);
		text-align: center;
		padding: 16px;
	}
</style>
