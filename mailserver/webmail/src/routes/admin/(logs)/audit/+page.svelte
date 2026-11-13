<svelte:options runes={true} />

<script lang="ts">
	import { onMount } from 'svelte';
	import {
		Table, Card, Button, Input, Pagination,
		EmptyState, Spinner, Tooltip, type TableColumn, type SortDir,
	} from '$lib/components/ui';
	import {
		fetchAuditLog, exportAuditCSV, verifyAuditChain,
		getAuditPolicy, putAuditPolicy,
		type AuditEntry, type VerifyChainRow, type AuditPolicy,
	} from '$lib/admin/client';
	import { auditActionChip, formatAuditTime, formatAuditTarget } from '$lib/admin/audit';
	import { parseError } from '$lib/errors';
	import { downloadBlob } from '$lib/utils/downloadBlob';
	import { t } from '$lib/i18n';
	import Icon from '$lib/components/Icon.svelte';
	import Dialog from '$lib/components/ui/Dialog.svelte';

	// ── verify state ──────────────────────────────────────────────────────
	type VerifyState = 'idle' | 'verifying' | 'intact' | 'tamper';
	let verifyState = $state<VerifyState>('idle');
	let verifyChain = $state<VerifyChainRow[]>([]);
	let verifyFromId = $state(0);
	let verifyToId = $state(0);

	// Derived: id→valid map for per-row annotation
	const validityMap = $derived(
		new Map(verifyChain.map((r) => [r.id, r.valid]))
	);
	// First broken row id (tamper state)
	const firstBrokenId = $derived(
		verifyChain.find((r) => !r.valid)?.id ?? null
	);

	// Table columns — validity column injected when verify has run
	const BASE_COLUMNS: TableColumn[] = [
		{ key: 'occurredAt',  label: 'Time',   sortable: true,  mono: true },
		{ key: 'userEmail',   label: 'Actor',  sortable: true,  mono: true },
		{ key: 'action',      label: 'Action', sortable: true  },
		{ key: 'target',      label: 'Target', sortable: false, mono: true },
		{ key: 'notes',       label: 'Detail', sortable: false },
		{ key: 'proto',       label: 'Proto',  sortable: false, mono: true },
	];

	const VALIDITY_COLUMN: TableColumn = { key: '_valid', label: '✓', sortable: false };

	const COLUMNS = $derived(
		verifyState === 'intact' || verifyState === 'tamper'
			? [...BASE_COLUMNS, VALIDITY_COLUMN]
			: BASE_COLUMNS
	);

	// ── list state ────────────────────────────────────────────────────────
	let items = $state<AuditEntry[]>([]);
	let loading = $state(true);
	let error = $state('');
	let query = $state('');
	let actionFilter = $state('');
	let total = $state(0);
	let page = $state(1);
	let pageSize = $state(50);
	let sortKey = $state<string | undefined>('occurredAt');
	let sortDir = $state<SortDir>('desc');
	let debounceId: ReturnType<typeof setTimeout> | null = null;

	// ── policy editor state ────────────────────────────────────────────────
	const AREA_CHIPS = ['roles', 'identity', 'audit', 'security', 'system'];

	let policy = $state<AuditPolicy | null>(null);
	let policyLoading = $state(true);
	let policyError = $state('');
	// Working copy (editable)
	let draftLevel = $state<'lean' | 'full'>('lean');
	let draftAreas = $state<string[]>([]);
	// Save states
	let policySaving = $state(false);
	let policySuccess = $state(false);
	// Confirm-on-lower dialog
	let showConfirmLower = $state(false);
	let confirmReason = $state('');

	const policyDirty = $derived(
		policy !== null && (
			draftLevel !== policy.level ||
			JSON.stringify([...draftAreas].sort()) !== JSON.stringify([...policy.reasonRequiredAreas].sort())
		)
	);

	// "Lowering" = full→lean or removing a reason-required area
	const isLowering = $derived(
		policy !== null && (
			(policy.level === 'full' && draftLevel === 'lean') ||
			policy.reasonRequiredAreas.some((a) => !draftAreas.includes(a))
		)
	);

	async function loadPolicy() {
		policyLoading = true;
		policyError = '';
		try {
			policy = await getAuditPolicy();
			draftLevel = policy.level;
			draftAreas = [...policy.reasonRequiredAreas];
		} catch (e) {
			policyError = parseError(e).message;
		} finally {
			policyLoading = false;
		}
	}

	function onSavePolicy() {
		if (!policyDirty) return;
		if (isLowering) {
			confirmReason = '';
			showConfirmLower = true;
		} else {
			void doSavePolicy('');
		}
	}

	async function doSavePolicy(reason: string) {
		showConfirmLower = false;
		policySaving = true;
		policyError = '';
		try {
			await putAuditPolicy({ level: draftLevel, reasonRequiredAreas: draftAreas, reason });
			policy = { level: draftLevel, reasonRequiredAreas: [...draftAreas] };
			policySuccess = true;
			setTimeout(() => { policySuccess = false; }, 3000);
		} catch (e) {
			policyError = parseError(e).message;
		} finally {
			policySaving = false;
		}
	}

	function toggleArea(area: string) {
		if (draftAreas.includes(area)) {
			draftAreas = draftAreas.filter((a) => a !== area);
		} else {
			draftAreas = [...draftAreas, area];
		}
	}

	const confirmTrimmed = $derived(confirmReason.trim());
	const canConfirm = $derived(confirmTrimmed.length > 0);

	function deriveProto(_action: string): string {
		return 'http';
	}

	async function load() {
		loading = true;
		error = '';
		// Reset verify whenever the page re-loads
		verifyState = 'idle';
		verifyChain = [];
		try {
			const data = await fetchAuditLog({
				q: query || undefined,
				action: actionFilter || undefined,
				limit: pageSize,
				offset: (page - 1) * pageSize,
			});
			items = data.items ?? [];
			total = data.total ?? 0;
		} catch (e) {
			error = parseError(e).message;
		} finally {
			loading = false;
		}
	}

	onMount(() => {
		load();
		loadPolicy();
	});

	$effect(() => {
		void query;
		void actionFilter;
		void page;
		void pageSize;
		void sortKey;
		void sortDir;
		if (debounceId === null) {
			load();
		}
	});

	function onTextInput() {
		if (debounceId) clearTimeout(debounceId);
		debounceId = setTimeout(() => {
			page = 1;
			load();
			debounceId = null;
		}, 300);
	}

	function onSort(key: string, dir: SortDir) {
		sortKey = key;
		sortDir = dir;
		page = 1;
	}

	function onPageChange(p: number) { page = p; }
	function onPageSizeChange(s: number) { pageSize = s; page = 1; }

	async function onExportCSV() {
		try {
			const blob = await exportAuditCSV();
			downloadBlob(blob, 'audit-log.csv');
		} catch (e) {
			error = parseError(e).message;
		}
	}

	async function onVerify() {
		if (items.length === 0) return;
		// ponytail: id-range from displayed rows — chain walks by id order, not filter
		const ids = items.map((i) => i.id);
		const fromId = Math.min(...ids);
		const toId = Math.max(...ids);
		verifyFromId = fromId;
		verifyToId = toId;
		verifyState = 'verifying';
		verifyChain = [];
		try {
			const result = await verifyAuditChain(fromId, toId);
			verifyChain = result.chain ?? [];
			const allValid = verifyChain.every((r) => r.valid);
			verifyState = allValid ? 'intact' : 'tamper';
		} catch (e) {
			verifyState = 'idle';
			error = parseError(e).message;
		}
	}
</script>

<header class="page-header">
	<div class="page-header-left">
		<h1>{t('admin.sidebar.audit')}</h1>
		<p class="page-desc">
			Every admin action and security event, across HTTP, IMAP, SMTP and LDAP.
		</p>
	</div>
	<div class="page-header-actions">
		<Button variant="secondary" size="sm" onclick={onExportCSV}>
			<Icon name="Download" size={14} strokeWidth={1.75} />
			Export CSV
		</Button>
		<Tooltip text={t('admin.audit.verify.tooltip_action')}>
			<!-- svelte-ignore a11y_no_noninteractive_tabindex -->
			<span tabindex={0} style="display:inline-flex">
				<Button
					variant="secondary"
					size="sm"
					onclick={onVerify}
					disabled={items.length === 0 || verifyState === 'verifying'}
				>
					<Icon name="ShieldCheck" size={14} strokeWidth={1.75} aria-hidden="true" />
					{t('admin.audit.verify')}
				</Button>
			</span>
		</Tooltip>
	</div>
</header>

<div class="filter-bar">
	<div class="filter-input-wrap">
		<Input
			type="text"
			placeholder="Filter events..."
			mono={true}
			bind:value={query}
			oninput={onTextInput}
		/>
	</div>
</div>

<!-- ── verify result banner ───────────────────────────────────────────── -->
{#if verifyState === 'verifying'}
	<div class="verify-banner verify-banner--verifying" role="status">
		<Spinner size={16} />
		<span>Verifying rows {verifyFromId}–{verifyToId}…</span>
	</div>
{:else if verifyState === 'intact'}
	<div class="verify-banner verify-banner--intact" role="status" aria-live="polite">
		<Icon name="ShieldCheck" size={16} strokeWidth={1.75} aria-hidden="true" />
		<span>✓ Chain intact — rows {verifyFromId}–{verifyToId} verified</span>
	</div>
{:else if verifyState === 'tamper'}
	<!-- ponytail: assertive so screen reader announces chain break immediately -->
	<div class="verify-banner verify-banner--tamper" role="alert" aria-live="assertive">
		<div class="verify-banner__body">
			<Icon name="ShieldAlert" size={18} strokeWidth={1.75} aria-hidden="true" />
			<div>
				<strong>Tamper detected</strong>
				<span> — the chain breaks at row {firstBrokenId}. Entries after this point cannot be trusted.</span>
				<Tooltip text={t('admin.audit.verify.tooltip_invalid')}>
					<!-- svelte-ignore a11y_no_noninteractive_tabindex -->
					<span tabindex={0} class="verify-banner__what">
						<Icon name="Info" size={13} strokeWidth={1.75} aria-hidden="true" />
						<span class="sr-only">What this means: altered, deleted, or reordered rows</span>
					</span>
				</Tooltip>
			</div>
		</div>
		<Button variant="danger" size="sm" onclick={onExportCSV}>
			<Icon name="Download" size={14} strokeWidth={1.75} aria-hidden="true" />
			Export evidence (CSV)
		</Button>
	</div>
{/if}

{#if loading}
	<div class="audit-empty">
		<Spinner size={28} />
		<div>Loading audit log...</div>
	</div>
{:else if error}
	<div class="audit-error">
		<Icon name="FileSearch" size={24} strokeWidth={1.75} />
		<div>{error}</div>
		<Button variant="secondary" size="sm" onclick={load}>Retry</Button>
	</div>
{:else if items.length === 0}
	<EmptyState title="No audit entries found" watermark={true} />
{:else}
	<Card flush={true}>
		{@const rows = items.map((item) => ({
			_id: item.id,
			occurredAt: formatAuditTime(item.occurredAt),
			userEmail: item.userEmail || item.ip || 'system',
			action: item.action,
			target: formatAuditTarget(item.targetType ?? null, item.targetId ?? null),
			notes: item.notes || '—',
			proto: deriveProto(item.action),
		})) as Record<string, unknown>[]}
		<Table
			columns={COLUMNS}
			rows={rows as unknown as Record<string, unknown>[]}
			sortKey={sortKey}
			sortDir={sortDir}
			onSort={onSort}
			rowClass={(row) => {
				const id = Number(row['_id']);
				const valid = validityMap.get(id);
				return valid === false ? 'row--tamper' : '';
			}}
		>
			{#snippet cell(row, col)}
				{#if col.key === 'action'}
					{@const raw = String(row['action'] ?? '')}
					{@const slug = auditActionChip(raw)}
					<code class="action-chip">{slug}</code>
				{:else if col.key === 'proto'}
					{@const raw = String(row['proto'] ?? '')}
					<span class="proto-label">{raw}</span>
				{:else if col.key === '_valid'}
					{@const rowId = Number(row['_id'])}
					{@const isValid = validityMap.get(rowId)}
					{#if isValid === true}
						<Tooltip text={t('admin.audit.verify.tooltip_valid')}>
							<!-- svelte-ignore a11y_no_noninteractive_tabindex -->
							<span tabindex={0} class="validity-cell validity-cell--ok" aria-label="valid">
								<Icon name="ShieldCheck" size={13} strokeWidth={2} aria-hidden="true" />
								<span class="sr-only">valid</span>
							</span>
						</Tooltip>
					{:else if isValid === false}
						<Tooltip text={t('admin.audit.verify.tooltip_invalid')}>
							<!-- svelte-ignore a11y_no_noninteractive_tabindex -->
							<span tabindex={0} class="validity-cell validity-cell--bad" aria-label="INVALID">
								<Icon name="ShieldAlert" size={13} strokeWidth={2} aria-hidden="true" />
								<span class="sr-only">INVALID</span>
							</span>
						</Tooltip>
					{/if}
				{/if}
			{/snippet}

			{#snippet footer()}
				<Pagination
					page={page}
					pageSize={pageSize}
					total={total}
					pageSizeOptions={[25, 50, 100]}
					onPageChange={onPageChange}
					onPageSizeChange={onPageSizeChange}
				/>
			{/snippet}
		</Table>
	</Card>
{/if}

<!-- ── Audit policy editor ────────────────────────────────────────────── -->
<details class="policy-editor-wrap" open={false}>
	<summary class="policy-editor-summary">
		<Icon name="Settings" size={14} strokeWidth={1.75} aria-hidden="true" />
		{t('admin.audit.policy.title')}
	</summary>
	<Card>
		{#if policyLoading}
			<div class="policy-loading"><Spinner size={20} /></div>
		{:else if policyError}
			<div class="policy-error" role="alert">{policyError}</div>
		{:else}
			<div class="policy-body">
				<p class="policy-reassurance">
					{t('admin.audit.policy.reassurance')}
				</p>

				<!-- Level segmented control -->
				<div class="policy-field">
					<span class="policy-field__label">
						{t('admin.audit.policy.level.lean')} / {t('admin.audit.policy.level.full')}
						<Tooltip text={t('admin.audit.policy.level.tooltip')}>
							<!-- svelte-ignore a11y_no_noninteractive_tabindex -->
							<span tabindex={0} class="policy-tooltip-icon" aria-label={t('admin.audit.policy.level.tooltip')}>
								<Icon name="Info" size={13} strokeWidth={1.75} aria-hidden="true" />
							</span>
						</Tooltip>
					</span>
					<div class="policy-level-control" role="radiogroup" aria-label="Audit level">
						<label class="policy-level-opt" class:policy-level-opt--active={draftLevel === 'lean'}>
							<input
								type="radio"
								name="audit-level"
								value="lean"
								checked={draftLevel === 'lean'}
								onchange={() => (draftLevel = 'lean')}
							/>
							{t('admin.audit.policy.level.lean')}
						</label>
						<label class="policy-level-opt" class:policy-level-opt--active={draftLevel === 'full'}>
							<input
								type="radio"
								name="audit-level"
								value="full"
								checked={draftLevel === 'full'}
								onchange={() => (draftLevel = 'full')}
							/>
							{t('admin.audit.policy.level.full')}
						</label>
					</div>
				</div>

				<!-- reason_required_areas chips -->
				<div class="policy-field">
					<span class="policy-field__label">
						{t('admin.audit.policy.areas.label')}
						<Tooltip text={t('admin.audit.policy.areas.tooltip')}>
							<!-- svelte-ignore a11y_no_noninteractive_tabindex -->
							<span tabindex={0} class="policy-tooltip-icon">
								<Icon name="Info" size={13} strokeWidth={1.75} aria-hidden="true" />
							</span>
						</Tooltip>
					</span>
					<div class="policy-chips">
						{#each AREA_CHIPS as area}
							<button
								type="button"
								class="policy-chip"
								class:policy-chip--active={draftAreas.includes(area)}
								onclick={() => toggleArea(area)}
								aria-pressed={draftAreas.includes(area)}
							>{area}</button>
						{/each}
					</div>
					{#if draftAreas.length === 0}
						<span class="policy-chips-empty">{t('admin.audit.policy.areas.empty_hint')}</span>
					{/if}
				</div>

				<!-- First-run recommendation -->
				{#if policy?.level === 'lean' && policy.reasonRequiredAreas.length === 0}
					<p class="policy-recommend">{t('admin.audit.policy.recommend')}</p>
				{/if}

				<div class="policy-actions">
					{#if policySuccess}
						<span class="policy-saved" role="status">{t('admin.audit.policy.saved')}</span>
					{/if}
					<Button
						variant="primary"
						size="sm"
						disabled={!policyDirty || policySaving}
						onclick={onSavePolicy}
					>
						{#if policySaving}
							<Spinner size={16} />
							{t('admin.audit.policy.saving')}
						{:else}
							{t('admin.audit.policy.save')}
						{/if}
					</Button>
				</div>
			</div>
		{/if}
	</Card>
</details>

<!-- Confirm-lower dialog -->
<Dialog
	open={showConfirmLower}
	title={t('admin.audit.policy.confirm.title')}
	onClose={() => (showConfirmLower = false)}
>
	{#snippet children()}
		<div class="policy-confirm-body">
			<p>{t('admin.audit.policy.confirm.body')}</p>
			<div class="policy-confirm-reason">
				<label for="policy-confirm-reason-input" class="sj-field__label">
					{t('admin.audit.reason.label')}
				</label>
				<!-- svelte-ignore a11y_autofocus -->
				<textarea
					id="policy-confirm-reason-input"
					class="policy-confirm-textarea"
					bind:value={confirmReason}
					rows={3}
					maxlength={1000}
					placeholder={t('admin.audit.reason.placeholder')}
					autofocus
				></textarea>
				<span class="sj-field__hint">{t('admin.audit.reason.helper', { area: 'audit' })}</span>
			</div>
		</div>
	{/snippet}
	{#snippet footer()}
		<Button
			variant="danger"
			disabled={!canConfirm}
			onclick={() => doSavePolicy(confirmTrimmed)}
		>{t('admin.audit.policy.confirm.apply')}</Button>
		<Button variant="ghost" onclick={() => (showConfirmLower = false)}>{t('common.cancel')}</Button>
	{/snippet}
</Dialog>

<style>
	.page-header {
		display: flex;
		align-items: flex-start;
		justify-content: space-between;
		gap: 16px;
		margin-bottom: 16px;
		flex-wrap: wrap;
	}

	.page-header-left {
		flex: 1;
		min-width: 0;
	}

	.page-header h1 {
		font-family: var(--font-sans);
		font-size: var(--text-2xl);
		font-weight: var(--weight-semibold);
		letter-spacing: var(--tracking-heading);
		color: var(--text-primary);
		margin: 0 0 4px;
	}

	.page-desc {
		font-family: var(--font-sans);
		font-size: var(--text-sm);
		color: var(--text-secondary);
		margin: 0;
		line-height: var(--leading-normal);
	}

	.page-header-actions {
		display: flex;
		gap: 8px;
		flex-shrink: 0;
	}

	.filter-bar {
		display: flex;
		align-items: center;
		gap: 12px;
		margin-bottom: 12px;
		flex-wrap: wrap;
	}

	.filter-input-wrap {
		flex: 1 1 200px;
		max-width: 320px;
		min-width: 160px;
	}

	/* ── verify banners ──────────────────────────────────────────── */

	.verify-banner {
		display: flex;
		align-items: center;
		gap: 10px;
		padding: 10px 14px;
		border-radius: var(--radius-md);
		font-family: var(--font-sans);
		font-size: var(--text-sm);
		margin-bottom: 10px;
		border: 1px solid transparent;
	}

	.verify-banner--verifying {
		background: var(--surface-sunken);
		color: var(--text-secondary);
		border-color: var(--border-subtle);
	}

	.verify-banner--intact {
		background: var(--success-bg);
		color: var(--success-fg);
		border-color: var(--success-solid);
	}

	.verify-banner--tamper {
		background: var(--danger-bg);
		color: var(--danger-fg);
		border-color: var(--danger-solid);
		justify-content: space-between;
		flex-wrap: wrap;
		gap: 8px;
	}

	.verify-banner__body {
		display: flex;
		align-items: flex-start;
		gap: 10px;
		flex: 1;
	}

	.verify-banner__what {
		display: inline-flex;
		align-items: center;
		cursor: help;
		margin-left: 4px;
		opacity: 0.7;
	}

	/* ── validity column ─────────────────────────────────────────── */

	.validity-cell {
		display: inline-flex;
		align-items: center;
		justify-content: center;
		width: 22px;
		height: 22px;
		border-radius: var(--radius-xs);
		cursor: default;
	}

	.validity-cell--ok {
		color: var(--success-fg);
	}

	.validity-cell--bad {
		color: var(--danger-fg);
	}

	/* ── tamper row highlight ────────────────────────────────────── */

	:global(tr.row--tamper td) {
		background: var(--danger-bg);
	}

	/* ── action / proto labels ───────────────────────────────────── */

	.action-chip {
		font-family: var(--font-mono);
		font-size: var(--text-xs);
		background: var(--surface-sunken);
		border: 1px solid var(--border-subtle);
		border-radius: var(--radius-xs);
		padding: 1px 5px;
		color: var(--text-secondary);
		white-space: nowrap;
	}

	.proto-label {
		font-family: var(--font-mono);
		font-size: var(--text-2xs);
		color: var(--text-tertiary);
	}

	.audit-empty {
		display: flex;
		flex-direction: column;
		align-items: center;
		gap: 16px;
		padding: 64px 16px;
		color: var(--text-secondary);
		font-family: var(--font-sans);
		font-size: var(--text-sm);
	}

	.audit-error {
		display: flex;
		flex-direction: column;
		align-items: center;
		gap: 12px;
		padding: 48px 16px;
		color: var(--text-secondary);
		font-family: var(--font-sans);
		font-size: var(--text-sm);
		text-align: center;
	}

	.sr-only {
		position: absolute;
		width: 1px;
		height: 1px;
		padding: 0;
		margin: -1px;
		overflow: hidden;
		clip-path: inset(50%);
		white-space: nowrap;
		border: 0;
	}

	/* ── policy editor ───────────────────────────────────────────── */

	.policy-editor-wrap {
		margin-top: 24px;
	}

	.policy-editor-summary {
		display: flex;
		align-items: center;
		gap: 8px;
		font-family: var(--font-sans);
		font-size: var(--text-sm);
		font-weight: var(--weight-medium);
		color: var(--text-secondary);
		cursor: pointer;
		padding: 6px 0;
		list-style: none;
		user-select: none;
		margin-bottom: 8px;
	}

	.policy-editor-summary::-webkit-details-marker { display: none; }

	.policy-loading {
		padding: 24px;
		display: flex;
		justify-content: center;
	}

	.policy-error {
		color: var(--danger-fg);
		font-size: var(--text-sm);
		padding: 12px 16px;
	}

	.policy-body {
		padding: 16px;
		display: flex;
		flex-direction: column;
		gap: var(--space-4, 16px);
	}

	.policy-reassurance {
		font-family: var(--font-sans);
		font-size: var(--text-sm);
		color: var(--text-secondary);
		background: var(--surface-sunken);
		border-radius: var(--radius-sm);
		padding: 10px 14px;
		margin: 0;
		border-left: 3px solid var(--accent);
	}

	.policy-field {
		display: flex;
		flex-direction: column;
		gap: var(--space-2, 8px);
	}

	.policy-field__label {
		display: inline-flex;
		align-items: center;
		gap: 4px;
		font-family: var(--font-sans);
		font-size: var(--text-sm);
		font-weight: var(--weight-medium);
		color: var(--text-primary);
	}

	.policy-tooltip-icon {
		display: inline-flex;
		align-items: center;
		color: var(--text-tertiary);
		cursor: help;
		border-radius: var(--radius-xs);
		outline-offset: 2px;
	}

	.policy-tooltip-icon:focus-visible {
		outline: 2px solid var(--accent);
	}

	.policy-level-control {
		display: inline-flex;
		border: 1px solid var(--border-default);
		border-radius: var(--radius-sm);
		overflow: hidden;
		width: fit-content;
	}

	.policy-level-opt {
		display: inline-flex;
		align-items: center;
		justify-content: center;
		padding: 6px 18px;
		font-family: var(--font-sans);
		font-size: var(--text-sm);
		cursor: pointer;
		background: var(--surface-card);
		color: var(--text-secondary);
		min-height: 44px; /* touch target */
		transition: background var(--duration-fast) var(--ease-out);
	}

	.policy-level-opt input[type='radio'] {
		position: absolute;
		opacity: 0;
		width: 0;
		height: 0;
	}

	.policy-level-opt--active {
		background: var(--accent);
		color: var(--text-on-accent);
		font-weight: var(--weight-medium);
	}

	.policy-chips {
		display: flex;
		flex-wrap: wrap;
		gap: var(--space-2, 8px);
	}

	.policy-chip {
		display: inline-flex;
		align-items: center;
		padding: 4px 12px;
		font-family: var(--font-mono);
		font-size: var(--text-sm);
		border: 1px solid var(--border-default);
		border-radius: var(--radius-full);
		background: var(--surface-card);
		color: var(--text-secondary);
		cursor: pointer;
		min-height: 32px;
		transition:
			background var(--duration-fast) var(--ease-out),
			color var(--duration-fast) var(--ease-out);
	}

	.policy-chip--active {
		background: var(--accent);
		color: var(--text-on-accent);
		border-color: var(--accent);
	}

	.policy-chip:focus-visible {
		outline: 2px solid var(--accent);
		outline-offset: 2px;
	}

	.policy-chips-empty {
		font-family: var(--font-sans);
		font-size: var(--text-xs);
		color: var(--text-tertiary);
	}

	.policy-recommend {
		font-family: var(--font-sans);
		font-size: var(--text-xs);
		color: var(--text-tertiary);
		margin: 0;
	}

	.policy-actions {
		display: flex;
		align-items: center;
		gap: var(--space-3, 12px);
		justify-content: flex-end;
	}

	.policy-saved {
		font-family: var(--font-sans);
		font-size: var(--text-sm);
		color: var(--success-fg);
	}

	/* ── confirm-lower dialog ────────────────────────────────────── */

	.policy-confirm-body {
		display: flex;
		flex-direction: column;
		gap: var(--space-3, 12px);
	}

	.policy-confirm-body p {
		margin: 0;
	}

	.policy-confirm-reason {
		display: flex;
		flex-direction: column;
		gap: 5px;
	}

	.policy-confirm-textarea {
		min-height: 64px;
		padding: var(--space-2) var(--space-3);
		font-family: var(--font-sans);
		font-size: var(--text-sm);
		line-height: var(--leading-normal);
		color: var(--text-primary);
		background: var(--surface-card);
		border: 1px solid var(--border-default);
		border-radius: var(--radius-sm);
		width: 100%;
		resize: vertical;
	}

	.policy-confirm-textarea:focus-visible {
		outline: none;
		border-color: var(--accent);
		box-shadow: var(--focus-ring);
	}

	.sj-field__label {
		font-size: var(--text-sm);
		font-weight: var(--weight-medium);
		color: var(--text-primary);
	}

	.sj-field__hint {
		font-size: var(--text-sm);
		color: var(--text-caption);
	}
</style>
