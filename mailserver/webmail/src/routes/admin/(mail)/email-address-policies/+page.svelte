<svelte:options runes={true} />

<script lang="ts">
	import { onMount, onDestroy } from 'svelte';
	import {
		adminListEAPolicies,
		adminCreateEAPolicy,
		adminUpdateEAPolicy,
		adminDeleteEAPolicy,
		adminReorderEAPolicies,
		adminPreviewEAPolicy,
		adminApplyEAPolicy,
		adminApplyStatusEAPolicy,
		adminMatchCountEAPolicy,
		adminDomainList,
		adminUserList,
		adminMailboxList,
		adminDeptTree,
		type EmailAddressPolicy,
		type EmailAddressPolicyInput,
		type Domain,
		type AdminUser,
		type TreeNode,
	} from '$lib/admin/client';
	import { parseError } from '$lib/errors';
	import { adminPermissions, hasPermission } from '$lib/stores/auth';
	import { t, locale } from '$lib/i18n';
	import {
		Card, Table, Badge, Button, Input, Textarea, Checkbox, Select, Switch,
		Dialog, EmptyState, Spinner, Progress,
		type TableColumn,
	} from '$lib/components/ui';
	import Icon from '$lib/components/Icon.svelte';

	// $locale subscription keeps t() reactive across locale switches.
	$locale;

	const MAILBOX_TYPES = ['personal', 'shared', 'resource', 'distribution'] as const;
	type MailboxType = (typeof MAILBOX_TYPES)[number];

	// ── List state ──
	let policies = $state<EmailAddressPolicy[]>([]);
	let loading = $state(true);
	let error = $state('');

	// ── Data sources (loaded once) ──
	let domains = $state<Domain[]>([]);
	let domainsError = $state('');
	let departments = $state<string[]>([]);

	// ── Editor state ──
	let showEditor = $state(false);
	let editing = $state<EmailAddressPolicy | null>(null);
	let saving = $state(false);
	let saveError = $state('');

	let fName = $state('');
	let fPriority = $state(100);
	let fEnabled = $state(true);
	let fOverwrite = $state(false);
	let fPrimaryTemplate = $state('');
	let fAdditionalTemplates = $state(''); // newline-separated in the textarea
	let fDuplicateResolution = $state('numeric_suffix');

	// Conditions
	let condDepartment = $state<string[]>([]);
	let condDomainNames = $state<string[]>([]); // admin sees names; mapped → ids on save
	let condMailboxType = $state<string[]>([]);
	let condAdOu = $state('');

	// ── DR4: overwrite confirm ──
	let overwriteConfirmed = $state(false);

	// ── DR3: live preview ──
	let sampleQuery = $state('');
	let sampleResults = $state<AdminUser[]>([]);
	let sampleUser = $state<AdminUser | null>(null);
	let sampleSearching = $state(false);
	let preview = $state<{ primary: string; additionals: string[]; collided: boolean; suffix: string } | null>(null);
	let previewing = $state(false);
	let previewError = $state('');

	// ── DR3: live match count ──
	let matchCount = $state<number | null>(null);
	let matchCounting = $state(false);

	// ── Delete confirm ──
	let showDelete = $state(false);
	let deleteTarget = $state<EmailAddressPolicy | null>(null);

	// ── Apply flow ──
	let applyJobId = $state<number | null>(null);
	let applyStatus = $state<'idle' | 'queued' | 'running' | 'done' | 'error'>('idle');
	let applyApplied = $state(0);
	let applyTotal = $state<number | null>(null);
	let applyError = $state('');
	let applyPolicyId = $state<number | null>(null); // null = apply all
	let applyTimer: ReturnType<typeof setTimeout> | null = null;

	onMount(() => {
		load();
		loadSources();
	});

	onDestroy(() => {
		clearTimeout(matchTimer ?? undefined);
		clearTimeout(sampleTimer ?? undefined);
		clearTimeout(previewTimer ?? undefined);
		clearTimeout(applyTimer ?? undefined);
	});

	async function load() {
		loading = true;
		error = '';
		try {
			policies = await adminListEAPolicies();
		} catch (e) {
			error = parseError(e).message;
		} finally {
			loading = false;
		}
	}

	async function loadSources() {
		await loadDomains();
		try {
			const tree = await adminDeptTree();
			departments = flattenDeptNames(tree);
		} catch {
			departments = [];
		}
	}

	async function loadDomains() {
		domainsError = '';
		try {
			domains = await adminDomainList();
		} catch (e) {
			domains = [];
			domainsError = parseError(e).message;
		}
	}

	function flattenDeptNames(nodes: TreeNode[]): string[] {
		const out: string[] = [];
		const walk = (ns: TreeNode[]) => {
			for (const n of ns) {
				out.push(n.name);
				if (n.children?.length) walk(n.children);
			}
		};
		walk(nodes);
		// De-dup, keep stable order.
		return Array.from(new Set(out));
	}

	function domainNameById(id: number): string {
		return domains.find((d) => d.id === id)?.name ?? `#${id}`;
	}

	// ── Editor open/close ──
	function openNew() {
		editing = null;
		fName = '';
		fPriority = policies.length > 0 ? Math.max(...policies.map((p) => p.priority)) + 10 : 100;
		fEnabled = true;
		fOverwrite = false;
		fPrimaryTemplate = '{first_initial}{surname}@{domain}';
		fAdditionalTemplates = '';
		fDuplicateResolution = 'numeric_suffix';
		condDepartment = [];
		condDomainNames = [];
		condMailboxType = [];
		condAdOu = '';
		resetEditorTransient();
		showEditor = true;
	}

	function openEdit(p: EmailAddressPolicy) {
		editing = p;
		fName = p.name;
		fPriority = p.priority;
		fEnabled = p.enabled;
		fOverwrite = p.overwriteDirectoryAddress;
		fPrimaryTemplate = p.primaryTemplate;
		fAdditionalTemplates = (p.additionalTemplates ?? []).join('\n');
		fDuplicateResolution = p.duplicateResolution || 'numeric_suffix';
		condDepartment = [...(p.condDepartment ?? [])];
		condDomainNames = (p.condDomainIds ?? []).map(domainNameById);
		condMailboxType = [...(p.condMailboxType ?? [])];
		condAdOu = (p.condAdOu ?? []).join(', ');
		resetEditorTransient();
		// An already-overwriting saved policy counts as previously confirmed.
		overwriteConfirmed = p.overwriteDirectoryAddress;
		showEditor = true;
		void runMatchCount();
	}

	function resetEditorTransient() {
		saveError = '';
		overwriteConfirmed = false;
		sampleQuery = '';
		sampleResults = [];
		sampleUser = null;
		preview = null;
		previewError = '';
		matchCount = null;
	}

	function closeEditor() {
		showEditor = false;
		editing = null;
	}

	// ── Save ──
	function parseAdditional(): string[] {
		return fAdditionalTemplates
			.split('\n')
			.map((s) => s.trim())
			.filter(Boolean);
	}

	function parseAdOu(): string[] {
		return condAdOu
			.split(',')
			.map((s) => s.trim())
			.filter(Boolean);
	}

	function selectedDomainIds(): number[] {
		return condDomainNames
			.map((name) => domains.find((d) => d.name === name)?.id)
			.filter((id): id is number => typeof id === 'number');
	}

	function buildInput(): EmailAddressPolicyInput {
		const adOu = parseAdOu();
		// DATA-LOSS GUARD: if the domain list failed to load and we're editing an
		// existing policy, preserve the original condDomainIds rather than
		// re-deriving from the (empty) domain list — which would silently clear them.
		const domainIds = (domainsError && editing?.condDomainIds?.length)
			? editing.condDomainIds
			: selectedDomainIds();
		return {
			name: fName.trim(),
			priority: fPriority,
			enabled: fEnabled,
			overwriteDirectoryAddress: fOverwrite,
			primaryTemplate: fPrimaryTemplate.trim(),
			additionalTemplates: parseAdditional(),
			duplicateResolution: fDuplicateResolution,
			condDepartment: condDepartment.length ? condDepartment : null,
			condDomainIds: domainIds.length ? domainIds : null,
			condMailboxType: condMailboxType.length ? condMailboxType : null,
			condAdOu: adOu.length ? adOu : null,
		};
	}

	async function save() {
		if (!fName.trim()) { saveError = t('admin.eap.name') + ' — required'; return; }
		if (!fPrimaryTemplate.trim()) { saveError = t('admin.eap.primary_template') + ' — required'; return; }
		if (fOverwrite && !overwriteConfirmed) { saveError = t('admin.eap.override_warning'); return; }
		saving = true;
		saveError = '';
		try {
			const input = buildInput();
			if (editing) {
				await adminUpdateEAPolicy(editing.id, input);
			} else {
				await adminCreateEAPolicy(input);
			}
			closeEditor();
			await load();
		} catch (e) {
			// Surfaces backend 409 duplicate-priority / 400 invalid-template messages.
			saveError = parseError(e).message;
		} finally {
			saving = false;
		}
	}

	// ── Reorder (DR5: a11y labels) ──
	let reordering = $state(false);
	async function move(index: number, dir: -1 | 1) {
		const to = index + dir;
		if (to < 0 || to >= policies.length) return;
		const next = [...policies];
		[next[index], next[to]] = [next[to], next[index]];
		policies = next;
		reordering = true;
		try {
			await adminReorderEAPolicies(next.map((p) => p.id));
			await load();
		} catch (e) {
			await load();
			error = parseError(e).message;
		} finally {
			reordering = false;
		}
	}

	// ── Delete ──
	function askDelete(p: EmailAddressPolicy) {
		deleteTarget = p;
		showDelete = true;
	}

	async function confirmDelete() {
		if (!deleteTarget) return;
		try {
			await adminDeleteEAPolicy(deleteTarget.id);
			showDelete = false;
			deleteTarget = null;
			await load();
		} catch (e) {
			error = parseError(e).message;
		}
	}

	// ── DR3: debounced match count ──
	let matchTimer: ReturnType<typeof setTimeout> | null = null;
	function scheduleMatchCount() {
		if (matchTimer) clearTimeout(matchTimer);
		matchTimer = setTimeout(() => void runMatchCount(), 400);
	}

	async function runMatchCount() {
		matchCounting = true;
		try {
			const adOu = parseAdOu();
			const domainIds = selectedDomainIds();
			const res = await adminMatchCountEAPolicy({
				condDepartment: condDepartment.length ? condDepartment : null,
				condDomainIds: domainIds.length ? domainIds : null,
				condMailboxType: condMailboxType.length ? condMailboxType : null,
				condAdOu: adOu.length ? adOu : null,
			});
			matchCount = res.count;
		} catch {
			matchCount = null;
		} finally {
			matchCounting = false;
		}
	}

	// ── DR3: sample-user search + live preview ──
	let sampleTimer: ReturnType<typeof setTimeout> | null = null;
	function onSampleQuery(v: string) {
		sampleQuery = v;
		if (sampleTimer) clearTimeout(sampleTimer);
		sampleTimer = setTimeout(() => void searchSample(), 350);
	}

	async function searchSample() {
		const q = sampleQuery.trim();
		if (!q) { sampleResults = []; return; }
		sampleSearching = true;
		try {
			sampleResults = await adminUserList(q, 8);
		} catch {
			sampleResults = [];
		} finally {
			sampleSearching = false;
		}
	}

	async function pickSample(u: AdminUser) {
		sampleUser = u;
		sampleResults = [];
		sampleQuery = u.email;
		await runPreview();
	}

	let previewTimer: ReturnType<typeof setTimeout> | null = null;
	function schedulePreview() {
		if (previewTimer) clearTimeout(previewTimer);
		previewTimer = setTimeout(() => void runPreview(), 400);
	}

	async function runPreview() {
		preview = null;
		previewError = '';
		if (!editing || !sampleUser) return; // only for saved policies w/ a chosen user
		previewing = true;
		try {
			const mbs = await adminMailboxList(undefined, sampleUser.id);
			const primaryMb = mbs.find((m) => m.isPrimary) ?? mbs[0];
			if (!primaryMb) { previewError = 'User has no mailbox'; return; }
			preview = await adminPreviewEAPolicy(editing.id, sampleUser.id, primaryMb.id);
		} catch (e) {
			previewError = parseError(e).message;
		} finally {
			previewing = false;
		}
	}

	// ── DR4 + DR2: apply flow ──
	function startApply(policyId: number | null) {
		applyPolicyId = policyId;
		applyError = '';
		applyApplied = 0;
		applyTotal = null;
		applyStatus = 'queued';
		void enqueueApply();
	}

	async function enqueueApply() {
		try {
			const { jobId } = await adminApplyEAPolicy(applyPolicyId ?? undefined);
			applyJobId = jobId;
			pollApply();
		} catch (e) {
			applyStatus = 'error';
			applyError = parseError(e).message;
		}
	}

	function pollApply() {
		if (applyTimer) clearTimeout(applyTimer);
		applyTimer = setTimeout(async () => {
			if (applyJobId === null) return;
			try {
				const s = await adminApplyStatusEAPolicy(applyJobId);
				applyApplied = s.applied;
				applyTotal = s.total;
				if (s.status === 'done' || s.status === 'completed') {
					applyStatus = 'done';
					await load();
				} else if (s.status === 'error' || s.status === 'failed') {
					applyStatus = 'error';
					applyError = s.error || 'Apply job failed';
				} else {
					applyStatus = 'running';
					pollApply();
				}
			} catch (e) {
				applyStatus = 'error';
				applyError = parseError(e).message;
			}
		}, 1500);
	}

	function dismissApply() {
		if (applyTimer) clearTimeout(applyTimer);
		applyTimer = null;
		applyJobId = null;
		applyStatus = 'idle';
		applyError = '';
	}

	// ── Condition toggles ──
	function toggleMailboxType(ty: MailboxType, on: boolean) {
		if (on) {
			if (!condMailboxType.includes(ty)) condMailboxType = [...condMailboxType, ty];
		} else {
			condMailboxType = condMailboxType.filter((x) => x !== ty);
		}
		scheduleMatchCount();
	}

	function toggleDept(name: string, on: boolean) {
		if (on) {
			if (!condDepartment.includes(name)) condDepartment = [...condDepartment, name];
		} else {
			condDepartment = condDepartment.filter((x) => x !== name);
		}
		scheduleMatchCount();
	}

	function toggleDomain(name: string, on: boolean) {
		if (on) {
			if (!condDomainNames.includes(name)) condDomainNames = [...condDomainNames, name];
		} else {
			condDomainNames = condDomainNames.filter((x) => x !== name);
		}
		scheduleMatchCount();
	}

	function onOverwriteChange(on: boolean) {
		fOverwrite = on;
		if (!on) {
			overwriteConfirmed = false; // toggling OFF needs no confirm
		} else {
			overwriteConfirmed = false; // require explicit confirm step
			void runMatchCount();
		}
	}

	const COLUMNS: TableColumn[] = [
		{ key: 'priority', label: '#', sortable: false, width: '48px' },
		{ key: 'name', label: t('admin.eap.name'), sortable: false },
		{ key: 'template', label: t('admin.eap.primary_template'), sortable: false },
		{ key: 'conditions', label: 'Conditions', sortable: false },
		{ key: 'enabled', label: t('admin.eap.enabled'), sortable: false },
		{ key: 'actions', label: '', sortable: false },
	];

	function condSummary(p: EmailAddressPolicy): string {
		const parts: string[] = [];
		if (p.condDepartment?.length) parts.push(`dept: ${p.condDepartment.join(', ')}`);
		if (p.condDomainIds?.length) parts.push(`domain: ${p.condDomainIds.map(domainNameById).join(', ')}`);
		if (p.condMailboxType?.length) parts.push(`type: ${p.condMailboxType.join(', ')}`);
		if (p.condAdOu?.length) parts.push(`OU: ${p.condAdOu.join(', ')}`);
		return parts.length ? parts.join(' · ') : 'all mailboxes';
	}
</script>

<div class="sj-page">
	<header class="sj-page-head">
		<div class="sj-page-head-left">
			<h1>{t('admin.eap.title')}</h1>
			<p>{t('admin.eap.description')}</p>
		</div>
		<div class="sj-page-head-right">
			<Button variant="secondary" size="sm" onclick={() => startApply(null)} disabled={policies.length === 0 || !hasPermission($adminPermissions, 'identity.write')}>
				{t('admin.eap.apply_now')}
			</Button>
			<Button variant="primary" size="sm" onclick={openNew} disabled={!hasPermission($adminPermissions, 'identity.write')}>
				{#snippet icon()}<Icon name="Plus" size={16} />{/snippet}
				{t('admin.eap.new_policy')}
			</Button>
		</div>
	</header>

	{#if error}
		<div class="alert alert-danger" role="alert">{error}</div>
	{/if}

	{#if applyStatus !== 'idle'}
		<div class="apply-panel" role="status" aria-live="polite">
			{#if applyStatus === 'error'}
				<div class="apply-panel__row">
					<Icon name="AlertTriangle" size={16} class="apply-panel__danger" />
					<span class="apply-panel__msg">{applyError || 'Apply failed'}</span>
					<Button variant="ghost" size="sm" onclick={() => startApply(applyPolicyId)} disabled={!hasPermission($adminPermissions, 'identity.write')}>
						{#snippet icon()}<Icon name="RefreshCw" size={14} />{/snippet}
						Retry
					</Button>
					<Button variant="ghost" size="sm" onclick={dismissApply}>Dismiss</Button>
				</div>
			{:else if applyStatus === 'done'}
				<div class="apply-panel__row">
					<Icon name="MailCheck" size={16} class="apply-panel__ok" />
					<span class="apply-panel__msg">{t('admin.eap.applied_to_n', { n: String(applyApplied) })}</span>
					<Button variant="ghost" size="sm" onclick={dismissApply}>Dismiss</Button>
				</div>
			{:else}
				<div class="apply-panel__col">
					<span class="apply-panel__msg">{t('admin.eap.apply_in_progress')}</span>
					<Progress value={applyApplied} max={Math.max(applyTotal ?? 0, applyApplied, 1)} label={t('admin.eap.apply_in_progress')} />
					<span class="apply-panel__count">{applyApplied}{applyTotal != null ? ` / ${applyTotal}` : ''}</span>
				</div>
			{/if}
		</div>
	{/if}

	<Card flush={true}>
		{#if loading}
			<div class="loading"><Spinner /> <span>{t('common.loading')}</span></div>
		{:else if policies.length === 0}
			<div class="empty-wrap">
				<EmptyState title={t('admin.eap.no_policies')} watermark={true}>
					{#snippet action()}
						<div class="empty-body">
							<p class="empty-desc">{t('admin.eap.description')}</p>
							<Button variant="primary" onclick={openNew} disabled={!hasPermission($adminPermissions, 'identity.write')}>
								{#snippet icon()}<Icon name="Plus" size={16} />{/snippet}
								{t('admin.eap.new_policy')}
							</Button>
						</div>
					{/snippet}
				</EmptyState>
			</div>
		{:else}
			{@const rows = policies as unknown as Record<string, unknown>[]}
			<Table columns={COLUMNS} rows={rows}>
				{#snippet cell(row, col)}
					{@const p = row as unknown as EmailAddressPolicy}
					{@const i = policies.findIndex((x) => x.id === p.id)}
					{#if col.key === 'priority'}
						<span class="prio" aria-label={`priority ${i + 1} of ${policies.length}`}>{p.priority}</span>
					{:else if col.key === 'name'}
						<span class="sj-name">{p.name}</span>
					{:else if col.key === 'template'}
						<code class="tmpl">{p.primaryTemplate}</code>
					{:else if col.key === 'conditions'}
						<span class="cond-summary">{condSummary(p)}</span>
					{:else if col.key === 'enabled'}
						<Badge variant={p.enabled ? 'success' : 'neutral'} label={p.enabled ? t('admin.eap.enabled') : 'Off'} />
					{:else if col.key === 'actions'}
						<div class="sj-actions">
							<button
								type="button" class="reorder-btn"
								aria-label={`Move ${p.name} up`}
								disabled={i === 0 || reordering || !hasPermission($adminPermissions, 'identity.write')}
								onclick={() => move(i, -1)}
							><Icon name="ChevronUp" size={16} /></button>
							<button
								type="button" class="reorder-btn"
								aria-label={`Move ${p.name} down`}
								disabled={i >= policies.length - 1 || reordering || !hasPermission($adminPermissions, 'identity.write')}
								onclick={() => move(i, 1)}
							><Icon name="ChevronDown" size={16} /></button>
							<Button variant="ghost" size="sm" onclick={() => openEdit(p)} disabled={!hasPermission($adminPermissions, 'identity.write')}>{t('common.edit')}</Button>
							<Button variant="ghost" size="sm" onclick={() => askDelete(p)} disabled={!hasPermission($adminPermissions, 'identity.write')}>{t('common.delete')}</Button>
						</div>
					{/if}
				{/snippet}
			</Table>
		{/if}
	</Card>
</div>

{#if showEditor}
<Dialog open={showEditor} wide={true} title={editing ? t('admin.eap.edit') : t('admin.eap.new_policy')} onClose={closeEditor}>
	{#snippet children()}
		<div class="editor">
			{#if saveError}
				<div class="alert alert-danger" role="alert">{saveError}</div>
			{/if}

			<!-- Section: Identity -->
			<section class="grp">
				<h3 class="grp__title">{t('admin.eap.name')}</h3>
				<div class="grp__grid grp__grid--2">
					<Input label={t('admin.eap.name')} value={fName}
						oninput={(e) => fName = (e.target as HTMLInputElement).value}
						placeholder="Engineering staff" maxlength={120} />
					<Input label={t('admin.eap.priority')} type="number" value={String(fPriority)}
						hint="Lower numbers match first"
						oninput={(e) => fPriority = parseInt((e.target as HTMLInputElement).value) || 0} />
				</div>
			</section>

			<!-- Section: Who it applies to -->
			<section class="grp">
				<div class="grp__head">
					<h3 class="grp__title">Who it applies to</h3>
					<span class="match-badge">
						{#if matchCounting}
							<Spinner size={16} />
						{:else if matchCount != null}
							<Badge variant="info" label={t('admin.eap.matches_n_recipients', { n: String(matchCount) })} />
						{/if}
					</span>
				</div>

				{#if departments.length > 0}
					<fieldset class="picker">
						<legend>{t('admin.eap.condition_department')}</legend>
						<div class="chips">
							{#each departments as d (d)}
								<Checkbox label={d} checked={condDepartment.includes(d)}
									onchange={(e) => toggleDept(d, (e.target as HTMLInputElement).checked)} />
							{/each}
						</div>
					</fieldset>
				{:else}
					<Input label={t('admin.eap.condition_department')}
						hint="Comma-separated department names"
						value={condDepartment.join(', ')}
						oninput={(e) => { condDepartment = (e.target as HTMLInputElement).value.split(',').map((s) => s.trim()).filter(Boolean); scheduleMatchCount(); }} />
				{/if}

				{#if domains.length > 0}
					<fieldset class="picker">
						<legend>{t('admin.eap.condition_domain')}</legend>
						<div class="chips">
							{#each domains as d (d.id)}
								<Checkbox label={d.name} checked={condDomainNames.includes(d.name)}
									onchange={(e) => toggleDomain(d.name, (e.target as HTMLInputElement).checked)} />
							{/each}
						</div>
					</fieldset>
				{:else}
					<fieldset class="picker picker--unavailable">
						<legend>{t('admin.eap.condition_domain')}</legend>
						<p class="picker__notice">
							{domainsError ? t('admin.eap.domain_condition_error') : t('admin.eap.no_domains_configured')}
						</p>
						{#if domainsError}
							<Button variant="ghost" size="sm" onclick={loadDomains}>{t('common.retry')}</Button>
						{/if}
					</fieldset>
				{/if}

				<fieldset class="picker">
					<legend>{t('admin.eap.condition_mailbox_type')}</legend>
					<div class="chips">
						{#each MAILBOX_TYPES as ty (ty)}
							<Checkbox label={ty} checked={condMailboxType.includes(ty)}
								onchange={(e) => toggleMailboxType(ty, (e.target as HTMLInputElement).checked)} />
						{/each}
					</div>
				</fieldset>

				<Input label={t('admin.eap.condition_ad_ou')}
					hint="Comma-separated organizational units (optional)"
					value={condAdOu}
					oninput={(e) => { condAdOu = (e.target as HTMLInputElement).value; scheduleMatchCount(); }} />
			</section>

			<!-- Section: Address format -->
			<section class="grp">
				<h3 class="grp__title">{t('admin.eap.primary_template')}</h3>
				<Input label={t('admin.eap.primary_template')} mono={true} value={fPrimaryTemplate}
					hint={'Variables: {given_name} {surname} {first_initial} {user_name} {department} {domain}'}
					oninput={(e) => { fPrimaryTemplate = (e.target as HTMLInputElement).value; if (editing && sampleUser) schedulePreview(); }}
					placeholder={'{first_initial}{surname}@{domain}'} />
				<Textarea label={t('admin.eap.additional_templates')} rows={3} value={fAdditionalTemplates}
					hint="One template per line — generates additional aliases"
					oninput={(e) => fAdditionalTemplates = (e.target as HTMLTextAreaElement).value} />
				<!-- The DB CHECK constraint (eap_dupres_check) allows ONLY 'numeric_suffix'
				     and the apply reducer implements only that strategy — 'skip'/'fail'
				     were never backed, so sending them 500s the create/update (23514).
				     Offer the one real strategy; add options here only alongside backend support. -->
				<Select label={t('admin.eap.duplicate_resolution')} value={fDuplicateResolution}
					options={[
						{ value: 'numeric_suffix', label: 'Append numeric suffix (jdoe2@…)' },
					]}
					onchange={(e) => fDuplicateResolution = (e.target as HTMLSelectElement).value} />

				<!-- DR3: live preview -->
				<div class="preview">
					<div class="preview__head">
						<Icon name="Sparkles" size={14} />
						<span>{t('admin.eap.preview')}</span>
					</div>
					{#if !editing}
						<p class="preview__hint">Save the policy to preview generated addresses.</p>
					{:else}
						<div class="preview__search">
							<Input value={sampleQuery} placeholder="Search a sample user…"
								oninput={(e) => onSampleQuery((e.target as HTMLInputElement).value)} />
							{#if sampleSearching}<Spinner size={16} />{/if}
						</div>
						{#if sampleResults.length > 0}
							<ul class="sample-list">
								{#each sampleResults as u (u.id)}
									<li>
										<button type="button" class="sample-opt" onclick={() => pickSample(u)}>
											<span class="sample-opt__name">{u.displayName || u.email}</span>
											<span class="sample-opt__email">{u.email}</span>
										</button>
									</li>
								{/each}
							</ul>
						{/if}
						{#if previewing}
							<p class="preview__hint">Generating…</p>
						{:else if previewError}
							<p class="preview__err">{previewError}</p>
						{:else if preview}
							<div class="preview__out">
								<div class="preview__row">
									<span class="preview__label">Primary</span>
									<code>{preview.primary}</code>
									{#if preview.collided}<Badge variant="warning" label={`collision → ${preview.suffix}`} />{/if}
								</div>
								{#each preview.additionals as a (a)}
									<div class="preview__row">
										<span class="preview__label">Alias</span>
										<code>{a}</code>
									</div>
								{/each}
							</div>
						{/if}
					{/if}
				</div>
			</section>

			<!-- Section: Behavior -->
			<section class="grp">
				<h3 class="grp__title">{t('admin.eap.enabled')}</h3>
				<div class="behavior">
					<Switch label={t('admin.eap.enabled')} checked={fEnabled}
						onchange={(e) => fEnabled = (e.target as HTMLInputElement).checked} />
					<Switch label={t('admin.eap.overwrite_directory')} checked={fOverwrite}
						onchange={(e) => onOverwriteChange((e.target as HTMLInputElement).checked)} />
				</div>

				<!-- DR4: override confirm -->
				{#if fOverwrite}
					<div class="danger-panel" role="alert">
						<div class="danger-panel__head">
							<Icon name="AlertTriangle" size={16} class="danger-panel__icon" />
							<strong>{t('admin.eap.overwrite_directory')}</strong>
						</div>
						<p>{t('admin.eap.override_warning')} The previous address is kept as an alias.</p>
						<p class="danger-panel__count">
							{#if matchCounting}
								Counting affected users…
							{:else if matchCount != null}
								Will affect <strong>{matchCount}</strong> synced user{matchCount === 1 ? '' : 's'}.
							{/if}
						</p>
						<Checkbox label="I understand this overrides directory-managed addresses for matching synced users"
							checked={overwriteConfirmed}
							onchange={(e) => overwriteConfirmed = (e.target as HTMLInputElement).checked} />
					</div>
				{/if}
			</section>
		</div>
	{/snippet}
	{#snippet footer()}
		{#if editing}
			<Button variant="secondary" onclick={() => startApply(editing!.id)} disabled={!hasPermission($adminPermissions, 'identity.write')}>{t('admin.eap.apply_now')}</Button>
		{/if}
		<Button variant="primary" onclick={save} disabled={saving || !hasPermission($adminPermissions, 'identity.write')}>{saving ? '…' : t('common.save')}</Button>
		<Button variant="ghost" onclick={closeEditor}>{t('common.cancel')}</Button>
	{/snippet}
</Dialog>
{/if}

{#if showDelete}
<Dialog open={showDelete} title={t('admin.eap.delete_confirm')} onClose={() => { showDelete = false; }}>
	{#snippet children()}
		<p>{t('admin.eap.delete_confirm')}</p>
		{#if deleteTarget}<p class="del-name"><strong>{deleteTarget.name}</strong></p>{/if}
	{/snippet}
	{#snippet footer()}
		<Button variant="danger" onclick={confirmDelete} disabled={!hasPermission($adminPermissions, 'identity.write')}>{t('common.delete')}</Button>
		<Button variant="ghost" onclick={() => { showDelete = false; }}>{t('common.cancel')}</Button>
	{/snippet}
</Dialog>
{/if}

<style>
	.sj-page { max-width: 1080px; }
	.sj-page-head {
		display: flex; align-items: flex-start; gap: 12px;
		margin-bottom: 16px; flex-wrap: wrap;
	}
	.sj-page-head-left { flex: 1 1 320px; min-width: 0; }
	.sj-page-head-left h1 {
		margin: 0; font-size: clamp(20px, 16px + 1.2vw, 24px);
		font-weight: 600; letter-spacing: var(--tracking-display); color: var(--text-primary);
	}
	.sj-page-head-left p { margin: 4px 0 0; font-size: var(--text-sm); color: var(--text-secondary); max-width: 60ch; }
	.sj-page-head-right { display: flex; gap: 8px; align-items: center; }

	.loading { display: flex; align-items: center; gap: 8px; padding: 32px; color: var(--text-secondary); font-size: var(--text-sm); }

	.empty-wrap { padding: 8px 0 24px; }
	.empty-body { display: flex; flex-direction: column; align-items: center; gap: 14px; }
	.empty-desc { margin: 0; max-width: 44ch; color: var(--text-secondary); font-size: var(--text-sm); line-height: var(--leading-normal); }

	.sj-name { font-weight: 500; }
	.prio { font-family: var(--font-mono); font-size: var(--text-xs); color: var(--text-secondary); }
	.tmpl { font-family: var(--font-mono); font-size: var(--text-xs); color: var(--text-secondary); }
	.cond-summary { font-size: var(--text-xs); color: var(--text-secondary); }
	.sj-actions { display: flex; gap: 2px; align-items: center; }

	.reorder-btn {
		display: inline-flex; align-items: center; justify-content: center;
		min-width: 44px; min-height: 44px; padding: 0;
		border: none; background: transparent; cursor: pointer;
		color: var(--text-tertiary); border-radius: var(--radius-sm);
	}
	.reorder-btn:hover:not(:disabled) { background: var(--surface-hover); color: var(--text-primary); }
	.reorder-btn:disabled { opacity: 0.35; cursor: not-allowed; }
	.reorder-btn:focus-visible { outline: none; box-shadow: var(--focus-ring); }

	.alert { padding: 8px 12px; border-radius: var(--radius-sm); margin-bottom: 12px; font-size: var(--text-sm); }
	.alert-danger { background: var(--danger-bg); color: var(--danger-fg); border: 1px solid var(--danger-solid); }

	/* Apply panel */
	.apply-panel {
		margin-bottom: 16px; padding: 12px 14px;
		background: var(--surface-sunken); border: 1px solid var(--border-subtle); border-radius: var(--radius-md);
	}
	.apply-panel__row { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }
	.apply-panel__col { display: flex; flex-direction: column; gap: 8px; }
	.apply-panel__msg { font-size: var(--text-sm); color: var(--text-primary); flex: 1 1 auto; }
	.apply-panel__count { font-family: var(--font-mono); font-size: var(--text-xs); color: var(--text-secondary); }
	:global(.apply-panel__danger) { color: var(--danger-fg); }
	:global(.apply-panel__ok) { color: var(--success-fg); }

	/* Editor */
	.editor { display: flex; flex-direction: column; gap: 18px; }
	.grp {
		display: flex; flex-direction: column; gap: 12px;
		padding: 14px; border: 1px solid var(--border-subtle); border-radius: var(--radius-md);
		background: var(--surface-card);
	}
	.grp__head { display: flex; align-items: center; justify-content: space-between; gap: 8px; }
	.grp__title {
		margin: 0; font-size: var(--text-xs); font-weight: var(--weight-semibold);
		text-transform: uppercase; letter-spacing: var(--tracking-caps); color: var(--text-tertiary);
	}
	.grp__grid { display: grid; gap: 12px; }
	.grp__grid--2 { grid-template-columns: 2fr 1fr; }
	.match-badge { display: inline-flex; align-items: center; min-height: 20px; }

	.picker { border: none; margin: 0; padding: 0; }
	.picker legend {
		padding: 0 0 6px; font-size: var(--text-sm); font-weight: var(--weight-medium); color: var(--text-primary);
	}
	.chips { display: flex; flex-wrap: wrap; gap: 8px 16px; }
	.picker--unavailable { display: flex; flex-direction: column; gap: 6px; }
	.picker__notice { margin: 0; font-size: var(--text-sm); color: var(--text-secondary); }

	.behavior { display: flex; flex-direction: column; gap: 12px; }

	/* Preview */
	.preview {
		margin-top: 4px; padding: 12px; border-radius: var(--radius-md);
		background: var(--surface-sunken); border: 1px solid var(--border-subtle);
		display: flex; flex-direction: column; gap: 8px;
	}
	.preview__head { display: flex; align-items: center; gap: 6px; font-size: var(--text-sm); font-weight: var(--weight-medium); color: var(--text-primary); }
	.preview__hint { margin: 0; font-size: var(--text-sm); color: var(--text-secondary); }
	.preview__err { margin: 0; font-size: var(--text-sm); color: var(--danger-fg); }
	.preview__search { display: flex; align-items: center; gap: 8px; }
	.preview__search :global(.sj-field) { flex: 1 1 auto; }
	.sample-list { list-style: none; margin: 0; padding: 0; display: flex; flex-direction: column; gap: 2px; max-height: 180px; overflow-y: auto; }
	.sample-opt {
		display: flex; flex-direction: column; align-items: flex-start; gap: 1px;
		width: 100%; min-height: 44px; padding: 6px 8px; text-align: left;
		border: none; background: transparent; cursor: pointer; border-radius: var(--radius-sm);
	}
	.sample-opt:hover { background: var(--surface-hover); }
	.sample-opt:focus-visible { outline: none; box-shadow: var(--focus-ring); }
	.sample-opt__name { font-size: var(--text-sm); color: var(--text-primary); }
	.sample-opt__email { font-size: var(--text-xs); color: var(--text-secondary); }
	.preview__out { display: flex; flex-direction: column; gap: 4px; }
	.preview__row { display: flex; align-items: center; gap: 8px; }
	.preview__label { font-size: var(--text-2xs); text-transform: uppercase; letter-spacing: var(--tracking-caps); color: var(--text-tertiary); min-width: 48px; }
	.preview__row code { font-family: var(--font-mono); font-size: var(--text-xs); color: var(--text-primary); }

	/* DR4 danger panel */
	.danger-panel {
		padding: 12px 14px; border-radius: var(--radius-md);
		background: var(--danger-bg); border: 1px solid var(--danger-solid);
		display: flex; flex-direction: column; gap: 8px;
	}
	.danger-panel__head { display: flex; align-items: center; gap: 6px; color: var(--danger-fg); }
	:global(.danger-panel__icon) { color: var(--danger-fg); }
	.danger-panel p { margin: 0; font-size: var(--text-sm); color: var(--danger-fg); line-height: var(--leading-normal); }
	.danger-panel__count strong { font-variant-numeric: tabular-nums; }

	.del-name { margin: 8px 0 0; }

	/* DR5: full-height sheet under 640px */
	@media (max-width: 640px) {
		:global(.sj-dialog--wide) { max-width: 100%; }
		:global(.sj-dialog-backdrop) { padding: 0; align-items: stretch; }
		:global(.sj-dialog) {
			max-width: 100%; width: 100%; min-height: 100%;
			border-radius: 0; display: flex; flex-direction: column;
		}
		.grp__grid--2 { grid-template-columns: 1fr; }
	}
</style>
