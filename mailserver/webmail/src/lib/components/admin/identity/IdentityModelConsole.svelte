<svelte:options runes={true} />

<script lang="ts">
	import { onMount } from 'svelte';
	import {
		adminIdentitySources,
		adminIdentityPeople,
		adminIdentityConflicts,
		adminIdentityTransitions,
		adminIdentityEvents,
		adminIdentitySourceDetail,
		adminIdentitySourcePlan,
		adminIdentitySourceApply,
		adminIdentitySourceDryRun,
		adminIdentitySourceActivate,
		adminIdentitySourcePause,
		adminIdentitySourceResume,
		adminIdentitySourceRetire,
		adminIdentitySourceSecret,
		adminIdentityPersonDetail,
		adminIdentityConflictDetail,
		adminIdentityConflictDecide,
		adminIdentityUpgradeStatus,
		adminIdentityTransitionPreview,
		adminIdentityTransitionDetail,
		adminIdentityTransitionChallenge,
		adminIdentityTransitionChallengeComplete,
		adminIdentityTransitionRequest,
		adminIdentityTransitionApprove,
		adminIdentityTransitionDeny,
		adminIdentityTransitionExecute,
		adminIdentityTransitionCancel,
		adminIdentityTransitionRetry,
		adminIdentityTransitionRollbackPreview,
		adminIdentityTransitionRollback,
		adminIdentityTransitionReport,
		type IdentityV2Source,
		type IdentityV2Person,
		type IdentityV2Conflict,
		type IdentityV2Transition,
		type IdentityV2Event,
		type IdentitySourceDocument,
		type IdentitySourceDetail,
		type IdentitySourcePlan,
		type IdentityPersonDetail,
		type IdentityConflictDetail,
		type IdentityUpgradeStatus,
		type IdentityTransitionPreview,
		type IdentityTransitionDetail,
		type IdentityTransitionChallenge,
	} from '$lib/admin/client';
	import { parseError } from '$lib/errors';
	import { locale } from '$lib/i18n';
	import { adminPermissions, hasPermission } from '$lib/stores/auth';
	import {
		Badge, Button, Card, Dialog, EmptyState, Input, Select, Spinner, Textarea, showToast,
	} from '$lib/components/ui';

	type Section = 'overview' | 'sources' | 'people' | 'conflicts' | 'transitions' | 'audit';
	type OverviewSection = 'sources' | 'people' | 'conflicts' | 'transitions' | 'events';
	type TransitionAction = 'request' | 'approve' | 'deny' | 'execute' | 'rollback';
	type OverviewLoadState = { loading: boolean; loaded: boolean; error: string };

	const IDENTITY_COPY = {
		en: {
			overview: 'Overview', sources: 'Sources', people: 'People', conflicts: 'Conflicts',
			transitions: 'Transitions', audit: 'Audit', continuity: 'Identity continuity',
			subtitle: 'Inspect normalized shadow evidence and run preview-bound identity operations.',
			productionOff: 'Production admission off', reviewFeature: 'Review feature state',
			featureUnavailable: 'Feature state unavailable', sections: 'Identity sections',
			status: 'Identity feature and read-path status', identityModel: 'Identity model',
			normalizedReads: 'Normalized reads', sourceModes: 'Source modes',
			reviewQueue: 'Review queue', sourceHealth: 'Source health', shadowGate: 'Shadow gate',
			peopleGlance: 'People at a glance', conflictsProof: 'Conflicts requiring proof',
			recentAudit: 'Recent audit', directoryLocal: 'Directory → local transition',
			auditInventory: 'Audit inventory',
			auditDescription: 'Who decided what, on which redacted evidence, and under which correlation or transition ID.',
			auditFilters: 'Identity audit filters', personId: 'Person ID', sourceKey: 'Source key',
			transitionId: 'Transition ID', actorId: 'Actor ID', outcome: 'Outcome',
			fromDate: 'From date', toDate: 'To date', serverFilter: 'Server filter',
			refreshInventory: 'Refresh inventory', exportCsv: 'Export redacted CSV',
			noAuditMatches: 'No identity events match this filter',
		},
		zh: {
			overview: '概览', sources: '身份源', people: '人员', conflicts: '冲突',
			transitions: '转换', audit: '审计', continuity: '身份连续性',
			subtitle: '检查标准化影子证据，并执行与精确预览绑定的身份操作。',
			productionOff: '生产准入已关闭', reviewFeature: '检查功能状态',
			featureUnavailable: '功能状态不可用', sections: '身份功能区',
			status: '身份功能与读取路径状态', identityModel: '身份模型',
			normalizedReads: '标准化读取', sourceModes: '身份源模式',
			reviewQueue: '待处理队列', sourceHealth: '身份源健康度', shadowGate: '影子验证门槛',
			peopleGlance: '人员概览', conflictsProof: '需要证据的冲突',
			recentAudit: '最近审计', directoryLocal: '目录账号 → 本地账号转换',
			auditInventory: '审计清单',
			auditDescription: '按脱敏证据、相关 ID 或转换 ID 追溯由谁、基于什么原因作出了何种决定。',
			auditFilters: '身份审计筛选条件', personId: '人员 ID', sourceKey: '身份源键',
			transitionId: '转换 ID', actorId: '操作人 ID', outcome: '结果',
			fromDate: '开始日期', toDate: '结束日期', serverFilter: '服务端筛选',
			refreshInventory: '刷新清单', exportCsv: '导出脱敏 CSV',
			noAuditMatches: '没有符合当前筛选条件的身份事件',
		},
	} as const;

	let {
		initialSection = 'overview',
		selectedId = '',
		sourceSetup = false,
	}: {
		initialSection?: Section;
		selectedId?: string;
		sourceSetup?: boolean;
	} = $props();

	const copy = $derived(IDENTITY_COPY[$locale === 'zh' ? 'zh' : 'en']);
	const sections = $derived<Array<{ id: Section; label: string; href: string }>>([
		{ id: 'overview', label: copy.overview, href: '/admin/identity' },
		{ id: 'sources', label: copy.sources, href: '/admin/identity/sources' },
		{ id: 'people', label: copy.people, href: '/admin/identity/people' },
		{ id: 'conflicts', label: copy.conflicts, href: '/admin/identity/conflicts' },
		{ id: 'transitions', label: copy.transitions, href: '/admin/identity/transitions' },
		{ id: 'audit', label: copy.audit, href: '/admin/identity/audit' },
	]);

	let loading = $state(true);
	let sectionError = $state('');
	let statusError = $state('');
	let status = $state<IdentityUpgradeStatus | null>(null);
	let sources = $state<IdentityV2Source[]>([]);
	let people = $state<IdentityV2Person[]>([]);
	let conflicts = $state<IdentityV2Conflict[]>([]);
	let transitions = $state<IdentityV2Transition[]>([]);
	let events = $state<IdentityV2Event[]>([]);
	let sourceDetail = $state<IdentitySourceDetail | null>(null);
	let personDetail = $state<IdentityPersonDetail | null>(null);
	let conflictDetail = $state<IdentityConflictDetail | null>(null);
	let transitionDetail = $state<IdentityTransitionDetail | null>(null);
	let filter = $state('');
	let busy = $state(false);
	let reason = $state('');
	// Per-secret values keyed by secret name — a single shared field let a value
	// typed for one secret be submitted to a different secret's row (the
	// cross-row mistake-proofing gap). Each row's input owns its own entry.
	let secretValues = $state<Record<string, string>>({});
	let sourcePlan = $state<IdentitySourcePlan | null>(null);
	let sourceDocumentText = $state(JSON.stringify({
		apiVersion: 'setjoin.io/v1',
		kind: 'IdentitySource',
		metadata: { sourceKey: 'corp-ldap', displayName: 'Corporate LDAP' },
		spec: {
			type: 'ldap',
			capabilities: ['provisionLifecycle', 'immutableSubject'],
			endpoint: { host: 'ldap.example.test', port: 636, tls: 'ldaps' },
			subjectAttribute: 'entryUUID',
			baseDN: 'dc=example,dc=test',
			bindDN: 'cn=setjoin,dc=example,dc=test',
			userFilter: '(objectClass=person)',
			groupFilter: '(objectClass=groupOfNames)',
			mapping: { email: 'mail', displayName: 'displayName' },
			deletionPolicy: 'disable',
		},
	}, null, 2));

	let transitionUserId = $state('');
	let transitionReason = $state('');
	let transitionTargetLinkId = $state('');
	let transitionPreview = $state<IdentityTransitionPreview | null>(null);
	let transitionChallenge = $state<IdentityTransitionChallenge | null>(null);
	let transitionAction = $state<TransitionAction>('request');
	let rollbackApprovalId = $state('');
	let auditPerson = $state('');
	let auditSource = $state('');
	let auditTransition = $state('');
	let auditActor = $state('');
	let auditOutcome = $state('');
	let auditFrom = $state('');
	let auditTo = $state('');
	let overviewState = $state<Record<OverviewSection, OverviewLoadState>>({
		sources: { loading: false, loaded: false, error: '' },
		people: { loading: false, loaded: false, error: '' },
		conflicts: { loading: false, loaded: false, error: '' },
		transitions: { loading: false, loaded: false, error: '' },
		events: { loading: false, loaded: false, error: '' },
	});

	const canWrite = $derived(hasPermission($adminPermissions, 'identity.write'));
	const flagsKnownOff = $derived(
		status !== null &&
		!status.masterEnabled &&
		!status.normalizedReadsEnabled &&
		!status.transitionsEnabled
	);
	const unresolvedReviewCount = $derived(
		conflicts.length + transitions.filter((item) =>
			['awaiting_approval', 'failed_precommit', 'failed_recoverable', 'effects_pending'].
				includes(item.state)
		).length
	);
	const filteredEvents = $derived.by(() => events.filter((event) => {
		const includes = (actual: string | null | undefined, wanted: string) =>
			!wanted.trim() || (actual ?? '').toLocaleLowerCase().includes(wanted.trim().toLocaleLowerCase());
		const eventDate = event.occurredAt.slice(0, 10);
		return includes(event.userId, auditPerson) &&
			includes(event.sourceKey, auditSource) &&
			includes(event.transitionId, auditTransition) &&
			includes(eventActor(event), auditActor) &&
			includes(event.action, auditOutcome) &&
			(!auditFrom || eventDate >= auditFrom) &&
			(!auditTo || eventDate <= auditTo);
	}));

	onMount(() => {
		requestAnimationFrame(() => revealSection(initialSection));
		void load();
	});

	function sectionTabId(section: Section): string {
		return `identity-section-${section}`;
	}

	function revealSection(section: Section, focus = false) {
		const element = document.getElementById(sectionTabId(section));
		element?.scrollIntoView?.({ block: 'nearest', inline: 'nearest' });
		if (focus) element?.focus();
	}

	function onSectionKeydown(event: KeyboardEvent, index: number) {
		let next = index;
		if (event.key === 'ArrowRight' || event.key === 'ArrowDown') {
			next = (index + 1) % sections.length;
		} else if (event.key === 'ArrowLeft' || event.key === 'ArrowUp') {
			next = (index - 1 + sections.length) % sections.length;
		} else if (event.key === 'Home') {
			next = 0;
		} else if (event.key === 'End') {
			next = sections.length - 1;
		} else {
			return;
		}
		event.preventDefault();
		revealSection(sections[next].id, true);
	}

	function closeStepUp() {
		if (!busy) transitionChallenge = null;
	}

	async function loadStatus() {
		try {
			status = await adminIdentityUpgradeStatus();
			statusError = '';
		} catch (error) {
			statusError = parseError(error).message;
		}
	}

	function setOverviewState(section: OverviewSection, patch: Partial<OverviewLoadState>) {
		overviewState = {
			...overviewState,
			[section]: { ...overviewState[section], ...patch },
		};
	}

	async function loadOverviewSection(section: OverviewSection) {
		setOverviewState(section, { loading: true, error: '' });
		try {
			switch (section) {
				case 'sources':
					sources = await adminIdentitySources();
					break;
				case 'people':
					people = await adminIdentityPeople();
					break;
				case 'conflicts':
					conflicts = await adminIdentityConflicts();
					break;
				case 'transitions':
					transitions = await adminIdentityTransitions();
					break;
				case 'events':
					events = await adminIdentityEvents();
					break;
			}
			setOverviewState(section, { loaded: true, error: '' });
		} catch (error) {
			setOverviewState(section, { error: parseError(error).message });
		} finally {
			setOverviewState(section, { loading: false });
		}
	}

	async function load() {
		loading = true;
		sectionError = '';
		await loadStatus();
		try {
			if (initialSection === 'overview') {
				loading = false;
				await Promise.all([
					loadOverviewSection('sources'),
					loadOverviewSection('people'),
					loadOverviewSection('conflicts'),
					loadOverviewSection('transitions'),
					loadOverviewSection('events'),
				]);
				return;
			} else if (initialSection === 'sources') {
				sources = await adminIdentitySources(filter);
				if (selectedId) sourceDetail = await adminIdentitySourceDetail(selectedId);
			} else if (initialSection === 'people') {
				people = await adminIdentityPeople(filter);
				if (selectedId) personDetail = await adminIdentityPersonDetail(selectedId);
			} else if (initialSection === 'conflicts') {
				conflicts = await adminIdentityConflicts(filter);
				if (selectedId) conflictDetail = await adminIdentityConflictDetail(selectedId);
			} else if (initialSection === 'transitions') {
				transitions = await adminIdentityTransitions(filter);
				if (selectedId) transitionDetail = await adminIdentityTransitionDetail(selectedId);
			} else {
				events = await adminIdentityEvents(filter);
			}
		} catch (error) {
			sectionError = parseError(error).message;
		} finally {
			loading = false;
		}
	}

	function statusVariant(value: string): 'neutral' | 'success' | 'info' | 'warning' | 'danger' {
		if (['active', 'completed', 'rolled_back'].includes(value)) return 'success';
		if (['error', 'failed_precommit', 'failed_recoverable'].includes(value)) return 'danger';
		if (['paused', 'awaiting_approval', 'effects_pending', 'deferred'].includes(value)) return 'warning';
		if (['canary', 'normalized', 'executing', 'authorized'].includes(value)) return 'info';
		return 'neutral';
	}

	function formatWhen(value?: string | null): string {
		if (!value) return 'Not recorded';
		const date = new Date(value);
		return Number.isNaN(date.valueOf()) ? value : date.toLocaleString();
	}

	function eventActor(event: IdentityV2Event): string {
		const metadata = event.metadata ?? {};
		for (const key of ['actor', 'actorId', 'actorUserId', 'actor_user_id']) {
			const value = metadata[key];
			if (typeof value === 'string' || typeof value === 'number') return String(value);
		}
		return '';
	}

	function csvCell(value: unknown): string {
		let text = value == null ? '' : String(value);
		if (/^[=+\-@]/.test(text)) text = `'${text}`;
		return `"${text.replaceAll('"', '""')}"`;
	}

	function exportAudit() {
		const header = ['when', 'outcome', 'person_id', 'source_key', 'transition_id', 'actor_id', 'reason', 'correlation_id'];
		const lines = filteredEvents.map((event) => [
			event.occurredAt,
			event.action,
			event.userId ?? '',
			event.sourceKey ?? '',
			event.transitionId ?? '',
			eventActor(event),
			event.reason,
			event.correlationId,
		].map(csvCell).join(','));
		const blob = new Blob([[[...header.map(csvCell)].join(','), ...lines].join('\n')], {
			type: 'text/csv;charset=utf-8',
		});
		const url = URL.createObjectURL(blob);
		const anchor = document.createElement('a');
		anchor.href = url;
		anchor.download = 'identity-audit-redacted.csv';
		document.body.append(anchor);
		anchor.click();
		anchor.remove();
		URL.revokeObjectURL(url);
		showToast(`Exported ${filteredEvents.length} redacted identity events`);
	}

	function parseSourceDocument(): IdentitySourceDocument {
		const value = JSON.parse(sourceDocumentText) as IdentitySourceDocument;
		if (value.apiVersion !== 'setjoin.io/v1' || value.kind !== 'IdentitySource' ||
			!value.metadata?.sourceKey || !value.metadata?.displayName || !value.spec?.type) {
			throw new Error('Source document must contain apiVersion, kind, metadata, and spec.type.');
		}
		return value;
	}

	async function planSource() {
		busy = true;
		sectionError = '';
		try {
			sourcePlan = await adminIdentitySourcePlan(parseSourceDocument());
		} catch (error) {
			sectionError = parseError(error).message;
		} finally {
			busy = false;
		}
	}

	async function applySource() {
		if (!sourcePlan || !reason.trim()) return;
		busy = true;
		sectionError = '';
		try {
			const result = await adminIdentitySourceApply(
				parseSourceDocument(),
				reason.trim(),
				crypto.randomUUID(),
				sourcePlan.currentGeneration,
			);
			showToast(`Source saved as draft at generation ${result.generation}`);
			sourcePlan = null;
			await load();
		} catch (error) {
			sectionError = parseError(error).message;
		} finally {
			busy = false;
		}
	}

	async function sourceAction(action: 'dry-run' | 'activate' | 'pause' | 'resume' | 'retire') {
		if (!sourceDetail || !reason.trim()) return;
		busy = true;
		sectionError = '';
		try {
			const args = [
				sourceDetail.sourceKey,
				sourceDetail.generation,
				reason.trim(),
				crypto.randomUUID(),
			] as const;
			const result = action === 'dry-run'
				? await adminIdentitySourceDryRun(...args)
				: action === 'activate'
					? await adminIdentitySourceActivate(...args)
					: action === 'pause'
						? await adminIdentitySourcePause(...args)
						: action === 'resume'
							? await adminIdentitySourceResume(...args)
							: await adminIdentitySourceRetire(...args);
			if (action === 'dry-run') {
				showToast(result.valid
					? `Dry run passed with ${result.personWrites ?? 0} person writes`
					: `Dry run blocked: ${(result.blockers ?? []).join(', ')}`);
			} else {
				showToast(`Source ${action} accepted at generation ${result.generation}`);
			}
			sourceDetail = await adminIdentitySourceDetail(sourceDetail.sourceKey);
		} catch (error) {
			sectionError = parseError(error).message;
		} finally {
			busy = false;
		}
	}

	async function saveSecret(name: string, rotate: boolean) {
		const secret = secretValues[name] ?? '';
		if (!sourceDetail || !secret || !reason.trim()) return;
		busy = true;
		sectionError = '';
		try {
			const result = await adminIdentitySourceSecret(
				sourceDetail.sourceKey, name, secret, sourceDetail.generation,
				reason.trim(), crypto.randomUUID(), rotate,
			);
			delete secretValues[name];
			showToast(`Secret ${rotate ? 'rotation' : 'setup'} accepted at generation ${result.generation}`);
			sourceDetail = await adminIdentitySourceDetail(sourceDetail.sourceKey);
		} catch (error) {
			sectionError = parseError(error).message;
		} finally {
			busy = false;
		}
	}

	async function decideConflict(decision: 'link' | 'create' | 'reject' | 'defer') {
		if (!conflictDetail || !reason.trim()) return;
		busy = true;
		sectionError = '';
		try {
			await adminIdentityConflictDecide(
				conflictDetail,
				decision,
				reason.trim(),
				crypto.randomUUID(),
				decision === 'link' ? conflictDetail.candidatePerson?.userId : undefined,
			);
			showToast(`Conflict decision recorded: ${decision}`);
			conflictDetail = await adminIdentityConflictDetail(conflictDetail.id);
		} catch (error) {
			sectionError = parseError(error).message;
		} finally {
			busy = false;
		}
	}

	async function previewTransition(personId?: string) {
		const userId = personId ?? transitionUserId;
		if (!userId.trim() || !transitionReason.trim()) return;
		busy = true;
		sectionError = '';
		try {
			transitionUserId = userId;
			transitionPreview = await adminIdentityTransitionPreview(
				userId.trim(), transitionReason.trim(), crypto.randomUUID(), transitionTargetLinkId.trim() || undefined,
			);
			transitionDetail = null;
			transitionChallenge = null;
		} catch (error) {
			sectionError = parseError(error).message;
		} finally {
			busy = false;
		}
	}

	function challengeTarget(action: TransitionAction): { transitionId: string; previewDigest: string } | null {
		if (action === 'request') return transitionPreview;
		if (!transitionDetail) return null;
		if (action === 'rollback' && transitionDetail.rollback.previewDigest) {
			return {
				transitionId: transitionDetail.transitionId,
				previewDigest: transitionDetail.rollback.previewDigest,
			};
		}
		return transitionDetail;
	}

	async function beginStepUp(action: TransitionAction) {
		const target = challengeTarget(action);
		if (!target) return;
		busy = true;
		sectionError = '';
		try {
			transitionAction = action;
			transitionChallenge = await adminIdentityTransitionChallenge(target, crypto.randomUUID());
		} catch (error) {
			sectionError = parseError(error).message;
		} finally {
			busy = false;
		}
	}

	function openVerification() {
		window.open('/login', '_blank', 'noopener,noreferrer');
	}

	async function completeStepUp() {
		const target = challengeTarget(transitionAction);
		if (!target || !transitionChallenge || !transitionReason.trim()) return;
		busy = true;
		sectionError = '';
		try {
			const elevation = await adminIdentityTransitionChallengeComplete(
				target, transitionChallenge.challengeId, crypto.randomUUID(),
			);
			if (transitionAction === 'request' && transitionPreview) {
				transitionDetail = await adminIdentityTransitionRequest(
					transitionPreview, elevation.elevationId,
					transitionReason.trim(), crypto.randomUUID(),
				);
			} else if (transitionDetail && transitionAction === 'approve') {
				transitionDetail = await adminIdentityTransitionApprove(
					transitionDetail, elevation.elevationId,
					transitionReason.trim(), crypto.randomUUID(),
				);
			} else if (transitionDetail && transitionAction === 'deny') {
				transitionDetail = await adminIdentityTransitionDeny(
					transitionDetail, elevation.elevationId,
					transitionReason.trim(), crypto.randomUUID(),
				);
			} else if (transitionDetail && transitionAction === 'execute') {
				transitionDetail = await adminIdentityTransitionExecute(
					transitionDetail, elevation.elevationId,
					transitionReason.trim(), crypto.randomUUID(),
					transitionDetail.approvalRequestId ?? undefined,
				);
			} else if (transitionDetail && transitionAction === 'rollback') {
				const approval = (
					rollbackApprovalId || transitionDetail.rollback.approvalRequestId || ''
				).trim();
				if (!/^[1-9][0-9]*$/.test(approval)) {
					throw new Error('Rollback requires the independent approval request ID.');
				}
				transitionDetail = await adminIdentityTransitionRollback(
					transitionDetail, elevation.elevationId,
					transitionReason.trim(), crypto.randomUUID(), approval,
				);
			}
			transitionChallenge = null;
			showToast('Transition command accepted. Refresh or return by transition ID.');
			await refreshTransition();
		} catch (error) {
			sectionError = parseError(error).message;
		} finally {
			busy = false;
		}
	}

	async function refreshTransition() {
		const id = transitionDetail?.transitionId ?? transitionPreview?.transitionId;
		if (!id) return;
		try {
			transitionDetail = await adminIdentityTransitionDetail(id);
		} catch (error) {
			sectionError = parseError(error).message;
		}
	}

	async function cancelTransition() {
		if (!transitionDetail || !transitionReason.trim()) return;
		busy = true;
		try {
			transitionDetail = await adminIdentityTransitionCancel(
				transitionDetail, transitionReason.trim(), crypto.randomUUID(),
			);
			showToast('Transition draft cancelled');
		} catch (error) {
			sectionError = parseError(error).message;
		} finally {
			busy = false;
		}
	}

	async function retryEffect(effectId: string) {
		if (!transitionDetail || !transitionReason.trim()) return;
		busy = true;
		try {
			transitionDetail = await adminIdentityTransitionRetry(
				transitionDetail, effectId, transitionReason.trim(), crypto.randomUUID(),
			);
			showToast('Exact effect retry accepted');
		} catch (error) {
			sectionError = parseError(error).message;
		} finally {
			busy = false;
		}
	}

	async function previewRollback() {
		if (!transitionDetail || !transitionReason.trim()) return;
		busy = true;
		try {
			transitionDetail = await adminIdentityTransitionRollbackPreview(
				transitionDetail, transitionReason.trim(), crypto.randomUUID(),
			);
			showToast('Rollback preview created. It requires fresh step-up and independent approval.');
		} catch (error) {
			sectionError = parseError(error).message;
		} finally {
			busy = false;
		}
	}

	async function downloadReport(id: string) {
		try {
			const blob = await adminIdentityTransitionReport(id);
			const url = URL.createObjectURL(blob);
			const anchor = document.createElement('a');
			anchor.href = url;
			anchor.download = `identity-transition-${id}.json`;
			anchor.click();
			URL.revokeObjectURL(url);
		} catch (error) {
			sectionError = parseError(error).message;
		}
	}
</script>

<section class="identity-console" aria-labelledby="identity-console-title">
	{#snippet overviewFeedback(section: OverviewSection, label: string)}
		{#if overviewState[section].loading}
			<div class="stable-loading section-feedback" role="status">
				<Spinner size={16} /> Loading {label}
			</div>
		{/if}
		{#if overviewState[section].error}
			<div class="inline-error section-feedback" role="alert">
				<span>{label} unavailable: {overviewState[section].error}</span>
				<Button variant="secondary" size="sm" onclick={() => loadOverviewSection(section)}>
					Retry {label}
				</Button>
			</div>
		{/if}
	{/snippet}

	<header class="identity-heading">
		<div>
			<h2 id="identity-console-title">{copy.continuity}</h2>
			<p>{copy.subtitle}</p>
		</div>
		{#if flagsKnownOff}
			<Badge variant="neutral" label={copy.productionOff} />
		{:else if status}
			<Badge variant="warning" label={copy.reviewFeature} />
		{:else}
			<Badge variant="warning" label={copy.featureUnavailable} />
		{/if}
	</header>

	<div class="identity-tabs" role="tablist" aria-label={copy.sections}>
		{#each sections as item, index}
			<a
				id={sectionTabId(item.id)}
				href={item.href}
				class:active={item.id === initialSection}
				role="tab"
				aria-selected={item.id === initialSection}
				aria-current={item.id === initialSection ? 'page' : undefined}
				tabindex={item.id === initialSection ? 0 : -1}
				onkeydown={(event) => onSectionKeydown(event, index)}
			>{item.label}</a>
		{/each}
	</div>
	<details class="identity-overflow">
		<summary>{copy.sections}</summary>
		<ul>
			{#each sections as item}<li><a href={item.href}>{item.label}</a></li>{/each}
		</ul>
	</details>

	{#if status}
		<div class="flag-strip" role="status" aria-label={copy.status}>
			<div><span>{copy.identityModel}</span><Badge variant={status.masterEnabled ? 'warning' : 'neutral'} label={status.masterEnabled ? 'ON' : 'OFF'} /></div>
			<div><span>{copy.normalizedReads}</span><Badge variant={status.normalizedReadsEnabled ? 'warning' : 'neutral'} label={status.normalizedReadsEnabled ? 'ON' : 'OFF'} /></div>
			<div><span>{copy.transitions}</span><Badge variant={status.transitionsEnabled ? 'warning' : 'neutral'} label={status.transitionsEnabled ? 'ON' : 'OFF'} /></div>
			<div><span>{copy.sourceModes}</span><strong>{status.sources.shadow} shadow · {status.sources.canary} canary · {status.sources.normalized} normalized</strong></div>
		</div>
	{:else if statusError}
		<div class="inline-warning" role="alert">
			Feature state could not be verified. This screen does not imply production admission:
			{statusError}
			<Button variant="secondary" size="sm" onclick={loadStatus}>Retry status</Button>
		</div>
	{/if}

	{#if sectionError}
		<div class="inline-error" role="alert">
			{sectionError}
			<Button variant="secondary" size="sm" onclick={load}>Retry section</Button>
		</div>
	{:else if loading}
		<div class="stable-loading" role="status"><Spinner size={16} /> Loading identity data</div>
	{:else if initialSection === 'overview'}
		<div class="overview-grid">
			<Card title={copy.reviewQueue}>
				{#snippet children()}
					{@render overviewFeedback('conflicts', 'conflicts')}
					{@render overviewFeedback('transitions', 'transitions')}
					{#if overviewState.conflicts.loaded || overviewState.transitions.loaded}
						<p class="signal-number">{unresolvedReviewCount}</p>
						<p>
							Known conflicts, protected approvals, and recoverable transitions needing an exact action.
							{#if !overviewState.conflicts.loaded || !overviewState.transitions.loaded}
								Available inventories only; retry the unavailable section before acting.
							{/if}
						</p>
					{/if}
					<div class="action-row">
						<a class="text-link" href="/admin/identity/conflicts">Review conflicts</a>
						<a class="text-link" href="/admin/identity/transitions">Review transitions</a>
					</div>
				{/snippet}
			</Card>
			<Card title={copy.sourceHealth}>
				{#snippet children()}
					{@render overviewFeedback('sources', 'sources')}
					{#if overviewState.sources.loaded}
						<p class="signal-number">{sources.filter((source) => source.state === 'active').length} / {sources.length}</p>
						<p>Active sources. {sources.reduce((sum, source) => sum + source.attentionCount, 0)} inbox or quarantine items need review.</p>
					{/if}
					<a class="text-link" href="/admin/identity/sources">Open sources</a>
				{/snippet}
			</Card>
			<Card title={copy.shadowGate}>
				{#snippet children()}
					<p class="signal-number">{status?.blockers.criticalDivergences ?? '—'}</p>
					<p>Critical person, authority, or access divergences. Production flags remain a separate operator decision.</p>
				{/snippet}
			</Card>
		</div>

		<Card title={copy.peopleGlance} flush={true}>
			{@render overviewFeedback('people', 'people')}
			{#if overviewState.people.loaded && people.length === 0}
				<EmptyState title="No normalized people are available" />
			{:else if overviewState.people.loaded}
				<div class="table-wrap">
					<table>
						<caption>Normalized people and lifecycle authority</caption>
						<thead><tr><th scope="col">Person</th><th scope="col">Lifecycle</th><th scope="col">Links</th><th scope="col">Action</th></tr></thead>
						<tbody>
							{#each people.slice(0, 10) as person}
								<tr>
									<td data-label="Person"><strong>{person.displayName ?? person.email}</strong><small>{person.email} · ID {person.userId}</small></td>
									<td data-label="Lifecycle"><Badge variant={person.lifecycleAuthority === 'local' ? 'neutral' : 'info'} label={person.lifecycleAuthority} /> {person.sourceKey ?? 'Setjoin local'}</td>
									<td data-label="Links">{person.activeLinks} active · {person.detachedLinks} detached</td>
									<td data-label="Action"><a class="text-link" href={`/admin/identity/people/${person.userId}`}>Inspect</a></td>
								</tr>
							{/each}
						</tbody>
					</table>
				</div>
			{/if}
		</Card>

		<div class="overview-lists">
			<Card title={copy.conflictsProof}>
				{#snippet children()}
					{@render overviewFeedback('conflicts', 'conflicts')}
					{#if overviewState.conflicts.loaded && conflicts.length === 0}
						<EmptyState title="No unresolved identity conflicts" />
					{:else if overviewState.conflicts.loaded}
						<ul class="record-list">
							{#each conflicts.slice(0, 6) as conflict}
								<li><Badge variant="warning" label={conflict.evidenceClass} /><a href={`/admin/identity/conflicts/${conflict.id}`}>{conflict.sourceKey}</a><span>{conflict.explanation}</span></li>
							{/each}
						</ul>
					{/if}
				{/snippet}
			</Card>
			<Card title={copy.recentAudit}>
				{#snippet children()}
					{@render overviewFeedback('events', 'audit events')}
					{#if overviewState.events.loaded && events.length === 0}
						<EmptyState title="No identity events" />
					{:else if overviewState.events.loaded}
						<ul class="record-list">
							{#each events.slice(0, 6) as event}
								<li><Badge variant="neutral" label={event.action} /><span>{event.reason}</span><small>{formatWhen(event.occurredAt)}</small></li>
							{/each}
						</ul>
					{/if}
				{/snippet}
			</Card>
		</div>

		<Card title={copy.directoryLocal}>
			{#snippet children()}
				<div class="wizard-progress" aria-label="Transition steps">
					<span class="current">1 Select scope</span><span>2 Prove recovery</span><span>3 Preview</span><span>4 Authorize</span>
				</div>
				<p class="mobile-step">Step 1 of 4 — Select scope</p>
				<p>Use the durable Setjoin person ID. Email and UPN are search evidence, never linking proof.</p>
				<div class="form-grid">
					<Input label="User ID" id="identity-transition-user" bind:value={transitionUserId} placeholder="123" />
					<Input label="Target provisioning link ID (optional)" id="identity-transition-target-link" bind:value={transitionTargetLinkId} placeholder="Leave blank for directory → Local" />
					<Input label="Audited reason" id="identity-transition-reason" bind:value={transitionReason} maxlength={1024} placeholder="Approved directory retirement" />
				</div>
				<div class="action-row">
					<Button variant="secondary" onclick={() => previewTransition()} disabled={busy || !transitionUserId.trim() || !transitionReason.trim() || !canWrite}>Preview</Button>
				</div>
				{#if transitionPreview}
					<div class="preview-panel" role="status">
						<h3>Exact preview</h3>
						<p><strong>Transition ID</strong> <code dir="ltr">{transitionPreview.transitionId}</code></p>
						<p><strong>Digest</strong> <code dir="ltr">{transitionPreview.previewDigest}</code></p>
						<p><strong>Recovery</strong> {transitionPreview.recoveryReady ? 'ready' : 'blocked'}</p>
						<p><strong>Mode</strong> {transitionPreview.preview?.type === 'source_to_source' ? `Source → source (target link ${transitionPreview.preview.targetLinkId})` : 'Directory → Local (existing auth links remain)'}</p>
						<p><strong>Protected</strong> {transitionPreview.protected ? 'yes — independent approval required' : 'no'}</p>
						<p><strong>Expires</strong> {formatWhen(transitionPreview.previewExpiresAt)}</p>
						<div class="action-row">
							<Button variant="primary" onclick={() => beginStepUp('request')} disabled={busy || !transitionPreview.recoveryReady}>Authorize exact preview</Button>
						</div>
					</div>
				{/if}
				{#if transitionDetail}
					{@const detail = transitionDetail}
					<div class="preview-panel" aria-live="polite">
						<h3>Durable transition state</h3>
						<p><Badge variant={statusVariant(detail.state)} label={detail.state} /> Generation {detail.transitionGeneration}</p>
						{#if detail.approvalRequestId}<p>Approval request <code>{detail.approvalRequestId}</code>. A different active break-glass administrator must inspect this same digest.</p>{/if}
						<div class="action-row">
							{#if detail.state === 'authorized'}
								<Button variant="danger" onclick={() => beginStepUp('execute')} disabled={busy}>Complete final step-up and execute</Button>
							{:else if detail.state === 'awaiting_approval'}
								<Button variant="secondary" onclick={refreshTransition} disabled={busy}>Refresh approval status</Button>
							{/if}
							<a class="text-link" href={`/admin/identity/transitions/${detail.transitionId}`}>Open durable detail</a>
						</div>
					</div>
				{/if}
			{/snippet}
		</Card>

	{:else if initialSection === 'sources'}
		{#if sourceSetup}
			<Card title="Add identity source">
				{#snippet children()}
					<p>Plan validates and canonicalizes the non-secret document. Apply saves a draft only; activation is always a separate command.</p>
					<Textarea label="Source document" bind:value={sourceDocumentText} rows={18} />
					<Input label="Audited reason" id="source-setup-reason" bind:value={reason} maxlength={1024} placeholder="Add corporate directory source" />
					<div class="action-row">
						<Button variant="secondary" onclick={planSource} disabled={busy || !canWrite}>Plan source</Button>
						{#if sourcePlan}
							<Button variant="primary" onclick={applySource} disabled={busy || !reason.trim() || !sourcePlan.changed}>Save draft</Button>
						{/if}
					</div>
					{#if sourcePlan}
						<div class="preview-panel" role="status">
							<h3>{sourcePlan.create ? 'Create draft' : sourcePlan.changed ? 'Update draft' : 'No changes'}</h3>
							<p>Source key <code>{sourcePlan.sourceKey}</code></p>
							<p>Operations: {sourcePlan.operations.join(', ') || 'none'}</p>
							<p>Activation is not part of apply.</p>
						</div>
					{/if}
				{/snippet}
			</Card>
		{:else if sourceDetail}
			{@const detail = sourceDetail}
			<div class="detail-head">
				<div><a class="text-link" href="/admin/identity/sources">Back to sources</a><h3>{detail.displayName}</h3><p><code>{detail.sourceKey}</code></p></div>
				<Badge variant={statusVariant(detail.state)} label={detail.state} />
			</div>
			<div class="detail-grid">
				<Card title="Source authority">
					{#snippet children()}
						<dl>
							<div><dt>Type</dt><dd>{detail.kind.toUpperCase()}</dd></div>
							<div><dt>Generation</dt><dd>{detail.generation}</dd></div>
							<div><dt>Mapping version</dt><dd>{detail.mappingVersion ?? '—'}</dd></div>
							<div><dt>Last success</dt><dd>{formatWhen(detail.lastSuccessAt)}</dd></div>
							<div><dt>Last failure</dt><dd>{formatWhen(detail.lastFailureAt)}</dd></div>
							<div><dt>Error code</dt><dd>{detail.lastErrorCode ?? 'None'}</dd></div>
						</dl>
					{/snippet}
				</Card>
				<Card title="Secrets">
					{#snippet children()}
						{#if Object.keys(detail.secretConfigured).length === 0}
							<p>This source kind has no external secret.</p>
						{:else}
							{#each Object.entries(detail.secretConfigured) as [name, configured]}
								<div class="secret-row">
									<span><code>{name}</code> <Badge variant={configured ? 'success' : 'warning'} label={configured ? 'configured' : 'missing'} /></span>
									<Input
										label={`${name} value`}
										id={`secret-${name}`}
										type="password"
										value={secretValues[name] ?? ''}
										oninput={(e) => (secretValues[name] = (e.currentTarget as HTMLInputElement).value)}
										autocomplete="new-password"
									/>
									<div class="action-row">
										<Button variant="secondary" onclick={() => saveSecret(name, configured)} disabled={busy || !secretValues[name] || !reason.trim() || !canWrite}>{configured ? 'Rotate secret' : 'Set secret'}</Button>
									</div>
								</div>
							{/each}
						{/if}
					{/snippet}
				</Card>
			</div>
			<Card title="Safe source operations">
				{#snippet children()}
					<Input label="Audited reason" id="source-action-reason" bind:value={reason} maxlength={1024} />
					<div class="action-row">
						<Button variant="secondary" onclick={() => sourceAction('dry-run')} disabled={busy || !reason.trim() || !canWrite}>Run dry run</Button>
						{#if detail.state === 'draft' || detail.state === 'validated'}<Button variant="primary" onclick={() => sourceAction('activate')} disabled={busy || !reason.trim() || !canWrite}>Activate</Button>{/if}
						{#if detail.state === 'active'}<Button variant="secondary" onclick={() => sourceAction('pause')} disabled={busy || !reason.trim() || !canWrite}>Pause</Button>{/if}
						{#if detail.state === 'paused'}<Button variant="secondary" onclick={() => sourceAction('resume')} disabled={busy || !reason.trim() || !canWrite}>Resume</Button>{/if}
						{#if detail.state !== 'retired'}<Button variant="danger" onclick={() => sourceAction('retire')} disabled={busy || !reason.trim() || !canWrite}>Retire permanently</Button>{/if}
					</div>
					<p>Every mutation uses the current generation, a new idempotency key, and this exact reason. Dry run writes zero people.</p>
				{/snippet}
			</Card>
			<Card title="Canonical non-secret configuration">
				{#snippet children()}<pre>{JSON.stringify(detail.document, null, 2)}</pre>{/snippet}
			</Card>
		{:else}
			<div class="section-toolbar">
				<div><h3>Sources</h3><p>Systems that authenticate people or control lifecycle, attributes, and grants.</p></div>
				<a class="primary-link" href="/admin/identity/sources/new">Add source</a>
			</div>
			<Input label="Search sources" id="identity-source-filter" bind:value={filter} />
			<div class="action-row"><Button variant="secondary" onclick={load}>Search</Button></div>
			{#if sources.length === 0}
				<EmptyState title="No normalized sources. Run identity upgrade preflight before configuring production reads." />
			{:else}
				<div class="table-wrap">
					<table>
						<caption>Identity sources and current operating state</caption>
						<thead><tr><th scope="col">Source</th><th scope="col">Capabilities</th><th scope="col">State</th><th scope="col">Generation</th><th scope="col">Health</th></tr></thead>
						<tbody>
							{#each sources as source}
								<tr tabindex="0">
									<td data-label="Source"><a href={`/admin/identity/sources/${encodeURIComponent(source.sourceKey)}`}><strong>{source.displayName}</strong></a><small><code>{source.sourceKey}</code> · {source.kind}</small></td>
									<td data-label="Capabilities">{Object.keys(source.capabilities ?? {}).join(', ') || 'Not declared'}</td>
									<td data-label="State"><Badge variant={statusVariant(source.state)} label={source.state} /></td>
									<td data-label="Generation">{source.generation}</td>
									<td data-label="Health">{source.attentionCount} attention · {formatWhen(source.lastSuccessAt)}</td>
								</tr>
							{/each}
						</tbody>
					</table>
				</div>
			{/if}
		{/if}

	{:else if initialSection === 'people'}
		{#if personDetail}
			{@const detail = personDetail}
			<div class="split-detail">
				<aside class="desktop-master" aria-label="People">
					<div class="master-list">
						{#each people as person}
							<a href={`/admin/identity/people/${person.userId}`} aria-current={person.userId === detail.userId ? 'page' : undefined}>
								<strong>{person.displayName ?? person.email}</strong>
								<span>{person.email} · ID {person.userId}</span>
							</a>
						{/each}
					</div>
				</aside>
				<div class="split-detail-main">
			<div class="detail-head">
				<div><a class="text-link" href="/admin/identity/people">Back to people</a><h3>{detail.displayName ?? detail.email}</h3><p>{detail.email} · Person ID <code>{detail.userId}</code></p></div>
				<div><Badge variant={detail.enabled ? 'success' : 'danger'} label={detail.enabled ? 'enabled' : 'disabled'} /> {#if detail.protected}<Badge variant="warning" label="protected" />{/if}</div>
			</div>
			<div class="detail-grid">
				<Card title="Lifecycle and recovery">
					{#snippet children()}
						<dl>
							<div><dt>Relationship</dt><dd>{detail.relationship}</dd></div>
							<div><dt>Lifecycle owner</dt><dd>{detail.lifecycleAuthority.sourceKey ?? detail.lifecycleAuthority.kind}</dd></div>
							<div><dt>Authority generation</dt><dd>{detail.lifecycleAuthority.generation}</dd></div>
							<div><dt>Local password</dt><dd>{detail.recovery.hasLocalPassword ? 'verified posture present' : 'not present'}</dd></div>
							<div><dt>Passkeys</dt><dd>{detail.recovery.passkeyCount}</dd></div>
							<div><dt>Active auth links</dt><dd>{detail.recovery.activeAuthenticationLinks}</dd></div>
						</dl>
					{/snippet}
				</Card>
				<Card title="Authentication links">
					{#snippet children()}
						{#if detail.links.length === 0}<EmptyState title="No identity links" />{:else}
							<ul class="record-list">{#each detail.links as link}<li><Badge variant={statusVariant(link.state)} label={link.state} /><strong>{link.sourceKey}</strong><span>{link.purposes.join(', ')} · generation {link.generation}</span><small>Subject fingerprint <code>{link.subjectFingerprint}</code></small></li>{/each}</ul>
						{/if}
					{/snippet}
				</Card>
			</div>
			<Card title="Field authority">
				{#snippet children()}
					{#if detail.fieldAuthority.length === 0}<EmptyState title="No governed field authority rows" />{:else}
						<div class="table-wrap">
							<table>
								<caption>Field ownership and source generation</caption>
								<thead><tr><th scope="col">Field</th><th scope="col">Authority</th><th scope="col">Source</th><th scope="col">Generation</th><th scope="col">Override</th></tr></thead>
								<tbody>
									{#each detail.fieldAuthority as row}
										<tr tabindex="0">
											<td data-label="Field">{row.field}</td>
											<td data-label="Authority">{row.authorityKind}</td>
											<td data-label="Source">{row.sourceKey ?? 'Local'}</td>
											<td data-label="Generation">{row.generation}</td>
											<td data-label="Override">{row.localOverrideState}</td>
										</tr>
									{/each}
								</tbody>
							</table>
						</div>
					{/if}
				{/snippet}
			</Card>
			<Card title="Entitlement provenance">
				{#snippet children()}
					{#if detail.entitlementProvenance.length === 0}<EmptyState title="No source-owned entitlement grants" />{:else}
						<ul class="record-list">{#each detail.entitlementProvenance as grant}<li><Badge variant="neutral" label={grant.provenanceKind} /><strong>{grant.entitlementKind} {grant.entitlementId}</strong><span>{grant.sourceKey ?? 'Manual'} · generation {grant.sourceGeneration}</span></li>{/each}</ul>
					{/if}
				{/snippet}
			</Card>
			<Card title="Transition and link history">
				{#snippet children()}
					<ul class="record-list">{#each detail.transitionHistory as item}<li><Badge variant={statusVariant(item.state)} label={item.state} /><a href={`/admin/identity/transitions/${item.id}`}>{item.kind}</a><small>{formatWhen(item.updatedAt)}</small></li>{/each}{#each detail.linkHistory as item}<li><Badge variant="neutral" label={item.action} /><span>{item.reason}</span><small>{formatWhen(item.occurredAt)} · {item.correlationId}</small></li>{/each}</ul>
				{/snippet}
			</Card>
				</div>
			</div>
		{:else}
			<div class="section-toolbar"><div><h3>People</h3><p>Durable Setjoin people, lifecycle ownership, authentication links, and recovery posture.</p></div></div>
			<Input label="Search people" id="identity-people-filter" bind:value={filter} />
			<div class="action-row"><Button variant="secondary" onclick={load}>Search</Button></div>
			{#if people.length === 0}<EmptyState title="No normalized people are available" />{:else}
				<div class="master-list">{#each people as person}<a href={`/admin/identity/people/${person.userId}`}><strong>{person.displayName ?? person.email}</strong><span>{person.email} · ID {person.userId}</span><span><Badge variant={person.lifecycleAuthority === 'local' ? 'neutral' : 'info'} label={person.lifecycleAuthority} /> {person.sourceKey ?? 'Setjoin local'} · {person.activeLinks} active links</span></a>{/each}</div>
			{/if}
		{/if}

	{:else if initialSection === 'conflicts'}
		{#if conflictDetail}
			{@const detail = conflictDetail}
			<div class="split-detail">
				<aside class="desktop-master" aria-label="Conflicts">
					<div class="master-list">
						{#each conflicts as conflict}
							<a href={`/admin/identity/conflicts/${conflict.id}`} aria-current={conflict.id === detail.id ? 'page' : undefined}>
								<strong>{conflict.sourceKey}</strong>
								<span><Badge variant="warning" label={conflict.evidenceClass} /> {conflict.state}</span>
								<small>{conflict.explanation}</small>
							</a>
						{/each}
					</div>
				</aside>
				<div class="split-detail-main">
			<div class="detail-head">
				<div><a class="text-link" href="/admin/identity/conflicts">Back to conflicts</a><h3>Conflict evidence</h3><p>Conflict ID <code>{detail.id}</code></p></div>
				<Badge variant={statusVariant(detail.state)} label={detail.state} />
			</div>
			{#if detail.candidatePerson?.protected}<div class="inline-warning" role="alert">This candidate is protected. Direct linking is prohibited; use an independently approved transition.</div>{/if}
			<div class="compare-grid">
				<Card title="Source object">
					{#snippet children()}
						<dl><div><dt>Source</dt><dd>{detail.source.displayName} · <code>{detail.source.sourceKey}</code></dd></div><div><dt>Immutable subject fingerprint</dt><dd><code>{detail.subjectFingerprint}</code></dd></div><div><dt>Evidence class</dt><dd><Badge variant={detail.evidenceClass === 'soft' ? 'warning' : 'info'} label={detail.evidenceClass} /></dd></div><div><dt>Evidence digest</dt><dd><code dir="ltr">{detail.evidenceDigest}</code></dd></div><div><dt>Expires</dt><dd>{formatWhen(detail.expiresAt)}</dd></div></dl>
						<p>{detail.explanation}</p>
						{#if detail.evidenceClass === 'soft'}<p class="soft-warning">Review evidence only—never linking proof.</p>{/if}
					{/snippet}
				</Card>
				<Card title="Candidate Setjoin person">
					{#snippet children()}
						{#if detail.candidatePerson}
							<dl><div><dt>Person</dt><dd>{detail.candidatePerson.displayName ?? detail.candidatePerson.email}</dd></div><div><dt>Email evidence</dt><dd>{detail.candidatePerson.email}</dd></div><div><dt>Stable ID</dt><dd><code>{detail.candidatePerson.userId}</code></dd></div><div><dt>Account</dt><dd>{detail.candidatePerson.enabled ? 'enabled' : 'disabled'}{detail.candidatePerson.protected ? ' · protected' : ''}</dd></div></dl>
						{:else}<EmptyState title="No candidate person. Create new, reject, or defer after reviewing source evidence." />{/if}
					{/snippet}
				</Card>
			</div>
			<Card title="Record one decision">
				{#snippet children()}
					<p>No bulk-link action exists. The server rechecks the exact candidate generation and protected-account boundary.</p>
					<Input label="Audited reason" id="conflict-reason" bind:value={reason} maxlength={1024} />
					<div class="action-row">
						{#each detail.allowedDecisions as decision}
							<Button variant={decision === 'reject' ? 'danger' : decision === 'link' ? 'primary' : 'secondary'} onclick={() => decideConflict(decision)} disabled={busy || !reason.trim() || !canWrite}>{decision === 'link' ? 'Link evidenced person' : decision === 'create' ? 'Create new person' : decision === 'reject' ? 'Reject candidate' : 'Defer review'}</Button>
						{/each}
					</div>
				{/snippet}
			</Card>
			<Card title="Decision history">
				{#snippet children()}
					{#if detail.decisionHistory.length === 0}<EmptyState title="No prior decisions" />{:else}<ul class="record-list">{#each detail.decisionHistory as item}<li><Badge variant="neutral" label={item.decision} /><span>{item.reason}</span><small>{formatWhen(item.occurredAt)} · actor {item.decidedBy}</small></li>{/each}</ul>{/if}
				{/snippet}
			</Card>
				</div>
			</div>
		{:else}
			<div class="section-toolbar"><div><h3>Conflicts</h3><p>Immutable and soft evidence remain separate. Every decision is single-record, reasoned, and generation-fenced.</p></div></div>
			<Input label="Search conflicts" id="identity-conflict-filter" bind:value={filter} />
			<div class="action-row"><Button variant="secondary" onclick={load}>Search</Button></div>
			{#if conflicts.length === 0}<EmptyState title="No unresolved identity conflicts" />{:else}
				<div class="master-list">{#each conflicts as conflict}<a href={`/admin/identity/conflicts/${conflict.id}`}><strong>{conflict.sourceKey}</strong><span><Badge variant="warning" label={conflict.evidenceClass} /> {conflict.state} · generation {conflict.generation}</span><span>{conflict.explanation}</span><small>Expires {formatWhen(conflict.expiresAt)}</small></a>{/each}</div>
			{/if}
		{/if}

	{:else if initialSection === 'transitions'}
		{#if transitionDetail}
			{@const detail = transitionDetail}
			<div class="detail-head">
				<div><a class="text-link" href="/admin/identity/transitions">Back to transitions</a><h3>{detail.type.replaceAll('_', ' → ')}</h3><p>Transition <code dir="ltr">{detail.transitionId}</code></p></div>
				<Badge variant={statusVariant(detail.state)} label={detail.state} />
			</div>
			<div class="inline-info" role="status">
				<strong>Durable boundary:</strong> {detail.rollback.boundary}. Authority and pending external effects are shown separately; after cutover this screen never calls forward recovery “cancel”.
			</div>
			<div class="detail-grid">
				<Card title="Authorization">
					{#snippet children()}
						<dl><div><dt>Person</dt><dd><code>{detail.personId}</code></dd></div><div><dt>Generation</dt><dd>{detail.transitionGeneration}</dd></div><div><dt>Preview digest</dt><dd><code dir="ltr">{detail.previewDigest}</code></dd></div><div><dt>Requested by</dt><dd>{detail.requestedBy ?? '—'} · {formatWhen(detail.requestedAt)}</dd></div><div><dt>Approval</dt><dd>{detail.approvalRequestId ?? 'Not required'}{detail.approvedBy ? ` · approved by ${detail.approvedBy}` : ''}</dd></div><div><dt>Correlation ID</dt><dd><code>{detail.correlationId}</code></dd></div></dl>
					{/snippet}
				</Card>
				<Card title="Recovery posture">
					{#snippet children()}
						<dl><div><dt>Rollback boundary</dt><dd>{detail.rollback.boundary}</dd></div><div><dt>Rollback preview</dt><dd>{detail.rollback.previewDigest ? 'available' : 'not created'}</dd></div><div><dt>Failure code</dt><dd>{detail.failureCode ?? 'None'}</dd></div><div><dt>Committed</dt><dd>{formatWhen(detail.committedAt)}</dd></div><div><dt>Completed</dt><dd>{formatWhen(detail.completedAt)}</dd></div></dl>
					{/snippet}
				</Card>
			</div>
			<Card title="Progress timeline">
				{#snippet children()}
					<div class="timeline" role="region" aria-label="Transition progress">
						{#each detail.steps ?? [] as step}<div><Badge variant={statusVariant(step.state)} label={step.state} /><strong>{step.ordinal}. {step.stage}</strong><span>Attempt {step.attemptCount}{step.errorCode ? ` · ${step.errorCode}` : ''}</span></div>{/each}
					</div>
				{/snippet}
			</Card>
			<Card title="External effects and exact recovery">
				{#snippet children()}
					{#if detail.effects.length === 0}<EmptyState title="No external effects recorded" />{:else}
						<div class="table-wrap">
							<table>
								<caption>Durable external effects</caption>
								<thead><tr><th scope="col">Effect</th><th scope="col">State</th><th scope="col">Attempts</th><th scope="col">Next attempt</th><th scope="col">Recovery</th></tr></thead>
								<tbody>
									{#each detail.effects as effect}
										<tr tabindex="0">
											<td data-label="Effect">{effect.kind}<small><code>{effect.effectId}</code></small></td>
											<td data-label="State"><Badge variant={statusVariant(effect.state)} label={effect.state} />{effect.lastErrorCode ? ` ${effect.lastErrorCode}` : ''}</td>
											<td data-label="Attempts">{effect.attemptCount}</td>
											<td data-label="Next attempt">{formatWhen(effect.nextAttemptAt)}</td>
											<td data-label="Recovery">{#if effect.state === 'failed'}<Button variant="secondary" size="sm" onclick={() => retryEffect(effect.effectId)} disabled={busy || !transitionReason.trim() || !canWrite}>Retry this effect</Button>{:else}<span>Worker-owned</span>{/if}</td>
										</tr>
									{/each}
								</tbody>
							</table>
						</div>
					{/if}
				{/snippet}
			</Card>
			<Card title="Protected commands">
				{#snippet children()}
					<Input label="Audited reason" id="transition-detail-reason" bind:value={transitionReason} maxlength={1024} />
					{#if detail.rollback.previewDigest}
						<Input label="Rollback approval request ID" id="rollback-approval-id" bind:value={rollbackApprovalId} placeholder={detail.rollback.approvalRequestId ?? ''} />
					{/if}
					<div class="action-row">
						<Button variant="secondary" onclick={refreshTransition} disabled={busy}>Refresh</Button>
						{#if detail.state === 'awaiting_approval'}
							<Button variant="primary" onclick={() => beginStepUp('approve')} disabled={busy || !transitionReason.trim() || !canWrite}>Step up and approve</Button>
							<Button variant="danger" onclick={() => beginStepUp('deny')} disabled={busy || !transitionReason.trim() || !canWrite}>Step up and deny</Button>
						{/if}
						{#if detail.state === 'authorized'}
							<Button variant="danger" onclick={() => beginStepUp('execute')} disabled={busy || !transitionReason.trim() || !canWrite}>Step up and execute</Button>
						{/if}
						{#if ['draft', 'previewed', 'awaiting_approval', 'authorized', 'failed_precommit'].includes(detail.state)}
							<Button variant="secondary" onclick={cancelTransition} disabled={busy || !transitionReason.trim() || !canWrite}>Cancel pre-commit transition</Button>
						{/if}
						{#if detail.state === 'failed_recoverable' && !detail.rollback.previewDigest}
							<Button variant="secondary" onclick={previewRollback} disabled={busy || !transitionReason.trim() || !canWrite}>Preview rollback boundary</Button>
						{/if}
						{#if detail.rollback.previewDigest}
							<Button variant="danger" onclick={() => beginStepUp('rollback')} disabled={busy || !transitionReason.trim() || !canWrite}>Step up for approved rollback</Button>
						{/if}
						<Button variant="secondary" onclick={() => downloadReport(detail.transitionId)}>Download sanitized report</Button>
					</div>
				{/snippet}
			</Card>
		{:else}
			<div class="section-toolbar"><div><h3>Transitions</h3><p>Draft, approval, execution, committed authority, effect convergence, and rollback are distinct durable states.</p></div></div>
			<div class="form-grid"><Input label="Person ID for new preview" id="transition-list-person" bind:value={transitionUserId} /><Input label="Audited reason" id="transition-list-reason" bind:value={transitionReason} maxlength={1024} /></div>
			<div class="action-row"><Button variant="secondary" onclick={() => previewTransition()} disabled={busy || !transitionUserId.trim() || !transitionReason.trim() || !canWrite}>Preview</Button></div>
			{#if transitionPreview}
				<div class="preview-panel"><h3>Step 3 of 4 — Preview</h3><p>Transition <code>{transitionPreview.transitionId}</code></p><p>Digest <code dir="ltr">{transitionPreview.previewDigest}</code></p><p>Recovery {transitionPreview.recoveryReady ? 'ready' : 'blocked'} · protected {transitionPreview.protected ? 'yes' : 'no'}</p><div class="action-row"><Button variant="primary" onclick={() => beginStepUp('request')} disabled={busy || !transitionPreview.recoveryReady}>Authorize exact preview</Button></div></div>
			{/if}
			{#if transitions.length === 0}<EmptyState title="No identity transitions. Preview is required before any directory account is detached." />{:else}
				<div class="master-list">{#each transitions as item}<a href={`/admin/identity/transitions/${item.id}`}><strong>{item.kind.replaceAll('_', ' → ')}</strong><span><Badge variant={statusVariant(item.state)} label={item.state} /> Person {item.userId} · {item.sourceKey}</span><span>{item.pendingEffects} pending effects{item.failureCode ? ` · ${item.failureCode}` : ''}</span><small>{formatWhen(item.updatedAt)}</small></a>{/each}</div>
			{/if}
		{/if}

	{:else}
		<div class="section-toolbar"><div><h3>{copy.auditInventory}</h3><p>{copy.auditDescription}</p></div></div>
		<div class="audit-filters" role="search" aria-label={copy.auditFilters}>
			<Input label={copy.personId} id="identity-audit-person" bind:value={auditPerson} maxlength={64} />
			<Input label={copy.sourceKey} id="identity-audit-source" bind:value={auditSource} maxlength={256} />
			<Input label={copy.transitionId} id="identity-audit-transition" bind:value={auditTransition} maxlength={64} />
			<Input label={copy.actorId} id="identity-audit-actor" bind:value={auditActor} maxlength={64} />
			<Input label={copy.outcome} id="identity-audit-outcome" bind:value={auditOutcome} maxlength={128} />
			<Input label={copy.fromDate} id="identity-audit-from" type="date" bind:value={auditFrom} />
			<Input label={copy.toDate} id="identity-audit-to" type="date" bind:value={auditTo} />
			<Input label={copy.serverFilter} id="identity-audit-filter" bind:value={filter} maxlength={256} placeholder="Action or source key" />
		</div>
		<div class="action-row">
			<Button variant="secondary" onclick={load}>{copy.refreshInventory}</Button>
			<Button variant="secondary" onclick={exportAudit} disabled={filteredEvents.length === 0}>{copy.exportCsv}</Button>
		</div>
		<p class="filter-summary" role="status">{filteredEvents.length} of {events.length} loaded events match the current filters.</p>
		{#if filteredEvents.length === 0}<EmptyState title={copy.noAuditMatches} />{:else}
			<div class="table-wrap">
				<table>
					<caption>Identity link, authority, conflict, transition, and notice events</caption>
					<thead><tr><th scope="col">When</th><th scope="col">Outcome</th><th scope="col">Scope</th><th scope="col">Actor</th><th scope="col">Reason</th><th scope="col">Correlation</th></tr></thead>
					<tbody>
						{#each filteredEvents as event}
							<tr tabindex="0">
								<td data-label="When">{formatWhen(event.occurredAt)}</td>
								<td data-label="Outcome"><Badge variant="neutral" label={event.action} /></td>
								<td data-label="Scope">{event.sourceKey ?? 'Local'}{event.userId ? ` · person ${event.userId}` : ''}{event.transitionId ? ` · transition ${event.transitionId}` : ''}</td>
								<td data-label="Actor">{eventActor(event) || 'Not recorded'}</td>
								<td data-label="Reason">{event.reason}</td>
								<td data-label="Correlation"><code dir="ltr">{event.correlationId}</code></td>
							</tr>
						{/each}
					</tbody>
				</table>
			</div>
		{/if}
	{/if}

	{#if transitionChallenge}
		{@const challenge = transitionChallenge}
		<Dialog
			open={true}
			title="Fresh, digest-bound step-up"
			onClose={busy ? undefined : closeStepUp}
		>
			{#snippet children()}
				<div class="step-up-dialog" aria-live="polite">
					<p>Verification code <code>{challenge.displayCode}</code></p>
					<p>
						Complete MFA as the currently signed-in administrator before
						{formatWhen(challenge.expiresAt)}. This one-use elevation is
						bound to the exact transition and preview digest.
					</p>
					{#if transitionAction === 'approve' || transitionAction === 'deny'}
						<p>The requester cannot review their own protected transition.</p>
					{/if}
					<div class="action-row">
						<Button variant="secondary" onclick={openVerification} disabled={busy}>Open verification</Button>
						<Button variant="primary" onclick={completeStepUp} disabled={busy}>I completed MFA</Button>
					</div>
				</div>
			{/snippet}
		</Dialog>
	{/if}
</section>

<style>
	.identity-console { display: grid; gap: var(--space-4); min-width: 0; }
	.identity-heading, .detail-head, .section-toolbar { display: flex; align-items: flex-start; justify-content: space-between; gap: var(--space-4); }
	.identity-heading h2, .detail-head h3, .section-toolbar h3 { margin: 0; font-size: var(--text-xl); }
	.identity-heading p, .detail-head p, .section-toolbar p { margin: var(--space-1) 0 0; color: var(--text-secondary); }
	.identity-tabs { display: flex; gap: var(--space-1); overflow-x: auto; border-bottom: 1px solid var(--border-default); scrollbar-width: thin; }
	.identity-tabs a { min-height: 44px; display: inline-flex; align-items: center; padding: 0 var(--space-3); color: var(--text-secondary); text-decoration: none; white-space: nowrap; border-bottom: 2px solid transparent; }
	.identity-tabs a.active { color: var(--text-primary); border-bottom-color: var(--indigo-600); font-weight: var(--weight-medium); }
	.identity-tabs a:focus-visible, .text-link:focus-visible, .primary-link:focus-visible, .master-list a:focus-visible { outline: var(--focus-ring); outline-offset: -2px; }
	.identity-overflow { display: none; }
	.flag-strip { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: var(--space-3); padding: var(--space-3); border: 1px solid var(--border-default); border-radius: var(--radius-md); background: var(--surface-card); }
	.flag-strip > div { display: grid; gap: var(--space-1); }
	.flag-strip span { color: var(--text-caption); font-size: var(--text-sm); }
	.inline-error, .inline-warning, .inline-info, .stable-loading { display: flex; flex-wrap: wrap; align-items: center; gap: var(--space-3); min-width: 0; padding: var(--space-3); overflow-wrap: anywhere; border: 1px solid var(--danger-solid); background: var(--danger-bg); color: var(--danger-fg); border-radius: var(--radius-md); font-size: var(--text-sm); }
	.section-feedback { margin-bottom: var(--space-2); }
	.inline-warning { border-color: var(--warning-solid); background: var(--warning-bg); color: var(--warning-fg); }
	.inline-info, .stable-loading { border-color: var(--info-solid); background: var(--info-bg); color: var(--info-fg); }
	.overview-grid { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: var(--space-3); }
	.overview-lists, .detail-grid, .compare-grid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: var(--space-3); }
	.signal-number { margin: 0; font-size: var(--text-3xl); font-weight: var(--weight-semibold); }
	.action-row { display: flex; flex-wrap: wrap; align-items: center; gap: var(--space-2); margin-top: var(--space-3); }
	.text-link { color: var(--link); }
	.primary-link { display: inline-flex; min-height: 44px; align-items: center; padding: 0 var(--space-3); background: var(--indigo-600); color: var(--text-inverse); border-radius: var(--radius-md); text-decoration: none; }
	.form-grid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: var(--space-3); }
	.audit-filters { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: var(--space-3); }
	.filter-summary { margin: 0; color: var(--text-caption); font-size: var(--text-sm); }
	.table-wrap { overflow-x: auto; }
	table { width: 100%; border-collapse: collapse; font-size: var(--text-sm); }
	td::before { display: none; }
	caption { text-align: left; color: var(--text-caption); padding: var(--space-2) var(--space-3); }
	th, td { text-align: left; vertical-align: top; padding: var(--space-3); border-bottom: 1px solid var(--border-default); }
	th { color: var(--text-caption); font-weight: var(--weight-medium); }
	td small, .record-list small, .master-list span, .master-list small { display: block; margin-top: var(--space-1); color: var(--text-caption); }
	code, pre { font-family: var(--font-mono); overflow-wrap: anywhere; }
	pre { margin: 0; padding: var(--space-3); max-height: 420px; overflow: auto; background: var(--surface-sunken); border: 1px solid var(--border-default); border-radius: var(--radius-sm); font-size: var(--text-sm); }
	.record-list { list-style: none; padding: 0; margin: 0; display: grid; gap: var(--space-3); }
	.record-list li { display: grid; grid-template-columns: max-content 1fr; gap: var(--space-1) var(--space-2); align-items: start; }
	.record-list li small { grid-column: 2; }
	.master-list { display: grid; border: 1px solid var(--border-default); border-radius: var(--radius-md); overflow: hidden; }
	.master-list > a { display: grid; gap: var(--space-1); min-height: 64px; padding: var(--space-3); color: var(--text-primary); text-decoration: none; border-bottom: 1px solid var(--border-default); }
	.master-list > a:last-child { border-bottom: 0; }
	.master-list > a:hover { background: var(--surface-hover); }
	.master-list > a[aria-current="page"] { background: var(--surface-selected); box-shadow: inset 3px 0 0 var(--indigo-600); }
	.split-detail { display: grid; grid-template-columns: minmax(240px, 300px) minmax(0, 1fr); gap: var(--space-4); align-items: start; }
	.split-detail-main { min-width: 0; display: grid; gap: var(--space-4); }
	.desktop-master { position: sticky; top: var(--space-4); min-width: 0; max-height: calc(100vh - var(--space-8)); overflow: auto; }
	dl { margin: 0; display: grid; gap: var(--space-2); }
	dl > div { display: grid; grid-template-columns: minmax(120px, .7fr) 1fr; gap: var(--space-3); }
	dt { color: var(--text-caption); }
	dd { margin: 0; min-width: 0; overflow-wrap: anywhere; }
	.preview-panel { margin-top: var(--space-3); padding: var(--space-3); border: 1px solid var(--border-default); border-radius: var(--radius-md); background: var(--surface-sunken); }
	.preview-panel h3 { margin: 0 0 var(--space-2); font-size: var(--text-md); }
	.preview-panel p, .step-up-dialog p { margin: var(--space-2) 0; }
	.wizard-progress { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: var(--space-2); margin-bottom: var(--space-3); }
	.wizard-progress span { padding: var(--space-2); border-bottom: 2px solid var(--border-default); color: var(--text-caption); }
	.wizard-progress .current { border-bottom-color: var(--indigo-600); color: var(--text-primary); font-weight: var(--weight-medium); }
	.mobile-step { display: none; }
	.soft-warning { color: var(--warning-fg); font-weight: var(--weight-medium); }
	.secret-row { display: grid; gap: var(--space-2); padding-block: var(--space-2); border-bottom: 1px solid var(--border-default); }
	.secret-row:last-child { border-bottom: 0; }
	.timeline { display: grid; gap: var(--space-2); }
	.timeline > div { display: grid; grid-template-columns: max-content 1fr max-content; gap: var(--space-2); align-items: center; padding: var(--space-2); border-left: 2px solid var(--border-default); }

	@media (max-width: 960px) {
		.flag-strip, .overview-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
		.detail-grid, .compare-grid { grid-template-columns: 1fr; }
		.audit-filters { grid-template-columns: repeat(2, minmax(0, 1fr)); }
		.split-detail { grid-template-columns: 1fr; }
		.desktop-master { display: none; }
	}

	@media (max-width: 680px) {
		.identity-heading, .detail-head, .section-toolbar { display: grid; }
		.identity-tabs { scroll-snap-type: x proximity; }
		.identity-tabs a { scroll-snap-align: start; }
		.identity-overflow { display: block; }
		.identity-overflow summary { min-height: 44px; display: flex; align-items: center; cursor: pointer; }
		.identity-overflow ul { list-style: none; padding: 0; }
		.identity-overflow a { min-height: 44px; display: flex; align-items: center; }
		.flag-strip, .overview-grid, .overview-lists, .form-grid, .audit-filters { grid-template-columns: 1fr; }
		.wizard-progress { display: none; }
		.mobile-step { display: block; font-weight: var(--weight-medium); }
		.table-wrap table, .table-wrap thead, .table-wrap tbody, .table-wrap tr, .table-wrap th, .table-wrap td { display: block; }
		.table-wrap thead { position: absolute; width: 1px; height: 1px; overflow: hidden; clip-path: inset(50%); }
		.table-wrap tr { margin: var(--space-2); padding: var(--space-2); border: 1px solid var(--border-default); border-radius: var(--radius-md); }
		.table-wrap td { border: 0; padding: var(--space-2); min-width: 0; overflow-wrap: anywhere; }
		.table-wrap td::before { content: attr(data-label); display: block; margin-bottom: var(--space-1); color: var(--text-caption); font-size: var(--text-xs); font-weight: var(--weight-medium); }
		.timeline > div { grid-template-columns: max-content 1fr; }
		.timeline > div span:last-child { grid-column: 2; }
	}

	@media (forced-colors: active) {
		.identity-tabs a.active, .wizard-progress .current { border-color: Highlight; }
	}

	@media (prefers-reduced-motion: reduce) {
		.identity-tabs { scroll-behavior: auto; }
	}
</style>
