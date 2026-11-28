<svelte:options runes={true} />

<script lang="ts">
	import { onMount } from 'svelte';
	import { Button } from '$lib/components/ui';
	import { t } from '$lib/i18n';
	import { listConversations, type Conversation } from '$lib/chat/api';
	import { listSpaces, tree, type DriveNode } from '$lib/drive/api';
	import { user } from '$lib/stores/auth';
	import {
		mailCommentGet, mailCommentSet, mailWorkAction, mailWorkCollaboratorsGet, mailWorkGet, mailWorkSet,
		mailWorkMetricsGet, mailWorkNotificationPreferenceSet, mailWorkNotificationPreferencesGet,
		mailWorkPolicyGet, mailWorkPolicySet,
		type MailActivityItem, type MailWorkCollaborator, type MailWorkItem, type MailWorkMetrics,
		type MailWorkNotificationDelivery, type MailWorkNotificationPreference, type MailWorkPolicyProjection,
		type MailWorkStatus,
	} from '$lib/mail/mailWork';

	let { accountId, threadId, canCollaborate, commentsEnabled, notificationsEnabled = false,
		analyticsEnabled = false, integrationsEnabled = false, onClose, onChanged }:
		{ accountId: string; threadId: string; canCollaborate: boolean; commentsEnabled: boolean;
			notificationsEnabled?: boolean; analyticsEnabled?: boolean; integrationsEnabled?: boolean;
			onClose: () => void; onChanged?: () => void } = $props();
	let work = $state<MailWorkItem | null>(null);
	let loading = $state(true);
	let pending = $state(false);
	let error = $state('');
	let dueLocal = $state('');
	let activity = $state<MailActivityItem[]>([]);
	let commentBody = $state('');
	let preferences = $state<MailWorkNotificationPreference[]>([]);
	let metrics = $state<MailWorkMetrics | null>(null);
	let conversations = $state<Conversation[]>([]);
	let driveNodes = $state<Array<DriveNode & { spaceName: string }>>([]);
	let chatTargetId = $state('');
	let driveTargetId = $state('');
	let actionQueued = $state('');
	let handoffQuery = $state('');
	let handoffResults = $state<MailWorkCollaborator[]>([]);
	let handoffTarget = $state<MailWorkCollaborator | null>(null);
	let handoffSearching = $state(false);
	let mentionQuery = $state('');
	let mentionResults = $state<MailWorkCollaborator[]>([]);
	let mentionTargets = $state<MailWorkCollaborator[]>([]);
	let mentionSearching = $state(false);
	let editingCommentId = $state<string | null>(null);
	let retainedMentionIds = $state<string[]>([]);
	let policy = $state<MailWorkPolicyProjection | null>(null);
	let policyTimezone = $state('UTC');
	let policyWeekdayMask = $state(62);
	let policyStart = $state('09:00');
	let policyEnd = $state('17:00');
	let policyHolidays = $state('');
	let policySlaMinutes = $state(480);
	const weekdays = [
		{ bit: 1, key: 'sun' }, { bit: 2, key: 'mon' }, { bit: 4, key: 'tue' },
		{ bit: 8, key: 'wed' }, { bit: 16, key: 'thu' }, { bit: 32, key: 'fri' }, { bit: 64, key: 'sat' },
	];

	onMount(() => {
		void load();
		if (integrationsEnabled && canCollaborate) void loadIntegrationTargets();
		const timer = window.setInterval(() => {
			if (!pending && document.visibilityState === 'visible') void load(true);
		}, 10_000);
		return () => window.clearInterval(timer);
	});

	async function loadIntegrationTargets() {
		try {
			const [chatResult, spaces] = await Promise.all([listConversations(), listSpaces()]);
			conversations = chatResult.conversations.slice(0, 100);
			const roots = await Promise.all(spaces.slice(0, 20).map(async (space) =>
				(await tree(space.id)).filter((node) => node.capabilities?.includes('read_metadata'))
					.map((node) => ({ ...node, spaceName: space.name }))));
			driveNodes = roots.flat().slice(0, 200);
		} catch {
			// The action reducer still rechecks authority. A target catalog failure
			// leaves the affected selector empty instead of accepting a typed raw id.
		}
	}

	async function runHandoffSearch() {
		if (handoffQuery.trim().length < 2) { handoffResults = []; return; }
		handoffSearching = true;
		try {
			handoffResults = (await mailWorkCollaboratorsGet(accountId, handoffQuery.trim(), 8))
				.filter((member) => member.capability === 'comment');
		} catch { handoffResults = []; }
		finally { handoffSearching = false; }
	}

	async function runMentionSearch() {
		if (mentionQuery.trim().length < 2) { mentionResults = []; return; }
		mentionSearching = true;
		try {
			mentionResults = await mailWorkCollaboratorsGet(accountId, mentionQuery.trim(), 8);
		} catch { mentionResults = []; }
		finally { mentionSearching = false; }
	}

	function toggleMention(member: MailWorkCollaborator) {
		mentionTargets = mentionTargets.some((target) => target.id === member.id)
			? mentionTargets.filter((target) => target.id !== member.id)
			: [...mentionTargets, member];
	}

	function beginEdit(item: MailActivityItem) {
		if (item.kind !== 'comment' || item.tombstoned || !item.body) return;
		editingCommentId = item.id;
		commentBody = item.body;
		retainedMentionIds = (item.mentions ?? []).map((mention) => mention.userId);
		mentionTargets = [];
		mentionQuery = '';
		mentionResults = [];
	}

	function cancelEdit() {
		editingCommentId = null;
		retainedMentionIds = [];
		commentBody = '';
	}

	async function handoff() {
		if (!handoffTarget || !commentBody.trim() || pending || !work) return;
		pending = true; error = '';
		try {
			await mailCommentSet({ accountId, threadId, expectedGeneration: work.generation,
				body: commentBody.trim(), handoffUserId: String(handoffTarget.id) });
			commentBody = ''; handoffTarget = null; handoffQuery = ''; handoffResults = [];
			await load(); onChanged?.();
		} catch { await load(true); error = t('inbox.work.conflict'); }
		finally { pending = false; }
	}

	async function enqueueAction(actionKind: 'task' | 'chat' | 'drive') {
		if (pending || !work) return;
		const targetId = actionKind === 'chat' ? chatTargetId : actionKind === 'drive' ? driveTargetId : undefined;
		if (actionKind !== 'task' && !targetId) return;
		pending = true; error = ''; actionQueued = '';
		try {
			await mailWorkAction({ accountId, threadId, expectedGeneration: work.generation, actionKind,
				...(targetId ? { targetId } : {}) });
			actionQueued = t(`inbox.work.${actionKind}_queued`);
			await load(); onChanged?.();
		} catch { await load(true); error = t('inbox.work.conflict'); }
		finally { pending = false; }
	}

	async function load(background = false) {
		if (!background) loading = true;
		error = '';
		try {
			const projection = await mailWorkGet(accountId, threadId);
			work = projection.list[0] ?? null;
			dueLocal = work?.dueAt ? work.dueAt.slice(0, 16) : '';
			if (commentsEnabled) activity = await mailCommentGet(accountId, threadId);
			if (!background && notificationsEnabled && canCollaborate) {
				preferences = await mailWorkNotificationPreferencesGet(accountId);
			}
			if (!background && analyticsEnabled) {
				const to = new Date();
				const from = new Date(to); from.setUTCDate(from.getUTCDate() - 29);
				metrics = await mailWorkMetricsGet(accountId, from.toISOString().slice(0, 10), to.toISOString().slice(0, 10));
			}
			if (!background) {
				policy = await mailWorkPolicyGet(accountId);
				policyTimezone = policy.policy.timezone;
				policyWeekdayMask = policy.policy.weekdayMask;
				policyStart = policy.policy.workdayStart.slice(0, 5);
				policyEnd = policy.policy.workdayEnd.slice(0, 5);
				policyHolidays = policy.policy.holidays.join(', ');
				policySlaMinutes = policy.policy.slaMinutes;
			}
		} catch { if (!background) error = t('inbox.work.error'); }
		finally { if (!background) loading = false; }
	}

	function togglePolicyWeekday(bit: number) {
		const next = policyWeekdayMask ^ bit;
		if (next > 0) policyWeekdayMask = next;
	}

	async function savePolicy() {
		if (!policy?.canManage || pending) return;
		const holidays = Array.from(new Set(policyHolidays.split(',').map((value) => value.trim()).filter(Boolean)));
		pending = true; error = '';
		try {
			policy = await mailWorkPolicySet({ accountId,
				expectedGeneration: policy.policy.generation ?? '0', timezone: policyTimezone.trim(),
				weekdayMask: policyWeekdayMask, workdayStart: policyStart, workdayEnd: policyEnd,
				holidays, slaMinutes: policySlaMinutes });
			await load(); onChanged?.();
		} catch { error = t('inbox.work.policy_error'); }
		finally { pending = false; }
	}

	async function setPreference(preference: MailWorkNotificationPreference, delivery: MailWorkNotificationDelivery) {
		if (pending || !canCollaborate) return;
		pending = true; error = '';
		try {
			await mailWorkNotificationPreferenceSet({
				accountId, category: preference.category, delivery,
				timezone: Intl.DateTimeFormat().resolvedOptions().timeZone || preference.timezone,
				digestHour: preference.digestHour, expectedGeneration: preference.generation,
			});
			preferences = await mailWorkNotificationPreferencesGet(accountId);
		} catch { error = t('inbox.work.conflict'); }
		finally { pending = false; }
	}

	async function addComment() {
		const body = commentBody.trim();
		if (!body || pending || !canCollaborate) return;
		pending = true; error = '';
		try {
			const mentionUserIds = Array.from(new Set([
				...retainedMentionIds,
				...mentionTargets.map((member) => String(member.id)),
			]));
			await mailCommentSet({ accountId, threadId, expectedGeneration: work?.generation ?? '0', body,
				...(mentionUserIds.length ? { mentionUserIds } : {}),
				...(editingCommentId ? { replacesCommentId: editingCommentId } : {}) });
			commentBody = ''; editingCommentId = null; retainedMentionIds = [];
			mentionTargets = []; mentionQuery = ''; mentionResults = [];
			await load(); onChanged?.();
		} catch { await load(true); error = t('inbox.work.conflict'); }
		finally { pending = false; }
	}

	async function mutate(action: 'claim' | 'status' | 'due', status?: MailWorkStatus) {
		if (pending || !canCollaborate) return;
		pending = true; error = '';
		try {
			await mailWorkSet({
				accountId, threadId, action,
				expectedGeneration: work?.generation ?? '0',
				...(status ? { status } : {}),
				...(action === 'due' ? { dueAt: dueLocal ? new Date(dueLocal).toISOString() : null } : {}),
				reason: action === 'claim' ? 'Claimed from reading rail' : 'Updated from reading rail',
			});
			await load(); onChanged?.();
		} catch { await load(true); error = t('inbox.work.conflict'); }
		finally { pending = false; }
	}
</script>

<aside class="sj-mail-work" aria-label={t('inbox.work.title')}>
	<header>
		<div><strong>{t('inbox.work.title')}</strong><span>{threadId}</span></div>
		<button type="button" onclick={onClose} aria-label={t('common.close')}>×</button>
	</header>
	{#if loading}
		<p>{t('common.loading')}</p>
	{:else}
		<div class="status" aria-live="polite">
			<span>{t('inbox.work.status')}</span>
			<strong>{work ? t(`inbox.work.${work.status}`) : t('inbox.work.unassigned')}</strong>
		</div>
		{#if !canCollaborate}
			<p>{t('inbox.work.view_only')}</p>
		{:else if !work || work.status === 'unassigned'}
			<Button size="sm" variant="primary" disabled={pending} onclick={() => mutate('claim')}>{t('inbox.work.claim')}</Button>
		{:else}
			<div class="actions">
				<Button size="sm" variant="secondary" disabled={pending} onclick={() => mutate('status', 'owned')}>{t('inbox.work.owned')}</Button>
				<Button size="sm" variant="secondary" disabled={pending} onclick={() => mutate('status', 'waiting')}>{t('inbox.work.waiting')}</Button>
				<Button size="sm" variant="primary" disabled={pending} onclick={() => mutate('status', 'done')}>{t('inbox.work.done')}</Button>
			</div>
			<label>{t('inbox.work.due')}<input type="datetime-local" bind:value={dueLocal} disabled={pending} /></label>
			<Button size="sm" variant="ghost" disabled={pending} onclick={() => mutate('due')}>{t('common.save')}</Button>
		{/if}
		{#if commentsEnabled}
			<section class="activity" aria-label={t('inbox.work.activity')}>
				<h3>{t('inbox.work.activity')}</h3>
				{#if activity.length === 0}<p>{t('inbox.work.no_comments')}</p>{/if}
				{#each activity as item (item.id)}
					<div class="activity-item">
						<div class="activity-head">
							<strong>{item.kind === 'comment' ? item.authorDisplay : item.actorDisplay}</strong>
							{#if item.kind === 'comment' && item.authorUserId === String($user?.userId ?? '') && !item.tombstoned}
								<button type="button" onclick={() => beginEdit(item)}>{t('inbox.work.edit_comment')}</button>
							{/if}
						</div>
						<span>{item.kind === 'comment' ? (item.body ?? t('inbox.work.edited')) : item.eventType}</span>
						{#if item.kind === 'comment' && item.edited && !item.tombstoned}<small>{t('inbox.work.revised')}</small>{/if}
						{#if item.kind === 'comment' && (item.mentions?.length ?? 0) > 0}<small>{t('inbox.work.mention_count', { count: String(item.mentions?.length ?? 0) })}</small>{/if}
					</div>
				{/each}
				{#if canCollaborate}
					<label>{editingCommentId ? t('inbox.work.edit_comment') : t('inbox.work.private_comment')}<textarea maxlength="8192" rows="3" bind:value={commentBody} disabled={pending}></textarea></label>
					<label>{t('inbox.work.mention_people')}
						<input type="search" bind:value={mentionQuery} disabled={pending}
							placeholder={t('inbox.work.mention_search')} oninput={() => void runMentionSearch()} />
					</label>
					{#if mentionSearching}<p>{t('common.loading')}</p>{/if}
					{#each mentionResults as member (member.id)}
						<button class:selected={mentionTargets.some((target) => target.id === member.id)} type="button" aria-pressed={mentionTargets.some((target) => target.id === member.id)} onclick={() => toggleMention(member)}>
							{member.displayName || member.email} <span>{member.email}{member.capability === 'view_only' ? ` · ${t('inbox.work.mention_view_only')}` : ''}</span>
						</button>
					{/each}
					{#if retainedMentionIds.length > 0}<p>{t('inbox.work.mentions_retained', { count: String(retainedMentionIds.length) })}</p>{/if}
					<div class="comment-actions">
						<Button size="sm" variant="primary" disabled={pending || !commentBody.trim()} onclick={addComment}>{editingCommentId ? t('common.save') : t('inbox.work.add_comment')}</Button>
						{#if editingCommentId}<Button size="sm" variant="ghost" disabled={pending} onclick={cancelEdit}>{t('common.cancel')}</Button>{/if}
					</div>
					{#if work}
						<label>{t('inbox.work.handoff_to')}
							<input type="search" bind:value={handoffQuery} disabled={pending}
								placeholder={t('inbox.work.handoff_search')} oninput={() => void runHandoffSearch()} />
						</label>
						{#if handoffSearching}<p>{t('common.loading')}</p>{/if}
						{#each handoffResults as member (member.id)}
							<button class:selected={handoffTarget?.id === member.id} type="button" onclick={() => (handoffTarget = member)}>
								{member.displayName || member.email} <span>{member.email}</span>
							</button>
						{/each}
						<Button size="sm" variant="secondary" disabled={pending || !handoffTarget || !commentBody.trim()} onclick={handoff}>
							{t('inbox.work.handoff')}{handoffTarget ? ` · ${handoffTarget.displayName || handoffTarget.email}` : ''}
						</Button>
					{/if}
				{/if}
			</section>
		{/if}
		{#if integrationsEnabled && canCollaborate && work}
			<section class="integrations" aria-label={t('inbox.work.integrations')}>
				<h3>{t('inbox.work.integrations')}</h3>
				<p>{t('inbox.work.integrations_safe')}</p>
				<Button size="sm" variant="secondary" disabled={pending} onclick={() => enqueueAction('task')}>{t('inbox.work.create_task')}</Button>
				<label>{t('inbox.work.chat_target')}
					<select bind:value={chatTargetId} disabled={pending}>
						<option value="">{t('inbox.work.choose_chat')}</option>
						{#each conversations as conversation (conversation.channelId)}
							<option value={String(conversation.channelId)}>{conversation.name || `#${conversation.channelId}`}</option>
						{/each}
					</select>
				</label>
				<Button size="sm" variant="secondary" disabled={pending || !chatTargetId} onclick={() => enqueueAction('chat')}>{t('inbox.work.move_chat')}</Button>
				<label>{t('inbox.work.drive_target')}
					<select bind:value={driveTargetId} disabled={pending}>
						<option value="">{t('inbox.work.choose_drive')}</option>
						{#each driveNodes as node (node.id)}
							<option value={String(node.id)}>{node.spaceName} / {node.name}</option>
						{/each}
					</select>
				</label>
				<Button size="sm" variant="secondary" disabled={pending || !driveTargetId} onclick={() => enqueueAction('drive')}>{t('inbox.work.attach_drive')}</Button>
				{#if actionQueued}<p role="status">{actionQueued}</p>{/if}
			</section>
		{/if}
		{#if notificationsEnabled && canCollaborate && preferences.length > 0}
			<section class="preferences" aria-label={t('inbox.work.notifications')}>
				<h3>{t('inbox.work.notifications')}</h3>
				<p>{t('inbox.work.notification_why')}</p>
				{#each preferences as preference (preference.category)}
					<label>{t(`inbox.work.notify_${preference.category}`)}
						<select value={preference.delivery} disabled={pending}
							onchange={(event) => setPreference(preference, event.currentTarget.value as MailWorkNotificationDelivery)}>
							<option value="immediate">{t('inbox.work.immediate')}</option>
							<option value="digest">{t('inbox.work.digest')}</option>
							<option value="off">{t('inbox.work.off')}</option>
						</select>
					</label>
				{/each}
			</section>
		{/if}
		{#if policy}
			<section class="policy" aria-label={t('inbox.work.policy')}>
				<h3>{t('inbox.work.policy')}</h3>
				<p>{t('inbox.work.policy_summary', { timezone: policy.policy.timezone, minutes: String(policy.policy.slaMinutes) })}</p>
				{#if policy.canManage}
					<label>{t('inbox.work.policy_timezone')}<input maxlength="64" bind:value={policyTimezone} disabled={pending} /></label>
					<fieldset>
						<legend>{t('inbox.work.policy_days')}</legend>
						<div class="weekday-grid">
							{#each weekdays as day (day.bit)}
								<label><input type="checkbox" checked={(policyWeekdayMask & day.bit) !== 0}
									onchange={() => togglePolicyWeekday(day.bit)} disabled={pending} />{t(`inbox.work.day_${day.key}`)}</label>
							{/each}
						</div>
					</fieldset>
					<div class="policy-times">
						<label>{t('inbox.work.policy_start')}<input type="time" bind:value={policyStart} disabled={pending} /></label>
						<label>{t('inbox.work.policy_end')}<input type="time" bind:value={policyEnd} disabled={pending} /></label>
					</div>
					<label>{t('inbox.work.policy_sla')}<input type="number" min="1" max="525600" bind:value={policySlaMinutes} disabled={pending} /></label>
					<label>{t('inbox.work.policy_holidays')}<input placeholder="2026-01-01, 2026-02-17" bind:value={policyHolidays} disabled={pending} /></label>
					<p>{t('inbox.work.policy_future_only')}</p>
					<Button size="sm" variant="secondary" disabled={pending || !policyTimezone.trim() || policyWeekdayMask < 1 || policyStart >= policyEnd || policySlaMinutes < 1} onclick={savePolicy}>{t('common.save')}</Button>
				{/if}
			</section>
		{/if}
			{#if analyticsEnabled && metrics}
			<section class="metrics" aria-label={t('inbox.work.analytics')}>
				<h3>{t('inbox.work.analytics')}</h3>
					{#if metrics.available}
						<p>{t('inbox.work.analytics_available')} · {metrics.list?.length ?? 0} {t('inbox.work.days')}</p>
						<div class="metric-table" role="table" aria-label={t('inbox.work.analytics')}>
							<div class="metric-row metric-head" role="row">
								<span role="columnheader">{t('inbox.work.metric_day')}</span>
								<span role="columnheader">{t('inbox.work.metric_conversations')}</span>
								<span role="columnheader">{t('inbox.work.metric_response')}</span>
								<span role="columnheader">{t('inbox.work.metric_outcomes')}</span>
							</div>
							{#each [...(metrics.list ?? [])].slice(-7).reverse() as metric (metric.metric_day)}
								<div class="metric-row" role="row">
									<span role="cell">{metric.metric_day}</span>
									<span role="cell">{metric.conversation_count}</span>
									<span role="cell">{metric.first_response_count > 0 ? `${Math.round(Number(metric.first_response_seconds) / metric.first_response_count / 60)}m` : '—'}</span>
									<span role="cell">{metric.completed_count} / {metric.breached_count}</span>
								</div>
							{/each}
						</div>
				{:else}
					<p>{t('inbox.work.analytics_private', { actors: String(metrics.minimumActors ?? 5), conversations: String(metrics.minimumConversations ?? 20) })}</p>
				{/if}
			</section>
		{/if}
	{/if}
	{#if error}<p class="error" role="alert">{error}</p>{/if}
</aside>

<style>
	.sj-mail-work { position:absolute; z-index:var(--z-popover); top:calc(100% + var(--space-1)); right:var(--space-2); width:min(420px,calc(100vw - var(--space-4))); max-height:min(680px,calc(100vh - 96px)); overflow:auto; padding:var(--space-3); border:1px solid var(--border-default); border-radius:var(--radius-md); background:var(--surface-card); box-shadow:var(--shadow-lg); }
	header,.status,.actions { display:flex; align-items:center; gap:var(--space-2); }
	header { justify-content:space-between; margin-bottom:var(--space-3); }
	header div { display:flex; flex-direction:column; min-width:0; }
	header span { overflow:hidden; text-overflow:ellipsis; color:var(--text-secondary); font-size:var(--text-xs); }
	header button { min-width:32px; min-height:32px; border:0; background:transparent; color:var(--text-secondary); cursor:pointer; }
	.status { justify-content:space-between; padding:var(--space-2); border-radius:var(--radius-sm); background:var(--surface-sunken); }
	.actions { flex-wrap:wrap; margin:var(--space-3) 0; }
	label { display:grid; gap:var(--space-1); color:var(--text-secondary); font-size:var(--text-sm); margin:var(--space-2) 0; }
	input { min-height:36px; padding:0 var(--space-2); border:1px solid var(--border-default); border-radius:var(--radius-sm); background:var(--surface-card); color:var(--text-primary); }
	.activity,.preferences,.metrics,.integrations,.policy { display:grid; gap:var(--space-2); margin-top:var(--space-3); padding-top:var(--space-3); border-top:1px solid var(--border-subtle); }
	h3 { margin:0; font-size:var(--text-sm); }
	.activity-item { display:grid; gap:var(--space-1); padding:var(--space-2); border-radius:var(--radius-sm); background:var(--surface-sunken); }
	.activity-item span { white-space:pre-wrap; overflow-wrap:anywhere; }
	.activity-item small { color:var(--text-caption); font-size:var(--text-xs); }
	.activity-head,.comment-actions { display:flex; align-items:center; justify-content:space-between; gap:var(--space-2); }
	.activity-head button { border:0; background:transparent; color:var(--text-accent); cursor:pointer; font:inherit; font-size:var(--text-xs); }
	.activity-head button:focus-visible { outline:none; box-shadow:var(--focus-ring); }
	textarea { resize:vertical; padding:var(--space-2); border:1px solid var(--border-default); border-radius:var(--radius-sm); background:var(--surface-card); color:var(--text-primary); }
	select { min-height:36px; padding:0 var(--space-2); border:1px solid var(--border-default); border-radius:var(--radius-sm); background:var(--surface-card); color:var(--text-primary); }
	fieldset { margin:0; padding:var(--space-2); border:1px solid var(--border-subtle); border-radius:var(--radius-sm); }
	legend { padding:0 var(--space-1); color:var(--text-secondary); font-size:var(--text-sm); }
	.weekday-grid { display:flex; flex-wrap:wrap; gap:var(--space-2); }
	.weekday-grid label { display:flex; align-items:center; gap:var(--space-1); margin:0; }
	.weekday-grid input { min-height:auto; }
	.policy-times { display:grid; grid-template-columns:1fr 1fr; gap:var(--space-2); }
	.activity > button { display:grid; gap:var(--space-1); padding:var(--space-2); text-align:left; border:1px solid var(--border-default); border-radius:var(--radius-sm); background:var(--surface-card); color:var(--text-primary); }
	.activity > button.selected { border-color:var(--border-accent); background:var(--surface-selected); }
	.activity > button span { color:var(--text-secondary); font-size:var(--text-xs); }
	.metric-table { display:grid; border:1px solid var(--border-subtle); border-radius:var(--radius-sm); overflow:hidden; }
	.metric-row { display:grid; grid-template-columns:1.35fr .75fr .8fr .9fr; gap:var(--space-1); padding:var(--space-2); font-size:var(--text-xs); color:var(--text-caption); }
	.metric-row + .metric-row { border-top:1px solid var(--border-subtle); }
	.metric-head { background:var(--surface-sunken); color:var(--text-primary); font-weight:var(--weight-medium); }
	p { color:var(--text-secondary); }
	.error { color:var(--text-danger); }
</style>
