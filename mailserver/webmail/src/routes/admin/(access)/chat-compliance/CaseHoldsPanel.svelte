<svelte:options runes={true} />

<!--
	CaseHoldsPanel — Chat A4b Task 9: the Holds tab. Case picker (D-H: one
	registry, `ediscovery_cases`, reused across mail + chat) + durable
	case/custodian hold CRUD against V127's chat_case_holds. Supersedes the
	per-channel custodian-hold affordance the old (deleted, Task 5)
	POST /admin/chat-holds/custodian route backed — resolved ambiguity 2.

	Holds destroy nothing (spec §8): NO ConfirmDestructive anywhere on this
	surface — release uses a plain confirm Dialog.

	The case list comes from the Task 5 chat-side projection
	(adminListChatEDiscoveryCases → GET /admin/chat-ediscovery/cases), NOT the
	mail console's own /admin/ediscovery/cases (requireMailPerm-gated — would
	403 a chat-compliance-only persona, review F3).

	"Open case" links to the existing mail eDiscovery console
	(/admin/ediscovery) — a per-case URL does not exist yet on that side (only
	its Go route does, GET /admin/ediscovery/cases/{id}, with no matching
	svelte page); linking to the console page is the closest existing target
	and keeps this task chat-side-only, per D-H's "one registry, two
	consoles" posture.
-->
<script lang="ts">
	import { onMount } from 'svelte';
	import { Card, Button, Spinner, Select, Input, Radio, Dialog, showToast } from '$lib/components/ui';
	import { t, formatDateTime } from '$lib/i18n';
	import { parseError } from '$lib/errors';
	import {
		adminListChatEDiscoveryCases,
		adminListChatCaseHolds,
		adminSetChatCaseHold,
		adminReleaseChatCaseHold,
		adminListChatChannels,
		type ChatEDiscoveryCase,
		type ChatCaseHold,
		type ChatChannelRow,
	} from '$lib/admin/client';
	import { channelDisplayName, channelCache } from './channels.svelte';

	interface Props {
		canManage: boolean;
	}
	let { canManage }: Props = $props();

	let error = $state('');

	// ── case picker ──────────────────────────────────────────────────────────
	let cases = $state<ChatEDiscoveryCase[]>([]);
	let casesLoading = $state(false);
	let selectedCaseIdStr = $state('');
	let selectedCaseId = $derived(selectedCaseIdStr ? Number(selectedCaseIdStr) : null);
	let selectedCase = $derived(cases.find((c) => c.id === selectedCaseId) ?? null);

	async function loadCases() {
		casesLoading = true;
		error = '';
		try {
			cases = await adminListChatEDiscoveryCases();
			if (!selectedCaseIdStr) {
				const firstActive = cases.find((c) => c.status === 'active');
				if (firstActive) selectedCaseIdStr = String(firstActive.id);
			}
		} catch (e) {
			error = parseError(e).message;
		} finally {
			casesLoading = false;
		}
	}

	// ── holds list ───────────────────────────────────────────────────────────
	// m4: its own error state, distinct from the cases-load `error` above —
	// a holds-fetch failure must not blank out an already-loaded case picker
	// and new-hold form (the shared var this used to write to did exactly
	// that: it also gated the whole panel below).
	let holds = $state<ChatCaseHold[]>([]);
	let holdsLoading = $state(false);
	let holdsError = $state('');

	async function loadHolds() {
		if (selectedCaseId == null) {
			holds = [];
			return;
		}
		// Stale-response guard: a holds list resolving after the operator
		// switched cases must not render Case A's holds under Case B. The
		// list is also CLEARED up front (final-pass F2): without it, a stale
		// request's finally clearing the spinner while the fresh one is still
		// in flight would transiently show Case A's rows under Case B.
		const requestCaseId = selectedCaseId;
		holds = [];
		holdsLoading = true;
		holdsError = '';
		try {
			const res = await adminListChatCaseHolds(requestCaseId);
			if (selectedCaseId !== requestCaseId) return;
			holds = res;
		} catch (e) {
			if (selectedCaseId === requestCaseId) holdsError = parseError(e).message;
		} finally {
			if (selectedCaseId === requestCaseId) holdsLoading = false;
		}
	}

	$effect(() => {
		void selectedCaseId;
		void loadHolds();
	});

	onMount(() => {
		void loadCases();
		// I1: prefetch so #ids already resolve to names on first paint instead
		// of only after the operator opens the channel-scope search below.
		void adminListChatChannels()
			.then((rows) => channelCache.remember(rows))
			.catch(() => {});
	});

	// ── new-hold form ────────────────────────────────────────────────────────
	type Scope = 'custodian' | 'channel';
	let scope = $state<Scope>('custodian');
	let custodianUserIdStr = $state('');
	let channelQuery = $state('');
	let channelResults = $state<ChatChannelRow[]>([]);
	let channelSearching = $state(false);
	let selectedChannel = $state<ChatChannelRow | null>(null);
	let reason = $state('');
	let formBusy = $state(false);
	let formError = $state('');

	let channelSearched = $state(false);

	function resetForm() {
		custodianUserIdStr = '';
		channelQuery = '';
		channelResults = [];
		channelSearched = false;
		selectedChannel = null;
		reason = '';
		formError = '';
	}

	// I3: switching scope leaves a picked channel from the OTHER scope
	// dangling in state (canSubmit would still read it if the operator flips
	// back) — reset the channel-search half of the form on every scope flip.
	function setScope(s: Scope) {
		scope = s;
		selectedChannel = null;
		channelResults = [];
		channelSearched = false;
	}

	async function searchChannels() {
		channelSearching = true;
		formError = '';
		// m3: a stale pick from a PRIOR search must not silently ride a new
		// search's results — force an explicit re-pick.
		selectedChannel = null;
		channelResults = [];
		try {
			const rows = await adminListChatChannels({ q: channelQuery || undefined });
			channelResults = rows;
			channelCache.remember(rows);
		} catch (e) {
			formError = parseError(e).message;
		} finally {
			channelSearching = false;
			channelSearched = true;
		}
	}

	function pickChannel(c: ChatChannelRow) {
		selectedChannel = c;
	}

	// I1: echo the resolved participant name for a typed custodian user id —
	// the numeric-id input still works standalone (no directory-lookup route
	// exists, same posture as Drive's MembersSheet), this is best-effort only.
	let custodianResolvedName = $derived.by(() => {
		const id = Number(custodianUserIdStr);
		if (!custodianUserIdStr.trim() || !Number.isFinite(id)) return null;
		const p = channelCache.resolveParticipant(id);
		return p ? p.displayName || p.email : null;
	});

	let canSubmit = $derived.by(() => {
		if (selectedCaseId == null || reason.trim() === '') return false;
		if (scope === 'custodian') {
			return custodianUserIdStr.trim() !== '' && Number.isFinite(Number(custodianUserIdStr));
		}
		return selectedChannel != null;
	});

	async function submitHold() {
		if (selectedCaseId == null || !canSubmit) return;
		formBusy = true;
		formError = '';
		try {
			await adminSetChatCaseHold({
				caseId: selectedCaseId,
				custodianUserId: scope === 'custodian' ? Number(custodianUserIdStr) : undefined,
				channelId: scope === 'channel' ? (selectedChannel?.id ?? undefined) : undefined,
				reason: reason.trim(),
			});
			showToast(t('admin.chatCompliance.holds.holdPlaced'));
			resetForm();
			void loadHolds();
		} catch (e) {
			formError = parseError(e).message;
		} finally {
			formBusy = false;
		}
	}

	// ── release (plain confirm Dialog — holds destroy nothing, no
	// ConfirmDestructive anywhere on this surface, spec §8) ──────────────────
	let releaseTarget = $state<ChatCaseHold | null>(null);
	let releaseReason = $state('');
	let releaseBusy = $state(false);
	let releaseError = $state('');

	function openRelease(h: ChatCaseHold) {
		releaseTarget = h;
		releaseReason = '';
		releaseError = '';
	}

	async function confirmRelease() {
		if (!releaseTarget) return;
		releaseBusy = true;
		releaseError = '';
		try {
			await adminReleaseChatCaseHold(releaseTarget.id, releaseReason.trim());
			releaseTarget = null;
			showToast(t('admin.chatCompliance.holds.holdReleased'));
			void loadHolds();
		} catch (e) {
			releaseError = parseError(e).message;
		} finally {
			releaseBusy = false;
		}
	}
</script>

<div class="chp">
	{#if error}
		<Card>
			<p class="chp-error" role="alert">{error}</p>
			<Button variant="ghost" size="sm" onclick={loadCases}>{t('common.retry')}</Button>
		</Card>
	{:else if casesLoading}
		<div class="chp-loading"><Spinner /></div>
	{:else if cases.length === 0}
		<Card><p class="chp-empty">{t('admin.chatCompliance.holds.noCases')}</p></Card>
	{:else}
		<Card>
			<div class="chp-row">
				<Select label={t('admin.chatCompliance.holds.case')} bind:value={selectedCaseIdStr}>
					<option value="" disabled>{t('admin.chatCompliance.holds.pickCase')}</option>
					{#each cases as c (c.id)}
						<option value={String(c.id)} disabled={c.status !== 'active'}>
							{c.name}{c.status !== 'active' ? ` (${t('admin.chatCompliance.holds.caseStatus.closed')})` : ''}
						</option>
					{/each}
				</Select>
				{#if selectedCase}
					<a class="chp-case-link" href="/admin/ediscovery">{t('admin.chatCompliance.holds.openCasePage')}</a>
				{/if}
			</div>
		</Card>

		{#if cases.every((c) => c.status !== 'active')}
			<Card><p class="chp-hint" role="note">{t('admin.chatCompliance.holds.allCasesClosed')}</p></Card>
		{/if}

		{#if canManage && selectedCaseId != null}
			<Card>
				<h3 class="chp-section__title">{t('admin.chatCompliance.holds.newHold')}</h3>
				<form
					onsubmit={(e) => {
						e.preventDefault();
						void submitHold();
					}}
				>
					<fieldset class="chp-fieldset">
						<legend class="chp-legend">{t('admin.chatCompliance.holds.scopeLabel')}</legend>
						<div class="chp-row">
							<Radio
								name="chp-scope"
								value="custodian"
								checked={scope === 'custodian'}
								label={t('admin.chatCompliance.holds.scope.custodian')}
								onchange={() => setScope('custodian')}
							/>
							<Radio
								name="chp-scope"
								value="channel"
								checked={scope === 'channel'}
								label={t('admin.chatCompliance.holds.scope.channel')}
								onchange={() => setScope('channel')}
							/>
						</div>
						<p class="chp-hint">{t(`admin.chatCompliance.holds.scopeHint.${scope}`)}</p>
					</fieldset>

					{#if scope === 'custodian'}
						<div class="chp-row">
							<Input
								type="number"
								label={t('admin.chatCompliance.holds.custodianUserId_label')}
								bind:value={custodianUserIdStr}
								disabled={formBusy}
							/>
						</div>
						{#if custodianResolvedName}
							<p class="chp-hint">
								{t('admin.chatCompliance.holds.selectedChannel', { name: custodianResolvedName })}
							</p>
						{/if}
					{:else}
						<div class="chp-row">
							<Input
								label={t('admin.chatCompliance.channels.search_placeholder')}
								bind:value={channelQuery}
								disabled={formBusy}
								onkeydown={(e: KeyboardEvent) => {
									if (e.key === 'Enter') {
										e.preventDefault();
										void searchChannels();
									}
								}}
							/>
							<Button type="button" variant="secondary" size="sm" onclick={searchChannels} disabled={channelSearching}>
								{t('admin.chatCompliance.channels.search_button')}
							</Button>
						</div>
						{#if channelResults.length > 0}
							<ul class="chp-channel-results">
								{#each channelResults as c (c.id)}
									<li>
										<button type="button" class="chp-channel-pick" onclick={() => pickChannel(c)}>
											{channelDisplayName(c) || `#${c.id}`}
										</button>
									</li>
								{/each}
							</ul>
						{:else if channelSearched && !channelSearching}
							<p class="chp-hint">{t('admin.chatCompliance.channels.empty')}</p>
						{/if}
						{#if selectedChannel}
							<p class="chp-hint">
								{t('admin.chatCompliance.holds.selectedChannel', {
									name: channelDisplayName(selectedChannel) || `#${selectedChannel.id}`,
								})}
							</p>
						{/if}
					{/if}

					<div class="chp-row">
						<Input label={t('admin.chatCompliance.holds.reason')} bind:value={reason} disabled={formBusy} />
						<Button type="submit" variant="primary" size="sm" disabled={formBusy || !canSubmit}>
							{t('admin.chatCompliance.sheet.holdSet')}
						</Button>
					</div>
					{#if formError}<p class="chp-error" role="alert">{formError}</p>{/if}
				</form>
			</Card>
		{/if}

		{#if holdsError}
			<Card>
				<p class="chp-error" role="alert">{holdsError}</p>
				<Button variant="ghost" size="sm" onclick={loadHolds}>{t('common.retry')}</Button>
			</Card>
		{:else if holdsLoading}
			<div class="chp-loading"><Spinner /></div>
		{:else if holds.length === 0}
			<Card><p class="chp-empty">{t('admin.chatCompliance.holds.empty')}</p></Card>
		{:else}
			<Card flush>
				<div class="chp-scroll">
					<table class="chp-table">
						<thead>
							<tr>
								<th>{t('admin.chatCompliance.holds.col_scope')}</th>
								<th>{t('admin.chatCompliance.holds.reason')}</th>
								<th>{t('admin.chatCompliance.holds.channelsCovered')}</th>
								<th>{t('admin.chatCompliance.holds.col_created')}</th>
								<th>{t('admin.chatCompliance.holds.releasedAt')}</th>
								{#if canManage}<th></th>{/if}
							</tr>
						</thead>
						<tbody>
							{#each holds as h (h.id)}
								<tr>
									<td>
										{#if h.custodianUserId != null}
											{t('admin.chatCompliance.holds.scope.custodian')}: {channelCache.participantLabel(h.custodianUserId)}
										{:else if h.channelId != null}
											{t('admin.chatCompliance.holds.scope.channel')}: {channelCache.label(h.channelId)}
										{/if}
									</td>
									<td>{h.reason}</td>
									<td>{h.channels}</td>
									<td>{formatDateTime(h.createdAt)}</td>
									<td>{h.releasedAt ? formatDateTime(h.releasedAt) : '—'}</td>
									{#if canManage}
										<td>
											{#if !h.releasedAt}
												<Button variant="ghost" size="sm" onclick={() => openRelease(h)}>
													{t('admin.chatCompliance.holds.release')}
												</Button>
											{/if}
										</td>
									{/if}
								</tr>
							{/each}
						</tbody>
					</table>
				</div>
			</Card>
		{/if}
	{/if}
</div>

<Dialog
	open={releaseTarget != null}
	title={t('admin.chatCompliance.sheet.holdReleaseConfirmTitle')}
	onClose={releaseBusy ? undefined : () => (releaseTarget = null)}
>
	{#snippet children()}
		<p>{t('admin.chatCompliance.holds.releasePrompt')}</p>
		<Input label={t('admin.chatCompliance.holds.reasonOptional')} bind:value={releaseReason} disabled={releaseBusy} />
		{#if releaseError}<p class="chp-error" role="alert">{releaseError}</p>{/if}
	{/snippet}
	{#snippet footer()}
		<Button variant="ghost" size="sm" disabled={releaseBusy} onclick={() => (releaseTarget = null)}>
			{t('admin.chatCompliance.policy.cancel')}
		</Button>
		<Button variant="primary" size="sm" disabled={releaseBusy} onclick={confirmRelease}>
			{t('admin.chatCompliance.holds.release')}
		</Button>
	{/snippet}
</Dialog>

<style>
	.chp {
		display: flex;
		flex-direction: column;
		gap: var(--space-4);
	}
	.chp-loading {
		display: flex;
		align-items: center;
		gap: var(--space-2);
		padding: var(--space-6);
		color: var(--text-secondary);
	}
	.chp-empty,
	.chp-hint {
		font-size: var(--text-sm);
		color: var(--text-tertiary);
	}
	.chp-error {
		font-size: var(--text-sm);
		color: var(--text-danger);
	}
	.chp-row {
		display: flex;
		align-items: flex-end;
		gap: var(--space-3);
		flex-wrap: wrap;
	}
	.chp-section__title {
		font-size: var(--text-sm);
		font-weight: var(--weight-semibold);
		color: var(--text-primary);
		margin: 0 0 var(--space-2);
	}
	.chp-case-link {
		font-size: var(--text-sm);
		color: var(--link);
	}
	.chp-fieldset {
		border: none;
		margin: 0 0 var(--space-3);
		padding: 0;
		display: flex;
		flex-direction: column;
		gap: var(--space-2);
	}
	.chp-legend {
		font-size: var(--text-sm);
		font-weight: var(--weight-medium);
		color: var(--text-primary);
		padding: 0;
	}
	.chp-channel-results {
		margin: 0;
		padding: 0;
		list-style: none;
		display: flex;
		flex-direction: column;
		gap: var(--space-1);
		/* ~140px via tokens (no dedicated max-height scale exists) */
		max-height: calc(var(--space-16) * 2 + var(--space-4));
		overflow-y: auto;
	}
	.chp-channel-pick {
		border: none;
		background: transparent;
		text-align: left;
		padding: var(--space-1) var(--space-2);
		border-radius: var(--radius-sm);
		cursor: pointer;
		color: var(--text-primary);
		font-size: var(--text-sm);
	}
	.chp-channel-pick:hover {
		background: var(--surface-hover);
	}
	.chp-scroll {
		overflow-x: auto;
	}
	.chp-table {
		width: 100%;
		border-collapse: collapse;
		font-size: var(--text-sm);
	}
	.chp-table th {
		text-align: left;
		padding: var(--space-2) var(--space-3);
		font-weight: var(--weight-medium);
		color: var(--text-secondary);
		border-bottom: 1px solid var(--border-default);
		white-space: nowrap;
	}
	.chp-table td {
		padding: var(--space-3);
		border-bottom: 1px solid var(--border-subtle);
		vertical-align: middle;
		white-space: nowrap;
	}
</style>
