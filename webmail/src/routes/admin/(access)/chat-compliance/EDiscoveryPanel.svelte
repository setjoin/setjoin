<svelte:options runes={true} />

<!--
	EDiscoveryPanel — Chat A4b Task 10: the eDiscovery tab (search → reader →
	export). Rendered by +page.svelte ONLY for chat.ediscovery holders (D-A's
	SoD split: chat.compliance_manage does NOT satisfy it) — every route this
	panel calls re-checks the same permission server-side regardless.

	Search hits / the reader window / are the reducer JSON verbatim
	(chat_ediscovery_search / chat_ediscovery_read) — client.ts does zero
	result-shaping, and neither does this component.

	The record-floor banner (reader) and the export disclaimer render the
	SAME L8 sentence: admin.chatCompliance.ediscovery.recordFloorDisclaimer is
	exportDisclaimers[2] from admin_chat_ediscovery_export.go,
	character-for-character (review F7 — the two surfaces previously drifted).

	Export destroys nothing (spec §8): the export button is a cookie-authed
	`window.open` on the same-origin download URL (the ChannelComplianceSheet
	downloadEvidence / chatChannelAuditCsvUrl precedent, m2) — NO
	ConfirmDestructive anywhere on this surface.
-->
<script lang="ts">
	import { onMount } from 'svelte';
	import { Card, Button, Spinner, Select, Input, Badge, Checkbox } from '$lib/components/ui';
	import { t, formatDateTime } from '$lib/i18n';
	import { parseError } from '$lib/errors';
	import {
		adminListChatEDiscoveryCases,
		adminChatEDiscoverySearch,
		adminChatEDiscoveryMessages,
		adminChatEDiscoveryExportUrl,
		adminListChatChannels,
		type ChatEDiscoveryCase,
		type ChatEDiscoveryHit,
		type ChatEDiscoveryScheduledHit,
		type ChatEDiscoveryReadResult,
	} from '$lib/admin/client';
	import { channelCache } from './channels.svelte';

	// m1: mirrors the server defaults (admin_chat_ediscovery.go) — the client
	// never sends `limit`, so a page shorter than these means there is no
	// next page. Keep in sync if the server default ever changes.
	const SEARCH_PAGE_LIMIT = 50;
	const READ_PAGE_LIMIT = 100;

	let error = $state('');

	// ── case picker (the CaseHoldsPanel genre — a separate fetch, not shared
	// state: the two tabs are independently-mounted panels) ─────────────────
	let cases = $state<ChatEDiscoveryCase[]>([]);
	let casesLoading = $state(false);
	let selectedCaseIdStr = $state('');
	let selectedCaseId = $derived(selectedCaseIdStr ? Number(selectedCaseIdStr) : null);

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
	onMount(() => {
		void loadCases();
		// I1: prefetch so #ids in a first search's results already resolve to
		// names instead of only after the operator opens a hold-form search.
		void adminListChatChannels()
			.then((rows) => channelCache.remember(rows))
			.catch(() => {});
	});

	// ── search form ──────────────────────────────────────────────────────────
	let terms = $state('');
	let channelIdsStr = $state('');
	let authorIdStr = $state('');
	let dateFrom = $state('');
	let dateTo = $state('');
	let searchBusy = $state(false);
	let searchError = $state('');
	let searched = $state(false);

	let hits = $state<ChatEDiscoveryHit[]>([]);
	let scheduledHits = $state<ChatEDiscoveryScheduledHit[]>([]);
	let hitsHasMore = $state(false);

	function parseChannelIds(): number[] | undefined {
		const ids = channelIdsStr
			.split(',')
			.map((s) => Number(s.trim()))
			.filter((n) => Number.isFinite(n) && n > 0);
		return ids.length > 0 ? ids : undefined;
	}

	let canSearch = $derived(selectedCaseId != null && terms.trim() !== '');

	async function runSearch(beforeId?: number) {
		if (selectedCaseId == null || terms.trim() === '') return;
		// A search resolving after the operator switched cases must not land
		// stale Case-A hits under Case B (the C1 contamination class, async
		// variant): capture the case the request was issued for and drop the
		// response if the selection moved on.
		const requestCaseId = selectedCaseId;
		searchBusy = true;
		searchError = '';
		try {
			const res = await adminChatEDiscoverySearch({
				caseId: requestCaseId,
				terms: terms.trim(),
				channelIds: parseChannelIds(),
				authorId: authorIdStr.trim() ? Number(authorIdStr.trim()) : undefined,
				dateFrom: dateFrom || undefined,
				dateTo: dateTo || undefined,
				beforeId,
			});
			if (selectedCaseId !== requestCaseId) return;
			if (beforeId == null) {
				hits = res.hits;
				scheduledHits = res.scheduledHits;
			} else {
				hits = [...hits, ...res.hits];
			}
			hitsHasMore = res.hits.length >= SEARCH_PAGE_LIMIT;
			searched = true;
		} catch (e) {
			if (selectedCaseId === requestCaseId) searchError = parseError(e).message;
		} finally {
			searchBusy = false;
		}
	}

	function loadMoreHits() {
		const last = hits[hits.length - 1];
		if (last) void runSearch(last.messageId);
	}

	// ── reader panel ─────────────────────────────────────────────────────────
	let readerChannelId = $state<number | null>(null);
	let reader = $state<ChatEDiscoveryReadResult | null>(null);
	let readerLoading = $state(false);
	let readerError = $state('');
	let readerHasMore = $state(false);
	// C2: which message (if any) the reader was opened to land ON — set only
	// on a fresh (non-paged) open, so "load more" pages don't clear it.
	let anchorMessageId = $state<number | null>(null);

	// Whether a call CONTINUES the current window (append) or OPENS a fresh
	// one (replace) is an explicit flag, never inferred from beforeId — an
	// anchored hit-open also carries a beforeId, and inferring "append" from
	// it merged windows across channels / duplicated message keys on repeated
	// hit clicks (final-pass F1).
	async function openReader(channelId: number, opts: { beforeId?: number; append?: boolean } = {}) {
		if (selectedCaseId == null) return;
		const { beforeId, append = false } = opts;
		// Same stale-response guard as runSearch: a window resolving after a
		// case switch (or after the operator opened a different channel) must
		// not overwrite the fresh state.
		const requestCaseId = selectedCaseId;
		// I9 + F1: every non-append open REPLACES the window — clear
		// immediately so the old channel's tail never shows under the new
		// title while the fresh page is in flight.
		if (!append) reader = null;
		// A "load more" continuation must keep whatever anchor
		// openReaderOnHit already set; a fresh non-anchored open (no
		// beforeId) has no specific message to highlight.
		if (!append && beforeId == null) anchorMessageId = null;
		readerChannelId = channelId;
		readerLoading = true;
		readerError = '';
		try {
			const res = await adminChatEDiscoveryMessages(channelId, requestCaseId, { beforeId });
			if (selectedCaseId !== requestCaseId || readerChannelId !== channelId) return;
			reader = append ? { ...res, messages: [...(reader?.messages ?? []), ...res.messages] } : res;
			readerHasMore = res.messages.length >= READ_PAGE_LIMIT;
		} catch (e) {
			if (selectedCaseId === requestCaseId && readerChannelId === channelId)
				readerError = parseError(e).message;
		} finally {
			readerLoading = false;
		}
	}

	// C2: a hit click must land the reader ON that hit, not just open the
	// channel's latest window — page backwards from just past the hit and
	// anchor-highlight it once it's in view. Set BEFORE the (async) call.
	// NOT an append: each hit click replaces the window (F1).
	function openReaderOnHit(h: ChatEDiscoveryHit) {
		anchorMessageId = h.messageId;
		void openReader(h.channelId, { beforeId: h.messageId + 1 });
	}

	function readerLoadMore() {
		if (readerChannelId == null || !reader || reader.messages.length === 0) return;
		void openReader(readerChannelId, {
			beforeId: reader.messages[reader.messages.length - 1].messageId,
			append: true,
		});
	}

	let showRecordFloor = $derived(reader != null && (reader.purgeActs.length > 0 || reader.lastPurgedSeq > 0));

	// I8: raw scheduled_actions.status enum values, mapped to copy — an
	// unrecognized value (future status the client hasn't caught up to)
	// falls back to the raw string rather than a leaked translation key.
	const SCHEDULED_STATUSES = ['pending', 'failed', 'canceled', 'sent'] as const;
	function scheduledStatusLabel(status: string): string {
		if ((SCHEDULED_STATUSES as readonly string[]).includes(status)) {
			return t(`admin.chatCompliance.ediscovery.scheduledStatus.${status}`);
		}
		return status;
	}

	// ── export (destroys nothing — no ConfirmDestructive, spec §8) ──────────
	let includeAttachments = $state(false);
	let exportChannelIds = $derived.by(() => {
		const ids = new Set<number>();
		for (const h of hits) ids.add(h.channelId);
		for (const h of scheduledHits) ids.add(h.channelId);
		if (readerChannelId != null) ids.add(readerChannelId);
		return [...ids].sort((a, b) => a - b);
	});
	let excludedChannelIds = $state(new Set<number>());
	function toggleExportChannel(id: number) {
		const next = new Set(excludedChannelIds);
		if (next.has(id)) next.delete(id);
		else next.add(id);
		excludedChannelIds = next;
	}
	let selectedExportChannelIds = $derived(exportChannelIds.filter((id) => !excludedChannelIds.has(id)));
	let exportUrl = $derived(
		selectedCaseId != null && selectedExportChannelIds.length > 0
			? adminChatEDiscoveryExportUrl(selectedCaseId, selectedExportChannelIds, includeAttachments)
			: null
	);

	// C1: switching cases must not let a stale Case-A hit list, reader, or
	// export selection survive into Case B — that's a cross-case export
	// contamination bug, not just a stale display. Mirrors CaseHoldsPanel's
	// case-watch effect.
	$effect(() => {
		void selectedCaseId;
		hits = [];
		scheduledHits = [];
		hitsHasMore = false;
		searched = false;
		reader = null;
		readerChannelId = null;
		readerHasMore = false;
		anchorMessageId = null;
		excludedChannelIds = new Set();
		includeAttachments = false;
	});
</script>

<div class="edp">
	{#if error}
		<Card>
			<p class="edp-error" role="alert">{error}</p>
			<Button variant="ghost" size="sm" onclick={loadCases}>{t('common.retry')}</Button>
		</Card>
	{:else if casesLoading}
		<div class="edp-loading"><Spinner /></div>
	{:else if cases.length === 0}
		<Card><p class="edp-empty">{t('admin.chatCompliance.holds.noCases')}</p></Card>
	{:else}
		<Card>
			<div class="edp-row">
				<Select label={t('admin.chatCompliance.holds.case')} bind:value={selectedCaseIdStr}>
					<option value="" disabled>{t('admin.chatCompliance.holds.pickCase')}</option>
					{#each cases as c (c.id)}
						<option value={String(c.id)} disabled={c.status !== 'active'}>
							{c.name}{c.status !== 'active' ? ` (${t('admin.chatCompliance.holds.caseStatus.closed')})` : ''}
						</option>
					{/each}
				</Select>
			</div>
			<p class="edp-hint">{t('admin.chatCompliance.ediscovery.caseFirstHint')}</p>
		</Card>

		{#if cases.every((c) => c.status !== 'active')}
			<Card><p class="edp-hint" role="note">{t('admin.chatCompliance.holds.allCasesClosed')}</p></Card>
		{/if}

		<Card>
			<h3 class="edp-section__title">{t('admin.chatCompliance.ediscovery.search')}</h3>
			<form
				class="edp-row"
				onsubmit={(e) => {
					e.preventDefault();
					if (canSearch) void runSearch();
				}}
			>
				<Input label={t('admin.chatCompliance.ediscovery.terms')} bind:value={terms} disabled={searchBusy} />
				<Input label={t('admin.chatCompliance.ediscovery.channelIds_label')} bind:value={channelIdsStr} disabled={searchBusy} />
				<Input type="number" label={t('admin.chatCompliance.ediscovery.authorId_label')} bind:value={authorIdStr} disabled={searchBusy} />
				<Input type="date" label={t('admin.chatCompliance.ediscovery.dateFrom_label')} bind:value={dateFrom} disabled={searchBusy} />
				<Input type="date" label={t('admin.chatCompliance.ediscovery.dateTo_label')} bind:value={dateTo} disabled={searchBusy} />
				<Button type="submit" variant="primary" size="sm" disabled={searchBusy || !canSearch}>
					{t('admin.chatCompliance.ediscovery.search')}
				</Button>
			</form>
			{#if searchError}<p class="edp-error" role="alert">{searchError}</p>{/if}
		</Card>

		{#if searchBusy && hits.length === 0 && scheduledHits.length === 0}
			<div class="edp-loading"><Spinner /></div>
		{:else if hits.length > 0 || scheduledHits.length > 0}
			<Card flush>
				<div class="edp-scroll">
					<table class="edp-table">
						<thead>
							<tr>
								<th>{t('admin.chatCompliance.ediscovery.col_excerpt')}</th>
								<th>{t('admin.chatCompliance.ediscovery.col_author')}</th>
								<th>{t('admin.chatCompliance.ediscovery.col_channel')}</th>
								<th>{t('admin.chatCompliance.ediscovery.col_when')}</th>
							</tr>
						</thead>
						<tbody>
							{#each hits as h (h.messageId)}
								<tr
									class="edp-row-clickable"
									role="button"
									tabindex="0"
									onclick={() => openReaderOnHit(h)}
									onkeydown={(e) => {
										if (e.key === 'Enter' || e.key === ' ') {
											e.preventDefault();
											openReaderOnHit(h);
										}
									}}
								>
									<td>
										{h.excerpt}
										{#if h.deleted}<Badge variant="danger" label={t('admin.chatCompliance.ediscovery.deletedBadge')} />{/if}
										{#if h.matchedIn.includes('revision')}<Badge variant="warning" label={t('admin.chatCompliance.ediscovery.revisionBadge')} />{/if}
										{#if h.matchedIn.includes('filename')}<Badge variant="info" label={t('admin.chatCompliance.ediscovery.filenameBadge')} />{/if}
									</td>
									<td>{channelCache.participantLabel(h.authorId)}</td>
									<td>{channelCache.label(h.channelId)}</td>
									<td>{formatDateTime(h.createdAt)}</td>
								</tr>
							{/each}
							{#each scheduledHits as s (s.scheduledActionId)}
								<tr
									class="edp-row-clickable"
									role="button"
									tabindex="0"
									onclick={() => openReader(s.channelId)}
									onkeydown={(e) => {
										if (e.key === 'Enter' || e.key === ' ') {
											e.preventDefault();
											openReader(s.channelId);
										}
									}}
								>
									<td>
										{s.excerpt}
										<Badge
											variant="accent"
											label={t('admin.chatCompliance.ediscovery.scheduledBadge', { status: scheduledStatusLabel(s.status) })}
										/>
									</td>
									<td>{channelCache.participantLabel(s.authorId)}</td>
									<td>{channelCache.label(s.channelId)}</td>
									<td>{formatDateTime(s.fireAt)}</td>
								</tr>
							{/each}
						</tbody>
					</table>
				</div>
				{#if hits.length > 0}
					{#if hitsHasMore}
						<Button variant="ghost" size="sm" disabled={searchBusy} onclick={loadMoreHits}>
							{t('admin.chatCompliance.ediscovery.loadMore')}
						</Button>
					{:else}
						<p class="edp-hint">{t('admin.chatCompliance.ediscovery.endOfResults')}</p>
					{/if}
				{/if}
			</Card>
		{:else if searched}
			<Card><p class="edp-empty">{t('admin.chatCompliance.ediscovery.noHits')}</p></Card>
		{/if}

		{#if readerChannelId != null}
			<Card>
				<h3 class="edp-section__title">
					{t('admin.chatCompliance.ediscovery.reader.windowTitle')} {channelCache.label(readerChannelId)}
				</h3>
				{#if showRecordFloor}
					<div class="edp-record-floor" role="note">
						<p>{t('admin.chatCompliance.ediscovery.recordFloorIntro')}</p>
						<p>{t('admin.chatCompliance.ediscovery.recordFloorDisclaimer')}</p>
					</div>
				{/if}
				{#if readerLoading && !reader}
					<div class="edp-loading"><Spinner /></div>
				{:else if readerError}
					<p class="edp-error" role="alert">{readerError}</p>
				{:else if reader}
					<ul class="edp-messages">
						{#each reader.messages as m (m.messageId)}
							<li
								class="edp-message"
								class:edp-message--deleted={m.deletedAt != null}
								class:edp-message--hit={m.messageId === anchorMessageId}
							>
								<p class="edp-message__meta">
									#{m.messageId} · {channelCache.participantLabel(m.authorId)} · {formatDateTime(m.createdAt)}
									{#if m.messageId === anchorMessageId}<Badge label={t('admin.chatCompliance.ediscovery.matchBadge')} />{/if}
									{#if m.deletedAt}<Badge variant="danger" label={t('admin.chatCompliance.ediscovery.deletedBadge')} />{/if}
								</p>
								<p class="edp-message__body">{m.body}</p>
								{#if m.revisions.length > 0}
									<div class="edp-sub">
										<p class="edp-subtitle">{t('admin.chatCompliance.ediscovery.reader.revisions')}</p>
										<ul>
											{#each m.revisions as rv (rv.id)}
												<li>{rv.priorBody} — {channelCache.participantLabel(rv.editedBy)} · {formatDateTime(rv.createdAt)}</li>
											{/each}
										</ul>
									</div>
								{/if}
								{#if m.poll}
									<div class="edp-sub">
										<p class="edp-subtitle">{t('admin.chatCompliance.ediscovery.reader.poll')}: {m.poll.question}</p>
										<table class="edp-table">
											<thead>
												<tr>
													<th>{t('admin.chatCompliance.ediscovery.reader.poll')}</th>
													<th>{t('admin.chatCompliance.ediscovery.reader.votes')}</th>
												</tr>
											</thead>
											<tbody>
												{#each m.poll.options as o (o.id)}
													<tr>
														<td>{o.label}</td>
														<td>{m.poll?.votes.filter((v) => v.optionId === o.id).length ?? 0}</td>
													</tr>
												{/each}
											</tbody>
										</table>
									</div>
								{/if}
								{#if m.attachments.length > 0}
									<div class="edp-sub">
										<p class="edp-subtitle">{t('admin.chatCompliance.ediscovery.reader.attachments')}</p>
										<ul>
											{#each m.attachments as a (a.id)}
												<li>{a.filename} — {a.sha256 ?? '—'}</li>
											{/each}
										</ul>
									</div>
								{/if}
							</li>
						{/each}
						{#each reader.scheduledRows as s (s.scheduledActionId)}
							<li class="edp-message">
								<p class="edp-message__meta">
									{channelCache.participantLabel(s.authorId)} · {formatDateTime(s.fireAt)}
									<Badge
										variant="accent"
										label={t('admin.chatCompliance.ediscovery.scheduledBadge', { status: scheduledStatusLabel(s.status) })}
									/>
								</p>
								<p class="edp-message__body">{s.body}</p>
							</li>
						{/each}
					</ul>
					{#if reader.messages.length > 0}
						{#if readerHasMore}
							<Button variant="ghost" size="sm" disabled={readerLoading} onclick={readerLoadMore}>
								{t('admin.chatCompliance.ediscovery.loadMore')}
							</Button>
						{:else}
							<p class="edp-hint">{t('admin.chatCompliance.ediscovery.endOfResults')}</p>
						{/if}
					{/if}
				{/if}
			</Card>
		{/if}

		{#if exportChannelIds.length > 0}
			<Card>
				<h3 class="edp-section__title">{t('admin.chatCompliance.ediscovery.export')}</h3>
				<ul class="edp-channel-checklist">
					{#each exportChannelIds as id (id)}
						<li>
							<Checkbox label={channelCache.label(id)} checked={!excludedChannelIds.has(id)} onchange={() => toggleExportChannel(id)} />
						</li>
					{/each}
				</ul>
				<Checkbox label={t('admin.chatCompliance.ediscovery.includeAttachments')} bind:checked={includeAttachments} />
				<div class="edp-record-floor" role="note">
					<p>{t('admin.chatCompliance.ediscovery.recordFloorDisclaimer')}</p>
				</div>
				{#if exportUrl}
					<Button variant="primary" size="sm" onclick={() => window.open(exportUrl, '_blank')}>
						{t('admin.chatCompliance.ediscovery.export')}
					</Button>
				{/if}
			</Card>
		{/if}
	{/if}
</div>

<style>
	.edp {
		display: flex;
		flex-direction: column;
		gap: var(--space-4);
	}
	.edp-loading {
		display: flex;
		align-items: center;
		gap: var(--space-2);
		padding: var(--space-6);
		color: var(--text-secondary);
	}
	.edp-empty,
	.edp-hint {
		font-size: var(--text-sm);
		color: var(--text-tertiary);
	}
	.edp-error {
		font-size: var(--text-sm);
		color: var(--text-danger);
	}
	.edp-row {
		display: flex;
		align-items: flex-end;
		gap: var(--space-3);
		flex-wrap: wrap;
	}
	.edp-section__title {
		font-size: var(--text-sm);
		font-weight: var(--weight-semibold);
		color: var(--text-primary);
		margin: 0 0 var(--space-2);
	}
	.edp-subtitle {
		font-size: var(--text-xs);
		font-weight: var(--weight-medium);
		color: var(--text-secondary);
		margin: var(--space-2) 0 var(--space-1);
	}
	.edp-scroll {
		overflow-x: auto;
	}
	.edp-table {
		width: 100%;
		border-collapse: collapse;
		font-size: var(--text-sm);
	}
	.edp-table th {
		text-align: left;
		padding: var(--space-2) var(--space-3);
		font-weight: var(--weight-medium);
		color: var(--text-secondary);
		border-bottom: 1px solid var(--border-default);
		white-space: nowrap;
	}
	.edp-table td {
		padding: var(--space-3);
		border-bottom: 1px solid var(--border-subtle);
		vertical-align: middle;
	}
	.edp-row-clickable {
		cursor: pointer;
	}
	.edp-row-clickable:hover {
		background: var(--surface-hover);
	}
	.edp-record-floor {
		display: flex;
		flex-direction: column;
		gap: var(--space-1);
		padding: var(--space-3);
		border-radius: var(--radius-md);
		background: var(--warning-bg, var(--gray-100));
		color: var(--warning-fg, var(--text-secondary));
		font-size: var(--text-sm);
		margin: var(--space-2) 0;
	}
	.edp-messages {
		list-style: none;
		margin: 0;
		padding: 0;
		display: flex;
		flex-direction: column;
		gap: var(--space-3);
	}
	.edp-message {
		padding: var(--space-3);
		border: 1px solid var(--border-subtle);
		border-radius: var(--radius-md);
	}
	.edp-message--deleted {
		background: var(--danger-bg, var(--gray-50));
	}
	/* C2: the hit that opened this reader — landed on, not just the channel's
	   latest window. Background is reinforced by the "Match" badge in the row
	   meta so the signal is never color-alone (WCAG 1.4.1). */
	.edp-message--hit {
		background: var(--accent-subtle);
	}
	.edp-message__meta {
		display: flex;
		align-items: center;
		gap: var(--space-2);
		font-size: var(--text-xs);
		color: var(--text-tertiary);
		margin: 0 0 var(--space-1);
	}
	.edp-message__body {
		font-size: var(--text-sm);
		color: var(--text-primary);
		margin: 0;
		white-space: pre-wrap;
	}
	.edp-sub ul {
		margin: 0;
		padding-left: var(--space-4);
		font-size: var(--text-xs);
		color: var(--text-secondary);
	}
	.edp-channel-checklist {
		list-style: none;
		margin: 0 0 var(--space-2);
		padding: 0;
		display: flex;
		flex-wrap: wrap;
		gap: var(--space-3);
	}
</style>
