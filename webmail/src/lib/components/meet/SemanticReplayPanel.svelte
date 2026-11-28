<svelte:options runes={true} />

<script lang="ts">
	// SemanticReplayPanel — MEET plan M4: deterministic replay of a `.sjrec`
	// semantic recording (retired-docs:superpowers/plans/2026-08-25-meet-document-
	// presentation-semantic-recording.md, M4 + R5.4). The panel renders the
	// model built by `$lib/meet/semanticReplay` — it NEVER invents media:
	//
	//   · Gaps are explicit stops with their exact bounds announced and a
	//     "continue at next available interval" affordance ONLY when one
	//     exists (R5.4); stale material is never presented as current.
	//   · Unavailable (interrupted/failed) segments are NAMED with their
	//     reason — truthful partial results, never synthesized silence.
	//   · Local-only provenance is a visible label: these bytes were never
	//     centrally retained (the typed-locality failure mode).
	//   · Export confirms its exact bounds AND exclusions, and is disabled
	//     outright when no verified interval exists.
	//   · A fenced package (delete/hold) explains itself instead of playing.
	//
	// Svelte 5 runes; `onclick=`; token-only styling; 44px controls; polite
	// live-region announcements for gap stops.
	import { t } from '$lib/i18n';
	import {
		buildSemanticReplay,
		seekReplay,
		replayExportBounds,
		replayFactRail,
		replayFidelityNotice,
		gapAnnouncement,
		type SemanticPackageRead,
		type ReplayModel,
	} from '$lib/meet/semanticReplay';

	let {
		pkg,
		loading = false,
		error = null,
	}: {
		pkg: SemanticPackageRead | null;
		loading?: boolean;
		error?: string | null;
	} = $props();

	let positionMs = $state(0);
	let announcement = $state('');

	const model: ReplayModel | null = $derived(pkg ? buildSemanticReplay(pkg) : null);
	const bounds = $derived(model ? replayExportBounds(model) : null);
	// M4 replay-feed riders: version links are NEVER hidden ("presentation
	// version links visible"); annotation references list the committed
	// durable snapshots (bytes ride the authorized bounded read, never the
	// feed); the fact rail is deterministic (semanticReplay.replayFactRail).
	const links = $derived(pkg?.presentationLinks ?? []);
	// M6 fidelity surface: a link carrying a document-mode capability shows
	// its fidelity warning + fallback beside itself (honest fidelity — the
	// shared page canvas never re-paginates word/text and never pretends a
	// static print snapshot is a live grid). Launch-vocabulary links and
	// partial triples surface nothing.
	const fidelityNotices = $derived.by(() => {
		const map = new Map<number, ReturnType<typeof replayFidelityNotice>>();
		for (const link of links) map.set(link.presentationId, replayFidelityNotice(link));
		return map;
	});
	const annotationRefs = $derived(pkg?.annotations ?? []);
	const captions = $derived(pkg?.captions ?? []);
	const facts = $derived(pkg ? replayFactRail(pkg) : []);
	const activeGap = $derived.by(() => {
		if (!model) return null;
		const r = seekReplay(model, positionMs);
		return r.ok ? null : r.outcome === 'gap' ? r : null;
	});
	const pastEnd = $derived.by(() => {
		if (!model) return false;
		const r = seekReplay(model, positionMs);
		return !r.ok && r.outcome === 'past-end';
	});

	function seek(ms: number): void {
		positionMs = ms;
		if (!model) return;
		const r = seekReplay(model, ms);
		if (!r.ok && r.outcome === 'gap') {
			// R5.4: stop at the gap and ANNOUNCE its bounds + unavailable
			// facts; offer continue only when a later interval exists.
			announcement = gapAnnouncement(model, r);
		} else if (!r.ok && r.outcome === 'past-end') {
			announcement = 'Past the end of the recording';
		} else {
			announcement = '';
		}
	}

	const fmt = (ms: number): string => `${(ms / 1000).toFixed(1)}s`;
</script>

<section class="semantic-replay" aria-label={t('meet.replay.title')}>
	{#if loading}
		<p class="semantic-replay__status" role="status">{t('meet.replay.loading')}</p>
	{:else if error}
		<p class="semantic-replay__status semantic-replay__status--error" role="alert">{error}</p>
	{:else if model}
		<header class="semantic-replay__head">
			<h3 class="semantic-replay__title">{t('meet.replay.title')}</h3>
			{#if model.localOnly}
				<span class="semantic-replay__chip semantic-replay__chip--local" role="note">
					{t('meet.replay.localOnly')}
				</span>
			{/if}
			{#if model.packageState !== 'ACTIVE'}
				<span class="semantic-replay__chip" role="note">{model.packageState}</span>
			{/if}
		</header>

		{#if model.entries.length === 0}
			<p class="semantic-replay__status" role="status">{t('meet.replay.empty')}</p>
		{:else}
			<ol class="semantic-replay__timeline">
				{#each model.entries as entry (entry.kind + '-' + entry.startMs)}
					<li>
						{#if entry.kind === 'media'}
							<button
								type="button"
								class="semantic-replay__run"
								onclick={() => seek(entry.startMs)}
							>
								{fmt(entry.startMs)}–{fmt(entry.endMs)}
								<span class="semantic-replay__mime">{entry.mimeType}</span>
							</button>
						{:else}
							<button
								type="button"
								class="semantic-replay__gap"
								onclick={() => seek(entry.startMs)}
							>
								{t('meet.replay.gap')} {fmt(entry.startMs)}–{fmt(entry.endMs)}
							</button>
						{/if}
					</li>
				{/each}
			</ol>

			<p class="semantic-replay__position" role="status">
				{t('meet.replay.position')} {fmt(positionMs)}
				{#if activeGap}
					— {t('meet.replay.unavailable')} {fmt(activeGap.startMs)}–{fmt(activeGap.endMs)}
					{#if activeGap.nextAvailableMs !== null}
						<button
							type="button"
							class="semantic-replay__continue"
							onclick={() => seek(activeGap.nextAvailableMs ?? 0)}
						>
							{t('meet.replay.continue')} {fmt(activeGap.nextAvailableMs)}
						</button>
					{/if}
				{:else if pastEnd}
					— {t('meet.replay.pastEnd')}
				{/if}
			</p>
			<p class="semantic-replay__sr" role="status" aria-live="polite">{announcement}</p>
		{/if}

		{#if model.unavailableSegments.length > 0}
			<div class="semantic-replay__unavailable">
				<h4>{t('meet.replay.unavailableTitle')}</h4>
				<ul>
					{#each model.unavailableSegments as seg (seg.seq)}
						<li>
							{t('meet.replay.segment')} {seg.seq}: {seg.reason || seg.state}
							({fmt(seg.startMs)}–{fmt(seg.endMs)})
						</li>
					{/each}
				</ul>
			</div>
		{/if}

		{#if links.length > 0}
			<div class="semantic-replay__links">
				<h4>{t('meet.replay.linksTitle')}</h4>
				<ul>
					{#each links as link (link.presentationId)}
						{@const notice = fidelityNotices.get(link.presentationId)}
						<li>
							{t('meet.replay.linkVersion', { n: String(link.manifestGeneration) })}
							<span class="semantic-replay__mime">v{link.driveVersionId}</span>
							<span class="semantic-replay__mime">{link.status}</span>
							{#if notice}
								<p class="semantic-replay__fidelity" role="note">
									{t(notice.warningKey)}
									{t(notice.fallbackKey)}
								</p>
							{/if}
						</li>
					{/each}
				</ul>
			</div>
		{/if}

		{#if annotationRefs.length > 0}
			<div class="semantic-replay__annotations">
				<h4>{t('meet.replay.annotationsTitle')}</h4>
				<ul>
					{#each annotationRefs as a (a.snapshotPath)}
						<li>
							{t('meet.replay.annotation')} {a.checkpointSeq}
							<span class="semantic-replay__mime">{a.snapshotPath}</span>
						</li>
					{/each}
				</ul>
			</div>
		{/if}

		{#if captions.length > 0}
			<div class="semantic-replay__captions">
				<h4>{t('meet.replay.captionsTitle')}</h4>
				<ul>
					{#each captions as c (c.language)}
						<li>{c.language}</li>
					{/each}
				</ul>
			</div>
		{/if}

		{#if facts.length > 0}
			<div class="semantic-replay__facts">
				<h4>{t('meet.replay.factsTitle')}</h4>
				<ul>
					{#each facts as f (f.checkpointSeq + '-' + f.presentationId)}
						<li>
							<span class="semantic-replay__mime">{f.kind}</span>
							{f.mediaMs >= 0 ? fmt(f.mediaMs) : t('meet.replay.factUnaligned')}
						</li>
					{/each}
				</ul>
			</div>
		{/if}

		{#if bounds}
			<div class="semantic-replay__export">
				<h4>{t('meet.replay.exportTitle')}</h4>
				{#if bounds.exportable}
					<p>
						{t('meet.replay.exportBounds')}
						{bounds.bounds.map((b) => `${fmt(b.startMs)}–${fmt(b.endMs)}`).join(', ')}
						{#if bounds.exclusions.length > 0}
							; {t('meet.replay.exportExcludes')}
							{bounds.exclusions.map((b) => `${fmt(b.startMs)}–${fmt(b.endMs)}`).join(', ')}
						{/if}
					</p>
				{:else}
					<p>{t('meet.replay.exportDisabled')}</p>
				{/if}
			</div>
		{/if}
	{/if}
</section>

<style>
	.semantic-replay {
		display: flex;
		flex-direction: column;
		gap: var(--space-2);
		padding: var(--space-3);
		background: var(--surface-raised);
		border: 1px solid var(--border-default);
		border-radius: var(--radius-lg);
		color: var(--text-primary);
	}
	.semantic-replay__head {
		display: flex;
		align-items: center;
		gap: var(--space-2);
		flex-wrap: wrap;
	}
	.semantic-replay__title {
		margin: 0;
		font-size: var(--text-md);
		font-weight: var(--font-weight-semibold);
		color: var(--text-primary);
	}
	.semantic-replay__chip {
		display: inline-flex;
		align-items: center;
		padding: var(--space-1) var(--space-2);
		border: 1px solid var(--border-default);
		border-radius: var(--radius-full);
		font-size: var(--text-xs);
		color: var(--text-secondary);
	}
	.semantic-replay__chip--local {
		color: var(--text-primary);
		border-color: var(--border-strong);
	}
	.semantic-replay__status {
		margin: 0;
		font-size: var(--text-sm);
		color: var(--text-secondary);
	}
	.semantic-replay__status--error {
		color: var(--danger-text);
	}
	.semantic-replay__timeline {
		list-style: none;
		margin: 0;
		padding: 0;
		display: flex;
		flex-wrap: wrap;
		gap: var(--space-1);
	}
	.semantic-replay__run,
	.semantic-replay__gap,
	.semantic-replay__continue {
		min-height: 44px;
		min-width: 44px;
		padding: var(--space-1) var(--space-2);
		border-radius: var(--radius-md);
		border: 1px solid var(--border-default);
		background: var(--surface-sunken);
		color: var(--text-primary);
		font-size: var(--text-sm);
		cursor: pointer;
	}
	.semantic-replay__gap {
		border-style: dashed;
		color: var(--text-secondary);
	}
	.semantic-replay__run:focus-visible,
	.semantic-replay__gap:focus-visible,
	.semantic-replay__continue:focus-visible {
		outline: var(--focus-ring);
		outline-offset: var(--focus-ring-offset);
	}
	.semantic-replay__mime {
		color: var(--text-secondary);
		font-size: var(--text-xs);
	}
	.semantic-replay__fidelity {
		margin: var(--space-1) 0 0;
		padding-inline-start: var(--space-2);
		border-inline-start: 2px solid var(--border-strong);
		font-size: var(--text-xs);
		color: var(--text-secondary);
	}
	.semantic-replay__position {
		margin: 0;
		font-size: var(--text-sm);
		color: var(--text-secondary);
	}
	.semantic-replay__sr {
		position: absolute;
		width: 1px;
		height: 1px;
		overflow: hidden;
		clip-path: inset(50%);
		white-space: nowrap;
	}
	.semantic-replay__unavailable h4,
	.semantic-replay__export h4,
	.semantic-replay__links h4,
	.semantic-replay__annotations h4,
	.semantic-replay__captions h4,
	.semantic-replay__facts h4 {
		margin: 0 0 var(--space-1);
		font-size: var(--text-sm);
		color: var(--text-primary);
	}
	.semantic-replay__links ul,
	.semantic-replay__annotations ul,
	.semantic-replay__captions ul,
	.semantic-replay__facts ul {
		margin: 0;
		padding-inline-start: var(--space-4);
		font-size: var(--text-sm);
		color: var(--text-secondary);
		display: flex;
		flex-direction: column;
		gap: var(--space-1);
	}
	.semantic-replay__unavailable ul {
		margin: 0;
		padding-inline-start: var(--space-4);
		font-size: var(--text-sm);
		color: var(--text-secondary);
	}
	.semantic-replay__export p {
		margin: 0;
		font-size: var(--text-sm);
		color: var(--text-secondary);
	}
</style>
