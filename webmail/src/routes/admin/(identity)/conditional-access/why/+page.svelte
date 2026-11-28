<!-- why/+page.svelte — Why-blocked admin trace page.
     Deep-link via ?correlation_id=… → auto-resolves + scrolls + highlights.
     Three distinct user-not-found/empty states, distinct from loading/error.
     ponytail: correlation_id comes from $page.url.searchParams (sveltekit native). -->
<svelte:options runes={true} />

<script lang="ts">
	import { onMount } from 'svelte';
	import { page } from '$app/stores';
	import { tick } from 'svelte';
	import { adminFetch } from '$lib/admin/client';
	import { t, formatNumber } from '$lib/i18n';
	import { parseError } from '$lib/errors';
	import { Button, Input, Select, EmptyState } from '$lib/components/ui';
	import OutcomeLegend from '$lib/components/ca/OutcomeLegend.svelte';
	import OutcomeChip from '$lib/components/ca/OutcomeChip.svelte';
	import PolicyTraceRow from '$lib/components/ca/PolicyTraceRow.svelte';
	import type { TraceRow } from '$lib/components/ca/PolicyTraceRow.svelte';
	import ImpactCard from '$lib/components/ca/ImpactCard.svelte';

	// ── Types ──
	interface SignInRecord {
		id: string;
		correlation_id: string;
		outcome: string;
		policy_name?: string;
		policy_id?: number;
		timestamp: string;
		trace?: TraceRow[];
	}

	// ── Form state ──
	let query = $state('');
	let timeWindow = $state('7d'); // ponytail: renamed from 'window' — avoids shadowing globalThis.window
	let correlationInput = $state('');

	// ── Async state ──
	type Phase = 'idle' | 'loading' | 'error' | 'not_found' | 'zero_signins' | 'result';
	let phase = $state<Phase>('idle');
	let records = $state<SignInRecord[]>([]);
	let errMsg = $state('');
	let foundUser = $state('');
	let expandedId = $state<string | null>(null);
	let highlightedId = $state<string | null>(null);

	// aria-live announces
	let announce = $state('');

	// ── Deep-link: ?correlation_id= ──
	// ponytail: runs on mount after the DOM is ready so scrollIntoView works.
	onMount(async () => {
		const params = $page.url.searchParams;
		const corrId = params.get('correlation_id');
		if (corrId) {
			correlationInput = corrId;
			await lookupCorrelation(corrId);
		}
	});

	async function lookupCorrelation(corrId: string) {
		phase = 'loading';
		announce = '';
		try {
			const res = await adminFetch(`/admin/conditional-access/why-lookup?correlation_id=${encodeURIComponent(corrId)}`);
			if (!res.ok) throw new Error(String(res.status));
			const data = await res.json();
			records = Array.isArray(data) ? data : (data.records ?? []);
			if (!records.length) {
				phase = 'zero_signins';
				return;
			}
			foundUser = records[0]?.id ?? corrId;
			phase = 'result';
			// Highlight + scroll the matching record after DOM update
			const match = records.find((r) => r.correlation_id === corrId || r.id === corrId);
			if (match) {
				highlightedId = match.id;
				expandedId = match.id;
				announce = t('admin.conditional_access.why.announce_correlation', { id: corrId });
				await tick();
				const el = document.querySelector(`[data-signin-id="${match.id}"]`) as HTMLElement | null;
				el?.scrollIntoView({ behavior: 'smooth', block: 'center' });
				el?.focus();
			}
		} catch (e) {
			errMsg = parseError(e).message;
			phase = 'error';
		}
	}

	async function lookup() {
		if (!query.trim()) return;
		phase = 'loading';
		errMsg = '';
		announce = '';
		try {
			// Backend contract (admin_ca_why.go): user=<id|email>, since=<24h|7d|30d>,
			// optional correlation_id. `since` also accepts empty (defaults 7d).
			const params = new URLSearchParams({ user: query.trim(), since: timeWindow });
			// The server distinguishes an unresolvable user (404 {found:false})
			// from found-but-empty (200 + []); admit the 404 past the transport's
			// throw-on-non-OK seam so the dedicated warning-tone not-found state
			// below stays reachable (other non-OK statuses still throw → error).
			const res = await adminFetch(`/admin/conditional-access/why-lookup?${params}`, { allowStatuses: [404] });
			if (res.status === 404) {
				phase = 'not_found';
				return;
			}
			if (!res.ok) throw new Error(String(res.status));
			const data = await res.json();
			records = Array.isArray(data) ? data : (data.records ?? []);
			foundUser = query.trim();
			if (!records.length) {
				phase = 'zero_signins';
			} else {
				phase = 'result';
			}
		} catch (e) {
			errMsg = parseError(e).message;
			phase = 'error';
		}
	}

	function toggleExpand(id: string) {
		expandedId = expandedId === id ? null : id;
	}
</script>

<div class="why-page" data-testid="why-page">
	<header class="why-header">
		<h1>{t('admin.conditional_access.why.page_title')}</h1>
	</header>

	<!-- OutcomeLegend always shown (teaches colours once — §5c) -->
	<OutcomeLegend />

	<!-- aria-live correlation announce — §(w) -->
	<span
		class="sr-only"
		role="status"
		aria-live="polite"
		data-testid="why-announce"
	>{announce}</span>

	<!-- Lookup form -->
	<div class="why-controls" role="search">
		<Input
			label={t('admin.conditional_access.why.lookup_label')}
			value={query}
			placeholder="alice@example.com"
			disabled={phase === 'loading'}
			oninput={(e) => (query = (e.target as HTMLInputElement).value)}
			aria-describedby={phase === 'not_found' ? 'why-not-found-msg' : undefined}
		/>
		<Select
			label={t('admin.conditional_access.why.window_label')}
			options={[
				{ value: '24h', label: t('admin.conditional_access.why.window.24h') },
				{ value: '7d',  label: t('admin.conditional_access.why.window.7d')  },
				{ value: '30d', label: t('admin.conditional_access.why.window.30d') },
			]}
			value={timeWindow}
			onchange={(e) => (timeWindow = (e.target as HTMLSelectElement).value)}
		/>
		<Input
			label={t('admin.conditional_access.why.correlation_label')}
			value={correlationInput}
			mono={true}
			placeholder="correlation-id"
			oninput={(e) => (correlationInput = (e.target as HTMLInputElement).value)}
		/>
		<Button
			variant="primary"
			disabled={phase === 'loading' || !query.trim()}
			onclick={lookup}
			data-testid="lookup-btn"
		>
			{t('admin.conditional_access.why.lookup_btn')}
		</Button>
	</div>

	<!-- States -->

	{#if phase === 'idle'}
		<!-- (a) no query yet — §5c -->
		<EmptyState title={t('admin.conditional_access.why.empty')} />

	{:else if phase === 'loading'}
		<!-- LOADING — skeleton rows + inputs already disabled above -->
		<div data-testid="loading-state" class="why-skel-list" aria-busy="true">
			{#each [1, 2, 3] as _, i (i)}
				<div class="why-skel-row"></div>
			{/each}
		</div>

	{:else if phase === 'error'}
		<!-- ERROR — role=alert; distinct from not-found §5c -->
		<div role="alert" data-testid="error-state" class="why-error">
			<span>{t('admin.conditional_access.why.load_error')}</span>
			{#if errMsg}<span class="why-err-detail">{errMsg}</span>{/if}
			<Button variant="secondary" size="sm" onclick={lookup}>{t('common.retry')}</Button>
		</div>

	{:else if phase === 'not_found'}
		<!-- (b) user not found — warning tone, NOT error, NOT empty §5c load-bearing -->
		<div
			id="why-not-found-msg"
			role="status"
			data-testid="not-found-state"
			class="why-not-found"
		>
			{t('admin.conditional_access.why.not_found', { q: query.trim() })}
		</div>

	{:else if phase === 'zero_signins'}
		<!-- (c) user found, zero sign-ins in window — distinct from not-found §5c -->
		<div data-testid="zero-signins-state" class="why-zero">
			<p class="why-zero-msg">
				{t('admin.conditional_access.why.zero_signins', { user: foundUser, window: timeWindow })}
			</p>
			<Button
				variant="secondary"
				size="sm"
				onclick={() => { timeWindow = timeWindow === '24h' ? '7d' : '30d'; lookup(); }}
			>
				{t('admin.conditional_access.why.widen')}
			</Button>
		</div>

	{:else if phase === 'result'}
		<!-- RESULTS — expandable sign-in rows with PolicyTraceRow trace -->
		<div data-testid="result-state">
			<ul class="why-list" aria-label="Sign-in records">
				{#each records as rec (rec.id)}
					<li
						class="why-record"
						class:why-record--highlight={highlightedId === rec.id}
						data-signin-id={rec.id}
						data-testid="signin-record"
					>
						<!-- expandable header -->
						<button
							class="why-record-head"
							type="button"
							aria-expanded={expandedId === rec.id}
							onclick={() => toggleExpand(rec.id)}
							aria-label={t('admin.conditional_access.why.expand_trace', { id: rec.id })}
							data-testid="expand-btn"
						>
							<span class="why-record-ts">{rec.timestamp}</span>
							<OutcomeChip outcome={rec.outcome} size="sm" />
							{#if rec.policy_name}
								<span class="why-record-policy">{rec.policy_name}</span>
							{/if}
							<span class="why-record-caret" aria-hidden="true">{expandedId === rec.id ? '▲' : '▼'}</span>
						</button>

						<!-- expanded trace + F1 ImpactCard for the matched policy — §brief "Consumes: ImpactCard (F1)" -->
						{#if expandedId === rec.id && rec.trace?.length}
							<div class="why-trace-wrap">
								{#if rec.policy_id}
									<ImpactCard policyId={rec.policy_id} fetchData />
								{/if}
								<ol class="why-trace" aria-label="Policy evaluation trace" data-testid="trace-list">
									{#each rec.trace as row (row.policy_id)}
										<PolicyTraceRow {row} />
									{/each}
								</ol>
							</div>
						{/if}
					</li>
				{/each}
			</ul>
		</div>
	{/if}
</div>

<style>
	.why-page { max-width: 900px; }

	.why-header {
		margin-bottom: 12px;
	}
	.why-header h1 {
		margin: 0;
		font-size: clamp(18px, 14px + 1vw, 22px);
		font-weight: 600;
		color: var(--text-primary);
	}

	/* Controls */
	.why-controls {
		display: flex;
		flex-wrap: wrap;
		gap: 10px;
		align-items: flex-end;
		margin: 14px 0;
	}

	/* Loading skeletons */
	.why-skel-list {
		display: flex;
		flex-direction: column;
		gap: 6px;
		margin-top: 8px;
	}
	.why-skel-row {
		height: 48px;
		border-radius: var(--radius-sm);
		position: relative;
		overflow: hidden;
		background: var(--surface-sunken);
	}
	.why-skel-row::after {
		content: '';
		position: absolute;
		inset: 0;
		background: linear-gradient(90deg, var(--gray-100) 25%, var(--gray-200) 50%, var(--gray-100) 75%);
		background-size: 400% 100%;
		animation: why-shimmer var(--duration-slow) ease-in-out infinite;
	}

	@keyframes why-shimmer {
		0% { background-position: 100% 50%; }
		100% { background-position: 0% 50%; }
	}

	/* Error */
	.why-error {
		display: flex;
		flex-direction: column;
		gap: 8px;
		padding: 12px 14px;
		border-radius: var(--radius-sm);
		background: var(--danger-bg);
		color: var(--danger-fg);
		font-size: var(--text-sm);
	}
	.why-err-detail { font-size: var(--text-xs); opacity: 0.8; }

	/* Not-found — warning tone, NOT error §5c */
	.why-not-found {
		padding: 10px 14px;
		border-radius: var(--radius-sm);
		background: var(--warning-bg);
		color: var(--warning-fg);
		font-size: var(--text-sm);
		border: 1px solid var(--warning-solid, var(--warning-bg));
	}

	/* Zero sign-ins */
	.why-zero {
		display: flex;
		flex-direction: column;
		align-items: flex-start;
		gap: 8px;
		padding: 12px 0;
	}
	.why-zero-msg {
		margin: 0;
		font-size: var(--text-sm);
		color: var(--text-secondary);
	}

	/* Sign-in record list */
	.why-list {
		list-style: none;
		margin: 0;
		padding: 0;
		display: flex;
		flex-direction: column;
		gap: 4px;
	}

	.why-record {
		border-radius: var(--radius-sm);
		border: 1px solid var(--border-subtle);
		background: var(--surface-card);
		overflow: hidden;
		/* correlation-id highlight: accent rail + surface-selected pulse — §5c */
		border-inline-start: 3px solid transparent;
		transition:
			border-inline-start-color var(--duration-slow) var(--ease-out),
			background var(--duration-slow) var(--ease-out);
	}

	/* Highlighted record — transient glow, then fades — §5c (prefers-reduced-motion: static) */
	.why-record--highlight {
		border-inline-start-color: var(--accent);
		background: var(--surface-selected);
	}

	@media (prefers-reduced-motion: reduce) {
		.why-record {
			transition: none;
		}
		.why-skel-row::after { animation: none; }
	}

	/* Expandable header — real button aria-expanded — §5c */
	.why-record-head {
		display: flex;
		align-items: center;
		gap: 10px;
		width: 100%;
		padding: 10px 14px;
		background: transparent;
		border: none;
		cursor: pointer;
		font-family: var(--font-sans);
		font-size: var(--text-sm);
		text-align: start;
		color: var(--text-primary);
		/* Touch target ≥44px — §(aa) */
		min-height: 44px;
	}
	.why-record-head:focus-visible {
		outline: none;
		box-shadow: var(--focus-ring);
	}
	.why-record-head:hover { background: var(--surface-hover); }

	.why-record-ts {
		font-family: var(--font-mono);
		font-size: var(--text-xs);
		color: var(--text-tertiary);
		flex: none;
	}

	.why-record-policy {
		font-size: var(--text-sm);
		color: var(--text-secondary);
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
		flex: 1;
		/* Long policy names truncate — §(z) */
		min-width: 0;
	}

	.why-record-caret {
		font-size: var(--text-2xs);
		color: var(--text-tertiary);
		flex: none;
	}

	/* Trace content */
	.why-trace-wrap {
		padding: 4px 14px 12px;
		border-top: 1px solid var(--border-subtle);
	}

	.why-trace {
		list-style: none;
		margin: 0;
		padding: 0;
		display: flex;
		flex-direction: column;
		gap: 2px;
	}

	.sr-only {
		position: absolute;
		width: 1px; height: 1px;
		padding: 0; margin: -1px;
		overflow: hidden;
		clip-path: inset(50%);
		white-space: nowrap;
		border: 0;
	}
</style>
