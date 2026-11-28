<!-- simulate/+page.svelte — What-If CA simulator, two-pane.
     LEFT: context-builder form (primary + secondary via disclosure).
     RIGHT: ordered PolicyTraceRow trace + final decision banner.
     Five explicit states: EMPTY / LOADING / ERROR / NO-MATCH / RESULT.
     ponytail: adminFetch, no custom fetch layer; fetch is the stdlib. -->
<svelte:options runes={true} />

<script lang="ts">
	import { onMount } from 'svelte';
	import { page } from '$app/stores';
	import { adminFetch } from '$lib/admin/client';
	import { t, formatNumber } from '$lib/i18n';
	import { parseError } from '$lib/errors';
	import { Card, Button, Input, Select, EmptyState, Spinner, showToast } from '$lib/components/ui';
	import OutcomeLegend from '$lib/components/ca/OutcomeLegend.svelte';
	import OutcomeChip from '$lib/components/ca/OutcomeChip.svelte';
	import PolicyTraceRow from '$lib/components/ca/PolicyTraceRow.svelte';
	import type { TraceRow } from '$lib/components/ca/PolicyTraceRow.svelte';
	import ImpactCard from '$lib/components/ca/ImpactCard.svelte';

	// ── Types ──
	interface SimulateContext {
		identity?: string;
		client_type?: string;
		country?: string;
		ip?: string;
		platform?: string;
		factors?: string[];
		acr?: string;
		from_signin?: string;
	}

	interface SimulateResult {
		matched: boolean;
		decision?: string;          // block | allow | step_up | notify
		matched_policy_name?: string;
		matched_policy_id?: number;
		trace: TraceRow[];
	}

	// ── Form state ──
	let identity = $state('');
	let client_type = $state('web');
	let country = $state('');
	let ip = $state('');
	let platform = $state('');
	let factors = $state<string[]>([]); // multi-select: completed auth factors — §4 secondary field
	let acr = $state('');
	let fromSignin = $state('');
	let moreOpen = $state(false);

	const FACTOR_OPTIONS = ['password', 'totp', 'push', 'webauthn', 'sms'] as const;

	function toggleFactor(f: string) {
		factors = factors.includes(f) ? factors.filter((x) => x !== f) : [...factors, f];
	}

	// ── Async state ──
	type Phase = 'idle' | 'loading' | 'error' | 'nomatch' | 'result';
	let phase = $state<Phase>('idle');
	let result = $state<SimulateResult | null>(null);
	let errMsg = $state('');
	let lastCtx = $state<SimulateContext | null>(null);

	// aria-live announcement (polite — fires once per result) — §(w)
	let announce = $state('');

	// ── Seed from sign-in ──
	async function seedFromSignin() {
		if (!fromSignin.trim()) return;
		try {
			const res = await adminFetch(`/admin/conditional-access/why?correlation_id=${encodeURIComponent(fromSignin.trim())}`);
			if (!res.ok) throw new Error(String(res.status));
			const data = await res.json();
			const ctx = data?.context ?? data;
			if (ctx) {
				identity = ctx.identity ?? identity;
				client_type = ctx.client_type ?? client_type;
				country = ctx.country ?? country;
				ip = ctx.ip ?? ip;
				platform = ctx.platform ?? platform;
				acr = ctx.acr ?? acr;
			}
			showToast(t('admin.conditional_access.simulate.seed_toast', { id: fromSignin.trim() }));
		} catch {
			// non-fatal: just don't prefill
		}
	}

	// ── Run simulation ──
	async function runSim() {
		const ctx: SimulateContext = {
			identity: identity.trim() || undefined,
			client_type: client_type || undefined,
			country: country.trim() || undefined,
			ip: ip.trim() || undefined,
			platform: platform.trim() || undefined,
			factors: factors.length ? factors : undefined,
			acr: acr.trim() || undefined,
		};
		lastCtx = ctx;
		phase = 'loading';
		errMsg = '';
		announce = '';
		try {
			const res = await adminFetch('/admin/conditional-access/simulate', {
				method: 'POST',
				body: JSON.stringify(ctx),
			});
			if (!res.ok) throw new Error(String(res.status));
			result = await res.json() as SimulateResult;
			if (!result.matched) {
				phase = 'nomatch';
				announce = t('admin.conditional_access.simulate.announce_nomatch');
			} else {
				phase = 'result';
				announce = t('admin.conditional_access.simulate.announce', {
					decision: result.decision ?? '',
					policy: result.matched_policy_name ?? '',
				});
			}
		} catch (e) {
			errMsg = parseError(e).message;
			phase = 'error';
		}
	}

	// ── Retry ──
	async function retry() {
		if (lastCtx) await runSim();
	}
</script>

<div class="sim-page">
	<header class="sim-header">
		<h1>{t('admin.conditional_access.simulate.run')}</h1>
	</header>

	<div class="sim-panes">
		<!-- LEFT: context builder -->
		<section class="sim-form-pane" aria-label={t('admin.conditional_access.simulate.more_conditions')}>
			<Card>
				{#snippet children()}
				<div class="sim-form">
					<!-- Seed from a sign-in -->
					<div class="sim-form-group">
						<Input
							label={t('admin.conditional_access.simulate.seed_from_signin')}
							value={fromSignin}
							placeholder="correlation-id or sign-in id"
							oninput={(e) => (fromSignin = (e.target as HTMLInputElement).value)}
						/>
						<Button
							variant="secondary"
							size="sm"
							onclick={seedFromSignin}
							disabled={!fromSignin.trim()}
						>
							{t('admin.conditional_access.simulate.seed_from_signin')}
						</Button>
					</div>

					<hr class="sim-divider" aria-hidden="true" />

					<!-- PRIMARY fields: always visible -->
					<Input
						label={t('admin.conditional_access.trace.condition.client_type') + ' / identity'}
						value={identity}
						placeholder="user@example.com or user-id"
						oninput={(e) => (identity = (e.target as HTMLInputElement).value)}
					/>
					<Select
						label={t('admin.conditional_access.trace.condition.client_type')}
						options={[
							{ value: 'web', label: 'Web' },
							{ value: 'imap', label: 'IMAP' },
							{ value: 'smtp', label: 'SMTP' },
							{ value: 'mobile', label: 'Mobile' },
						]}
						value={client_type}
						onchange={(e) => (client_type = (e.target as HTMLSelectElement).value)}
					/>
					<Input
						label={t('admin.conditional_access.trace.condition.country_in')}
						value={country}
						placeholder="US"
						oninput={(e) => (country = (e.target as HTMLInputElement).value)}
					/>

					<!-- "More conditions" disclosure — §4 progressive disclosure -->
					<!-- ponytail: real <button aria-expanded> — not a Switch (§4 spec) -->
					<button
						class="sim-more-btn"
						type="button"
						aria-expanded={moreOpen}
						onclick={() => (moreOpen = !moreOpen)}
						data-testid="more-conditions-btn"
					>
						{t('admin.conditional_access.simulate.more_conditions')}
						<span class="sim-more-caret" aria-hidden="true">{moreOpen ? '▲' : '▼'}</span>
					</button>

					{#if moreOpen}
						<div class="sim-secondary" data-testid="secondary-fields">
							<Input
								label={t('admin.conditional_access.trace.condition.ip_in')}
								value={ip}
								mono={true}
								placeholder="1.2.3.4"
								oninput={(e) => (ip = (e.target as HTMLInputElement).value)}
							/>
							<Select
								label={t('admin.conditional_access.trace.condition.platform')}
								options={[
									{ value: '', label: '—' },
									{ value: 'windows', label: 'Windows' },
									{ value: 'macos', label: 'macOS' },
									{ value: 'linux', label: 'Linux' },
									{ value: 'ios', label: 'iOS' },
									{ value: 'android', label: 'Android' },
								]}
								value={platform}
								onchange={(e) => (platform = (e.target as HTMLSelectElement).value)}
							/>
							<!-- factors multi-select — §4 secondary field; §5 SimulateContext.factors -->
						<fieldset class="sim-factors" data-testid="factors-field">
							<legend class="sim-factors-legend">{t('admin.conditional_access.trace.condition.factors')}</legend>
							<div class="sim-factors-list">
								{#each FACTOR_OPTIONS as f (f)}
									<label class="sim-factor-check">
										<input
											type="checkbox"
											checked={factors.includes(f)}
											onchange={() => toggleFactor(f)}
										/>
										{t(`admin.conditional_access.auth_strength.factor.${f}`)}
									</label>
								{/each}
							</div>
						</fieldset>
						<Input
							label={t('admin.conditional_access.trace.condition.acr')}
							value={acr}
							placeholder="e.g. 2"
							oninput={(e) => (acr = (e.target as HTMLInputElement).value)}
						/>
					</div>
					{/if}

					<Button
						variant="primary"
						disabled={phase === 'loading'}
						onclick={runSim}
						data-testid="run-btn"
					>
						{#if phase === 'loading'}
							<Spinner size={16} />
							{t('admin.conditional_access.simulate.running')}
						{:else}
							{t('admin.conditional_access.simulate.run')}
						{/if}
					</Button>
				</div>
				{/snippet}
			</Card>
		</section>

		<!-- RIGHT: results pane -->
		<!-- aria-live: polite — SR hears the announce text after each run. §(w) -->
		<section
			class="sim-results-pane"
			aria-label="Policy evaluation results"
			aria-live="polite"
			data-testid="results-pane"
		>
			<!-- sr-only announce — visible in DOM but visually hidden until announced. -->
			<span class="sr-only" role="status" data-testid="result-announce">{announce}</span>

			{#if phase === 'idle'}
				<!-- EMPTY/FIRST-TIME — warmth + hint — §4 -->
				<EmptyState
					title={t('admin.conditional_access.simulate.empty')}
					watermark={true}
				/>

			{:else if phase === 'loading'}
				<!-- LOADING — skeleton trace rows — §4 -->
				<div data-testid="loading-state">
					<OutcomeLegend />
					<div class="sim-skel-rows" aria-busy="true">
						{#each [1, 2, 3, 4] as _, i (i)}
							<div class="sim-skel-row"></div>
						{/each}
					</div>
				</div>

			{:else if phase === 'error'}
				<!-- ERROR — inline alert + Retry — §4 -->
				<div role="alert" data-testid="error-state" class="sim-error">
					<span>{t('admin.conditional_access.simulate.load_error')}</span>
					{#if errMsg}<span class="sim-err-detail">{errMsg}</span>{/if}
					<Button variant="secondary" size="sm" onclick={retry}>{t('common.retry')}</Button>
				</div>

			{:else if phase === 'nomatch'}
				<!-- NO-MATCH — calm info panel, NOT an error — §4 -->
				<div data-testid="nomatch-state" class="sim-nomatch">
					<OutcomeLegend />
					<div class="sim-nomatch-banner" role="status">
						<span>{t('admin.conditional_access.simulate.nomatch')}</span>
					</div>
					{#if result?.trace?.length}
						<!-- Full evaluated trace (every policy skipped) so admin sees it was genuinely evaluated -->
						<ol class="sim-trace" aria-label="Policy evaluation trace" data-testid="trace-list">
							{#each result.trace as row (row.policy_id)}
								<PolicyTraceRow {row} />
							{/each}
						</ol>
					{/if}
				</div>

			{:else if phase === 'result' && result}
				<!-- RESULT — legend + matched banner + trace + F1 ImpactCard — §4 -->
				<div data-testid="result-state">
					<OutcomeLegend />
					<!-- matched outcome banner -->
					<div class="sim-match-banner" data-testid="match-banner">
						<OutcomeChip outcome={result.decision ?? 'applied'} size="md" />
						{#if result.matched_policy_name}
							<span class="sim-match-name">{result.matched_policy_name}</span>
						{/if}
					</div>
					<!-- F1 ImpactCard for the matched policy — §brief "Consumes: ImpactCard (F1)" -->
					{#if result.matched_policy_id}
						<ImpactCard policyId={result.matched_policy_id} fetchData />
					{/if}
					<!-- ordered trace -->
					{#if result.trace?.length}
						<ol class="sim-trace" aria-label="Policy evaluation trace" data-testid="trace-list">
							{#each result.trace as row (row.policy_id)}
								<PolicyTraceRow
									{row}
									policyHref={row.policy_id ? `/admin/conditional-access#p${row.policy_id}` : undefined}
								/>
							{/each}
						</ol>
					{/if}
				</div>
			{/if}
		</section>
	</div>
</div>

<style>
	.sim-page {
		max-width: 1200px;
	}

	.sim-header {
		margin-bottom: 16px;
	}
	.sim-header h1 {
		margin: 0;
		font-size: clamp(18px, 14px + 1vw, 22px);
		font-weight: 600;
		color: var(--text-primary);
	}

	/* Two-pane CSS grid; stacks below 900px form-first (DOM order preserved) — §4 §(aa) */
	.sim-panes {
		display: grid;
		grid-template-columns: 340px 1fr;
		gap: 20px;
		align-items: start;
	}

	@media (max-width: 900px) {
		/* ponytail: single-column; DOM order is already form→results so tab order stays sane. */
		.sim-panes {
			grid-template-columns: 1fr;
		}
	}

	.sim-form-pane { min-width: 0; }
	.sim-results-pane { min-width: 0; }

	.sim-form {
		display: flex;
		flex-direction: column;
		gap: 10px;
	}

	.sim-form-group {
		display: flex;
		flex-direction: column;
		gap: 6px;
	}

	.sim-divider {
		border: none;
		border-top: 1px solid var(--border-subtle);
		margin: 4px 0;
	}

	/* More conditions button — real <button aria-expanded> per §4 */
	.sim-more-btn {
		display: flex;
		align-items: center;
		justify-content: space-between;
		width: 100%;
		padding: 7px 10px;
		background: var(--surface-sunken);
		border: 1px solid var(--border-subtle);
		border-radius: var(--radius-sm);
		font-size: var(--text-sm);
		color: var(--text-secondary);
		cursor: pointer;
		font-family: var(--font-sans);
		min-height: 32px;
	}
	.sim-more-btn:focus-visible {
		outline: none;
		box-shadow: var(--focus-ring);
	}
	/* Touch target ≥44px — §(aa) */
	@media (pointer: coarse) {
		.sim-more-btn { min-height: 44px; }
	}

	.sim-more-caret {
		font-size: var(--text-2xs);
		color: var(--text-tertiary);
	}

	.sim-secondary {
		display: flex;
		flex-direction: column;
		gap: 8px;
		padding: 8px 10px;
		background: var(--surface-sunken);
		border-radius: var(--radius-sm);
	}

	/* Factors multi-select fieldset */
	.sim-factors {
		border: 1px solid var(--border-subtle);
		border-radius: var(--radius-sm);
		padding: 6px 8px;
		margin: 0;
	}
	.sim-factors-legend {
		font-size: var(--text-sm);
		font-weight: var(--weight-medium);
		color: var(--text-primary);
		padding: 0 4px;
	}
	.sim-factors-list {
		display: flex;
		flex-wrap: wrap;
		gap: 6px 12px;
		margin-top: 4px;
	}
	.sim-factor-check {
		display: flex;
		align-items: center;
		gap: 5px;
		font-size: var(--text-sm);
		color: var(--text-secondary);
		cursor: pointer;
		/* Touch target ≥44px on coarse — §(aa) */
	}

	@media (pointer: coarse) {
		.sim-factor-check { min-height: 44px; }
	}

	/* Loading skeleton */
	.sim-skel-rows {
		display: flex;
		flex-direction: column;
		gap: 6px;
		margin-top: 12px;
	}
	.sim-skel-row {
		height: 36px;
		border-radius: var(--radius-sm);
		position: relative;
		overflow: hidden;
		background: var(--surface-sunken);
	}
	.sim-skel-row::after {
		content: '';
		position: absolute;
		inset: 0;
		background: linear-gradient(90deg, var(--gray-100) 25%, var(--gray-200) 50%, var(--gray-100) 75%);
		background-size: 400% 100%;
		animation: sim-shimmer var(--duration-slow) ease-in-out infinite;
	}

	@keyframes sim-shimmer {
		0% { background-position: 100% 50%; }
		100% { background-position: 0% 50%; }
	}

	/* Error state */
	.sim-error {
		display: flex;
		flex-direction: column;
		gap: 8px;
		padding: 12px 14px;
		border-radius: var(--radius-sm);
		background: var(--danger-bg);
		color: var(--danger-fg);
		font-size: var(--text-sm);
	}
	.sim-err-detail {
		font-size: var(--text-xs);
		opacity: 0.8;
	}

	/* No-match: calm info panel */
	.sim-nomatch-banner {
		padding: 12px 14px;
		border-radius: var(--radius-sm);
		background: var(--info-bg);
		color: var(--info-fg);
		font-size: var(--text-sm);
		margin: 12px 0;
		border: 1px solid var(--info-solid, var(--info-bg));
	}

	/* Match banner: big chip + policy name */
	.sim-match-banner {
		display: flex;
		align-items: center;
		gap: 10px;
		margin: 12px 0;
		padding: 10px 14px;
		border-radius: var(--radius-sm);
		background: var(--surface-selected);
		border: 1px solid var(--border-subtle);
	}
	.sim-match-name {
		font-size: var(--text-md);
		font-weight: var(--weight-semibold);
		color: var(--text-primary);
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
	}

	/* Trace list */
	.sim-trace {
		list-style: none;
		margin: 0;
		padding: 0;
		display: flex;
		flex-direction: column;
		gap: 2px;
	}

	/* No-match trace wrapper */
	.sim-nomatch { display: flex; flex-direction: column; }

	/* sr-only utility — NOT re-defined locally (global.css owns it; ponytail nit from review).
	   We use a local class only because global.css is in the app layout, not in this scope. */
	.sr-only {
		position: absolute;
		width: 1px; height: 1px;
		padding: 0; margin: -1px;
		overflow: hidden;
		clip-path: inset(50%);
		white-space: nowrap;
		border: 0;
	}

	@media (prefers-reduced-motion: reduce) {
		.sim-skel-row::after { animation: none; }
	}
</style>
