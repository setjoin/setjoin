<!-- AuthStrengthMatrix.svelte — OR-of-ANDs factor picker.
     shape: [["webauthn"], ["password","totp"]] = webauthn OR (password AND totp)
     ponytail: OR-of-AND structure made visual via fieldset+legend rows. -->
<svelte:options runes={true} />

<script lang="ts">
	import { get } from 'svelte/store';
	import { Checkbox, IconButton } from '$lib/components/ui';
	import { t, locale } from '$lib/i18n';

	// ponytail: locale→BCP-47 inline; mirrors i18n/index.ts LOCALE_MAP (not exported).
	const LOCALE_BCP47: Record<string, string> = { en: 'en-US', de: 'de-DE', zh: 'zh-CN' };

	interface Props {
		combinations: string[][];
		onChange: (v: string[][]) => void;
		showValidation?: boolean;
	}

	// ponytail: onChange callback only — parent never uses bind:combinations, so $bindable is dropped.
	let { combinations = [[]], onChange, showValidation = false }: Props = $props();

	// ponytail: hardcoded factor list — never changes without a schema migration anyway.
	const FACTORS = ['password', 'totp', 'push', 'webauthn', 'sms'] as const;
	type Factor = typeof FACTORS[number];

	function factorLabel(f: string): string {
		const key = `admin.conditional_access.auth_strength.factor.${f}` as const;
		return t(key as Parameters<typeof t>[0]) || f;
	}

	function toggleFactor(rowIdx: number, factor: string) {
		const row = combinations[rowIdx] ?? [];
		const next = row.includes(factor)
			? row.filter((f) => f !== factor)
			: [...row, factor];
		const updated = combinations.map((r, i) => (i === rowIdx ? next : r));
		onChange(updated);
	}

	function addBranch() {
		onChange([...combinations, []]);
	}

	function deleteBranch(rowIdx: number) {
		onChange(combinations.filter((_, i) => i !== rowIdx));
	}

	/** Plain-English echo for one AND-combination row. */
	function echoText(row: string[]): string {
		if (row.length === 0) return '—';
		if (row.length === 1) {
			return t('admin.conditional_access.auth_strength.echo_one', { factor: factorLabel(row[0]) });
		}
		// ICU list formatting via Intl.ListFormat — no hardcoded "and" connector.
		const bcp47 = LOCALE_BCP47[get(locale)] ?? 'en-US';
		const factors = new Intl.ListFormat(bcp47, { style: 'long', type: 'conjunction' }).format(
			row.map(factorLabel)
		);
		return t('admin.conditional_access.auth_strength.echo_and', { factors });
	}

	const hasEmpty = $derived(combinations.some((r) => r.length === 0));
</script>

<div class="asm" data-testid="auth-strength-matrix">
	{#each combinations as row, rowIdx (rowIdx)}
		{#if rowIdx > 0}
			<!-- OR divider — decorative, legends carry SR structure -->
			<div class="asm-or-divider" aria-hidden="true" data-testid="as-or-divider">
				<span class="asm-or-rule"></span>
				<span class="asm-or-word">OR</span>
				<span class="asm-or-rule"></span>
			</div>
		{/if}

		<fieldset class="asm-branch" data-testid="as-branch-{rowIdx}">
			<div class="asm-branch-head">
				<legend class="asm-legend">
					{t('admin.conditional_access.auth_strength.or_branch', { n: String(rowIdx + 1) })}
				</legend>
				{#if combinations.length > 1}
					<IconButton
						label={t('admin.conditional_access.auth_strength.remove_branch', { n: String(rowIdx + 1) })}
						size="sm"
						onclick={() => deleteBranch(rowIdx)}
						data-testid="as-delete-branch-{rowIdx}"
					>
						<!-- Trash icon -->
						<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
							<path d="M3 6h18M8 6V4h8v2M19 6l-1 14H6L5 6"/>
						</svg>
					</IconButton>
				{/if}
			</div>

			<div class="asm-factors">
				{#each FACTORS as factor}
					<span data-testid="as-factor-{factor}-{rowIdx}">
						<Checkbox
							checked={row.includes(factor)}
							label={factorLabel(factor)}
							onchange={() => toggleFactor(rowIdx, factor)}
						/>
					</span>
				{/each}
			</div>

			<!-- Plain-English echo (aria-live="polite" — announces on change) -->
			<div
				class="asm-echo"
				aria-live="polite"
				aria-atomic="true"
				data-testid="as-echo-{rowIdx}"
			>
				{echoText(row)}
			</div>
		</fieldset>
	{/each}

	<!-- Add branch -->
	<button
		type="button"
		class="asm-add-btn"
		onclick={addBranch}
		data-testid="as-add-branch"
	>
		{t('admin.conditional_access.auth_strength.add_branch')}
	</button>

	{#if showValidation && hasEmpty}
		<div class="asm-validation" role="alert" data-testid="as-empty-matrix-msg">
			{t('admin.conditional_access.auth_strength.empty_matrix')}
		</div>
	{/if}
</div>

<style>
	.asm {
		display: flex;
		flex-direction: column;
		gap: 0;
		font-family: var(--font-sans);
	}

	.asm-branch {
		border: 1px solid var(--border-subtle);
		border-radius: var(--radius-sm);
		padding: 12px;
		margin: 0;
		display: flex;
		flex-direction: column;
		gap: 8px;
		/* cross-fade on add/remove */
		transition: opacity var(--duration-fast) var(--ease-out);
	}

	.asm-branch-head {
		display: flex;
		align-items: center;
		justify-content: space-between;
	}

	.asm-legend {
		font-size: var(--text-xs);
		font-weight: var(--weight-medium);
		color: var(--text-tertiary);
		padding: 0;
	}

	.asm-factors {
		display: flex;
		flex-wrap: wrap;
		gap: 10px 16px;
	}

	.asm-echo {
		font-size: var(--text-xs);
		color: var(--text-secondary);
		font-style: italic;
		min-height: 1.4em;
	}

	.asm-or-divider {
		display: flex;
		align-items: center;
		gap: 8px;
		margin: 8px 0;
	}

	.asm-or-rule {
		flex: 1;
		height: 1px;
		background: var(--border-subtle);
	}

	.asm-or-word {
		font-size: var(--text-2xs);
		color: var(--text-tertiary);
		font-weight: var(--weight-medium);
		letter-spacing: 0.05em;
	}

	.asm-add-btn {
		align-self: flex-start;
		margin-top: 10px;
		padding: 6px 12px;
		border: 1px dashed var(--border-default);
		border-radius: var(--radius-sm);
		background: transparent;
		color: var(--text-secondary);
		font-family: var(--font-sans);
		font-size: var(--text-sm);
		cursor: pointer;
		transition: background var(--duration-fast) var(--ease-out),
			border-color var(--duration-fast) var(--ease-out);
	}
	.asm-add-btn:hover {
		background: var(--surface-hover);
		border-color: var(--border-strong);
		color: var(--text-primary);
	}
	.asm-add-btn:focus-visible {
		outline: none;
		box-shadow: var(--focus-ring);
	}

	.asm-validation {
		margin-top: 8px;
		padding: 6px 10px;
		border-radius: var(--radius-xs);
		background: var(--danger-bg);
		color: var(--danger-fg);
		font-size: var(--text-xs);
		border: 1px solid var(--danger-solid);
	}

	@media (prefers-reduced-motion: reduce) {
		.asm-branch { transition: none; }
		.asm-add-btn { transition: none; }
	}

	@media (pointer: coarse) {
		.asm-add-btn { min-height: 44px; }
		.asm-branch-head :global(.sj-iconbtn) { min-height: 44px; min-width: 44px; }
	}
</style>
