<svelte:options runes={true} />

<script lang="ts">
	import { onMount } from 'svelte';
	import { parseError } from '$lib/errors';
	import { Button, EmptyState } from '$lib/components/ui';
	import { adminFetch } from '$lib/admin/client';
	import { t } from '$lib/i18n';
	import TemplateWizard from './TemplateWizard.svelte';

	interface CATemplate {
		id: number;
		slug: string;
		name: string;
		description: string;
		scope_type: string;
		conditions: unknown;
		actions: unknown;
	}

	// ── State ──
	let templates: CATemplate[] = $state([]);
	let loading = $state(true);
	let listError = $state('');
	let policiesExist = $state(false);

	let wizardTemplate: CATemplate | null = $state(null);

	// ponytail: authorId stays 0 until a /admin/me numeric-ID endpoint is added.
	// Break-glass IDs are fetched from the live endpoint on mount.
	let authorId = $state(0);
	let breakGlassIds: number[] = $state([]);

	// ── Load ──
	onMount(load);

	async function load() {
		loading = true;
		listError = '';
		try {
			// Load templates + check if any policies exist (FIRST-TIME vs RETURN) + break-glass set
			const [tmplRes, polRes, bgRes] = await Promise.all([
				adminFetch('/admin/conditional-access/templates-list'),
				adminFetch('/admin/conditional-access/policies'),
				adminFetch('/admin/conditional-access/break-glass'),
			]);
			if (!tmplRes.ok) throw new Error(String(tmplRes.status));
			templates = await tmplRes.json();
			if (polRes.ok) {
				const policies = await polRes.json();
				policiesExist = Array.isArray(policies) && policies.length > 0;
			}
			if (bgRes.ok) {
				const bg = await bgRes.json() as { admins?: Array<{ id: number }> };
				breakGlassIds = (bg.admins ?? []).map((a) => a.id);
			}
		} catch (e) {
			listError = parseError(e).message;
		} finally {
			loading = false;
		}
	}

	function openWizard(tmpl: CATemplate) {
		wizardTemplate = tmpl;
	}

	function closeWizard() {
		wizardTemplate = null;
	}

	function handleCreated(_policyId: number) {
		policiesExist = true;
	}
</script>

<div class="sj-page">
	<header class="sj-page-head">
		<div class="sj-page-head-left">
			<h1>{t('admin.conditional_access.wizard.page_title')}</h1>
		</div>
	</header>

	{#if !loading && !listError && !policiesExist}
		<!-- FIRST-TIME: hero banner -->
		<div class="tmpl-hero" data-testid="tmpl-hero">
			<p>{t('admin.conditional_access.wizard.hero')}</p>
		</div>
	{/if}

	{#if loading}
		<div aria-busy="true" data-testid="tmpl-loading">
			<span class="sr-only" role="status">{t('common.loading')}</span>
			<div class="tmpl-grid">
				{#each [1, 2, 3] as _, i (i)}
					<div class="tmpl-skeleton" data-testid="tmpl-skeleton"></div>
				{/each}
			</div>
		</div>
	{:else if listError}
		<div class="tmpl-error" role="alert" data-testid="tmpl-error">
			<span>{t('admin.conditional_access.wizard.load_error')}</span>
			<Button variant="secondary" size="sm" onclick={load} data-testid="tmpl-retry">
				{t('common.retry')}
			</Button>
		</div>
	{:else if templates.length === 0}
		<!-- 3 seeded templates exist; this is defensive-only -->
		<EmptyState title={t('admin.conditional_access.wizard.load_error')} />
	{:else}
		<div class="tmpl-grid">
			{#each templates as tmpl (tmpl.id)}
				<button
					type="button"
					class="tmpl-card"
					onclick={() => openWizard(tmpl)}
					data-testid="tmpl-card-{tmpl.id}"
				>
					<div class="tmpl-card-icon" aria-hidden="true">
						<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75">
							<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
						</svg>
					</div>
					<div class="tmpl-card-body">
						<span class="tmpl-name">{tmpl.name}</span>
						<span class="tmpl-desc">{tmpl.description}</span>
					</div>
					<div class="tmpl-arrow" aria-hidden="true">→</div>
				</button>
			{/each}
		</div>
	{/if}
</div>

{#if wizardTemplate}
	<TemplateWizard
		open={!!wizardTemplate}
		template={wizardTemplate}
		{breakGlassIds}
		{authorId}
		onClose={closeWizard}
		onCreated={handleCreated}
	/>
{/if}

<style>
	.sj-page { max-width: 980px; }
	.sj-page-head {
		display: flex;
		align-items: flex-start;
		gap: 12px;
		margin-bottom: 16px;
		flex-wrap: wrap;
	}
	.sj-page-head-left { flex: 1 1 260px; min-width: 0; }
	.sj-page-head-left h1 {
		margin: 0;
		font-size: clamp(20px, 16px + 1.2vw, 24px);
		font-weight: 600;
		letter-spacing: var(--tracking-display);
		color: var(--text-primary);
	}

	/* Hero banner — first-time warm welcome */
	.tmpl-hero {
		padding: 14px 18px;
		border-radius: var(--radius-sm);
		background: var(--info-bg, var(--surface-sunken));
		border: 1px solid var(--info-solid, var(--border-default));
		color: var(--info-fg, var(--text-primary));
		font-size: var(--text-sm);
		margin-bottom: 20px;
	}
	.tmpl-hero p { margin: 0; }

	/* Error */
	.tmpl-error {
		display: flex;
		align-items: center;
		gap: 10px;
		padding: 10px 14px;
		border-radius: var(--radius-sm);
		background: var(--danger-bg);
		color: var(--danger-fg);
		font-size: var(--text-sm);
		margin-bottom: 12px;
	}

	/* Gallery grid */
	.tmpl-grid {
		display: grid;
		grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
		gap: 12px;
	}

	/* Template card (button) */
	.tmpl-card {
		display: flex;
		align-items: center;
		gap: 12px;
		padding: 16px;
		border: 1px solid var(--border-default);
		border-radius: var(--radius-md);
		background: var(--surface-card);
		cursor: pointer;
		text-align: left;
		font-family: var(--font-sans);
		transition:
			border-color var(--duration-fast) var(--ease-out),
			box-shadow var(--duration-fast) var(--ease-out);
	}
	.tmpl-card:hover {
		border-color: var(--accent);
		box-shadow: var(--shadow-sm);
	}
	.tmpl-card:focus-visible {
		outline: none;
		box-shadow: var(--focus-ring);
	}

	.tmpl-card-icon {
		flex-shrink: 0;
		width: 40px;
		height: 40px;
		border-radius: var(--radius-sm);
		background: var(--surface-sunken);
		display: flex;
		align-items: center;
		justify-content: center;
		color: var(--text-secondary);
	}

	.tmpl-card-body {
		flex: 1;
		min-width: 0;
		display: flex;
		flex-direction: column;
		gap: 2px;
	}

	.tmpl-name {
		font-size: var(--text-sm);
		font-weight: var(--weight-medium);
		color: var(--text-primary);
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
	}

	.tmpl-desc {
		font-size: var(--text-xs);
		color: var(--text-secondary);
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
	}

	.tmpl-arrow {
		font-size: var(--text-sm);
		color: var(--text-tertiary);
		flex-shrink: 0;
	}

	/* Skeleton */
	.tmpl-skeleton {
		height: 76px;
		border-radius: var(--radius-md);
		border: 1px solid var(--border-subtle);
		background: var(--surface-sunken);
		position: relative;
		overflow: hidden;
	}
	.tmpl-skeleton::after {
		content: '';
		position: absolute;
		inset: 0;
		background: linear-gradient(90deg, var(--gray-100) 25%, var(--gray-200) 50%, var(--gray-100) 75%);
		background-size: 400% 100%;
		animation: tmpl-shimmer var(--duration-slow) ease-in-out infinite;
	}

	/* sr-only — ponytail: global.css owns this; define inline only where global is absent in jsdom */
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

	@keyframes tmpl-shimmer {
		0% { background-position: 100% 50%; }
		100% { background-position: 0% 50%; }
	}

	@media (prefers-reduced-motion: reduce) {
		.tmpl-card { transition: none; }
		.tmpl-skeleton::after { animation: none; }
	}

	@media (pointer: coarse) {
		.tmpl-card { min-height: 64px; }
	}
</style>
