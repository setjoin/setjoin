<!-- TemplateWizard.svelte — 4-step first-policy wizard.
     Steps: 1=pick(pre-selected), 2=review-impact, 3=scope/exclude, 4=confirm.
     ponytail: wizard never navigates away — all state in-component. -->
<svelte:options runes={true} />

<script lang="ts">
	import { goto } from '$app/navigation';
	import { parseError } from '$lib/errors';
	import { Button, Spinner, showToast } from '$lib/components/ui';
	import { adminFetch } from '$lib/admin/client';
	import { t } from '$lib/i18n';
	import ImpactCard from '$lib/components/ca/ImpactCard.svelte';
	import { focusTrap } from '$lib/actions/focusTrap';

	interface CATemplate {
		id: number;
		slug: string;
		name: string;
		description: string;
		scope_type: string;
		conditions: unknown;
		actions: unknown;
	}

	interface Props {
		open: boolean;
		template: CATemplate;
		breakGlassIds: number[];
		authorId: number;
		onClose: () => void;
		onCreated?: (policyId: number) => void;
	}

	let { open, template, breakGlassIds, authorId, onClose, onCreated }: Props = $props();

	// ── Wizard step: 2=review, 3=scope, 4=confirm, 5=success ──
	let step = $state(2); // always start at review (template pre-selected in step 1)
	const STEPS = ['review', 'scope', 'confirm'] as const;
	type WizardStep = 'review' | 'scope' | 'confirm';

	const stepIndexOf = (s: WizardStep) => STEPS.indexOf(s);

	// ponytail: templates are born report_only — impact is moot until instantiated as a real
	// policy. Fetching with template.id would hit the wrong policy-impact endpoint (id collision).
	// ImpactCard with data=null + loading=false renders the NO-DATA state, which is correct here.

	// ── Exclude list (step 3) — pre-filled with author + break-glass ──
	// ponytail: computed via $derived so props are read reactively; the wizard never changes these props.
	const initialExcludeIds = $derived([...new Set([authorId, ...breakGlassIds])]);
	let excludeIds = $state<number[]>([]);
	let excludeIdsInit = $state(false);
	$effect(() => {
		if (!excludeIdsInit) {
			excludeIds = [...initialExcludeIds];
			excludeIdsInit = true;
		}
	});
	let bgRemoved = $state(false); // track if break-glass was removed

	// ── Create (step 4) ──
	let creating = $state(false);
	let createError = $state('');

	// ── Success arc ──
	let success = $state(false);
	let createdPolicyId = $state<number | null>(null);
	let createdPolicyName = $state('');

	// ── Step heading text ──
	const stepHeading = $derived(
		step === 2
			? t('admin.conditional_access.wizard.step.review')
			: step === 3
			? t('admin.conditional_access.wizard.step.scope')
			: step === 4
			? t('admin.conditional_access.wizard.step.confirm')
			: t('admin.conditional_access.wizard.success')
	);

	function next() {
		if (step < 4) step++;
	}

	function prev() {
		if (step > 2) step--;
	}

	// Keyboard: ArrowLeft/Right + Home/End between completed steps; Escape = guarded close.
	// ARIA tablist spec requires Home/End to first/last focusable tab.
	const FIRST_STEP = 2; // steps are numbered 2–4 (step 1 = template pick, pre-selected)
	const LAST_STEP = 4;
	function onStepperKeydown(e: KeyboardEvent, tabStep: number) {
		if (e.key === 'ArrowLeft' && tabStep > FIRST_STEP) {
			e.preventDefault();
			step = tabStep - 1;
		} else if (e.key === 'ArrowRight' && tabStep < step && tabStep < LAST_STEP) {
			e.preventDefault();
			step = tabStep + 1;
		} else if (e.key === 'Home') {
			e.preventDefault();
			step = FIRST_STEP; // jump to first completed step
		} else if (e.key === 'End') {
			e.preventDefault();
			// jump to last completed step (= current step, can't jump to a future one)
			step = Math.min(step, LAST_STEP);
		}
	}

	function removeExclude(id: number) {
		excludeIds = excludeIds.filter((x) => x !== id);
		if (breakGlassIds.includes(id)) bgRemoved = true;
	}

	// Keyboard chip removal: Backspace/Delete
	function onChipKeydown(e: KeyboardEvent, id: number) {
		if (e.key === 'Backspace' || e.key === 'Delete') {
			e.preventDefault();
			removeExclude(id);
		}
	}

	async function create() {
		creating = true;
		createError = '';
		try {
			const body = {
				state: 'report_only',
				scope_type: template.scope_type,
				exclude_users: excludeIds,
			};
			// D4: POST /admin/conditional-access/templates/{slug}/instantiate (slug in path)
			const res = await adminFetch(`/admin/conditional-access/templates/${template.slug}/instantiate`, {
				method: 'POST',
				body: JSON.stringify(body),
			});
			if (!res.ok) {
				const err = await res.json().catch(() => ({}));
				createError = (err as Record<string, string>)?.message ?? String(res.status);
				return;
			}
			const policy = await res.json();
			createdPolicyId = policy.id;
			createdPolicyName = policy.name;
			success = true;
			step = 5;
			showToast(t('admin.conditional_access.wizard.success', { name: policy.name }));
			onCreated?.(policy.id);
		} catch (e) {
			createError = parseError(e).message;
		} finally {
			creating = false;
		}
	}

	function handleDialogKeydown(e: KeyboardEvent) {
		if (e.key === 'Escape') {
			e.preventDefault();
			onClose();
		}
	}

	/** Template-slug → summary i18n key */
	function summaryKey(slug: string): string {
		return `admin.conditional_access.wizard.tmpl.${slug}.summary`;
	}

	function summaryText(slug: string): string {
		const key = summaryKey(slug) as Parameters<typeof t>[0];
		return t(key) || template.description;
	}

	// Step tabs: only steps up to current are navigable; future steps are aria-disabled
	function tabIndex(tabStep: number): number {
		return tabStep <= step ? 0 : -1;
	}
</script>

{#if open}
	<div
		class="wiz-backdrop"
		role="presentation"
		onmousedown={(e) => { if (e.target === e.currentTarget) onClose(); }}
	>
		<div
			class="wiz-dialog"
			role="dialog"
			aria-modal="true"
			aria-labelledby="wiz-title"
			tabindex="-1"
			use:focusTrap={{ onEscape: onClose }}
			onkeydown={handleDialogKeydown}
			data-testid="wizard-dialog"
		>
			<div class="wiz-head">
				<span id="wiz-title" class="wiz-title">
					{#if success}
						{t('admin.conditional_access.wizard.success', { name: createdPolicyName })}
					{:else}
						{template.name}
					{/if}
				</span>
				<button type="button" class="wiz-close" aria-label={t('common.close')} onclick={onClose}>
					<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
						<path d="M18 6 6 18M6 6l12 12" />
					</svg>
				</button>
			</div>

			{#if !success}
				<!-- Stepper (role=tablist, aria-current="step") -->
				<div class="wiz-stepper" role="tablist" data-testid="wizard-stepper">
					{#each [
						{ step: 2, id: 'review', label: t('admin.conditional_access.wizard.step.review') },
						{ step: 3, id: 'scope',  label: t('admin.conditional_access.wizard.step.scope') },
						{ step: 4, id: 'confirm', label: t('admin.conditional_access.wizard.step.confirm') },
					] as tab (tab.id)}
						<button
							type="button"
							class="wiz-step-tab"
							class:wiz-step-tab--active={step === tab.step}
							class:wiz-step-tab--done={step > tab.step}
							role="tab"
							aria-current={step === tab.step ? 'step' : undefined}
							aria-disabled={tab.step > step ? 'true' : undefined}
							tabindex={tabIndex(tab.step)}
							onclick={() => { if (tab.step <= step) step = tab.step; }}
							onkeydown={(e) => onStepperKeydown(e, tab.step)}
							data-testid="wizard-stepper-{tab.id}"
						>
							<span class="wiz-step-num">{tab.step - 1}</span>
							<span class="wiz-step-label">{tab.label}</span>
						</button>
					{/each}
				</div>

				<!-- Step heading (aria-live="polite" — announces step changes) -->
				<div
					class="wiz-step-heading"
					aria-live="polite"
					aria-atomic="true"
					data-testid="wizard-step-heading"
				>
					{stepHeading}
				</div>
			{/if}

			<!-- Step 2: Review impact -->
			{#if step === 2}
				<div class="wiz-body" data-testid="wizard-step-review">
					<p class="wiz-summary" data-testid="wizard-tmpl-summary">
						{summaryText(template.slug)}
					</p>
					<div class="wiz-impact" data-testid="wizard-impact">
						<!-- ponytail: no-data state; templates are born report_only (see script block comment) -->
					<ImpactCard policyId={template.id} />
					</div>
				</div>
			{/if}

			<!-- Step 3: Scope & exclude -->
			{#if step === 3}
				<div class="wiz-body" data-testid="wizard-step-scope">
					<p class="wiz-section-label">{t('admin.conditional_access.wizard.excluded_accounts')}</p>
					<div class="wiz-exclude-list" data-testid="wizard-exclude-list">
						{#each excludeIds as id (id)}
							<span
								class="wiz-chip"
								data-testid="wizard-exclude-chip-{id}"
							>
								<span class="wiz-chip-label">{t('admin.conditional_access.wizard.exclude_chip', { id: String(id) })}</span>
								<button
									type="button"
									class="wiz-chip-remove"
									aria-label={t('admin.conditional_access.wizard.remove_user', { id: String(id) })}
									onclick={() => removeExclude(id)}
									onkeydown={(e) => onChipKeydown(e, id)}
								>
									<svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3">
										<path d="M18 6 6 18M6 6l12 12" />
									</svg>
									<span class="sr-only">{t('admin.conditional_access.wizard.removed_user', { id: String(id) })}</span>
								</button>
							</span>
						{/each}
					</div>

					{#if bgRemoved}
						<div class="wiz-bg-warn" role="alert" data-testid="wizard-bg-warn">
							{t('admin.conditional_access.wizard.breakglass_remove_warn')}
						</div>
					{/if}
				</div>
			{/if}

			<!-- Step 4: Confirm (report-only) -->
			{#if step === 4}
				<div class="wiz-body" data-testid="wizard-step-confirm">
					<div class="wiz-report-only-panel" data-testid="wizard-report-only-panel">
						<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true">
							<circle cx="12" cy="12" r="10"/><path d="M12 16v-4M12 8h.01"/>
						</svg>
						<p>{t('admin.conditional_access.wizard.report_only_panel')}</p>
					</div>
					{#if createError}
						<div class="wiz-create-error" role="alert">{createError}</div>
					{/if}
				</div>
			{/if}

			<!-- Step 5: Success arc -->
			{#if success}
				<div class="wiz-body wiz-success" data-testid="wizard-success">
					<div class="wiz-success-icon" aria-hidden="true">
						<svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
							<path d="M20 6 9 17l-5-5"/>
						</svg>
					</div>
					<p class="wiz-success-msg">
						{t('admin.conditional_access.wizard.success', { name: createdPolicyName })}
					</p>
					<div class="wiz-success-actions">
						<Button
							variant="primary"
							onclick={() => {
								onClose();
								// Land in F1 policy editor with the new policy selected
								if (createdPolicyId != null) {
									goto(`/admin/conditional-access?policy=${createdPolicyId}`);
								} else {
									goto('/admin/conditional-access');
								}
							}}
							data-testid="wizard-open-editor-btn"
						>
							{t('admin.conditional_access.wizard.success_open_editor')}
						</Button>
						<Button
							variant="secondary"
							onclick={() => {
								onClose();
								// Land on policy impact/why view
								if (createdPolicyId != null) {
									goto(`/admin/conditional-access?policy=${createdPolicyId}&tab=impact`);
								} else {
									goto('/admin/conditional-access');
								}
							}}
							data-testid="wizard-view-impact-btn"
						>
							{t('admin.conditional_access.wizard.success_view_impact')}
						</Button>
					</div>
				</div>
			{/if}

			<!-- Footer nav -->
			{#if !success}
				<div class="wiz-footer">
					{#if step === 4}
						<Button
							variant="primary"
							disabled={creating}
							onclick={create}
							data-testid="wizard-create-btn"
						>
							{#if creating}<Spinner size={16} />{/if}
							{t('admin.conditional_access.wizard.create_confirm')}
						</Button>
						<Button variant="secondary" onclick={prev}>
							{t('common.cancel')}
						</Button>
					{:else}
						<Button variant="primary" onclick={next} data-testid="wizard-next-btn">
							{t('admin.conditional_access.wizard.next')}
						</Button>
						{#if step > 2}
							<Button variant="secondary" onclick={prev}>{t('admin.conditional_access.wizard.back')}</Button>
						{/if}
					{/if}
					<Button variant="ghost" onclick={onClose}>{t('common.cancel')}</Button>
				</div>
			{/if}
		</div>
	</div>
{/if}

<style>
	.wiz-backdrop {
		position: fixed;
		inset: 0;
		background: var(--overlay);
		z-index: 200;
		display: flex;
		align-items: center;
		justify-content: center;
		padding: 16px;
	}

	.wiz-dialog {
		background: var(--surface-card);
		border-radius: var(--radius-md);
		box-shadow: var(--shadow-lg);
		width: 100%;
		max-width: 640px;
		max-height: 90vh;
		overflow-y: auto;
		display: flex;
		flex-direction: column;
	}

	.wiz-head {
		display: flex;
		align-items: center;
		justify-content: space-between;
		padding: 16px 20px 12px;
		border-bottom: 1px solid var(--border-subtle);
	}

	.wiz-title {
		font-size: var(--text-base);
		font-weight: var(--weight-semibold);
		color: var(--text-primary);
	}

	.wiz-close {
		background: transparent;
		border: none;
		cursor: pointer;
		color: var(--text-tertiary);
		padding: 4px;
		border-radius: var(--radius-xs);
		display: flex;
		align-items: center;
		justify-content: center;
	}
	.wiz-close:hover { color: var(--text-primary); background: var(--surface-hover); }
	.wiz-close:focus-visible { outline: none; box-shadow: var(--focus-ring); }

	/* Stepper */
	.wiz-stepper {
		display: flex;
		padding: 12px 20px 0;
		gap: 2px;
		border-bottom: 1px solid var(--border-subtle);
	}

	.wiz-step-tab {
		display: flex;
		align-items: center;
		gap: 6px;
		padding: 8px 12px;
		border: none;
		background: transparent;
		cursor: pointer;
		color: var(--text-tertiary);
		font-size: var(--text-sm);
		border-bottom: 2px solid transparent;
		margin-bottom: -1px;
		transition:
			color var(--duration-fast) var(--ease-out),
			border-color var(--duration-fast) var(--ease-out);
	}
	.wiz-step-tab:focus-visible { outline: none; box-shadow: var(--focus-ring); }
	.wiz-step-tab--active {
		color: var(--text-accent);
		border-bottom-color: var(--accent);
	}
	.wiz-step-tab--done { color: var(--text-secondary); }
	.wiz-step-tab[aria-disabled="true"] {
		cursor: default;
		opacity: 0.4;
	}

	.wiz-step-num {
		width: 18px;
		height: 18px;
		border-radius: 50%;
		background: var(--surface-sunken);
		font-size: var(--text-2xs);
		font-weight: var(--weight-bold);
		display: flex;
		align-items: center;
		justify-content: center;
		flex-shrink: 0;
	}
	.wiz-step-tab--active .wiz-step-num { background: var(--accent); color: var(--text-inverse); }

	.wiz-step-label { font-weight: var(--weight-medium); }

	/* Step heading */
	.wiz-step-heading {
		padding: 12px 20px 4px;
		font-size: var(--text-xs);
		font-weight: var(--weight-medium);
		color: var(--text-tertiary);
		text-transform: uppercase;
		letter-spacing: 0.06em;
	}

	/* Body */
	.wiz-body {
		padding: 16px 20px;
		flex: 1;
		display: flex;
		flex-direction: column;
		gap: 12px;
	}

	.wiz-summary {
		margin: 0;
		font-size: var(--text-sm);
		color: var(--text-primary);
		line-height: 1.6;
	}

	.wiz-impact { margin-top: 4px; }

	.wiz-section-label {
		font-size: var(--text-xs);
		font-weight: var(--weight-medium);
		color: var(--text-tertiary);
		text-transform: uppercase;
		letter-spacing: 0.06em;
	}

	/* Exclude chips */
	.wiz-exclude-list {
		display: flex;
		flex-wrap: wrap;
		gap: 6px;
	}

	.wiz-chip {
		display: inline-flex;
		align-items: center;
		gap: 4px;
		padding: 4px 8px;
		border-radius: var(--radius-sm);
		background: var(--surface-sunken);
		border: 1px solid var(--border-subtle);
		font-size: var(--text-xs);
		color: var(--text-primary);
	}

	.wiz-chip-label { font-family: var(--font-mono); }

	.wiz-chip-remove {
		background: transparent;
		border: none;
		cursor: pointer;
		padding: 2px;
		color: var(--text-tertiary);
		display: flex;
		align-items: center;
		border-radius: var(--radius-xs);
	}
	.wiz-chip-remove:hover { color: var(--danger-fg); }
	.wiz-chip-remove:focus-visible { outline: none; box-shadow: var(--focus-ring); }

	/* Break-glass warning */
	.wiz-bg-warn {
		padding: 8px 12px;
		border-radius: var(--radius-sm);
		background: var(--warning-bg, var(--surface-sunken));
		border: 1px solid var(--warning-solid, var(--border-default));
		color: var(--warning-fg, var(--text-primary));
		font-size: var(--text-sm);
	}

	/* Report-only panel */
	.wiz-report-only-panel {
		display: flex;
		gap: 10px;
		padding: 12px 14px;
		border-radius: var(--radius-sm);
		background: var(--info-bg, var(--surface-sunken));
		border: 1px solid var(--info-solid, var(--border-default));
		color: var(--info-fg, var(--text-primary));
		font-size: var(--text-sm);
	}
	.wiz-report-only-panel p { margin: 0; }

	.wiz-create-error {
		padding: 8px 12px;
		border-radius: var(--radius-sm);
		background: var(--danger-bg);
		color: var(--danger-fg);
		border: 1px solid var(--danger-solid);
		font-size: var(--text-sm);
	}

	/* Success arc */
	.wiz-success {
		align-items: center;
		text-align: center;
		padding: 32px 20px;
	}

	.wiz-success-icon {
		width: 52px;
		height: 52px;
		border-radius: 50%;
		background: var(--success-bg);
		border: 2px solid var(--success-solid);
		color: var(--success-fg);
		display: flex;
		align-items: center;
		justify-content: center;
		margin: 0 auto;
	}

	.wiz-success-msg {
		font-size: var(--text-base);
		font-weight: var(--weight-medium);
		color: var(--text-primary);
		margin: 8px 0 0;
	}

	.wiz-success-actions {
		display: flex;
		gap: 8px;
		flex-wrap: wrap;
		justify-content: center;
		margin-top: 8px;
	}

	/* Footer */
	.wiz-footer {
		display: flex;
		align-items: center;
		gap: 8px;
		padding: 12px 20px 16px;
		border-top: 1px solid var(--border-subtle);
	}

	/* ponytail: .sr-only is in global.css — not re-defined here */

	@media (prefers-reduced-motion: reduce) {
		.wiz-step-tab { transition: none; }
		/* steps swap instantly */
	}

	@media (pointer: coarse) {
		.wiz-step-tab { min-height: 44px; }
		.wiz-chip-remove { min-width: 44px; min-height: 44px; }
		.wiz-footer :global(.sj-btn) { min-height: 44px; }
	}
</style>
