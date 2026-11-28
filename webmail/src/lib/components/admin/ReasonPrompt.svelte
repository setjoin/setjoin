<svelte:options runes={true} />

<!--
  ReasonPrompt — compliance-required reason field.
  Use inline (inside an existing form) or inside a Dialog for bare-button ops.
  ponytail: module-level lastReason persists for the session (survives
  unmount/remount), scoped per area so a reason never carries across actions
-->

<script module lang="ts">
	// Module-level: survives component unmount, shared across all instances.
	// ponytail: plain Record (no reactivity needed — only read at mount time).
	// Remember-last is scoped PER AREA: a reason describes THIS action, so the
	// last 'roles' reason must never pre-fill an 'identity' prompt (audit
	// reason-carryover). Repeats within the same area still pre-fill.
	const lastReasons: Record<string, string> = {};

	export function getLastReason(area: string) { return lastReasons[area]; }
	export function setLastReason(area: string, v: string) { lastReasons[area] = v; }
</script>

<script lang="ts">
	import { Textarea, Button } from '$lib/components/ui';
	import { t } from '$lib/i18n';

	interface Props {
		/** The permission-domain area, e.g. 'roles', 'audit', 'identity'. */
		area: string;
		onSubmit: (reason: string) => void;
		onCancel?: () => void;
		submitLabel?: string;
	}

	let { area, onSubmit, onCancel, submitLabel }: Props = $props();

	// Pre-fill with this area's last-used reason (remember-last, area-scoped),
	// editable. Captured once at init via the closure below — `area` is fixed
	// for a prompt instance, so the initial capture is intended.
	function areaInitialReason(): string {
		return lastReasons[area] ?? '';
	}
	let reason = $state(areaInitialReason());

	const trimmed = $derived(reason.trim());
	const canSubmit = $derived(trimmed.length > 0);

	function submit() {
		if (!canSubmit) return;
		lastReasons[area] = trimmed;
		onSubmit(trimmed);
	}
</script>

<div class="sj-reason-prompt">
	<Textarea
		label={t('admin.audit.reason.label')}
		hint={t('admin.audit.reason.helper', { area })}
		bind:value={reason}
		rows={3}
		maxlength={1000}
		placeholder={t('admin.audit.reason.placeholder')}
	/>
	<div class="sj-reason-prompt__actions">
		<Button variant="primary" disabled={!canSubmit} onclick={submit}>
			{submitLabel ?? t('admin.audit.reason.submit')}
		</Button>
		{#if onCancel}
			<Button variant="ghost" onclick={onCancel}>{t('common.cancel')}</Button>
		{/if}
	</div>
</div>

<style>
	.sj-reason-prompt {
		display: flex;
		flex-direction: column;
		gap: var(--space-3);
	}
	.sj-reason-prompt__actions {
		display: flex;
		gap: var(--space-2);
		justify-content: flex-end;
	}
</style>
