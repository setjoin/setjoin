<svelte:options runes={true} />

<script lang="ts">
	import { toasts, dismissToast, pauseToast, resumeToast } from './toasts.svelte';

	let pendingActions = $state(new Set<number>());

	async function runAction(id: number, onAction?: () => void | Promise<void>) {
		if (!onAction || pendingActions.has(id)) return;
		pendingActions = new Set(pendingActions).add(id);
		pauseToast(id);
		try {
			await onAction();
			dismissToast(id);
		} catch {
			const next = new Set(pendingActions);
			next.delete(id);
			pendingActions = next;
			resumeToast(id);
		}
	}
</script>

<div class="sj-toast-stack">
	{#each toasts as toast (toast.id)}
		<div
			class="sj-toast"
			class:sj-toast--success={toast.variant === 'success'}
			class:sj-toast--danger={toast.variant === 'danger'}
			role={toast.variant === 'danger' ? 'alert' : 'status'}
			onmouseenter={() => pauseToast(toast.id)}
			onmouseleave={() => { if (!pendingActions.has(toast.id)) resumeToast(toast.id); }}
			onfocusin={() => pauseToast(toast.id)}
			onfocusout={() => { if (!pendingActions.has(toast.id)) resumeToast(toast.id); }}
		>
			<span>{toast.message}</span>
			{#if toast.actionLabel}
				<button
					type="button"
					class="sj-toast__action"
					disabled={pendingActions.has(toast.id)}
					aria-busy={pendingActions.has(toast.id)}
					onclick={() => runAction(toast.id, toast.onAction)}
				>
					{toast.actionLabel}
				</button>
			{/if}
			<button
				type="button"
				class="sj-toast__x"
				aria-label="Dismiss"
				onclick={() => dismissToast(toast.id)}
			>
				<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
					<path d="M18 6 6 18M6 6l12 12" />
				</svg>
			</button>
		</div>
	{/each}
</div>

<style>
	.sj-toast-stack {
		position: fixed;
		left: 16px;
		bottom: 16px;
		z-index: 1100;
		display: flex;
		flex-direction: column;
		align-items: flex-start;
		gap: 8px;
	}
	.sj-toast {
		display: inline-flex;
		align-items: center;
		gap: 14px;
		min-height: 40px;
		padding: 8px 8px 8px 14px;
		background: var(--surface-inverse);
		color: var(--text-inverse);
		border-radius: var(--radius-md);
		box-shadow: var(--shadow-lg);
		font-family: var(--font-sans);
		font-size: var(--text-sm);
		animation: sj-toast-in var(--duration-base) var(--ease-out);
	}
	.sj-toast__action {
		border: none;
		background: transparent;
		color: var(--indigo-300);
		cursor: pointer;
		font-family: inherit;
		font-size: var(--text-sm);
		font-weight: var(--weight-semibold);
		padding: 4px 8px;
		border-radius: var(--radius-sm);
	}
	.sj-toast__action:hover {
		background: rgb(255, 255, 255, 0.1);
		color: var(--indigo-200);
	}
	.sj-toast__action:disabled {
		cursor: wait;
		opacity: 0.7;
	}
	.sj-toast__action:focus-visible {
		outline: none;
		box-shadow: var(--focus-ring);
	}
	.sj-toast__x {
		border: none;
		background: transparent;
		color: var(--gray-400);
		cursor: pointer;
		width: 24px;
		height: 24px;
		border-radius: var(--radius-sm);
		display: flex;
		align-items: center;
		justify-content: center;
		padding: 0;
	}
	.sj-toast__x:hover {
		background: rgb(255, 255, 255, 0.1);
		color: var(--gray-200);
	}
	.sj-toast__x:focus-visible {
		outline: none;
		box-shadow: var(--focus-ring);
	}
	.sj-toast--success {
		background: var(--success-bg);
		color: var(--success-fg);
	}
	.sj-toast--danger {
		background: var(--danger-bg);
		color: var(--danger-fg);
	}

	@keyframes sj-toast-in {
		from { opacity: 0; transform: translateY(8px); }
		to { opacity: 1; transform: none; }
	}

	@media (prefers-reduced-motion: reduce) {
		.sj-toast {
			animation: none;
		}
	}

	@media (pointer: coarse) {
		.sj-toast__action,
		.sj-toast__x {
			min-width: calc(var(--control-height-lg) + var(--space-1));
			min-height: calc(var(--control-height-lg) + var(--space-1));
		}
	}
</style>
