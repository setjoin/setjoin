<svelte:options runes={true} />

<script lang="ts">
	import type { Snippet } from 'svelte';
	import { focusTrap } from '$lib/actions/focusTrap';

	let {
		open = false,
		title,
		titleHtmlAttr,
		wide = false,
		onClose,
		children,
		footer
	}: {
		open?: boolean;
		title: string;
		/** Optional HTML title attribute on the heading span (tooltip + AT hover text).
		 *  Used when the visible title may be truncated and the full value must be preserved.
		 *  Omit (default) to keep the heading undecorated — preserves existing caller behaviour. */
		titleHtmlAttr?: string;
		wide?: boolean;
		onClose?: () => void;
		children: Snippet;
		footer?: Snippet;
	} = $props();

	const uid = $props.id();
	const titleId = `${uid}-title`;

	function handleBackdropMousedown(e: MouseEvent) {
		if (e.target === e.currentTarget) onClose?.();
	}
</script>

{#if open}
	<div class="sj-dialog-backdrop" role="presentation" onmousedown={handleBackdropMousedown}>
		<div
			class="sj-dialog"
			class:sj-dialog--wide={wide}
			role="dialog"
			aria-modal="true"
			aria-labelledby={titleId}
			tabindex="-1"
			use:focusTrap={{ onEscape: () => onClose?.() }}
		>
			<div class="sj-dialog__head">
				<span class="sj-dialog__title" id={titleId} title={titleHtmlAttr}>{title}</span>
				{#if onClose}
					<button type="button" class="sj-dialog__close" aria-label="Close" onclick={() => onClose?.()}>
						<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
							<path d="M18 6 6 18M6 6l12 12" />
						</svg>
					</button>
				{/if}
			</div>
			<div class="sj-dialog__body">{@render children()}</div>
			{#if footer}
				<div class="sj-dialog__footer">{@render footer()}</div>
			{/if}
		</div>
	</div>
{/if}

<style>
	.sj-dialog-backdrop {
		position: fixed;
		inset: 0;
		background: var(--scrim);
		z-index: 1000;
		display: flex;
		align-items: flex-start;
		justify-content: center;
		padding: 9vh 16px 16px;
		animation: sj-fade-in var(--duration-fast) var(--ease-out);
	}
	.sj-dialog {
		background: var(--surface-card);
		border-radius: var(--radius-lg);
		box-shadow: var(--shadow-lg);
		width: 100%;
		max-width: 440px;
		font-family: var(--font-sans);
		overflow: hidden;
		outline: none;
		animation: sj-dialog-in var(--duration-base) var(--ease-out);
		/* Bound the height and pin head/footer via flex so the body — not the
		   whole dialog — absorbs content growth. Without this the dialog grows
		   downward as async content (e.g. the EAP match-count badge) lands,
		   physically moving the footer's Save button and failing every
		   click-when-stable check. The body below is the sole scroll region. */
		display: flex;
		flex-direction: column;
		max-height: 82vh;
	}
	.sj-dialog--wide {
		max-width: 640px;
	}
	.sj-dialog__head {
		display: flex;
		align-items: center;
		justify-content: space-between;
		padding: 14px 20px 0;
	}
	.sj-dialog__title {
		font-size: var(--text-lg);
		font-weight: var(--weight-semibold);
		letter-spacing: var(--tracking-heading);
		color: var(--text-primary);
	}
	.sj-dialog__close {
		border: none;
		background: transparent;
		cursor: pointer;
		color: var(--text-tertiary);
		width: 28px;
		height: 28px;
		border-radius: var(--radius-sm);
		display: flex;
		align-items: center;
		justify-content: center;
	}
	.sj-dialog__close:hover {
		background: var(--surface-hover);
		color: var(--text-primary);
	}
	.sj-dialog__close:focus-visible {
		outline: none;
		box-shadow: var(--focus-ring);
	}
	.sj-dialog__body {
		padding: 12px 20px 20px;
		font-size: var(--text-sm);
		color: var(--text-secondary);
		line-height: var(--leading-normal);
		/* The sole scroll region: head + footer stay pinned, content grows here. */
		overflow-y: auto;
		flex: 1 1 auto;
		min-height: 0;
		overflow-wrap: anywhere;
	}
	.sj-dialog__footer {
		display: flex;
		justify-content: flex-end;
		gap: 8px;
		padding: 12px 20px;
		border-top: 1px solid var(--border-subtle);
		background: var(--gray-25);
		flex: 0 0 auto;
	}

	@keyframes sj-fade-in {
		from { opacity: 0; }
		to { opacity: 1; }
	}

	@keyframes sj-dialog-in {
		from { opacity: 0; transform: translateY(-8px) scale(0.98); }
		to { opacity: 1; transform: none; }
	}
	/* Narrow viewports: the dialog becomes a near-full-width sheet (drop the
	   backdrop's horizontal inset, lift the height cap, unclamp max-width) so
	   the editor uses the screen on mobile instead of a cramped centered card. */
	@media (max-width: 640px) {
		.sj-dialog-backdrop {
			padding: 5vh var(--space-2) var(--space-2);
		}
		.sj-dialog,
		.sj-dialog--wide {
			max-width: none;
			max-height: 90vh;
		}
	}

	@media (pointer: coarse) {
		.sj-dialog__close {
			min-width: calc(var(--control-height-lg) + var(--space-1));
			min-height: calc(var(--control-height-lg) + var(--space-1));
		}
	}

	@media (prefers-reduced-motion: reduce) {
		.sj-dialog-backdrop,
		.sj-dialog {
			animation: none;
		}
	}
</style>
