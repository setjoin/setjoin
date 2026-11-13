<script lang="ts">
	type BadgeVariant = 'neutral' | 'success' | 'warning' | 'danger' | 'info' | 'accent';

	interface Props {
		variant?: BadgeVariant;
		dot?: boolean;
		label?: string;
		/** When set, renders the mono count pill (variant/dot/label are ignored). >99 displays as "99+". */
		count?: number;
	}

	let { variant = 'neutral', dot = false, label = '', count }: Props = $props();

	const VARIANTS: Record<BadgeVariant, { bg: string; fg: string; dot: string }> = {
		neutral: { bg: 'var(--gray-100)', fg: 'var(--gray-600)', dot: 'var(--gray-400)' },
		success: { bg: 'var(--success-bg)', fg: 'var(--success-fg)', dot: 'var(--success-solid)' },
		warning: { bg: 'var(--warning-bg)', fg: 'var(--warning-fg)', dot: 'var(--warning-solid)' },
		danger: { bg: 'var(--danger-bg)', fg: 'var(--danger-fg)', dot: 'var(--danger-solid)' },
		info: { bg: 'var(--info-bg)', fg: 'var(--info-fg)', dot: 'var(--info-solid)' },
		accent: { bg: 'var(--accent-subtle)', fg: 'var(--accent-fg-on-subtle)', dot: 'var(--accent)' }
	};

	const v = $derived(VARIANTS[variant]);
</script>

{#if count !== undefined}
	<span class="badge badge--count">{count > 99 ? '99+' : count}</span>
{:else}
	<span class="badge" style="background: {v.bg}; color: {v.fg};">
		{#if dot}<span class="badge__dot" style="background: {v.dot};"></span>{/if}
		{label}
	</span>
{/if}

<style>
	.badge {
		display: inline-flex;
		align-items: center;
		gap: 5px;
		height: 20px;
		padding: 0 7px;
		border-radius: var(--radius-full);
		font-family: var(--font-sans);
		font-size: var(--text-2xs);
		font-weight: var(--weight-semibold);
		letter-spacing: 0.02em;
		white-space: nowrap;
	}
	.badge__dot {
		width: 6px;
		height: 6px;
		border-radius: var(--radius-full);
		flex: none;
	}
	.badge--count {
		background: var(--accent);
		color: var(--text-inverse);
		min-width: 18px;
		justify-content: center;
		padding: 0 5px;
		font-family: var(--font-mono);
	}
</style>
