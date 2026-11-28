<svelte:options runes={true} />

<script lang="ts">
	import { t, switchLocale, META, type Locale, locale } from '$lib/i18n';
	import { onMount } from 'svelte';
	import { Card, showToast, Toast } from '$lib/components/ui';

	let current = $state<Locale>('en');

	onMount(() => {
		const unsub = locale.subscribe((val: Locale) => { current = val; });
		return unsub;
	});

	async function select(l: Locale) {
		await switchLocale(l);
		current = l;
		showToast(t('settings.saved'));
	}

	const locales: { code: Locale; name: string; nativeName: string }[] = [
		{ code: 'en', name: 'English', nativeName: 'English' },
		{ code: 'de', name: 'German', nativeName: 'Deutsch' },
		{ code: 'zh', name: 'Chinese', nativeName: '中文' },
	];
</script>

<div class="sj-language-page">
	<h1 class="sj-page-title">{t('settings.language')}</h1>

	<Card title={t('settings.language')}>
		<p class="sj-section-desc">Choose your preferred display language. This setting is saved to your browser and applied across all SetJoin apps.</p>

		<div class="sj-locale-list">
			{#each locales as lang}
				<button
					class="sj-locale-btn"
					class:active={current === lang.code}
					aria-pressed={current === lang.code}
					onclick={() => void select(lang.code)}
				>
					<div class="sj-locale-info">
						<span class="sj-locale-name">{lang.nativeName}</span>
						<span class="sj-locale-code">{lang.name}</span>
					</div>
					{#if current === lang.code}
						<span class="sj-locale-check">&#10003;</span>
					{/if}
				</button>
			{/each}
		</div>
	</Card>

	<Card title="Regional Format">
		<p class="sj-section-desc">Date, time, and number formats follow your selected language automatically.</p>

		<div class="sj-format-preview">
			{#if current === 'en'}
				<div class="sj-format-item"><span class="sj-format-label">Date</span> <span class="sj-format-val">Jun 5, 2026</span></div>
				<div class="sj-format-item"><span class="sj-format-label">Time</span> <span class="sj-format-val">2:30 PM</span></div>
				<div class="sj-format-item"><span class="sj-format-label">Number</span> <span class="sj-format-val">1,234.56</span></div>
			{:else if current === 'de'}
				<div class="sj-format-item"><span class="sj-format-label">Date</span> <span class="sj-format-val">05.06.2026</span></div>
				<div class="sj-format-item"><span class="sj-format-label">Time</span> <span class="sj-format-val">14:30</span></div>
				<div class="sj-format-item"><span class="sj-format-label">Number</span> <span class="sj-format-val">1.234,56</span></div>
			{:else if current === 'zh'}
				<div class="sj-format-item"><span class="sj-format-label">Date</span> <span class="sj-format-val">2026年6月5日</span></div>
				<div class="sj-format-item"><span class="sj-format-label">Time</span> <span class="sj-format-val">14:30</span></div>
				<div class="sj-format-item"><span class="sj-format-label">Number</span> <span class="sj-format-val">1,234.56</span></div>
			{/if}
		</div>
	</Card>
</div>

<Toast />

<style>
	.sj-language-page {
		max-width: 640px;
		margin: 0 auto;
		padding: clamp(16px, 4vw, 28px) clamp(12px, 4vw, 24px) 48px;
	}

	.sj-page-title {
		font-size: clamp(20px, 16px + 1.2vw, 24px);
		font-weight: 600;
		letter-spacing: var(--tracking-display);
		margin: 0 0 16px;
		color: var(--text-primary);
	}

	.sj-section-desc {
		font-size: var(--text-sm);
		color: var(--text-secondary);
		margin: 0 0 12px;
	}

	.sj-locale-list {
		display: flex;
		flex-direction: column;
		gap: 8px;
	}

	.sj-locale-btn {
		display: flex;
		align-items: center;
		justify-content: space-between;
		padding: 12px 16px;
		border-radius: var(--radius-sm);
		border: 2px solid var(--border-default);
		background: var(--surface-card);
		cursor: pointer;
		font-family: inherit;
		text-align: left;
		transition: border-color 0.15s ease, background 0.15s ease;
	}

	.sj-locale-btn:hover {
		background: var(--surface-hover);
	}

	.sj-locale-btn.active {
		border-color: var(--border-accent);
		background: var(--surface-selected);
	}

	.sj-locale-name {
		font-size: var(--text-md);
		font-weight: 500;
		color: var(--text-primary);
	}

	.sj-locale-code {
		display: block;
		font-size: var(--text-sm);
		color: var(--text-tertiary);
		margin-top: 2px;
	}

	.sj-locale-check {
		width: 24px;
		height: 24px;
		display: flex;
		align-items: center;
		justify-content: center;
		color: var(--text-accent);
		font-size: 18px;
	}

	.sj-format-preview {
		display: flex;
		flex-direction: column;
		gap: 8px;
		background: var(--surface-sunken);
		border-radius: var(--radius-sm);
		padding: 12px;
	}

	.sj-format-item {
		display: flex;
		justify-content: space-between;
		align-items: center;
	}

	.sj-format-label {
		font-size: var(--text-xs);
		font-weight: 500;
		color: var(--text-tertiary);
		text-transform: uppercase;
		letter-spacing: 0.04em;
	}

	.sj-format-val {
		font-size: var(--text-md);
		color: var(--text-primary);
	}
</style>
