<svelte:options runes={true} />

<script lang="ts">
	import { onMount } from 'svelte';
	import { t } from '$lib/i18n';
	import { parseError } from '$lib/errors';
	import { logger } from '$lib/logger';
	import { loadSession } from '$lib/jmap/client';
	import { directorySearch, setDirectoryAccountId } from '$lib/stores/directory';
	import type { DirectoryMember } from '$lib/stores/directory';
	import { Card, Switch, Input, Button, showToast, Toast, Spinner } from '$lib/components/ui';

	// Wire shape for GET/PUT /user/approval-delegation (matches Go ApprovalDelegation).
	// Identity (the delegator) is derived server-side from the JWT — never sent here.
	interface DelegationWire {
		enabled: boolean;
		delegate_user_id: number;
		delegate_name: string;
		delegate_email: string;
		starts_at: string | null; // "2026-07-01T09:00" or null
		ends_at: string | null;
	}

	let enabled = $state(false);
	let delegateId = $state(0);
	let delegateName = $state('');
	let delegateEmail = $state('');
	let startsAt = $state('');
	let endsAt = $state('');

	// Delegate picker state (reuses the directory search primitive).
	let query = $state('');
	let results = $state<DirectoryMember[]>([]);
	let searching = $state(false);

	let loading = $state(true);
	let saving = $state(false);
	let error = $state('');

	onMount(async () => {
		try {
			await loadSession();
			setDirectoryAccountId('-1');
			const res = await fetch('/api/user/approval-delegation', { credentials: 'include' });
			if (res.ok) {
				const data = (await res.json()) as DelegationWire;
				enabled = !!data.enabled;
				delegateId = data.delegate_user_id ?? 0;
				delegateName = data.delegate_name ?? '';
				delegateEmail = data.delegate_email ?? '';
				startsAt = data.starts_at ?? '';
				endsAt = data.ends_at ?? '';
			}
		} catch (e) {
			error = parseError(e).message;
			logger.error('settings/approval-delegation: failed to load', e);
		}
		loading = false;
	});

	async function runSearch() {
		if (query.trim().length < 2) {
			results = [];
			return;
		}
		searching = true;
		try {
			results = await directorySearch(query.trim(), 8);
		} catch (e) {
			logger.error('settings/approval-delegation: directory search failed', e);
			results = [];
		}
		searching = false;
	}

	function pickDelegate(m: DirectoryMember) {
		delegateId = Number(m.id);
		delegateName = m.displayName || m.email;
		delegateEmail = m.email;
		query = '';
		results = [];
	}

	async function save() {
		error = '';

		if (enabled) {
			if (!delegateId) {
				error = t('approvalDelegation.pick_delegate_error');
				return;
			}
			// Client guard for the inverted window the reducer rejects (BZ119). The server
			// stays the source of truth; this just keeps an obviously-bad request local.
			if (startsAt && endsAt && startsAt >= endsAt) {
				error = t('approvalDelegation.date_range_error');
				return;
			}
			if (!startsAt || !endsAt) {
				error = t('approvalDelegation.date_required_error');
				return;
			}
		}

		saving = true;
		const body: DelegationWire = {
			enabled,
			delegate_user_id: enabled ? delegateId : 0,
			delegate_name: '',
			delegate_email: '',
			starts_at: enabled && startsAt ? startsAt : null,
			ends_at: enabled && endsAt ? endsAt : null
		};
		try {
			const res = await fetch('/api/user/approval-delegation', {
				method: 'PUT',
				headers: { 'Content-Type': 'application/json' },
				credentials: 'include',
				body: JSON.stringify(body)
			});
			if (res.ok) {
				showToast(t('approvalDelegation.saved'));
			} else {
				const data = (await res.json().catch(() => ({}))) as { detail?: string };
				error = data.detail || t('approvalDelegation.save_failed');
			}
		} catch (e) {
			error = parseError(e).message;
			logger.error('settings/approval-delegation: failed to save', e);
		}
		saving = false;
	}
</script>

<div class="sj-ad-page">
	<h1 class="sj-page-title">{t('approvalDelegation.title')}</h1>

	<Card title={t('approvalDelegation.card_title')}>
		{#if loading}
			<Spinner />
		{:else}
			<div class="sj-ad-stack">
				<Switch
					label={t('approvalDelegation.enable_label')}
					description={t('approvalDelegation.enable_desc')}
					bind:checked={enabled}
				/>

				{#if enabled}
					<div class="sj-ad-field">
						<span class="sj-ad-label">{t('approvalDelegation.delegate_label')}</span>
						{#if delegateId}
							<div class="sj-ad-chip">
								<span>{delegateName}{delegateEmail ? ` <${delegateEmail}>` : ''}</span>
								<Button
									variant="secondary"
									size="sm"
									onclick={() => {
										delegateId = 0;
										delegateName = '';
										delegateEmail = '';
									}}
								>
									{t('approvalDelegation.change')}
								</Button>
							</div>
						{:else}
							<Input
								placeholder={t('approvalDelegation.search_placeholder')}
								bind:value={query}
								oninput={() => runSearch()}
							/>
							{#if searching}
								<p class="sj-ad-hint">{t('approvalDelegation.searching')}</p>
							{:else if results.length > 0}
								<ul class="sj-ad-results">
									{#each results as m (m.id)}
										<li>
											<button type="button" class="sj-ad-result" onclick={() => pickDelegate(m)}>
												<span class="sj-ad-result-name">{m.displayName || m.email}</span>
												<span class="sj-ad-result-email">{m.email}</span>
											</button>
										</li>
									{/each}
								</ul>
							{/if}
						{/if}
					</div>

					<div class="sj-ad-dates">
						<Input
							type="datetime-local"
							label={t('approvalDelegation.start')}
							bind:value={startsAt}
						/>
						<Input
							type="datetime-local"
							label={t('approvalDelegation.end')}
							bind:value={endsAt}
						/>
					</div>
				{/if}

				<div class="sj-ad-actions">
					<Button
						variant="primary"
						size="sm"
						onclick={save}
						disabled={saving}
						data-testid="ad-save"
					>
						{saving ? t('approvalDelegation.saving') : t('approvalDelegation.save')}
					</Button>
				</div>

				{#if error}
					<p class="sj-ad-error" role="alert">{error}</p>
				{/if}
			</div>
		{/if}
	</Card>
</div>

<Toast />

<style>
	.sj-ad-page {
		max-width: 720px;
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

	.sj-ad-stack {
		display: flex;
		flex-direction: column;
		gap: 16px;
	}

	.sj-ad-field {
		display: flex;
		flex-direction: column;
		gap: 6px;
	}

	.sj-ad-label {
		font-size: var(--text-sm);
		font-weight: 500;
		color: var(--text-primary);
	}

	.sj-ad-chip {
		display: flex;
		align-items: center;
		justify-content: space-between;
		gap: 12px;
		padding: 8px 12px;
		border: 1px solid var(--border-default);
		border-radius: var(--radius-md);
		background: var(--surface-raised);
		color: var(--text-primary);
		font-size: var(--text-sm);
	}

	.sj-ad-results {
		list-style: none;
		margin: 0;
		padding: 0;
		border: 1px solid var(--border-default);
		border-radius: var(--radius-md);
		overflow: hidden;
	}

	.sj-ad-result {
		display: flex;
		flex-direction: column;
		gap: 2px;
		width: 100%;
		text-align: left;
		padding: 8px 12px;
		background: transparent;
		border: none;
		border-bottom: 1px solid var(--border-subtle);
		cursor: pointer;
		color: var(--text-primary);
	}

	.sj-ad-result:last-child {
		border-bottom: none;
	}

	.sj-ad-result:hover {
		background: var(--surface-hover);
	}

	.sj-ad-result-email {
		font-size: var(--text-xs);
		color: var(--text-secondary);
	}

	.sj-ad-hint {
		font-size: var(--text-sm);
		color: var(--text-secondary);
		margin: 0;
	}

	.sj-ad-dates {
		display: grid;
		grid-template-columns: 1fr 1fr;
		gap: 12px;
	}

	.sj-ad-actions {
		display: flex;
		gap: 8px;
		margin-top: 4px;
	}

	.sj-ad-error {
		font-size: var(--text-sm);
		color: var(--danger-fg);
		margin: 4px 0 0;
	}

	@container (max-width: 460px) {
		.sj-ad-dates {
			grid-template-columns: 1fr;
		}
	}
</style>
