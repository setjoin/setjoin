<svelte:options runes={true} />

<!--
	ChannelComplianceSheet — per-channel drill-in dialog (Chat A4a Task 12):
	classification upgrade, retention override, legal hold set/release,
	members, and the audit pane (recent acts + Verify chain + Download
	evidence). Copy source for the confirm-overlay shape: approvals/+page.svelte
	(:396-415); the verdict card renders EXACTLY the three outcomes verdict.ts
	computes — there is no ⚠/"probably fine" fourth state anywhere here.
-->
<script lang="ts">
	import { Dialog, Button, Badge, Input, Select, Spinner, ConfirmDestructive } from '$lib/components/ui';
	import { t, formatDateTime } from '$lib/i18n';
	import { parseError } from '$lib/errors';
	import {
		adminSetChatChannelHold,
		adminSetChatChannelClassification,
		adminSetChatChannelRetention,
		adminGetChatChannelAudit,
		adminVerifyChatChannelAudit,
		chatChannelAuditCsvUrl,
		type ChatChannelRow,
		type ChatAuditAct,
		type ChatAuditVerifyResult,
	} from '$lib/admin/client';
	import { channelDisplayName, retentionLabel } from './channels.svelte';
	import { computeChatVerdict } from './verdict';

	interface Props {
		open: boolean;
		channel: ChatChannelRow | null;
		canManage: boolean;
		onClose: () => void;
		/** Fired after any mutation — the parent reloads the channel list row. */
		onChanged: () => void;
	}

	let { open, channel, canManage, onClose, onChanged }: Props = $props();

	let displayName = $derived(channel ? channelDisplayName(channel) : '');
	let effectiveLabel = $derived(channel ? retentionLabel(channel) : '');

	// ── classification upgrade (regular -> gxp; no downgrade is offered) ──────
	let upgradeRetentionDaysStr = $state('30');
	let upgradeWormMode = $state<'governance' | 'compliance'>('governance');
	let upgradeConfirmOpen = $state(false);
	let upgrading = $state(false);
	let upgradeError = $state('');

	const WORM_MODE_OPTIONS = [
		{ value: 'governance', label: t('admin.chatCompliance.sheet.wormMode.governance') },
		{ value: 'compliance', label: t('admin.chatCompliance.sheet.wormMode.compliance') },
	];

	function openUpgradeConfirm() {
		upgradeError = '';
		upgradeConfirmOpen = true;
	}

	async function confirmUpgrade() {
		if (!channel) return;
		upgrading = true;
		upgradeError = '';
		try {
			await adminSetChatChannelClassification(channel.id, Number(upgradeRetentionDaysStr) || 0, upgradeWormMode);
			upgradeConfirmOpen = false;
			onChanged();
		} catch (e) {
			upgradeError = parseError(e).message;
		} finally {
			upgrading = false;
		}
	}

	// ── per-channel retention override (immediate-by-design, FIX 3) ──────────
	let overrideStr = $state('');
	let overrideError = $state('');
	let overrideSaving = $state(false);
	let overrideConfirmOpen = $state(false);

	$effect(() => {
		overrideStr = channel?.retentionDays != null ? String(channel.retentionDays) : '';
		overrideError = '';
		overrideConfirmOpen = false;
	});

	let overrideShortens = $derived.by(() => {
		if (!channel || overrideStr.trim() === '') return false;
		const n = Number(overrideStr);
		if (!(n > 0)) return false;
		return channel.effectiveRetentionDays == null || n < channel.effectiveRetentionDays;
	});

	function submitOverride() {
		if (overrideShortens) {
			overrideConfirmOpen = true;
		} else {
			void saveOverride();
		}
	}

	async function saveOverride() {
		if (!channel) return;
		overrideSaving = true;
		overrideError = '';
		try {
			const val = overrideStr.trim() === '' ? null : Number(overrideStr);
			await adminSetChatChannelRetention(channel.id, val);
			overrideConfirmOpen = false;
			onChanged();
		} catch (e) {
			overrideError = parseError(e).message;
		} finally {
			overrideSaving = false;
		}
	}

	// ── legal hold set / release (N8: release is matter-scoped) ─────────────
	let holdReasonStr = $state('');
	let releaseReasonStr = $state('');
	let holdBusy = $state(false);
	let holdError = $state('');
	let releaseConfirmOpen = $state(false);

	$effect(() => {
		holdReasonStr = '';
		releaseReasonStr = channel?.legalHoldReason ?? '';
		holdError = '';
		releaseConfirmOpen = false;
	});

	let releaseMatches = $derived(
		releaseReasonStr.trim() !== '' && releaseReasonStr === (channel?.legalHoldReason ?? '')
	);

	async function setHold() {
		if (!channel || holdReasonStr.trim() === '') return;
		holdBusy = true;
		holdError = '';
		try {
			await adminSetChatChannelHold(channel.id, true, holdReasonStr.trim());
			onChanged();
		} catch (e) {
			holdError = parseError(e).message;
		} finally {
			holdBusy = false;
		}
	}

	async function confirmRelease() {
		if (!channel) return;
		holdBusy = true;
		holdError = '';
		try {
			await adminSetChatChannelHold(channel.id, false, releaseReasonStr.trim());
			releaseConfirmOpen = false;
			onChanged();
		} catch (e) {
			holdError = parseError(e).message;
		} finally {
			holdBusy = false;
		}
	}

	// ── audit pane: recent acts + verify chain + CSV evidence ────────────────
	let acts = $state<ChatAuditAct[]>([]);
	let actsLoading = $state(false);
	let actsError = $state('');

	let verifyState = $state<'idle' | 'verifying' | 'done' | 'error'>('idle');
	let verifyResult = $state<ChatAuditVerifyResult | null>(null);
	let verifyError = $state('');

	$effect(() => {
		acts = [];
		actsError = '';
		verifyState = 'idle';
		verifyResult = null;
		verifyError = '';
		if (channel) void loadAudit(channel.id);
	});

	async function loadAudit(channelId: number) {
		actsLoading = true;
		actsError = '';
		try {
			acts = await adminGetChatChannelAudit(channelId, { limit: 20 });
		} catch (e) {
			actsError = parseError(e).message;
		} finally {
			actsLoading = false;
		}
	}

	async function runVerify() {
		if (!channel) return;
		verifyState = 'verifying';
		verifyError = '';
		try {
			verifyResult = await adminVerifyChatChannelAudit(channel.id);
			verifyState = 'done';
		} catch (e) {
			verifyError = parseError(e).message;
			verifyState = 'error';
		}
	}

	function downloadEvidence() {
		if (!channel) return;
		window.open(chatChannelAuditCsvUrl(channel.id), '_blank');
	}

	let verdict = $derived(verifyResult ? computeChatVerdict(verifyResult) : null);
</script>

{#if channel}
	<Dialog {open} title={displayName || t('admin.chatCompliance.sheet.title')} {onClose} wide>
		{#snippet children()}
			<div class="ccs">
				<div class="ccs-header">
					<Badge
						variant={channel.classification === 'gxp' ? 'accent' : 'neutral'}
						label={t(`admin.chatCompliance.class.${channel.classification}`)}
					/>
					{#if channel.legalHold}
						<Badge variant="danger" label={t('admin.chatCompliance.channels.holdBadge')} />
					{/if}
					<span class="ccs-retention">{effectiveLabel}</span>
					<span class="ccs-members">
						{t('admin.chatCompliance.sheet.members', { n: String(channel.memberCount) })}
					</span>
				</div>

				<!-- Classification upgrade -->
				{#if canManage && channel.classification === 'regular'}
					<section class="ccs-section">
						<h3 class="ccs-section__title">{t('admin.chatCompliance.sheet.classification_label')}</h3>
						<div class="ccs-row">
							<Input
								type="number"
								min="1"
								label={t('admin.chatCompliance.sheet.upgradeRetentionDays_label')}
								bind:value={upgradeRetentionDaysStr}
							/>
							<Select
								label={t('admin.chatCompliance.sheet.upgradeWormMode_label')}
								bind:value={upgradeWormMode}
								options={WORM_MODE_OPTIONS}
							/>
							<Button variant="secondary" size="sm" onclick={openUpgradeConfirm}>
								{t('admin.chatCompliance.sheet.upgradeToGxp')}
							</Button>
						</div>
						{#if upgradeError}<p class="ccs-error" role="alert">{upgradeError}</p>{/if}
					</section>
				{/if}

				<!-- Retention override -->
				{#if canManage}
					<section class="ccs-section">
						<h3 class="ccs-section__title">{t('admin.chatCompliance.sheet.retentionOverride_label')}</h3>
						<div class="ccs-row">
							<Input
								type="number"
								min="1"
								label={t('admin.chatCompliance.sheet.retentionOverride_label')}
								bind:value={overrideStr}
								disabled={overrideSaving}
							/>
							<Button variant="secondary" size="sm" onclick={submitOverride} disabled={overrideSaving}>
								{t('admin.chatCompliance.sheet.retentionOverrideSave')}
							</Button>
						</div>
						<p class="ccs-hint">{t('admin.chatCompliance.sheet.retentionOverrideHint')}</p>
						{#if overrideError}<p class="ccs-error" role="alert">{overrideError}</p>{/if}
					</section>
				{/if}

				<!-- Legal hold -->
				{#if canManage}
					<section class="ccs-section">
						<h3 class="ccs-section__title">{t('admin.chatCompliance.sheet.holdToggle_label')}</h3>
						{#if channel.legalHold}
							<p class="ccs-hint">{channel.legalHoldReason}</p>
							<div class="ccs-row">
								<Input
									label={t('admin.chatCompliance.sheet.holdReason_label')}
									bind:value={releaseReasonStr}
									disabled={holdBusy}
								/>
								<Button
									variant="danger"
									size="sm"
									disabled={holdBusy || !releaseMatches}
									onclick={() => (releaseConfirmOpen = true)}
								>
									{t('admin.chatCompliance.sheet.holdReleaseConfirmTitle')}
								</Button>
							</div>
						{:else}
							<div class="ccs-row">
								<Input
									label={t('admin.chatCompliance.sheet.holdReason_label')}
									bind:value={holdReasonStr}
									disabled={holdBusy}
								/>
								<Button
									variant="secondary"
									size="sm"
									disabled={holdBusy || holdReasonStr.trim() === ''}
									onclick={setHold}
								>
									{t('admin.chatCompliance.sheet.holdSet')}
								</Button>
							</div>
						{/if}
						{#if holdError}<p class="ccs-error" role="alert">{holdError}</p>{/if}
					</section>
				{/if}

				<!-- Members -->
				{#if channel.participants.length > 0}
					<section class="ccs-section">
						<h3 class="ccs-section__title">{t('admin.chatCompliance.sheet.members', { n: String(channel.memberCount) })}</h3>
						<ul class="ccs-members-list">
							{#each channel.participants as p (p.userId)}
								<li>{p.displayName || p.email}</li>
							{/each}
						</ul>
					</section>
				{/if}

				<!-- Audit -->
				<section class="ccs-section">
					<h3 class="ccs-section__title">{t('admin.chatCompliance.sheet.auditTitle')}</h3>
					{#if actsLoading}
						<Spinner />
					{:else if actsError}
						<p class="ccs-error" role="alert">{actsError}</p>
					{:else}
						<div class="ccs-audit-scroll">
							<table class="ccs-audit-table">
								<thead>
									<tr>
										<th>{t('admin.chatCompliance.sheet.auditTitle')}</th>
									</tr>
								</thead>
								<tbody>
									{#each acts as act (act.id)}
										<tr>
											<td>
												<span class="ccs-mono">{formatDateTime(act.occurredAt)}</span>
												<span class="ccs-action">{act.action}</span>
												{#if act.notes}<span class="ccs-hint">{act.notes}</span>{/if}
											</td>
										</tr>
									{/each}
								</tbody>
							</table>
						</div>
					{/if}

					<div class="ccs-row">
						<Button variant="secondary" size="sm" disabled={verifyState === 'verifying'} onclick={runVerify}>
							{verifyState === 'verifying' ? t('admin.chatCompliance.sheet.verifying') : t('admin.chatCompliance.sheet.verifyChain')}
						</Button>
						<Button variant="ghost" size="sm" onclick={downloadEvidence}>
							{t('admin.chatCompliance.sheet.downloadEvidence')}
						</Button>
					</div>

					{#if verifyError}<p class="ccs-error" role="alert">{verifyError}</p>{/if}

					{#if verdict && verifyResult}
						<div class="ccs-verdict ccs-verdict--{verdict.kind}" role="status">
							{#if verdict.kind === 'pass'}
								<p class="ccs-verdict__title">✓ {t('admin.chatCompliance.verdict.pass')}</p>
								<p class="ccs-verdict__detail">
									{t('admin.chatCompliance.verdict.summary', {
										checked: String(verifyResult.checked),
										fromId: String(verifyResult.fromId ?? '—'),
										toId: String(verifyResult.toId ?? '—'),
										anchors: String(verifyResult.anchors?.length ?? 0),
										keyVersion: verifyResult.keyVersion,
										verifiedAt: verifyResult.verifiedAt,
									})}
								</p>
								{#each (verifyResult.anchors ?? []).filter((a) => a.reconciledFromPurge > 0) as a (a.anchorId)}
									<p class="ccs-verdict__neutral">
										{t('admin.chatCompliance.verdict.reconciled', { n: String(a.reconciledFromPurge) })}
									</p>
								{/each}
							{:else if verdict.kind === 'broken'}
								<p class="ccs-verdict__title">
									✗ {verdict.truncated ? t('admin.chatCompliance.verdict.truncated') : t('admin.chatCompliance.verdict.broken')}
								</p>
								{#if verdict.truncated}
									<p class="ccs-verdict__detail">
										{t('admin.chatCompliance.verdict.truncatedAt', {
											live: String(verifyResult.liveHead?.id ?? '—'),
											notarized: String(verifyResult.notarizedHead?.id ?? '—'),
										})}
									</p>
								{:else}
									<p class="ccs-verdict__detail">
										{t('admin.chatCompliance.verdict.brokenAt', { id: String(verifyResult.firstInvalid ?? '—') })}
									</p>
								{/if}
							{:else}
								<p class="ccs-verdict__title">✗ {t('admin.chatCompliance.verdict.altered')}</p>
								{#each (verifyResult.anchors ?? []).filter((a) => !a.valid) as a (a.anchorId)}
									<p class="ccs-verdict__detail">
										{t('admin.chatCompliance.verdict.alteredAnchor', {
											id: String(a.anchorId),
											from: String(a.idFrom),
											to: String(a.idTo),
										})}
									</p>
								{/each}
								{#each (verifyResult.anchors ?? []).filter((a) => a.revisionsUnchained > 0) as a (a.anchorId)}
									<p class="ccs-verdict__detail">
										{t('admin.chatCompliance.verdict.alteredRevisions', { n: String(a.revisionsUnchained) })}
									</p>
								{/each}
							{/if}
						</div>
					{/if}
				</section>
			</div>
		{/snippet}
	</Dialog>

	<ConfirmDestructive
		open={upgradeConfirmOpen}
		title={t('admin.chatCompliance.sheet.upgradeConfirmTitle')}
		message={t('admin.chatCompliance.sheet.upgradeConfirmMessage', { n: upgradeRetentionDaysStr })}
		confirmWord={displayName || 'DESTROY'}
		confirmLabel={t('admin.chatCompliance.sheet.upgradeToGxp')}
		busy={upgrading}
		error={upgradeError}
		onConfirm={confirmUpgrade}
		onCancel={() => (upgradeConfirmOpen = false)}
	/>

	<ConfirmDestructive
		open={overrideConfirmOpen}
		title={t('admin.chatCompliance.sheet.retentionShortenConfirmTitle')}
		message={t('admin.chatCompliance.sheet.retentionShortenConfirmMessage', { n: overrideStr })}
		confirmWord="DESTROY"
		confirmLabel={t('admin.chatCompliance.sheet.retentionOverrideSave')}
		busy={overrideSaving}
		error={overrideError}
		onConfirm={saveOverride}
		onCancel={() => (overrideConfirmOpen = false)}
	/>

	<ConfirmDestructive
		open={releaseConfirmOpen}
		title={t('admin.chatCompliance.sheet.holdReleaseConfirmTitle')}
		message={t('admin.chatCompliance.sheet.holdReleaseConfirmMessage')}
		confirmWord="DESTROY"
		confirmLabel={t('admin.chatCompliance.sheet.holdReleaseConfirmTitle')}
		busy={holdBusy}
		error={holdError}
		onConfirm={confirmRelease}
		onCancel={() => (releaseConfirmOpen = false)}
	/>
{/if}

<style>
	.ccs {
		display: flex;
		flex-direction: column;
		gap: var(--space-4);
		min-width: 480px;
	}
	.ccs-header {
		display: flex;
		align-items: center;
		gap: var(--space-3);
		flex-wrap: wrap;
	}
	.ccs-retention {
		font-size: var(--text-sm);
		color: var(--text-secondary);
	}
	.ccs-members {
		font-size: var(--text-xs);
		color: var(--text-tertiary);
	}
	.ccs-section {
		display: flex;
		flex-direction: column;
		gap: var(--space-2);
		border-top: 1px solid var(--border-subtle);
		padding-top: var(--space-3);
	}
	.ccs-section__title {
		font-size: var(--text-sm);
		font-weight: var(--weight-semibold);
		color: var(--text-primary);
		margin: 0;
	}
	.ccs-row {
		display: flex;
		align-items: flex-end;
		gap: var(--space-2);
		flex-wrap: wrap;
	}
	.ccs-hint {
		font-size: var(--text-xs);
		color: var(--text-tertiary);
		margin: 0;
	}
	.ccs-error {
		font-size: var(--text-xs);
		color: var(--text-danger);
		margin: 0;
	}
	.ccs-members-list {
		margin: 0;
		padding-left: var(--space-4);
		font-size: var(--text-sm);
		color: var(--text-secondary);
	}
	.ccs-audit-scroll {
		overflow-x: auto;
	}
	.ccs-audit-table {
		width: 100%;
		border-collapse: collapse;
		font-size: var(--text-xs);
	}
	.ccs-audit-table td {
		padding: var(--space-1) 0;
		border-bottom: 1px solid var(--border-subtle);
		white-space: nowrap;
	}
	.ccs-mono {
		font-family: var(--font-mono);
		color: var(--text-tertiary);
		margin-right: var(--space-2);
	}
	.ccs-action {
		font-weight: var(--weight-medium);
		color: var(--text-primary);
		margin-right: var(--space-2);
	}
	.ccs-verdict {
		border-radius: var(--radius-md);
		padding: var(--space-3);
		display: flex;
		flex-direction: column;
		gap: var(--space-1);
	}
	.ccs-verdict--pass {
		background: var(--success-bg);
	}
	.ccs-verdict--broken,
	.ccs-verdict--altered {
		background: var(--danger-bg);
	}
	.ccs-verdict__title {
		font-size: var(--text-sm);
		font-weight: var(--weight-semibold);
		margin: 0;
	}
	.ccs-verdict--pass .ccs-verdict__title {
		color: var(--success-fg);
	}
	.ccs-verdict--broken .ccs-verdict__title,
	.ccs-verdict--altered .ccs-verdict__title {
		color: var(--danger-fg);
	}
	.ccs-verdict__detail {
		font-size: var(--text-xs);
		color: var(--text-secondary);
		margin: 0;
	}
	.ccs-verdict__neutral {
		font-size: var(--text-xs);
		color: var(--text-tertiary);
		margin: 0;
	}
</style>
