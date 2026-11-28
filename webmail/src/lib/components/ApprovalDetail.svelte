<svelte:options runes={true} />
<script lang="ts">
	import { Button, Badge, Spinner } from '$lib/components/ui';
	import Icon from '$lib/components/Icon.svelte';
	import HrEvidence from '$lib/components/HrEvidence.svelte';
	import { t } from '$lib/i18n';
	import type { ApprovalRequest, ApprovalStatus, DriveAccessApprovalPayload, DriveAccessDecisionInput } from '$lib/types/approvals';

	interface Props {
		request: ApprovalRequest | null;
		deciding: 'approve' | 'deny' | 'cancel' | null;
		decideError: string;
		decideSuccess: string;
		comment: string;
		tab: 'pending' | 'my_requests';
		onCommentChange: (v: string) => void;
		onApprove: (narrowing?: DriveAccessDecisionInput) => void;
		onDeny: () => void;
		onCancel: () => void;
		onBack: () => void;
	}

	let { request, deciding, decideError, decideSuccess, comment, tab, onCommentChange, onApprove, onDeny, onCancel, onBack }: Props = $props();

	// Live countdown
	let now = $state(Date.now());
	$effect(() => {
		const id = setInterval(() => { now = Date.now(); }, 1000);
		return () => clearInterval(id);
	});

	let timeLeft = $derived.by(() => {
		if (!request) return '';
		const diff = new Date(request.expiresAt).getTime() - now;
		if (diff <= 0) return t('approvals.detail.expired');
		const totalMin = Math.floor(diff / 60_000);
		const h = Math.floor(totalMin / 60);
		const m = totalMin % 60;
		if (h > 0) return `${h}h ${m}m`;
		return `${m}m`;
	});

	let isExpired = $derived(request ? new Date(request.expiresAt).getTime() <= now : false);
	let isDenyCommentRequired = $derived(tab === 'pending'); // comment required when denying
	let canDeny = $derived(!isDenyCommentRequired || comment.trim().length > 0);
	let isMail = $derived(request?.consumerType === 'mail.external_send' || request?.consumerType === 'mail.group_moderation');
	let isRbac = $derived(request?.consumerType === 'rbac.jit_activation');
	let isHR = $derived(request?.consumerType === 'hr.leave' || request?.consumerType === 'hr.expense');
	let isGuestInvite = $derived(request?.consumerType === 'guest.invite');
	let isDriveAccess = $derived(request?.consumerType === 'drive.access');
	let driveCaps = $state<string[]>([]);
	let drivePropagation = $state<'self' | 'children' | 'subtree'>('self');
	let driveExpiresAt = $state('');
	let driveMaxUses = $state('');
	let initializedDriveRequest = $state<number | null>(null);

	function drivePayload(): DriveAccessApprovalPayload | null {
		if (!request?.payload || request.consumerType !== 'drive.access') return null;
		return request.payload as unknown as DriveAccessApprovalPayload;
	}

	function localDateTime(value: string): string {
		const date = new Date(value);
		if (Number.isNaN(date.getTime())) return '';
		const offset = date.getTimezoneOffset() * 60_000;
		return new Date(date.getTime() - offset).toISOString().slice(0, 16);
	}

	$effect(() => {
		const payload = drivePayload();
		if (!request || !payload || initializedDriveRequest === request.id) return;
		driveCaps = [...payload.requestedCapabilities];
		drivePropagation = payload.requestedPropagation;
		driveExpiresAt = localDateTime(payload.requestedExpiresAt);
		driveMaxUses = payload.requestedMaxUses == null ? '' : String(payload.requestedMaxUses);
		initializedDriveRequest = request.id;
	});

	function toggleDriveCapability(capability: string) {
		driveCaps = driveCaps.includes(capability)
			? driveCaps.filter((value) => value !== capability)
			: [...driveCaps, capability];
	}

	function approve() {
		const payload = drivePayload();
		if (!payload) {
			onApprove();
			return;
		}
		const expiresAt = new Date(driveExpiresAt);
		if (driveCaps.length === 0 || Number.isNaN(expiresAt.getTime())) return;
		onApprove({
			capabilities: driveCaps,
			propagation: drivePropagation,
			expiresAt: expiresAt.toISOString(),
			...(driveMaxUses === '' ? {} : { maxUses: Number(driveMaxUses) }),
			expectedEpoch: payload.expectedEpoch,
		});
	}

	function statusVariant(status: ApprovalStatus): 'neutral' | 'success' | 'danger' {
		if (status === 'approved' || status === 'applied') return 'success';
		if (status === 'denied' || status === 'apply_failed') return 'danger';
		return 'neutral';
	}

	function consumerLabel(type: string): string {
		if (type === 'rbac.jit_activation') return t('approvals.consumer.rbac');
		if (type === 'mail.external_send') return t('approvals.consumer.mail_external');
		if (type === 'hr.leave') return t('approvals.consumer.hr_leave');
		if (type === 'hr.expense') return t('approvals.consumer.hr_expense');
		if (type === 'guest.invite') return t('approvals.consumer.guest_invite');
		if (type === 'drive.access') return t('approvals.consumer.drive_access');
		return t('approvals.consumer.mail_group');
	}

	function rbacPayload() {
		// payload is NOT returned by the list endpoint (approvalSelectCols omits
		// it — it is consumer-internal). Guard against undefined so the rbac
		// detail still renders (with the decide buttons) instead of throwing.
		if (!request?.payload) return null;
		const p = request.payload as Record<string, unknown>;
		return {
			roleName: String(p.role_name ?? p.roleName ?? ''),
			scope: String(p.scope ?? ''),
			justification: String(p.justification ?? ''),
			durationMinutes: Number(p.duration_minutes ?? p.durationMinutes ?? 0),
		};
	}
</script>

<div class="ad-root">
	{#if !request}
		<div class="ad-empty">
			<button class="ad-back" onclick={onBack} aria-label={t('approvals.detail.back')}>
				<Icon name="ArrowLeft" size={16} />
			</button>
			<p class="ad-empty__title">{t('approvals.detail.empty_title')}</p>
		</div>
	{:else}
		<!-- Mobile back -->
		<div class="ad-topbar">
			<button class="ad-back" onclick={onBack} aria-label={t('approvals.detail.back')}>
				<Icon name="ArrowLeft" size={16} />
			</button>
			<span class="ad-topbar__subject">{request.subject}</span>
			<Badge variant={statusVariant(request.status)} dot label={t(`approvals.status.${request.status}`)} />
		</div>

		<div class="ad-scroll">
			<!-- Header -->
			<div class="ad-header">
				<div class="ad-header__row">
					<span class="ad-label">{t('approvals.detail.requested_by')}</span>
					<span class="ad-value">{request.requesterName || request.requesterEmail}</span>
				</div>
				{#if request.approverName}
					<div class="ad-header__row">
						<span class="ad-label">{t('approvals.detail.approver')}</span>
						<span class="ad-value">{request.approverName}</span>
					</div>
				{/if}
				<div class="ad-header__row">
					<span class="ad-label">{t('approvals.detail.expires_in')}</span>
					<span class="ad-value ad-value--countdown" class:ad-value--expired={isExpired}>{timeLeft}</span>
				</div>
				<span class="ad-consumer-pill">{consumerLabel(request.consumerType)}</span>
			</div>

			<div class="ad-divider"></div>

			<!-- Evidence -->
			<div class="ad-evidence">
				<h3 class="ad-section-title">{t('approvals.detail.evidence')}</h3>

				{#if isMail && request.heldMessageHtml}
					<p class="ad-label">{t('approvals.detail.mail_preview')}</p>
					<iframe
						class="ad-mail-frame"
						title={t('approvals.detail.mail_preview')}
						sandbox=""
						srcdoc={request.heldMessageHtml}
					></iframe>
				{:else if isMail}
					<p class="ad-label">{t('approvals.detail.mail_preview')}</p>
					<p class="ad-placeholder">{request.subject}</p>
				{:else if isRbac}
					{@const rbac = rbacPayload()}
					{#if rbac}
						{#if rbac.roleName}
							<div class="ad-field">
								<span class="ad-label">{t('approvals.detail.role')}</span>
								<span class="ad-value">{rbac.roleName}</span>
							</div>
						{/if}
						{#if rbac.scope}
							<div class="ad-field">
								<span class="ad-label">{t('approvals.detail.scope')}</span>
								<span class="ad-value">{rbac.scope}</span>
							</div>
						{/if}
						{#if rbac.durationMinutes}
							<div class="ad-field">
								<span class="ad-label">{t('approvals.detail.duration')}</span>
								<span class="ad-value">{rbac.durationMinutes}{t('approvals.detail.minutesSuffix')}</span>
							</div>
						{/if}
						{#if rbac.justification}
							<div class="ad-field">
								<span class="ad-label">{t('approvals.detail.justification')}</span>
								<span class="ad-value ad-value--pre">{rbac.justification}</span>
							</div>
						{/if}
					{/if}
				{:else if isHR}
					<HrEvidence {request} />
				{:else if isGuestInvite && request.payload}
					<div class="ad-field">
						<span class="ad-label">{t('approvals.detail.guest_email')}</span>
						<span class="ad-value">{String(request.payload.invited_email ?? '')}</span>
					</div>
					<div class="ad-field">
						<span class="ad-label">{t('approvals.detail.requested_by')}</span>
						<span class="ad-value">{String(request.payload.requester_name ?? request.requesterName)}</span>
					</div>
					{#if request.payload.message}
						<div class="ad-field">
							<span class="ad-label">{t('approvals.detail.guest_message')}</span>
							<span class="ad-value ad-value--pre">{String(request.payload.message)}</span>
						</div>
					{/if}
				{:else if isDriveAccess}
					{@const drive = drivePayload()}
					{#if drive}
						<div class="ad-field"><span class="ad-label">{t('approvals.drive.node')}</span><span class="ad-value">{drive.nodeId}</span></div>
						<div class="ad-field"><span class="ad-label">{t('approvals.detail.justification')}</span><span class="ad-value ad-value--pre">{drive.reason}</span></div>
						<div class="ad-drive-summary">
							<strong>{t('approvals.drive.requested')}</strong>
							<span>{drive.requestedCapabilities.map((capability) => t(`drive.access.capability.${capability}`)).join(', ')}</span>
							<span>{t(`drive.access.scope.${drive.requestedPropagation}`)} · {new Date(drive.requestedExpiresAt).toLocaleString()}</span>
							{#if drive.emergency}<Badge variant="danger" label={t('approvals.drive.emergency')} />{/if}
						</div>
						{#if tab === 'pending' && request.status === 'pending'}
							<fieldset class="ad-drive-narrow"><legend>{t('approvals.drive.applied')}</legend>
								<p>{t('approvals.drive.narrowHint')}</p>
								{#each drive.requestedCapabilities as capability}
									<label><input type="checkbox" checked={driveCaps.includes(capability)} onchange={() => toggleDriveCapability(capability)} />{t(`drive.access.capability.${capability}`)}</label>
								{/each}
								<label>{t('approvals.detail.scope')}<select bind:value={drivePropagation}>
									<option value="self">{t('drive.access.scope.self')}</option>
									{#if drive.requestedPropagation !== 'self'}<option value="children">{t('drive.access.scope.children')}</option>{/if}
									{#if drive.requestedPropagation === 'subtree'}<option value="subtree">{t('drive.access.scope.subtree')}</option>{/if}
								</select></label>
								<label>{t('approvals.drive.expiresAt')}<input type="datetime-local" max={localDateTime(drive.requestedExpiresAt)} bind:value={driveExpiresAt} /></label>
								{#if drive.requestedMaxUses != null}<label>{t('approvals.drive.maxUses')}<input type="number" min="1" max={drive.requestedMaxUses} bind:value={driveMaxUses} /></label>{/if}
							</fieldset>
						{/if}
					{/if}
				{:else}
					<p class="ad-placeholder">{request.subject}</p>
				{/if}
			</div>

			<!-- Decided info (for my requests or already-decided) -->
			{#if request.status !== 'pending' && request.decidedByName}
				<div class="ad-divider"></div>
				<div class="ad-decided">
					<div class="ad-field">
						<span class="ad-label">{t('approvals.detail.decided_by')}</span>
						<span class="ad-value">{request.decidedByName}</span>
					</div>
					{#if request.decisionComment}
						<div class="ad-field">
							<span class="ad-label">{t('approvals.detail.comment')}</span>
							<span class="ad-value ad-value--pre">{request.decisionComment}</span>
						</div>
					{/if}
				</div>
			{/if}

			<!-- Decide actions (only for pending items in the approver's queue) -->
			{#if tab === 'pending' && request.status === 'pending'}
				<div class="ad-divider"></div>
				<div class="ad-actions">
					<div class="ad-comment">
						<label for="ad-comment-input" class="ad-label">{t('approvals.comment.label')}</label>
						<textarea
							id="ad-comment-input"
							class="ad-textarea"
							value={comment}
							placeholder={t('approvals.comment.deny_placeholder')}
							oninput={(e) => onCommentChange((e.currentTarget as HTMLTextAreaElement).value)}
							rows={3}
						></textarea>
						<span class="ad-hint">{t('approvals.comment.required_hint')}</span>
					</div>

					<!-- aria-live for decision results -->
					<div aria-live="polite" class="ad-result">
						{#if decideSuccess}
							<span class="ad-result--ok">
								<Icon name="CheckCircle" size={14} />
								{decideSuccess}
							</span>
						{:else if decideError}
							<span class="ad-result--err">{decideError}</span>
						{/if}
					</div>

					<div class="ad-btn-row">
						<Button
							variant="danger"
							size="md"
							disabled={deciding !== null || !canDeny}
							aria-label={`${t('approvals.btn.deny')}: ${request.subject}`}
							onclick={onDeny}
						>
							{#if deciding === 'deny'}
								<Spinner size={16} label="" />
								{t('approvals.btn.denying')}
							{:else}
								{t('approvals.btn.deny')}
							{/if}
						</Button>
						<Button
							variant="primary"
							size="md"
							aria-label={`${t('approvals.btn.approve')}: ${request.subject}`}
							disabled={deciding !== null || (isDriveAccess && driveCaps.length === 0)}
							onclick={approve}
						>
							{#if deciding === 'approve'}
								<Spinner size={16} label="" />
								{t('approvals.btn.approving')}
							{:else}
								{t('approvals.btn.approve')}
							{/if}
						</Button>
					</div>
				</div>
			{/if}

			<!-- Cancel action for my requests still pending -->
			{#if tab === 'my_requests' && request.status === 'pending'}
				<div class="ad-divider"></div>
				<div class="ad-actions">
					<div aria-live="polite" class="ad-result">
						{#if decideSuccess}
							<span class="ad-result--ok">{decideSuccess}</span>
						{:else if decideError}
							<span class="ad-result--err">{decideError}</span>
						{/if}
					</div>
					<Button
						variant="secondary"
						size="md"
						disabled={deciding !== null}
						onclick={onCancel}
					>
						{#if deciding === 'cancel'}
							<Spinner size={16} label="" />
							{t('approvals.btn.cancelling')}
						{:else}
							{t('approvals.btn.cancel_request')}
						{/if}
					</Button>
				</div>
			{/if}
		</div>
	{/if}
</div>

<style>
	.ad-root {
		display: flex;
		flex-direction: column;
		height: 100%;
		background: var(--surface-card);
		overflow: hidden;
	}
	.ad-empty {
		display: flex;
		flex-direction: column;
		align-items: center;
		justify-content: center;
		flex: 1;
		gap: var(--space-3);
	}
	.ad-empty__title {
		margin: 0;
		font-size: var(--text-sm);
		color: var(--text-tertiary);
	}
	.ad-topbar {
		display: flex;
		align-items: center;
		gap: var(--space-2);
		padding: var(--space-3) var(--space-4);
		border-bottom: 1px solid var(--border-default);
		flex-shrink: 0;
		min-width: 0;
	}
	.ad-topbar__subject {
		font-size: var(--text-sm);
		font-weight: var(--weight-semibold);
		color: var(--text-primary);
		flex: 1;
		min-width: 0;
		white-space: nowrap;
		overflow: hidden;
		text-overflow: ellipsis;
	}
	.ad-back {
		display: flex;
		align-items: center;
		border: none;
		background: none;
		cursor: pointer;
		color: var(--text-secondary);
		padding: var(--space-1);
		border-radius: var(--radius-sm);
		min-width: 44px;
		min-height: 44px;
		justify-content: center;
		flex-shrink: 0;
	}
	.ad-back:focus-visible {
		outline: none;
		box-shadow: var(--focus-ring);
	}
	.ad-scroll {
		flex: 1;
		overflow-y: auto;
		padding: var(--space-4);
		display: flex;
		flex-direction: column;
		gap: var(--space-4);
	}
	.ad-header {
		display: flex;
		flex-direction: column;
		gap: var(--space-2);
	}
	.ad-header__row {
		display: flex;
		gap: var(--space-2);
		align-items: baseline;
	}
	.ad-consumer-pill {
		display: inline-block;
		font-size: var(--text-xs);
		color: var(--text-secondary);
		background: var(--surface-sunken);
		border: 1px solid var(--border-subtle);
		border-radius: var(--radius-sm);
		padding: 0 var(--space-2);
		align-self: flex-start;
	}
	.ad-divider {
		height: 1px;
		background: var(--border-default);
	}
	.ad-drive-summary,
	.ad-drive-narrow {
		display: flex;
		flex-direction: column;
		gap: var(--space-2);
		padding: var(--space-3);
		border: 1px solid var(--border-default);
		border-radius: var(--radius-sm);
		font-size: var(--text-sm);
	}
	.ad-drive-summary span,
	.ad-drive-narrow p {
		margin: 0;
		color: var(--text-secondary);
	}
	.ad-drive-narrow legend {
		padding: 0 var(--space-1);
		font-weight: var(--weight-semibold);
	}
	.ad-drive-narrow label {
		display: flex;
		align-items: center;
		gap: var(--space-2);
	}
	.ad-drive-narrow label:has(select),
	.ad-drive-narrow label:has(input[type='datetime-local']),
	.ad-drive-narrow label:has(input[type='number']) {
		justify-content: space-between;
	}
	.ad-drive-narrow select,
	.ad-drive-narrow input[type='datetime-local'],
	.ad-drive-narrow input[type='number'] {
		min-height: 36px;
		max-width: 62%;
		border: 1px solid var(--border-default);
		border-radius: var(--radius-xs);
		background: var(--surface-card);
		color: var(--text-primary);
	}
	.ad-section-title {
		font-size: var(--text-xs);
		font-weight: var(--weight-semibold);
		color: var(--text-tertiary);
		text-transform: uppercase;
		letter-spacing: 0.06em;
		margin: 0 0 var(--space-2) 0;
	}
	.ad-evidence {
		display: flex;
		flex-direction: column;
		gap: var(--space-3);
	}
	.ad-field {
		display: flex;
		flex-direction: column;
		gap: var(--space-1);
	}
	.ad-label {
		font-size: var(--text-xs);
		font-weight: var(--weight-medium);
		color: var(--text-secondary);
	}
	.ad-value {
		font-size: var(--text-sm);
		color: var(--text-primary);
	}
	.ad-value--pre {
		white-space: pre-wrap;
	}
	.ad-value--countdown {
		font-family: var(--font-mono);
		font-size: var(--text-sm);
		color: var(--warning-fg);
	}
	.ad-value--expired {
		color: var(--danger-fg);
	}
	.ad-placeholder {
		font-size: var(--text-sm);
		color: var(--text-secondary);
		font-style: italic;
		margin: 0;
	}
	.ad-mail-frame {
		width: 100%;
		min-height: 300px;
		border: 1px solid var(--border-default);
		border-radius: var(--radius-md);
		background: var(--surface-page);
	}
	.ad-decided {
		display: flex;
		flex-direction: column;
		gap: var(--space-2);
	}
	.ad-actions {
		display: flex;
		flex-direction: column;
		gap: var(--space-3);
	}
	.ad-comment {
		display: flex;
		flex-direction: column;
		gap: var(--space-1);
	}
	.ad-textarea {
		width: 100%;
		border: 1px solid var(--border-default);
		border-radius: var(--radius-md);
		padding: var(--space-2) var(--space-3);
		font-family: var(--font-sans);
		font-size: var(--text-sm);
		color: var(--text-primary);
		background: var(--surface-page);
		resize: vertical;
		min-height: 80px;
		box-sizing: border-box;
	}
	.ad-textarea:focus-visible {
		outline: none;
		border-color: var(--accent);
		box-shadow: 0 0 0 2px var(--accent-subtle);
	}
	.ad-hint {
		font-size: var(--text-xs);
		color: var(--text-tertiary);
	}
	.ad-result {
		min-height: 20px;
		font-size: var(--text-sm);
	}
	.ad-result--ok {
		display: flex;
		align-items: center;
		gap: var(--space-1);
		color: var(--success-fg);
	}
	.ad-result--err {
		color: var(--danger-fg);
	}
	.ad-btn-row {
		display: flex;
		gap: var(--space-2);
		justify-content: flex-end;
	}
</style>
