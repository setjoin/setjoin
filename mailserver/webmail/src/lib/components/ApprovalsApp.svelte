<svelte:options runes={true} />
<script lang="ts">
	import { onMount, onDestroy } from 'svelte';
	import { user } from '$lib/stores/auth';
	import { typedFetch } from '$lib/http';
	import { parseError } from '$lib/errors';
	import { approvalsCount } from '$lib/stores/approvals.svelte';
	import { t } from '$lib/i18n';
	import ApprovalQueue from '$lib/components/ApprovalQueue.svelte';
	import ApprovalDetail from '$lib/components/ApprovalDetail.svelte';
	import NewHrRequestDialog from '$lib/components/NewHrRequestDialog.svelte';
	import { Button } from '$lib/components/ui';
	import type { ApprovalRequest, ApprovalsResponse, DriveAccessDecisionInput } from '$lib/types/approvals';

	const POLL_MS = 60_000;
	type ApprovalDecision = 'approved' | 'denied' | 'cancelled';
	type ApprovalAction = 'approve' | 'deny' | 'cancel';

	function actionForDecision(decision: ApprovalDecision): ApprovalAction {
		switch (decision) {
			case 'approved':
				return 'approve';
			case 'denied':
				return 'deny';
			case 'cancelled':
				return 'cancel';
		}
	}

	let pendingItems = $state<ApprovalRequest[]>([]);
	let myRequests = $state<ApprovalRequest[]>([]);
	let loading = $state(false);
	let error = $state('');
	let tab = $state<'pending' | 'my_requests'>('pending');
	let selectedId = $state<number | null>(null);
	let deciding = $state<'approve' | 'deny' | 'cancel' | null>(null);
	let decideError = $state('');
	let decideSuccess = $state('');
	let comment = $state('');
	let showDetail = $state(false); // mobile: true when a row is selected
	let showNewRequestDialog = $state(false);

	let pollTimer: ReturnType<typeof setInterval> | null = null;

	let selectedRequest = $derived.by(() => {
		if (selectedId === null) return null;
		const all = [...pendingItems, ...myRequests];
		return all.find(r => r.id === selectedId) ?? null;
	});

	async function load() {
		loading = true;
		error = '';
		try {
			const data = await typedFetch<ApprovalsResponse>('/api/me/approvals');
			pendingItems = data.pendingForMe ?? [];
			myRequests = data.myRequests ?? [];
			// ponytail: update rail badge singleton
			approvalsCount.set(pendingItems.filter(r => r.requesterEmail !== ($user?.email ?? '')).length);
		} catch (e) {
			error = parseError(e).message;
		} finally {
			loading = false;
		}
	}

	onMount(() => {
		load();
		pollTimer = setInterval(load, POLL_MS);
	});

	onDestroy(() => {
		if (pollTimer !== null) clearInterval(pollTimer);
	});

	function selectRequest(id: number) {
		selectedId = id;
		decideError = '';
		decideSuccess = '';
		comment = '';
		showDetail = true;
	}

	function handleBack() {
		showDetail = false;
		selectedId = null;
	}

	async function handleDecide(decision: ApprovalDecision, narrowing?: DriveAccessDecisionInput) {
		if (selectedId === null) return;
		const action = actionForDecision(decision);
		deciding = action;
		decideError = '';
		decideSuccess = '';
		try {
			if (action === 'cancel') {
				// Engine-level cancel (spec §10.1) is its own endpoint — approval_request_cancel
				// takes only an actor, no decision body. Previously this incorrectly POSTed
				// decision:'cancel' to /decide, which only accepts approve/deny and always 400ed.
				await typedFetch(`/api/me/approvals/${selectedId}/cancel`, {
					method: 'POST',
					onError: async (r) => {
						const body = await r.json().catch(() => ({})) as Record<string, unknown>;
						const code = String(body.code ?? '');
						if (code === 'BZ125') return 'race'; // already decided/cancelled/not found
						return `error:${r.status}`;
					},
				});
			} else {
				await typedFetch(`/api/me/approvals/${selectedId}/decide`, {
					method: 'POST',
					headers: { 'Content-Type': 'application/json' },
					// Send the imperative `action` (approve/deny), not the past-tense
					// `decision` (approved/denied) — the backend validates "approve"/"deny".
					body: JSON.stringify({ decision: action, comment, ...(action === 'approve' ? narrowing : undefined) }),
					onError: async (r) => {
						const body = await r.json().catch(() => ({})) as Record<string, unknown>;
						const code = String(body.code ?? '');
						if (code === 'BZ108') return 'race'; // already decided/expired
						if (code === 'BZ107') return 'notYours';
						return `error:${r.status}`;
					},
				});
			}
			// Success: show message, remove from pending, reload
			decideSuccess = t(`approvals.decision.${decision}`);
			// Remove from the relevant list
			if (tab === 'pending') {
				pendingItems = pendingItems.filter(r => r.id !== selectedId);
			} else {
				myRequests = myRequests.map((request) => request.id === selectedId ? { ...request, status: decision } : request);
			}
			approvalsCount.set(pendingItems.filter(r => r.requesterEmail !== ($user?.email ?? '')).length);
			selectedId = null;
			showDetail = false;
			// Reload for fresh state
			setTimeout(load, 1000);
		} catch (e) {
			const msg = parseError(e).message;
			if (msg === 'race') {
				decideError = t('approvals.decision.race');
				// Remove the row — it's no longer actionable
				pendingItems = pendingItems.filter(r => r.id !== selectedId);
				selectedId = null;
				showDetail = false;
			} else if (msg === 'notYours') {
				decideError = t('approvals.decision.not_yours');
			} else {
				decideError = msg;
			}
		} finally {
			deciding = null;
		}
	}

	function handleHrSubmitted() {
		showNewRequestDialog = false;
		load();
	}
</script>

<div class="aa-shell" class:aa-shell--detail={showDetail}>
	<div class="aa-queue" class:aa-queue--hidden={showDetail}>
		<div class="aa-queue__header">
			<Button variant="secondary" size="sm" onclick={() => (showNewRequestDialog = true)}>
				{t('approvals.hr.new_request_button')}
			</Button>
		</div>
		<ApprovalQueue
			{pendingItems}
			{myRequests}
			{selectedId}
			{tab}
			{loading}
			{error}
			currentUserEmail={$user?.email ?? ''}
			onSelect={selectRequest}
			onTabChange={(newTab) => { tab = newTab; selectedId = null; showDetail = false; }}
			onRetry={load}
		/>
	</div>

	<div class="aa-detail" class:aa-detail--visible={showDetail || selectedRequest !== null}>
		<ApprovalDetail
			request={selectedRequest}
			{deciding}
			{decideError}
			{decideSuccess}
			{comment}
			{tab}
			onCommentChange={(v) => { comment = v; }}
			onApprove={(narrowing) => handleDecide('approved', narrowing)}
			onDeny={() => handleDecide('denied')}
			onCancel={() => handleDecide('cancelled')}
			onBack={handleBack}
		/>
	</div>
</div>

<NewHrRequestDialog
	open={showNewRequestDialog}
	onClose={() => (showNewRequestDialog = false)}
	onSubmitted={handleHrSubmitted}
/>

<style>
	.aa-shell {
		display: flex;
		height: 100%;
		overflow: hidden;
		background: var(--surface-card);
	}
	.aa-queue__header {
		flex-shrink: 0;
		padding: var(--space-2) var(--space-3);
		border-bottom: 1px solid var(--border-subtle);
		display: flex;
		justify-content: flex-end;
	}
	.aa-queue {
		flex: 0 0 auto;
		width: clamp(260px, 36vw, 380px);
		border-right: 1px solid var(--border-default);
		overflow: hidden;
		display: flex;
		flex-direction: column;
	}
	.aa-detail {
		flex: 1;
		min-width: 0;
		overflow: hidden;
		display: flex;
		flex-direction: column;
	}

	/* Mobile: single-pane, full-width */
	@media (max-width: 767px) {
		.aa-queue {
			width: 100%;
			border-right: none;
		}
		.aa-detail {
			display: none;
		}
		/* When detail is active on mobile, show it fullscreen */
		.aa-shell--detail .aa-queue--hidden {
			display: none;
		}
		.aa-shell--detail .aa-detail {
			display: flex;
			position: fixed;
			inset: 0;
			z-index: 20;
			background: var(--surface-card);
		}
	}
</style>
