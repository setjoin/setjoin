<svelte:options runes={true} />

<script lang="ts">
    import { onMount } from 'svelte';
    import { adminFetch } from '$lib/admin/client';
    import { adminPermissions, hasPermission } from '$lib/stores/auth';
    import { Card, Badge, Button, Input, Dialog, Tabs, EmptyState, Spinner, showToast } from '$lib/components/ui';
    import type { TabItem } from '$lib/components/ui';

    let subscriptions = $state<any[]>([]);
    let deliveries = $state<any[]>([]);
    let selectedSub = $state<any>(null);
    let tab = $state('subscriptions');
    let loading = $state(true);

    // Create form
    let showCreate = $state(false);
    let createURL = $state('');
    let createEvents = $state<string[]>([]);
    let createdSecret = $state('');
    let createError = $state('');
    let rotatedSecret = $state('');
	interface EventCatalogItem { type: string; category: string; source: string }
	let eventCatalog = $state<EventCatalogItem[]>([]);
	let catalogError = $state('');
	let allEvents = $derived(eventCatalog.map((event) => event.type));

    onMount(() => { void Promise.all([loadSubscriptions(), loadEventCatalog()]); });

	async function loadEventCatalog() {
		const res = await adminFetch('/admin/webhooks/events');
		if (!res.ok) { catalogError = 'Event catalog unavailable. New subscriptions are disabled.'; return; }
		eventCatalog = await res.json();
	}

	function safePayloadPreview(eventType: string): string {
		if (!eventType.startsWith('mailwork.')) return 'Event-specific documented fields';
		return JSON.stringify({ mailboxId: '<opaque>', threadId: '<opaque>', eventId: '<uuid>',
			eventType, generation: '<decimal>' });
	}

    async function loadSubscriptions() {
        loading = true;
        const res = await adminFetch('/admin/webhooks');
        if (res.ok) subscriptions = await res.json();
        loading = false;
    }

    async function loadDeliveries(subID: number) {
        const res = await adminFetch(`/admin/webhooks/${subID}/deliveries`);
        if (res.ok) deliveries = await res.json();
    }

    async function createWebhook() {
        if (!createURL || createEvents.length === 0) return;
        createError = ''; createdSecret = '';
        const res = await adminFetch('/admin/webhooks', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url: createURL, eventTypes: createEvents }),
        });
        if (res.ok) {
            const data = await res.json();
            createdSecret = data.secret;
            createURL = ''; createEvents = [];
            loadSubscriptions();
        } else {
            const err = await res.json().catch(() => ({ error: 'Failed' }));
            createError = err.error || 'Failed to create';
        }
    }

    async function deleteWebhook(id: number) {
        if (!confirm('Delete this webhook subscription? Deliveries to its endpoint will stop.')) return;
        const res = await adminFetch(`/admin/webhooks/${id}`, { method: 'DELETE' });
        if (!res.ok) {
            showToast('Failed to delete webhook');
            return;
        }
        loadSubscriptions();
        showToast('Webhook deleted');
    }

    async function rotateSecret(id: number) {
        const res = await adminFetch(`/admin/webhooks/${id}/rotate-secret`, { method: 'POST' });
        if (res.ok) {
            const data = await res.json();
            rotatedSecret = data.secret;
        } else {
            showToast('Failed to rotate secret');
        }
    }

    // Show-once invariant (S19): the create dialog's secret is displayed exactly
    // once and dropped from component state when the dialog closes or is
    // reopened — it never re-renders on a subsequent visit.
    function openCreate() {
        createdSecret = '';
        createError = '';
        createURL = '';
        createEvents = [];
        showCreate = true;
    }

    function closeCreate() {
        createdSecret = '';
        createError = '';
        showCreate = false;
    }

    function toggleEvent(ev: string) {
        if (createEvents.includes(ev)) {
            createEvents = createEvents.filter(e => e !== ev);
        } else {
            createEvents = [...createEvents, ev];
        }
    }

    function deliveryStatusVariant(s: string): 'success' | 'danger' | 'neutral' {
        if (s === 'success') return 'success';
        if (s === 'failed') return 'danger';
        return 'neutral';
    }

    const tabItems = $derived<TabItem[]>([
        { id: 'subscriptions', label: 'Subscriptions', count: subscriptions.length },
        { id: 'catalog', label: 'Event catalog' },
    ]);
</script>

<div class="sj-page">
    <header class="sj-page-head">
        <div class="sj-page-head-left">
            <h1>Webhooks</h1>
        </div>
    </header>

    <Tabs items={tabItems} active={tab} onChange={(id: string) => tab = id} />

    <div style="margin-top:12px">
    {#if tab === 'subscriptions'}
        <Card title="Subscriptions">
            {#snippet actions()}
                <Button variant="primary" size="sm" onclick={openCreate}>New webhook</Button>
            {/snippet}
            {#snippet children()}
                {#if loading}
                    <EmptyState title="Loading…" />
                {:else if subscriptions.length === 0}
                    <EmptyState title="No webhook subscriptions configured." />
                {:else}
                    <table class="sj-table">
                        <thead><tr><th>URL</th><th>Events</th><th>Active</th><th></th></tr></thead>
                        <tbody>
                            {#each subscriptions as sub}
                                <tr>
                                    <td><span class="sj-ellipsis">{sub.url}</span></td>
                                    <td><Badge variant="info" label={String(sub.eventTypes?.length || 0) + ' events'} /></td>
                                    <td><Badge variant={sub.isActive ? 'success' : 'neutral'} label={sub.isActive ? 'Active' : 'Off'} dot={true} /></td>
                                    <td>
                                        <div class="sj-actions">
                                            <Button variant="ghost" size="sm" onclick={() => { selectedSub = sub; deliveries = []; loadDeliveries(sub.id); }}>Log</Button>
                                            <Button variant="ghost" size="sm" onclick={() => rotateSecret(sub.id)} disabled={!hasPermission($adminPermissions, 'system.config')}>Rotate</Button>
                                            <Button variant="ghost" size="sm" onclick={() => deleteWebhook(sub.id)} disabled={!hasPermission($adminPermissions, 'system.config')}>Delete</Button>
                                        </div>
                                    </td>
                                </tr>
                            {/each}
                        </tbody>
                    </table>
                {/if}
            {/snippet}
        </Card>

        {#if selectedSub}
            <div style="margin-top:12px">
            <Card title={'Delivery log — ' + selectedSub.url}>
                {#snippet children()}
                    {#if deliveries.length === 0}
                        <EmptyState title="No deliveries yet." />
                    {:else}
                        <table class="sj-table">
                            <thead><tr><th>Event</th><th>Status</th><th>Code</th><th>Latency</th><th>Time</th></tr></thead>
                            <tbody>
                                {#each deliveries as d}
                                    <tr>
                                        <td><Badge variant="accent" label={d.eventType} /></td>
                                        <td><Badge variant={deliveryStatusVariant(d.status)} label={d.status} dot={true} /></td>
                                        <td>{d.responseCode || '—'}</td>
                                        <td>{d.latencyMs ? d.latencyMs + 'ms' : '—'}</td>
                                        <td class="sj-muted">{new Date(d.createdAt).toLocaleString()}</td>
                                    </tr>
                                {/each}
                            </tbody>
                        </table>
                    {/if}
                {/snippet}
            </Card>
            </div>
        {/if}

        {#if showCreate}
        <Dialog open={showCreate} title="New webhook" onClose={closeCreate}>
            {#snippet children()}
                <div class="sj-form">
                    {#if createdSecret}
                        <div class="sj-secret-box">
                            <strong>Webhook created.</strong> Copy the secret now — it will not be shown again.<br />
                            <code class="sj-secret-code">{createdSecret}</code>
                        </div>
                    {/if}

                    {#if createError}
                        <div class="sj-alert-danger">{createError}</div>
                    {/if}

                    <Input label="Destination URL" type="url" value={createURL}
                        oninput={(e) => createURL = (e.target as HTMLInputElement).value}
                        placeholder="https://your-server.com/webhook" />

                    <div class="sj-events-group">
                        <span class="sj-events-label">Event types</span>
                        <div class="sj-events-chips">
                            {#each allEvents as ev}
                                <button
                                    class="sj-event-chip"
                                    class:sj-event-chip--on={createEvents.includes(ev)}
                                    onclick={() => toggleEvent(ev)}
                                >
                                    {ev}
                                </button>
                            {/each}
                        </div>
                    </div>
					<p class="sj-hint">{createEvents.length ? safePayloadPreview(createEvents[0]) : 'Select an event to preview its redacted payload shape.'}</p>
					{#if catalogError}<div class="sj-alert-danger" role="alert">{catalogError}</div>{/if}
                </div>
            {/snippet}
            {#snippet footer()}
                <Button variant="primary" onclick={createWebhook} disabled={!createURL || createEvents.length === 0 || !hasPermission($adminPermissions, 'system.config')}>Create</Button>
                <Button variant="ghost" onclick={closeCreate}>Cancel</Button>
            {/snippet}
        </Dialog>
        {/if}

        {#if rotatedSecret}
        <Dialog open={true} title="Secret rotated" onClose={() => rotatedSecret = ''}>
            {#snippet children()}
                <div class="sj-secret-box">
                    <strong>New signing secret.</strong> Copy it now — it will not be shown again. The previous secret no longer validates deliveries.<br />
                    <code class="sj-secret-code">{rotatedSecret}</code>
                </div>
            {/snippet}
            {#snippet footer()}
                <Button variant="primary" onclick={() => rotatedSecret = ''}>Done</Button>
            {/snippet}
        </Dialog>
        {/if}
    {:else}
        <Card title="Event catalog">
            {#snippet children()}
				<p class="sj-hint">Server-authoritative event catalog. Mail-work payloads contain opaque routing fields only—never subject, sender, body, or private comments.</p>
				{#if catalogError}<div class="sj-alert-danger" role="alert">{catalogError}</div>{/if}
                <table class="sj-table">
					<thead><tr><th>Event type</th><th>Category</th><th>Source</th><th>Redacted payload preview</th></tr></thead>
                    <tbody>
						{#each eventCatalog as event (event.type)}
							<tr><td><code>{event.type}</code></td><td><Badge variant={event.category === 'admin' ? 'success' : 'warning'} label={event.category} /></td><td>{event.source}</td><td><code>{safePayloadPreview(event.type)}</code></td></tr>
						{/each}
                    </tbody>
                </table>
            {/snippet}
        </Card>
    {/if}
    </div>
</div>

<style>
    .sj-page { max-width: 980px; }
    .sj-page-head { display: flex; align-items: flex-start; gap: 12px; margin-bottom: 16px; }
    .sj-page-head-left { flex: 1 1 260px; min-width: 0; }
    .sj-page-head-left h1 { margin: 0; font-size: clamp(20px, 16px + 1.2vw, 24px); font-weight: 600; letter-spacing: var(--tracking-display); color: var(--text-primary); }
    .sj-table { width: 100%; border-collapse: collapse; font-size: var(--text-sm); }
    .sj-table th { text-align: left; padding: 8px 12px; font-size: var(--text-2xs); letter-spacing: var(--tracking-caps); text-transform: uppercase; color: var(--text-tertiary); font-weight: 600; border-bottom: 1px solid var(--border-default); white-space: nowrap; }
    .sj-table td { padding: 8px 12px; border-bottom: 1px solid var(--border-subtle); }
    .sj-ellipsis { display: block; max-width: 300px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .sj-muted { font-size: var(--text-xs); color: var(--text-tertiary); }
    .sj-actions { display: flex; gap: 2px; }
    .sj-form { display: flex; flex-direction: column; gap: 12px; }
    .sj-secret-box { padding: 10px 12px; border-radius: var(--radius-sm); margin-bottom: 8px; font-size: var(--text-sm); background: var(--success-bg); color: var(--success-fg); border: 1px solid var(--success-fg); }
    .sj-secret-code { font-family: var(--font-mono); font-size: var(--text-sm); word-break: break-all; user-select: all; }
    .sj-alert-danger { padding: 8px 12px; border-radius: var(--radius-sm); margin-bottom: 4px; font-size: var(--text-sm); background: var(--danger-bg); color: var(--danger-fg); border: 1px solid var(--danger-fg); }
    .sj-events-label { display: block; font-size: var(--text-sm); font-weight: 500; margin-bottom: 6px; color: var(--text-primary); }
    .sj-events-chips { display: flex; flex-wrap: wrap; gap: 6px; }
    .sj-event-chip { padding: 4px 10px; border-radius: var(--radius-sm); border: 1px solid var(--border-default); background: var(--surface-card); color: var(--text-secondary); font-size: var(--text-xs); cursor: pointer; transition: background var(--duration-fast) var(--ease-out); }
    .sj-event-chip:hover { background: var(--surface-hover); }
    .sj-event-chip--on { background: var(--accent-subtle); color: var(--accent-fg-on-subtle); border-color: var(--border-accent); }
    .sj-hint { font-size: var(--text-sm); color: var(--text-secondary); margin-bottom: 12px; }
</style>
