<svelte:options runes={true} />

<script lang="ts">
    import { Checkbox, Card, Badge, Button, Input, Dialog, EmptyState } from '$lib/components/ui';
    import { adminFetch } from '$lib/admin/client';
    import { adminPermissions, hasPermission } from '$lib/stores/auth';

    let keywords = $state('');
    let fromAddr = $state('');
    let dateFrom = $state('');
    let dateTo = $state('');
    let loading = $state(false);
    let error = $state('');
    let results = $state<any[]>([]);
    let selected = $state<Set<number>>(new Set());
    let showDeleteConfirm = $state(false);
    let deleteReason = $state('');
    let deleting = $state(false);
    let deleteResult = $state<{deleted: number; held: number; notFound: number} | null>(null);

    async function doSearch() {
        if (!keywords && !fromAddr) return;
        loading = true; results = []; error = '';
        try {
            const body: Record<string, unknown> = { keywords, fromAddr: fromAddr || undefined };
            if (dateFrom) body.dateFrom = dateFrom;
            if (dateTo) body.dateTo = dateTo;
            const res = await adminFetch('/admin/content-search/search', {
                method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body),
            });
            if (!res.ok) throw new Error(`Search failed (${res.status})`);
            const data = await res.json(); results = data.results || [];
        } catch (e) {
            error = e instanceof Error ? e.message : 'Search failed';
        } finally {
            loading = false;
        }
    }

    function toggleSelect(id: number) {
        const s = new Set(selected);
        if (s.has(id)) s.delete(id); else s.add(id);
        selected = s;
    }

    function openDeleteConfirm() {
        if (selected.size === 0) return;
        deleteReason = ''; deleteResult = null;
        showDeleteConfirm = true;
    }

    async function confirmDelete() {
        if (deleteReason.length < 10) return;
        deleting = true; error = '';
        try {
            const res = await adminFetch('/admin/content-search/delete', {
                method: 'POST', headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ ids: Array.from(selected), reason: deleteReason }),
            });
            if (!res.ok) throw new Error(`Delete failed (${res.status})`);
            deleteResult = await res.json();
            results = results.filter(r => !selected.has(r.id));
            selected = new Set();
        } catch (e) {
            error = e instanceof Error ? e.message : 'Delete failed';
        } finally {
            deleting = false;
        }
    }
</script>

<div class="sj-page">
    <header class="sj-page-head">
        <div class="sj-page-head-left">
            <h1>Content search</h1>
        </div>
    </header>

    {#if error}<div class="alert alert-danger" role="alert">{error}</div>{/if}

    <div class="sj-search-bar">
        <Input placeholder="Keywords (body/subject search)" value={keywords}
            oninput={(e) => keywords = (e.target as HTMLInputElement).value}
            onkeydown={(e) => { if (e.key === 'Enter') doSearch(); }} />
        <Input placeholder="From address" value={fromAddr}
            oninput={(e) => fromAddr = (e.target as HTMLInputElement).value} />
        <div class="sj-date-row">
            <input class="sj-date-input" type="date" bind:value={dateFrom} />
            <input class="sj-date-input" type="date" bind:value={dateTo} />
        </div>
        <Button variant="primary" onclick={doSearch} disabled={loading}>Search</Button>
    </div>

    {#if loading}
        <EmptyState title="Searching…" />
    {:else if results.length === 0}
        <EmptyState title="Enter keywords and click Search to find messages across all mailboxes." />
    {:else}
        <Card title={String(results.length) + ' results'} flush={true}>
            {#snippet actions()}
                <Button variant="danger" size="sm" onclick={openDeleteConfirm} disabled={selected.size === 0 || !hasPermission($adminPermissions, 'compliance.write')}>
                    Delete selected ({selected.size})
                </Button>
            {/snippet}
            {#snippet children()}
                <table class="sj-table">
                    <thead><tr><th><Checkbox checked={false} label="" /></th><th>Subject</th><th>From</th><th>Mailbox</th><th>Date</th></tr></thead>
                    <tbody>
                        {#each results as r}
                            <tr>
                                <td><Checkbox checked={selected.has(r.id)} onchange={() => toggleSelect(r.id)} label="" /></td>
                                <td>{r.subject}</td>
                                <td>{r.from}</td>
                                <td>{r.mailbox}</td>
                                <td>{new Date(r.receivedAt).toLocaleDateString()}</td>
                            </tr>
                        {/each}
                    </tbody>
                </table>
            {/snippet}
        </Card>
    {/if}

    {#if showDeleteConfirm}
    <Dialog open={showDeleteConfirm} title="Delete messages" onClose={() => showDeleteConfirm = false}>
        {#snippet children()}
            {#if deleteResult}
                <div class="sj-result-box">
                    Deleted {deleteResult.deleted} message{deleteResult.deleted !== 1 ? 's' : ''}.
                    {#if deleteResult.held > 0}
                        {deleteResult.held} message{deleteResult.held !== 1 ? 's' : ''} skipped (on litigation hold).
                    {/if}
                </div>
            {:else}
                <p class="sj-confirm-text">Permanently delete {selected.size} message{selected.size !== 1 ? 's' : ''} across all mailboxes?</p>
                <Input label="Reason (required, min 10 characters)" value={deleteReason}
                    oninput={(e) => deleteReason = (e.target as HTMLInputElement).value}
                    placeholder="e.g. Phishing email cleanup — subject 'Urgent password reset'" />
            {/if}
        {/snippet}
        {#snippet footer()}
            {#if deleteResult}
                <Button variant="primary" onclick={() => showDeleteConfirm = false}>Done</Button>
            {:else}
                <Button variant="danger" onclick={confirmDelete} disabled={deleteReason.length < 10 || deleting || !hasPermission($adminPermissions, 'compliance.write')}>
                    {deleting ? 'Deleting…' : 'Confirm delete'}
                </Button>
                <Button variant="ghost" onclick={() => showDeleteConfirm = false}>Cancel</Button>
            {/if}
        {/snippet}
    </Dialog>
    {/if}
</div>

<style>
    .sj-page { max-width: 980px; }
    .sj-page-head { display: flex; align-items: flex-start; gap: 12px; margin-bottom: 16px; }
    .sj-page-head-left { flex: 1 1 260px; min-width: 0; }
    .sj-page-head-left h1 { margin: 0; font-size: clamp(20px, 16px + 1.2vw, 24px); font-weight: 600; letter-spacing: var(--tracking-display); color: var(--text-primary); }
    .sj-search-bar { display: flex; gap: 8px; align-items: flex-end; margin-bottom: 16px; flex-wrap: wrap; }
    .sj-search-bar > :global(.sj-input) { min-width: 180px; flex: 1; }
    .sj-date-row { display: flex; gap: 4px; }
    .sj-date-input { height: var(--control-height); padding: 0 10px; border: 1px solid var(--border-default); border-radius: var(--radius-sm); background: var(--surface-card); color: var(--text-primary); font-size: var(--text-sm); }
    .sj-date-input:focus-visible { outline: none; box-shadow: var(--focus-ring); }
    .sj-table { width: 100%; border-collapse: collapse; font-size: var(--text-sm); }
    .sj-table th { text-align: left; padding: 8px 12px; font-size: var(--text-2xs); letter-spacing: var(--tracking-caps); text-transform: uppercase; color: var(--text-tertiary); font-weight: 600; border-bottom: 1px solid var(--border-default); white-space: nowrap; }
    .sj-table td { padding: 8px 12px; border-bottom: 1px solid var(--border-subtle); }
    .sj-confirm-text { margin-bottom: 12px; font-size: var(--text-sm); color: var(--text-primary); }
    .sj-result-box { padding: 10px 12px; border-radius: var(--radius-sm); margin-bottom: 12px; font-size: var(--text-sm); background: var(--surface-sunken); color: var(--text-primary); }
</style>
