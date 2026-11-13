<svelte:options runes={true} />

<script lang="ts">
    import { onMount } from 'svelte';
    import {
        adminDeptTree,
        adminDeptCreate,
        adminDeptUpdate,
        adminDeptDelete,
        adminDeptAssignUser,
        adminUserList,
        type TreeNode,
        type AdminUser
    } from '$lib/admin/client';
    import { parseError } from '$lib/errors';
    import { adminPermissions, hasPermission } from '$lib/stores/auth';
    import { Card, Badge, Button, Input, Dialog, Select, EmptyState, Spinner, showToast } from '$lib/components/ui';

    const canWrite = $derived(hasPermission($adminPermissions, 'users.create'));

    let tree = $state<TreeNode[]>([]);
    let users = $state<AdminUser[]>([]);
    let loading = $state(true);
    let error = $state('');
    let usersLoadError = $state('');

    let showCreate = $state(false);
    let createParentId = $state<number | null>(null);
    let createName = $state('');
    let createLdapOu = $state('');

    let editingId = $state<number | null>(null);
    let editName = $state('');
    let editLdapOu = $state('');

    let showDeleteConfirm = $state(false);
    let deleteTargetId = $state<number | null>(null);

    onMount(async () => {
        await Promise.all([refreshTree(), loadUsers()]);
    });

    async function refreshTree() {
        try { tree = await adminDeptTree(); }
        catch (e) { error = parseError(e).message; }
        finally { loading = false; }
    }

    async function loadUsers() {
        usersLoadError = '';
        try { users = await adminUserList(undefined, 500, 0); }
        catch (e) { usersLoadError = parseError(e).message; }
    }

    async function createDept() {
        if (!createName.trim()) return;
        try {
            await adminDeptCreate({ name: createName.trim(), parentId: createParentId, ldapOu: createLdapOu.trim() || createName.trim() });
            showCreate = false; createName = ''; createLdapOu = ''; createParentId = null;
            await refreshTree();
            showToast('Department created');
        } catch (e) { error = parseError(e).message; }
    }

    async function saveEdit() {
        if (!editingId || !editName.trim()) return;
        try {
            await adminDeptUpdate(editingId, { name: editName.trim(), ldapOu: editLdapOu.trim() });
            editingId = null;
            await refreshTree();
            showToast('Department saved');
        } catch (e) { error = parseError(e).message; }
    }

    async function removeDept(id: number) {
        deleteTargetId = id;
        showDeleteConfirm = true;
    }

    async function doDeleteDept() {
        if (!deleteTargetId) return;
        try {
            await adminDeptDelete(deleteTargetId);
            showDeleteConfirm = false; deleteTargetId = null;
            await refreshTree();
            showToast('Department deleted');
        } catch (e) {
            error = parseError(e).message;
            showDeleteConfirm = false; deleteTargetId = null;
        }
    }

    async function assignUser(userId: number, deptId: number | null) {
        try {
            await adminDeptAssignUser(userId, deptId);
            await loadUsers();
        } catch (e) { error = parseError(e).message; }
    }

    function flatDepts(nodes: TreeNode[], depth = 0): Array<{ node: TreeNode; depth: number }> {
        const out: Array<{ node: TreeNode; depth: number }> = [];
        for (const n of nodes) {
            out.push({ node: n, depth });
            if (n.children?.length) out.push(...flatDepts(n.children, depth + 1));
        }
        return out;
    }

    const flatList = $derived(flatDepts(tree));
</script>

<div class="sj-page">
    <header class="sj-page-head">
        <div class="sj-page-head-left">
            <h1>Departments</h1>
        </div>
        <div class="sj-page-head-right">
            <Button variant="primary" size="sm" disabled={!canWrite} onclick={() => { showCreate = true; createParentId = null; }}>New department</Button>
        </div>
    </header>

    {#if error}<div class="sj-alert-danger">{error}</div>{/if}

    {#if loading}
        <EmptyState title="Loading…" />
    {:else}
        <Card title="Departments" flush={true}>
            {#snippet children()}
                <table class="sj-table">
                    <thead>
                        <tr><th>Name</th><th>Path</th><th>LDAP OU</th><th>Users</th><th>Actions</th></tr>
                    </thead>
                    <tbody>
                        {#each flatList as { node, depth }}
                            <tr>
                                <td style="padding-left: {depth * 24 + 12}px">{node.name}</td>
                                <td class="sj-mono">{node.path}</td>
                                <td>{node.ldapOu}</td>
                                <td><Badge variant="info" count={node.userCount} /></td>
                                <td>
                                    {#if editingId === node.id}
                                        <div class="sj-inline-edit">
                                            <input class="sj-inline-input" bind:value={editName} placeholder="Name" maxlength="128" />
                                            <input class="sj-inline-input" bind:value={editLdapOu} placeholder="LDAP OU" />
                                            <Button variant="primary" size="sm" disabled={!canWrite} onclick={saveEdit}>Save</Button>
                                            <Button variant="ghost" size="sm" onclick={() => editingId = null}>Cancel</Button>
                                        </div>
                                    {:else}
                                        <div class="sj-actions">
                                            <Button variant="ghost" size="sm" disabled={!canWrite} onclick={() => { editingId = node.id; editName = node.name; editLdapOu = node.ldapOu; }}>Edit</Button>
                                            <Button variant="ghost" size="sm" disabled={!canWrite} onclick={() => { showCreate = true; createParentId = node.id; }}>Add sub</Button>
                                            <Button variant="ghost" size="sm" disabled={!canWrite} onclick={() => removeDept(node.id)}>Delete</Button>
                                        </div>
                                    {/if}
                                </td>
                            </tr>
                        {:else}
                            <tr>
                                <td colspan="5">
                                    <EmptyState title="No departments yet." />
                                </td>
                            </tr>
                        {/each}
                    </tbody>
                </table>
            {/snippet}
        </Card>

        <div style="margin-top:24px">
        <Card title="Assign users" flush={true}>
            {#snippet children()}
                {#if usersLoadError}
                    <div class="sj-field-error">{usersLoadError}</div>
                {/if}
                <table class="sj-table">
                    <thead>
                        <tr><th>User</th><th>Current department</th><th>Assign to</th></tr>
                    </thead>
                    <tbody>
                        {#each users as u}
                            <tr>
                                <td class="sj-user-name">{u.displayName || u.email}</td>
                                <td>{flatList.find(f => f.node.id === u.departmentId)?.node.name || '—'}</td>
                                <td>
                                    <select class="sj-select" disabled={!canWrite} onchange={(e) => assignUser(u.id, e.currentTarget.value ? Number(e.currentTarget.value) : null)}>
                                        <option value="">— None —</option>
                                        {#each flatList as { node }}
                                            <option value={node.id} selected={u.departmentId === node.id}>{node.path}</option>
                                        {/each}
                                    </select>
                                </td>
                            </tr>
                        {/each}
                    </tbody>
                </table>
            {/snippet}
        </Card>
        </div>
    {/if}

    {#if showCreate}
    <Dialog open={showCreate} title="Create department" onClose={() => showCreate = false}>
        {#snippet children()}
            <div class="sj-form">
                <Input label="Department name" value={createName}
                    oninput={(e) => createName = (e.target as HTMLInputElement).value}
                    placeholder="Name" maxlength={128} required={true} />
                <Input label="LDAP OU" value={createLdapOu}
                    oninput={(e) => createLdapOu = (e.target as HTMLInputElement).value}
                    placeholder="LDAP OU (optional)" />
                <div class="form-group">
                    <label for="create-parent">Parent department</label>
                    <select id="create-parent" class="sj-select" bind:value={createParentId}>
                        <option value={null}>No parent (top level)</option>
                        {#each flatList as { node }}
                            <option value={node.id}>{node.path}</option>
                        {/each}
                    </select>
                </div>
            </div>
        {/snippet}
        {#snippet footer()}
            <Button variant="primary" disabled={!canWrite} onclick={createDept}>Create</Button>
            <Button variant="ghost" onclick={() => showCreate = false}>Cancel</Button>
        {/snippet}
    </Dialog>
    {/if}

    {#if showDeleteConfirm}
    <Dialog open={showDeleteConfirm} title="Delete department" onClose={() => { showDeleteConfirm = false; deleteTargetId = null; }}>
        {#snippet children()}
            <p>Delete this department? It must be empty.</p>
        {/snippet}
        {#snippet footer()}
            <Button variant="danger" disabled={!canWrite} onclick={doDeleteDept}>Delete</Button>
            <Button variant="ghost" onclick={() => { showDeleteConfirm = false; deleteTargetId = null; }}>Cancel</Button>
        {/snippet}
    </Dialog>
    {/if}
</div>

<style>
    .sj-page { max-width: 980px; }
    .sj-page-head { display: flex; align-items: flex-start; gap: 12px; margin-bottom: 16px; flex-wrap: wrap; }
    .sj-page-head-left { flex: 1 1 260px; min-width: 0; }
    .sj-page-head-left h1 { margin: 0; font-size: clamp(20px, 16px + 1.2vw, 24px); font-weight: 600; letter-spacing: var(--tracking-display); color: var(--text-primary); }
    .sj-page-head-right { display: flex; gap: 8px; align-items: center; }
    .sj-alert-danger { padding: 8px 12px; border-radius: var(--radius-sm); margin-bottom: 12px; font-size: var(--text-sm); background: var(--danger-bg); color: var(--danger-fg); border: 1px solid var(--danger-fg); }
    .sj-table { width: 100%; border-collapse: collapse; font-size: var(--text-sm); }
    .sj-table th { text-align: left; padding: 8px 12px; font-size: var(--text-2xs); letter-spacing: var(--tracking-caps); text-transform: uppercase; color: var(--text-tertiary); font-weight: 600; border-bottom: 1px solid var(--border-default); white-space: nowrap; }
    .sj-table td { padding: 8px 12px; border-bottom: 1px solid var(--border-subtle); }
    .sj-mono { font-family: var(--font-mono); font-size: var(--text-xs); }
    .sj-actions { display: flex; gap: 2px; }
    .sj-inline-edit { display: flex; gap: 4px; align-items: center; }
    .sj-inline-input { width: 110px; height: var(--control-height-sm); padding: 0 8px; border: 1px solid var(--border-default); border-radius: var(--radius-sm); background: var(--surface-card); color: var(--text-primary); font-size: var(--text-xs); }
    .sj-inline-input:focus-visible { outline: none; box-shadow: var(--focus-ring); }
    .sj-user-name { font-weight: 500; }
    .sj-form { display: flex; flex-direction: column; gap: 12px; }
    .sj-field-error { color: var(--danger-fg); font-size: var(--text-xs); margin: 0 0 8px; }
    .sj-select { width: 100%; height: var(--control-height); padding: 0 10px; border: 1px solid var(--border-default); border-radius: var(--radius-sm); background: var(--surface-card); color: var(--text-primary); font: var(--font-sans); font-size: var(--text-sm); }
    .sj-select:focus-visible { outline: none; box-shadow: var(--focus-ring); }
    .form-group label { display: block; font-size: var(--text-sm); font-weight: 500; margin-bottom: 4px; color: var(--text-primary); }
</style>
