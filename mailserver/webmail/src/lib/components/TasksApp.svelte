<svelte:options runes={true} />

<script lang="ts">
	import { onMount, onDestroy, tick } from 'svelte';
	import { goto } from '$app/navigation';

	import { loadSession, galSearch, taskActivityList, taskCommentCreate } from '$lib/jmap/client';
	import { PushHandlerStore } from '$lib/stores/pushHandler.svelte';
	import { parseError } from '$lib/errors';
	import { validate, required, maxLength, normalize } from '$lib/validation';
	import { Dialog, Button, IconButton, Input, Select, Textarea, Checkbox, Spinner, EmptyState, Menu, showToast } from '$lib/components/ui';
	import type { MenuItem } from '$lib/components/ui/Menu.svelte';
	import Icon from '$lib/components/Icon.svelte';
	import PimShell from '$lib/components/PimShell.svelte';
	import TaskListMembersDialog from '$lib/components/TaskListMembersDialog.svelte';
	import { t } from '$lib/i18n';
	import {
		tasks, viewMode, searchText, statusFilter,
		loadTasks, createTask, updateTask, deleteTask,
		groupByStatus, priorityLabel, priorityColor, statusLabel,
		formatDateShort, isOverdue, computeReorderSortOrder
	} from '$lib/stores/tasks';
	import {
		taskLists, activeView, assignedTasks, listTasks,
		loadLists, setActiveView, createTaskList, renameTaskList, deleteTaskList,
		createListTask, updateListTask, deleteListTask, refreshListTaskTarget,
		setAssignedStatus, onTaskListPush
	} from '$lib/stores/taskLists';
	import type { Task, ContactCard, TaskActivity, ChecklistItem, TaskList } from '$lib/types/jmap';
	import {
		TasksActionConflictError,
		TasksActionCoordinator,
		actionTargetEquals,
		captureActionTarget,
		type ActionTarget,
	} from '$lib/tasks/actionCoordinator.svelte';

	let loading = $state(false);
	let error = $state('');
	let showModal = $state(false);
	let modalMode = $state<'create' | 'edit' | 'detail'>('create');
	let editingTask = $state<Task | null>(null);

	let form = $state({
		title: '',
		description: '',
		status: 'needs-action' as Task['status'],
		priority: 0,
		startAt: '',
		dueAt: '',
		reminderAt: '',
		categories: [] as string[],
		assignee: '',        // assigneeEmail — resolved to an internal user server-side
		assigneeName: '',    // display only; cleared when the email is edited by hand
		recurrenceRule: '',  // RFC-5545 RRULE (or '' for none)
		parentId: '',        // subtask parent task id (or '' for top-level)
		checklist: [] as ChecklistItem[]  // QoL #21 in-task steps
	});
	let formErrors = $state<Record<string, string>>({});
	let formServerError = $state('');
	let formServerErrorElement = $state<HTMLDivElement | null>(null);
	let modalEpoch = 0;
	let modalActionTarget = $state<ActionTarget | null>(null);

	// Shared task lists (Phase 1) — feature-gated on the session capability
	// (h.sharedTaskListsEnabled()'s webmail mirror: no extra round trip).
	let sharedListsEnabled = $state(false);
	let showListDialog = $state(false);
	let listDialogMode = $state<'create' | 'rename'>('create');
	let listDialogListId = $state<string | null>(null);
	let listDialogName = $state('');
	let listDialogSaving = $state(false);
	let membersDialogList = $state<TaskList | null>(null);

	// Assignee GAL autocomplete (mirrors the compose recipient picker: debounced
	// galSearch over the directory; a task has ONE assignee, so no multi-select).
	let assigneeResults = $state<ContactCard[]>([]);
	let assigneeShow = $state(false);
	let assigneeTimer: ReturnType<typeof setTimeout> | null = null;

	// Activity feed / comments (QoL #17) — shown in the detail modal.
	let activity = $state<TaskActivity[]>([]);
	let activityLoading = $state(false);
	let commentBody = $state('');
	let commentSaving = $state(false);
	let commentMentions = $state<string[]>([]); // resolved emails picked via '@'
	let mentionResults = $state<ContactCard[]>([]);
	let mentionShow = $state(false);
	let mentionTimer: ReturnType<typeof setTimeout> | null = null;
	let mentionStart = $state(-1); // index of the '@' currently being completed
	let commentTextarea = $state<HTMLTextAreaElement | null>(null);

	let mounted = $state(false);
	const push = new PushHandlerStore();
	const taskActions = new TasksActionCoordinator({
		async create(target, data) {
			return target.kind === 'list'
				? createListTask(target.listId, data, false)
				: createTask(data);
		},
		async update(target, taskId, patch) {
			if (target.kind === 'list') await updateListTask(target.listId, taskId, patch, false);
			else await updateTask(taskId, patch);
		},
		async remove(target, taskId) {
			if (target.kind === 'list') await deleteListTask(target.listId, taskId, false);
			else await deleteTask(taskId);
		},
		async refresh(target) {
			if (target.kind === 'list') {
				await refreshListTaskTarget(target.listId);
				return;
			}
			const filter: Record<string, unknown> = {};
			if ($searchText) filter.text = $searchText;
			if ($statusFilter) filter.status = $statusFilter;
			await loadTasks(filter);
		},
	});

	onMount(async () => {
		try {
			const session = await loadSession();
			const tasksCap = session.capabilities?.['urn:ietf:params:jmap:tasks'] as
				| { sharedLists?: boolean }
				| undefined;
			sharedListsEnabled = !!tasksCap?.sharedLists;
			if (sharedListsEnabled) await loadLists();
			// Cross-tab/device reactivity: re-fetch on any Task push
			// (notify_task_state → task:{mailbox_id}). No debounce — refreshTasks'
			// own loading guard coalesces; the $effect handles the initial + filter loads.
			// The shared-list seam (notify_task_list_state) pushes on the SAME
			// task:{mailbox_id} channel (zero new subscription plumbing), so a
			// 'tasklist_changed' event surfaces here too — the push framework
			// abstracts it to the generic 'Task changed' signal (no per-list id),
			// so onTaskListPush(null) means "refetch whatever's on screen".
			push.register(['Task'], (changes) => {
				if (changes && (changes as Record<string, unknown>).Task) {
					refreshTasks();
					if (sharedListsEnabled) onTaskListPush(null);
				}
			});
		} catch (e) {
			error = parseError(e).message;
		} finally {
			// Flip mounted last so the $effect performs the single initial
			// task load (and every subsequent search/filter change reload).
			mounted = true;
		}
	});

	onDestroy(() => {
		push.teardown();
		if (assigneeTimer) clearTimeout(assigneeTimer);
		if (mentionTimer) clearTimeout(mentionTimer);
	});

	// ── Activity feed + comments (QoL #17) ──
	async function loadActivity(taskId: string) {
		activityLoading = true;
		try {
			activity = await taskActivityList(taskId);
		} catch (e) {
			error = parseError(e).message;
		} finally {
			activityLoading = false;
		}
	}

	// '@'-mention: reuse the same debounced galSearch the assignee picker uses,
	// with a caret-position trigger over the plain-text comment box (ponytail:
	// no TipTap Mention — that's coupled to the rich compose editor).
	function onCommentInput(e: Event) {
		const ta = e.currentTarget as HTMLTextAreaElement;
		commentTextarea = ta; // captured for caret math in pickMention (no bind:this on the primitive)
		commentBody = ta.value;
		const caret = ta.selectionStart ?? commentBody.length;
		const m = /(?:^|\s)@([^\s@]*)$/.exec(commentBody.slice(0, caret));
		if (!m) { mentionShow = false; mentionStart = -1; return; }
		mentionStart = caret - m[1].length - 1;
		const q = m[1];
		if (mentionTimer) clearTimeout(mentionTimer);
		if (q.length < 1) { mentionResults = []; mentionShow = false; return; }
		mentionTimer = setTimeout(async () => {
			try {
				mentionResults = await galSearch(q, 8);
				mentionShow = mentionResults.length > 0;
			} catch {
				mentionResults = [];
				mentionShow = false;
			}
		}, 200);
	}

	function pickMention(c: ContactCard) {
		const addr = c.email || c.emails?.[0]?.address || '';
		if (!addr || mentionStart < 0) return;
		const name = c.displayName || addr;
		const caret = commentTextarea?.selectionStart ?? commentBody.length;
		commentBody = commentBody.slice(0, mentionStart) + '@' + name + ' ' + commentBody.slice(caret);
		if (!commentMentions.includes(addr)) commentMentions = [...commentMentions, addr];
		mentionShow = false; mentionResults = []; mentionStart = -1;
	}

	async function submitComment() {
		const body = commentBody.trim();
		if (!body || commentSaving || !editingTask) return;
		commentSaving = true;
		try {
			await taskCommentCreate(editingTask.id, body, commentMentions);
			commentBody = '';
			commentMentions = [];
			await loadActivity(editingTask.id);
		} catch (e) {
			error = parseError(e).message;
		} finally {
			commentSaving = false;
		}
	}

	function activitySystemText(a: TaskActivity): string {
		const name = a.authorName || a.authorEmail;
		if (a.kind === 'status_change') {
			const oldV = a.meta?.old ? statusLabel(String(a.meta.old)) : '—';
			const newV = a.meta?.new ? statusLabel(String(a.meta.new)) : '—';
			return t('tasks.activity_status_change', { name, old: oldV, new: newV });
		}
		if (a.kind === 'assignee_change') return t('tasks.activity_assignee_change', { name });
		if (a.kind === 'due_change') return t('tasks.activity_due_change', { name });
		return '';
	}

	function onAssigneeInput(val: string) {
		form.assignee = val;
		form.assigneeName = ''; // hand-editing the address invalidates the picked name
		if (assigneeTimer) clearTimeout(assigneeTimer);
		const q = val.trim();
		if (q.length < 2) { assigneeResults = []; assigneeShow = false; return; }
		assigneeTimer = setTimeout(async () => {
			try {
				assigneeResults = await galSearch(q, 8);
				assigneeShow = assigneeResults.length > 0;
			} catch {
				assigneeResults = [];
				assigneeShow = false;
			}
		}, 200);
	}

	function pickAssignee(c: ContactCard) {
		const addr = c.email || c.emails?.[0]?.address || '';
		if (!addr) return;
		form.assignee = addr;
		form.assigneeName = c.displayName || '';
		assigneeShow = false;
		assigneeResults = [];
	}

	// Recurrence: a preset dropdown <-> RFC-5545 RRULE string (FREQ only). An
	// unrecognised stored rule shows as "Custom" and is preserved untouched.
	const RECURRENCE_FREQ: Record<string, string> = {
		DAILY: 'FREQ=DAILY', WEEKLY: 'FREQ=WEEKLY', MONTHLY: 'FREQ=MONTHLY', YEARLY: 'FREQ=YEARLY'
	};

	function rruleToPreset(rr: string): string {
		if (!rr) return '';
		const m = /FREQ=(DAILY|WEEKLY|MONTHLY|YEARLY)/.exec(rr);
		return m ? m[1] : 'CUSTOM';
	}

	function onRecurrenceChange(preset: string) {
		if (preset === 'CUSTOM') return; // display-only; leave the existing rule as-is
		form.recurrenceRule = preset ? RECURRENCE_FREQ[preset] : '';
	}

	function recurrenceLabel(rr: string): string {
		const p = rruleToPreset(rr);
		if (p === 'CUSTOM') return rr; // unrecognised rule — show it verbatim
		if (!p) return t('tasks.recurrence_none');
		return t('tasks.recurrence_' + p.toLowerCase());
	}

	const recurrencePreset = $derived(rruleToPreset(form.recurrenceRule));
	const recurrenceOptions = $derived([
		{ value: '', label: t('tasks.recurrence_none') },
		{ value: 'DAILY', label: t('tasks.recurrence_daily') },
		{ value: 'WEEKLY', label: t('tasks.recurrence_weekly') },
		{ value: 'MONTHLY', label: t('tasks.recurrence_monthly') },
		{ value: 'YEARLY', label: t('tasks.recurrence_yearly') },
		...(recurrencePreset === 'CUSTOM' ? [{ value: 'CUSTOM', label: t('tasks.recurrence_custom') }] : [])
	]);

	async function refreshTasks() {
		loading = true;
		try {
			const filter: Record<string, unknown> = {};
			if ($searchText) filter.text = $searchText;
			if ($statusFilter) filter.status = $statusFilter;
			await loadTasks(filter);
		} catch (e) {
			error = parseError(e).message;
		} finally {
			loading = false;
		}
	}

	$effect(() => {
		// Dependencies tracked automatically by Svelte via store accesses
		void $searchText; void $statusFilter;
		if (!mounted) return;
		refreshTasks();
	});

	// ── Shared task lists (Phase 1): view-aware data source + CRUD ──
	// Personal and shared-list actions share one immutable-target coordinator;
	// assigned is a separate, list-mode-only view with its own reducer contract.
	const currentListId = $derived($activeView.kind === 'list' ? $activeView.listId : null);
	const boardTasks = $derived(currentListId ? $listTasks : $tasks);
	const currentListMembers = $derived($taskLists.find((l) => l.id === currentListId)?.members);
	const modalTaskId = $derived(modalMode === 'create' ? 'new' : editingTask?.id ?? 'new');
	const modalSaving = $derived(modalActionTarget ? taskActions.isTaskBusy(modalActionTarget, modalTaskId) : false);

	function currentActionTarget(): ActionTarget | null {
		return captureActionTarget($activeView);
	}

	function isTaskBusy(taskId: string): boolean {
		const target = currentActionTarget();
		return target ? taskActions.isTaskBusy(target, taskId) : false;
	}

	// ── Shared task lists (Phase 1): sidebar nav + list CRUD dialog ──
	const assignedOpenCount = $derived(
		$assignedTasks.filter((t) => t.status !== 'completed' && t.status !== 'cancelled').length
	);

	const listMenuItems: MenuItem[] = [
		{ id: 'rename', label: t('tasks.lists.rename') },
		{ id: 'members', label: t('tasks.lists.members') },
		{ id: 'delete', label: t('tasks.lists.delete'), destructive: true }
	];

	function onListMenuSelect(id: string, list: TaskList) {
		if (id === 'rename') openRenameListDialog(list);
		else if (id === 'members') membersDialogList = list;
		else if (id === 'delete') confirmDeleteList(list);
	}

	function openNewListDialog() {
		listDialogMode = 'create';
		listDialogListId = null;
		listDialogName = '';
		showListDialog = true;
	}

	function openRenameListDialog(list: TaskList) {
		listDialogMode = 'rename';
		listDialogListId = list.id;
		listDialogName = list.name;
		showListDialog = true;
	}

	function closeListDialog() {
		showListDialog = false;
		listDialogName = '';
		listDialogListId = null;
	}

	async function saveListDialog() {
		const name = listDialogName.trim();
		if (!name || listDialogSaving) return;
		listDialogSaving = true;
		try {
			if (listDialogMode === 'create') {
				const id = await createTaskList(name);
				if (id) setActiveView({ kind: 'list', listId: id });
			} else if (listDialogListId) {
				await renameTaskList(listDialogListId, name);
			}
			closeListDialog();
		} catch (e) {
			error = parseError(e).message;
		} finally {
			listDialogSaving = false;
		}
	}

	async function confirmDeleteList(list: TaskList) {
		// confirm()-gated (not act-then-undo): deleting a shared list removes
		// every member's access and re-personalizes its tasks — the same
		// destructive-not-cleanly-reversible bar /settings/rules' delete uses.
		if (!confirm(t('tasks.lists.deleteConfirm', { name: list.name }))) return;
		try {
			await deleteTaskList(list.id);
		} catch (e) {
			error = parseError(e).message;
		}
	}

	function openCreateModal() {
		modalEpoch += 1;
		modalActionTarget = currentActionTarget();
		modalMode = 'create';
		editingTask = null;
		formServerError = '';
		form = {
			title: '',
			description: '',
			status: 'needs-action',
			priority: 0,
			startAt: '',
			dueAt: '',
			reminderAt: '',
			categories: [],
			assignee: '',
			assigneeName: '',
			recurrenceRule: '',
			parentId: '',
			checklist: []
		};
		assigneeResults = []; assigneeShow = false;
		showModal = true;
	}

	function openEditModal(task: Task) {
		modalEpoch += 1;
		modalActionTarget = currentActionTarget();
		modalMode = 'edit';
		editingTask = task;
		formServerError = '';
		form = {
			title: task.title || '',
			description: task.description || '',
			status: task.status || 'needs-action',
			priority: task.priority || 0,
			startAt: task.startAt ? task.startAt.slice(0, 16) : '',
			dueAt: task.dueAt ? task.dueAt.slice(0, 16) : '',
			reminderAt: task.reminderAt ? task.reminderAt.slice(0, 16) : '',
			categories: task.categories || [],
			assignee: task.assigneeEmail || '',
			assigneeName: task.assigneeName || '',
			recurrenceRule: task.recurrenceRule || '',
			parentId: task.parentId || '',
			// Clone so edits don't mutate the store's task object in place.
			checklist: (task.checklist || []).map((c) => ({ ...c }))
		};
		assigneeResults = []; assigneeShow = false;
		showModal = true;
	}

	function openDetailModal(task: Task) {
		modalEpoch += 1;
		modalActionTarget = currentActionTarget();
		modalMode = 'detail';
		editingTask = task;
		showModal = true;
		activity = [];
		commentBody = '';
		commentMentions = [];
		mentionShow = false;
		loadActivity(task.id);
	}

	function closeModal() {
		modalEpoch += 1;
		showModal = false;
		editingTask = null;
		assigneeShow = false;
		assigneeResults = [];
		mentionShow = false;
		mentionResults = [];
		formServerError = '';
		modalActionTarget = null;
	}

	/** Jump from a task to the email it was created from (email→task linkage).
	 *  ?t= also accepts a message id (selectionFromUrl); resolution happens
	 *  against the loaded inbox view, so a message outside it opens the inbox
	 *  without a selection rather than erroring. */
	function openLinkedEmail() {
		const id = editingTask?.linkedMessageId;
		if (!id) return;
		closeModal();
		goto(`/inbox?t=${id}`);
	}

	async function saveTask() {
		const target = modalActionTarget;
		if (!target || taskActions.isTaskBusy(target, modalTaskId)) return;
		const operationEpoch = modalEpoch;
		formErrors = {};
		formServerError = '';
		const result = validate({
			title: [required('Title is required'), maxLength(255)],
			description: [maxLength(5000)],
		}, { title: normalize(form.title), description: normalize(form.description) });
		if (!result.valid) { formErrors = result.errors; return; }
		try {
			let refreshError: unknown | undefined;
			const data: Partial<Task> = {
				title: form.title,
				description: form.description || undefined,
				status: form.status,
				priority: form.priority,
				startAt: form.startAt || undefined,
				dueAt: form.dueAt || undefined,
				reminderAt: form.reminderAt || undefined,
				categories: form.categories.length > 0 ? form.categories : undefined,
				// Sent present-but-empty (not undefined) so an edit can UNASSIGN / clear the
				// rule: the reducer treats a present blank assigneeEmail as unassign and a
				// blank recurrenceRule as "no recurrence"; an omitted key would keep the old
				// value. On create both blanks are harmless no-ops. assigneeUserId is never sent.
				assigneeEmail: form.assignee,
				recurrenceRule: form.recurrenceRule,
				// Whole-array replace (QoL #21) — the reducer validates + (re)assigns ids.
				checklist: form.checklist
			};
			if (modalMode === 'create') {
				// Create path parses parentId as BIGINT with no NULLIF — omit when empty
				// (an empty string would error); a present id nests the new subtask.
				if (form.parentId) data.parentId = form.parentId;
				refreshError = (await taskActions.create(target, data)).refreshError;
			} else if (modalMode === 'edit' && editingTask) {
				// Update path uses NULLIF(...,'') so a present '' clears the parent
				// (back to top-level); the reducer rejects self/cross-tenant parents.
				data.parentId = form.parentId;
				refreshError = (await taskActions.update(target, editingTask.id, data)).refreshError;
			}
			if (
				modalEpoch === operationEpoch &&
				actionTargetEquals(target, currentActionTarget())
			) {
				closeModal();
				if (refreshError) error = parseError(refreshError).message;
			}
		} catch (e) {
			if (e instanceof TasksActionConflictError) return;
			if (
				modalEpoch === operationEpoch &&
				actionTargetEquals(target, currentActionTarget())
			) {
				formServerError = parseError(e).message;
				await tick();
				formServerErrorElement?.focus();
			}
		}
	}

	async function removeTask(task: Task) {
		const target = currentActionTarget();
		if (!target || taskActions.isTaskBusy(target, task.id)) return;
		try {
			const completion = await taskActions.remove(target, task);
			const recipe = completion.value;
			if (completion.refreshError && actionTargetEquals(target, currentActionTarget())) {
				error = parseError(completion.refreshError).message;
			}
			showToast('Task deleted', {
				actionLabel: 'Restore copy',
				onAction: async () => {
					try {
						const restored = await taskActions.restoreCopy(recipe);
						if (restored.refreshError && actionTargetEquals(recipe.target, currentActionTarget())) {
							error = parseError(restored.refreshError).message;
						}
						showToast('Task copy restored', { variant: 'success' });
					} catch (restoreError) {
						showToast(parseError(restoreError).message, { variant: 'danger', durationMs: 8000 });
						throw restoreError;
					}
				}
			});
		} catch (e) {
			if (e instanceof TasksActionConflictError) return;
			if (actionTargetEquals(target, currentActionTarget())) error = parseError(e).message;
		}
	}

	async function moveStatus(task: Task, newStatus: Task['status']) {
		const target = currentActionTarget();
		if (!target || taskActions.isTaskBusy(target, task.id)) return;
		try {
			const completion = await taskActions.update(target, task.id, { status: newStatus }, 'move');
			if (completion.refreshError && actionTargetEquals(target, currentActionTarget())) {
				error = parseError(completion.refreshError).message;
			}
		} catch (e) {
			if (e instanceof TasksActionConflictError) return;
			if (actionTargetEquals(target, currentActionTarget())) error = parseError(e).message;
		}
	}

	// ── Drag-and-drop reorder / kanban move (QoL #20) ──
	// Native HTML5 DnD (no drag lib — the browser API covers a simple list/kanban).
	// The Start/Done buttons stay the keyboard/a11y fallback.
	let draggingId = $state<string | null>(null);

	async function applyReorder(id: string, patch: Partial<Task>) {
		const target = currentActionTarget();
		if (!target || taskActions.isTaskBusy(target, id)) return;
		try {
			const completion = await taskActions.update(target, id, patch, 'reorder');
			if (completion.refreshError && actionTargetEquals(target, currentActionTarget())) {
				error = parseError(completion.refreshError).message;
			}
		} catch (e) {
			if (e instanceof TasksActionConflictError) return;
			if (actionTargetEquals(target, currentActionTarget())) error = parseError(e).message;
		}
	}

	// Drop ON a card/row → insert the dragged task immediately BEFORE `target` in
	// `siblings` (the visible order), computing a fractional key between the
	// target and its predecessor. `status` (kanban only) also moves the column.
	function reorderBefore(target: Task, siblings: Task[], status?: Task['status']) {
		const id = draggingId;
		draggingId = null;
		if (!id || id === target.id) return;
		const dragged = boardTasks.find((t) => t.id === id);
		if (!dragged) return;
		const idx = siblings.findIndex((t) => t.id === target.id);
		if (idx < 0) return;
		const prev = siblings[idx - 1];
		const prevOrder = prev && prev.id !== id ? prev.sortOrder : undefined;
		const patch: Partial<Task> = { sortOrder: computeReorderSortOrder(prevOrder, target.sortOrder) };
		if (status && dragged.status !== status) patch.status = status;
		applyReorder(id, patch);
	}

	// Drop on empty column space → move to that status, appended at the end of the
	// global manual order.
	function dropOnColumn(status: Task['status']) {
		const id = draggingId;
		draggingId = null;
		if (!id) return;
		const dragged = boardTasks.find((t) => t.id === id);
		if (!dragged) return;
		const maxOrder = boardTasks.reduce((m, t) => Math.max(m, t.sortOrder ?? 0), 0);
		const patch: Partial<Task> = { sortOrder: maxOrder + 1 };
		if (dragged.status !== status) patch.status = status;
		applyReorder(id, patch);
	}

	// The flat visible order for the LIST view (top-level rows with their children
	// interleaved) — the neighbour source for a row-level reorder drop.
	const listVisible = $derived.by(() => {
		const out: Task[] = [];
		for (const tk of topLevelTasks) {
			out.push(tk);
			for (const c of childrenByParent[tk.id] || []) out.push(c);
		}
		return out;
	});

	function addCategory() {
		form.categories = [...form.categories, ''];
	}

	function removeCategory(idx: number) {
		form.categories = form.categories.filter((_, i) => i !== idx);
	}

	function updateCategory(idx: number, value: string) {
		form.categories = form.categories.map((c, i) => (i === idx ? value : c));
	}

	// — Checklist (QoL #21) — local edits to form.checklist; the server assigns a
	// real id on save, so a client-only item uses a temporary one just for keying.
	let checklistDraft = $state('');

	function addChecklistItem() {
		const text = checklistDraft.trim();
		if (!text) return;
		form.checklist = [...form.checklist, { id: `new-${Date.now()}-${form.checklist.length}`, text, done: false }];
		checklistDraft = '';
	}

	function toggleChecklistItem(idx: number) {
		form.checklist = form.checklist.map((c, i) => (i === idx ? { ...c, done: !c.done } : c));
	}

	function updateChecklistText(idx: number, value: string) {
		form.checklist = form.checklist.map((c, i) => (i === idx ? { ...c, text: value } : c));
	}

	function removeChecklistItem(idx: number) {
		form.checklist = form.checklist.filter((_, i) => i !== idx);
	}

	function checklistProgress(task: Task): { done: number; total: number } {
		const items = task.checklist || [];
		return { done: items.filter((i) => i.done).length, total: items.length };
	}

	const statusColumns: Task['status'][] = ['needs-action', 'in-progress', 'completed', 'cancelled'];

	const statusFilterOptions = $derived([
		{ value: '', label: 'All statuses' },
		...statusColumns.map((s) => ({ value: s, label: statusLabel(s) }))
	]);

	// — Subtasks (ONE level of nesting, Outlook/Gmail parity) —
	// Parent→children grouping over the already-loaded $tasks store (mirrors
	// groupByStatus; no fetch — taskQuery already pulls up to 500). One level only,
	// so a child (parentId set) is never itself a valid parent → no cycle possible.
	const childrenByParent = $derived.by(() => {
		const map: Record<string, Task[]> = {};
		for (const tk of boardTasks) {
			if (tk.parentId) (map[tk.parentId] ||= []).push(tk);
		}
		return map;
	});
	const topLevelTasks = $derived(boardTasks.filter((tk) => !tk.parentId));

	// Parent picker options: top-level tasks only (excludes self + all children →
	// keeps nesting flat and acyclic). A task that already HAS children can't be
	// re-parented (that would create a 2nd level), so its picker is empty.
	const selfHasChildren = $derived(
		!!editingTask && boardTasks.some((tk) => tk.parentId === editingTask!.id)
	);
	const parentOptions = $derived([
		{ value: '', label: t('tasks.parent_none') },
		...(selfHasChildren
			? []
			: topLevelTasks
					.filter((tk) => tk.id !== editingTask?.id)
					.map((tk) => ({ value: tk.id, label: tk.title || '(untitled)' })))
	]);

	function childProgress(parentId: string): { done: number; total: number } {
		const kids = childrenByParent[parentId] || [];
		return { done: kids.filter((k) => k.status === 'completed').length, total: kids.length };
	}

	function statusBadgeClass(status: string): string {
		if (status === 'in-progress') return 'status-in-progress';
		if (status === 'completed') return 'status-completed';
		if (status === 'cancelled') return 'status-cancelled';
		return 'status-needs-action';
	}

	function statusColumnBorderColor(status: string): string {
		switch (status) {
			case 'in-progress': return 'var(--accent)';
			case 'completed': return 'var(--success-fg)';
			case 'cancelled': return 'var(--text-disabled)';
			default: return 'var(--info-fg)';
		}
	}
</script>

	{#if error}
		<div class="error-banner" role="alert">{error}</div>
	{/if}

	<PimShell title="Tasks">
		{#snippet topbarActions()}
			{#if $activeView.kind === 'personal'}
				<Input bind:value={$searchText} placeholder="Search tasks" aria-label="Search tasks" maxlength={255} size="md" />
			{/if}
			{#if $activeView.kind !== 'assigned'}
				<div class="view-toggle">
					<IconButton label="Kanban view" variant="ghost" size="sm" active={$viewMode === 'kanban'} onclick={() => viewMode.set('kanban')}>
						<Icon name="Kanban" size={18} />
					</IconButton>
					<IconButton label="List view" variant="ghost" size="sm" active={$viewMode === 'list'} onclick={() => viewMode.set('list')}>
						<Icon name="List" size={18} />
					</IconButton>
				</div>
				<Button variant="primary" size="md" onclick={openCreateModal}>New task</Button>
			{/if}
		{/snippet}

		{#snippet sidebar()}
			<nav class="task-views" aria-label={t('tasks.lists.title')}>
				<button
					class="task-view-row"
					class:is-active={$activeView.kind === 'personal'}
					aria-current={$activeView.kind === 'personal' ? 'page' : undefined}
					onclick={() => setActiveView({ kind: 'personal' })}
				>
					<Icon name="ListChecks" size={16} strokeWidth={1.75} />
					<span>{t('tasks.title')}</span>
				</button>
				{#if sharedListsEnabled}
					<button
						class="task-view-row"
						class:is-active={$activeView.kind === 'assigned'}
						aria-current={$activeView.kind === 'assigned' ? 'page' : undefined}
						onclick={() => setActiveView({ kind: 'assigned' })}
					>
						<Icon name="UserCheck" size={16} strokeWidth={1.75} />
						<span>{t('tasks.assigned.title')}</span>
						{#if assignedOpenCount > 0}<span class="task-view-badge">{assignedOpenCount}</span>{/if}
					</button>

					<div class="task-view-section-header">
						<span>{t('tasks.lists.title')}</span>
						<IconButton label={t('tasks.lists.new')} variant="ghost" size="sm" onclick={openNewListDialog}>
							<Icon name="Plus" size={14} />
						</IconButton>
					</div>
					{#if $taskLists.length === 0}
						<p class="task-view-empty">{t('tasks.lists.empty')}</p>
					{/if}
					{#each $taskLists as list (list.id)}
						<div class="task-view-row task-list-row" class:is-active={$activeView.kind === 'list' && $activeView.listId === list.id}>
							<button
								class="task-view-row-btn"
								aria-current={$activeView.kind === 'list' && $activeView.listId === list.id ? 'page' : undefined}
								onclick={() => setActiveView({ kind: 'list', listId: list.id })}
							>
								<span class="list-color-dot" style="background: {list.color || 'var(--text-tertiary)'}"></span>
								<span class="list-name">{list.name}</span>
								{#if (list.openCount ?? 0) > 0}<span class="task-view-badge">{list.openCount}</span>{/if}
							</button>
							{#if list.role === 'owner'}
								<Menu
									label={t('tasks.lists.manageMenu', { name: list.name })}
									align="end"
									items={listMenuItems}
									onSelect={(id) => onListMenuSelect(id, list)}
								>
									{#snippet children()}
										<Icon name="MoreHorizontal" size={14} />
									{/snippet}
								</Menu>
							{/if}
						</div>
					{/each}
				{/if}
			</nav>
			{#if $activeView.kind === 'personal'}
				<div class="sidebar-filter">
					<Select
						label="Filter by status"
						value={$statusFilter || ''}
						onchange={(e) => statusFilter.set((e.currentTarget as HTMLSelectElement).value || null)}
						options={statusFilterOptions}
					/>
				</div>
			{/if}
		{/snippet}

		{#snippet main()}
			{#if $activeView.kind === 'assigned'}
				<!-- Assigned-to-me: list-mode only (ponytail: a kanban here would
				     imply drag = full edit, but the only legal mutation is status —
				     add a kanban if users ask for one). -->
				{#if $assignedTasks.length === 0}
					<EmptyState title={t('tasks.assigned.empty')} />
				{:else}
					<ul class="assigned-list">
						{#each $assignedTasks as row (row.id)}
							<li class="assigned-row">
								<div class="assigned-row-main">
									<span class="list-title" class:done={row.status === 'completed'}>{row.title}</span>
									<span class="assigned-provenance">
										{t('tasks.assigned.from', { name: row.ownerName || row.ownerEmail })}
										{row.listName ? ' · ' + row.listName : ' · ' + t('tasks.assigned.personalTask')}
									</span>
								</div>
								{#if row.dueAt}
									<span class="due-date" class:overdue={isOverdue(row.dueAt)}>{formatDateShort(row.dueAt)}</span>
								{/if}
								<Select
									aria-label={t('tasks.assigned.title') + ': ' + row.title}
									value={row.status}
									onchange={async (e) => {
										const status = (e.currentTarget as HTMLSelectElement).value;
										try {
											await setAssignedStatus(row.id, status);
										} catch (err) {
											error = parseError(err).message;
											showToast(t('tasks.assigned.statusUpdateFailed'), {});
										}
									}}
									options={statusColumns.map((s) => ({ value: s, label: statusLabel(s) }))}
								/>
							</li>
						{/each}
					</ul>
				{/if}
			{:else if loading && boardTasks.length === 0}
				<div class="loading-wrap">
					<Spinner size={20} label="Loading tasks" />
				</div>
			{:else if boardTasks.length === 0}
				<EmptyState title="No tasks. Create your first task." />
			{:else if $viewMode === 'kanban'}
				{@const grouped = groupByStatus(boardTasks)}
				<div class="kanban">
					{#each statusColumns as status}
						<div
							class="kanban-column"
							role="list"
							aria-label={statusLabel(status)}
							ondragover={(e) => e.preventDefault()}
							ondrop={(e) => { e.preventDefault(); dropOnColumn(status); }}
						>
							<div class="column-header" style="border-color: {statusColumnBorderColor(status)}">
								<span class="column-title">{statusLabel(status)}</span>
								<span class="column-count">{(grouped[status] || []).length}</span>
							</div>
							<div class="column-cards">
								{#each grouped[status] || [] as task (task.id)}
									<div
										class="task-card"
										class:dragging={draggingId === task.id}
										draggable={!isTaskBusy(task.id)}
										ondragstart={(e) => { if (isTaskBusy(task.id)) { e.preventDefault(); return; } draggingId = task.id; e.dataTransfer?.setData('text/plain', task.id); }}
										ondragend={() => { draggingId = null; }}
										ondragover={(e) => e.preventDefault()}
										ondrop={(e) => { e.preventDefault(); e.stopPropagation(); reorderBefore(task, grouped[status] || [], status); }}
										onclick={() => openDetailModal(task)}
										role="button"
										tabindex="0"
										onkeydown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); openDetailModal(task); } }}
									>
										<div class="card-header">
											<span class="priority-dot" style="background: {priorityColor(task.priority)}" title={priorityLabel(task.priority)}></span>
											{#if task.dueAt}
												<span class="due-date" class:overdue={isOverdue(task.dueAt)}>{formatDateShort(task.dueAt)}</span>
											{/if}
										</div>
										<h4 class="card-title">{task.title}</h4>
										{#if checklistProgress(task).total > 0}
											{@const clp = checklistProgress(task)}
											<span class="checklist-badge">
												<Icon name="SquareCheck" size={12} />
												{t('tasks.checklist_progress', { done: String(clp.done), total: String(clp.total) })}
											</span>
										{/if}
										{#if task.description}
											<p class="card-desc">{task.description.slice(0, 80)}{task.description.length > 80 ? '...' : ''}</p>
										{/if}
										{#if task.assigneeName || task.assigneeEmail}
											<div class="card-assignee">{task.assigneeName || task.assigneeEmail}</div>
										{/if}
										<div class="card-actions">
											{#if status !== 'in-progress'}
												<button class="action-btn" disabled={isTaskBusy(task.id)} onclick={(e) => { e.stopPropagation(); moveStatus(task, 'in-progress'); }}>Start</button>
											{/if}
											{#if status !== 'completed'}
												<button class="action-btn" disabled={isTaskBusy(task.id)} onclick={(e) => { e.stopPropagation(); moveStatus(task, 'completed'); }}>Done</button>
											{/if}
										</div>
									</div>
								{/each}
							</div>
						</div>
					{/each}
				</div>
			{:else}
				<div class="list-view">
					<table>
						<thead>
							<tr>
								<th class="check-col"><span class="sr-only">Done</span></th>
								<th>Task</th>
								<th>Status</th>
								<th>Priority</th>
								<th>Due</th>
								<th>Assignee</th>
								<th>Actions</th>
							</tr>
						</thead>
						<tbody>
							{#snippet taskRow(task: Task, isChild: boolean)}
								<tr
									draggable={!isTaskBusy(task.id)}
									ondragstart={(e) => { if (isTaskBusy(task.id)) { e.preventDefault(); return; } draggingId = task.id; e.dataTransfer?.setData('text/plain', task.id); }}
									ondragend={() => { draggingId = null; }}
									ondragover={(e) => e.preventDefault()}
									ondrop={(e) => { e.preventDefault(); reorderBefore(task, listVisible); }}
									onclick={() => openDetailModal(task)}
									onkeydown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); openDetailModal(task); } }}
									role="button"
									tabindex="0"
									class="list-row"
									class:dragging={draggingId === task.id}
									class:sub-row={isChild}
								>
									<td class="check-col">
										<input
											type="checkbox"
											aria-label="Mark task done"
											checked={task.status === 'completed'}
											disabled={isTaskBusy(task.id)}
											onclick={(e) => {
												e.stopPropagation();
												moveStatus(task, task.status === 'completed' ? 'needs-action' : 'completed');
											}}
										/>
									</td>
									<td>
										<div class="list-title" class:done={task.status === 'completed'} class:sub-title={isChild}>
											{task.title}
											{#if !isChild}
												{@const prog = childProgress(task.id)}
												{#if prog.total > 0}
													<span class="subtask-count">{t('tasks.subtasks_progress', { done: String(prog.done), total: String(prog.total) })}</span>
												{/if}
											{/if}
											{#if checklistProgress(task).total > 0}
												{@const clp = checklistProgress(task)}
												<span class="checklist-badge">
													<Icon name="SquareCheck" size={12} />
													{t('tasks.checklist_progress', { done: String(clp.done), total: String(clp.total) })}
												</span>
											{/if}
										</div>
										{#if task.description}
											<div class="list-desc">{task.description.slice(0, 60)}{task.description.length > 60 ? '...' : ''}</div>
										{/if}
									</td>
									<td>
										<span class="status-badge {statusBadgeClass(task.status)}">
											{statusLabel(task.status)}
										</span>
									</td>
									<td>
										<span class="priority-badge" style="color: {priorityColor(task.priority)}">
											{priorityLabel(task.priority)}
										</span>
									</td>
									<td class:overdue={isOverdue(task.dueAt)}>{formatDateShort(task.dueAt)}</td>
									<td>{task.assigneeName || task.assigneeEmail || '-'}</td>
									<td class="actions-cell">
										<IconButton label="Edit task" variant="ghost" size="sm" disabled={isTaskBusy(task.id)} onclick={(e) => { e.stopPropagation(); openEditModal(task); }}>
											<Icon name="Pencil" size={16} />
										</IconButton>
										<IconButton label="Delete task" variant="ghost" size="sm" disabled={isTaskBusy(task.id)} onclick={(e) => { e.stopPropagation(); removeTask(task); }}>
											<Icon name="Trash2" size={16} />
										</IconButton>
									</td>
								</tr>
							{/snippet}
							{#each topLevelTasks as task (task.id)}
								{@render taskRow(task, false)}
								{#each childrenByParent[task.id] || [] as child (child.id)}
									{@render taskRow(child, true)}
								{/each}
							{/each}
						</tbody>
					</table>
				</div>
			{/if}
		{/snippet}
	</PimShell>

	<!-- Create / Edit modal -->
	<Dialog
		open={showModal && modalMode !== 'detail'}
		title={modalMode === 'create' ? 'New task' : 'Edit task'}
		onClose={closeModal}
	>
		{#snippet children()}
			<form class="tasks-form" onsubmit={(e) => { e.preventDefault(); saveTask(); }}>
				{#if formServerError}
					<div class="error-banner" role="alert" tabindex="-1" bind:this={formServerErrorElement}>{formServerError}</div>
				{/if}
				<div class="form-group">
					<Input label="Title" bind:value={form.title} placeholder="Task title" maxlength={255} required error={formErrors.title} />
				</div>
				<div class="form-row">
					<div class="form-group">
						<Select label="Status" bind:value={form.status} options={[
							{value: 'needs-action', label: 'To Do'},
							{value: 'in-progress', label: 'In Progress'},
							{value: 'completed', label: 'Done'},
							{value: 'cancelled', label: 'Cancelled'}
						]} />
					</div>
					<div class="form-group">
						<Select label="Priority" value={String(form.priority)} onchange={(e) => form.priority = parseInt((e.target as HTMLSelectElement).value)} options={[
							{value: '0', label: 'None'},
							{value: '1', label: 'Low'},
							{value: '5', label: 'Medium'},
							{value: '9', label: 'High'}
						]} />
					</div>
				</div>
				<div class="form-row">
					<div class="form-group">
						<Input label="Start date" type="datetime-local" bind:value={form.startAt} />
						<Input label="Due date" type="datetime-local" bind:value={form.dueAt} />
					</div>
					<div class="form-group">
						<Input label="Reminder" type="datetime-local" bind:value={form.reminderAt} />
					</div>
				</div>
				<div class="form-row">
					<div class="form-group assignee-picker">
						{#if currentListId}
							<!-- Shared list: assignment must land on a list member (server-
							     enforced, BZ133) — a free-text email invites a mismatch the
							     reducer would reject anyway, so pick from the roster instead. -->
							<Select
								label={t('tasks.assignee')}
								value={form.assignee}
								onchange={(e) => (form.assignee = (e.currentTarget as HTMLSelectElement).value)}
								options={[
									{ value: '', label: t('tasks.unassigned') },
									...(currentListMembers?.map((m) => ({ value: m.email, label: m.displayName || m.email })) ?? [])
								]}
							/>
						{:else}
							<Input
								label={t('tasks.assignee')}
								value={form.assignee}
								oninput={(e) => onAssigneeInput(e.currentTarget.value)}
								placeholder={t('tasks.assignee_placeholder')}
								maxlength={320}
							/>
							{#if form.assigneeName}
								<span class="assignee-name">{form.assigneeName}</span>
							{/if}
							{#if assigneeShow && assigneeResults.length > 0}
								<div class="assignee-dropdown" role="listbox">
									{#each assigneeResults as c (c.id)}
										{@const addr = c.email || c.emails?.[0]?.address || ''}
										<button type="button" class="assignee-item" role="option" aria-selected="false" onclick={() => pickAssignee(c)}>
											<strong>{c.displayName || addr}</strong>
											{#if c.displayName}<span>{addr}</span>{/if}
										</button>
									{/each}
								</div>
							{/if}
						{/if}
					</div>
					<div class="form-group">
						<Select
							label={t('tasks.recurrence')}
							value={recurrencePreset}
							onchange={(e) => onRecurrenceChange((e.target as HTMLSelectElement).value)}
							options={recurrenceOptions}
						/>
					</div>
				</div>
				<div class="form-group">
					<Select label={t('tasks.parent')} bind:value={form.parentId} options={parentOptions} />
				</div>
				<div class="form-group">
					<Textarea label="Description" bind:value={form.description} rows={3} placeholder="Add details..." maxlength={5000} error={formErrors.description} />
				</div>
				<div class="form-group">
					<span class="field-label">Categories</span>
					<div class="categories-list">
						{#each form.categories as cat, idx}
							<div class="category-row">
								<Input value={cat} oninput={(e) => updateCategory(idx, e.currentTarget.value)} placeholder="Category" maxlength={100} />
								<IconButton label="Remove category" variant="ghost" size="sm" onclick={() => removeCategory(idx)}>
									<Icon name="X" size={14} />
								</IconButton>
							</div>
						{/each}
						<Button variant="ghost" size="sm" onclick={addCategory}>Add category</Button>
					</div>
				</div>
				<div class="form-group">
					<span class="field-label">{t('tasks.checklist')}</span>
					<div class="checklist-list">
						{#each form.checklist as item, idx (item.id)}
							<div class="checklist-row">
								<Checkbox checked={item.done} ariaLabel={item.text} onchange={() => toggleChecklistItem(idx)} />
								<Input value={item.text} oninput={(e) => updateChecklistText(idx, e.currentTarget.value)} maxlength={500} />
								<IconButton label="Remove item" variant="ghost" size="sm" onclick={() => removeChecklistItem(idx)}>
									<Icon name="X" size={14} />
								</IconButton>
							</div>
						{/each}
						<div class="checklist-add">
							<Input
								value={checklistDraft}
								oninput={(e) => (checklistDraft = e.currentTarget.value)}
								onkeydown={(e) => { if (e.key === 'Enter') { e.preventDefault(); addChecklistItem(); } }}
								placeholder={t('tasks.checklist_add_placeholder')}
								maxlength={500}
							/>
							<Button variant="ghost" size="sm" onclick={addChecklistItem}>+</Button>
						</div>
					</div>
				</div>
			</form>
		{/snippet}
		{#snippet footer()}
			<div class="form-actions">
				<Button variant="primary" type="submit" disabled={modalSaving} onclick={saveTask}>
					{modalSaving ? 'Saving...' : 'Save'}
				</Button>
				<Button variant="secondary" onclick={closeModal}>Cancel</Button>
			</div>
		{/snippet}
	</Dialog>

	<!-- Detail modal -->
	<Dialog
		open={showModal && modalMode === 'detail'}
		title={editingTask?.title ?? ''}
		onClose={closeModal}
	>
		{#snippet children()}
			{#if editingTask}
				<div class="detail-content">
					<div class="detail-grid">
						<div class="detail-field">
							<span class="field-label">Status</span>
							<span class="status-badge {statusBadgeClass(editingTask.status)}">{statusLabel(editingTask.status)}</span>
						</div>
						<div class="detail-field">
							<span class="field-label">Priority</span>
							<span style="color: {priorityColor(editingTask.priority)}">{priorityLabel(editingTask.priority)}</span>
						</div>
						{#if editingTask.dueAt}
							<div class="detail-field">
								<span class="field-label">Due</span>
								<span class:overdue={isOverdue(editingTask.dueAt)}>{new Date(editingTask.dueAt).toLocaleString()}</span>
							</div>
						{/if}
						{#if editingTask.assigneeName || editingTask.assigneeEmail}
							<div class="detail-field">
								<span class="field-label">{t('tasks.assignee')}</span>
								<span>{editingTask.assigneeName || editingTask.assigneeEmail}</span>
							</div>
						{/if}
						{#if editingTask.recurrenceRule}
							<div class="detail-field">
								<span class="field-label">{t('tasks.recurrence')}</span>
								<span>{recurrenceLabel(editingTask.recurrenceRule)}</span>
							</div>
						{/if}
						{#if editingTask.linkedMessageId}
							<div class="detail-field">
								<span class="field-label">{t('tasks.linked_email')}</span>
								<Button variant="secondary" size="sm" onclick={openLinkedEmail}>
									{t('tasks.open_linked_email')}
								</Button>
							</div>
						{/if}
					</div>
					{#if editingTask.description}
						<div class="detail-description">
							<span class="field-label">Description</span>
							<p>{editingTask.description}</p>
						</div>
					{/if}
					{#if editingTask.categories && editingTask.categories.length > 0}
						<div class="detail-tags">
							{#each editingTask.categories as cat}
								<span class="tag-chip">{cat}</span>
							{/each}
						</div>
					{/if}

					<!-- Activity feed + comments (QoL #17) -->
					<details class="activity" open>
						<summary class="activity-summary">{t('tasks.activity')}</summary>
						{#if activityLoading}
							<div class="activity-loading"><Spinner size={16} label={t('tasks.activity')} /></div>
						{:else if activity.length === 0}
							<p class="activity-empty">{t('tasks.activity_empty')}</p>
						{:else}
							<ul class="activity-list">
								{#each activity as a (a.id)}
									<li class="activity-item">
										{#if a.kind === 'comment'}
											<div class="activity-head">
												<span class="activity-author">{t('tasks.activity_commented', { name: a.authorName || a.authorEmail })}</span>
												<span class="activity-time">{new Date(a.createdAt).toLocaleString()}</span>
											</div>
											<p class="activity-body">{a.body}</p>
										{:else}
											<div class="activity-head">
												<span class="activity-system">{activitySystemText(a)}</span>
												<span class="activity-time">{new Date(a.createdAt).toLocaleString()}</span>
											</div>
										{/if}
									</li>
								{/each}
							</ul>
						{/if}

						<div class="comment-box">
							<Textarea
								label={t('tasks.comment_submit')}
								value={commentBody}
								oninput={onCommentInput}
								rows={2}
								placeholder={t('tasks.comment_placeholder')}
								maxlength={5000}
							/>
							{#if mentionShow && mentionResults.length > 0}
								<div class="assignee-dropdown" role="listbox">
									{#each mentionResults as c (c.id)}
										{@const addr = c.email || c.emails?.[0]?.address || ''}
										<button type="button" class="assignee-item" role="option" aria-selected="false" onclick={() => pickMention(c)}>
											<strong>{c.displayName || addr}</strong>
											{#if c.displayName}<span>{addr}</span>{/if}
										</button>
									{/each}
								</div>
							{/if}
							<div class="comment-actions">
								<span class="comment-hint">{t('tasks.comment_mention_hint')}</span>
								<Button variant="primary" size="sm" disabled={commentSaving || !commentBody.trim()} onclick={submitComment}>
									{t('tasks.comment_submit')}
								</Button>
							</div>
						</div>
					</details>
				</div>
			{/if}
		{/snippet}
		{#snippet footer()}
			<div class="detail-actions">
				<Button variant="secondary" size="sm" onclick={() => editingTask && openEditModal(editingTask)}>Edit</Button>
				<Button variant="danger" size="sm" disabled={editingTask ? isTaskBusy(editingTask.id) : false} onclick={() => { if (editingTask) { removeTask(editingTask); closeModal(); } }}>
					{editingTask && isTaskBusy(editingTask.id) ? 'Deleting...' : 'Delete'}
				</Button>
			</div>
		{/snippet}
	</Dialog>

	<!-- Shared task lists (Phase 1): new/rename list dialog -->
	<Dialog
		open={showListDialog}
		title={listDialogMode === 'create' ? t('tasks.lists.new') : t('tasks.lists.rename')}
		onClose={closeListDialog}
	>
		{#snippet children()}
			<form class="tasks-form" onsubmit={(e) => { e.preventDefault(); saveListDialog(); }}>
				<Input
					label={t('tasks.lists.title')}
					bind:value={listDialogName}
					placeholder={t('tasks.lists.new')}
					maxlength={200}
					required
				/>
			</form>
		{/snippet}
		{#snippet footer()}
			<div class="form-actions">
				<Button variant="primary" type="submit" disabled={listDialogSaving || !listDialogName.trim()} onclick={saveListDialog}>
					{listDialogSaving ? 'Saving...' : 'Save'}
				</Button>
				<Button variant="secondary" onclick={closeListDialog}>Cancel</Button>
			</div>
		{/snippet}
	</Dialog>

	<!-- Shared task lists (Phase 1): member management -->
	{#if membersDialogList}
		<TaskListMembersDialog list={membersDialogList} onClose={() => (membersDialogList = null)} />
	{/if}

<style>

	/* — Error — */
	.error-banner {
		background: var(--danger-bg);
		color: var(--danger-fg);
		padding: 0.75rem;
		border-radius: var(--radius-sm);
		margin: 0.5rem 1rem;
	}

	/* — Sidebar filter — */
	.sidebar-filter {
		padding: 1rem;
	}

	/* — Shared task lists (Phase 1): sidebar nav — */
	.task-views {
		display: flex;
		flex-direction: column;
		padding: 0.5rem 0;
	}

	.task-view-row,
	.task-view-row-btn {
		display: flex;
		align-items: center;
		gap: 0.5rem;
		width: 100%;
		padding: 0.5rem 1rem;
		background: none;
		border: none;
		text-align: left;
		font-family: var(--font-sans);
		font-size: var(--text-sm);
		color: var(--text-secondary);
		cursor: pointer;
		border-radius: var(--radius-sm);
	}

	.task-view-row-btn {
		flex: 1;
		padding: 0.5rem 0;
		border-radius: 0;
	}

	.task-view-row:hover,
	.task-view-row-btn:hover {
		background: var(--surface-hover);
	}

	.task-view-row.is-active,
	.task-view-row-btn[aria-current='page'] {
		background: var(--surface-hover);
		color: var(--text-primary);
		font-weight: var(--weight-semibold);
	}

	.task-list-row {
		padding-right: 0.5rem;
	}

	.task-view-badge {
		margin-left: auto;
		background: var(--surface-sunken);
		color: var(--text-secondary);
		padding: 0.05rem 0.4rem;
		border-radius: 10px;
		font-size: var(--text-xs);
		font-weight: var(--weight-medium);
	}

	.task-view-section-header {
		display: flex;
		align-items: center;
		justify-content: space-between;
		padding: 0.75rem 1rem 0.25rem;
		font-size: var(--text-xs);
		font-weight: var(--weight-semibold);
		color: var(--text-tertiary);
		text-transform: uppercase;
		letter-spacing: 0.05em;
	}

	.task-view-empty {
		padding: 0.25rem 1rem 0.5rem;
		font-size: var(--text-xs);
		color: var(--text-tertiary);
	}

	.list-color-dot {
		width: 8px;
		height: 8px;
		border-radius: 50%;
		flex: none;
	}

	.list-name {
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
	}

	/* — Assigned-to-me view — */
	.assigned-list {
		list-style: none;
		margin: 0;
		padding: 1rem;
		display: flex;
		flex-direction: column;
		gap: 0.5rem;
	}

	.assigned-row {
		display: flex;
		align-items: center;
		gap: 0.75rem;
		background: var(--surface-card);
		border: 1px solid var(--border-default);
		border-radius: var(--radius-md);
		padding: 0.6rem 0.75rem;
	}

	.assigned-row-main {
		flex: 1;
		display: flex;
		flex-direction: column;
		gap: 0.1rem;
		min-width: 0;
	}

	.assigned-provenance {
		font-size: var(--text-xs);
		color: var(--text-tertiary);
	}

	/* — View toggle — */
	.view-toggle {
		display: flex;
		gap: 2px;
	}

	/* — Loading / empty — */
	.loading-wrap {
		display: flex;
		align-items: center;
		justify-content: center;
		padding: 3rem;
	}

	/* — Kanban — */
	.kanban {
		display: grid;
		grid-template-columns: 1fr;
		gap: 1rem;
		flex: 1;
		overflow-x: auto;
		min-height: 0;
		padding: 1rem;
	}

	@container (min-width: 640px) {
		.kanban {
			grid-template-columns: repeat(2, 1fr);
		}
	}

	@container (min-width: 1024px) {
		.kanban {
			grid-template-columns: repeat(4, 1fr);
		}
	}

	.kanban-column {
		background: var(--surface-sunken);
		border-radius: var(--radius-md);
		display: flex;
		flex-direction: column;
		min-height: 200px;
	}

	.column-header {
		display: flex;
		justify-content: space-between;
		align-items: center;
		padding: 0.75rem;
		border-bottom: 3px solid;
		font-weight: var(--weight-semibold);
		color: var(--text-primary);
	}

	.column-count {
		background: var(--surface-hover);
		color: var(--text-secondary);
		padding: 0.1rem 0.5rem;
		border-radius: 12px;
		font-size: var(--text-xs);
		font-weight: var(--weight-medium);
	}

	.column-cards {
		padding: 0.5rem;
		display: flex;
		flex-direction: column;
		gap: 0.5rem;
		overflow-y: auto;
		flex: 1;
	}

	.task-card {
		background: var(--surface-card);
		border: 1px solid var(--border-default);
		border-radius: var(--radius-md);
		padding: 0.75rem;
		box-shadow: var(--shadow-sm, 0 1px 3px rgb(20,21,29,0.08));
		cursor: pointer;
		transition: box-shadow var(--duration-fast, 0.15s) var(--ease-out);
	}

	.task-card:hover {
		box-shadow: var(--shadow-md, 0 3px 8px rgb(20,21,29,0.12));
	}

	/* — Drag-and-drop reorder (QoL #20) — */
	.task-card[draggable='true'] {
		cursor: grab;
	}

	.task-card.dragging,
	.list-row.dragging {
		opacity: 0.5;
	}

	.card-header {
		display: flex;
		justify-content: space-between;
		align-items: center;
		margin-bottom: 0.4rem;
	}

	.priority-dot {
		width: 10px;
		height: 10px;
		border-radius: 50%;
		display: inline-block;
		flex: none;
	}

	.due-date {
		font-size: var(--text-xs);
		color: var(--text-tertiary);
	}

	.due-date.overdue,
	.overdue {
		color: var(--danger-fg);
		font-weight: var(--weight-semibold);
	}

	.card-title {
		margin: 0 0 0.3rem;
		font-size: var(--text-md);
		font-weight: var(--weight-semibold);
		color: var(--text-primary);
	}

	.card-desc {
		margin: 0 0 0.5rem;
		font-size: var(--text-sm);
		color: var(--text-tertiary);
		line-height: 1.4;
	}

	.card-assignee {
		font-size: var(--text-xs);
		color: var(--text-secondary);
		margin-bottom: 0.5rem;
	}

	.card-actions {
		display: flex;
		gap: 0.3rem;
		flex-wrap: wrap;
	}

	.action-btn {
		background: var(--surface-sunken);
		color: var(--text-secondary);
		border: 1px solid var(--border-default);
		padding: 0.2rem 0.5rem;
		border-radius: var(--radius-sm);
		font-size: var(--text-xs);
		font-family: var(--font-sans);
		cursor: pointer;
		transition: background var(--duration-fast, 0.15s);
	}

	.action-btn:hover {
		background: var(--surface-hover);
		color: var(--text-primary);
	}

	/* — List view — */
	.list-view {
		overflow: auto;
		flex: 1;
	}

	.list-view table {
		width: 100%;
		border-collapse: collapse;
		background: var(--surface-card);
		border-radius: var(--radius-md);
		overflow: hidden;
		font-size: var(--text-sm);
	}

	.list-view th {
		background: var(--surface-inverse);
		color: var(--text-inverse);
		padding: 0.6rem;
		text-align: left;
		font-size: var(--text-sm);
		font-weight: var(--weight-medium);
	}

	.list-view td {
		padding: 0.6rem;
		border-bottom: 1px solid var(--border-subtle);
		font-size: var(--text-sm);
		color: var(--text-primary);
	}

	.list-row {
		cursor: pointer;
	}

	.list-row:hover {
		background: var(--surface-hover);
	}

	.list-title {
		font-weight: var(--weight-semibold);
		color: var(--text-primary);
	}

	.list-title.done {
		text-decoration: line-through;
		color: var(--text-tertiary);
	}

	/* — Subtasks (one level) — */
	.sub-row td:first-child {
		border-left: 2px solid var(--border-default);
	}

	.sub-title {
		padding-left: 1.25rem;
		font-weight: var(--weight-regular);
	}

	.subtask-count {
		margin-left: 0.5rem;
		font-size: var(--text-xs);
		font-weight: var(--weight-medium);
		color: var(--text-secondary);
	}

	.check-col {
		width: 2rem;
		text-align: center;
	}

	.sr-only {
		position: absolute;
		width: 1px;
		height: 1px;
		padding: 0;
		margin: -1px;
		overflow: hidden;
		clip-path: inset(50%);
		white-space: nowrap;
		border: 0;
	}

	.list-desc {
		font-size: var(--text-xs);
		color: var(--text-tertiary);
	}

	/* — Status badges — */
	.status-badge {
		padding: 0.2rem 0.5rem;
		border-radius: var(--radius-sm);
		font-size: var(--text-xs);
		font-weight: var(--weight-semibold);
	}

	.status-needs-action {
		background: var(--surface-sunken);
		color: var(--text-secondary);
	}

	.status-in-progress {
		background: var(--indigo-100);
		color: var(--accent);
	}

	.status-completed {
		background: var(--success-bg);
		color: var(--success-fg);
	}

	.status-cancelled {
		background: var(--surface-sunken);
		color: var(--text-disabled);
	}

	.priority-badge {
		font-size: var(--text-sm);
		font-weight: var(--weight-semibold);
	}

	.actions-cell {
		display: flex;
		gap: 2px;
	}

	/* — Form (inside Dialog) — */
	.tasks-form {
		display: flex;
		flex-direction: column;
		gap: 0.75rem;
	}

	.form-group {
		display: flex;
		flex-direction: column;
		gap: 0.3rem;
	}

	.form-row {
		display: grid;
		grid-template-columns: 1fr 1fr;
		gap: 0.75rem;
	}

	.field-label {
		font-size: var(--text-xs);
		font-weight: var(--weight-semibold);
		color: var(--text-secondary);
		text-transform: uppercase;
		letter-spacing: 0.05em;
	}

	.categories-list {
		display: flex;
		flex-direction: column;
		gap: 0.3rem;
	}

	.category-row {
		display: flex;
		gap: 0.3rem;
		align-items: center;
	}

	.category-row :global(.sj-input) {
		flex: 1;
	}

	/* — Checklist (QoL #21) — */
	.checklist-list {
		display: flex;
		flex-direction: column;
		gap: 0.3rem;
	}

	.checklist-row,
	.checklist-add {
		display: flex;
		gap: 0.4rem;
		align-items: center;
	}

	.checklist-row :global(.sj-field),
	.checklist-add :global(.sj-field) {
		flex: 1;
	}

	.checklist-badge {
		display: inline-flex;
		align-items: center;
		gap: 0.2rem;
		margin-left: 0.5rem;
		font-size: var(--text-xs);
		font-weight: var(--weight-medium);
		color: var(--text-secondary);
		vertical-align: middle;
	}

	/* — Assignee picker — */
	.assignee-picker {
		position: relative;
	}

	.assignee-name {
		font-size: var(--text-xs);
		color: var(--text-secondary);
	}

	.assignee-dropdown {
		position: absolute;
		top: 100%;
		left: 0;
		right: 0;
		z-index: 20;
		margin-top: 2px;
		max-height: 220px;
		overflow-y: auto;
		background: var(--surface-card);
		border: 1px solid var(--border-default);
		border-radius: var(--radius-md);
		box-shadow: var(--shadow-md, 0 3px 8px rgb(20,21,29,0.12));
	}

	.assignee-item {
		display: flex;
		flex-direction: column;
		gap: 1px;
		width: 100%;
		padding: 0.4rem 0.6rem;
		text-align: left;
		background: none;
		border: none;
		cursor: pointer;
		font-family: var(--font-sans);
	}

	.assignee-item:hover,
	.assignee-item:focus-visible {
		background: var(--surface-hover);
	}

	.assignee-item strong {
		font-size: var(--text-sm);
		font-weight: var(--weight-medium);
		color: var(--text-primary);
	}

	.assignee-item span {
		font-size: var(--text-xs);
		color: var(--text-secondary);
	}

	.form-actions {
		display: flex;
		gap: 0.5rem;
	}

	/* — Detail view — */
	.detail-content {
		padding: 0;
	}

	.detail-grid {
		display: grid;
		grid-template-columns: 1fr 1fr;
		gap: 0.75rem;
		margin-bottom: 1rem;
	}

	.detail-field {
		display: flex;
		flex-direction: column;
		gap: 0.2rem;
	}

	.detail-field .field-label,
	.detail-description .field-label {
		font-size: var(--text-xs);
		color: var(--text-tertiary);
		font-weight: var(--weight-semibold);
		display: block;
		margin-bottom: 0.2rem;
	}

	.detail-description {
		margin-bottom: 1rem;
	}

	.detail-description p {
		margin: 0;
		white-space: pre-wrap;
		color: var(--text-primary);
		font-size: var(--text-sm);
		line-height: 1.5;
	}

	.detail-tags {
		display: flex;
		gap: 0.3rem;
		flex-wrap: wrap;
	}

	.tag-chip {
		background: var(--surface-sunken);
		color: var(--text-secondary);
		padding: 0.2rem 0.5rem;
		border-radius: var(--radius-sm);
		font-size: var(--text-xs);
		font-weight: var(--weight-medium);
	}

	.detail-actions {
		display: flex;
		gap: 0.5rem;
	}

	/* — Activity feed + comments (QoL #17) — */
	.activity {
		margin-top: 1rem;
		border-top: 1px solid var(--border-subtle);
		padding-top: 0.75rem;
	}

	.activity-summary {
		font-size: var(--text-xs);
		font-weight: var(--weight-semibold);
		color: var(--text-secondary);
		text-transform: uppercase;
		letter-spacing: 0.05em;
		cursor: pointer;
	}

	.activity-loading,
	.activity-empty {
		font-size: var(--text-sm);
		color: var(--text-tertiary);
		padding: 0.5rem 0;
	}

	.activity-list {
		list-style: none;
		margin: 0.5rem 0;
		padding: 0;
		display: flex;
		flex-direction: column;
		gap: 0.6rem;
	}

	.activity-item {
		border-left: 2px solid var(--border-default);
		padding-left: 0.6rem;
	}

	.activity-head {
		display: flex;
		justify-content: space-between;
		align-items: baseline;
		gap: 0.5rem;
	}

	.activity-author {
		font-size: var(--text-sm);
		font-weight: var(--weight-semibold);
		color: var(--text-primary);
	}

	.activity-system {
		font-size: var(--text-sm);
		color: var(--text-secondary);
	}

	.activity-time {
		font-size: var(--text-xs);
		color: var(--text-tertiary);
		white-space: nowrap;
	}

	.activity-body {
		margin: 0.2rem 0 0;
		font-size: var(--text-sm);
		color: var(--text-primary);
		white-space: pre-wrap;
		line-height: 1.5;
	}

	.comment-box {
		position: relative;
		margin-top: 0.5rem;
	}

	.comment-actions {
		display: flex;
		justify-content: space-between;
		align-items: center;
		gap: 0.5rem;
		margin-top: 0.4rem;
	}

	.comment-hint {
		font-size: var(--text-xs);
		color: var(--text-tertiary);
	}
</style>
