// M1 primitive library barrel — the single import point for all setjoin UI primitives.
// Usage: import { Button, Dialog, showToast } from '$lib/components/ui';

// — Buttons (part 1) —
export { default as Button } from './Button.svelte';
export { default as IconButton } from './IconButton.svelte';

// — Forms (part 2) —
export { default as Input } from './Input.svelte';
export { default as Select } from './Select.svelte';
export { default as Checkbox } from './Checkbox.svelte';
export { default as Switch } from './Switch.svelte';
export { default as Radio } from './Radio.svelte';
export { default as Textarea } from './Textarea.svelte';
export { default as Tag } from './Tag.svelte';
// TAG_COLORS lives in the sibling plain module (not Tag.svelte's script module).
export { TAG_COLORS } from './tag';

// — Display & navigation (part 3) —
export { default as Badge } from './Badge.svelte';
export { default as Avatar } from './Avatar.svelte';
export { default as Card } from './Card.svelte';
export { default as Tabs } from './Tabs.svelte';
export type { TabItem } from './Tabs.svelte';
export { default as SidebarItem } from './SidebarItem.svelte';
export { default as Menu } from './Menu.svelte';
export { default as Tooltip } from './Tooltip.svelte';
export { default as Resizer } from './Resizer.svelte';
export { default as SplitPane } from './SplitPane.svelte';

// — Feedback & data display (part 4) —
export { default as Dialog } from './Dialog.svelte';
export { default as ConfirmDestructive } from './ConfirmDestructive.svelte';
export { default as Toast } from './Toast.svelte';
export { showToast, dismissToast, clearToasts, toasts } from './toasts.svelte';
export type { ToastHandle, ToastItem, ToastOptions } from './toasts.svelte';
export { default as Spinner } from './Spinner.svelte';
export { default as Progress } from './Progress.svelte';
export { default as EmptyState } from './EmptyState.svelte';
export { default as Pagination } from './Pagination.svelte';
export { formatRange, pageCount } from './pagination';
export { default as DateTimePicker } from './DateTimePicker.svelte';
export { buildTimeSlots, combineDateTime, isFuture, toDateStr, toTimeSlot } from './datetime';
export { default as Table } from './Table.svelte';
export { nextSort, ariaSort } from './table';
export type { TableColumn, SortDir } from './table';

// — Controls (part 5) —
export { default as Slider } from './Slider.svelte';
