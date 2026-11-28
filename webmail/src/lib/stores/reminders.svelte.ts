import { reminderGet, reminderDismiss, reminderSnooze, type Reminder } from '$lib/jmap/client';

export type SnoozePreset = '5m' | '1h' | 'tomorrow';

// Resolve a snooze preset to an absolute ISO instant (the reducer wants a future time).
export function presetToISO(preset: SnoozePreset): string {
	const d = new Date();
	if (preset === '5m') d.setMinutes(d.getMinutes() + 5);
	else if (preset === '1h') d.setHours(d.getHours() + 1);
	else {
		d.setDate(d.getDate() + 1);
		d.setHours(9, 0, 0, 0);
	}
	return d.toISOString();
}

// RemindersStore — the active-reminders surface. load() fetches fired-not-dismissed
// reminders (event VALARM + task reminder_at + flagged mail, all via Reminder/get);
// dismiss/snooze are optimistic and re-sync on failure. Backend gate is the reducer.
export class RemindersStore {
	list = $state<Reminder[]>([]);
	loading = $state(false);

	async load(): Promise<void> {
		if (this.loading) return;
		this.loading = true;
		try {
			this.list = await reminderGet();
		} catch {
			// Leave the current list on a transient fetch error — never blank the window.
		} finally {
			this.loading = false;
		}
	}

	async dismiss(id: string): Promise<void> {
		this.list = this.list.filter((r) => r.id !== id); // optimistic
		try {
			await reminderDismiss(id);
		} catch {
			await this.load();
		}
	}

	async dismissAll(): Promise<void> {
		this.list = [];
		try {
			await reminderDismiss();
		} catch {
			await this.load();
		}
	}

	async snooze(id: string, preset: SnoozePreset): Promise<void> {
		this.list = this.list.filter((r) => r.id !== id); // optimistic
		try {
			await reminderSnooze(id, presetToISO(preset));
		} catch {
			await this.load();
		}
	}
}
