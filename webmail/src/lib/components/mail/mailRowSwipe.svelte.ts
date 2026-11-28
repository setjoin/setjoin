// Swipe-reveal coordination (QoL #2 — swipe actions on mail rows). Module-level
// $state so every MailRow instance can see which row (if any) currently has its
// action tray revealed — only one row may be open at a time: opening a new one
// snaps back whichever was previously open, per spec.
let openRowId = $state<string | null>(null);

export function getOpenSwipeRowId(): string | null {
	return openRowId;
}

export function setOpenSwipeRowId(id: string | null): void {
	openRowId = id;
}
