// blocked.ts — pure: blockedCopy(native) → { titleKey, bodyKey, actions[] }
// Testable seam: no DOM, no i18n runtime, no Svelte.
// Maps {native shell vs plain browser} to the right copy + recovery actions
// for the end-user lockout screen (CA-2 T15b / shared-widget §7).

export interface BlockedAction {
	id: 'request_approval' | 'install_app' | 'contact_admin' | 'check_again';
	primary: boolean;
	labelKey: string;
}

export interface BlockedCopy {
	titleKey: string;
	bodyKey: string;
	actions: BlockedAction[];
}

export function blockedCopy(native: boolean): BlockedCopy {
	const actions: BlockedAction[] = native
		? [
				{ id: 'request_approval', primary: true,  labelKey: 'device_lockdown.blocked.request' },
				{ id: 'contact_admin',    primary: false, labelKey: 'device_lockdown.blocked.contact' },
			]
		: [
				// ponytail: plain browser cannot present a device proof — direct to native install.
				{ id: 'install_app',   primary: true,  labelKey: 'device_lockdown.blocked.install' },
				{ id: 'contact_admin', primary: false, labelKey: 'device_lockdown.blocked.contact' },
			];
	return {
		titleKey: 'device_lockdown.blocked.title',
		bodyKey: 'device_lockdown.blocked.body',
		actions,
	};
}
