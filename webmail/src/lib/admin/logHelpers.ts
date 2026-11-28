type BadgeVariant = 'neutral' | 'success' | 'warning' | 'danger' | 'info' | 'accent';

/**
 * Maps a log level string to an M1 Badge variant.
 * error → danger, warn/warning → warning, info → info,
 * debug/trace → neutral, everything else → neutral.
 */
export function logLevelBadgeVariant(level: string): BadgeVariant {
	switch (level?.toLowerCase()) {
		case 'error':
			return 'danger';
		case 'warn':
		case 'warning':
			return 'warning';
		case 'info':
			return 'info';
		case 'debug':
		case 'trace':
			return 'neutral';
		default:
			return 'neutral';
	}
}

/**
 * Maps an auth event name to an M1 Badge variant.
 * login → success, login_failed → danger, everything else → neutral.
 */
export function eventBadgeVariant(event: string): BadgeVariant {
	switch (event) {
		case 'login':
			return 'success';
		case 'login_failed':
			return 'danger';
		default:
			return 'neutral';
	}
}
