/**
 * Threat-flow types and helpers for the Logs & threats console.
 *
 * Mirrors the admin-kit §5.1 spec (UniFi-inspired threat-flow table) and
 * §7 fixture shape, mapped onto backend-wave2's GET /admin/threat/{view} API
 * envelope {rows, total, limit, offset}.
 */

/** §7 fixture shape — one row in the threat-flow table. */
export interface ThreatFlow {
	id: number;
	/** 24h time (HH:MM:SS). */
	time: string;
	/** Source IP address. */
	src: string;
	/** ISO 3166-1 alpha-2 country code. */
	country: string;
	/** Destination (username or hostname). */
	dst: string;
	/** Protocol / service (IMAP, SMTP AUTH, HTTPS, SMTP, LDAP, Telnet). */
	service: string;
	/** Risk level — low, medium, or high. */
	risk: RiskLevel;
	/** Rule slug (spray_detection, auth_bruteforce, etc.). */
	rule: string;
	/** Interceptor action — Block, Tarpit, CAPTCHA, Allow. */
	action: ThreatAction;
}

export type RiskLevel = 'low' | 'medium' | 'high';
export type ThreatAction = 'Block' | 'Tarpit' | 'CAPTCHA' | 'Allow' | 'Challenge' | 'Pass';

/** Shaped API response from GET /admin/threat/{view}. */
export interface ThreatApiResponse {
	rows: Record<string, unknown>[];
	total: number;
	limit: number;
	offset: number;
}

/** Parsed result from parseThreatResponse. */
export interface ParsedThreatResult {
	flows: ThreatFlow[];
	total: number;
}

/**
 * Return the number of filled risk bars for a risk level.
 * high=3, medium=2, low=1, unknown=0.
 */
export function riskBars(level: string): number {
	switch (level) {
		case 'high': return 3;
		case 'medium': return 2;
		case 'low': return 1;
		default: return 0;
	}
}

/** Badge variant names matching the M1 Badge component. */
export type BadgeVariantName = 'neutral' | 'success' | 'warning' | 'danger' | 'info' | 'accent';

/**
 * Return the Badge variant for a threat action.
 */
export function actionBadgeVariant(action: string): BadgeVariantName {
	switch (action) {
		case 'Block': return 'danger';
		case 'Tarpit': return 'warning';
		case 'CAPTCHA': return 'info';
		case 'Challenge': return 'info';
		case 'Allow': return 'success';
		case 'Pass': return 'success';
		default: return 'neutral';
	}
}

/**
 * Derive a risk level from an attempt outcome string.
 * - blocked → high
 * - challenged, captcha, tarpit → medium
 * - success, allow, pass → low
 */
function deriveRisk(outcome: string): RiskLevel {
	const o = outcome.toLowerCase();
	if (o === 'blocked' || o === 'denied' || o === 'failure') return 'high';
	if (o === 'challenged' || o.includes('captcha') || o.includes('tarpit')) return 'medium';
	return 'low';
}

/**
 * Derive a display action from an attempt outcome string.
 */
function deriveAction(outcome: string): ThreatAction {
	const o = outcome.toLowerCase();
	if (o === 'blocked' || o === 'denied') return 'Block';
	if (o === 'challenged' || o.includes('captcha')) return 'CAPTCHA';
	if (o.includes('tarpit')) return 'Tarpit';
	if (o === 'success' || o === 'pass') return 'Allow';
	return 'Allow';
}

/**
 * Format an ISO 8601 timestamp string to 24h HH:MM:SS.
 */
function formatTime(iso: string): string {
	try {
		const d = new Date(iso);
		if (isNaN(d.getTime())) return iso.slice(11, 19) || iso;
		const hh = String(d.getHours()).padStart(2, '0');
		const mm = String(d.getMinutes()).padStart(2, '0');
		const ss = String(d.getSeconds()).padStart(2, '0');
		return `${hh}:${mm}:${ss}`;
	} catch {
		return iso;
	}
}

let _rowId = 0;

/**
 * Parse the raw API response from GET /admin/threat/{view} into a typed
 * ThreatFlow[] suitable for the 8-column threat-flow table.
 *
 * Expects the `attempts` view shape: {sourceIp, targetUsername, protocol,
 * outcome, failureReason, geoCountry, occurredAt}. Other views are
 * best-effort mapped.
 */
export function parseThreatResponse(data: ThreatApiResponse): ParsedThreatResult {
	const flows: ThreatFlow[] = [];
	for (const row of data.rows) {
		_rowId++;
		const occurredAt = String(row['occurredAt'] ?? row['time'] ?? row['created_at'] ?? '');
		const sourceIp = String(row['sourceIp'] ?? row['src'] ?? row['source_ip'] ?? '');
		const targetUsername = String(row['targetUsername'] ?? row['dst'] ?? row['target'] ?? row['lockoutKey'] ?? '');
		const protocol = String(row['protocol'] ?? row['service'] ?? '');
		const outcome = String(row['outcome'] ?? row['result'] ?? 'success');
		const failureReason = String(row['failureReason'] ?? row['reason'] ?? row['rule'] ?? '');
		const geoCountry = String(row['geoCountry'] ?? row['country'] ?? row['geo_country'] ?? '');

		flows.push({
			id: _rowId,
			time: formatTime(occurredAt),
			src: sourceIp,
			country: geoCountry,
			dst: targetUsername,
			service: protocol,
			risk: deriveRisk(outcome),
			rule: failureReason,
			action: deriveAction(outcome),
		});
	}
	return { flows, total: data.total };
}
