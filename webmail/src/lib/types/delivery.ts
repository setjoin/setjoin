export interface Hop {
	index: number;
	fromHost?: string;
	byHost?: string;
	withProtocol?: string;
	ip?: string;
	rdns?: string;
	timestamp: string | null;
	delayMs: number | null;
	tlsActive: boolean;
	isOurInfra: boolean;
	parseOk: boolean;
	rawLine?: string;
}

export interface AuthResult {
	result: string;
	domain?: string;
	evidence?: string;
}

export interface AuthResults {
	spf?: AuthResult;
	dkim?: AuthResult;
	dmarc?: AuthResult;
	arc?: AuthResult;
}

/** One delivery attempt for a recipient (outbound). Append-only per attempt. */
export interface Attempt {
	n: number;
	at: string | null;
	mxHost: string | null;
	smtpCode: number | null;
	smtpText: string | null;
	outcome: string;
	tls: boolean;
}

/** Latest-per-recipient delivery state (outbound). Server reduces + sorts. */
export interface Recipient {
	email: string;
	status: 'delivered' | 'deferred' | 'bounced' | 'queued';
	mxHost: string | null;
	deliveredAt: string | null;
	nextAttemptAt: string | null;
	lastSmtpCode: number | null;
	lastSmtpText: string | null;
	attempts: Attempt[];
}

export interface Trace {
	direction: 'inbound' | 'outbound';
	hopCount?: number;
	totalTransitMs?: number | null;
	slowestHopIndex?: number | null;
	hops?: Hop[];
	truncated?: boolean;
	auth?: AuthResults;
	raw?: { url: string; sizeBytes: number };
	/** Outbound only: send-queue overall status (survives retention pruning). */
	overallStatus?: string;
	/** Outbound only: per-recipient delivery, server-sorted problems-first. */
	recipients?: Recipient[];
}
