// The 6-outcome chip mapping is the single-sourced design-system-additions.md §1
// table — NOT authored here. Variants/icons/keys are copied VERBATIM from §1 so this
// trace, the CA-1 why-blocked trace, the What-If simulator and the report-only impact
// all render identical chips. A test asserts each entry matches §1 (see signin-trace.test.ts).
// ponytail: local mirror of §1; when OutcomeChip is extracted to lib/components/ui, import it instead.
type Variant = 'neutral' | 'success' | 'warning' | 'danger' | 'info';
export interface OutcomeMeta { outcome: string; variant: Variant; icon: string; key: string; tip: string; }

export const OUTCOME_LEGEND: OutcomeMeta[] = [
	{ outcome: 'applied',       variant: 'success', icon: 'CheckCircle2', key: 'ca.outcome.applied',       tip: 'ca.outcome.applied.tip' },
	{ outcome: 'would_block',   variant: 'danger',  icon: 'ShieldX',      key: 'ca.outcome.would_block',   tip: 'ca.outcome.would_block.tip' },
	{ outcome: 'would_step_up', variant: 'info',    icon: 'KeyRound',     key: 'ca.outcome.would_step_up', tip: 'ca.outcome.would_step_up.tip' },
	{ outcome: 'would_notify',  variant: 'warning', icon: 'BellRing',     key: 'ca.outcome.would_notify',  tip: 'ca.outcome.would_notify.tip' },
	{ outcome: 'skipped',       variant: 'neutral', icon: 'MinusCircle',  key: 'ca.outcome.skipped',       tip: 'ca.outcome.skipped.tip' },
	{ outcome: 'excluded',      variant: 'neutral', icon: 'UserMinus',    key: 'ca.outcome.excluded',      tip: 'ca.outcome.excluded.tip' },
];

const BY = Object.fromEntries(OUTCOME_LEGEND.map((o) => [o.outcome, o]));

// Unknown/forward-compat outcome from a newer server → the §1 neutral fallback chip;
// never crash and never silently mis-color.
const UNKNOWN: OutcomeMeta = { outcome: 'unknown', variant: 'neutral', icon: 'HelpCircle', key: 'ca.outcome.unknown', tip: 'ca.outcome.unknown.tip' };

export function outcomeChip(outcome: string): OutcomeMeta {
	// Own-property guard: a bare `BY[outcome]` lets Object.prototype keys
	// ('constructor', 'toString', …) through as lookup "hits", bypassing the
	// unknown-outcome fallback. Only the §1 vocabulary itself may match.
	return Object.hasOwn(BY, outcome) ? BY[outcome] : UNKNOWN;
}

export function decisionVariant(decision: string): Variant {
	switch (decision) {
		case 'block':
			return 'danger';
		case 'step_up':
			return 'warning';
		case 'notify':
			return 'info';
		default:
			return 'success';
	}
}
