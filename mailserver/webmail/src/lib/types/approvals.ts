export type ApprovalStatus = 'pending' | 'approved' | 'applied' | 'denied' | 'cancelled' | 'expired' | 'skipped' | 'apply_failed';
export type ConsumerType = 'rbac.jit_activation' | 'mail.external_send' | 'mail.group_moderation' | 'hr.leave' | 'hr.expense' | 'guest.invite' | 'drive.access';

export interface DriveAccessApprovalPayload {
	nodeId: string;
	spaceId: string;
	requestedCapabilities: string[];
	requestedPropagation: 'self' | 'children' | 'subtree';
	requestedExpiresAt: string;
	requestedMaxUses?: number | null;
	emergency: boolean;
	reason: string;
	expectedEpoch: string;
	grantId?: string | null;
}

/** Optional approval-time narrowing. The reducer independently proves every
 * value is a subset of the request and still satisfies the current policy. */
export interface DriveAccessDecisionInput {
	capabilities: string[];
	propagation: 'self' | 'children' | 'subtree';
	expiresAt: string;
	maxUses?: number;
	expectedEpoch: string;
}

export type LeaveType = 'annual' | 'sick' | 'personal' | 'marriage' | 'maternity' | 'paternity' | 'bereavement' | 'other';
export type ExpenseCategory = 'travel' | 'meals' | 'lodging' | 'supplies' | 'other';

/** hr.leave payload contract — mirrors hr_request_create.sql's validation exactly. */
export interface HrLeaveForm {
	leave_type: LeaveType;
	start_date: string; // YYYY-MM-DD
	end_date: string; // YYYY-MM-DD
	days: number;
	reason: string;
}

export interface HrExpenseLineItem {
	description: string;
	amount_cents: number;
	category: ExpenseCategory;
	receipt_sha256?: string;
	receipt_filename?: string;
}

/** hr.expense payload contract — mirrors hr_request_create.sql's validation exactly. */
export interface HrExpenseForm {
	currency: string; // ISO-4217, 3 uppercase letters
	total_cents: number;
	line_items: HrExpenseLineItem[];
}

export interface ApprovalRequest {
	id: number;
	consumerType: ConsumerType;
	requesterUserId?: number; // absent for mail.group_moderation (external sender, no internal user)
	requesterName?: string; // legacy/enriched response only; base list rows omit it
	requesterEmail?: string; // legacy/enriched response only; base list rows omit it
	subject: string;
	payload?: Record<string, unknown>; // returned only for allowlisted HR/guest review evidence
	status: ApprovalStatus;
	approverKind: 'user' | 'role_group';
	approverRef: number;
	approverName?: string;
	decidedByUserId?: number;
	decidedByName?: string;
	decisionComment?: string;
	createdAt: string;
	expiresAt: string;
	decidedAt?: string;
	// For mail consumers - the held message body for iframe sandbox
	heldMessageHtml?: string;
}

export interface ApprovalsResponse {
	pendingForMe: ApprovalRequest[];
	myRequests: ApprovalRequest[];
}
