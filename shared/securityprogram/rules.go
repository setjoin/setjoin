package securityprogram

// stateConstraints names exact axis values; an omitted axis is unconstrained.
// The same values drive Go staging and the generated offline-checker grammar.
type stateConstraints struct {
	Disposition        Disposition        `json:"disposition,omitempty"`
	LocalStatus        LocalStatus        `json:"localStatus,omitempty"`
	VerificationStatus VerificationStatus `json:"verificationStatus,omitempty"`
	ReleaseStatus      ReleaseStatus      `json:"releaseStatus,omitempty"`
}

func (c stateConstraints) matches(s RowState) bool {
	return (c.Disposition == "" || c.Disposition == s.Disposition) &&
		(c.LocalStatus == "" || c.LocalStatus == s.LocalStatus) &&
		(c.VerificationStatus == "" || c.VerificationStatus == s.VerificationStatus) &&
		(c.ReleaseStatus == "" || c.ReleaseStatus == s.ReleaseStatus)
}

func (c stateConstraints) apply(s RowState) RowState {
	if c.Disposition != "" {
		s.Disposition = c.Disposition
	}
	if c.LocalStatus != "" {
		s.LocalStatus = c.LocalStatus
	}
	if c.VerificationStatus != "" {
		s.VerificationStatus = c.VerificationStatus
	}
	if c.ReleaseStatus != "" {
		s.ReleaseStatus = c.ReleaseStatus
	}
	return s
}

// opSpec is the v2 grammar. To overlays the input state, preserving unmentioned
// axis. LocalRewrites then rewrites a named local state. An operation with
// Outcomes gets its disposition from that outcome, subject to OutcomeFrom.
// Requires names caller-supplied fields; ReceiptRequires names fields minted
// during completion. AttemptState is the recorded attempt's resulting state.
type opSpec struct {
	Op                    string                           `json:"op"`
	Readonly              bool                             `json:"readonly"`
	OpensAttempt          bool                             `json:"opensAttempt,omitempty"`
	RequiresActiveAttempt bool                             `json:"requiresActiveAttempt,omitempty"`
	From                  stateConstraints                 `json:"from"`
	To                    stateConstraints                 `json:"to"`
	LocalRewrites         map[LocalStatus]LocalStatus      `json:"localRewrites,omitempty"`
	Outcomes              []Disposition                    `json:"outcomes,omitempty"`
	OutcomeFrom           map[Disposition]stateConstraints `json:"outcomeFrom,omitempty"`
	Requires              []string                         `json:"requires,omitempty"`
	ReceiptRequires       []string                         `json:"receiptRequires,omitempty"`
	AttemptState          string                           `json:"attemptState,omitempty"`
}

func openSealedState() stateConstraints {
	return stateConstraints{Disposition: DispositionBlocked, VerificationStatus: VerificationNone}
}

func startRule() opSpec {
	return opSpec{
		Op: OpStart, OpensAttempt: true, From: openSealedState(),
		LocalRewrites: map[LocalStatus]LocalStatus{LocalUnmapped: LocalTraced},
		Requires:      []string{"attemptId", "runId"}, AttemptState: AttemptActive,
	}
}

func completeRule() opSpec {
	return opSpec{
		Op: OpComplete, RequiresActiveAttempt: true, From: openSealedState(),
		To:              stateConstraints{LocalStatus: LocalProofPatched, VerificationStatus: VerificationReceiptBound, ReleaseStatus: ReleaseNotReady},
		Outcomes:        []Disposition{DispositionFixed, DispositionNoChange},
		OutcomeFrom:     map[Disposition]stateConstraints{DispositionNoChange: {LocalStatus: LocalNoChangeCandidate}},
		Requires:        []string{"attemptId", "runId", "closurePatch", "tests", "evidenceManifest"},
		ReceiptRequires: []string{"evidenceSha256"}, AttemptState: AttemptCompleted,
	}
}

func rejectRule() opSpec {
	return opSpec{
		Op: OpReject, RequiresActiveAttempt: true, From: openSealedState(),
		To:       stateConstraints{Disposition: DispositionBlocked, LocalStatus: LocalBlocked, VerificationStatus: VerificationNone, ReleaseStatus: ReleaseNotReady},
		Requires: []string{"attemptId", "runId", "reason"}, AttemptState: AttemptRejected,
	}
}

func operationRules() []opSpec {
	return []opSpec{startRule(), completeRule(), rejectRule(), {Op: OpStatus, Readonly: true}}
}

func (r opSpec) nextState(from RowState, outcome Disposition) RowState {
	to := r.To.apply(from)
	if local, ok := r.LocalRewrites[from.LocalStatus]; ok {
		to.LocalStatus = local
	}
	if len(r.Outcomes) > 0 {
		to.Disposition = outcome
	}
	return to
}
