package securityprogram

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// LedgerSchemaV1 is the sealed remediation ledger schema this namespace
// operates on. Any other schema fails closed.
const LedgerSchemaV1 = "setjoin.sec.deep-security-remediation-ledger/v1"

// StatementNoReceipts is the substring the ER1 checker treats as the honest
// zero-receipt claim. Once any row carries receipt-bound verification the
// statement must no longer contain it, so Complete rewrites the statement to
// StatementWithReceipts on the first receipt (keeping the ledger
// checker-green).
const (
	StatementNoReceipts   = "No sealed occurrence carries closure verification"
	StatementWithReceipts = "Closure verification is receipt-bound per sealed occurrence: remediationTransitions and published evidence manifests own the receipts; nightly deep-run receipts remain intake input only."
)

// LedgerDoc is an in-memory view of the sealed remediation ledger that
// preserves every field it does not own. Fields are held as raw JSON so a
// republication can never silently drop colleague-owned content; owned fields
// are rewritten in place.
type LedgerDoc struct {
	top  map[string]json.RawMessage
	rows []map[string]json.RawMessage
}

// EvidenceRef mirrors the per-row evidence block fields the namespace owns.
type EvidenceRef struct {
	SealedIndex       string `json:"sealedIndex"`
	Plan              string `json:"plan"`
	PlanBatch         string `json:"planBatch,omitempty"`
	Verification      string `json:"verification"`
	Manifest          string `json:"manifest,omitempty"`
	SourceFingerprint string `json:"sourceFingerprint,omitempty"`
	Verdict           string `json:"verdict,omitempty"`
}

// AttemptState is the per-row remediation attempt record. Exactly one attempt
// record may exist per row; State is active until a complete/reject closes it.
type AttemptState struct {
	AttemptID string `json:"attemptId"`
	RunID     string `json:"runId"`
	State     string `json:"state"`
	OpenedAt  string `json:"openedAt"`
	ClosedAt  string `json:"closedAt,omitempty"`
}

// Attempt states.
const (
	AttemptActive    = "active"
	AttemptCompleted = "completed"
	AttemptRejected  = "rejected"
)

// Operation names recorded in transitions. Status is read-only and never
// records a transition.
const (
	OpStart    = "start"
	OpStatus   = "status"
	OpComplete = "complete"
	OpReject   = "reject"
)

// Transition is the recorded, auditable occurrence transition. It is appended
// to the row's remediationTransitions array on every mutating operation and
// validated by the ER1 checker against the frozen grammar
// (docs/verification/deep-security-remediation-transitions.json).
type Transition struct {
	Op               string   `json:"op"`
	Contract         string   `json:"contract"`
	OccurrenceID     string   `json:"occurrenceId"`
	AttemptID        string   `json:"attemptId"`
	RunID            string   `json:"runId"`
	Authority        string   `json:"authority"`
	Actor            string   `json:"actor,omitempty"`
	From             RowState `json:"from"`
	To               RowState `json:"to"`
	At               string   `json:"at"`
	Reason           string   `json:"reason,omitempty"`
	EvidenceManifest string   `json:"evidenceManifest,omitempty"`
	EvidenceSHA256   string   `json:"evidenceSha256,omitempty"`
}

// ClosurePatch binds the closure patch evidence a complete requires
// (checker: "closure patch binding trigger/legitimate/bypass evidence").
type ClosurePatch struct {
	Trigger    string `json:"trigger"`
	Legitimate string `json:"legitimate"`
	Bypass     string `json:"bypass"`
}

// LoadLedger parses and structurally validates a sealed remediation ledger
// document. Unknown top-level or row fields are preserved; unknown schema
// versions fail closed with CodeSchemaUnsupported.
func LoadLedger(data []byte) (*LedgerDoc, error) {
	doc := &LedgerDoc{}
	if err := json.Unmarshal(data, &doc.top); err != nil {
		return nil, newErr(CodeEvidenceInvalid, "", "", "ledger: invalid JSON envelope: "+err.Error())
	}
	var schema string
	if err := decodeOwned(doc.top, "schema", &schema); err != nil {
		return nil, newErr(CodeEvidenceInvalid, "", "", "ledger: missing schema field")
	}
	if schema != LedgerSchemaV1 {
		return nil, newErr(CodeSchemaUnsupported, "", "",
			fmt.Sprintf("ledger schema %q unsupported (supported: %s)", schema, LedgerSchemaV1))
	}
	var rawRows []json.RawMessage
	if err := decodeOwned(doc.top, "rows", &rawRows); err != nil {
		return nil, newErr(CodeEvidenceInvalid, "", "", "ledger: missing rows array")
	}
	seen := map[string]bool{}
	for _, rr := range rawRows {
		row := map[string]json.RawMessage{}
		if err := json.Unmarshal(rr, &row); err != nil {
			return nil, newErr(CodeEvidenceInvalid, "", "", "ledger: row is not a JSON object")
		}
		id := rowString(row, "occurrenceId")
		if id == "" {
			return nil, newErr(CodeEvidenceInvalid, "", id, "ledger: row without occurrenceId")
		}
		if seen[id] {
			return nil, newErr(CodeEvidenceInvalid, "", id, "duplicate occurrenceId")
		}
		seen[id] = true
		doc.rows = append(doc.rows, row)
	}
	return doc, nil
}

// Rows returns the number of rows (sealed occurrences) in the document.
func (d *LedgerDoc) Rows() int { return len(d.rows) }

// Find returns the raw row map for occurrenceID.
func (d *LedgerDoc) Find(occurrenceID string) (map[string]json.RawMessage, bool) {
	for _, row := range d.rows {
		if rowString(row, "occurrenceId") == occurrenceID {
			return row, true
		}
	}
	return nil, false
}

// Bytes renders the document deterministically (sorted keys, single-space
// indent, trailing newline). Content the namespace does not own is preserved
// in value; key order is canonicalized. The namespace owns the rows array's
// CONTENT: the parsed row maps (which hold colleague-owned fields verbatim
// as raw JSON) are re-encoded onto the document here — the single
// serialization point — so the rendered bytes carry every in-place row
// mutation a transition committed (state, attempt, evidence and
// transitions) instead of silently republishing the pre-mutation bytes with
// only the top-level tallies moved.
func (d *LedgerDoc) Bytes() ([]byte, error) {
	rows, err := json.Marshal(d.rows)
	if err != nil {
		return nil, newErr(CodeInternal, "", "", "ledger rows re-encode failed: "+err.Error())
	}
	d.top["rows"] = rows
	out, err := json.MarshalIndent(d.top, "", " ")
	if err != nil {
		return nil, newErr(CodeInternal, "", "", "ledger re-marshal failed: "+err.Error())
	}
	return append(out, '\n'), nil
}

// RowView is the typed, validated projection of a row the grammar reasons
// over.
type RowView struct {
	OccurrenceID       string
	FindingID          string
	State              RowState
	BlockedReason      string
	ClosurePatch       *ClosurePatch
	Tests              []string
	Attempt            *AttemptState
	Transitions        []Transition
	Evidence           EvidenceRef
	TransitionsPresent bool
}

// ViewRow builds the typed projection, failing closed if any closed-enum
// field is outside its vocabulary.
func ViewRow(row map[string]json.RawMessage) (*RowView, error) {
	v := &RowView{
		OccurrenceID:  rowString(row, "occurrenceId"),
		FindingID:     rowString(row, "findingId"),
		BlockedReason: rowString(row, "blockedReason"),
		Tests:         rowStringList(row, "tests"),
	}
	var err error
	if v.State.Disposition, err = parseDisposition(rowString(row, "disposition")); err != nil {
		return nil, newErr(CodeEvidenceInvalid, "", v.OccurrenceID, err.Error())
	}
	if v.State.LocalStatus, err = parseLocalStatus(rowString(row, "localStatus")); err != nil {
		return nil, newErr(CodeEvidenceInvalid, "", v.OccurrenceID, err.Error())
	}
	if v.State.VerificationStatus, err = parseVerificationStatus(rowString(row, "verificationStatus")); err != nil {
		return nil, newErr(CodeEvidenceInvalid, "", v.OccurrenceID, err.Error())
	}
	if v.State.ReleaseStatus, err = parseReleaseStatus(rowString(row, "releaseStatus")); err != nil {
		return nil, newErr(CodeEvidenceInvalid, "", v.OccurrenceID, err.Error())
	}
	if raw, ok := row["closurePatch"]; ok && string(raw) != "null" {
		patch := &ClosurePatch{}
		if err := json.Unmarshal(raw, patch); err != nil {
			return nil, newErr(CodeEvidenceInvalid, "", v.OccurrenceID, "closurePatch is not a valid object")
		}
		v.ClosurePatch = patch
	}
	if raw, ok := row["evidence"]; ok && string(raw) != "null" {
		var ev struct {
			SealedIndex       *string `json:"sealedIndex"`
			Plan              *string `json:"plan"`
			PlanBatch         *string `json:"planBatch"`
			Verification      *string `json:"verification"`
			Manifest          *string `json:"manifest"`
			SourceFingerprint *string `json:"sourceFingerprint"`
			Verdict           *string `json:"verdict"`
		}
		if err := json.Unmarshal(raw, &ev); err != nil {
			return nil, newErr(CodeEvidenceInvalid, "", v.OccurrenceID, "evidence is not a valid object")
		}
		v.Evidence = EvidenceRef{
			SealedIndex:       deref(ev.SealedIndex),
			Plan:              deref(ev.Plan),
			PlanBatch:         deref(ev.PlanBatch),
			Verification:      deref(ev.Verification),
			Manifest:          deref(ev.Manifest),
			SourceFingerprint: deref(ev.SourceFingerprint),
			Verdict:           deref(ev.Verdict),
		}
	}
	if raw, ok := row["remediation"]; ok && string(raw) != "null" {
		att := &AttemptState{}
		if err := json.Unmarshal(raw, att); err != nil {
			return nil, newErr(CodeEvidenceInvalid, "", v.OccurrenceID, "remediation is not a valid attempt object")
		}
		v.Attempt = att
	}
	if raw, ok := row["remediationTransitions"]; ok && string(raw) != "null" {
		if err := json.Unmarshal(raw, &v.Transitions); err != nil {
			return nil, newErr(CodeEvidenceInvalid, "", v.OccurrenceID, "remediationTransitions is not a valid array")
		}
		v.TransitionsPresent = true
	}
	return v, nil
}

// writeRowState writes the four-axis state plus the namespace-owned evidence
// and attempt fields back onto the raw row.
func writeRowState(row map[string]json.RawMessage, state RowState, ev *EvidenceRef, att *AttemptState) error {
	for key, val := range map[string]any{
		"disposition":        state.Disposition,
		"localStatus":        state.LocalStatus,
		"verificationStatus": state.VerificationStatus,
		"releaseStatus":      state.ReleaseStatus,
	} {
		if err := setOwned(row, key, val); err != nil {
			return err
		}
	}
	if ev != nil {
		enc, err := json.Marshal(ev)
		if err != nil {
			return newErr(CodeInternal, "", "", "evidence re-marshal failed: "+err.Error())
		}
		row["evidence"] = enc
	}
	if att != nil {
		enc, err := json.Marshal(att)
		if err != nil {
			return newErr(CodeInternal, "", "", "attempt re-marshal failed: "+err.Error())
		}
		row["remediation"] = enc
	}
	return nil
}

// appendTransition appends a transition record to the row's
// remediationTransitions array, creating the array on first write.
func appendTransition(row map[string]json.RawMessage, t Transition) error {
	v, err := ViewRow(row)
	if err != nil {
		return err
	}
	transitions := append(v.Transitions, t)
	enc, err := json.Marshal(transitions)
	if err != nil {
		return newErr(CodeInternal, "", t.OccurrenceID, "transition marshal failed: "+err.Error())
	}
	row["remediationTransitions"] = enc
	return nil
}

// bumpCounts maintains the ledger-level tally the ER1 checker reconciles:
// a completion moves one occurrence from blocked to fixed/no_change.
func (d *LedgerDoc) bumpCounts(outcome Disposition) error {
	rawCounts, ok := d.top["counts"]
	if !ok {
		return newErr(CodeInternal, "", "", "ledger has no counts object")
	}
	counts := map[string]json.RawMessage{}
	if err := json.Unmarshal(rawCounts, &counts); err != nil {
		return newErr(CodeEvidenceInvalid, "", "", "counts is not a valid object")
	}
	bump := func(key string, delta int) error {
		cur, err := strconv.Atoi(string(counts[key]))
		if err != nil {
			return newErr(CodeEvidenceInvalid, "", "", fmt.Sprintf("counts.%s is not an integer", key))
		}
		counts[key] = json.RawMessage(strconv.Itoa(cur + delta))
		return nil
	}
	switch outcome {
	case DispositionFixed:
		if err := bump("fixed", 1); err != nil {
			return err
		}
	case DispositionNoChange:
		if err := bump("no_change", 1); err != nil {
			return err
		}
	default:
		return nil
	}
	if err := bump("blocked", -1); err != nil {
		return err
	}
	if err := bump("locallyRemediated", 1); err != nil {
		return err
	}
	out, err := json.Marshal(counts)
	if err != nil {
		return newErr(CodeInternal, "", "", "counts re-marshal failed: "+err.Error())
	}
	d.top["counts"] = out
	return nil
}

// refreshVerificationStatement keeps the ledger's zero-receipt statement
// honest once any receipt exists (the ER1 checker fails on the contradiction).
func (d *LedgerDoc) refreshVerificationStatement() {
	raw, ok := d.top["verification"]
	if !ok {
		return
	}
	verif := map[string]json.RawMessage{}
	if err := json.Unmarshal(raw, &verif); err != nil {
		return
	}
	stmt, err := strconv.Unquote(string(verif["statement"]))
	if err != nil || !strings.Contains(stmt, StatementNoReceipts) {
		return
	}
	verif["statement"] = jsonRaw(StatementWithReceipts)
	out, err := json.Marshal(verif)
	if err != nil {
		return
	}
	d.top["verification"] = out
}

// RFC3339UTC renders t the way transitions record time (UTC, RFC 3339).
func RFC3339UTC(t time.Time) string {
	return t.UTC().Format(time.RFC3339)
}

// SHA256Hex is the lowercase hex SHA-256 used for every binding in the
// namespace (evidence artifacts, ledger before/after pins).
func SHA256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// ── raw-field helpers ──────────────────────────────────────────────────────

func decodeOwned(top map[string]json.RawMessage, key string, dst any) error {
	raw, ok := top[key]
	if !ok {
		return fmt.Errorf("missing %s", key)
	}
	return json.Unmarshal(raw, dst)
}

func setOwned(row map[string]json.RawMessage, key string, val any) error {
	enc, err := json.Marshal(val)
	if err != nil {
		return newErr(CodeInternal, "", "", key+" marshal failed: "+err.Error())
	}
	row[key] = enc
	return nil
}

func rowString(row map[string]json.RawMessage, key string) string {
	var s string
	if err := json.Unmarshal(row[key], &s); err != nil {
		return ""
	}
	return s
}

func rowStringList(row map[string]json.RawMessage, key string) []string {
	var out []string
	if raw, ok := row[key]; ok && string(raw) != "null" {
		if err := json.Unmarshal(raw, &out); err != nil {
			return nil
		}
	}
	return out
}

func jsonRaw(s string) json.RawMessage {
	enc, err := json.Marshal(s)
	if err != nil {
		return json.RawMessage(`""`)
	}
	return enc
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
