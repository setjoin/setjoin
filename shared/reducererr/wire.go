package reducererr

import (
	"errors"
	"net/http"
	"strings"

	"github.com/jackc/pgx/v5/pgconn"

	"setjoin.com/shared/httputil"
)

// wire.go — the shared reducer→HTTP translator kit (whole-pipeline review
// arch #3). Before this, chat/errors.go's writeChatProblem, meet/errors.go's
// writeMeetProblem, and drive/problem.go's writeDriveProblem were three
// (chat/meet: byte-identical, drive: identical plus two escape hatches)
// copies of "classify a reducer error onto RFC 7807 and write it"; chat's
// queryChatJSON and meet's queryMeetJSON were the same "run a jsonb-returning
// reducer, write the row verbatim, or project the error" function twice. The
// per-package bzSlug tables (which BZ code maps to which URL slug) STAY
// local to each consumer package — only the projection MECHANICS live here.

// StatusOverride optionally replaces the class-derived HTTP status for a
// specific error. Return ok=false to keep the Classify-derived status. The
// sanctioned seam for a per-code override is reducererr.IsCode inside the
// override func — never a raw pgErr.Code branch (drive's BZ148→413,
// BZ149→423; scripts/check-reducererr-contract.sh guards this repo-wide).
type StatusOverride func(err error) (status int, ok bool)

// ProblemExtend optionally mutates the built Problem before it is written
// (drive's BZ149 HolderID hint extraction, sourced from the reducer HINT).
type ProblemExtend func(err error, p *httputil.Problem)

// ProblemOptions is the per-package wire-projection contract: everything a
// writeXProblem needs beyond the shared BZ->status/detail projection.
// Namespace and Slugs are required; Override and Extend are the two escape
// hatches drive alone needs today — chat and meet leave them nil.
type ProblemOptions struct {
	// Namespace renders the RFC 7807 `type` as
	// "https://setjoin.com/problems/<namespace>/<slug>".
	Namespace string
	// Slugs is the package-local BZ->slug table (bzSlug) — stays local to
	// each consumer package, passed in, never owned here.
	Slugs map[string]string
	// Override optionally replaces the class-derived HTTP status. Nil means
	// no override (chat/meet's posture — every BZ code's codeClass entry
	// already projects to the exact wire status those packages want).
	Override StatusOverride
	// Extend optionally mutates the built Problem after Override/Slugs are
	// applied. Nil means no extension.
	Extend ProblemExtend
}

// WriteProblem projects a reducer error onto RFC 7807 via the shared
// classifier (Classify/Detail — never a hand-rolled pgErr.Code switch,
// banned outside this package by scripts/check-reducererr-contract.sh) and
// writes it. The one home for what chat/meet/drive each used to hand-roll as
// writeChatProblem/writeMeetProblem/writeDriveProblem.
func WriteProblem(w http.ResponseWriter, r *http.Request, err error, opts ProblemOptions) {
	status := Classify(err).HTTPStatus()
	if opts.Override != nil {
		if s, ok := opts.Override(err); ok {
			status = s
		}
	}
	var code, slug string
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		if s, ok := opts.Slugs[pgErr.Code]; ok {
			code, slug = pgErr.Code, s
		}
	}
	p := &httputil.Problem{Status: status, Detail: Detail(err), Code: code}
	if slug != "" {
		p.Type = "https://setjoin.com/problems/" + opts.Namespace + "/" + slug
	}
	if opts.Extend != nil {
		opts.Extend(err, p)
	}
	httputil.WriteProblem(w, r, p)
}

// WriteClassified projects err onto RFC 7807 via the shared Classify/Detail
// projection and writes it — no Namespace/Slugs table, for the many admin/
// user/approval/booking handlers that have no per-package `type` slug of
// their own (arch #A1: this idiom was hand-copied at ~13 call sites — three
// of them, admin_chat_compliance.go's/admin_chat_ediscovery.go's `mapErr` and
// admin_jit.go's `mapJITErr`, byte-identical). Writes the problem and returns
// true for every classified (non-ClassUnknown) error; writes NOTHING and
// returns false for ClassUnknown, so the caller falls back to its own
// generic/logged 500 without a double write — the exact contract every
// existing `mapXErr(w, r, err) bool` caller already assumes
// (`if h.mapErr(w, r, err) { return }; fallback()`).
//
// A caller needing a per-code override or an anti-oracle collapse (the
// couple of sites arch #A1 left alone — admin_offline.go's BZ099 slug split
// is already inside Classify itself, so no override is needed there;
// booking/public.go's ClassNotFound→fixed-body anti-oracle IS a real
// pre-check) keeps a small `reducererr.IsCode`/`Classify` guard before
// calling WriteClassified, mirroring ProblemOptions.Override's escape hatch.
func WriteClassified(w http.ResponseWriter, r *http.Request, err error) bool {
	class := Classify(err)
	if class == ClassUnknown {
		return false
	}
	retryable := class == ClassTransient
	p := &httputil.Problem{
		Status:      class.HTTPStatus(),
		Detail:      Detail(err),
		Retryable:   &retryable,
		Remediation: classRemediation(class),
	}
	var pgErr *pgconn.PgError
	if class != ClassTransient && errors.As(err, &pgErr) && CodeIsKnown(pgErr.Code) {
		p.Code = pgErr.Code
		p.Type = "https://setjoin.com/problems/reducer/" + strings.ToLower(pgErr.Code)
		if parsed, parseErr := ParseReducerError(err); parseErr == nil && parsed.Remediation != "" {
			p.Remediation = parsed.Remediation
		}
	}
	httputil.WriteProblem(w, r, p)
	return true
}

func classRemediation(class ReplyClass) string {
	switch class {
	case ClassConflict, ClassStateMismatch, ClassCannotCalc:
		return "Refresh current state, resolve the conflict, and retry."
	case ClassForbidden:
		return "Complete the required authorization, approval, or recovery step before retrying."
	case ClassNotFound, ClassAccountNotFound:
		return "Refresh the target identifier and retry only if the resource still exists."
	case ClassInvalidArguments:
		return "Correct the request fields and retry."
	case ClassUnprocessable:
		return "Correct the requested operation using the documented runbook and retry."
	case ClassOverQuota, ClassSendQuota:
		return "Reduce usage or raise the applicable quota before retrying."
	case ClassTransient:
		return "Retry after the service dependency or configuration has recovered."
	default:
		return ""
	}
}

// NOTE: a shared QueryJSON("run a jsonb reducer, write the row verbatim")
// helper briefly lived here (arch #3) and was deliberately DELETED by the W4
// native-RLS leg: every user-request-path reducer call must run inside
// dbscope.RunUserScoped (the transaction-local app.current_user_id GUC the
// V134 policies key on), so chat's queryChatJSON and meet's queryMeetJSON
// now own that dance per-package. A pool-taking QueryJSON here would be a
// scope-bypass footgun for the next consumer — do not reintroduce it;
// WriteProblem below remains the shared projection choke point.
