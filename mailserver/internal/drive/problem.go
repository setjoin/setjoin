// Package drive serves /api/drive/* — spaces, tree, chunk-manifest versions.
// Thin protocol translator over the drive_* reducers ("logic where the data
// is"); every error is RFC 7807 with the spec-§7 BZ→status map and the BZ code
// in the `code` extension.
package drive

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/jackc/pgx/v5/pgconn"

	"setjoin.com/shared/httputil"
	"setjoin.com/shared/reducererr"
)

// bzSlug is the locked §7 map from a drive-raised BZ code to its RFC 7807
// `type` URL slug. Codes absent here are not drive-specific — the `code`
// extension is left empty and the status/detail fall back to the shared
// reducererr projection.
var bzSlug = map[string]string{
	"BZ139": "not-found",
	"BZ140": "forbidden",
	"BZ141": "invalid-arguments",
	"BZ142": "no-downgrade",
	"BZ143": "cross-space",
	"BZ144": "chunk-not-proven",
	"BZ145": "immutable",
	"BZ146": "invalid-grant",
	"BZ147": "duplicate-name",
	"BZ148": "quota-exceeded",
	"BZ149": "locked",
	"BZ150": "branch-error",
	"BZ260": "name-unavailable",
	"BZ321": "office-not-found",
	"BZ322": "office-invalid-arguments",
	"BZ323": "office-forbidden",
	"BZ324": "office-session-stale",
	"BZ325": "office-lock-conflict",
	"BZ326": "office-replay-conflict",
	"BZ327": "office-provider-unavailable",
}

// driveProblemOpts is this package's half of the shared
// reducererr.WriteProblem contract (whole-pipeline review arch #3): the
// namespace + bzSlug table above, plus drive's two semantic overrides — both
// via the sanctioned reducererr.IsCode seam (never a raw pgErr.Code branch,
// banned outside internal/reducererr by scripts/check-reducererr-contract.sh):
// BZ148 (quota/upload-limit) is 413 on the drive REST surface, not the
// generic 507 Insufficient Storage every other quota code gets; BZ149 (file
// hard-locked by another user) is 423 Locked, not the generic 409 Conflict
// every other drive state-conflict code gets (P4 Task 9's BZ149/BZ150 map —
// BZ150 already classifies to 409, so it needs no override). Extend carries
// BZ149's HINT holding-user id (drive_file_lock.sql / drive_file_put_version.sql:
// {"type":"locked",...,"holderId":N}) — the client's save-as-branch offer
// needs to name whose checkout is blocking.
var driveProblemOpts = reducererr.ProblemOptions{
	Namespace: "drive",
	Slugs:     bzSlug,
	Override: func(err error) (int, bool) {
		switch {
		case reducererr.IsCode(err, "BZ148"):
			return http.StatusRequestEntityTooLarge, true
		case reducererr.IsCode(err, "BZ149"):
			return http.StatusLocked, true
		}
		return 0, false
	},
	Extend: func(err error, p *httputil.Problem) {
		if !reducererr.IsCode(err, "BZ149") {
			return
		}
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) || pgErr.Hint == "" {
			return
		}
		var hint struct {
			HolderID int64 `json:"holderId"`
		}
		if json.Unmarshal([]byte(pgErr.Hint), &hint) == nil {
			p.HolderID = hint.HolderID
		}
	},
}

// writeDriveProblem projects a reducer error onto RFC 7807 via the shared
// reducererr kit (reducererr.WriteProblem) — the classify/detail/status/type
// wiring itself lives once in internal/reducererr, shared with chat and meet.
func writeDriveProblem(w http.ResponseWriter, r *http.Request, err error) {
	reducererr.WriteProblem(w, r, err, driveProblemOpts)
}

// originalContentGateBlocked keeps protected classifications on the governed
// export-token path.  `download` is eligibility to request/consume an export;
// it is never unconditional authority to stream secure/GxP source bytes.
func originalContentGateBlocked(w http.ResponseWriter, r *http.Request, classification string) bool {
	if classification == "regular" {
		return false
	}
	httputil.WriteProblem(w, r, &httputil.Problem{
		Status: http.StatusForbidden,
		Type:   "https://setjoin.com/problems/drive/export-required",
		Detail: "secure/gxp original content requires a governed export grant",
	})
	return true
}
