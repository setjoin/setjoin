package user

import (
	"setjoin.com/shared/reducererr"
)

// reducerErrorStatus classifies a reducer error through the shared
// internal/reducererr projection and returns the matching HTTP status, instead
// of the blanket 500 every user-package reducer failure used to return — so an
// over-quota write now yields 507, a forbidden/ownership failure 403, a missing
// target 404, and a stale-state conflict 409. A genuinely-unrecognized error (a
// transport blip, an internal/non-business BZ code) classifies to ClassUnknown,
// whose HTTPStatus() is 500 — so the fallback is preserved with no special-case.
//
// Each call site keeps its own error writer (httputil.WriteError / WriteJSON),
// its existing log line, and its existing human message — ONLY the status code
// flows through this helper. The reducer's raw message is never written to the
// client; the status carries the meaning.
func reducerErrorStatus(err error) int {
	return reducererr.Classify(err).HTTPStatus()
}
