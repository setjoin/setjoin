package scim

import (
	"context"

	"setjoin.com/shared/reducererr"
)

// reducerStatus classifies a reducer (scim_*) error through the shared
// internal/reducererr projection and returns the HTTP status the SCIM gateway
// should write, instead of the blanket 500 every scim reducer failure used to
// return. So a duplicate/conflict write now yields 409, a forbidden one 403, a
// missing target 404, an over-quota one 507, and a bad-input one 400 — while a
// genuinely-unrecognized error (transport blip, internal code) keeps the 500
// fallback. The caller preserves its existing SCIM error JSON shape
// (WriteSCIMError with the same detail/scimType); only the status changes.
func reducerStatus(err error) int {
	return reducererr.Classify(err).HTTPStatus()
}

// logReducerError classifies the reducer error once and logs it at the class's
// LogLevel() — a client-actionable business failure (conflict/forbidden/
// not-found/over-quota) logs at Info, not Error, since it is an expected
// caller-driven condition the SCIM response already reports; only a genuinely-
// internal error (the 500 fallback) logs at Error. It returns the matching HTTP
// status so a write site stays a single call: WriteSCIMError(w, s.logReducerError(...), ...).
func (s *Server) logReducerError(msg string, err error) int {
	class := reducererr.Classify(err)
	s.logger.Log(context.Background(), class.LogLevel(), msg, "error", err)
	return reducerStatus(err)
}
