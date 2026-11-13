// Package validate provides shared field-level validation functions used by
// both authserver and mailserver gateway. All validators return either nil
// (valid) or a *ValidationError with a structured rejection reason.
package validate

import (
	"fmt"

	"setjoin.com/shared/httputil"
)

// ValidationError carries a structured field-level rejection reason.
type ValidationError struct {
	Field  string `json:"field"`
	Reason string `json:"reason"`
	Code   string `json:"code"`
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("validation failed for %s: %s", e.Field, e.Reason)
}

// ToFieldError projects the validation error onto the HTTP-layer
// httputil.FieldError ({field, message}) consumed by RFC 7807 problem
// responses. Message carries Reason, so a call site writing
// `Detail: ve.Reason` is byte-identical to `Detail: ve.ToFieldError().Message`.
func (e *ValidationError) ToFieldError() httputil.FieldError {
	return httputil.FieldError{Field: e.Field, Message: e.Reason}
}

// NewValidationError constructs a ValidationError.
func NewValidationError(field, reason, code string) *ValidationError {
	return &ValidationError{
		Field:  field,
		Reason: reason,
		Code:   code,
	}
}
