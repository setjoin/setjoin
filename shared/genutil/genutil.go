// Package genutil provides generic utility functions.
package genutil

// PtrOr returns *ptr if ptr is non-nil, otherwise returns def.
func PtrOr[T any](ptr *T, def T) T {
	if ptr == nil {
		return def
	}
	return *ptr
}
