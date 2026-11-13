// Package admin — sod.go
//
// SodMode and DeriveSodClass implement the 等保三级 Separation-of-Duties (SoD)
// feature gate and per-session class derivation for the JMAP session surface.
//
// Key safety property: the key is DEFAULT OFF via the toggle registry
// (toggle.registryDefaults), so an unseeded feature_toggles table can never
// silently engage the strict SoD regime on a fresh deployment.
package admin

import "setjoin.com/shared/toggle"

// SodModeToggleKey is the feature_toggles key for the 等保三级 SoD-mode gate —
// an alias of toggle.FeatureDengbaoSodMode shared by SodMode (the runtime
// read), the generic feature-endpoint block (admin_features.go), and the
// dedicated gated handler (sod_handler.go).
const SodModeToggleKey = toggle.FeatureDengbaoSodMode

// SodMode reports whether 等保三级 SoD mode is enabled.
//
// DEFAULT OFF: returns false when "dengbao.sod_mode" is absent from the
// feature_toggles table (the toggle registry default). This prevents the
// strict SoD regime from being engaged silently on a fresh deployment.
func SodMode(t *toggle.FeatureFlags) bool {
	return t.IsEnabled(SodModeToggleKey)
}

// DeriveSodClass derives the caller's SoD class from their role assignments'
// sod_class column values. It returns the single non-empty distinct class when
// all non-empty entries agree, or "" when the slice is empty, contains only
// empty strings, or contains more than one distinct non-empty value (mixed).
//
// Important: derive from the role-level sod_class column values passed in —
// never union per-permission PermClasses. Unioning per-permission classes would
// make every user holding "users.read" (which touches multiple perm classes) look
// "mixed" regardless of their actual role assignments.
func DeriveSodClass(roleClasses []string) string {
	var distinct string
	for _, c := range roleClasses {
		if c == "" {
			continue // skip NULL / empty — these are roles with no sod_class set
		}
		if distinct == "" {
			distinct = c
		} else if distinct != c {
			return "" // mixed — more than one non-empty class
		}
	}
	return distinct
}
