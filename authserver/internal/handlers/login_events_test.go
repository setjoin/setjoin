package handlers

import (
	"testing"
)

func TestGeoIPLookup_NilDB(t *testing.T) {
	h := &AuthHandler{deps: &deps{geoipDB: nil}}
	loc := h.geoIPLookup("8.8.8.8")
	if loc != "" {
		t.Errorf("expected empty location for nil GeoIP DB, got %q", loc)
	}
}

func TestNullIfEmpty(t *testing.T) {
	if nullIfEmpty("") != nil {
		t.Error("expected nil for empty string")
	}
	if nullIfEmpty("value") == nil {
		t.Error("expected non-nil for non-empty string")
	}
}
