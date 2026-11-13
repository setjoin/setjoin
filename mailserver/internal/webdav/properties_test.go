package webdav

import (
	"reflect"
	"testing"
)

func TestResolvePropertiesMatrix(t *testing.T) {
	type value struct{ text string }
	lookup := PropertyLookup[value](func(name PropertyName) (value, bool) {
		values := map[PropertyName]value{
			"displayname": {text: "Work"},
			"getetag":     {text: `"abc"`},
		}
		v, ok := values[name]
		return v, ok
	})

	tests := []struct {
		name        string
		requested   []PropertyName
		allProp     []PropertyName
		wantAllProp bool
		wantPresent []PropertyName
		wantMissing []PropertyName
	}{
		{
			name:        "explicit request preserves ordered present and missing groups",
			requested:   []PropertyName{"getetag", "resourcetype", "displayname"},
			allProp:     []PropertyName{"displayname"},
			wantPresent: []PropertyName{"getetag", "displayname"},
			wantMissing: []PropertyName{"resourcetype"},
		},
		{
			name:        "nil requested selects ordered allprop catalog",
			requested:   nil,
			allProp:     []PropertyName{"displayname", "resourcetype", "getetag"},
			wantAllProp: true,
			wantPresent: []PropertyName{"displayname", "getetag"},
			wantMissing: []PropertyName{"resourcetype"},
		},
		{
			name:        "explicit empty request stays empty",
			requested:   []PropertyName{},
			allProp:     []PropertyName{"displayname"},
			wantPresent: nil,
			wantMissing: nil,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := ResolveProperties(tc.requested, tc.allProp, lookup)
			if got.AllProp != tc.wantAllProp {
				t.Errorf("AllProp = %v, want %v", got.AllProp, tc.wantAllProp)
			}
			var present []PropertyName
			for _, p := range got.Present {
				present = append(present, p.Name)
			}
			if !reflect.DeepEqual(present, tc.wantPresent) {
				t.Errorf("Present = %v, want %v", present, tc.wantPresent)
			}
			if !reflect.DeepEqual(got.Missing, tc.wantMissing) {
				t.Errorf("Missing = %v, want %v", got.Missing, tc.wantMissing)
			}
		})
	}
}

func TestResolveProperties_TypedNilIsMissing(t *testing.T) {
	type value struct{ label string }
	var nilValue *value
	got := ResolveProperties(
		[]PropertyName{"resourcetype"},
		nil,
		PropertyLookup[*value](func(PropertyName) (*value, bool) { return nilValue, true }),
	)
	if len(got.Present) != 0 || !reflect.DeepEqual(got.Missing, []PropertyName{"resourcetype"}) {
		t.Fatalf("typed nil resolution = present %v missing %v, want missing", got.Present, got.Missing)
	}
}
