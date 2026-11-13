package handlers

import "testing"

func TestAcceptBodyValidation(t *testing.T) {
	// touID 0 / version 0 is invalid -> the handler must reject before calling the reducer.
	if acceptBodyValid(0, 1) {
		t.Fatal("tou_id 0 must be rejected")
	}
	if acceptBodyValid(5, 0) {
		t.Fatal("version 0 must be rejected")
	}
	if !acceptBodyValid(5, 2) {
		t.Fatal("valid tou_id+version must pass")
	}
}
