package main

import "testing"

func TestCAStateDefaultsReportOnly(t *testing.T) {
	body, err := buildCACreateBody([]string{"--name", "p"})
	if err != nil {
		t.Fatal(err)
	}
	if body["state"] != "report_only" {
		t.Fatalf("default state = %v, want report_only", body["state"])
	}
}

func TestCAEnabledAliasMapsToOn(t *testing.T) {
	body, err := buildCACreateBody([]string{"--name", "p", "--enabled=true"})
	if err != nil {
		t.Fatal(err)
	}
	if body["state"] != "on" {
		t.Fatalf("--enabled=true must map to state=on, got %v", body["state"])
	}
}

func TestCAEnabledFalseMapsToOff(t *testing.T) {
	body, err := buildCACreateBody([]string{"--name", "p", "--enabled=false"})
	if err != nil {
		t.Fatal(err)
	}
	if body["state"] != "off" {
		t.Fatalf("--enabled=false must map to state=off, got %v", body["state"])
	}
}
