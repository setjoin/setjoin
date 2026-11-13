package threat

import "testing"

func TestParseDevicePlatform(t *testing.T) {
	cases := map[string]string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64)":              "windows",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X)": "ios",
		"Mozilla/5.0 (iPad; CPU OS 17_0 like Mac OS X)":          "ios",
		"Mozilla/5.0 (Linux; Android 14; Pixel 8)":               "android",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)":        "macos",
		"Mozilla/5.0 (X11; Linux x86_64)":                        "linux",
		"":                                                       "unknown",
		"curl/8.0":                                               "unknown",
	}
	for ua, want := range cases {
		if got := parseDevicePlatform(ua); got != want {
			t.Errorf("parseDevicePlatform(%q) = %q, want %q", ua, got, want)
		}
	}
}

func TestMatchDevicePlatform(t *testing.T) {
	if !matchDevicePlatform(map[string]interface{}{}, "ios") {
		t.Fatal("empty condition must match")
	}
	if !matchDevicePlatform(map[string]interface{}{"device_platform": "ios"}, "ios") {
		t.Fatal("ios must match ios")
	}
	if matchDevicePlatform(map[string]interface{}{"device_platform": "ios"}, "android") {
		t.Fatal("ios must not match android")
	}
}

func TestMatchCountryIn(t *testing.T) {
	cond := map[string]interface{}{"country_in": []interface{}{"KP", "RU"}}
	if !matchCountryIn(cond, "RU") {
		t.Fatal("RU in {KP,RU} must match")
	}
	if matchCountryIn(cond, "US") {
		t.Fatal("US not in {KP,RU}")
	}
	unknown := map[string]interface{}{"country_in": []interface{}{""}}
	if !matchCountryIn(unknown, "") {
		t.Fatal("unknown-country member matches empty country")
	}
	if !matchCountryIn(map[string]interface{}{}, "ZZ") {
		t.Fatal("empty condition matches")
	}
}
