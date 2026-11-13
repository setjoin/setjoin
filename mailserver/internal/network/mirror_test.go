package network

import "testing"

func TestResolveDownloadURL_China(t *testing.T) {
	primary, fallback := ResolveDownloadURL(ModeChina, "SetJoin_1.0.0_x64.dmg")

	if primary == "" {
		t.Error("expected non-empty primary URL for China mode")
	}
	if fallback == "" {
		t.Error("expected non-empty fallback URL for China mode")
	}

	// China: primary should be Gitee, fallback GitHub.
	if !contains(primary, "gitee.com") {
		t.Errorf("expected primary on gitee.com, got %s", primary)
	}
	if !contains(fallback, "github.com") {
		t.Errorf("expected fallback on github.com, got %s", fallback)
	}
}

func TestResolveDownloadURL_Global(t *testing.T) {
	primary, fallback := ResolveDownloadURL(ModeGlobal, "SetJoin_1.0.0_x64.AppImage")

	if primary == "" {
		t.Error("expected non-empty primary URL for Global mode")
	}
	if fallback == "" {
		t.Error("expected non-empty fallback URL for Global mode")
	}

	// Global: primary should be GitHub, fallback Gitee.
	if !contains(primary, "github.com") {
		t.Errorf("expected primary on github.com, got %s", primary)
	}
	if !contains(fallback, "gitee.com") {
		t.Errorf("expected fallback on gitee.com, got %s", fallback)
	}
}

func TestResolveDownloadURL_Airgap(t *testing.T) {
	primary, fallback := ResolveDownloadURL(ModeAirgap, "gateway_v2.0.0")

	if primary == "" {
		t.Error("expected non-empty primary URL for Airgap mode")
	}
	if fallback != "" {
		t.Errorf("expected empty fallback for Airgap mode, got %s", fallback)
	}

	if !contains(primary, "/updates") {
		t.Errorf("expected primary on /updates, got %s", primary)
	}
}

func TestResolveDownloadURL_Manual(t *testing.T) {
	// Manual mode uses config-specified mode via override.
	// When manual itself is not in the mirror map, it falls back to Global.
	primary, fallback := ResolveDownloadURL(ModeManual, "asset.exe")
	if primary == "" || fallback == "" {
		t.Error("expected URLs for manual mode fallback to Global")
	}
}

func TestResolveDownloadURL_IncludesAsset(t *testing.T) {
	primary, _ := ResolveDownloadURL(ModeGlobal, "SetJoin_2.0.0_arm64.dmg")
	if !contains(primary, "SetJoin_2.0.0_arm64.dmg") {
		t.Errorf("expected asset name in URL, got %s", primary)
	}
}

func TestMirrorConfigs_AllModesHavePrimary(t *testing.T) {
	modes := []NetworkMode{ModeChina, ModeGlobal, ModeAirgap}
	for _, mode := range modes {
		cfg, ok := defaultMirrors[mode]
		if !ok {
			t.Errorf("missing mirror config for mode %q", mode)
			continue
		}
		if cfg.Primary == nil {
			t.Errorf("mode %q has nil primary mirror", mode)
		}
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && searchSubstring(s, substr)
}

func searchSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
