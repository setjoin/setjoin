package network

import (
	"context"
	"testing"
)

// mockReachability returns predetermined results keyed by "host:port".
type mockReachability struct {
	results map[string]bool
}

func (m *mockReachability) IsReachable(ctx context.Context, addr string) bool {
	if m.results == nil {
		return false
	}
	return m.results[addr]
}

func TestDetectNetworkMode_Manual(t *testing.T) {
	checker := &mockReachability{
		results: map[string]bool{
			"baidu.com:443":  true,
			"github.com:443": true,
		},
	}

	mode := DetectNetworkMode(context.Background(), checker, "china")
	if mode != ModeManual {
		t.Errorf("expected ModeManual when override is set, got %q", mode)
	}
}

func TestDetectNetworkMode_China(t *testing.T) {
	// When both baidu and github are reachable, we have full internet access
	// (NOT behind the GFW). The old code incorrectly returned ModeChina here,
	// routing downloads to Gitee on US/EU servers. The correct result is ModeGlobal.
	checker := &mockReachability{
		results: map[string]bool{
			"baidu.com:443":  true,
			"github.com:443": true,
		},
	}

	mode := DetectNetworkMode(context.Background(), checker, "")
	if mode != ModeGlobal {
		t.Errorf("expected ModeGlobal when both baidu and github are reachable, got %q", mode)
	}
}

func TestDetectNetworkMode_Global(t *testing.T) {
	checker := &mockReachability{
		results: map[string]bool{
			"baidu.com:443":  false,
			"github.com:443": true,
		},
	}

	mode := DetectNetworkMode(context.Background(), checker, "")
	if mode != ModeGlobal {
		t.Errorf("expected ModeGlobal when only github is reachable, got %q", mode)
	}
}

func TestDetectNetworkMode_Airgap(t *testing.T) {
	checker := &mockReachability{
		results: map[string]bool{
			"baidu.com:443":  false,
			"github.com:443": false,
		},
	}

	mode := DetectNetworkMode(context.Background(), checker, "")
	if mode != ModeAirgap {
		t.Errorf("expected ModeAirgap when nothing is reachable, got %q", mode)
	}
}

func TestDetectNetworkMode_ChinaOnly(t *testing.T) {
	// China-only: baidu reachable, github blocked
	checker := &mockReachability{
		results: map[string]bool{
			"baidu.com:443":  true,
			"github.com:443": false,
		},
	}

	mode := DetectNetworkMode(context.Background(), checker, "")
	if mode != ModeChina {
		t.Errorf("expected ModeChina when only baidu is reachable, got %q", mode)
	}
}

func TestNetworkMode_String(t *testing.T) {
	tests := []struct {
		mode     NetworkMode
		expected string
	}{
		{ModeChina, "china"},
		{ModeGlobal, "global"},
		{ModeAirgap, "airgap"},
		{ModeManual, "manual"},
	}

	for _, tt := range tests {
		if string(tt.mode) != tt.expected {
			t.Errorf("expected %q, got %q", tt.expected, string(tt.mode))
		}
	}
}
