// Package network provides network environment detection and mirror URL
// resolution for China/Global/Airgap deployment modes.
package network

import (
	"context"
	"net"
	"time"
)

// NetworkMode describes the network environment the gateway is running in.
type NetworkMode string

const (
	// ModeChina — gateway is behind the Great Firewall. Primary mirror is Gitee.
	ModeChina NetworkMode = "china"

	// ModeGlobal — gateway has unrestricted internet access. Primary mirror is GitHub.
	ModeGlobal NetworkMode = "global"

	// ModeAirgap — gateway has no internet access. Updates served from local bundle.
	ModeAirgap NetworkMode = "airgap"

	// ModeManual — admin has explicitly set NETWORK_MODE in config.
	ModeManual NetworkMode = "manual"
)

// ReachabilityChecker tests whether a TCP address is reachable.
// The production implementation dials the address; tests use a mock.
type ReachabilityChecker interface {
	IsReachable(ctx context.Context, addr string) bool
}

// tcpChecker is the production ReachabilityChecker using net.Dialer.
type tcpChecker struct {
	timeout time.Duration
}

func (c *tcpChecker) IsReachable(ctx context.Context, addr string) bool {
	d := net.Dialer{Timeout: c.timeout}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// NewTCPChecker returns a ReachabilityChecker that dials TCP addresses
// with the given timeout.
func NewTCPChecker(timeout time.Duration) ReachabilityChecker {
	return &tcpChecker{timeout: timeout}
}

// DetectNetworkMode probes external endpoints to determine which network
// environment the gateway is running in.
//
//   - If manualOverride is non-empty, returns ModeManual immediately.
//   - If baidu.com:443 reachable AND github.com:443 blocked → ModeChina (GFW present)
//   - If github.com:443 is reachable → ModeGlobal
//   - If neither is reachable → ModeAirgap
//
// Baidu alone is not sufficient for China detection: baidu.com is reachable from
// the global internet too (GFW blocks outbound to github, not inbound to baidu).
// A server in the US would otherwise be misidentified as China and route all
// downloads to Gitee.
func DetectNetworkMode(ctx context.Context, checker ReachabilityChecker, manualOverride string) NetworkMode {
	if manualOverride != "" {
		return ModeManual
	}

	// Correct GFW signal: baidu up AND github down.
	if checker.IsReachable(ctx, "baidu.com:443") && !checker.IsReachable(ctx, "github.com:443") {
		return ModeChina
	}

	// github.com is reachable from the global internet.
	if checker.IsReachable(ctx, "github.com:443") {
		return ModeGlobal
	}

	return ModeAirgap
}
