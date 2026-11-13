// Package deploycatalog owns the fixed Setjoin systemd unit inventory.
//
// The catalog is compiled into privileged updater binaries. Its generated
// shell projection is for repository-owned install/lifecycle tooling only;
// neither an HTTP caller nor a signed release manifest can add a command,
// unit, path, or renderer.
package deploycatalog

import "sort"

type Role string

const (
	RoleInfrastructure Role = "infrastructure"
	RoleCore           Role = "core"
	RoleUpdater        Role = "updater"
	RoleOptional       Role = "optional-sidecar"
)

type Unit struct {
	Name             string
	Role             Role
	Template         string
	Destination      string
	Renderer         string
	StartOrder       int
	StopOrder        int
	Required         bool
	DefaultEnable    bool
	RecoveryObserved bool
	Feature          string
}

var units = []Unit{
	{Name: "setjoin-valkey", Role: RoleInfrastructure, Template: "setjoin-valkey.service.template", Destination: "/etc/systemd/system/setjoin-valkey.service", Renderer: "render_valkey_unit", StartOrder: 10, StopOrder: 80, Required: true, DefaultEnable: true},
	{Name: "setjoin-sfu", Role: RoleInfrastructure, Template: "setjoin-sfu.service.template", Destination: "/etc/systemd/system/setjoin-sfu.service", Renderer: "render_sfu_unit", StartOrder: 20, StopOrder: 70, Required: true, DefaultEnable: true},
	{Name: "setjoin-egress", Role: RoleInfrastructure, Template: "setjoin-egress.service.template", Destination: "/etc/systemd/system/setjoin-egress.service", Renderer: "render_egress_unit", StartOrder: 30, StopOrder: 60, Required: true, DefaultEnable: true},
	{Name: "setjoin-funasr", Role: RoleOptional, Template: "setjoin-funasr.service.template", Destination: "/etc/systemd/system/setjoin-funasr.service", Renderer: "render_funasr_unit", StartOrder: 40, StopOrder: 50, Feature: "captions"},
	{Name: "setjoin-asr-bot", Role: RoleOptional, Template: "setjoin-asr-bot.service.template", Destination: "/etc/systemd/system/setjoin-asr-bot.service", Renderer: "render_asrbot_unit", StartOrder: 50, StopOrder: 40, Feature: "captions"},
	{Name: "setjoin-auth", Role: RoleCore, Template: "authserver.service.template", Destination: "/etc/systemd/system/setjoin-auth.service", Renderer: "render_authserver_unit", StartOrder: 60, StopOrder: 30, Required: true, DefaultEnable: true, RecoveryObserved: true},
	{Name: "setjoin", Role: RoleCore, Template: "mailserver.service.template", Destination: "/etc/systemd/system/setjoin.service", Renderer: "render_mailserver_unit", StartOrder: 70, StopOrder: 20, Required: true, DefaultEnable: true, RecoveryObserved: true},
	// The Rust front door (#264, ARCH-027): socket-activated, capability-free,
	// restarted with the Go core; rollback points clients back at Go.
	{Name: "setjoin-gateway", Role: RoleCore, Template: "setjoin-gateway.service.template", Destination: "/etc/systemd/system/setjoin-gateway.service", Renderer: "render_gateway_unit", StartOrder: 75, StopOrder: 15, Required: true, DefaultEnable: true},
	{Name: "setjoin-updater", Role: RoleUpdater, Template: "setjoin-updater.service.template", Destination: "/etc/systemd/system/setjoin-updater.service", Renderer: "render_updater_unit", StartOrder: 80, StopOrder: 10, Required: true, DefaultEnable: true, RecoveryObserved: true},
}

func All() []Unit {
	return cloneSorted(func(Unit) bool { return true }, func(unit Unit) int { return unit.StartOrder })
}

func RequiredStart() []Unit {
	return cloneSorted(func(unit Unit) bool { return unit.Required }, func(unit Unit) int { return unit.StartOrder })
}

func OptionalStart() []Unit {
	return cloneSorted(func(unit Unit) bool { return !unit.Required }, func(unit Unit) int { return unit.StartOrder })
}

func Stop() []Unit {
	return cloneSorted(func(Unit) bool { return true }, func(unit Unit) int { return unit.StopOrder })
}

func Core() []Unit {
	return cloneSorted(func(unit Unit) bool { return unit.Role == RoleCore }, func(unit Unit) int { return unit.StartOrder })
}

func CoreStop() []Unit {
	return cloneSorted(func(unit Unit) bool { return unit.Role == RoleCore }, func(unit Unit) int { return unit.StopOrder })
}

func RecoveryObserved() []Unit {
	return cloneSorted(func(unit Unit) bool { return unit.RecoveryObserved }, func(unit Unit) int { return unit.StartOrder })
}

func Updater() Unit {
	for _, unit := range units {
		if unit.Role == RoleUpdater {
			return unit
		}
	}
	panic("deploy catalog has no updater unit")
}

func cloneSorted(include func(Unit) bool, order func(Unit) int) []Unit {
	result := make([]Unit, 0, len(units))
	for _, unit := range units {
		if include(unit) {
			result = append(result, unit)
		}
	}
	sort.Slice(result, func(i, j int) bool { return order(result[i]) < order(result[j]) })
	return result
}
