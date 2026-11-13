package network

// Mirror holds download URLs for a platform's release assets.
type Mirror struct {
	GitHub string // e.g., https://github.com/setjoin/setjoin/releases/download
	Gitee  string // e.g., https://gitee.com/setjoin/setjoin/releases/download
	Local  string // e.g., /updates (air-gap, served from local gateway)
}

// MirrorConfig maps each network mode to its primary and fallback mirrors.
type MirrorConfig struct {
	Primary  *Mirror
	Fallback *Mirror
}

// Default mirrors. Gitee URL uses the same org/repo as GitHub; adjust if
// your Gitee mirror uses a different org or path.
var defaultMirrors = map[NetworkMode]MirrorConfig{
	ModeChina: {
		Primary: &Mirror{
			Gitee: "https://gitee.com/setjoin/setjoin/releases/download",
		},
		Fallback: &Mirror{
			GitHub: "https://github.com/setjoin/setjoin/releases/download",
		},
	},
	ModeGlobal: {
		Primary: &Mirror{
			GitHub: "https://github.com/setjoin/setjoin/releases/download",
		},
		Fallback: &Mirror{
			Gitee: "https://gitee.com/setjoin/setjoin/releases/download",
		},
	},
	ModeAirgap: {
		Primary: &Mirror{
			Local: "/updates",
		},
		Fallback: nil,
	},
}

// ResolveDownloadURL returns the best download URL for a given asset name
// (e.g. "SetJoin_1.0.0_x64.dmg") based on the current network mode.
// Returns the primary URL first; callers may retry with the fallback URL
// on download failure.
func ResolveDownloadURL(mode NetworkMode, asset string) (primary string, fallback string) {
	cfg, ok := defaultMirrors[mode]
	if !ok {
		cfg = defaultMirrors[ModeGlobal]
	}

	primary = buildURL(cfg.Primary, asset)
	if cfg.Fallback != nil {
		fallback = buildURL(cfg.Fallback, asset)
	}

	return primary, fallback
}

func buildURL(m *Mirror, asset string) string {
	if m == nil {
		return ""
	}
	switch {
	case m.GitHub != "":
		return m.GitHub + "/" + asset
	case m.Gitee != "":
		return m.Gitee + "/" + asset
	case m.Local != "":
		return m.Local + "/" + asset
	default:
		return ""
	}
}
