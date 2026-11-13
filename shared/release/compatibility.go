package release

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

type Version struct {
	Major, Minor, Patch uint64
	Prerelease          []string
}

var semverRE = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$`)

func ParseVersion(raw string) (Version, error) {
	m := semverRE.FindStringSubmatch(raw)
	if m == nil {
		return Version{}, fmt.Errorf("invalid semantic version %q", raw)
	}
	parts := make([]uint64, 3)
	for i := range parts {
		v, err := strconv.ParseUint(m[i+1], 10, 64)
		if err != nil {
			return Version{}, fmt.Errorf("semantic version component overflow")
		}
		parts[i] = v
	}
	v := Version{Major: parts[0], Minor: parts[1], Patch: parts[2]}
	if m[4] != "" {
		v.Prerelease = strings.Split(m[4], ".")
		for _, id := range v.Prerelease {
			if len(id) > 1 && id[0] == '0' && numeric(id) {
				return Version{}, fmt.Errorf("numeric prerelease identifiers cannot have leading zeroes")
			}
		}
	}
	return v, nil
}
func (v Version) Compare(o Version) int {
	for _, p := range [][2]uint64{{v.Major, o.Major}, {v.Minor, o.Minor}, {v.Patch, o.Patch}} {
		if p[0] < p[1] {
			return -1
		}
		if p[0] > p[1] {
			return 1
		}
	}
	if len(v.Prerelease) == 0 && len(o.Prerelease) == 0 {
		return 0
	}
	if len(v.Prerelease) == 0 {
		return 1
	}
	if len(o.Prerelease) == 0 {
		return -1
	}
	for i := 0; i < len(v.Prerelease) && i < len(o.Prerelease); i++ {
		l, r := v.Prerelease[i], o.Prerelease[i]
		if l == r {
			continue
		}
		ln, rn := numeric(l), numeric(r)
		if ln && rn {
			lv, _ := strconv.ParseUint(l, 10, 64)
			rv, _ := strconv.ParseUint(r, 10, 64)
			if lv < rv {
				return -1
			}
			return 1
		}
		if ln {
			return -1
		}
		if rn {
			return 1
		}
		if l < r {
			return -1
		}
		return 1
	}
	if len(v.Prerelease) < len(o.Prerelease) {
		return -1
	}
	if len(v.Prerelease) > len(o.Prerelease) {
		return 1
	}
	return 0
}

type versionConstraint struct {
	op      string
	version Version
}

func ValidateVersionRange(raw string) error { _, err := parseVersionRange(raw); return err }
func VersionInRange(rawVersion, rawRange string) (bool, error) {
	v, err := ParseVersion(rawVersion)
	if err != nil {
		return false, err
	}
	cs, err := parseVersionRange(rawRange)
	if err != nil {
		return false, err
	}
	for _, c := range cs {
		cmp := v.Compare(c.version)
		switch c.op {
		case "=":
			if cmp != 0 {
				return false, nil
			}
		case ">":
			if cmp <= 0 {
				return false, nil
			}
		case ">=":
			if cmp < 0 {
				return false, nil
			}
		case "<":
			if cmp >= 0 {
				return false, nil
			}
		case "<=":
			if cmp > 0 {
				return false, nil
			}
		}
	}
	return true, nil
}
func parseVersionRange(raw string) ([]versionConstraint, error) {
	parts := strings.Fields(raw)
	if len(parts) == 0 || len(parts) > 4 {
		return nil, fmt.Errorf("version range requires one to four constraints")
	}
	out := make([]versionConstraint, 0, len(parts))
	for _, part := range parts {
		op, vr := "=", part
		for _, candidate := range []string{">=", "<=", ">", "<", "="} {
			if strings.HasPrefix(part, candidate) {
				op, vr = candidate, strings.TrimPrefix(part, candidate)
				break
			}
		}
		v, err := ParseVersion(vr)
		if err != nil {
			return nil, err
		}
		out = append(out, versionConstraint{op: op, version: v})
	}
	return out, nil
}
func numeric(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

type LocalState struct {
	Version                string
	SchemaVersion          int
	Platform, Architecture string
	Channel                Channel
	LastMetadataVersion    uint64
	LastMetadataDigest     string
	AllowEnterprise        bool
}

func CheckCompatibility(m *Manifest, s LocalState) error {
	if err := m.Validate(); err != nil {
		return err
	}
	if s.Channel != m.Channel {
		return fmt.Errorf("wrong channel: manifest=%s local=%s", m.Channel, s.Channel)
	}
	if !contains(m.Platforms, s.Platform) || !contains(m.Architectures, s.Architecture) {
		return fmt.Errorf("manifest does not support %s/%s", s.Platform, s.Architecture)
	}
	ok, err := VersionInRange(s.Version, m.Compatibility.SourceVersionRange)
	if err != nil || !ok {
		return fmt.Errorf("source version %q is incompatible", s.Version)
	}
	if s.SchemaVersion != m.SchemaFrom {
		return fmt.Errorf("schema version %d does not match manifest source %d", s.SchemaVersion, m.SchemaFrom)
	}
	if m.Channel == ChannelEnterprise && !s.AllowEnterprise {
		return fmt.Errorf("enterprise entitlement is required")
	}
	if s.LastMetadataVersion > m.MetadataVersion {
		return fmt.Errorf("metadata rollback detected")
	}
	return nil
}
