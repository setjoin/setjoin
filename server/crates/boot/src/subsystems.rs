//! Runtime subsystem selection (`--subsystems=all|http,auth,protocols,workers`).

use std::fmt;
use std::str::FromStr;

/// Bitset of subsystems enabled in a server process.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Subsystems {
    pub http: bool,
    pub auth: bool,
    pub protocols: bool,
    pub workers: bool,
}

impl Subsystems {
    /// All four subsystems enabled (default single-node deployment).
    pub const ALL: Self = Self {
        http: true,
        auth: true,
        protocols: true,
        workers: true,
    };

    /// No subsystems enabled.
    pub const NONE: Self = Self {
        http: false,
        auth: false,
        protocols: false,
        workers: false,
    };

    /// True when no subsystem is active.
    pub const fn is_empty(self) -> bool {
        !self.http && !self.auth && !self.protocols && !self.workers
    }

    /// Parse a subsystem list (`all`, `http,auth`, or `--subsystems=http,workers`).
    /// Unknown names, empty segments, and mixing `all` with individual names are
    /// rejected fail-closed.
    pub fn parse(raw: &str) -> Result<Self, String> {
        let spec = raw.trim();
        let spec = spec.strip_prefix("--subsystems=").unwrap_or(spec).trim();
        if spec.is_empty() {
            return Err("subsystems list must not be empty".into());
        }
        if spec == "all" {
            return Ok(Self::ALL);
        }
        let mut out = Self::NONE;
        for token in spec.split(',') {
            let name = token.trim();
            match name {
                "http" => out.http = true,
                "auth" => out.auth = true,
                "protocols" => out.protocols = true,
                "workers" => out.workers = true,
                "all" => {
                    return Err(
                        "subsystems: 'all' cannot be combined with individual subsystem names"
                            .into(),
                    );
                }
                "" => {
                    return Err("subsystems: empty entry in comma-separated list".into());
                }
                other => {
                    return Err(format!(
                        "subsystems: unknown subsystem {other:?} (expected all, http, auth, protocols, or workers)"
                    ));
                }
            }
        }
        if out.is_empty() {
            return Err("subsystems list must enable at least one subsystem".into());
        }
        Ok(out)
    }
}

impl Default for Subsystems {
    fn default() -> Self {
        Self::ALL
    }
}

impl FromStr for Subsystems {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl fmt::Display for Subsystems {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if *self == Self::ALL {
            return f.write_str("all");
        }
        let mut parts = Vec::with_capacity(4);
        if self.http {
            parts.push("http");
        }
        if self.auth {
            parts.push("auth");
        }
        if self.protocols {
            parts.push("protocols");
        }
        if self.workers {
            parts.push("workers");
        }
        f.write_str(&parts.join(","))
    }
}

#[cfg(test)]
mod tests {
    use super::Subsystems;

    #[test]
    fn parses_all_and_individual_subsystems() {
        assert_eq!(Subsystems::parse("all").unwrap(), Subsystems::ALL);
        assert_eq!(
            Subsystems::parse("--subsystems=all").unwrap(),
            Subsystems::ALL
        );
        assert_eq!(
            Subsystems::parse("http,auth").unwrap(),
            Subsystems {
                http: true,
                auth: true,
                protocols: false,
                workers: false,
            }
        );
        assert_eq!(
            Subsystems::parse("--subsystems=protocols,workers").unwrap(),
            Subsystems {
                http: false,
                auth: false,
                protocols: true,
                workers: true,
            }
        );
        assert_eq!(Subsystems::ALL.to_string(), "all");
        assert_eq!(
            Subsystems {
                http: true,
                auth: false,
                protocols: false,
                workers: true,
            }
            .to_string(),
            "http,workers"
        );
    }

    #[test]
    fn rejects_empty_unknown_and_mixed_all() {
        for bad in [
            "",
            "--subsystems=",
            "http,",
            ",auth",
            "all,http",
            "http,all",
            "authh",
            "smtp",
        ] {
            assert!(
                Subsystems::parse(bad).is_err(),
                "expected error for {bad:?}"
            );
        }
    }
}
