//! Env contract (`asrbot/DOX.md` "Env contract"), parsed like Go's `loadConfig`.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    pub listen: String,
    pub livekit_url: String,
    pub funasr_url: String,
    pub token: String,
    pub max_meetings: i64,
    pub max_active_tracks: i64,
}

impl Config {
    pub fn from_env() -> Self {
        Self::from_lookup(|key| std::env::var(key).ok())
    }

    pub fn from_lookup(get: impl Fn(&str) -> Option<String>) -> Self {
        let text = |key: &str, default: &str| {
            get(key)
                .filter(|v| !v.is_empty())
                .unwrap_or_else(|| default.to_owned())
        };
        let int = |key: &str, default: i64| {
            get(key)
                .filter(|v| !v.is_empty())
                .and_then(|v| v.parse::<i64>().ok())
                .unwrap_or(default)
        };
        Self {
            listen: text("ASR_LISTEN", "127.0.0.1:7890"),
            livekit_url: get("LIVEKIT_URL").unwrap_or_default(),
            funasr_url: text("FUNASR_URL", "ws://127.0.0.1:10096"),
            // ASR_TOKEN is required and never logged.
            token: get("ASR_TOKEN").unwrap_or_default(),
            max_meetings: int("ASR_MAX_MEETINGS", 2),
            max_active_tracks: int("ASR_MAX_ACTIVE_TRACKS", 4),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn load(pairs: &[(&str, &str)]) -> Config {
        let map: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| ((*k).into(), (*v).into()))
            .collect();
        Config::from_lookup(|k| map.get(k).cloned())
    }

    #[test]
    fn defaults_match_the_env_contract() {
        let c = load(&[]);
        assert_eq!(c.listen, "127.0.0.1:7890");
        assert_eq!(c.funasr_url, "ws://127.0.0.1:10096");
        assert_eq!((c.max_meetings, c.max_active_tracks), (2, 4));
        assert_eq!((c.livekit_url.as_str(), c.token.as_str()), ("", ""));
    }

    #[test]
    fn bad_integers_fall_back_like_atoi() {
        assert_eq!(load(&[("ASR_MAX_MEETINGS", "x")]).max_meetings, 2);
        assert_eq!(load(&[("ASR_MAX_MEETINGS", " 3")]).max_meetings, 2);
        assert_eq!(load(&[("ASR_MAX_MEETINGS", "+3")]).max_meetings, 3);
        assert_eq!(
            load(&[("ASR_MAX_ACTIVE_TRACKS", "-1")]).max_active_tracks,
            -1
        );
        assert_eq!(load(&[("ASR_MAX_MEETINGS", "")]).max_meetings, 2);
    }
}
