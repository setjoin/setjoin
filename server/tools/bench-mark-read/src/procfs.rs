//! CPU time and memory of a serving process from `/proc/<pid>/{stat,status}`.

/// `utime + stime` in clock ticks (fields 14 and 15 of `stat`). The command
/// name may contain spaces and parentheses, so fields are counted after the
/// last `)`.
pub fn cpu_ticks(stat: &str) -> Option<u64> {
    let rest = &stat[stat.rfind(')')? + 1..];
    let f: Vec<&str> = rest.split_whitespace().collect();
    // After ")": field 3 (state) is f[0], so field n is f[n - 3].
    Some(f.get(11)?.parse::<u64>().ok()? + f.get(12)?.parse::<u64>().ok()?)
}

/// A `kB` line of `status` (`VmRSS`, `VmHWM`), in KiB.
pub fn status_kb(status: &str, key: &str) -> Option<u64> {
    status.lines().find_map(|l| {
        let v = l.strip_prefix(key)?.strip_prefix(':')?;
        v.trim().strip_suffix("kB")?.trim().parse().ok()
    })
}

/// One reading of a process; `None` once it is gone.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Reading {
    pub ticks: u64,
    pub rss_kb: u64,
    pub hwm_kb: u64,
}

pub fn read(pid: u32) -> Option<Reading> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    Some(Reading {
        ticks: cpu_ticks(&stat)?,
        rss_kb: status_kb(&status, "VmRSS")?,
        hwm_kb: status_kb(&status, "VmHWM")?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ticks_survive_a_command_name_with_spaces_and_parens() {
        let stat = "4242 (my (odd) name) S 1 4242 4242 0 -1 4194560 100 0 0 0 1234 567 0 0 20 0 9 0 999 1000 200";
        assert_eq!(cpu_ticks(stat), Some(1234 + 567));
        assert_eq!(cpu_ticks("1 (x) S 1"), None);
    }

    #[test]
    fn status_lines_in_kib() {
        let status = "Name:\tmailserverd\nVmHWM:\t  123456 kB\nVmRSS:\t   98765 kB\n";
        assert_eq!(status_kb(status, "VmHWM"), Some(123456));
        assert_eq!(status_kb(status, "VmRSS"), Some(98765));
        assert_eq!(status_kb(status, "VmSwap"), None);
    }

    #[test]
    fn reads_this_process() {
        let r = read(std::process::id()).unwrap();
        assert!(r.rss_kb > 0 && r.hwm_kb >= r.rss_kb);
    }
}
