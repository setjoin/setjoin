//! `bench-mark-read` CLI.
//!
//! ```text
//! bench-mark-read run  --addr HOST:PORT --token-file F --account A --ids 1,2,3
//!                      [--warmup N] (--samples N | --duration-s S) [--concurrency C]
//!                      --out DIR --label L [--pid NAME=PID]... [--clk-tck 100]
//!                      [--after-warmup 'shell command']
//! bench-mark-read once --addr HOST:PORT --token-file F --account A --id ID --seen true|false
//! bench-mark-read summarize FILE.csv
//! ```
//!
//! `run` drives the frozen sequence ([`plan`]) over `C` keep-alive
//! connections, discards the first `N` (warm-up) requests, writes every
//! measured request to `DIR/L.csv` and a summary to `DIR/L.json`: latency of
//! successful requests, outcome counts, the outage window (if any), and per
//! `--pid` process CPU seconds and peak RSS sampled every 100 ms during the
//! measured phase. Transport errors are recorded and the connection reopened;
//! nothing is retried.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bench_mark_read::http::{post_request, Client};
use bench_mark_read::outcome::Outcome;
use bench_mark_read::plan::{deal, mark_read_body};
use bench_mark_read::procfs;
use bench_mark_read::stats::Summary;
use bench_mark_read::timeline::{outage, Sample};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let r = match args.first().map(String::as_str) {
        Some("run") => run(&Opts::parse(&args[1..])),
        Some("once") => once(&Opts::parse(&args[1..])),
        Some("summarize") => summarize(args.get(1).map(String::as_str).unwrap_or("")),
        Some("compare") => compare(&Opts::parse(&args[1..])),
        _ => Err("usage: bench-mark-read run|once|summarize ... (see src/main.rs)".into()),
    };
    if let Err(e) = r {
        eprintln!("bench-mark-read: {e}");
        std::process::exit(2);
    }
}

struct Opts(BTreeMap<String, Vec<String>>);

impl Opts {
    fn parse(a: &[String]) -> Opts {
        let mut m: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for pair in a.chunks(2) {
            if let [k, v] = pair {
                m.entry(k.trim_start_matches("--").into())
                    .or_default()
                    .push(v.clone());
            }
        }
        Opts(m)
    }
    fn get(&self, k: &str) -> Result<&str, String> {
        self.0
            .get(k)
            .and_then(|v| v.last())
            .map(String::as_str)
            .ok_or(format!("--{k} is required"))
    }
    fn num(&self, k: &str, default: u64) -> Result<u64, String> {
        self.0
            .get(k)
            .and_then(|v| v.last())
            .map_or(Ok(default), |v| {
                v.parse().map_err(|_| format!("--{k}: not a number"))
            })
    }
    fn all(&self, k: &str) -> Vec<String> {
        self.0.get(k).cloned().unwrap_or_default()
    }
}

struct Target {
    addr: String,
    token: String,
    account: String,
}

impl Target {
    fn from(o: &Opts) -> Result<Target, String> {
        let token = std::fs::read_to_string(o.get("token-file")?)
            .map_err(|e| format!("token-file: {e}"))?;
        Ok(Target {
            addr: o.get("addr")?.into(),
            token: token.trim().into(),
            account: o.get("account")?.into(),
        })
    }
    fn request(&self, id: i64, seen: bool) -> Vec<u8> {
        let auth = format!("Bearer {}", self.token);
        let origin = format!("http://{}", self.addr);
        post_request(
            &self.addr,
            "/jmap",
            &[("Authorization", &auth), ("Origin", &origin)],
            &mark_read_body(&self.account, id, seen),
        )
    }
    fn call(&self, c: &mut Client, id: i64, seen: bool) -> (Outcome, String) {
        match c.send(&self.request(id, seen)) {
            Ok(r) => (Outcome::classify(r.status, &r.body, id), r.body),
            Err(e) => (Outcome::Transport, e),
        }
    }
}

fn once(o: &Opts) -> Result<(), String> {
    let t = Target::from(o)?;
    let id: i64 = o.get("id")?.parse().map_err(|_| "--id")?;
    let seen = o.get("seen")? == "true";
    let mut c = Client::new(&t.addr, Duration::from_secs(30));
    let r = c.send(&t.request(id, seen))?;
    println!("{}", r.status);
    print!("{}", r.body);
    Ok(())
}

fn run(o: &Opts) -> Result<(), String> {
    let t = Arc::new(Target::from(o)?);
    let ids: Vec<i64> = o
        .get("ids")?
        .split(',')
        .map(|s| s.trim().parse().map_err(|_| format!("bad id {s:?}")))
        .collect::<Result<_, _>>()?;
    let workers = o.num("concurrency", 1)? as usize;
    let warmup = o.num("warmup", 0)?;
    let samples = o.num("samples", 0)?;
    let duration = Duration::from_secs(o.num("duration-s", 0)?);
    if (samples == 0) == duration.is_zero() {
        return Err("give exactly one of --samples or --duration-s".into());
    }
    let clk = o.num("clk-tck", 100)? as f64;
    let out = o.get("out")?;
    let label = o.get("label")?;
    let pids: Vec<(String, u32)> = o
        .all("pid")
        .iter()
        .map(|p| {
            p.split_once('=')
                .and_then(|(n, v)| Some((n.to_string(), v.parse().ok()?)))
                .ok_or(format!("bad --pid {p}"))
        })
        .collect::<Result<_, _>>()?;

    let plans = deal(&ids, workers)?;
    // Warm-up: each worker runs its share, results discarded.
    let mut plans: Vec<_> = std::thread::scope(|s| {
        plans
            .into_iter()
            .enumerate()
            .map(|(w, mut p)| {
                let t = t.clone();
                let n = warmup / workers as u64 + u64::from((w as u64) < warmup % workers as u64);
                s.spawn(move || {
                    let mut c = Client::new(&t.addr, Duration::from_secs(30));
                    for _ in 0..n {
                        let (id, seen) = p.next().unwrap();
                        t.call(&mut c, id, seen);
                    }
                    p
                })
            })
            .collect::<Vec<_>>()
            .into_iter()
            .map(|h| h.join().unwrap())
            .collect()
    });

    // Optional hook between warm-up and measurement (e.g. reset DB counters).
    if let Ok(hook) = o.get("after-warmup") {
        let ok = std::process::Command::new("bash")
            .arg("-c")
            .arg(hook)
            .status()
            .map_err(|e| format!("after-warmup: {e}"))?;
        if !ok.success() {
            return Err(format!("after-warmup hook failed: {ok}"));
        }
    }
    let before: Vec<Option<procfs::Reading>> = pids.iter().map(|(_, p)| procfs::read(*p)).collect();
    let peak = Arc::new(Mutex::new(vec![0u64; pids.len()]));
    let stop = Arc::new(AtomicBool::new(false));
    let sampler = {
        let (peak, stop, pids) = (peak.clone(), stop.clone(), pids.clone());
        std::thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                let mut pk = peak.lock().unwrap();
                for (i, (_, p)) in pids.iter().enumerate() {
                    if let Some(r) = procfs::read(*p) {
                        pk[i] = pk[i].max(r.rss_kb);
                    }
                }
                drop(pk);
                std::thread::sleep(Duration::from_millis(100));
            }
        })
    };

    let t0 = Instant::now();
    // The first reply body (or transport error) seen per outcome class: what
    // the client was actually told.
    let first: Mutex<BTreeMap<String, String>> = Mutex::new(BTreeMap::new());
    let first = &first;
    let all: Vec<Sample> = std::thread::scope(|s| {
        let hs: Vec<_> = plans
            .drain(..)
            .enumerate()
            .map(|(w, mut p)| {
                let t = t.clone();
                let n = samples / workers as u64 + u64::from((w as u64) < samples % workers as u64);
                s.spawn(move || {
                    let mut c = Client::new(&t.addr, Duration::from_secs(30));
                    let mut v = Vec::new();
                    let mut i = 0u64;
                    loop {
                        if samples > 0 && i >= n || samples == 0 && t0.elapsed() >= duration {
                            break;
                        }
                        let (id, seen) = p.next().unwrap();
                        let start = t0.elapsed();
                        let (outcome, body) = t.call(&mut c, id, seen);
                        let lat = t0.elapsed() - start;
                        first
                            .lock()
                            .unwrap()
                            .entry(outcome.label())
                            .or_insert_with(|| body.chars().take(400).collect());
                        v.push(Sample {
                            start_us: start.as_micros() as u64,
                            latency_us: lat.as_micros() as u64,
                            outcome,
                        });
                        if outcome == Outcome::Transport {
                            // Do not spin on a refused port.
                            std::thread::sleep(Duration::from_millis(20));
                        }
                        i += 1;
                    }
                    v
                })
            })
            .collect();
        hs.into_iter().flat_map(|h| h.join().unwrap()).collect()
    });
    let wall = t0.elapsed().as_secs_f64();
    stop.store(true, Ordering::Relaxed);
    sampler.join().ok();
    let after: Vec<Option<procfs::Reading>> = pids.iter().map(|(_, p)| procfs::read(*p)).collect();

    let mut csv = String::from("start_us,latency_us,outcome\n");
    for s in &all {
        csv.push_str(&s.csv());
        csv.push('\n');
    }
    std::fs::write(format!("{out}/{label}.csv"), csv).map_err(|e| format!("write csv: {e}"))?;
    let bodies: String = first
        .lock()
        .unwrap()
        .iter()
        .map(|(k, v)| format!("{k}: {}\n", v.trim_end()))
        .collect();
    std::fs::write(format!("{out}/{label}.bodies.txt"), bodies)
        .map_err(|e| format!("write bodies: {e}"))?;

    let mut procs = Vec::new();
    for (i, (name, pid)) in pids.iter().enumerate() {
        let cpu = match (before[i], after[i]) {
            (Some(b), Some(a)) => {
                let s = (a.ticks - b.ticks) as f64 / clk;
                format!("{s:.3}")
            }
            _ => "null".into(),
        };
        let hwm = after[i].map_or("null".into(), |a| a.hwm_kb.to_string());
        procs.push(format!(
            r#"{{"name":"{name}","pid":{pid},"cpu_s":{cpu},"peak_rss_kb_sampled":{},"vmhwm_kb":{hwm}}}"#,
            peak.lock().unwrap()[i]
        ));
    }
    let json = summary_json(label, workers, wall, &all, &procs);
    std::fs::write(format!("{out}/{label}.json"), &json).map_err(|e| format!("write json: {e}"))?;
    println!("{json}");
    Ok(())
}

fn summary_json(
    label: &str,
    workers: usize,
    wall: f64,
    all: &[Sample],
    procs: &[String],
) -> String {
    let ok: Vec<u64> = all
        .iter()
        .filter(|s| s.outcome.is_success())
        .map(|s| s.latency_us)
        .collect();
    let lat = Summary::of(&ok).map_or("null".into(), |s| {
        format!(
            r#"{{"n":{},"min_us":{},"p50_us":{},"p95_us":{},"p99_us":{},"max_us":{},"mean_us":{:.1}}}"#,
            s.n, s.min, s.p50, s.p95, s.p99, s.max, s.mean
        )
    });
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    for s in all {
        *counts.entry(s.outcome.label()).or_default() += 1;
    }
    let counts: Vec<String> = counts
        .iter()
        .map(|(k, v)| format!(r#""{k}":{v}"#))
        .collect();
    let out = outage(all).map_or("null".into(), |o| {
        let f: Vec<String> = o.failures.iter().map(|(k, v)| format!(r#""{k}":{v}"#)).collect();
        format!(
            r#"{{"first_failure_ms":{:.1},"last_failure_ms":{:.1},"recovered_at_ms":{},"failures":{{{}}}}}"#,
            o.first_failure_us as f64 / 1000.0,
            o.last_failure_us as f64 / 1000.0,
            o.recovered_at_us.map_or("null".into(), |r| format!("{:.1}", r as f64 / 1000.0)),
            f.join(",")
        )
    });
    format!(
        r#"{{"label":"{label}","concurrency":{workers},"requests":{},"wall_s":{wall:.3},"throughput_rps":{:.1},"latency_ok":{lat},"outcomes":{{{}}},"outage":{out},"processes":[{}]}}"#,
        all.len(),
        all.len() as f64 / wall,
        counts.join(","),
        procs.join(",")
    )
}

/// `compare --a FILE --a-id N --b FILE --b-id M`: files are `once` output
/// (status line, then body). Prints `PARITY-EQUAL` or `PARITY-DIFF` with
/// both normalised replies; exit 1 on a difference.
fn compare(o: &Opts) -> Result<(), String> {
    let load = |f: &str, id: &str| -> Result<String, String> {
        let t = std::fs::read_to_string(o.get(f)?).map_err(|e| format!("--{f}: {e}"))?;
        let id: i64 = o.get(id)?.parse().map_err(|_| format!("--{id}"))?;
        Ok(bench_mark_read::outcome::normalize(&t, id))
    };
    let (a, b) = (load("a", "a-id")?, load("b", "b-id")?);
    if a == b {
        println!("PARITY-EQUAL {}", a.trim_end().replace('\n', " | "));
        Ok(())
    } else {
        println!("PARITY-DIFF\n a={a:?}\n b={b:?}");
        std::process::exit(1)
    }
}

fn summarize(path: &str) -> Result<(), String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
    let all: Vec<Sample> = text.lines().skip(1).filter_map(Sample::parse_csv).collect();
    let wall = all
        .iter()
        .map(|s| s.start_us + s.latency_us)
        .max()
        .unwrap_or(0) as f64
        / 1e6;
    println!("{}", summary_json(path, 0, wall.max(1e-9), &all, &[]));
    Ok(())
}
