//! Frozen Go's reviewed command/template bytes. No command executes on the gateway.
use super::{Config, Node};
pub(super) const STAGES: [(&str, &str); 7] = [
    ("ssh_check", "SSH connectivity check"),
    (
        "install_packages",
        "Install PostgreSQL + Pgpool-II + SeaweedFS",
    ),
    ("configure_replication", "Configure streaming replication"),
    ("configure_pgpool", "Configure Pgpool-II + watchdog"),
    ("configure_seaweedfs", "Configure SeaweedFS 3-node Raft"),
    ("start_services", "Start all services"),
    ("verify", "Verify cluster health"),
];
pub(super) struct Job {
    pub node: usize,
    pub credentials: usize,
    pub command: String,
    pub prefix: String,
    pub divider: &'static str,
    pub suffix: &'static str,
    pub secrets: Vec<String>,
    pub nonfatal: bool,
}
fn job(
    node: usize,
    credentials: usize,
    command: String,
    prefix: String,
    divider: &'static str,
    suffix: &'static str,
) -> Job {
    Job {
        node,
        credentials,
        command,
        prefix,
        divider,
        suffix,
        secrets: vec![],
        nonfatal: false,
    }
}
fn quote(text: &str) -> String {
    setjoin_contracts::go_quote::quote(text.as_bytes())
}
fn failure_ordering(cmd: &str, activation: &str) -> Result<(), String> {
    let lines = cmd.split('\n').collect::<Vec<_>>();
    let (mut first, mut heredoc, mut seen, mut steps) = (true, String::new(), false, 0);
    for (i, line) in lines.iter().enumerate() {
        let trimmed = line.trim();
        if !heredoc.is_empty() {
            if trimmed == heredoc {
                heredoc.clear();
            }
            continue;
        }
        if trimmed.is_empty() {
            continue;
        }
        if first {
            if trimmed != "set -e" {
                return Err(format!("remote install command must begin with set -e so any failed step aborts; first line is {}",quote(trimmed)));
            }
            first = false;
            continue;
        }
        if let Some((_, rest)) = trimmed.split_once("<<") {
            let rest = rest.trim();
            if !rest.is_empty() {
                let delimiter = if rest.starts_with(['\'', '"']) {
                    rest[1..]
                        .find(rest.as_bytes()[0] as char)
                        .map(|end| rest[1..1 + end].to_owned())
                } else {
                    Some(rest.split([' ', '\t']).next().unwrap_or("").to_owned())
                };
                if let Some(delimiter) = delimiter {
                    heredoc = delimiter;
                    steps += 1;
                    continue;
                }
            }
        }
        if line.contains(activation) {
            if seen {
                return Err(format!(
                    "activation step {} appears more than once",
                    quote(trimmed)
                ));
            }
            seen = true;
            for rest in &lines[i + 1..] {
                if !rest.trim().is_empty() {
                    return Err(format!("executable line {} follows the activation step; a failure there could no longer abort the restart",quote(rest)));
                }
            }
            continue;
        }
        if line.contains("&&") || line.contains("||") || line.contains(';') {
            return Err(format!("pre-activation step {} must be a single simple command: AND-OR lists are exempt from set -e for non-final commands, so a failure would not abort before the restart",quote(trimmed)));
        }
        steps += 1;
    }
    if first {
        return Err("remote install command has no executable lines".into());
    }
    if !seen {
        return Err(format!(
            "remote install command never activates the service ({} absent)",
            quote(activation)
        ));
    }
    if steps == 0 {
        return Err("remote install command has no install steps before activation".into());
    }
    Ok(())
}
fn printf(template: &str, args: &[String]) -> String {
    let mut out = String::new();
    let mut rest = template;
    for arg in args {
        let p = rest.find('%').expect("frozen template argument");
        out.push_str(&rest[..p]);
        out.push_str(arg);
        rest = &rest[p + 2..];
    }
    out.push_str(rest);
    out
}
fn artifact(config: &Config) -> Result<String, String> {
    let digest = config.checksum.trim();
    if digest.is_empty() {
        return Err("no pinned sha256 checksum recorded for SeaweedFS v3.80 — refusing to install an unverified artifact (record it in seaweedfsPinnedChecksums or set DEPLOY_SEAWEEDFS_SHA256)".into());
    }
    if digest.len() != 64 {
        return Err(format!(
            "pinned sha256 checksum for SeaweedFS v3.80 is malformed (want 64 hex chars, got {})",
            digest.len()
        ));
    }
    if !digest.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("pinned sha256 checksum for SeaweedFS v3.80 is not hex".into());
    }
    let digest = digest.to_ascii_lowercase();
    Ok(format!("weedTmp=$(mktemp -d) && trap 'rm -rf \"$weedTmp\"' EXIT && curl -fsSL -o $weedTmp/linux_amd64.tar.gz https://github.com/seaweedfs/seaweedfs/releases/download/v3.80/linux_amd64.tar.gz && if command -v sha256sum >/dev/null 2>&1; then weedGot=$(sha256sum $weedTmp/linux_amd64.tar.gz | cut -d' ' -f1); else weedGot=$(shasum -a 256 $weedTmp/linux_amd64.tar.gz | cut -d' ' -f1); fi && if [ \"$weedGot\" != \"{digest}\" ]; then echo \"seaweedfs v3.80 checksum mismatch: expected {digest}, got $weedGot — refusing to install\" >&2; exit 1; fi && tar -xzf $weedTmp/linux_amd64.tar.gz -C \"$weedTmp\" weed && install -m 0755 \"$weedTmp/weed\" /usr/local/bin/weed"))
}
fn s3_config(access: &str, secret: &str) -> Result<String, String> {
    if access.trim().is_empty() || secret.trim().is_empty() {
        return Err("refusing to render the S3 identity config: access and secret keys must both be non-empty generated material".into());
    }
    #[derive(serde::Serialize)]
    struct Credential<'a> {
        #[serde(rename = "accessKey")]
        access: &'a str,
        #[serde(rename = "secretKey")]
        secret: &'a str,
    }
    #[derive(serde::Serialize)]
    struct Identity<'a> {
        name: &'a str,
        credentials: Vec<Credential<'a>>,
        actions: Vec<&'a str>,
    }
    #[derive(serde::Serialize)]
    struct Identities<'a> {
        identities: Vec<Identity<'a>>,
    }
    let text = serde_json::to_string_pretty(&Identities {
        identities: vec![Identity {
            name: "admin",
            credentials: vec![Credential { access, secret }],
            actions: vec!["Admin", "Read", "Write", "List", "Tagging"],
        }],
    })
    .unwrap()
    .replace('&', "\\u0026")
    .replace('<', "\\u003c")
    .replace('>', "\\u003e")
    .replace('\u{2028}', "\\u2028")
    .replace('\u{2029}', "\\u2029")
        + "\n";
    for marker in [
        "minioadmin",
        "changeme",
        "change-me",
        "replace_me",
        "replace-me",
        "<generated",
        "{{.",
        "{{\"",
        "your-",
        "access_key>",
        "secret_key>",
    ] {
        if text.to_lowercase().contains(marker) {
            return Err(format!("S3 identity config contains well-known/placeholder credential marker {}; identities must be generated at install time, never defaulted",quote(marker)));
        }
    }
    Ok(text)
}
pub(super) fn build(stage: usize, nodes: &[Node], config: &Config) -> Result<Vec<Job>, String> {
    let mut jobs = vec![];
    // Defence in depth behind the request-time validation: no unvalidated host reaches a command.
    if nodes.iter().any(|n| !super::valid_host(&n.host)) {
        return Err("refusing to build remote commands: a node host is not a plain hostname or IP literal".into());
    }
    let primary = nodes
        .iter()
        .enumerate()
        .filter(|(_, n)| n.role == "primary")
        .last()
        .map(|(i, _)| i);
    let standbys = nodes
        .iter()
        .enumerate()
        .filter(|(_, n)| n.role != "primary")
        .map(|(i, _)| i)
        .collect::<Vec<_>>();
    match stage {
        0 => {
            for (i, n) in nodes.iter().enumerate() {
                if n.role == "primary" && n.host == "localhost" {
                    continue;
                }
                jobs.push(job(
                    i,
                    i,
                    "echo ok && hostname".into(),
                    format!("SSH {}: ", n.host),
                    " — output: ",
                    "",
                ));
            }
        }
        1 => {
            let weed = artifact(config).map_err(|e| format!("seaweedfs artifact pin: {e}"))?;
            for (i, n) in nodes.iter().enumerate() {
                if n.role == "primary" && n.host == "localhost" {
                    continue;
                }
                jobs.push(job(
                    i,
                    i,
                    format!("apt-get update && apt-get install -y postgresql-18 pgpool2 && {weed}"),
                    format!("install {}: ", n.host),
                    "\n",
                    "",
                ));
            }
        }
        2 => {
            let primary = primary.ok_or("no primary node found")?;
            for i in standbys {
                let host = &super::sh_quote(&nodes[primary].host);
                for(j,command)in ["systemctl stop postgresql".into(),"rm -rf /var/lib/postgresql/18/main".into(),format!("pg_basebackup -h {host} -D /var/lib/postgresql/18/main -U replicator -P -X stream"),"touch /var/lib/postgresql/18/main/standby.signal".into(),format!("echo 'primary_conninfo = host={} port=5432 user=replicator' >> /var/lib/postgresql/18/main/postgresql.auto.conf",nodes[primary].host),"systemctl start postgresql".into()].into_iter().enumerate(){jobs.push(job(i,0,command,format!("replication step {j} on {}: ",nodes[i].host),"\n",""));}
            }
        }
        3 => {
            let pin = super::ssh::pinned(&config.host_key).ok_or("pgpool failover provisioning: no pinned deployment host key — refusing to write /etc/pgpool2/known_hosts from unverified input")?;
            let pin = match pin {
                russh::keys::PublicKeyOrCertificate::PublicKey { key, .. } => ssh_key::PublicKey::new(key.key_data().clone(), "").to_openssh(),
                russh::keys::PublicKeyOrCertificate::Certificate(mut certificate) => { certificate.set_comment(""); certificate.to_openssh() }
            }.map_err(|e| e.to_string())?;
            let mut known = String::new();
            let mut hosts = std::collections::BTreeSet::new();
            for n in nodes {
                let host = n.host.trim();
                if host.is_empty() {
                    return Err("pgpool failover provisioning: empty node host in deployment inventory — refusing to write /etc/pgpool2/known_hosts".into());
                }
                if hosts.insert(host) {
                    known += &format!("{host} {pin}\n");
                }
            }
            let mut random = [0; 16];
            getrandom::getrandom(&mut random).map_err(|_| "random source unavailable")?;
            let pass = random
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>();
            let pattern = regex::Regex::new(r"\{\{\.([A-Za-z0-9]+)\}\}").unwrap();
            for (i, n) in nodes.iter().enumerate() {
                let peers = nodes
                    .iter()
                    .enumerate()
                    .filter(|(j, _)| *j != i)
                    .map(|(_, n)| n.host.clone())
                    .collect::<Vec<_>>();
                let values = std::collections::BTreeMap::from([
                    ("MyHost", n.host.clone()),
                    ("Node1", nodes[0].host.clone()),
                    ("Node2", nodes[1].host.clone()),
                    ("Node3", nodes[2].host.clone()),
                    ("Peer1", peers[0].clone()),
                    ("Peer2", peers[1].clone()),
                    ("PgpoolPass", pass.clone()),
                ]);
                let conf = pattern.replace_all(
                    include_str!("assets/pgpool.conf"),
                    |m: &regex::Captures<'_>| values.get(&m[1]).cloned().unwrap_or_default(),
                );
                let failover = include_str!("assets/failover.sh");
                let command=format!("set -e\ninstall -d -o root -g root -m 0755 /etc/pgpool2\ncat > /etc/pgpool2/failover.sh << 'ENDOFFAILOVER'\n{failover}\nENDOFFAILOVER\nchown root:root /etc/pgpool2/failover.sh\nchmod 0700 /etc/pgpool2/failover.sh\ncat > /etc/pgpool2/known_hosts << 'ENDOFKNOWNHOSTS'\n{known}ENDOFKNOWNHOSTS\nchown root:root /etc/pgpool2/known_hosts\nchmod 0644 /etc/pgpool2/known_hosts\ncat > /etc/pgpool2/pgpool.conf << 'ENDOFCONFIG'\n{conf}\nENDOFCONFIG\nchown root:postgres /etc/pgpool2/pgpool.conf\nchmod 0640 /etc/pgpool2/pgpool.conf\nsystemctl restart pgpool2 2>/dev/null || systemctl restart pgpool 2>/dev/null");
                failure_ordering(&command, "systemctl restart pgpool2").map_err(|e| {
                    format!(
                        "pgpool install command failure-ordering gate for {}: {e}",
                        n.host
                    )
                })?;
                let mut task = job(
                    i,
                    i,
                    command,
                    format!("pgpool config upload to {}: ", n.host),
                    " (output: ",
                    ")",
                );
                task.secrets.push(pass.clone());
                jobs.push(task);
            }
        }
        4 => {
            let (access, secret) = (config.credentials)();
            if access.is_empty() || secret.is_empty() {
                return Err("seaweedfs s3 identity (no node contacted): the gateway has no S3 client credentials configured (S3_ACCESS_KEY/S3_SECRET_KEY in its config.env, or s3.access_key/s3.secret_key in its SETJOIN_CONFIG YAML) — refusing to deploy a node-only identity no consumer shares; configure the gateway's S3 credentials first, then re-run the deployment".into());
            }
            let body = s3_config(&access, &secret)
                .map_err(|e| format!("seaweedfs s3 identity (no node contacted): {e}"))?;
            let peers = nodes
                .iter()
                .map(|n| format!("{}:9333", n.host))
                .collect::<Vec<_>>()
                .join(",");
            for (i, n) in nodes.iter().enumerate() {
                let unit = printf(
                    include_str!("assets/seaweedfs.service"),
                    &[
                        "/data/seaweedfs".into(),
                        format!("  -master.peers={peers} \\\n"),
                        "9000".into(),
                        "100".into(),
                        format!("rack1-{}", n.host),
                    ],
                );
                let body = body.trim_end_matches('\n');
                let command=format!("set -e\ninstall -d -o root -g mail -m 0750 /etc/mail\ncat > /etc/mail/seaweedfs-s3.json << 'ENDOFS3CONFIG'\n{body}\nENDOFS3CONFIG\nchown root:mail /etc/mail/seaweedfs-s3.json\nchmod 0640 /etc/mail/seaweedfs-s3.json\ncat > /etc/systemd/system/seaweedfs.service << 'ENDOFUNIT'\n{unit}\nENDOFUNIT\nsystemctl daemon-reload\nsystemctl enable seaweedfs\nsystemctl restart seaweedfs");
                failure_ordering(&command, "systemctl restart seaweedfs").map_err(|e| {
                    format!(
                        "seaweedfs install command failure-ordering gate (no node contacted): {e}"
                    )
                })?;
                let mut task = job(
                    i,
                    i,
                    command,
                    format!("seaweedfs config upload to {}: ", n.host),
                    " (output: ",
                    ")",
                );
                task.secrets = vec![access.clone(), secret.clone()];
                jobs.push(task);
            }
            let master = &nodes[0].host;
            for command in [
                format!(
                    "weed shell {} volume.configure.replication 001",
                    super::sh_quote(&format!("-master={master}:9333"))
                ),
                format!(
                    "weed shell {} volume.balance",
                    super::sh_quote(&format!("-master={master}:9333"))
                ),
                format!(
                    "curl -s {}",
                    super::sh_quote(&format!("http://{master}:9333/cluster/status"))
                ),
            ] {
                let mut task = job(0, 0, command, String::new(), "", "");
                task.nonfatal = true;
                jobs.push(task);
            }
        }
        5 => {
            for (i, n) in nodes.iter().enumerate() {
                if n.role == "primary" && n.host == "localhost" {
                    continue;
                }
                jobs.push(job(i,i,"systemctl start postgresql && systemctl start pgpool2 && systemctl start seaweedfs-master".into(),format!("start services on {}: ",n.host),"\n",""));
            }
        }
        6 => {
            if primary.is_none() && standbys.is_empty() {
                return Err("no nodes to verify".into());
            }
            if let Some(i) = primary {
                jobs.push(job(i,0,"psql -U mail -d mailserver -c \"SELECT usename, application_name, state, sync_state, sync_priority FROM pg_stat_replication;\"".into(),format!("verify replication on primary {}: ",nodes[i].host),"\n",""));
            }
            for i in standbys {
                jobs.push(job(
                    i,
                    0,
                    "psql -U mail -d mailserver -c \"SELECT pg_is_in_recovery();\"".into(),
                    format!("verify recovery on standby {}: ", nodes[i].host),
                    "\n",
                    "",
                ));
            }
        }
        _ => unreachable!(),
    }
    Ok(jobs)
}
