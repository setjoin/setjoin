//! DMARC policy discovery, alignment, deterministic sampling and best-effort
//! report accounting. Owner-approved security fixes 2026-11-05 (#492, #493):
//! the organizational domain comes from the public-suffix list (frozen Go used the
//! last two labels, so `a.example.co.uk` aligned with every `*.co.uk`), omitted
//! `adkim`/`aspf` are relaxed (RFC 7489 §6.3; Go defaulted to strict), the
//! subdomain policy `sp=` governs a subdomain whose policy was found at the
//! organizational domain, and several DMARC records at one name are not
//! concatenated: RFC 7489 §6.6.3 says discovery then ends without a policy.
use super::{DkimVerification, Dns, DnsError, DnsType};
use mail_auth::{
    common::parse::TxtRecordParser,
    dmarc::{Alignment, Dmarc, Policy},
};
use setjoin_pg::{workers::WorkerDatabase, Type};
use sha2::{Digest, Sha256};

struct Record {
    policy: Policy,
    pct: i64,
    adkim: Alignment,
    aspf: Alignment,
    rua: String,
    temporary: bool,
}
impl Default for Record {
    fn default() -> Self {
        Self {
            policy: Policy::None,
            pct: 100,
            adkim: Alignment::Relaxed,
            aspf: Alignment::Relaxed,
            rua: String::new(),
            temporary: false,
        }
    }
}
pub(crate) struct Outcome {
    pub result: &'static str,
    pub quarantine: bool,
    pub reject: bool,
}
impl Default for Outcome {
    fn default() -> Self {
        Self {
            result: "none",
            quarantine: false,
            reject: false,
        }
    }
}
/// Organizational (registrable) domain by the public-suffix list. A name that is
/// itself a public suffix has no registrable parent and stands for itself.
fn org(domain: &str) -> &str {
    if crate::mutants::on("dmarc-org-last-two-labels") {
        // Frozen Go: the last two labels, ignoring the public-suffix list.
        return domain
            .match_indices('.')
            .rev()
            .nth(1)
            .map_or(domain, |(i, _)| &domain[i + 1..]);
    }
    psl::domain_str(domain.trim_end_matches('.')).unwrap_or(domain)
}
fn aligned(child: &str, parent: &str, mode: &Alignment) -> bool {
    let (child, parent) = (child.to_lowercase(), parent.to_lowercase());
    let strict = if crate::mutants::on("dmarc-default-strict") {
        // Frozen Go treated an omitted tag as strict; only the parsed tag differs.
        true
    } else {
        *mode == Alignment::Strict
    };
    if strict {
        child == parent
    } else {
        org(&child) == org(&parent)
    }
}
fn raw_rua(value: &str) -> String {
    value
        .split(';')
        .filter_map(|part| part.trim().split_once('='))
        .find(|(k, _)| k.trim() == "rua")
        .map_or_else(String::new, |(_, v)| v.trim().to_owned())
}
async fn lookup(dns: &dyn Dns, domain: &str) -> Option<Record> {
    let domain = domain.strip_suffix('.').unwrap_or(domain);
    let organization = org(domain);
    let mut domains = vec![domain];
    if domain != organization && !organization.is_empty() {
        domains.push(organization)
    }
    for candidate in domains {
        if candidate.is_empty() {
            continue;
        }
        let txt = match dns
            .lookup(DnsType::Txt, &format!("_dmarc.{candidate}"))
            .await
        {
            Ok(txt) => txt,
            Err(DnsError::NotFound) => continue,
            Err(_) => {
                return Some(Record {
                    temporary: true,
                    ..Default::default()
                })
            }
        };
        let mut candidates = txt.iter().filter(|v| v.starts_with("v=DMARC1"));
        let value = if crate::mutants::on("dmarc-concatenate-records") {
            // Frozen Go joined every v=DMARC1 string into one record.
            candidates.map(String::as_str).collect::<String>()
        } else {
            match (candidates.next(), candidates.next()) {
                (Some(only), None) => only.clone(),
                // Several records (or none): policy discovery ends here.
                (Some(_), Some(_)) => return None,
                _ => continue,
            }
        };
        if value.trim().is_empty() {
            continue;
        }
        let Ok(parsed) = Dmarc::parse(value.trim().as_bytes()) else {
            continue;
        };
        let subdomain = candidate != domain;
        let mut policy = if subdomain && parsed.sp != Policy::Unspecified {
            parsed.sp
        } else {
            parsed.p
        };
        if crate::mutants::on("dmarc-ignore-subdomain-policy") {
            policy = parsed.p;
        }
        return Some(Record {
            policy: if policy == Policy::Unspecified {
                Policy::None
            } else {
                policy
            },
            pct: i64::from(parsed.pct),
            adkim: parsed.adkim,
            aspf: parsed.aspf,
            rua: raw_rua(value.trim()),
            temporary: false,
        });
    }
    None
}
pub(crate) async fn check(
    dns: &dyn Dns,
    db: &WorkerDatabase,
    from_domain: &str,
    message_id: &str,
    spf: &str,
    spf_domain: &str,
    dkim: &DkimVerification,
) -> Outcome {
    // Preserve Go's ordering: TrimPrefix before lower-casing, and do not strip
    // the trailing dot from the domain passed to alignment or sampling.
    let domain = from_domain
        .strip_prefix('@')
        .unwrap_or(from_domain)
        .to_lowercase();
    if domain.is_empty() {
        return Outcome::default();
    }
    let Some(rec) = lookup(dns, &domain).await else {
        return Outcome::default();
    };
    let result = if rec.temporary {
        "temperror"
    } else if (spf == "pass" && aligned(spf_domain, &domain, &rec.aspf))
        || (dkim.result == "pass"
            && dkim
                .domains
                .iter()
                .any(|signed| aligned(signed, &domain, &rec.adkim)))
    {
        "pass"
    } else {
        if rec.pct < 100 && !message_id.is_empty() {
            let digest = Sha256::digest(format!("{domain}{message_id}").as_bytes());
            if i64::from(digest[0] % 100) >= rec.pct {
                return Outcome::default();
            }
        }
        "fail"
    };
    report(db, from_domain, result, &rec).await;
    Outcome {
        result,
        quarantine: result == "fail" && rec.policy == Policy::Quarantine,
        reject: result == "fail" && rec.policy == Policy::Reject,
    }
}
async fn report(db: &WorkerDatabase, domain: &str, result: &str, rec: &Record) {
    if rec.rua.is_empty() {
        return;
    }
    let Ok(conn) = db.connect_session().await else {
        return;
    };
    let counts: [i32; 5] = [
        i32::from(result == "none"),
        i32::from(result == "pass"),
        i32::from(result == "fail"),
        i32::from(result == "temperror"),
        i32::from(result == "permerror"),
    ];
    // Go performs this independent, one-statement write before delivery. It is
    // intentionally not rolled back when policy rejects or storage later fails.
    let now = chrono::Utc::now();
    let start = now.date_naive().and_hms_opt(0, 0, 0).unwrap().and_utc();
    let end = start + chrono::Duration::days(1);
    let _=conn.query("INSERT INTO dmarc_reports (domain,report_uri,begin_time,end_time,total_count,count_none,count_pass,count_fail,count_temperror,count_permperror,policy_domain,policy_pct) VALUES ($1,$2,$3::text::timestamptz,$4::text::timestamptz,1,$5,$6,$7,$8,$9,$10,$11::bigint) ON CONFLICT (domain,begin_time,end_time) DO UPDATE SET total_count=dmarc_reports.total_count+1,count_none=dmarc_reports.count_none+EXCLUDED.count_none,count_pass=dmarc_reports.count_pass+EXCLUDED.count_pass,count_fail=dmarc_reports.count_fail+EXCLUDED.count_fail,count_temperror=dmarc_reports.count_temperror+EXCLUDED.count_temperror,count_permperror=dmarc_reports.count_permperror+EXCLUDED.count_permperror",&[(&domain,Type::TEXT),(&rec.rua,Type::TEXT),(&start.to_rfc3339(),Type::TEXT),(&end.to_rfc3339(),Type::TEXT),(&counts[0],Type::INT4),(&counts[1],Type::INT4),(&counts[2],Type::INT4),(&counts[3],Type::INT4),(&counts[4],Type::INT4),(&domain,Type::TEXT),(&rec.pct,Type::INT8)]).await;
}

pub(super) fn relaxed_aligned(child:&str,parent:&str)->bool {aligned(child,parent,&Alignment::Relaxed)}
