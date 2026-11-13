//! The frozen request sequence. Messages are dealt round-robin to workers so
//! no two workers ever write the same message; each worker cycles through
//! its messages and flips each one's `$seen` on every visit, starting from
//! `true` (the fixture starts all unread), so every command is a real
//! change rather than a no-op. The sequence depends only on the inputs.

pub struct Worker {
    ids: Vec<i64>,
    seen: Vec<bool>,
    next: usize,
}

/// Splits `ids` across `workers` (worker `w` gets `ids[w]`, `ids[w+k]`, ...).
pub fn deal(ids: &[i64], workers: usize) -> Result<Vec<Worker>, String> {
    if workers == 0 || ids.len() < workers {
        return Err(format!(
            "need at least one message per worker ({} ids, {workers} workers)",
            ids.len()
        ));
    }
    Ok((0..workers)
        .map(|w| {
            let mine: Vec<i64> = ids.iter().copied().skip(w).step_by(workers).collect();
            Worker {
                seen: vec![false; mine.len()],
                ids: mine,
                next: 0,
            }
        })
        .collect())
}

impl Iterator for Worker {
    type Item = (i64, bool);

    fn next(&mut self) -> Option<(i64, bool)> {
        let i = self.next;
        self.next = (i + 1) % self.ids.len();
        self.seen[i] = !self.seen[i];
        Some((self.ids[i], self.seen[i]))
    }
}

/// The webmail's mark-read call (`emailActionStore` → JMAP `Email/set`).
pub fn mark_read_body(account: &str, message: i64, seen: bool) -> String {
    format!(
        r#"{{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:mail"],"methodCalls":[["Email/set",{{"accountId":"{account}","update":{{"{message}":{{"keywords":{{"$seen":{seen}}}}}}}}},"0"]]}}"#
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn workers_own_disjoint_messages_and_flip_each_visit() {
        let mut w = deal(&[1, 2, 3, 4, 5], 2).unwrap();
        let a: Vec<_> = w[0].by_ref().take(6).collect();
        assert_eq!(
            a,
            [
                (1, true),
                (3, true),
                (5, true),
                (1, false),
                (3, false),
                (5, false)
            ]
        );
        let b: Vec<_> = w[1].by_ref().take(3).collect();
        assert_eq!(b, [(2, true), (4, true), (2, false)]);
    }

    #[test]
    fn refuses_more_workers_than_messages() {
        assert!(deal(&[1], 2).is_err());
        assert!(deal(&[1], 0).is_err());
    }

    #[test]
    fn body_is_one_seen_patch() {
        assert_eq!(
            mark_read_body("16", 29, true),
            r#"{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:mail"],"methodCalls":[["Email/set",{"accountId":"16","update":{"29":{"keywords":{"$seen":true}}}},"0"]]}"#
        );
    }
}
