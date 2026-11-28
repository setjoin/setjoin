//! #371 Calendar/delegateList (frozen Go calendar_a3.go:178-230; worker statement table).

use std::collections::BTreeMap;

use serde_json::Value;

use super::args::{self, Kind};
use super::seam::{self, WorkerRead};
use super::{always, Answer, Cx, Gate, Method, MethodError, Reply};

const CAPABILITY: &str = "urn:ietf:params:jmap:calendars";
const APP: &str = "calendar";

pub(super) const METHODS: &[Method] = &[Method {
    name: "Calendar/delegateList",
    capability: CAPABILITY,
    app: APP,
    gate: Gate::Personal,
    account: true,
    mutator: false,
    state: false,
    ready: always,
    run: delegate_list,
}];

fn delegate_list<'a>(cx: &'a Cx<'a>) -> Reply<'a> {
    Box::pin(async {
        const FIELDS: &[(&str, Kind)] = &[("accountId", Kind::Str)];
        let args = args::decode(cx.args(), "", FIELDS)?;
        let scope = seam::resolve(cx, args.str("accountId")).await?;
        let raw = seam::worker_read(cx, WorkerRead::CalendarDelegates).await?;
        let rows: Vec<BTreeMap<String, Value>> =
            serde_json::from_str(&raw).map_err(|_| MethodError::server_fail())?;
        let list = serde_json::to_value(rows).map_err(|_| MethodError::server_fail())?;
        Ok(Answer {
            name: "Calendar/delegateList",
            args: super::go_map(vec![
                ("accountId", Value::String(scope.id().to_string())),
                ("list", list),
            ]),
        })
    })
}
