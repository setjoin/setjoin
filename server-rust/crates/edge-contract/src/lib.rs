//! Edge-only plain `serde` DTOs generated from `contracts/edge/openapi/edge.v1.yaml` (#561).
//!
//! Zero OpenAPI proc-macro dependencies (`utoipa`, `aide`, `schemars`, etc.) live
//! here or in any domain/pg/contracts crate. Re-run `npm run build` inside
//! `contracts/edge/` after editing TypeSpec sources.

#![forbid(unsafe_code)]

pub mod generated;

pub use generated::*;

#[cfg(test)]
mod tests {
    use super::generated::*;
    use std::collections::BTreeMap;

    #[test]
    fn openapi_version_is_3_1_0_and_operations_non_empty() {
        assert_eq!(OPENAPI_VERSION, "3.1.0");
        assert!(CONTRACTED_OPERATIONS.contains(&("GET", "/health")));
        assert!(CONTRACTED_OPERATIONS.contains(&("GET", "/healthz")));
        assert!(CONTRACTED_OPERATIONS.contains(&("GET", "/_gateway/healthz")));
        assert!(CONTRACTED_OPERATIONS.contains(&("GET", "/ready")));
        assert!(CONTRACTED_OPERATIONS.contains(&("GET", "/api/settings/rules-list")));
        assert!(CONTRACTED_OPERATIONS.contains(&("POST", "/api/settings/rules")));
        assert!(CONTRACTED_OPERATIONS.contains(&("PUT", "/api/settings/rules/{id}")));
        assert!(CONTRACTED_OPERATIONS.contains(&("DELETE", "/api/settings/rules/{id}")));
        assert!(CONTRACTED_OPERATIONS.contains(&("POST", "/api/settings/rules/{id}/apply")));
        assert!(CONTRACTED_OPERATIONS.contains(&("GET", "/api/settings/rules/apply/{actionId}")));
        assert!(CONTRACTED_OPERATIONS.contains(&("GET", "/api/messages/{emailId}/trace")));
        assert!(CONTRACTED_OPERATIONS.contains(&("GET", "/api/offline/size-estimate")));
        assert!(CONTRACTED_OPERATIONS.contains(&("GET", "/api/user/quota")));
        assert!(CONTRACTED_OPERATIONS.contains(&("GET", "/api/settings/view")));
        assert!(CONTRACTED_OPERATIONS.contains(&("PUT", "/api/settings/view")));
    }

    #[test]
    fn ready_status_enforces_exact_ok_literal() -> Result<(), serde_json::Error> {
        let ok: ReadyStatus = serde_json::from_str(r#"{"status":"ok"}"#)?;
        assert_eq!(ok.status, ReadyVerdict::Ok);
        assert_eq!(serde_json::to_string(&ok)?, r#"{"status":"ok"}"#);
        let invalid = serde_json::from_str::<ReadyStatus>(r#"{"status":"degraded"}"#);
        assert!(invalid.is_err(), "ReadyStatus must reject non-'ok' values");
        Ok(())
    }

    #[test]
    fn problem_details_round_trips() -> Result<(), serde_json::Error> {
        let raw = r#"{"type":"https://setjoin.com/errors/not-found","title":"Not Found","status":404,"detail":"rule not found","code":"BZ121","instance":"/settings/rules/42"}"#;
        let parsed: ProblemDetails = serde_json::from_str(raw)?;
        assert_eq!(parsed.status, 404);
        assert_eq!(parsed.code.as_deref(), Some("BZ121"));
        assert_eq!(parsed.detail.as_deref(), Some("rule not found"));
        let reencoded = serde_json::to_string(&parsed)?;
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(raw)?,
            serde_json::from_str::<serde_json::Value>(&reencoded)?
        );
        Ok(())
    }

    #[test]
    fn user_rule_and_optional_nullable_update_round_trip() -> Result<(), serde_json::Error> {
        let mut params = BTreeMap::new();
        params.insert("folder".to_owned(), "Archive".to_owned());
        let input = RuleInput {
            name: "Archive newsletters".to_owned(),
            enabled: true,
            priority: 10,
            run_on: RunOn::Server,
            conditions: Some(vec![RuleCondition {
                field: "subject".to_owned(),
                op: "contains".to_owned(),
                value: "newsletter".to_owned(),
            }]),
            actions: Some(vec![RuleAction {
                r#type: "move_to".to_owned(),
                params: Some(params),
            }]),
            stop_processing: true,
        };
        let encoded = serde_json::to_string(&input)?;
        assert!(encoded.contains(r#""runOn":"server""#));
        assert!(encoded.contains(r#""stopProcessing":true"#));
        let decoded: RuleInput = serde_json::from_str(&encoded)?;
        assert_eq!(input, decoded);

        // Optional nullable `RuleUpdateInput`: omitted vs explicit null vs value.
        let omitted: RuleUpdateInput = serde_json::from_str(r#"{"enabled":false}"#)?;
        assert_eq!(omitted.enabled, Some(false));
        assert_eq!(omitted.conditions, None);
        assert_eq!(omitted.actions, None);
        assert_eq!(serde_json::to_string(&omitted)?, r#"{"enabled":false}"#);

        let cleared: RuleUpdateInput =
            serde_json::from_str(r#"{"enabled":true,"conditions":null}"#)?;
        assert_eq!(cleared.conditions, Some(None));
        assert_eq!(cleared.actions, None);
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&serde_json::to_string(&cleared)?)?,
            serde_json::json!({"enabled": true, "conditions": null})
        );

        let with_conds: RuleUpdateInput = serde_json::from_str(
            r#"{"conditions":[{"field":"subject","op":"contains","value":"hi"}]}"#,
        )?;
        assert_eq!(
            with_conds
                .conditions
                .as_ref()
                .and_then(|o| o.as_ref())
                .map(Vec::len),
            Some(1)
        );
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&serde_json::to_string(&with_conds)?)?,
            serde_json::json!({"conditions": [{"field": "subject", "op": "contains", "value": "hi"}]})
        );

        let empty_window: ApplyRetroRequest = serde_json::from_str(r#"{"window":""}"#)?;
        assert_eq!(empty_window.window, Some(RetroWindowInput::Empty));
        let omitted_window: ApplyRetroRequest = serde_json::from_str(r#"{}"#)?;
        assert_eq!(omitted_window.window, None);
        Ok(())
    }

    #[test]
    fn required_nullable_fields_preserve_null_and_reject_omission() -> Result<(), serde_json::Error>
    {
        let inbound_raw = r#"{"direction":"inbound","hopCount":0,"totalTransitMs":null,"slowestHopIndex":null,"hops":[]}"#;
        let parsed: MessageTrace = serde_json::from_str(inbound_raw)?;
        match &parsed {
            MessageTrace::InboundDeliveryTrace(t) => {
                assert_eq!(t.direction, InboundDirection::Inbound);
                assert_eq!(t.total_transit_ms, None);
                assert_eq!(t.slowest_hop_index, None);
            }
            other => panic!("expected InboundDeliveryTrace, got {other:?}"),
        }
        let reencoded = serde_json::to_string(&parsed)?;
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(inbound_raw)?,
            serde_json::from_str::<serde_json::Value>(&reencoded)?,
            "required nullable fields must serialize explicit null on round-trip"
        );

        // Omitting required nullable fields MUST fail deserialization (deserialize_required_nullable).
        let missing_required_nullable = r#"{"direction":"inbound","hopCount":0,"hops":[]}"#;
        assert!(
            serde_json::from_str::<InboundDeliveryTrace>(missing_required_nullable).is_err(),
            "omitting required nullable totalTransitMs/slowestHopIndex must fail"
        );
        Ok(())
    }

    #[test]
    fn offline_and_outbound_delivery_dtos_round_trip() -> Result<(), serde_json::Error> {
        let est_json = r#"{"buckets":[{"window":"30d","messageCount":12,"bodyBytes":4096},{"window":"all","messageCount":20,"bodyBytes":8192}]}"#;
        let est: OfflineSizeEstimate = serde_json::from_str(est_json)?;
        assert_eq!(est.buckets.len(), 2);
        assert_eq!(est.buckets[0].window, OfflineWindow::V30d);
        assert_eq!(est.buckets[1].window, OfflineWindow::All);

        let prefs_json = r#"{"defaultView":null,"offlineWindow":"90d","customFlag":true}"#;
        let prefs: ViewPreferences = serde_json::from_str(prefs_json)?;
        assert_eq!(prefs.default_view, Some(None));
        assert_eq!(prefs.offline_window, Some(Some("90d".to_owned())));
        assert_eq!(
            prefs.extra.get("customFlag"),
            Some(&serde_json::json!(true))
        );
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(prefs_json)?,
            serde_json::from_str::<serde_json::Value>(&serde_json::to_string(&prefs)?)?
        );

        let trace_json = r#"{"direction":"outbound","auth":{},"raw":{"url":"/jmap/download/1/abc/msg.eml","sizeBytes":0},"overallStatus":"delivered","recipients":[{"email":"alice@example.test","status":"delivered","mxHost":"mx.example.test","deliveredAt":"2026-11-27T00:00:00Z","nextAttemptAt":null,"lastSmtpCode":250,"lastSmtpText":"OK","attempts":[{"n":1,"at":"2026-11-27T00:00:00Z","mxHost":"mx.example.test","smtpCode":250,"smtpText":"OK","outcome":"delivered","tls":true}]}]}"#;
        let trace: MessageTrace = serde_json::from_str(trace_json)?;
        match &trace {
            MessageTrace::OutboundDeliveryTrace(t) => {
                assert_eq!(t.direction, OutboundDirection::Outbound);
                assert_eq!(t.recipients.len(), 1);
            }
            other => panic!("expected OutboundDeliveryTrace, got {other:?}"),
        }
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(trace_json)?,
            serde_json::from_str::<serde_json::Value>(&serde_json::to_string(&trace)?)?
        );
        Ok(())
    }
}
