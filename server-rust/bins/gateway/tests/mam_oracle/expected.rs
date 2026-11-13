//! Independent status floor checked against frozen Go before recording.
pub fn status(action: &str, label: &str) -> u16 {
    if matches!(label, "scope-error" | "evidence-scope-error") {
        return if action == "events" { 200 } else { 404 };
    }
    if label.ends_with("error") {
        return 500;
    }
    if matches!(label, "denied" | "wrong-perm") {
        return 403;
    }
    if label == "invalid" {
        return if matches!(action, "policies" | "devices") {
            200
        } else {
            400
        };
    }
    if label == "foreign"
        && matches!(
            action,
            "events" | "lock" | "unlock" | "device-set" | "device-delete"
        )
    {
        return 404;
    }
    if label == "repeat" && matches!(action, "group-delete" | "device-delete") {
        return 404;
    }
    if matches!(label, "registry-only" | "no-fingerprint") {
        return if action == "events" { 200 } else { 404 };
    }
    if label == "missing"
        || label == "missing-key"
        || (label == "bad-type" && action == "group-delete")
    {
        return 404;
    }
    if matches!(label, "zero-id" | "negative-id") && action != "group" {
        return 404;
    }
    if matches!(
        label,
        "typed-map" | "typed-value" | "typed-id" | "no-type" | "bad-type" | "bad-json"
    ) || (action == "group" && label == "null")
    {
        return 400;
    }
    200
}
