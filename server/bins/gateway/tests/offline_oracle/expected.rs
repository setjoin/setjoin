//! Independent branch/status expectations, confirmed by the frozen Go recorder.
pub fn status(action: &str, label: &str) -> u16 {
    if label.ends_with("-error") {
        return if matches!(action, "create" | "update") {
            400
        } else {
            500
        };
    }
    let device = matches!(action, "approve" | "deny" | "revoke" | "wipe");
    if label == "denied" {
        return 403;
    }
    if label == "foreign" && action == "preview" {
        return 403;
    }
    if label == "invalid" {
        return if matches!(action, "policies" | "enabled" | "pending" | "size") {
            200
        } else {
            400
        };
    }
    if label == "repeat" {
        return match action {
            "delete" => 404,
            "approve" | "deny" | "revoke" | "wipe" => 409,
            "create" => 201,
            _ => 200,
        };
    }
    if label.starts_with("rls") && device {
        return 409;
    }
    if matches!(label, "missing" | "zero-id" | "negative-id")
        && matches!(action, "policy" | "update" | "delete")
    {
        return 404;
    }
    if label == "missing" && device {
        return 409;
    }
    if matches!(label, "approved" | "pending") && device {
        return 409;
    }
    if label == "last-global" {
        return 409;
    }
    if label == "missing" && action == "preview" {
        return 403;
    }
    if matches!(label, "bad-scope" | "no-name" | "negative-days")
        || (label == "null" && matches!(action, "create" | "update"))
    {
        return 404;
    }
    if matches!(
        label,
        "typed"
            | "empty-body"
            | "bad-target"
            | "bad-device"
            | "fraction"
            | "partial-qos"
            | "int32-overflow"
    ) {
        return 400;
    }
    if label == "zero-id" && action == "ack" {
        return 400;
    }
    if matches!(
        label,
        "unknown-field" | "trailing" | "second-object" | "too-large"
    ) && matches!(action, "create" | "update" | "preview")
    {
        return 400;
    }
    if action == "wipe" {
        202
    } else if action == "create" {
        201
    } else {
        200
    }
}
