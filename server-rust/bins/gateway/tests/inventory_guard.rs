//! The inventory completeness check is an operator-facing CLI, run by the Rust lane.
#[test]
fn inventory_check_rejects_missing_go_routes() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..");
    for args in [vec![], vec!["--self-test"]] {
        let output = std::process::Command::new("python3")
            .arg(root.join("scripts/check-gofree-route-inventory.py"))
            .args(args)
            .output()
            .expect("python3 is required for the route inventory check");
        assert!(
            output.status.success(),
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[test]
fn chat_slice_ownership_is_exhaustive_and_disjoint() {
    use std::collections::BTreeSet;
    let inventory: serde_json::Value =
        serde_json::from_str(include_str!("../route-inventory.json")).unwrap();
    let mut keys = BTreeSet::new();
    let mut golden = BTreeSet::new();
    let mut counts = [0; 3];
    for route in inventory["routes"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|r| r["family"] == "F12")
    {
        let slice = match route["slice"].as_str().unwrap() {
            "golden-routes" => 0,
            "sub-router-a" => 1,
            "sub-router-b" => 2,
            unknown => panic!("unassigned F12 slice: {unknown}"),
        };
        counts[slice] += 1;
        let key = (
            route["method"].as_str().unwrap(),
            route["path"].as_str().unwrap(),
        );
        assert!(keys.insert(key), "duplicate F12 registration");
        if slice == 0 {
            golden.insert(key);
        }
    }
    assert_eq!(counts, [6, 27, 18]);
    assert_eq!(
        golden,
        BTreeSet::from([
            ("GET", "/admin/chat-channels"),
            ("GET", "/admin/chat-channels/{id}/audit"),
            ("GET", "/admin/chat-channels/{id}/audit/verify"),
            ("POST", "/admin/chat-channels/{id}/hold"),
            ("POST", "/admin/chat-channels/{id}/classification"),
            ("PUT", "/admin/chat-channels/{id}/retention"),
        ])
    );
}

#[test]
fn drive_slice_ownership_is_exhaustive_and_disjoint() {
    use std::collections::BTreeSet;
    let inventory: serde_json::Value =
        serde_json::from_str(include_str!("../route-inventory.json")).unwrap();
    let mut keys = BTreeSet::new();
    let mut golden = BTreeSet::new();
    let mut counts = [0; 4];
    for route in inventory["routes"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|r| r["family"] == "F14")
    {
        let slice = match route["slice"].as_str().unwrap() {
            "golden-routes" => 0,
            "sub-router-a" => 1,
            "sub-router-b" => 2,
            "sharing-watch" => 3,
            unknown => panic!("unassigned F14 slice: {unknown}"),
        };
        counts[slice] += 1;
        let key = (
            route["method"].as_str().unwrap(),
            route["path"].as_str().unwrap(),
        );
        assert!(keys.insert(key), "duplicate F14 registration");
        if slice == 0 {
            golden.insert(key);
        }
    }
    assert_eq!(counts, [10, 19, 29, 21]);
    assert_eq!(
        golden,
        BTreeSet::from([
            ("GET", "/me/sharing"),
            ("POST", "/me/sharing/delegates"),
            ("DELETE", "/me/sharing/delegates/{userId}"),
            ("PUT", "/me/sharing/default"),
            ("DELETE", "/me/sharing/default/{id}"),
            ("GET", "/admin/sharing/defaults"),
            ("POST", "/admin/sharing/defaults"),
            ("DELETE", "/admin/sharing/defaults/{id}"),
            ("GET", "/admin/sharing/users/{id}"),
            ("GET", "/admin/sharing/audit"),
        ])
    );
}

#[test]
fn admin_identity_slice_ownership_is_exhaustive_and_disjoint() {
    use std::collections::BTreeSet;
    let inventory: serde_json::Value =
        serde_json::from_str(include_str!("../route-inventory.json")).unwrap();
    let mut keys = BTreeSet::new();
    let mut users = BTreeSet::new();
    let mut roles = BTreeSet::new();
    let mut scope_sets = BTreeSet::new();
    let mut access_reviews = BTreeSet::new();
    let mut sod = BTreeSet::new();
    let mut lifecycle = BTreeSet::new();
    let mut idv2 = BTreeSet::new();
    let mut counts = [0; 11];
    for route in inventory["routes"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|r| r["family"] == "F01")
    {
        let slice = match route["slice"].as_str().unwrap() {
            "users" => 0,
            "roles" => 1,
            "scope-sets" => 2,
            "access-reviews" => 3,
            "sod" => 4,
            "rest" => 5,
            "user-lifecycle" => 6,
            "idv2-sources" => 7,
            "idv2-upgrade" => 8,
            "org-policies" => 9,
            "idv2-transitions" => 10,
            unknown => panic!("unassigned F01 slice: {unknown}"),
        };
        counts[slice] += 1;
        let key = (
            route["method"].as_str().unwrap(),
            route["path"].as_str().unwrap(),
        );
        assert!(keys.insert(key), "duplicate F01 registration");
        assert_eq!(route["state"] == "ON", slice <= 4 || slice >= 6, "{key:?}");
        if slice == 7 {
            idv2.insert(key);
        }
        if slice == 0 {
            users.insert(key);
        }
        if slice == 1 {
            roles.insert(key);
        }
        if slice == 2 {
            scope_sets.insert(key);
        }
        if slice == 3 {
            access_reviews.insert(key);
        }
        if slice == 4 {
            sod.insert(key);
        }
        if slice == 6 {
            lifecycle.insert(key);
        }
    }
    assert_eq!(counts, [11, 11, 7, 6, 5, 0, 8, 26, 12, 16, 14]);
    assert_eq!(idv2.len(), 26, "slice idv2-sources owns exactly the identity v2 sources, jobs, conflicts, people, inventory, events and group-mapping routes");
    assert_eq!(
        users,
        BTreeSet::from([
            ("GET", "/admin/users"),
            ("GET", "/admin/users/{id}"),
            ("GET", "/admin/users/{id}/aliases"),
            ("POST", "/admin/users/{id}/aliases"),
            ("DELETE", "/admin/users/{id}/aliases/{aliasId}"),
            ("GET", "/admin/users/{id}/quota"),
            ("PUT", "/admin/users/{id}/quota"),
            ("GET", "/admin/users/{id}/app-passwords"),
            ("GET", "/admin/users/{id}/app-access"),
            ("PUT", "/admin/users/{id}/app-access/{app}"),
            ("GET", "/admin/users/{id}/sessions"),
        ])
    );
    assert_eq!(
        roles,
        BTreeSet::from([
            ("GET", "/admin/roles"),
            ("POST", "/admin/roles"),
            ("GET", "/admin/roles/{id}"),
            ("PUT", "/admin/roles/{id}"),
            ("DELETE", "/admin/roles/{id}"),
            ("POST", "/admin/roles/{id}/members"),
            ("DELETE", "/admin/roles/{id}/members/{userId}"),
            ("POST", "/admin/roles/{id}/members:bulk"),
            ("DELETE", "/admin/roles/{id}/members:bulk"),
            ("GET", "/admin/users/{id}/effective-permissions"),
            ("GET", "/admin/permissions"),
        ])
    );
    assert_eq!(
        scope_sets,
        BTreeSet::from([
            ("GET", "/admin/scope-sets"),
            ("POST", "/admin/scope-sets"),
            ("GET", "/admin/scope-sets/{id}"),
            ("PUT", "/admin/scope-sets/{id}"),
            ("DELETE", "/admin/scope-sets/{id}"),
            ("POST", "/admin/scope-sets/{id}/members"),
            (
                "DELETE",
                "/admin/scope-sets/{id}/members/{memberType}/{memberId}"
            ),
        ])
    );
    assert_eq!(
        access_reviews,
        BTreeSet::from([
            ("GET", "/admin/access-reviews"),
            ("POST", "/admin/access-reviews"),
            ("GET", "/admin/access-reviews/{id}"),
            ("PUT", "/admin/access-reviews/{id}/items/{itemId}"),
            ("PUT", "/admin/access-reviews/{id}/items"),
            ("POST", "/admin/access-reviews/{id}/close"),
        ])
    );
    assert_eq!(
        sod,
        BTreeSet::from([
            ("GET", "/admin/me/roles"),
            ("POST", "/admin/me/roles/{id}/activate"),
            ("POST", "/admin/me/roles/{id}/deactivate"),
            ("GET", "/admin/roles/{id}/activation-policy"),
            ("PUT", "/admin/roles/{id}/activation-policy"),
        ])
    );
    assert_eq!(
        lifecycle,
        BTreeSet::from([
            ("POST", "/admin/users"),
            ("POST", "/admin/users/import"),
            ("PUT", "/admin/users/{id}"),
            ("DELETE", "/admin/users/{id}"),
            ("PUT", "/admin/users/{id}/password"),
            ("POST", "/admin/users/{id}/secure-account"),
            ("GET", "/admin/users/{id}/sign-ins"),
            ("DELETE", "/admin/users/{userId}/app-passwords/{apId}"),
        ])
    );
}

#[test]
fn directory_sync_slice_ownership_is_exhaustive_and_disjoint() {
    use std::collections::BTreeSet;
    let inventory: serde_json::Value =
        serde_json::from_str(include_str!("../route-inventory.json")).unwrap();
    let mut keys = BTreeSet::new();
    let mut ad_admin = BTreeSet::new();
    let mut ldap_ad_on = BTreeSet::new();
    let mut counts = [0; 4];
    for route in inventory["routes"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|r| r["family"] == "F02")
    {
        let slice = match route["slice"].as_str().unwrap() {
            "ad-admin" => 0,
            "ad-runtime" => 1,
            "ldap-runtime" => 2,
            "scim" => 3,
            unknown => panic!("unassigned F02 slice: {unknown}"),
        };
        counts[slice] += 1;
        let key = (
            route["method"].as_str().unwrap(),
            route["path"].as_str().unwrap(),
        );
        assert!(keys.insert(key), "duplicate F02 registration");
        // The LDAP runtime (#380) and the AD runtime (#381) moved routes and workers
        // together: every F02 route is native.
        assert_eq!(route["state"], "ON", "{key:?}");
        if slice == 0 {
            ad_admin.insert(key);
        }
        if slice == 2 {
            ldap_ad_on.insert(key);
        }
    }
    assert_eq!(counts, [8, 4, 7, 12]);
    assert_eq!(ldap_ad_on.len(), 7);
    assert_eq!(
        ad_admin,
        BTreeSet::from([
            ("GET", "/admin/ad/config"),
            ("GET", "/admin/ad/sync-log"),
            ("GET", "/admin/ad/conflicts"),
            ("POST", "/admin/ad/conflicts/{id}/resolve"),
            ("POST", "/admin/ad/conflicts/resolve-all"),
            ("GET", "/admin/ad/field-policy"),
            ("PUT", "/admin/ad/field-policy"),
            ("POST", "/admin/ad/principal"),
        ])
    );
}

#[test]
fn meet_slice_ownership_is_exhaustive_and_disjoint() {
    use std::collections::BTreeSet;
    let inventory: serde_json::Value =
        serde_json::from_str(include_str!("../route-inventory.json")).unwrap();
    let mut keys = BTreeSet::new();
    let mut golden = BTreeSet::new();
    let mut counts = [0; 4];
    for route in inventory["routes"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|r| r["family"] == "F13")
    {
        let slice = match route["slice"].as_str().unwrap() {
            "golden-routes" => 0,
            "sub-router-a" => 1,
            "sub-router-b" => 2,
            "sub-router-c" => 3,
            unknown => panic!("unassigned F13 slice: {unknown}"),
        };
        counts[slice] += 1;
        let key = (
            route["listener"].as_str().unwrap(),
            route["method"].as_str().unwrap(),
            route["path"].as_str().unwrap(),
        );
        assert!(keys.insert(key), "duplicate F13 registration");
        if slice == 0 {
            golden.insert((key.1, key.2));
        }
    }
    assert_eq!(counts, [7, 12, 17, 15]);
    assert_eq!(
        golden,
        BTreeSet::from([
            ("GET", "/meet"),
            ("POST", "/meet"),
            ("GET", "/meet/by-slug/{slug}"),
            ("GET", "/meet/{id}"),
            ("POST", "/meet/{id}/lock"),
            ("POST", "/meet/{id}/settings"),
            ("POST", "/meet/{id}/role"),
        ])
    );
}

#[test]
fn jmap_slice_ownership_is_exhaustive_and_disjoint() {
    use std::collections::BTreeSet;
    let inventory: serde_json::Value =
        serde_json::from_str(include_str!("../route-inventory.json")).unwrap();
    let mut keys = BTreeSet::new();
    let mut counts = [0; 5];
    let mut email = BTreeSet::new();
    for route in inventory["routes"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|r| r["family"] == "F18")
    {
        let slice = match route["slice"].as_str().unwrap() {
            "email-methods" => 0,
            "mailbox-thread-other" => 1,
            "submission" => 2,
            "websocket-push" => 3,
            "sse-event-source" => 4,
            unknown => panic!("unassigned F18 slice: {unknown}"),
        };
        counts[slice] += 1;
        let key = (
            route["listener"].as_str().unwrap(),
            route["method"].as_str().unwrap(),
            route["path"].as_str().unwrap(),
        );
        assert!(keys.insert(key), "duplicate F18 registration");
        if slice == 0 {
            email.insert((key.1, key.2));
        }
    }
    assert_eq!(counts, [5, 5, 2, 1, 1]);
    assert_eq!(
        email,
        BTreeSet::from([
            ("POST", "/jmap"),
            ("GET", "/messages/{emailId}/download"),
            ("GET", "/messages/{id}/attachments.zip"),
            ("POST", "/messages/{emailId}/unsubscribe"),
            ("POST", "/messages/{id}/focus"),
        ])
    );
}

#[test]
fn mailboxes_slice_ownership_is_exhaustive_and_disjoint() {
    use std::collections::BTreeSet;
    let inventory: serde_json::Value =
        serde_json::from_str(include_str!("../route-inventory.json")).unwrap();
    let mut keys = BTreeSet::new();
    let mut counts = [0; 3];
    for route in inventory["routes"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|r| r["family"] == "F05")
    {
        let slice = match route["slice"].as_str().unwrap() {
            "mailboxes" => 0,
            "migration" => 1,
            "exchange-replacement" => 2,
            unknown => panic!("unassigned F05 slice: {unknown}"),
        };
        counts[slice] += 1;
        let key = (
            route["method"].as_str().unwrap(),
            route["path"].as_str().unwrap(),
        );
        assert!(keys.insert(key), "duplicate F05 registration");
        // The mailbox console paths belong to the mailboxes slice and nothing else does.
        let mailboxes = key.1.starts_with("/admin/mailbox");
        assert_eq!(slice == 0, mailboxes, "{key:?} is in the wrong F05 slice");
    }
    // The fourth slice (the mailwork worker) owns no HTTP route.
    assert_eq!(counts, [19, 16, 13]);
}

#[test]
fn calendar_dav_slice_ownership_is_exhaustive_and_disjoint() {
    let inventory: serde_json::Value =
        serde_json::from_str(include_str!("../route-inventory.json")).unwrap();
    let mut counts = std::collections::BTreeMap::new();
    for route in inventory["routes"].as_array().unwrap() {
        if route["family"] != "F17" {
            continue;
        }
        let slice = route["slice"].as_str().unwrap();
        *counts.entry(slice.to_owned()).or_insert(0) += 1;
        let on = route["state"] == "ON";
        // CAL5 closes F17: all three slices, including both DAV bridges, are native.
        assert!(on, "F17 retains a Go route: {route}");
        assert_eq!(route["upstream"], "local-rust", "{route}");
    }
    assert_eq!(
        counts,
        std::collections::BTreeMap::from([
            ("calendar-booking".to_owned(), 12),
            ("contacts".to_owned(), 2),
            ("dav".to_owned(), 2),
        ])
    );
}

/// F06 Mail security has nine slices (#320..#328); every route belongs to exactly one, and
/// only a slice whose handler is ported (and qualified) may be ON.
#[test]
fn mail_security_slice_ownership_is_exhaustive_and_disjoint() {
    use std::collections::{BTreeMap, BTreeSet};
    let inventory: serde_json::Value =
        serde_json::from_str(include_str!("../route-inventory.json")).unwrap();
    let mut keys = BTreeSet::new();
    let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
    for route in inventory["routes"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|r| r["family"] == "F06")
    {
        let slice = route["slice"].as_str().unwrap();
        assert!(
            [
                "quarantine",
                "queue",
                "spam",
                "tls",
                "dmarc",
                "dlp",
                "threat",
                "trace",
                "smime"
            ]
            .contains(&slice),
            "unassigned F06 slice: {slice}"
        );
        *counts.entry(slice).or_default() += 1;
        let key = (
            route["listener"].as_str().unwrap(),
            route["method"].as_str().unwrap(),
            route["path"].as_str().unwrap(),
        );
        assert!(keys.insert(key), "duplicate F06 registration");
        if route["state"] == "ON" {
            // Each slice ticket appends its name once its oracle is green.
            assert!(
                ["quarantine", "queue", "spam", "tls", "dlp", "dmarc", "threat", "smime", "trace"].contains(&slice),
                "{key:?}"
            );
        }
    }
    assert_eq!(
        counts,
        BTreeMap::from([
            ("dlp", 6),
            ("dmarc", 4),
            ("queue", 4),
            ("quarantine", 9),
            ("smime", 4),
            ("spam", 15),
            ("threat", 4),
            ("tls", 6),
            ("trace", 4),
        ])
    );
    assert_eq!(keys.len(), 56);
}

/// F08 Platform has eight slices (#299..#305, #414); every route belongs to exactly one, in the
/// ON/OFF state its slice has reached. `secevents` is a worker-only slice with no routes.
#[test]
fn platform_slice_ownership_is_exhaustive_and_disjoint() {
    use std::collections::{BTreeMap, BTreeSet};
    let inventory: serde_json::Value =
        serde_json::from_str(include_str!("../route-inventory.json")).unwrap();
    let mut keys = BTreeSet::new();
    let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
    for route in inventory["routes"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|r| r["family"] == "F08")
    {
        let slice = route["slice"].as_str().unwrap();
        assert!(
            [
                "system-features",
                "updates-deploy",
                "jobs-storage",
                "webhooks",
                "terms-remaining",
                "configuration",
                "secevents",
                "acme-control"
            ]
            .contains(&slice),
            "unassigned F08 slice: {slice}"
        );
        *counts.entry(slice).or_default() += 1;
        let key = (
            route["listener"].as_str().unwrap(),
            route["method"].as_str().unwrap(),
            route["path"].as_str().unwrap(),
        );
        assert!(keys.insert(key), "duplicate F08 registration");
        if slice == "configuration" {
            assert_eq!(key, ("gateway", "POST", "/admin/reload"));
            assert_eq!(route["state"], "ON", "{key:?}");
        }
        // Only a route whose slice handler exists may be ON.
        if route["state"] == "ON" {
            assert!(
                matches!(
                    slice,
                    "system-features"
                        | "updates-deploy"
                        | "webhooks"
                        | "jobs-storage"
                        | "acme-control"
                        | "terms-remaining"
                        | "configuration"
                ),
                "{key:?}"
            );
        }
    }
    assert_eq!(
        counts,
        BTreeMap::from([
            ("acme-control", 9),
            ("configuration", 1),
            ("jobs-storage", 14),
            ("system-features", 27),
            ("terms-remaining", 29),
            ("updates-deploy", 35),
            ("webhooks", 6),
        ])
    );
    assert_eq!(keys.len(), 121);
}

/// F19 User mail settings and profile has four slices (#306..#309); every route belongs to
/// exactly one, and only a slice whose handler is ported (and qualified) may be ON.
#[test]
fn user_settings_slice_ownership_is_exhaustive_and_disjoint() {
    use std::collections::{BTreeMap, BTreeSet};
    let inventory: serde_json::Value =
        serde_json::from_str(include_str!("../route-inventory.json")).unwrap();
    let mut keys = BTreeSet::new();
    let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
    for route in inventory["routes"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|r| r["family"] == "F19")
    {
        let slice = route["slice"].as_str().unwrap();
        assert!(
            ["settings-a", "settings-b", "settings-c", "profile"].contains(&slice),
            "unassigned F19 slice: {slice}"
        );
        *counts.entry(slice).or_default() += 1;
        let key = (
            route["listener"].as_str().unwrap(),
            route["method"].as_str().unwrap(),
            route["path"].as_str().unwrap(),
        );
        assert!(keys.insert(key), "duplicate F19 registration");
        if route["state"] == "ON" {
            assert!(
                matches!(slice, "settings-a" | "settings-b" | "settings-c" | "profile"),
                "{key:?}"
            );
        }
        // Closing check (#309): the last slice completes F19, so every route is ON.
        assert_eq!(route["state"], "ON", "F19 route not ON: {key:?}");
        assert_eq!(route["upstream"], "local-rust", "{key:?}");
    }
    assert_eq!(
        counts,
        BTreeMap::from([
            ("profile", 2),
            ("settings-a", 11),
            ("settings-b", 9),
            ("settings-c", 7),
        ])
    );
    assert_eq!(keys.len(), 29);
}

/// F03 Conditional access has two slices (#313, #314); every route belongs to exactly one,
/// and only a slice whose handler is ported (and qualified) may be ON.
#[test]
fn conditional_access_slice_ownership_is_exhaustive_and_disjoint() {
    use std::collections::{BTreeMap, BTreeSet};
    let inventory: serde_json::Value =
        serde_json::from_str(include_str!("../route-inventory.json")).unwrap();
    let mut keys = BTreeSet::new();
    let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
    for route in inventory["routes"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|r| r["family"] == "F03")
    {
        let slice = route["slice"].as_str().unwrap();
        assert!(
            ["policies", "remaining"].contains(&slice),
            "unassigned F03 slice: {slice}"
        );
        *counts.entry(slice).or_default() += 1;
        let key = (
            route["listener"].as_str().unwrap(),
            route["method"].as_str().unwrap(),
            route["path"].as_str().unwrap(),
        );
        assert!(keys.insert(key), "duplicate F03 registration");
        assert_eq!(route["state"], "ON", "{key:?}");
    }
    assert_eq!(counts, BTreeMap::from([("policies", 8), ("remaining", 27)]));
    assert_eq!(keys.len(), 35);
}
