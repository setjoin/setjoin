//! Canonical SQL migration catalog and embedded role-provisioning script shared
//! by standalone server binaries.
#![forbid(unsafe_code)]
include!(concat!(env!("OUT_DIR"), "/migrations.rs"));
include!(concat!(env!("OUT_DIR"), "/provision_roles.rs"));

/// Return `(cluster_global_pass, db_local_pass)` split from the canonical
/// `scripts/provision-roles.sql` embedded at build time.
pub fn provision_roles_passes() -> (&'static str, &'static str) {
    (PROVISION_ROLES_CLUSTER_SQL, PROVISION_ROLES_DB_LOCAL_SQL)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provision_roles_sql_splits_cleanly_at_canonical_marker() {
        let (cluster, db_local) = provision_roles_passes();
        assert_eq!(
            format!("{cluster}{db_local}"),
            PROVISION_ROLES_SQL,
            "pass 1 + pass 2 must reconstruct provision-roles.sql byte-for-byte"
        );
        assert!(db_local.starts_with(PROVISION_ROLES_SECTION_MARKER));
        // Pass 1 holds all cluster-global role DDL and membership grants.
        for role in [
            "setjoin_owner",
            "setjoin_app",
            "setjoin_worker",
            "setjoin_updater",
        ] {
            assert!(
                cluster.contains(&format!("CREATE ROLE {role}")),
                "pass 1 missing CREATE ROLE {role}"
            );
            assert!(
                cluster.contains(&format!("ALTER ROLE {role}")),
                "pass 1 missing ALTER ROLE {role}"
            );
        }
        assert!(cluster.contains("GRANT setjoin_worker TO setjoin_owner;"));
        assert!(!cluster.contains("GRANT SELECT, INSERT, UPDATE, DELETE"));

        // Pass 2 holds owner-safe DB-local grants, revokes, carve-outs, and ownership.
        assert!(!db_local.contains("CREATE ROLE"));
        assert!(!db_local.contains("ALTER ROLE"));
        assert!(db_local.contains("GRANT USAGE ON SCHEMA public TO setjoin_app, setjoin_worker;"));
        assert!(db_local.contains("REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA public FROM PUBLIC;"));
        assert!(db_local.contains("REVOKE ALL ON FUNCTION %s FROM setjoin_app"));
        assert!(db_local.contains("antiphish_contact_graph"));
        assert!(db_local.contains("deploy_remote_fence"));
        assert!(db_local.contains("saml_assertion_replay"));
    }
}
