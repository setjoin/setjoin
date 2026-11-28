use std::{env, fs, path::PathBuf};

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    let dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap())
        .join("../../../sql/dbschema")
        .canonicalize()
        .unwrap();
    println!("cargo:rerun-if-changed={}", dir.display());
    let mut migrations = Vec::new();
    for entry in fs::read_dir(&dir).unwrap() {
        let path = entry.unwrap().path();
        let name = path.file_name().unwrap().to_str().unwrap();
        if name.starts_with('V') && name.ends_with(".sql") {
            if let Some((version, _)) = name[1..].split_once("__") {
                migrations.push((version.parse::<i32>().unwrap(), name.to_owned(), path));
            }
        }
    }
    migrations.sort_by_key(|m| m.0);
    let mut source = "pub const MIGRATIONS: &[(i32, &str, &str)] = &[\n".to_owned();
    for (version, name, path) in migrations {
        source.push_str(&format!(
            "({version}, {name:?}, include_str!({:?})),\n",
            path.to_str().unwrap()
        ));
    }
    source.push_str("];\n");
    fs::write(
        PathBuf::from(env::var("OUT_DIR").unwrap()).join("migrations.rs"),
        source,
    )
    .unwrap();

    // Single source of truth for native-RLS role/grant provisioning (#545).
    let provision_path = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap())
        .join("../../../scripts/provision-roles.sql")
        .canonicalize()
        .unwrap();
    println!("cargo:rerun-if-changed={}", provision_path.display());
    let provision_sql = fs::read_to_string(&provision_path).unwrap();
    const MARKER: &str = "-- === SETJOIN_PROVISION_ROLES_DB_LOCAL_PASS ===";
    let matches: Vec<_> = provision_sql.match_indices(MARKER).collect();
    assert_eq!(
        matches.len(),
        1,
        "scripts/provision-roles.sql must contain exactly one `{MARKER}` section marker"
    );
    let split_at = matches[0].0;
    let cluster_sql = &provision_sql[..split_at];
    let db_local_sql = &provision_sql[split_at..];
    let provision_rs = format!(
        "pub const PROVISION_ROLES_SECTION_MARKER: &str = {MARKER:?};\n\
         pub const PROVISION_ROLES_SQL: &str = include_str!({:?});\n\
         pub const PROVISION_ROLES_CLUSTER_SQL: &str = {cluster_sql:?};\n\
         pub const PROVISION_ROLES_DB_LOCAL_SQL: &str = {db_local_sql:?};\n",
        provision_path.to_str().unwrap()
    );
    fs::write(
        PathBuf::from(env::var("OUT_DIR").unwrap()).join("provision_roles.rs"),
        provision_rs,
    )
    .unwrap();
}
