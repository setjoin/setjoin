use std::{env, fs, path::PathBuf};

fn main() {
    let dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap())
        .join("../../../mailserver/sql/dbschema")
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
}
