//! F08 `GET /setup/status` (#364): the unauthenticated first-boot probe. An empty table is
//! staged by moving `users` aside for one request, a failing count by a view whose rows
//! raise; the case's cleanup restores the real table on every path.
use super::terms::Case;

const NONE: &str = "SELECT NULL::text WHERE false";
/// `users` moved aside: Go's request pool and the native worker both count an empty table.
const EMPTY: &str = "BEGIN; ALTER TABLE public.users RENAME TO gofree_setup_users; CREATE TABLE public.users (id bigint); GRANT SELECT ON public.users TO PUBLIC; COMMIT;";
/// `users` replaced by a view whose function raises: the count fails for every role.
const FAILING: &str = "BEGIN; CREATE FUNCTION public.gofree_setup_fault() RETURNS SETOF bigint LANGUAGE plpgsql AS $f$ BEGIN RAISE EXCEPTION 'gofree setup count fault'; END $f$; ALTER TABLE public.users RENAME TO gofree_setup_users; CREATE VIEW public.users AS SELECT f.id FROM public.gofree_setup_fault() AS f(id); GRANT SELECT ON public.users TO PUBLIC; COMMIT;";
/// Restores the real table only when this case moved it.
const RESTORE: &str = "DO $r$ BEGIN IF to_regclass('public.gofree_setup_users') IS NOT NULL THEN IF EXISTS (SELECT 1 FROM pg_class WHERE oid = to_regclass('public.users') AND relkind = 'v') THEN DROP VIEW public.users; ELSE DROP TABLE IF EXISTS public.users; END IF; ALTER TABLE public.gofree_setup_users RENAME TO users; END IF; DROP FUNCTION IF EXISTS public.gofree_setup_fault(); END $r$";

pub fn specs(action: &str, label: &str) -> Option<Case> {
    if action != "setup-status" {
        return None;
    }
    let mut c = Case {
        method: "GET",
        pattern: "/setup/status",
        fill: vec![],
        query: String::new(),
        perm: "users.read",
        body: String::new(),
        headers: vec![("authorization", String::new())],
        seed: vec![],
        cleanup: vec![RESTORE.into()],
        effects: NONE,
        table: "none",
        channels: vec![],
        status: 404,
        replace: vec![],
        unshift: vec![],
    };
    match label {
        "initialized" | "api-alias" => {}
        "empty-db" | "api-alias-empty-db" => {
            c.seed.push(EMPTY.into());
            c.status = 200;
        }
        "head" => c.method = "HEAD",
        "head-empty-db" => {
            c.method = "HEAD";
            c.seed.push(EMPTY.into());
            c.status = 200;
        }
        "count-fails" => c.seed.push(FAILING.into()),
        "escaped" => c.fill = vec!["!/s%65tup/status".into()],
        "escaped-empty-db" => {
            c.fill = vec!["!/s%65tup/status".into()];
            c.seed.push(EMPTY.into());
            c.status = 200;
        }
        // StripPrefix refuses the escaped mount: never the public answer, even on an empty table.
        "escaped-api-empty-db" => {
            c.fill = vec!["!/a%70i/setup/status".into()];
            c.seed.push(EMPTY.into());
        }
        "ignored-query" => {
            c.query = "?initialized=true&x=%zz".into();
            c.seed.push(EMPTY.into());
            c.status = 200;
        }
        // A signed session changes nothing: the probe never authenticates.
        "with-session" => c.headers = vec![],
        "post" | "post-empty-db" => {
            c.method = "POST";
            if label == "post-empty-db" {
                c.seed.push(EMPTY.into());
            }
            c.status = 0;
        }
        "trailing-slash" => {
            c.fill = vec!["!/setup/status/".into()];
            c.status = 0;
        }
        "rate-limit" => c.status = 429,
        _ => return None,
    }
    Some(c)
}
