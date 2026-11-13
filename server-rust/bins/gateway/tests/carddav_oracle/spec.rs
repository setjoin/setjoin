use super::{BOOK, OTHER};
pub struct Spec {
    pub method: &'static str,
    pub path: String,
    pub body: String,
    pub headers: Vec<(&'static str, String)>,
    pub repeat: bool,
    pub wanted: u16,
}
pub fn spec(route: &str, label: &str, user: i64, other: i64) -> Spec {
    if let Some(kind) = route.strip_prefix("gal-") {
        let mut s = spec(kind, "success", user, other);
        s.path = if kind == "get" {
            format!("/carddav/gal/u{other}.vcf")
        } else {
            "/carddav/gal/".into()
        };
        if kind == "multiget" {
            s.body = s.body.replace(
                &format!("/{BOOK}/cal5-contact.vcf"),
                &format!("/gal/u{other}.vcf</d:href><d:href>/gal/u{user}.vcf"),
            );
        }
        if kind == "put" || kind == "delete" {
            s.wanted = 403;
        }
        match label {
            "cross-tenant"=>{
                if matches!(kind,"get"|"propfind"){s.path=format!("/carddav/gal/u{other}.vcf");s.wanted=404;}
                if kind=="query"{s.body=s.body.replace("</r:addressbook-query>",&format!("<c:filter><c:prop-filter name=\"FN\"><c:text-match>cal5-other</c:text-match></c:prop-filter></c:filter></r:addressbook-query>"));}
                if kind=="multiget"{s.body=s.body.replace(&format!("<d:href>/gal/u{user}.vcf</d:href>"),"");}
            }
            "invalid-input"=>match kind {
                "get"|"propfind"=>{s.path="/carddav/gal/not-a-member".into();s.wanted=404;},
                "query"|"multiget"=>{s.body=format!("<{}",if kind=="query"{"addressbook-query"}else{"addressbook-multiget"});s.wanted=400;},
                "sync"=>{s.body=s.body.replace("</r:sync-collection>","<d:sync-token>bad-token</d:sync-token></r:sync-collection>");s.wanted=403;},
                _=>s.body="<invalid".into(),
            },
            "repeat"=>s.repeat=true,
            "disabled"|"hidden"|"guest" if kind=="get"=>s.wanted=404,
            "gal-off" if !matches!(kind,"options"|"put"|"delete")=>s.wanted=404,
            "properties"=>s.body=spec("propfind","members",user,other).body,
            "depth0"=>s.headers.push(("depth","0".into())),
            "alias-filter"=>s.body=s.body.replace("</r:addressbook-query>","<c:filter><c:prop-filter name=\"FN\"><c:text-match>alias@</c:text-match></c:prop-filter></c:filter></r:addressbook-query>"),
            "current"|"removed"|"never-visible"|"count-mismatch"|"future" if kind=="sync"=>{
                let token=match label {"removed"|"never-visible"=>"1925089445000000-2","count-mismatch"=>"1925089446000000-3","future"=>"999999999999999999-2",_=>"1925089446000000-2"};
                s.body=s.body.replace("</r:sync-collection>",&format!("<d:sync-token>{token}</d:sync-token></r:sync-collection>"));
                if matches!(label,"count-mismatch"|"never-visible"){s.wanted=403;}
            }
            _=>{}
        }
        if label == "limit" && matches!(kind, "propfind" | "query" | "multiget" | "sync") {
            s.body = "x".repeat((1 << 20) + 1);
            s.wanted = 413;
        }
        if label == "db-fault" {
            s.wanted = 500;
        }
        return s;
    }
    if route == "entitlement" {
        return Spec {
            method: "OPTIONS",
            path: if label == "cross-tenant" {
                format!("/carddav/{OTHER}/")
            } else {
                "/carddav/".into()
            },
            body: if label == "invalid-input" {
                "<invalid".into()
            } else {
                String::new()
            },
            headers: vec![],
            repeat: false,
            wanted: 403,
        };
    }
    let method = match route {
        "propfind" => "PROPFIND",
        "get" => "GET",
        "query" | "multiget" | "sync" => "REPORT",
        "put" | "put-update" => "PUT",
        "delete" => "DELETE",
        "unsupported" => "POST",
        _ => "OPTIONS",
    };
    let path = if route == "get" {
        format!("/carddav/{BOOK}/cal5-contact.vcf")
    } else if matches!(route, "put" | "put-update" | "delete") {
        format!("/carddav/{BOOK}/cal5-write.vcf")
    } else if label == "members" || method == "REPORT" {
        format!("/carddav/{BOOK}/")
    } else {
        "/carddav/".into()
    };
    let body = if method == "REPORT" {
        let name = match route {
            "query" => "addressbook-query",
            "multiget" => "addressbook-multiget",
            _ => "sync-collection",
        };
        let ns = if route == "sync" {
            "DAV:"
        } else {
            "urn:ietf:params:xml:ns:carddav"
        };
        format!("<r:{name} xmlns:r=\"{ns}\" xmlns:d=\"DAV:\" xmlns:c=\"urn:ietf:params:xml:ns:carddav\"><d:prop><d:getetag/><c:address-data/></d:prop>{}</r:{name}>",if route=="multiget"{format!("<d:href>/{BOOK}/cal5-contact.vcf</d:href>")}else{String::new()})
    } else if label == "members" {
        r#"<d:propfind xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:carddav"><d:prop><d:resourcetype/><d:displayname/><d:getetag/><d:getcontenttype/><d:getcontentlength/><c:address-data/><c:addressbook-description/><c:supported-address-data/><d:supported-report-set/></d:prop></d:propfind>"#.to_owned()
    } else if method == "PUT" {
        "BEGIN:VCARD\r\nVERSION:3.0\r\nUID:cal5-write\r\nFN:CAL5 write\r\nN:Writer;Alice;;;\r\nORG:Setjoin\r\nTITLE:Engineer\r\nROLE:Platform\r\nNOTE:first\\nsecond\r\nBDAY:20000229\r\nCATEGORIES:Friends,Work\r\nEMAIL;TYPE=WORK:alice@example.test\r\nTEL;TYPE=WORK:+15550100\r\nURL;TYPE=WORK:https://example.test\r\nADR;TYPE=HOME:;;One Street;Paris;;75001;France\r\nEND:VCARD\r\n".into()
    } else {
        String::new()
    };
    let mut s = Spec {
        method,
        path,
        body,
        headers: vec![],
        repeat: false,
        wanted: match route {
            "propfind" | "query" | "multiget" | "sync" => 207,
            "put" => 201,
            "put-update" | "delete" => 204,
            "unsupported" => 405,
            _ => 200,
        },
    };
    match label {
        "db-fault" | "unaccounted" | "bad-accounting" => s.wanted = 500,
        "bridge-disabled" => s.wanted = 404,
        "cross-tenant" => {
            if route == "get" {
                s.path = format!("/carddav/{OTHER}/cal5-contact.vcf");
                s.wanted = 404;
            } else if matches!(route, "put" | "put-update" | "delete") {
                s.path = format!("/carddav/{OTHER}/cal5-write.vcf");
                s.wanted = 404;
            } else {
                s.path = format!("/carddav/{OTHER}/");
                if matches!(route, "query" | "sync") {
                    s.wanted = 404;
                }
            }
            if route == "multiget" {
                s.body = s.body.replace(
                    &format!("/{BOOK}/cal5-contact.vcf"),
                    &format!("/{OTHER}/cal5-foreign.vcf"),
                );
            }
        }
        "invalid-input" => match route {
            "get" | "delete" => {
                s.path = "/carddav/not-a-book/no.vcf".into();
                s.wanted = 404;
            }
            "query" | "multiget" => {
                s.body = format!(
                    "<{}",
                    if route == "query" {
                        "addressbook-query"
                    } else {
                        "addressbook-multiget"
                    }
                );
                s.wanted = 400;
            }
            "sync" => {
                s.body = s.body.replace(
                    "</r:sync-collection>",
                    "<d:sync-token>bad-token</d:sync-token></r:sync-collection>",
                );
                s.wanted = 403;
            }
            "put" | "put-update" => {
                s.body = "BEGIN:VCARD\r\nFN:No UID\r\nEND:VCARD\r\n".into();
                s.wanted = 400;
            }
            _ => s.body = "<invalid".into(),
        },
        "repeat" => {
            s.repeat = true;
            if route == "put" {
                s.wanted = 204;
            }
            if route == "delete" {
                s.wanted = 404;
            }
        }
        _ => {}
    }
    match label {
        "properties" => {
            s.body = spec("propfind", "members", user, other).body;
            s.headers.push(("depth", "0".into()));
        }
        "resource" => {
            s.path = format!("/carddav/{BOOK}/cal5-contact.vcf");
            s.body = spec("propfind", "members", user, other).body;
        }
        "depth0" => {
            s.path = format!("/carddav/{BOOK}/");
            s.headers.push(("depth", "0".into()));
        }
        "bad-json" => s.wanted = if route == "put-update" { 400 } else { 404 },
        "encoded" => {
            s.path = s.path.replacen("/carddav/", "/%63arddav/", 1);
            s.wanted = 404;
        }
        "vcard4" => s.body = s.body.replace("VERSION:3.0", "VERSION:4.0"),
        "photo" => {
            s.body = s.body.replace(
                "END:VCARD",
                &format!("PHOTO;VALUE=URI:/blobs/{}\r\nEND:VCARD", "c5".repeat(32)),
            )
        }
        "if-none" => {
            s.headers.push(("if-none-match", "*".into()));
            s.wanted = 412;
        }
        "if-match" => {
            s.headers.push(("if-match", "\"wrong\"".into()));
            s.wanted = 412;
        }
        "if-match-good" => {
            s.headers.push(("if-match", "\"cal5-etag\"".into()));
            if route == "put" {
                s.wanted = 204;
            }
        }
        "if-match-missing" => {
            s.headers.push(("if-match", "*".into()));
            s.wanted = 412;
        }
        "current" | "removed" | "updated" | "pruned" | "resync" | "future" if route == "sync" => {
            let token = if label == "future" {
                "999999999999"
            } else {
                "1"
            };
            s.body = s.body.replace(
                "</r:sync-collection>",
                &format!("<d:sync-token>{token}</d:sync-token></r:sync-collection>"),
            );
            if matches!(label, "pruned" | "resync" | "future") {
                s.wanted = 403;
            }
        }
        "unknown" => {
            s.body = "<unknown/>".into();
            s.wanted = 501;
        }
        "wrong-namespace" => {
            s.body = s
                .body
                .replace("urn:ietf:params:xml:ns:carddav", "wrong:namespace");
            s.wanted = 400;
        }
        "filter" | "no-match" => {
            let text = if label == "filter" { "café" } else { "absent" };
            s.body=s.body.replace("</r:addressbook-query>",&format!("<c:filter><c:prop-filter name=\"FN\"><c:text-match>{text}</c:text-match></c:prop-filter></c:filter></r:addressbook-query>"));
        }
        "uid-collision" => {
            s.body = s.body.replace(
                &format!("/{BOOK}/cal5-contact.vcf"),
                &format!("/{OTHER}/cal5-contact.vcf"),
            )
        }
        "bad-path" => {
            s.path = format!("/carddav/{BOOK}/");
            s.wanted = if route == "put" { 409 } else { 404 };
        }
        "head" => s.method = "HEAD",
        "mkcol" => s.method = "MKCOL",
        "proppatch" => s.method = "PROPPATCH",
        "copy" => s.method = "COPY",
        "move" => s.method = "MOVE",
        "lock" => s.method = "LOCK",
        "unlock" => s.method = "UNLOCK",
        _ => {}
    }
    if label == "limit" {
        s.body = "x".repeat((if method == "PUT" { 10 << 20 } else { 1 << 20 }) + 1);
        s.wanted = 413;
    }
    s
}
