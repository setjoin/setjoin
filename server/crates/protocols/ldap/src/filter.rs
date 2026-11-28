//! Attribute identifiers are a closed map; only assertion values enter SQL
//! parameters. Preserve Go's dropped unsupported terms and substring semantics.
use ldap3_proto::proto::LdapFilter;
pub fn sql(f: &LdapFilter, ou: &str, start: usize, values: &mut Vec<String>) -> String {
    match f {
        LdapFilter::And(children) | LdapFilter::Or(children) => {
            let parts = children
                .iter()
                .map(|child| sql(child, ou, start, values))
                .filter(|x| !x.is_empty())
                .map(|x| format!("({x})"))
                .collect::<Vec<_>>();
            parts.join(if matches!(f, LdapFilter::And(_)) {
                " AND "
            } else {
                " OR "
            })
        }
        LdapFilter::Not(child) => {
            let child = sql(child, ou, start, values);
            if child.is_empty() {
                child
            } else {
                format!("NOT ({child})")
            }
        }
        LdapFilter::Equality(name, value) | LdapFilter::Approx(name, value) => assertion(
            ou,
            name,
            value,
            matches!(f, LdapFilter::Approx(..)),
            false,
            start,
            values,
        ),
        LdapFilter::Substring(name, parts) => {
            let value = parts
                .initial
                .iter()
                .chain(parts.any.iter())
                .chain(parts.final_.iter())
                .map(String::as_str)
                .collect::<String>();
            assertion(ou, name, &value, false, true, start, values)
        }
        // Go labels `(attr=*)` as "presence", which filterToSQL drops; >=/<=
        // and unsupported matching rules are likewise ignored.
        _ => String::new(),
    }
}
fn assertion(
    ou: &str,
    name: &str,
    value: &str,
    approx: bool,
    substring: bool,
    start: usize,
    values: &mut Vec<String>,
) -> String {
    let name = name.trim().to_lowercase();
    let value = value.trim().replace('*', "");
    if ou == "people" && name == "mail" {
        if value.is_empty() {
            return "COALESCE(v.address_blob,'')<>''".into();
        }
        values.push(if approx || substring {
            format!("%{value}%")
        } else {
            value
        });
        let i = start + values.len();
        return if approx || substring {
            format!("v.address_blob ILIKE ${i}")
        } else {
            format!("EXISTS (SELECT 1 FROM jsonb_array_elements(v.addresses) address WHERE LOWER(address->>'email')=LOWER(${i}))")
        };
    }
    let col = match (ou, name.as_str()) {
        ("people", "cn" | "displayname") => "v.display_name",
        ("people", "sn") => "v.last_name",
        ("people", "givenname") => "v.first_name",
        ("people", "telephonenumber") => "v.phone",
        ("people", "title") => "v.job_title",
        ("people", "ou" | "department") => "d.name",
        ("groups", "cn" | "displayname") => "m.display_name",
        ("groups", "mail") => "m.email",
        ("resources", "cn" | "displayname") => "display_name",
        ("resources", "mail") => "email",
        ("contacts", "cn" | "displayname") => "c.display_name",
        ("contacts", "sn") => "c.last_name",
        ("contacts", "givenname") => "c.first_name",
        ("contacts", "title") => "c.job_title",
        ("contacts", "o" | "company") => "c.company",
        ("contacts", "ou" | "department") => "c.department",
        _ => return String::new(),
    };
    if value.is_empty() {
        return format!("{col} IS NOT NULL");
    }
    let like = name != "mail" || substring;
    values.push(if like { format!("%{value}%") } else { value });
    let i = start + values.len();
    if like {
        format!("{col} ILIKE ${i}")
    } else {
        format!("LOWER({col})=LOWER(${i})")
    }
}
