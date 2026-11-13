//! Frozen encoding/json struct decoding and personal organize-only bounds.
use serde::de::{MapAccess, Visitor};
/// Original RawMessage bytes and its replacement-rune view used only for validation.
#[derive(Default)]
pub struct Raw(pub Option<String>, pub Option<String>);
trait Field: Sized {
    fn read<'de, M: MapAccess<'de>>(m: &mut M, old: Self) -> Result<Self, M::Error>;
}
macro_rules! plain {($($t:ty),*)=>{$(impl Field for $t { fn read<'de,M:MapAccess<'de>>(m:&mut M,old:Self)->Result<Self,M::Error>{Ok(m.next_value::<Option<Self>>()?.unwrap_or(old))}})*};}
plain!(String, bool, i64);
impl Field for Option<i64> {
    fn read<'de, M: MapAccess<'de>>(m: &mut M, _: Self) -> Result<Self, M::Error> {
        m.next_value()
    }
}
impl Field for Raw {
    fn read<'de, M: MapAccess<'de>>(m: &mut M, _: Self) -> Result<Self, M::Error> {
        Ok(Self(
            Some(
                m.next_value::<Box<serde_json::value::RawValue>>()?
                    .get()
                    .into(),
            ),
            None,
        ))
    }
}
fn fold(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            'ſ' => 's',
            'K' => 'k',
            _ => c.to_ascii_lowercase(),
        })
        .collect()
}
macro_rules! body {($name:ident {$($field:ident:$ty:ty=$key:literal),+$(,)?})=>{
    #[derive(Default)] pub struct $name {$(pub $field:$ty),+}
    impl<'de> serde::Deserialize<'de> for $name {
        fn deserialize<D:serde::Deserializer<'de>>(d:D)->Result<Self,D::Error>{
            struct Fields;
            impl<'de> Visitor<'de> for Fields {type Value=$name;
                fn expecting(&self,f:&mut std::fmt::Formatter<'_>)->std::fmt::Result{f.write_str("a JSON object")}
                fn visit_unit<E:serde::de::Error>(self)->Result<$name,E>{Ok($name::default())}
                fn visit_map<M:MapAccess<'de>>(self,mut m:M)->Result<$name,M::Error>{
                    let mut b=$name::default();
                    while let Some(k)=m.next_key::<String>()?{match fold(&k).as_str(){$($key=>b.$field=Field::read(&mut m,std::mem::take(&mut b.$field))?,)+ _=>{let _:serde::de::IgnoredAny=m.next_value()?;}}}
                    Ok(b)
                }
            } d.deserialize_any(Fields)
        }
    }
};}
body!(Rule {mailbox_id:Option<i64>="mailboxid",name:String="name",enabled:bool="enabled",priority:i64="priority",run_on:String="runon",transport:bool="istransportrule",conditions:Raw="conditions",actions:Raw="actions",stop:bool="stopprocessing"});
body!(Entry {
    kind: String = "type"
});
pub fn validate(r: &mut Rule, create: bool) -> Result<(), String> {
    if create && r.name.is_empty() {
        return Err("name is required".into());
    }
    if r.name.len() > 200 {
        return Err("name is too long".into());
    }
    for (field, program) in [("conditions", &r.conditions), ("actions", &r.actions)] {
        if let Some(raw) = &program.0 {
            if raw.len() > 16 << 10 {
                return Err(format!("{field} is too long"));
            }
            let entries = serde_json::from_str::<Option<Vec<Option<Entry>>>>(
                program.1.as_deref().unwrap_or(raw),
            )
            .map_err(|_| format!("{field} must be a JSON array"))?
            .unwrap_or_default();
            if entries.len() > 20 {
                return Err(format!("{field} has too many entries"));
            }
            if field == "actions" {
                for entry in entries.into_iter().flatten() {
                    if [
                        "forward_to",
                        "redirect",
                        "bcc",
                        "append_footer",
                        "add_header",
                    ]
                    .contains(&entry.kind.as_str())
                    {
                        return Err(format!(
                            "action type {:?} is not allowed on personal rules (organize-only)",
                            entry.kind
                        ));
                    }
                }
            }
        }
    }
    if r.run_on.is_empty() {
        r.run_on = "server".into()
    }
    if !["server", "client", "both"].contains(&r.run_on.as_str()) {
        return Err("runOn must be server, client, or both".into());
    }
    Ok(())
}
body!(Retro {
    window: String = "window"
});
impl Field for Option<bool> {
    fn read<'de, M: MapAccess<'de>>(m: &mut M, _: Self) -> Result<Self, M::Error> {
        m.next_value()
    }
}
body!(Template {name:String="name",description:String="description",category:String="category",conditions:Raw="conditions",actions:Raw="actions",parameters:Raw="parameters",enabled:Option<bool>="enabled",sort:Option<i64>="sortorder"});
body!(Visibility {user_id:Option<i64>="userid",hidden:bool="hidden"});
