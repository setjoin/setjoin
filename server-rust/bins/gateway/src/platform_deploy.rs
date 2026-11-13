//! Go's permissive first-value deployment request decoder and lifecycle adapter.
use crate::{Body, RequestContext};
use hyper::{Request, Response};
use setjoin_platform::deploy::{Node, Wizard};
#[derive(Default)]
struct Input {
    nodes: Vec<Node>,
}
#[derive(Default)]
struct NodeInput {
    node: Node,
    fields: u8,
}
impl NodeInput {
    fn apply(self, mut existing: Node) -> Node {
        macro_rules! field {
            ($name:ident, $bit:expr) => {
                if self.fields & (1 << $bit) != 0 {
                    existing.$name = self.node.$name;
                }
            };
        }
        field!(host, 0);
        field!(role, 1);
        field!(ssh_user, 2);
        field!(ssh_key, 3);
        field!(password, 4);
        existing
    }
}
impl<'de> serde::Deserialize<'de> for NodeInput {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct Fields;
        impl<'de> serde::de::Visitor<'de> for Fields {
            type Value = NodeInput;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("deployment node")
            }
            fn visit_unit<E: serde::de::Error>(self) -> Result<Self::Value, E> {
                Ok(NodeInput::default())
            }
            fn visit_map<M: serde::de::MapAccess<'de>>(
                self,
                mut fields: M,
            ) -> Result<Self::Value, M::Error> {
                let mut n = NodeInput::default();
                while let Some(key) = fields.next_key::<String>()? {
                    macro_rules! field {
                        ($f:ident, $bit:expr) => {
                            if let Some(v) = fields.next_value::<Option<String>>()? {
                                n.node.$f = v;
                                n.fields |= 1 << $bit;
                            }
                        };
                    }
                    match crate::guests_input::fold(&key).as_str() {
                        "host" => {
                            field!(host, 0);
                        }
                        "role" => {
                            field!(role, 1);
                        }
                        "ssh_user" => {
                            field!(ssh_user, 2);
                        }
                        "ssh_key" => {
                            field!(ssh_key, 3);
                        }
                        "password" => {
                            field!(password, 4);
                        }
                        _ => {
                            let _ = fields.next_value::<serde::de::IgnoredAny>()?;
                        }
                    }
                }
                Ok(n)
            }
        }
        d.deserialize_any(Fields)
    }
}
impl<'de> serde::Deserialize<'de> for Input {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct Fields;
        impl<'de> serde::de::Visitor<'de> for Fields {
            type Value = Input;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("deployment request")
            }
            fn visit_unit<E: serde::de::Error>(self) -> Result<Self::Value, E> {
                Ok(Input::default())
            }
            fn visit_map<M: serde::de::MapAccess<'de>>(
                self,
                mut fields: M,
            ) -> Result<Self::Value, M::Error> {
                let mut body = Input::default();
                while let Some(key) = fields.next_key::<String>()? {
                    if crate::guests_input::fold(&key) == "nodes" {
                        // encoding/json reuses existing slice elements across duplicate
                        // arrays. Missing/null scalar fields retain their earlier values.
                        let incoming = fields
                            .next_value::<Option<Vec<NodeInput>>>()?
                            .unwrap_or_default();
                        body.nodes = incoming
                            .into_iter()
                            .enumerate()
                            .map(|(i, node)| {
                                node.apply(body.nodes.get(i).cloned().unwrap_or_default())
                            })
                            .collect();
                    } else {
                        let _ = fields.next_value::<serde::de::IgnoredAny>()?;
                    }
                }
                Ok(body)
            }
        }
        d.deserialize_any(Fields)
    }
}
pub(crate) async fn serve(
    start: bool,
    wizard: &Wizard,
    r: &mut Request<Body>,
    auth: &setjoin_authz::Authorized,
    c: &RequestContext,
    id: &str,
) -> Response<Body> {
    if !start {
        wizard.reset().await;
        let mut response =
            crate::jmap::reply::response(String::new(), c.identity.proto, id.to_owned());
        *response.status_mut() = hyper::StatusCode::NO_CONTENT;
        response.headers_mut().remove("content-type");
        return response;
    }
    // #542 (owner-approved security fix 2026-11-05): frozen Go decoded the request without a
    // size bound and the port re-parsed the growing buffer on every frame (quadratic). Read at
    // most 1 MiB (as recovery does), then parse the first JSON value exactly once.
    let body = read_capped(r).await.and_then(|bytes| {
        let parsed = crate::guests_input::go_json_bytes(&bytes);
        serde_json::Deserializer::from_slice(&parsed)
            .into_iter::<Input>()
            .next()
            .and_then(Result::ok)
    });
    let Some(body) = body else {
        return crate::mailboxes::bare(400, "invalid JSON body", c, id);
    };
    if body.nodes.len() != 3 {
        return crate::mailboxes::bare(400, "exactly 3 nodes required for HA deployment", c, id);
    }
    // #542: hostnames/IP literals and POSIX user names only; nothing else reaches a command.
    if let Err(detail) = setjoin_platform::deploy::validate(&body.nodes) {
        return crate::mailboxes::bare(400, detail, c, id);
    }
    wizard.reset().await;
    if wizard
        .begin(body.nodes, auth.context().clone())
        .await
        .is_err()
    {
        return crate::mailboxes::bare(
            500,
            "Deploy failed. Check the server logs for details.",
            c,
            id,
        );
    }
    let mut response = crate::jmap::reply::response(
        "{\"status\":\"deploying\"}\n".into(),
        c.identity.proto,
        id.to_owned(),
    );
    *response.status_mut() = hyper::StatusCode::ACCEPTED;
    response
}

/// Request body cap for the deployment start route.
const BODY_CAP: usize = 1 << 20;

/// The whole request body, or `None` when it exceeds [`BODY_CAP`] or fails to arrive.
async fn read_capped(r: &mut Request<Body>) -> Option<Vec<u8>> {
    use http_body_util::BodyExt;
    // Test-only bug restoration (deploy-body-uncapped): no size bound.
    let cap = if setjoin_contracts::mutants::on("deploy-body-uncapped") {
        usize::MAX
    } else {
        BODY_CAP
    };
    let mut bytes = Vec::new();
    while let Some(frame) = r.body_mut().frame().await {
        if let Ok(data) = frame.ok()?.into_data() {
            if data.len() > cap - bytes.len() {
                return None;
            }
            bytes.extend_from_slice(&data);
        }
    }
    Some(bytes)
}
