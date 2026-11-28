//! Native provider I/O is an injected boundary; identity authority stays in push.
use std::{future::Future, pin::Pin};
pub trait NativeDelivery: Send {
    fn send<'a>(
        &'a mut self,
        provider: &'a str,
        device_token: &'a str,
        encrypted: &'a [u8],
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>>;
}
#[derive(Default)]
pub struct Dispatch {
    sender: Option<std::sync::Arc<tokio::sync::Mutex<Box<dyn NativeDelivery>>>>,
    jobs: std::sync::Mutex<tokio::task::JoinSet<()>>,
}
impl Dispatch {
    pub fn with_transport(transport: impl NativeDelivery + 'static) -> Self {
        Self {
            sender: Some(std::sync::Arc::new(tokio::sync::Mutex::new(Box::new(
                transport,
            )))),
            jobs: Default::default(),
        }
    }
}

struct Shared(setjoin_push::Set);
impl NativeDelivery for Shared {
    fn send<'a>(
        &'a mut self,
        provider: &'a str,
        token: &'a str,
        payload: &'a [u8],
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>> {
        Box::pin(async move {
            self.0
                .send(provider, token, payload)
                .await
                .unwrap_or(Ok(()))
        })
    }
}
impl Dispatch {
    pub fn from_env() -> Self {
        let (set, statuses) = setjoin_push::build();
        if statuses
            .iter()
            .any(|s| s.provider != "webpush" && s.state == "configured")
        {
            Self::with_transport(Shared(set))
        } else {
            Self::default()
        }
    }
    /// The dispatch survives the request, but dropping the owning auth runtime
    /// aborts its JoinSet. No self-reference keeps jobs or provider caches alive.
    pub fn enqueue(&self, exec: setjoin_pg::AuthDb, challenge: super::push::Challenge) {
        let Some(sender) = self.sender.clone() else {
            return;
        };
        let mut jobs = self.jobs.lock().expect("push jobs");
        while jobs.try_join_next().is_some() {}
        jobs.spawn(async move{
   use setjoin_pg::Type;
   let Ok(actor)=setjoin_contracts::ids::ActorId::new(challenge.user)else{return;};
   let Ok(rows)=exec.read_user_scoped_contract(actor,&crate::sql::PUSH_DELIVERY_L66,&[(&challenge.user,Type::INT8)]).await else{return;};
   for row in rows{
    // An unreadable subscription row skips only that device.
    let (id,provider,envelope,key) = match (row.try_get::<_,i64>(0),row.try_get::<_,String>(1),row.try_get::<_,Vec<u8>>(2),row.try_get::<_,Vec<u8>>(3)) {
     (Ok(id),Ok(provider),Ok(envelope),Ok(key)) => (id,provider,envelope,key),
     (a,b,c,d) => {
      eprintln!("push_delivery: unreadable device row: id={:?} provider={:?} envelope={:?} key={:?}",a.err(),b.err(),c.err(),d.err());
      continue;
     }
    };
    // Keep per-device failures independent: one unreadable subscription must
    // not suppress other enrolled devices. Keys are deployment context only.
    // The command executor installs the deployment crypto GUC transaction-locally;
    // read_user_scoped intentionally carries only the user scope.
    let token=exec.run_user_command_contract(actor,setjoin_contracts::ids::OperationId(*uuid::Uuid::new_v4().as_bytes()),&crate::sql::PUSH_DELIVERY_L80,&[(&envelope,Type::BYTEA)],|rows|rows.first().and_then(|r|r.try_get::<_,String>(0).ok()).ok_or_else(||setjoin_pg::StatementFailure{sqlstate:None,hint:None,message:"push token row".into()})).await;
    let token = match token {
     setjoin_pg::CommandOutcome::Committed(token) => token,
     other => {
      let reason = match &other {
       setjoin_pg::CommandOutcome::RolledBack(setjoin_pg::Rejection::Statement(e)) => e.message.as_str(),
       _ => "outcome unavailable",
      };
      eprintln!("push_delivery: unreadable device token result: {reason}");
      continue;
     }
    };if token.is_empty(){continue;}
    let payload=serde_json::json!({"type":"push_mfa","protocol":"setjoin.push-approval.v1","nonce":challenge.nonce,"code":challenge.code,"device_id":id,"user_id":challenge.user,"session_id":challenge.session,"expires_at":challenge.expires}).to_string();
    let Ok(encrypted)=encrypt_native(&key,payload.as_bytes())else{continue;};
    let _=sender.lock().await.send(&provider,&token,&encrypted).await;
   }
  });
    }
}
/// PUSH_ECIES_CONTRACT: audited ring ECDH -> HKDF-SHA256 -> AES-256-GCM.
/// A fresh ephemeral key and nonce are generated independently for every device.
pub fn encrypt_native(recipient: &[u8], plain: &[u8]) -> Result<Vec<u8>, ring::error::Unspecified> {
    use ring::{
        aead, agreement, hkdf,
        rand::{SecureRandom, SystemRandom},
    };
    if recipient.len() != 65 || recipient[0] != 4 {
        return Err(ring::error::Unspecified);
    }
    let rng = SystemRandom::new();
    let ephemeral = agreement::EphemeralPrivateKey::generate(&agreement::ECDH_P256, &rng)?;
    let public = ephemeral.compute_public_key()?;
    let peer = agreement::UnparsedPublicKey::new(&agreement::ECDH_P256, recipient);
    let key = agreement::agree_ephemeral(ephemeral, &peer, |shared| {
        let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, &[]).extract(shared);
        let info = [b"push-challenge".as_slice()];
        let mut key = [0u8; 32];
        prk.expand(&info, hkdf::HKDF_SHA256)?.fill(&mut key)?;
        aead::UnboundKey::new(&aead::AES_256_GCM, &key)
    })??;
    let mut nonce = [0u8; 12];
    rng.fill(&mut nonce)?;
    let mut encrypted = plain.to_vec();
    aead::LessSafeKey::new(key).seal_in_place_append_tag(
        aead::Nonce::assume_unique_for_key(nonce),
        aead::Aad::empty(),
        &mut encrypted,
    )?;
    let mut out = public.as_ref().to_vec();
    out.extend(nonce);
    out.extend(encrypted);
    Ok(out)
}
