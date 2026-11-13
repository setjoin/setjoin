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
    pub fn enqueue(&self, exec: setjoin_pg::ScopedExecutor, challenge: super::push::Challenge) {
        let Some(sender) = self.sender.clone() else {
            return;
        };
        let mut jobs = self.jobs.lock().expect("push jobs");
        while jobs.try_join_next().is_some() {}
        jobs.spawn(async move{
   use setjoin_pg::Type;
   let Ok(actor)=setjoin_contracts::ids::ActorId::new(challenge.user)else{return;};
   let Ok(rows)=exec.read_user_scoped(actor,"SELECT id,push_provider,push_token_enc,device_public_key FROM push_devices WHERE user_id=$1 AND push_provider IN ('apns','fcm','hms') AND revoked_at IS NULL AND device_public_key IS NOT NULL",&[(&challenge.user,Type::INT8)]).await else{return;};
   for row in rows{
    let id:i64=row.get(0);let provider:String=row.get(1);let envelope:Vec<u8>=row.get(2);let key:Vec<u8>=row.get(3);
    // Keep per-device failures independent: one unreadable subscription must
    // not suppress other enrolled devices. Keys are deployment context only.
    // The command executor installs the deployment crypto GUC transaction-locally;
    // read_user_scoped intentionally carries only the user scope.
    let token=exec.run_user_command(actor,setjoin_contracts::ids::OperationId(*uuid::Uuid::new_v4().as_bytes()),"SELECT pgp_sym_decrypt($1::bytea,current_setting('app.encryption_key'))::text",&[(&envelope,Type::BYTEA)],|rows|Ok(rows[0].get::<_,String>(0))).await;
    let setjoin_pg::CommandOutcome::Committed(token)=token else{continue;};if token.is_empty(){continue;}
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
