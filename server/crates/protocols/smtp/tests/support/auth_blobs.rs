use futures_util::future::BoxFuture;
#[derive(Default)]
pub struct Blobs(pub std::sync::Mutex<std::collections::BTreeMap<String, String>>);
impl setjoin_smtp::RawBlobs for Blobs {
    fn put<'a>(&'a self, key: &'a str, data: &'a [u8]) -> BoxFuture<'a, Result<(), String>> {
        Box::pin(async move {
            use base64::Engine;
            self.0.lock().unwrap().insert(
                key.into(),
                base64::engine::general_purpose::STANDARD.encode(data),
            );
            Ok(())
        })
    }
}
