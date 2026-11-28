//! Frozen Go's MDM observer is dormant: notify.Dispatcher refuses device_policy
//! before subscribing, then the named goroutine waits on an unregistered channel.
//! Preserve the warning and absence of DB/outbound effects (ARCH-029), rather
//! than silently wiring policy push. The process-local task can coexist with Go;
//! GO_WORKERS_OFF=mdm-notify stops its Go goroutine during explicit handover.
pub async fn run_until(stop: impl std::future::Future<Output = ()> + Send) {
    eprintln!(
        "{}",
        serde_json::json!({"level":"WARN","msg":"mam: failed to subscribe to device_policy channel","error":"channel \"device_policy\" is not in the dispatcher's NOTIFY channel grammar"})
    );
    eprintln!(
        "{}",
        serde_json::json!({"level":"INFO","msg":"mam: device_policy notification subscription active (logged, not WS-pushed)"})
    );
    stop.await;
}
