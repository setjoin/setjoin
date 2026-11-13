//! SMTP's post-commit event sink uses the one process-wide Dispatcher.
use crate::webhook::{CloudEvent, Dispatcher};
use futures_util::future::BoxFuture;

pub struct DeliveryEvents(pub Dispatcher);
impl setjoin_smtp::DeliveryEvents for DeliveryEvents {
    fn received<'a>(
        &'a self,
        user: i64,
        mailbox: i64,
        from: &'a str,
        to: &'a str,
    ) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            self.0
                .dispatch_for_mailbox(
                    user,
                    mailbox,
                    &CloudEvent::new(
                        "mailserver/gateway",
                        "mail.received",
                        serde_json::json!({"from": from, "to": to}),
                    ),
                )
                .await;
        })
    }
}

/// Submission's post-commit `mail.sent` (Go `DispatchForMailbox` after commit).
pub struct SubmissionEvents(pub Dispatcher);
impl setjoin_smtp::submission::SubmissionEvents for SubmissionEvents {
    fn sent<'a>(
        &'a self,
        user: i64,
        mailbox: i64,
        from: &'a str,
        to: &'a str,
    ) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            self.0
                .dispatch_for_mailbox(
                    user,
                    mailbox,
                    &CloudEvent::new(
                        "mailserver/gateway",
                        "mail.sent",
                        serde_json::json!({"from": from, "to": to}),
                    ),
                )
                .await;
        })
    }
}
