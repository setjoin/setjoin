//! Read-only push tokens scoped to the verified mailbox and actor.
use setjoin_authz::principals::{ReadCapability, TxFactory};

use crate::sql;

pub async fn tokens(tx_factory: &TxFactory, read: &ReadCapability) -> [String; 6] {
    let mailbox = read.mailbox().get();
    let user = read.actor().get();
    let mut tokens = std::array::from_fn(|_| "unavailable".to_owned());
    if let Ok(rows) = tx_factory
        .run_mailbox_read_contract(read, &sql::PUSH_STATE_MAIL, &[&mailbox, &user])
        .await
    {
        if let Some(row) = rows.first() {
            for (index, token) in tokens.iter_mut().enumerate().take(3) {
                *token = encode(row.try_get(index).unwrap_or(-1));
            }
        }
    }
    for (index, contract) in [
        &sql::PUSH_STATE_CALENDARS,
        &sql::PUSH_STATE_ADDRESSBOOKS,
        &sql::PUSH_STATE_TASKS,
    ]
    .into_iter()
    .enumerate()
    {
        if let Ok(rows) = tx_factory
            .run_mailbox_read_contract(read, contract, &[&mailbox])
            .await
        {
            if let Some(row) = rows.first() {
                tokens[index + 3] = encode(row.try_get(0).unwrap_or(-1));
            }
        }
    }
    tokens
}

fn encode(n: i64) -> String {
    if n < 0 {
        "unavailable".into()
    } else {
        n.to_string()
    }
}
