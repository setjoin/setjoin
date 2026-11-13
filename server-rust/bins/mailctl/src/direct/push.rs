use super::*;

pub async fn execute(action: &str, args: &[String]) -> Result<(), String> {
    if action == "test" {
        return test(args).await;
    }
    if action != "doctor" {
        return Err(format!("unknown push action: {action} (try: doctor, test)"));
    }
    let statuses = setjoin_push::doctor().await;
    for status in &statuses {
        let mark = match status.state {
            "configured" => "OK",
            "invalid" => "!!",
            _ => "..",
        };
        print!("  [{mark}] {:<8} {}", status.provider, status.state);
        if !status.detail.is_empty() {
            print!(" — {}", status.detail);
        }
        println!();
    }
    if statuses.iter().any(|s| s.state == "invalid") {
        return Err("one or more push providers have INVALID config".into());
    }
    Ok(())
}

async fn test(args: &[String]) -> Result<(), String> {
    let (fs, _) = parse_silent(args, &["user"], &[]).map_err(|e| {
        if e != "flag: help requested" {
            eprintln!("{e}");
        }
        let helps: BTreeMap<String, String> =
            serde_json::from_str(include_str!("../flags_help.json")).unwrap();
        eprint!("{}", helps["push test"]);
        e
    })?;
    let email = value(&fs, "user");
    if email.is_empty() {
        return Err("usage: mailctl push test --user <email>".into());
    }
    let encryption = env("DB_ENCRYPTION_KEY");
    if encryption.is_empty() {
        return Err("DB_ENCRYPTION_KEY is required to decrypt device tokens".into());
    }
    let (mut set, _) = setjoin_push::build();
    if !set.any() {
        return Err("no push providers configured (run 'mailctl push doctor')".into());
    }
    let mut db = database(false).await?;
    let (user, devices, unreadable) = db.resolve_push_devices(email, &encryption).await?;
    if unreadable > 0 {
        eprintln!("{} ERROR push: push_devices rows could not be decrypted; tokens skipped user_id={user} skipped_rows={unreadable} consequence=\"those devices will not receive this dispatch; check app.encryption_key at the connection pooler\"",chrono::Local::now().format("%Y/%m/%d %H:%M:%S"));
    }
    if devices.is_empty() {
        return Err(format!("user {email:?} has no registered push devices"));
    }
    let payload = serde_json::json!({"type":"test","body":"SetJoin mailctl push test"}).to_string();
    let mut sent = 0;
    let mut failed = 0;
    for device in devices {
        match set
            .send(&device.provider, &device.token, payload.as_bytes())
            .await
        {
            None => println!(
                "  SKIP device {} ({}): provider not configured here",
                device.id, device.provider
            ),
            Some(Err(e)) => {
                println!("  FAIL device {} ({}): {e}", device.id, device.provider);
                failed += 1;
            }
            Some(Ok(())) => {
                println!("  SENT device {} ({})", device.id, device.provider);
                sent += 1;
            }
        }
    }
    println!("Done: {sent} sent, {failed} failed");
    if sent == 0 {
        return Err("no test push delivered".into());
    }
    Ok(())
}
