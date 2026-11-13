# Minimal Dovecot config for IMAP integration testing.
# No SSL, plaintext auth, static user database.

protocols = imap
listen = *

# Disable SSL for testing — test on port 143 plaintext
ssl = no
disable_plaintext_auth = no

# Static test user — password is "testpass"
passdb {
  driver = static
  args = password=testpass
}

userdb {
  driver = static
  args = uid=5000 gid=5000 home=/var/mail/%u
}

# Deliver to Maildir
mail_location = maildir:/var/mail/%u

# IMAP specific
imap_client_workarounds = delay-newmail

# Log to stdout
log_path = /dev/stdout
info_log_path = /dev/stdout
auth_verbose = yes
mail_debug = yes

## Default config output
# 2.3.21.1 (d492236fa0): /etc/dovecot/dovecot.conf
# OS: Linux 6.12.76-linuxkit aarch64  overlay
# Hostname: 01ca8f2f6b64
auth_verbose = yes
disable_plaintext_auth = no
imap_client_workarounds = delay-newmail
info_log_path = /dev/stdout
listen = *
log_path = /dev/stdout
mail_debug = yes
mail_location = maildir:/var/mail/%u
passdb {
  args = password=#hidden_use-P_to_show#
  driver = static
}
service replication-notify-fifo {
  name = aggregator
}
service anvil-auth-penalty {
  name = anvil
}
service auth-worker {
  name = auth-worker
}
service auth-client {
  name = auth
}
service config {
  name = config
}
service dict-async {
  name = dict-async
}
service dict {
  name = dict
}
service login/proxy-notify {
  name = director
}
service dns-client {
  name = dns-client
}
service doveadm-server {
  name = doveadm
}
service imap-hibernate {
  name = imap-hibernate
}
service imap {
  name = imap-login
}
service imap-urlauth {
  name = imap-urlauth-login
}
service imap-urlauth-worker {
  name = imap-urlauth-worker
}
service token-login/imap-urlauth {
  name = imap-urlauth
}
service imap-master {
  name = imap
}
service indexer-worker {
  name = indexer-worker
}
service indexer {
  name = indexer
}
service ipc {
  name = ipc
}
service lmtp {
  name = lmtp
}
service log-errors {
  name = log
}
service old-stats-mail {
  name = old-stats
}
service pop3 {
  name = pop3-login
}
service login/pop3 {
  name = pop3
}
service replicator-doveadm {
  name = replicator
}
service login/stats-writer {
  name = stats
}
service submission {
  name = submission-login
}
service login/submission {
  name = submission
}
ssl = no
userdb {
  args = uid=5000 gid=5000 home=/var/mail/%u
  driver = static
}
