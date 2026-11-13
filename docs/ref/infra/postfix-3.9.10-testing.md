# Postfix 3.9.10 — Test Configuration

Used in `deploy/docker/test-smtp/` for E2E SMTP integration testing.

## main.cf

```ini
myhostname = smtp.test.local
mydomain = test.local
myorigin = $mydomain
inet_interfaces = all
inet_protocols = all
mydestination = $myhostname, localhost.$mydomain, localhost, $mydomain

# Disable TLS for testing
smtp_use_tls = no
smtpd_use_tls = no

# Accept mail from anywhere (testing only)
mynetworks = 0.0.0.0/0
smtpd_relay_restrictions = permit_mynetworks, reject_unauth_destination

# Minimal queue / bounce settings
maximal_queue_lifetime = 1d
bounce_queue_lifetime = 1d
```

## Behavior

- Accepts all mail sent to `@test.local` domain
- No SMTP authentication required
- No TLS (plaintext on port 25)
- Messages delivered to `/var/mail/<user>` mbox files
- Minimal queue lifetime (1 day) for test cleanup

## Image

```dockerfile
FROM alpine:3.21
RUN apk add --no-cache postfix
```

Postfix 3.9.10 ships with Alpine 3.21.
