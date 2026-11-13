# Shared push transports (#354)

Foundation helper ported on demand from frozen `shared/push`; no domain-crate
or database dependency. The standalone mailctl process oracle is its verification
seam. Provider order is webpush, apns, fcm, hms; absence is distinct from invalid
configuration. Never expose device capabilities or credentials in diagnostics.

`build` reads the same VAPID/APNs/FCM/HMS variables as Go; `doctor` additionally
checks FCM/HMS OAuth. APNs retains Go's SHA-1 PKCS#12 boundary, strict boolean
parsing, HTTP/2 and certificate authentication. FCM signs RS256 OAuth assertions
and caches access tokens until expiry. HMS fetches OAuth for each send. Payloads,
provider rejection errors and all-device delivery counts are verified at the
standalone CLI seam, including revoked/foreign/unreadable device exclusions.

Web Push implements aes128gcm RFC 8291 and signed VAPID, resolves and pins allowed
addresses, rejects private/reserved destinations, disables proxies and redirects.
Keep frozen Go's empty advertised VAPID key and doubled default mailto prefix;
the oracle verifies its signature using the known fixture key. URL-bearing
transport failures scrub capability paths/query before reaching callers.

The nondefault `oracle-loopback` feature allows explicit literal-loopback APNs
dial substitution and Web Push peer injection, preserving TLS/SNI/mTLS/protocol
checks. It exists only for the mailctl dev dependency. Normal builds ignore
`MAILCTL_ORACLE_APNS_ADDR` and `MAILCTL_ORACLE_WEBPUSH_LOOPBACK`. Tests require
OpenSSL plus system libcrypto/libnghttp2 and use synthetic credentials only.
