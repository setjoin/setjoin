# Recovery object-store TLS fixture

These are public test credentials for an ephemeral loopback S3 endpoint.
`ca.pem` is trusted only in the isolated child test process; `server.der` and
`server-key.der` are its server certificate and PKCS#8 key. They are never
runtime credentials. The SAN covers loopback; the test does not disable TLS
verification or change the parent process trust store.
