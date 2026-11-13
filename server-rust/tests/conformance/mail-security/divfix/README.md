# Certificate parity (#468)

`mailsec_smime` replays `status-*.json` through the authenticated HTTP route;
`cert_status_expiry_states` runs all six non-valid cases. Only the generated
certificate expiry timestamp is normalized. Status uses the first transport peer,
not headers, stored S/MIME certificates, or NotBefore. The optional-client-auth
socket cases additionally prove real TLS → request metadata and configured CA loading.

Record a new status case with `GOFREE_RECORD_DIVFIX=1 GOFREE_GO_SOURCE=<40-char commit>`
and the existing `drain/GoTick` environment. The `.go.txt` overlay calls frozen Go's
registered handler with Go TLS request metadata behind the Rust proxy. Ordinary replay
starts no Go. The auth wrapper is supplied by the existing authenticated route oracle.

`smime-certs/generate-strict.py` deterministically creates public DER mutations of
`a.pem`; it never recomputes signatures and refuses to overwrite different fixture bytes.
`strict-cases.json` pins DER SHA-256 and expectations checked by real Go recording.
`import_strict_certificate_cases` and `status_strict_certificate_cases` replay the
entire manifest, collecting all errors. The catalog selects each matrix once, using
its duplicate-extension recording as representative. Successful controls pin Go's
parse-only behavior: unknown critical extension, unknown key algorithm, bad signature,
legacy extensions, zero/long serial, wide path length, signed inhibit policy, BMP/T61 CN, long field OIDs and P-224.
Field OIDs retain Go's signed31bit component bound; policy OIDs retain arbitrary-width
components with canonical base-128 grammar (audited regex engine over DER-decoded values).
The separately selectable `policy_oid` controls pin this distinction.

Use the existing mailsec HTTP recorder with `GOFREE_RECORD_GO_BINARY` and
`GOFREE_GO_SOURCE` to capture *new* labels. Goldens use create-new semantics; do not
regenerate archived files to hide a mismatch. TLS upload deliberately stores arbitrary
bytes as frozen Go does; strict parsing belongs to its status reader and S/MIME import.
Runtime schema checks use RustCrypto `der` and NIST point decoders plus `x509-parser`;
no certificate signature, trust decision, or private-key primitive is implemented here.

`cert_status_without_client_roots_remains_optional` isolates native-root loading with
saved/restored SSL_CERT_FILE/SSL_CERT_DIR, an unreadable operator bundle and empty system
roots. It replays Go's no-peer body through real TLS and requires an untrusted certificate
to close the connection. Empty trust is a rejection-only policy, never no-client-auth.
