# RFC 6376 — DKIM Critical Sections
> Source: https://www.rfc-editor.org/rfc/rfc6376

## §3.4 Canonicalization (Our implementation must match these rules)

### Simple Header: No changes. Headers used exactly as-is.

### Relaxed Header: Apply in order
1. Convert header field names to lowercase
2. Unfold all header continuation lines (join folded lines)
3. Convert all WSP sequences to single SP
4. Delete all WSP at end of each unfolded header value
5. Delete WSP around colon separator (colon retained)

### Simple Body: Ignore trailing empty lines. Ensure one CRLF at end if non-empty.

### Relaxed Body:
- Ignore all whitespace at end of lines (keep CRLF)
- Reduce all WSP sequences within a line to single SP
- Ignore empty lines at end; add CRLF if body non-empty without trailing CRLF

### Empty Body Hash (SHA-256): `frcCV1k9oG9oKj3dpUqdJg1PxRT2RSN/XKdLCPjaYaY=`

## §3.5 DKIM-Signature Header Tags

| Tag | Required | Description |
|-----|----------|-------------|
| v= | REQUIRED | Version (must be "1") |
| a= | REQUIRED | Algorithm ("rsa-sha1" or "rsa-sha256") |
| b= | REQUIRED | Signature data (base64) |
| bh= | REQUIRED | Body hash (base64) |
| d= | REQUIRED | Signing Domain Identifier (SDID) |
| h= | REQUIRED | Signed header fields (colon-separated) |
| s= | REQUIRED | Selector |
| c= | OPTIONAL | Canonicalization (default "simple/simple") |
| i= | OPTIONAL | Agent or User Identifier (AUID) |
| l= | OPTIONAL | Body length limit |
| t= | OPTIONAL | Signature timestamp (UNIX epoch) |
| x= | OPTIONAL | Signature expiration (UNIX epoch) |

## §3.3.3 Key Sizes
- Signers MUST use RSA keys >= 1024 bits for long-lived keys
- Verifiers MUST validate 512-2048 bit keys

## §6.1.2 Verification Steps (Verifier MUST)
1. Extract signatures from message
2. Compute body hash with the specified canonicalization
3. Compare computed body hash against bh= tag
4. Verify the digital signature

## Updated by RFC 8301 §3.1
- Verifiers MUST NOT consider rsa-sha1 valid
- Signers MUST NOT sign with rsa-sha1

## Updated by RFC 8301 §3.2
- Verifiers MUST NOT accept signatures with RSA key size < 1024 bits
