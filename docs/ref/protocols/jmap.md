## JMAP Protocol Requirements
> **RFC 8620** (JMAP Core), **RFC 8621** (JMAP Mail), **RFC 8887** (WebSocket Push)

### MANDATORY — Error Handling (RFC 8620 §3.6)
- Request-level errors MUST be returned as RFC 7807 Problem Details JSON:
  - `urn:ietf:params:jmap:error:notJSON`, `notRequest`, `unknownCapability`, `limit`
- `maxCallsInRequest` violation MUST return request-level error, not method-level
- Unknown capability in `using` MUST be request-level error

### MANDATORY — Protocol Features (RFC 8620)
- ResultReference (`#id` back-reference) MUST be supported for method chaining (§3.7)
- Request `createdIds` MUST be propagated into response
- `downloadUrl` MUST include required `type` URI template variable (§2.5)
- `eventSourceUrl` MUST include `types`, `closeafter`, `ping` template variables

### MANDATORY — Method Coverage
- `Mailbox/query` and `Mailbox/queryChanges` MUST be implemented (§5.1, §5.2)
- `Identity/get` and `Identity/changes` MUST be implemented (§4.1, §4.2)
- Empty `using` array MUST be rejected per Errata 6606

### WebSocket (RFC 8887)
- WebSocket Request handling MUST enforce the same capability validation and limits as HTTP
- Error responses on WebSocket MUST use JMAP error structure, not plain text

### Account IDs
- Account IDs SHOULD use base64url-safe format, not numeric strings (§2)

### ✅ DONE — Blob Management (RFC 9404)
- `urn:ietf:params:jmap:blob` capability advertised in session + accountCapabilities
- `Blob/get`, `Blob/copy`, `Blob/lookup` methods implemented via `jmap_blob.go`
- `POST /jmap/upload/{accountId}` — content-hash computed server-side, stored to MinIO + `blobs` table
- `GET /jmap/download/{accountId}/{blobId}/{name}` — streams from MinIO with Content-Disposition
- Legacy REST `/blobs/{sha256}` endpoints preserved for backward compat

### DO NOT
- Do NOT return method-level errors for request-level violations
- Do NOT omit `type` variable from `downloadUrl` template
- Do NOT bypass capability validation on WebSocket requests
- Do NOT use numeric account IDs — use base64url-safe strings

### Verification
```bash
go test ./internal/handlers/... -run JMAP -v
```
