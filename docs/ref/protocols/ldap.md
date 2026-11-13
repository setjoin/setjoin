## LDAP Protocol Requirements
> **RFC 4511** (LDAP), **RFC 4514** (DN StrRep), **RFC 4513** (TLS)

### MANDATORY — Filter Parsing (RFC 4511 §4.5.1)
- MUST implement recursive filter parser supporting:
  - `&` (AND), `|` (OR), `!` (NOT) compound operators
  - `=` (equalityMatch), `=*` (presence), `=xxx*` (substring)
  - `~=` (approxMatch), `>=` / `<=` (orderingMatch — SHOULD)
- The broken `extractFilterValue()` that does flat substring matching MUST be replaced with `parseFilter()` → `filterToSQL()`

### MANDATORY — Search Scope (RFC 4511 §4.5.1)
- Scope 0 (baseObject): return only entry named by base DN
- Scope 1 (singleLevel): return only immediate children of base DN OU
- Scope 2 (wholeSubtree): return everything (current behavior)
- Scope MUST be checked in ALL search handlers (searchPeople, searchGroups, etc.)

### MANDATORY — DN Construction (RFC 4514)
- RDN attribute values MUST escape: `,`, `+`, `"`, `\`, `<`, `>`, `;`, leading `#`, trailing space
- Use `escapeRDN()` on all CN/OU/DC values before `fmt.Sprintf("cn=%s,...")`

### MANDATORY — Size Limit (RFC 4511 §4.5.1)
- When results exceed sizeLimit, MUST return `LDAPResultSizeLimitExceeded` (code 4)
- Query with `LIMIT sizeLimit+1` to detect overflow

### MANDATORY — Attribute Filtering
- Non-empty `attrs` list MUST filter which attributes are returned per entry
- Empty `attrs` means all user attributes (RFC 4511 §4.5.1)
- `typesOnly=TRUE` MUST omit attribute values per RFC 4511 §4.5.1

### MANDATORY — Time Limit (RFC 4511 §4.5.1)
- When search exceeds timeLimit, MUST return `LDAPResultTimeLimitExceeded` (code 3)
- Check `ctx.Err() == context.DeadlineExceeded` after query loop

### ✅ DONE — Write Operations (RFC 4511 §4.6-4.9)
- Add, Delete, Modify handlers registered, return `LDAPResultUnwillingToPerform` with diagnostic
- ModifyDN caught by library's default NotFound handler

### ✅ DONE — Compare Operation (RFC 4511 §4.10)
- `handleCompare` resolves DN → DB entry, compares attribute value, returns CompareTrue/CompareFalse

### SHOULD
- STARTTLS on port 389 via Extended operation (RFC 4513 §3)
- Respect `timeLimit` with context deadline (code 3 on expiry)
- Support Abandon operation via `m.Done` check in search loops (RFC 4511 §4.11)

### DO NOT
- Do NOT use `fmt.Sprintf("cn=%s,...")` without `escapeRDN()` on the value
- Do NOT silently clamp sizeLimit — return proper error code
- Do NOT ignore scope parameter — it must constrain results
- Do NOT return all attributes when client requests a specific subset

### Verification
```bash
go test ./internal/ldap/... -v
```
