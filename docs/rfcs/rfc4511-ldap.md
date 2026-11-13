# RFC 4511 — LDAP Critical Sections
> Source: https://www.rfc-editor.org/rfc/rfc4511

## §4.5.1 Search Request

### Filter (§4.5.1.7)
Filter operators that MUST be supported:
- `&` — AND (all child filters must be true)
- `|` — OR (at least one child filter must be true)  
- `!` — NOT (child filter must be false)
- `=` — equalityMatch
- `=*` — present (attribute exists)
- `=value*` — substrings (initial, any, final)

### Scope (§4.5.1.1)
- 0 (baseObject): only the entry named by base DN
- 1 (singleLevel): immediate children of base DN
- 2 (wholeSubtree): base DN and all descendants

### Size Limit (§4.5.1.4)
- Client specifies maximum entries to return
- Server MUST return `sizeLimitExceeded` (4) when exceeded
- Server MUST NOT return `success` (0) when size limit exceeded

### Time Limit (§4.5.1.5)
- Client specifies maximum time in seconds for search
- Server MUST return `timeLimitExceeded` (3) when exceeded

### Attribute Selection (§4.5.1.6)
- Non-empty attribute list: return only those attributes
- Empty list with `typesOnly=FALSE`: return all user attributes
- `typesOnly=TRUE`: return attribute types without values
- Special attribute `1.1`: no attributes (useful for existence checks)

## §4.1.10 Result Codes
| Code | Name | Meaning |
|------|------|---------|
| 0 | success | Operation completed |
| 3 | timeLimitExceeded | Search exceeded time limit |
| 4 | sizeLimitExceeded | Search exceeded size limit |
| 11 | adminLimitExceeded | Server administrative limit exceeded |
