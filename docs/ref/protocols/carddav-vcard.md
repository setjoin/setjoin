## CardDAV & vCard Protocol Requirements
> **RFC 6352** (CardDAV), **RFC 2426** (vCard 3.0 — current target)

### vCard Version
- Currently targets vCard 3.0 (RFC 2426, 1998) — do NOT advertise vCard 4.0 until fully migrated
- `supported-address-data` MUST only include `Version: "3.0"`

### vCard Serialization
- ALL property values MUST use `escape()`: `\` → `\\`, `;` → `\;`, `,` → `\,` (§5)
- Line folding MUST NOT break multi-byte UTF-8 (same `escapeLine()` bug as iCalendar)
- REV MUST use `20060102T150405Z` format (ISO 8601 basic, vCard 3.0) — NOT `time.RFC3339`

### ADR (Address) Property — RFC 2426 §3.2.1
- ADR MUST have 7 semicolon-delimited components:
  - Position 0: Post Office Box
  - Position 1: Extended Address
  - Position 2: Street
  - Position 3: City/Locality
  - Position 4: State/Region
  - Position 5: Postal Code
  - Position 6: Country
- Serialization MUST produce all 7, not just 5
- Parser MUST read all 7 positions, not just indices 2-6

### Parser Requirements
- VERSION check SHOULD detect and reject vCard 2.1 / 4.0 input
- BDAY format SHOULD be validated (expects `20060102` or `20060102T150405Z`)
- PHOTO SHOULD support both URI and inline encoding

### Missing Properties (vCard 4.0 migration target)
- NICKNAME, GENDER, ANNIVERSARY, IMPP, KIND, PRODID
- Full vCard 4.0 → JSContact (RFC 9553/9555) is the future direction

### DO NOT
- Do NOT advertise vCard 4.0 in CardDAV until generation supports v4.0 syntax
- Do NOT produce 5-field ADR — always 7-field
- Do NOT use `time.RFC3339` for vCard 3.0 REV — use `20060102T150405Z`

### Verification
```bash
go test ./internal/carddav/... -v
```
