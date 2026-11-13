# SSO Architecture Fixes + SAML/OIDC Group Provisioning

## Problem

Six issues found in the authserver's SAML SP and OIDC RP implementations:

1. **OIDC: no `sub` stored.** Only email is extracted from id_tokens. The stable `sub` claim is ignored. Email changes cause data loss (new account, no history).
2. **SAML: NameID forced to email.** The ACS handler requires NameID to contain `@` after stripping `mailto:`. Persistent/transient NameID formats break.
3. **SAML: no attribute extraction.** Assertion attributes are never read. The `AttributeMap` on `samlspRegistration` is unused.
4. **OIDC: no group extraction.** The `groups` claim is not extracted. Scopes don't include `"groups"`.
5. **No group re-evaluation on login.** Group memberships, roles, and department assignments are only set at JIT creation time — never refreshed.
6. **Fragile SAML middleware wrapper.** The ACS handler wraps ResponseWriter, intercepts cookies from headers, and creates a synthetic request to extract the NameID. Works but relies on internal crewjam/saml behavior.

## Design

### Phase 1: Stable Identity Matching

**Schema:**

```sql
ALTER TABLE users ADD COLUMN oidc_subject TEXT;
ALTER TABLE users ADD COLUMN oidc_issuer TEXT;
ALTER TABLE users ADD COLUMN saml_name_id TEXT;
ALTER TABLE users ADD COLUMN saml_idp_entity_id TEXT;
CREATE UNIQUE INDEX users_oidc_subject_idx ON users(oidc_issuer, oidc_subject) WHERE oidc_subject IS NOT NULL;
CREATE UNIQUE INDEX users_saml_name_id_idx ON users(saml_idp_entity_id, saml_name_id) WHERE saml_name_id IS NOT NULL;
```

**OIDC callback flow (updated):**

```
OIDC callback
  → Exchange code for id_token
  → Validate state, nonce, c_hash, email_verified
  → Extract sub, iss, email, email_verified
  → Lookup user by (oidc_issuer, oidc_subject)
     → Found: update email if changed, issue tokens
     → Not found: fall back to email lookup
        → Found: link oidc_subject to existing user, issue tokens
        → Not found: JIT create with oidc_subject + email
```

**SAML ACS flow (updated):**

```
SAML ACS
  → Process assertion via middleware
  → Replay detection (existing)
  → Extract NameID (raw, preserve format) + attributes
  → Extract email from:
     - emailAddress format NameID → use directly
     - persistent format NameID → use email from attributes
     - other format → use attribute-mapped email
  → Lookup user by (saml_idp_entity_id, saml_name_id)
     → Found: update email if changed, issue tokens
     → Not found: fall back to email lookup
        → Found: link saml_name_id to existing user, issue tokens
        → Not found: JIT create with saml_name_id + email
```

### Phase 2: Group Claim Extraction

**OIDC:**

Add `"groups"` to scopes at [oidc_rp.go:113](authserver/internal/federation/oidc_rp.go#L113). Add configurable `group_claim` field to `oidcProviderConfig` (default `"groups"`). Extract the claim from id_token claims:

```go
type oidcProviderConfig struct {
    // ... existing fields ...
    groupClaim string // configurable, default "groups"
}

func GroupsFromIDToken(idToken *gooidc.IDToken, claimName string) ([]string, error) {
    var claims map[string]interface{}
    if err := idToken.Claims(&claims); err != nil {
        return nil, err
    }
    raw, ok := claims[claimName]
    if !ok {
        return nil, nil // no groups claim — not an error
    }
    // Handle both string array and single string
    switch v := raw.(type) {
    case []interface{}:
        out := make([]string, 0, len(v))
        for _, item := range v {
            if s, ok := item.(string); ok {
                out = append(out, s)
            }
        }
        return out, nil
    case []string:
        return v, nil
    case string:
        return []string{v}, nil
    }
    return nil, nil
}
```

**SAML:**

Read assertion attributes from the crewjam/saml session. The middleware provides `session.(samlsp.JWTSessionClaims)` which has an `Attributes` field. Extract the configured group attribute:

```go
func GroupsFromSAMLAssertion(r *http.Request, reg *samlspRegistration) ([]string, error) {
    session, err := reg.middleware.Session.GetSession(r)
    if err != nil {
        return nil, err
    }
    sa, ok := session.(samlsp.JWTSessionClaims)
    if !ok {
        return nil, fmt.Errorf("unexpected session type")
    }
    attrName := reg.groupAttribute // configurable, default "memberOf"
    for _, attr := range sa.Attributes {
        if attr.Name == attrName {
            return attr.Values, nil
        }
    }
    return nil, nil // no group attribute — not an error
}
```

But wait — we need to check if `JWTSessionClaims` actually has an `Attributes` field. Read the crewjam/saml source to verify. If it doesn't, we'll need to access the underlying `saml.Session` or `saml.Assertion` directly through the middleware's `ServiceProvider`.

**Per-provider config additions:**

OIDC (`oidcProviderConfigJSON`):
```json
{
  "name": "azure",
  "provider_url": "https://login.microsoftonline.com/.../v2.0",
  "client_id": "...",
  "client_secret": "...",
  "redirect_url": "https://mail.company.com/auth/oidc/callback",
  "jit_enabled": true,
  "enabled": true,
  "group_claim": "groups",
  "group_mappings": [
    {"idp_group": "Engineering", "distribution_group_id": 5, "admin_role": null, "department_id": 3},
    {"idp_group": "IT", "distribution_group_id": 7, "admin_role": "super_admin", "department_id": null}
  ]
}
```

SAML (`saml_sp_registrations`):
```sql
ALTER TABLE saml_sp_registrations ADD COLUMN group_attribute TEXT DEFAULT 'memberOf';
ALTER TABLE saml_sp_registrations ADD COLUMN group_mappings JSONB;
```

### Phase 3: Group Refresh on Every Login

On each SSO login (not just JIT creation), after user lookup/creation:

```
  → Extract current groups from IdP claims
  → Read group_mappings from provider config
  → For each mapping where idp_group matches the user's groups:
      - Upsert distribution group membership (if distribution_group_id set)
      - Update users.admin_role (if admin_role set, highest priority wins)
      - Update users.department_id (if department_id set)
  → Remove user from any distribution groups they were previously auto-assigned
    to but are no longer in (track auto-assigned memberships)
```

**Tracking auto-assigned memberships:**

Add a `source` column to `distribution_group_members`:

```sql
ALTER TABLE distribution_group_members ADD COLUMN source TEXT DEFAULT 'manual';
-- source = 'manual' (admin-assigned) or 'sso' (auto-assigned from IdP groups)
```

On group refresh, only remove memberships where `source = 'sso'`. Admin-manual assignments (`source = 'manual'`) are never touched. New SSO assignments set `source = 'sso'`.

**Priority for admin_role:** If multiple IdP groups map to different admin roles (e.g., "IT" → super_admin, "Managers" → user_admin), the highest-privilege role wins. Order: `super_admin` > `user_admin` > `read_only` > `auditor`.

### Phase 4: Simplify SAML ACS

Replace the ResponseWriter-wrapping workaround with crewjam/saml's callback pattern. Research shows `Middleware.AcsCallback` is not the right approach. Instead, we use the middleware as a handler but intercept the session BEFORE the redirect happens. The correct approach:

```go
func (h *AuthHandler) SAMLACS(w http.ResponseWriter, r *http.Request) {
    // ... lookup reg, assertion replay detection ...

    // Use the middleware to parse the SAML response but capture the session
    // before the middleware redirects by providing a custom session callback
    mw := reg.Middleware()
    
    // The middleware stores the session and then redirects.
    // We can read the session cookie AFTER the middleware processes the request
    // by letting it write to a buffer, then extracting the session.
    
    // Current approach is actually the recommended pattern from crewjam/saml docs.
    // Keep it but document the reason clearly.
}
```

Actually, re-reading the crewjam/saml source, our current approach IS the recommended pattern. The library doesn't provide a cleaner callback API. We'll keep the current approach but add a clear comment explaining why.

### Data Flow (Complete)

```
SSO Login (SAML or OIDC)
  │
  ├─ 1. Extract stable ID:
  │     OIDC: sub + iss
  │     SAML: NameID (raw, preserve format)
  │
  ├─ 2. Extract email:
  │     OIDC: email claim (with email_verified check)
  │     SAML: from NameID (emailAddress format) or attributes
  │
  ├─ 3. Lookup user by stable ID
  │     ├─ Found → update email if changed
  │     └─ Not found → fall back to email lookup
  │          ├─ Found → link stable ID to existing user
  │          └─ Not found → JIT create user
  │
  ├─ 4. Extract groups from claims
  │     OIDC: groups claim from id_token
  │     SAML: group attribute from assertion
  │
  ├─ 5. Apply group mappings (every login):
  │     ├─ Remove old SSO-assigned distribution group memberships
  │     ├─ Add new SSO-assigned distribution group memberships
  │     ├─ Update admin_role (highest priority wins)
  │     └─ Update department_id
  │
  └─ 6. Issue tokens
```

### Scope

| Phase | What | Lines |
|-------|------|-------|
| 1 | Stable ID matching: schema + OIDC sub/iss + SAML NameID lookup | ~80 |
| 2 | Group claim extraction: OIDC groups scope + SAML attributes | ~60 |
| 3 | Group refresh on every login: apply/revoke mappings | ~70 |
| 4 | SAML cleanup: document middleware pattern, no code change | ~5 |
| Admin | Group mapping UI per IdP provider | ~60 |
| **Total** | | **~275 lines** |
