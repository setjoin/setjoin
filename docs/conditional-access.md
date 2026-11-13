# Conditional Access — Operator Guide

setjoin Conditional Access (CA) lets you define sign-in policies that evaluate
context (device trust, location, role, auth strength) and apply a grant
(`allow`, `block`, `step_up`, `notify`, `require_acr`, `require_strength`).
Policies are evaluated in priority order; the first match wins.

**Audience:** IT administrators and security engineers deploying setjoin for
300–10,000-user organisations.

---

## Contents

1. [Quickstart](#1-quickstart)
2. [Concepts](#2-concepts)
3. [Policy document format](#3-policy-document-format)
4. [Cookbook](#4-cookbook)
5. [Safe-rollout guide](#5-safe-rollout-guide)
6. [Policy repo and CI](#6-policy-repo-and-ci)
7. [Starter packs](#7-starter-packs)
8. [等保三级 / 三权分立 mapping](#8-等保三级--三权分立-mapping)
9. [Error reference](#9-error-reference)
10. [Break-glass](#10-break-glass)

---

## 1. Quickstart

```bash
# 1. Check CA health and see your time-to-first-policy
mailctl ca doctor

# 2. Start from a starter pack. MFA baselines install in report_only, but each
#    pack also ships enforcing guardrails (e.g. the high-risk country block
#    lands in `on`), so configure break-glass first (§5 Step 1).
mailctl ca install-pack docs/starter-packs/minimal-safe.json

# 3. Simulate a user to verify the policy fires as expected
mailctl ca simulate --user alice@corp.example --expect allow

# 4. Review sign-in log to confirm coverage and would_block counts
mailctl ca signin-log --limit 20

# 5. Promote a policy from report_only → on (enforced)
#    The promote command fetches impact first; refuses when --yes is absent
#    and would_block > 0, so you always see blast radius before committing.
mailctl ca promote --id 1 --yes

# 6. Run coverage to find any gaps
mailctl ca coverage --fail-on-gap
```

See §5 (Safe-rollout guide) for the full promotion sequence, including the
break-glass step that must come first.

---

## 2. Concepts

### Named locations

A **named location** is a labelled set of IP CIDR ranges (e.g. "Corporate
Network"). Policies reference locations by slug:

```json
{"conditions": {"location_in": ["corp-network"]}}
```

Manage via: `GET/POST/PUT/DELETE /admin/conditional-access/named-locations` or
the admin console → Conditional Access → Locations.

### Auth strengths

An **auth strength** is a named set of acceptable MFA factor combinations.
Built-in strengths: `phishing-resistant` (WebAuthn/passkey), `passwordless`,
`mfa` (any second factor). Admins can define custom strengths with specific
factor combinations.

Policies reference strengths by slug:

```json
{"actions": {"grants": [{"type": "require_strength", "strength_slug": "phishing-resistant"}]}}
```

### Policy states

| State | Effect |
|-------|--------|
| `report_only` | Evaluates and logs; never blocks. Safe for testing. |
| `on` | Enforced: grant actions are applied to sign-ins. |
| `off` | Disabled; skipped during evaluation. |

Always start new policies in `report_only` and promote with `mailctl ca promote`.

### Grant types

| Type | Effect |
|------|--------|
| `allow` | Permit the sign-in (short-circuit; stops evaluation) |
| `block` | Deny the sign-in (BZ080 guard prevents admin lockout) |
| `step_up` | Require an additional auth factor interactively |
| `notify` | Log a security alert; sign-in proceeds |
| `require_acr` | Require a minimum ACR level (e.g. `aal2` = MFA) |
| `require_strength` | Require a named auth strength |

### Condition keys

| Key | Values |
|-----|--------|
| `device_trust` | `managed`, `compliant`, `unmanaged` |
| `ip_reputation` | `clean`, `suspicious`, `malicious` |
| `geo_risk_tier` | `low`, `medium`, `high` |
| `user_group` | group slug or role name |
| `auth_method` | `password`, `webauthn`, `totp`, `push` |
| `client_type` | `webmail`, `imap`, `caldav`, `api` |
| `time_of_day` | `{"start":"09:00","end":"17:00","tz":"UTC"}` |
| `location_in` | array of named-location slugs |
| `location_trusted` | `true` / `false` |
| `device_platform` | `windows`, `macos`, `ios`, `android`, `linux` |
| `country_in` | ISO 3166-1 alpha-2 codes |
| `auth_strength` | named auth-strength slug |

---

## 3. Policy document format

The CA export format (`schemaVersion: 1`) is the interchange format for
`mailctl ca export/import/apply/diff`. It is also the format used by the CI
pipeline and the example policy repo.

```json
{
  "schemaVersion": 1,
  "named_locations": [
    {
      "slug": "corp-network",
      "name": "Corporate Network",
      "ip_ranges": ["10.0.0.0/8", "192.168.0.0/16"]
    }
  ],
  "auth_strengths": [
    {
      "slug": "phishing-resistant",
      "name": "Phishing-Resistant MFA",
      "builtin": true,
      "combinations": [["webauthn"], ["passkey"]]
    }
  ],
  "policies": [
    {
      "name": "Require MFA — All Users",
      "description": "Baseline: require MFA for every sign-in.",
      "priority": 100,
      "state": "on",
      "scope": {"type": "global"},
      "conditions": {},
      "actions": {"grants": [{"type": "require_acr", "acr": "aal2"}]}
    }
  ]
}
```

Validate offline before pushing to a server:

```bash
mailctl ca validate my-policies.json          # exit 0 = valid
mailctl ca validate --strict my-policies.json # warnings become errors
mailctl ca fmt my-policies.json               # canonically format (stable key order)
```

---

## 4. Cookbook

These are production-ready policy patterns. Sections 4.1–4.3 are committed as
`docs/examples/conditional-access-policy-repo/.policy/cookbook.json`, where all
three policies ship in the enforcing `on` state — importing the cookbook
applies them immediately, with no report_only observation window. Sections
4.4–4.6 are patterns to copy into your own policy document; they are not part
of the committed cookbook. The cookbook's agreement with the samples in this
guide is machine-verified by `mailctl/ca_docs_consistency_test.go`
(`TestCADocSamplesMatchCommittedCookbook`); schema validity of the format
sample is kept green by `mailctl/ca_roundtrip_test.go`.

### 4.1 Baseline MFA for all users

Every sign-in requires a second factor. The committed cookbook ships this
baseline in the enforcing `on` state shown below; applying it enforces MFA on
the next sign-in. If you need an observation window first, install the same
policy from the minimal-safe starter pack (it lands in `report_only`) or set
the state to `report_only` before applying, then promote once you have
confirmed your users have MFA enrolled.

```json
{
  "name": "Require MFA — All Users",
  "priority": 100,
  "state": "on",
  "scope": {"type": "global"},
  "conditions": {},
  "actions": {"grants": [{"type": "require_acr", "acr": "aal2"}]}
}
```

Promote from `report_only`: `mailctl ca promote --id <id>`. The promote command
fetches impact first; without `--yes` it refuses when `would_block > 0`, naming
the blocked-user count in the refusal — that refusal is the only blast-radius
display it gives. `--yes` skips the impact display and promotes even when users
would be blocked; reserve it for automation, and treat supplying it as the
operator's recorded obligation to have reviewed the blast radius first (request
the same `GET /admin/conditional-access/policies/<id>/impact` the promote
command uses before passing `--yes`).

### 4.2 Block high-risk countries

```json
{
  "name": "Block High-Risk Countries",
  "priority": 200,
  "state": "on",
  "scope": {"type": "global"},
  "conditions": {"country_in": ["KP", "IR", "CU"]},
  "actions": {"grants": [{"type": "block"}]}
}
```

### 4.3 Phishing-resistant MFA for admins

Require WebAuthn or passkey for all users in the `admin` role group.

```json
{
  "name": "Phishing-Resistant for Admins",
  "priority": 300,
  "state": "on",
  "scope": {"type": "group", "target": "role:admin"},
  "conditions": {},
  "actions": {"grants": [{"type": "require_strength", "strength_slug": "phishing-resistant"}]}
}
```

### 4.4 Allow corporate network without step-up

Users already on-network (inside corp-network named location) are allowed
without additional MFA. Place this **before** the MFA-all policy.

```json
{
  "name": "Allow Corporate Network",
  "priority": 50,
  "state": "on",
  "scope": {"type": "global"},
  "conditions": {"location_in": ["corp-network"]},
  "actions": {"grants": [{"type": "allow"}]}
}
```

### 4.5 Step-up on new devices

Require an additional factor when the device is unmanaged (not enrolled in
device management). This keeps the MFA policy from blocking managed device
users while still protecting unmanaged access.

```json
{
  "name": "Step-Up on Unmanaged Device",
  "priority": 400,
  "state": "report_only",
  "scope": {"type": "global"},
  "conditions": {"device_trust": "unmanaged"},
  "actions": {"grants": [{"type": "step_up"}]}
}
```

### 4.6 Notify on suspicious IP

Log a security alert when a sign-in originates from a suspicious IP (without
blocking — pair with your SIEM). Safe to run `on` from day one.

```json
{
  "name": "Notify on Suspicious IP",
  "priority": 500,
  "state": "on",
  "scope": {"type": "global"},
  "conditions": {"ip_reputation": "suspicious"},
  "actions": {"grants": [{"type": "notify"}]}
}
```

### 4.7 The committed cookbook document

The committed `cookbook.json` contains the three core policies above — the 4.1
MFA baseline, the 4.2 high-risk country block, and the 4.3 phishing-resistant
admins policy — all in the enforcing `on` state. Importing it enforces them
immediately; there is no report_only observation window. Complete the §5 Step 1
break-glass configuration and run `mailctl ca diff` before importing. Its
consistency with the samples in this guide is machine-verified by
`TestCADocSamplesMatchCommittedCookbook` in
`mailctl/ca_docs_consistency_test.go`, and the cookbook shape is kept
schema-valid by `TestCARoundTripExportSampleValidatesOffline` in
`mailctl/ca_roundtrip_test.go`.

```bash
# Export your live server state
mailctl ca export > live.json

# Apply the cookbook as a baseline (merge mode leaves custom policies in place)
mailctl ca import -f docs/examples/conditional-access-policy-repo/.policy/cookbook.json --mode merge

# Diff to verify what would change before applying
mailctl ca diff -f docs/examples/conditional-access-policy-repo/.policy/cookbook.json
```

---

## 5. Safe-rollout guide

Deploying conditional access incorrectly can lock out all users including
administrators. Follow this sequence.

### Step 1 — Designate break-glass users (MANDATORY FIRST)

Before enabling any `on`-state block policy, register at least one break-glass
admin. Break-glass users are excluded from every CA policy evaluation.

```bash
# List current break-glass users
mailctl ca doctor | grep break_glass

# Set break-glass via admin console:
#   Admin → Conditional Access → Break-glass → Add user
# Or via API: PUT /admin/conditional-access/break-glass
```

See §10 (Break-glass) for full instructions.

### Step 2 — Install a starter pack

```bash
# Minimal safe: MFA baseline installs in report_only; the high-risk country
# block ships enforcing (on) — break-glass (Step 1) must already be in place.
mailctl ca install-pack docs/starter-packs/minimal-safe.json
```

### Step 3 — Monitor in report_only

Run `mailctl ca signin-log --limit 100` and review the `would_block` count per
policy. Let policies run in `report_only` for at least 7 days before promoting.

### Step 4 — Simulate targeted users

```bash
mailctl ca simulate --user alice@corp.example --expect allow
mailctl ca simulate --user contractor@external.example --expect step_up
```

### Step 5 — Promote one policy at a time

```bash
# The promote command fetches impact and refuses without --yes when would_block > 0.
mailctl ca promote --id 1

# Or, if you have reviewed the blast radius and are ready:
mailctl ca promote --id 1 --yes
```

### Step 6 — Validate coverage

```bash
mailctl ca coverage --fail-on-gap
mailctl ca doctor
```

---

## 6. Policy repo and CI

See `docs/examples/conditional-access-policy-repo/` for a complete skeleton.

### Repo structure

```
.policy/
  cookbook.json          # committed policy document (schemaVersion: 1)
  minimal-safe.json      # starter pack symlink (or copy)
.ci/
  conditional-access.yml # GitHub Actions / Gitea Actions workflow
.pre-commit-hooks.yaml   # pre-commit hook definition
.gitignore
README.md
```

### CI workflow (`.ci/conditional-access.yml`)

The CI workflow runs `mailctl ca validate` + `mailctl ca diff` on every push
and pull request. On merge to `main` it applies the policy to the target server.

```yaml
# .ci/conditional-access.yml — see docs/examples/conditional-access-policy-repo/
# for the full file; key steps:
#
#   validate:  mailctl ca validate --strict .policy/*.json
#   diff:      mailctl ca diff     -f .policy/policies.json  # exit 2 = drift
#   apply:     mailctl ca apply    -f .policy/policies.json  # merge to main only
#   coverage:  mailctl ca coverage --fail-on-gap
```

### Pre-commit hook

The pre-commit hook runs `mailctl ca validate --strict` on any staged
`.policy/*.json` file so policy authors get instant feedback without a
round-trip to CI.

```bash
# Install
pip install pre-commit
pre-commit install

# Run manually
pre-commit run ca-validate --all-files
```

---

## 7. Starter packs

Three starter packs are provided under `docs/starter-packs/`. Each pack is a
valid CA export document (schemaVersion: 1) installable with
`mailctl ca install-pack`.

| Pack | File | Contents and shipped states |
|------|------|-----------------------------|
| Minimal safe | `minimal-safe.json` | MFA baseline (`report_only`) + high-risk country block (`on`) |
| CIS-style | `cis-style.json` | MFA, admin phishing-resistant, unmanaged-device step-up (`report_only`); suspicious-IP notify, malicious-IP and high-risk-country blocks (`on`) |
| 等保三级 | `dengbao-level3.json` | Identity/access controls: five baselines (`report_only`); high-risk country block and suspicious-IP alert ship `on` |

Only the MFA/step-up baselines install in `report_only`. Each pack also ships
enforcing guardrail policies (see the table), so an install activates deny and
alert coverage immediately — complete the §5 Step 1 break-glass configuration
before installing any pack.

Install:

```bash
mailctl ca install-pack docs/starter-packs/minimal-safe.json
mailctl ca install-pack docs/starter-packs/cis-style.json
mailctl ca install-pack docs/starter-packs/dengbao-level3.json
```

Verify the pack checksums before installing in air-gapped environments:

```bash
sha256sum -c docs/starter-packs/minimal-safe.json.sha256
sha256sum -c docs/starter-packs/cis-style.json.sha256
sha256sum -c docs/starter-packs/dengbao-level3.json.sha256
```

---

## 8. 等保三级 / 三权分立 mapping

GB/T 22239-2019 (信息安全技术 网络安全等级保护基本要求) 第三级要求对身份鉴别和
访问控制有明确规定。本节将等保三级相关条款映射到 setjoin CA 策略。

### 8.1 身份鉴别 (Identity Authentication)

| 等保条款 | 要求摘要 | setjoin CA 控制 |
|----------|----------|-----------------|
| 7.1.2.1 a) | 用户身份鉴别，口令长度≥8位，包含大小写、数字、特殊字符 | 密码策略在 `系统配置 → 密码规则` 中配置；CA 可附加 `require_acr: aal2` 强制多因子 |
| 7.1.2.1 b) | 重要操作需双因子鉴别 | `require_acr: aal2` 或 `require_strength: phishing-resistant` |
| 7.1.2.1 c) | 身份鉴别信息加密传输 | TLS 1.2+ 由网关强制；CA 策略不涉及 |
| 7.1.2.1 d) | 登录失败处理（连续失败锁定） | 由 authserver 账户锁定策略处理；CA 策略添加 `notify` 辅助告警 |
| 7.1.2.1 e) | 用户身份标识唯一性 | 每个邮箱账号唯一；CA scope 支持按用户/组/域划分 |

推荐策略（已含于 `dengbao-level3.json` 包）：

```json
{
  "name": "等保三级：双因子鉴别",
  "priority": 100,
  "state": "report_only",
  "scope": {"type": "global"},
  "conditions": {},
  "actions": {"grants": [{"type": "require_acr", "acr": "aal2"}]}
}
```

### 8.2 访问控制 (Access Control)

| 等保条款 | 要求摘要 | setjoin CA 控制 |
|----------|----------|-----------------|
| 7.1.2.2 a) | 自主访问控制，授权用户才能访问 | CA scope 按用户、角色组、域细分 |
| 7.1.2.2 b) | 对重要文件设置访问权限 | 邮件 RBAC + CA `user_group` 条件限制高权限组 |
| 7.1.2.2 c) | 访问控制信息防止被未授权修改 | CA 策略写入需 `access.policy_write` 权限 |
| 7.1.2.2 d) | 对特权账号实施严格管理 | `role:admin` scope + `require_strength: phishing-resistant` |

### 8.3 三权分立 (Separation of Duties — 系统管理员 / 安全管理员 / 审计管理员)

setjoin 通过 RBAC + CA 策略支持三权分立模型：

| 角色 | RBAC 权限 | 推荐 CA 控制 |
|------|-----------|-------------|
| 系统管理员 (sysadmin) | 用户/域/配置管理 | `require_strength: phishing-resistant` + 仅允许公司网络访问 |
| 安全管理员 (secadmin) | CA 策略 / 审计日志 / 威胁管理 | `require_strength: phishing-resistant` + `notify` 每次登录 |
| 审计管理员 (auditadmin) | 只读审计日志 | `require_acr: aal2` + 可选 IP 限制 |

示例策略片段（安全管理员）：

```json
{
  "name": "三权分立：安全管理员强鉴别",
  "priority": 250,
  "state": "report_only",
  "scope": {"type": "group", "target": "role:secadmin"},
  "conditions": {},
  "actions": {
    "grants": [
      {"type": "require_strength", "strength_slug": "phishing-resistant"},
      {"type": "notify"}
    ]
  }
}
```

### 8.4 安全审计 (Security Audit)

| 等保条款 | setjoin 能力 |
|----------|-------------|
| 7.1.2.5 a) 对用户行为、异常操作进行审计 | `mailctl ca signin-log` + CA `notify` 动作触发告警 |
| 7.1.2.5 b) 审计记录保护 | admin_audit_log 写后不可删（RLS R3 保护） |
| 7.1.2.5 c) 定期分析和审查 | `mailctl ca coverage --fail-on-gap` + `ca doctor` |

### 8.5 本节附注

- 等保测评时建议先以 `report_only` 状态运行，观察 7 天后再提升为 `on`。
- `dengbao-level3.json` 中身份鉴别、三权分立与步进鉴别策略以 `report_only` 安装；高风险地区阻断与可疑 IP 告警随包即为 `on`。安装前请先完成 §5 Step 1 的 break-glass 配置。
- 安装：`mailctl ca install-pack docs/starter-packs/dengbao-level3.json`

---

## 9. Error reference

CA errors follow the `BZ0nn` pattern. Use `mailctl ca explain <BZnnn>` for
offline plain-English explanations.

| Code | Summary | Resolution |
|------|---------|-----------|
| BZ080 | CA lockout guard — would lock out all break-glass users | Add a break-glass user before enabling a block policy |
| BZ081 | Resource not found — policy, named location, or auth strength | Check IDs/slugs; use `ca list` |
| BZ082 | Break-glass set empty — replacement set has zero users | Provide at least one user_id in the replacement set |
| BZ085 | Unknown template slug / invalid grant type / condition key | See `mailctl ca validate`; check the schema in §3 |
| BZ086 | Audit row missing — promote/rollback references absent audit row | Verify the audit_log entry exists |
| BZ087 | Priority conflict — slot held by a live policy | Reorder with `ca reorder` first |
| BZ088 | Import schemaVersion mismatch | Re-export from a compatible server or update schemaVersion |
| BZ089 | Name collision in merge mode | Rename the policy or switch to replace mode |
| BZ090 | Invalid import document shape | Check required fields; use `ca validate` |
| BZ091 | Unknown slug reference in import | Add the referenced named_location or auth_strength to the document |
| BZ092 | Invalid import mode | Use `merge`, `replace`, or `prune` |
| BZ093 | Named location restore name clash | Rename or delete the conflicting location |
| BZ094 | Built-in auth-strength mutation guard | Create a custom auth strength instead of modifying built-ins |

Full offline explanations: `mailctl ca explain BZ080` through `BZ094`.

---

## 10. Break-glass

**The break-glass set must be configured BEFORE you activate any `on`-state
block policy.** This is not optional.

Break-glass users are excluded from every CA policy evaluation, including
fail-closed branches. They are your recovery path if a policy misconfiguration
locks out all other administrators.

### Configure break-glass

```bash
# Check current break-glass users
curl -H "Authorization: Bearer $TOKEN" \
  https://mail.corp.example/admin/conditional-access/break-glass

# Set break-glass users (replaces the entire set)
curl -X PUT -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"user_ids": ["00000000-0000-0000-0000-000000000001"]}' \
  https://mail.corp.example/admin/conditional-access/break-glass

# Or via admin console:
# Admin → Conditional Access → Break-glass → Add user
```

### Break-glass operational hygiene

- Maintain at least **two** break-glass accounts in separate auth silos.
- Break-glass accounts should use phishing-resistant credentials (hardware keys).
- Audit break-glass logins: `mailctl ca signin-log --user breakglass@corp.example`
- Test break-glass accounts monthly (ensure they can still sign in).
- All break-glass set writes are recorded in `admin_audit_log` (`action='ca_break_glass_set'`).

### Recovery procedure

If you are locked out and cannot sign in normally:

1. Sign in with a break-glass account (exempt from all CA policies).
2. Navigate to Admin → Conditional Access.
3. Set the offending policy to `off` or `report_only`.
4. Investigate the cause using `mailctl ca doctor` and `mailctl ca signin-log`.
5. Re-promote only after the root cause is resolved and blast-radius re-checked.

See also: `docs/standards/CONDITIONAL_ACCESS_BREAK_GLASS.md`
