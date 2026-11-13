# SetJoin 身份源与单点登录配置指南

> 本文档详细说明如何配置 SAML 2.0、OpenID Connect (OIDC)、LDAP 和 Kerberos 身份源，实现单点登录 (SSO)。

> **身份模型升级提示（V153–V172）：** Setjoin 现在把内部人员
> `users.id`、生命周期来源、SAML/OIDC 认证链接和邮箱地址分开管理。
> 邮箱、UPN、别名、姓名和工号只能作为冲突候选证据，不能自动建立身份
> 链接。标准化读取和身份转换默认关闭；升级数据库不会自动启用它们。
> 配置、盘点、转换、恢复和回滚请从
> [Identity Source Setup](../guides/IDENTITY_SOURCE_SETUP.md) 与
> [Identity Upgrade and Rollback](../guides/IDENTITY_UPGRADE_AND_ROLLBACK.md)
> 开始。

## 目录

1. [概述](#概述)
2. [SAML 2.0 配置](#saml-20-配置)
3. [OpenID Connect 配置](#openid-connect-配置)
4. [LDAP 配置](#ldap-配置)
5. [Kerberos/SPNEGO 配置](#kerberosspnego-配置)
6. [中国主流 IdP 集成](#中国主流-idp-集成)
7. [即时用户配置 (JIT)](#即时用户配置-jit)
8. [同步与维护](#同步与维护)

---

## 概述

SetJoin 支持以下身份认证方式（按优先级排序）：

| 优先级 | 方式 | 适用场景 |
|--------|------|----------|
| 1 | **JWT Bearer** | 已登录用户（网页、移动端） |
| 2 | **Kerberos/SPNEGO** | 域内 Windows 客户端 |
| 3 | **Basic Auth** | 传统邮件客户端（可禁用） |

外部身份提供者（SAML/OIDC/LDAP）认证成功后，用户获得 JWT，后续请求使用 JWT Bearer 方式。

---

## SAML 2.0 配置

### 配置步骤

1. 登录管理后台 → **身份源 (Identity)** → **添加身份源**
2. 选择类型为 **SAML 2.0**
3. 填写以下参数：

| 参数 | 说明 | 示例 |
|------|------|------|
| 名称 | 身份源显示名称 | `公司 AD FS` |
| 实体 ID (Entity ID) | SAML SP 的实体 ID（通常为 SetJoin 的 URL） | `https://mail.example.com/auth/saml/metadata` |
| 元数据 URL | IdP 的 SAML 元数据地址 | `https://adfs.example.com/FederationMetadata/2007-06/FederationMetadata.xml` |
| 签名证书 | IdP 的签名公钥证书 (PEM) | 从元数据中提取或手动粘贴 |

4. 启用即时用户配置 (JIT)
5. 保存并测试连接

### SP 元数据

SetJoin 的 SAML SP 元数据可通过以下 URL 获取：
```
https://<您的域名>/auth/saml/<idp名称>/metadata
```

将此 URL 提供给您的 IdP 管理员完成对接。

### 安全性

- SAML 响应签名验证：强制启用
- SAML 断言加密：支持（可选）
- 重放攻击防护：基于 InResponseTo 的原子性验证
- 签名算法：RSA-SHA256（默认），SM2-SM3（国密模式）

---

## OpenID Connect 配置

### 配置步骤

1. 登录管理后台 → **身份源 (Identity)** → **添加身份源**
2. 选择类型为 **OpenID Connect**
3. 填写以下参数：

| 参数 | 说明 |
|------|------|
| 名称 | 身份源显示名称 |
| 发行者 URL (Issuer) | OIDC 提供者的发行者地址 |
| 客户端 ID | 在 IdP 注册的客户端 ID |
| 客户端密钥 | 在 IdP 注册的客户端密钥 |
| 回调 URL | `https://<域名>/auth/oidc/callback` （自动生成） |

4. 启用即时用户配置 (JIT)
5. 保存

### OIDC 端点

SetJoin 同时可以作为 OIDC 提供者 (OP)，向第三方应用提供 OIDC 认证：

| 端点 | URL |
|------|-----|
| Discovery | `/.well-known/openid-configuration` |
| Authorization | `/authorize` |
| Token | `/token` |
| UserInfo | `/userinfo` |
| JWKS | `/jwks` |

---

## LDAP 配置

### 配置步骤

| 参数 | 说明 | 示例 |
|------|------|------|
| 名称 | 身份源显示名称 | `公司 AD` |
| 主机 | LDAP 服务器地址（LDAPS 端口 636） | `ldaps://dc01.example.com:636` |
| 基础 DN | 搜索的基础 DN | `DC=example,DC=com` |
| 绑定 DN | 用于绑定的用户 DN | `CN=ldap-reader,OU=Service,DC=example,DC=com` |
| 绑定密码 | 绑定用户的密码 | — |
| 用户过滤器 | LDAP 搜索过滤器 | `(&(objectClass=user)(mail=%s))` |
| 属性映射 | LDAP 属性 → 用户字段 | `mail→email, displayName→name` |

### TLS 要求

LDAP 连接必须使用 LDAPS (端口 636) 或 STARTTLS，不支持明文 LDAP。

---

## Kerberos/SPNEGO 配置

Kerberos/SPNEGO 适用于已加入 Active Directory 域的 Windows 客户端，提供无缝单点登录体验。

### 配置参数

| 参数 | 说明 |
|------|------|
| Realm | Kerberos Realm 名称（通常为大写的域名） |
| KDC | 域控制器地址 |
| Keytab 路径 | 服务主体 keytab 文件路径 |
| 服务主体名称 | 格式为 `HTTP/mail.example.com@EXAMPLE.COM` |

### 限制

- Kerberos 认证后的用户如果启用了 TOTP MFA，需要额外完成 MFA 验证
- 适用于内网环境（域内计算机），不支持跨域（Cross-Realm）认证

---

## 中国主流 IdP 集成

### 钉钉 (DingTalk)

钉钉支持 OIDC 协议，可作为 SetJoin 的身份源。

**配置参数：**
- 发行者 URL: `https://login.dingtalk.com`
- 客户端 ID / 密钥：在钉钉开放平台创建应用后获取
- 属性映射：`sub→external_id, email→email, name→displayName`

### 飞书 (Feishu/Lark)

飞书开放平台支持 OIDC 和 SAML。

**OIDC 配置：**
- 发行者 URL: `https://open.feishu.cn`
- 客户端 ID / 密钥：在飞书开放平台 → 应用凭证获取
- 回调 URL: `https://<域名>/auth/oidc/callback`

**SAML 配置：**
- 实体 ID：飞书 SP 实体 ID
- 元数据 URL：飞书 IdP 元数据地址

### 企业微信 (WeCom)

企业微信支持 OIDC 协议。

**配置参数：**
- 发行者 URL: `https://login.work.weixin.qq.com`
- 客户端凭证：在企业微信管理后台 → 应用管理获取
- 回调 URL: `https://<域名>/auth/oidc/callback`

### 微软 AD FS (Active Directory Federation Services)

**SAML 配置：**
- 元数据 URL: `https://adfs.example.com/FederationMetadata/2007-06/FederationMetadata.xml`
- 声明映射：`Name ID→external_id, E-Mail Address→email, Display Name→displayName`

### Azure AD / Microsoft Entra ID

**OIDC 配置：**
- 发行者 URL: `https://login.microsoftonline.com/<tenant-id>/v2.0`
- 客户端凭证：在 Azure Portal → App Registrations 获取

---

## 即时用户配置 (JIT)

启用 JIT 后，首次通过 SAML/OIDC 登录的用户会自动在 SetJoin 中创建账户。

**注意事项：**
- JIT 创建的用户默认状态为"启用"
- 初始配额从全局默认值继承
- JIT 用户不会设置密码（密码登录不适用），建议要求绑定 WebAuthn 或启用 MFA

---

## 同步与维护

### AD 同步引擎

SetJoin 内置 Active Directory 同步引擎，每 15 分钟自动同步一次：

- **同步内容**：用户账户、显示名称、邮箱、部门、启用/禁用状态
- **增量同步**：基于 `uSNChanged` 属性的增量更新
- **匹配策略**：通过 `objectGUID` 匹配用户（支持 AD 重命名）

### 同步状态监控

在身份源管理页面查看：
- 上次同步时间
- 同步用户数量
- 同步失败详情

### 手动同步

在身份源详情页点击 **立即同步** 按钮触发全量同步。

---

## 国密适配（Stage 3.2）

信创环境下，SAML/OIDC 集成可使用 SM2/SM3 算法：

- **SM2**：替代 RSA 用于 SAML 签名和 OIDC ID Token 签名
- **SM3**：替代 SHA-256 用于摘要计算
- **SM4**：替代 AES 用于加密传输

启用国密模式后，身份源的签名/加密算法自动切换为国密算法。
