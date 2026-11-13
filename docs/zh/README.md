# SetJoin 管理文档（中文）

本目录包含面向中国系统管理员的 SetJoin 邮件系统管理文档。

## 文档索引

| 文档 | 说明 |
|------|------|
| [admin-console-guide.md](./admin-console-guide.md) | 管理控制台完整操作指南，涵盖全部 27 个管理模块 |
| [deployment-guide.md](./deployment-guide.md) | 部署指南，包含国产化平台（信创）适配说明 |
| [identity-sso-guide.md](./identity-sso-guide.md) | 身份源与单点登录配置指南（SAML/OIDC/Kerberos/LDAP） |
| [security-features.md](./security-features.md) | 安全功能说明（DLP、反垃圾邮件、DKIM/DMARC/SPF、隔离、频率限制） |
| [compliance-features.md](./compliance-features.md) | 合规功能说明（电子取证、内容搜索、保留策略、归档、审计日志） |
| [faq.md](./faq.md) | 常见问题与故障排除（中国市场场景） |

## 目标读者

- 企业 IT 系统管理员
- 信息安全管理员
- 合规审计人员
- 运维工程师

## 术语约定

本系列文档遵循以下术语规范：

| 英文术语 | 中文术语 | 说明 |
|----------|----------|------|
| Mailbox | 邮箱 | 不使用"邮件箱" |
| Administrator | 管理员 | 不使用"行政" |
| Console | 控制台 | 使用"管理后台"或"控制台" |
| Domain | 域 / 域名 | 根据上下文选用 |
| Compliance | 合规 | — |
| Audit | 审计 | — |
| eDiscovery | 电子取证 | — |
| Content Search | 内容搜索 | — |
| Retention Policy | 保留策略 | — |
| Migration | 迁移 | — |
| Trace | 跟踪 | — |
| Quarantine | 隔离 | — |
| Dashboard | 仪表盘 | — |
| Webhook | Webhook | 保留英文（业内通用） |
| DMARC | DMARC | 保留英文（协议名称） |
| SAML | SAML | 保留英文（协议名称） |
| OIDC | OIDC | 保留英文（协议名称） |
| LDAP | LDAP | 保留英文（协议名称） |

## 信创（Xinchuang）兼容性

SetJoin 已完成以下信创适配：

- **操作系统**：麒麟 Kylin V10、统信 UOS V20
- **数据库**：PolarDB for PostgreSQL
- **密码算法**：SM2/SM3/SM4 国密算法支持（Stage 3.2）
- **浏览器**：360 安全浏览器、奇安信可信浏览器

---

返回英文文档：[../README.md](../README.md)
