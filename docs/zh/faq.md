# SetJoin 常见问题 (FAQ)

> 本文档汇总中国市场环境下的常见安装、配置和故障排除问题。

## 目录

1. [安装与部署](#安装与部署)
2. [数据库配置](#数据库配置)
3. [DNS 配置](#dns-配置)
4. [证书配置](#证书配置)
5. [邮件发送与接收](#邮件发送与接收)
6. [身份认证与 SSO](#身份认证与-sso)
7. [国产化平台适配](#国产化平台适配)
8. [性能优化](#性能优化)
9. [备份与恢复](#备份与恢复)
10. [合规与安全](#合规与安全)

---

## 安装与部署

### Q: 如何在麒麟 Kylin V10 上安装 SetJoin？

麒麟 Kylin V10 基于 openEuler/rpm 系，推荐使用编译安装：

```bash
# 安装 Go 编译环境
sudo dnf install -y golang

# 编译 authserver
cd /opt/setjoin/authserver
go build -o authserver ./cmd/authserver

# 编译 gateway
cd /opt/setjoin/mailserver/gateway
go build -o gateway ./cmd/gateway

# 安装 PostgreSQL 或数据库
sudo dnf install -y postgresql16-server
```

### Q: 如何在统信 UOS V20 上安装 SetJoin？

统信 UOS V20 基于 Debian，推荐使用 apt：

```bash
sudo apt install -y golang postgresql-16
```

其余步骤与标准 Debian/Ubuntu 安装相同。

### Q: 国内服务器无法访问 GitHub，如何获取源码？

- 使用 Gitee 镜像或内部 Git 服务器
- 通过国内 CDN 下载预编译的二进制包
- 使用离线安装包（包含所有依赖的 Go modules）

---

## 数据库配置

### Q: 如何使用 PolarDB for PostgreSQL？

PolarDB for PostgreSQL 基于 PostgreSQL，天然兼容：

```bash
DB_DSN="postgres://mail:password@polardb-server:54321/mailserver"
DB_DIRECT_DSN="postgres://mail:password@polardb-server:54321/mailserver"
```

### Q: 在中国电信/联通/移动网络下，数据库连接不稳定怎么办？

建议：
- 使用 PgBouncer 连接池减少连接数
- 增加连接超时时间：`server_idle_timeout=600`
- 启用连接健康检查
- 使用内网 IP 而非公网 IP 连接数据库

---

## DNS 配置

### Q: 在中国电信网络下，DNS 记录传播很慢怎么办？

- 使用国内 DNS 服务商（DNSPod、阿里云 DNS、华为云 DNS）
- 减小 TTL 值（在迁移前设置为 300 秒）
- 等待 24-48 小时让全国 DNS 缓存刷新

### Q: 中国联通的用户收不到邮件怎么办？

- 检查服务器 IP 是否在联通的黑名单中
- 联通对 25 端口管控较严，建议使用 587 端口提交外发邮件
- 联系联通申请 IP 白名单（需要提供 ICP 备案号和企业资质）

### Q: 中国移动（CMCC）的用户邮件被拦截怎么办？

- 中国移动使用独立的垃圾邮件过滤系统
- 确保 SPF、DKIM、DMARC 全部正确配置
- 向中国移动提交 IP 信誉申诉

---

## 证书配置

### Q: 应该使用哪个 CA 的 SSL 证书？

国际通用：
- Let's Encrypt（免费，自动续期）
- DigiCert / GeoTrust

国内推荐：
- **CFCA（中国金融认证中心）**：金融和政府行业首选
- **沃通 (WoSign)**：国内 CA
- **天威诚信 (iTrusChina)**：国内 CA
- 阿里云 SSL 证书、腾讯云 SSL 证书、华为云 SSL 证书

### Q: 如何配置 SM2 国密证书？

```bash
# .env 配置
TLS_SIGN_CERT="/etc/setjoin/certs/sm2_sign.pem"
TLS_SIGN_KEY="/etc/setjoin/certs/sm2_sign_key.pem"
TLS_ENC_CERT="/etc/setjoin/certs/sm2_enc.pem"
TLS_ENC_KEY="/etc/setjoin/certs/sm2_enc_key.pem"
```

SM2 证书需要向支持国密的 CA 申请（如 CFCA 国密证书）。

---

## 邮件发送与接收

### Q: 如何通过阿里云邮件推送服务发送邮件？

阿里云邮件推送（DirectMail）支持 SMTP 协议：

```bash
# 配置 SetJoin 通过阿里云 SMTP 中继外发邮件
SMTP_RELAY_HOST="smtpdm.aliyun.com"
SMTP_RELAY_PORT="465"
SMTP_RELAY_USER="你的阿里云 DirectMail 发信地址"
SMTP_RELAY_PASSWORD="阿里云 DirectMail SMTP 密码"
```

### Q: 如何通过腾讯云邮件推送服务发送邮件？

```bash
SMTP_RELAY_HOST="smtp.qcloudmail.com"
SMTP_RELAY_PORT="465"
SMTP_RELAY_USER="你的腾讯云邮件推送发信地址"
SMTP_RELAY_PASSWORD="腾讯云邮件推送 SMTP 密码"
```

### Q: 如何从网易企业邮/腾讯企业邮/阿里企业邮迁移到 SetJoin？

使用迁移管理功能：

1. 登录管理后台 → **迁移 (Migration)**
2. 点击 **新建迁移**
3. 选择源类型：
   - **网易企业邮**：IMAP 迁移 (`imap.qiye.163.com:993`)
   - **腾讯企业邮**：IMAP 迁移 (`imap.exmail.qq.com:993`)
   - **阿里企业邮**：IMAP 迁移 (`imap.qiye.aliyun.com:993`)
4. 输入源邮箱的账户密码（或管理员授权）
5. 启动迁移

**注意事项：**
- 部分企业邮服务商可能限制 IMAP 并发连接数
- 建议分批迁移（每次 50-100 个邮箱）
- 迁移完成前不要关闭源邮箱服务

---

## 身份认证与 SSO

### Q: 如何与钉钉集成 SSO？

SetJoin 支持钉钉 OIDC 协议。在钉钉开放平台创建应用后：
- 在 SetJoin 管理后台添加 OIDC 身份源
- 发行者 URL: `https://login.dingtalk.com`
- 填入客户端 ID 和密钥

### Q: 如何与飞书 (Feishu) 集成 SSO？

飞书支持 OIDC 和 SAML。推荐使用 OIDC：
- 在飞书开放平台创建企业自建应用
- 获取 App ID 和 App Secret
- 在 SetJoin 添加 OIDC 身份源

### Q: 如何与 Active Directory 集成？

1. 在管理后台 → **身份源** → 添加 LDAP 身份源
2. 配置 AD 连接参数：
   - 主机：`ldaps://dc01.example.com:636`
   - 基础 DN：`DC=example,DC=com`
   - 用户过滤器：`(&(objectClass=user)(mail=%s))`
3. 可选：启用 Kerberos/SPNEGO 实现域内 SSO

---

## 国产化平台适配

### Q: 信创认证需要哪些准备？

信创 (Xinchuang) 认证需要满足：
1. **操作系统**：麒麟 Kylin V10 或统信 UOS V20
2. **数据库**：PolarDB for PostgreSQL
3. **CPU 架构**：支持鲲鹏 920 (ARM64)、飞腾 2000/2500 (ARM64)、海光 (x86_64)
4. **密码算法**：SM2/SM3/SM4 国密算法 (Stage 3.2)
5. **浏览器**：360 安全浏览器、奇安信可信浏览器
6. **中间件**：东方通 TongWeb 或中创中间件（可选，SetJoin 内置 Go HTTP 服务器）

### Q: 是否支持在鲲鹏/飞腾处理器上运行？

支持。Go 原生支持 ARM64 架构编译：

```bash
GOOS=linux GOARCH=arm64 go build -o authserver ./cmd/authserver
GOOS=linux GOARCH=arm64 go build -o gateway ./cmd/gateway
```

---

## 性能优化

### Q: 3000 用户的部署需要什么配置？

推荐配置：
- CPU：16 核 (x86_64 或 ARM64)
- 内存：32 GB
- 磁盘：1 TB NVMe SSD
- 数据库连接池：50 个连接
- 负载均衡：2-3 个 Gateway 实例

### Q: 邮件搜索很慢怎么办？

- 确保 PostgreSQL 的 `shared_buffers` 和 `effective_cache_size` 配置合理
- 在搜索字段上创建适当的索引
- 使用内容搜索的 KQL 查询限定日期范围
- 考虑使用 PostgreSQL 全文搜索 (tsvector)

---

## 备份与恢复

### Q: 如何备份到阿里云 OSS？

```bash
# .env 配置
BACKUP_PROVIDER="oss"
BACKUP_ENDPOINT="https://oss-cn-hangzhou.aliyuncs.com"
BACKUP_BUCKET="setjoin-backup"
BACKUP_ACCESS_KEY="你的阿里云 AccessKey ID"
BACKUP_SECRET_KEY="你的阿里云 AccessKey Secret"
BACKUP_REGION="cn-hangzhou"
```

### Q: 如何备份到华为云 OBS？

```bash
BACKUP_PROVIDER="s3"          # OBS 兼容 S3 协议
BACKUP_ENDPOINT="https://obs.cn-north-4.myhuaweicloud.com"
BACKUP_BUCKET="setjoin-backup"
BACKUP_ACCESS_KEY="你的华为云 AK"
BACKUP_SECRET_KEY="你的华为云 SK"
```

---

## 合规与安全

### Q: 如何满足等保三级要求？

参考 [合规功能说明](./compliance-features.md) 中的等保映射表，关键措施：
1. 启用 MFA 双因子认证（等保三级强制要求）
2. 配置国密算法（SM2/SM3/SM4）
3. 启用审计日志并保留 12 个月以上
4. 配置异地备份
5. 实施三权分立（超级管理员/用户管理员/只读管理员/审计员）

### Q: 如何配置 DLP 防止个人信息泄露？

在管理后台 → **功能开关** → DLP 中启用，然后配置规则：
- 身份证号正则：`[1-9]\d{5}(19|20)\d{2}(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])\d{3}[\dXx]`
- 手机号正则：`1[3-9]\d{9}`
- 银行卡号正则：`\d{16,19}`

违反 DLP 规则的邮件将被拦截或隔离。

### Q: 邮件需要留存多久？

- 《网络安全法》要求网络日志留存不少于 6 个月
- 等保二级建议邮件留存 1 年以上
- 等保三级建议关键业务邮件留存 3-7 年
- 金融行业（银保监会要求）建议留存 5 年以上
- 建议在保留策略中设置分层保留规则

---

> 如有其他问题，请联系 SetJoin 技术支持团队或查阅英文文档。
