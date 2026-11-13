# SetJoin 部署指南（中文）

> 本文档涵盖 SetJoin 在中国市场的部署方案，包括国产化平台适配、信创认证路径、国内云服务商集成。

## 目录

1. [系统要求](#系统要求)
2. [支持的国产化平台](#支持的国产化平台)
3. [快速安装](#快速安装)
4. [数据库配置](#数据库配置)
5. [TLS 证书配置](#tls-证书配置)
6. [DNS 配置](#dns-配置)
7. [网络要求与 ICP 备案](#网络要求与-icp-备案)
8. [等保 (MLPS) 合规建议](#等保-mlps-合规建议)
9. [高可用部署](#高可用部署)
10. [监控与运维](#监控与运维)

---

## 系统要求

### 最小硬件配置

| 资源 | 最低要求 | 推荐配置 |
|------|----------|----------|
| CPU | 4 核 | 8 核及以上 |
| 内存 | 8 GB | 16 GB 及以上 |
| 磁盘 | 100 GB SSD | 500 GB NVMe SSD 及以上 |
| 网络 | 100 Mbps | 1 Gbps |

### 操作系统

SetJoin 支持以下操作系统：

| 操作系统 | 版本 | 架构 |
|----------|------|------|
| CentOS / RHEL | 7.9+, 8.x, 9.x | x86_64 |
| Ubuntu Server | 20.04 LTS, 22.04 LTS | x86_64 |
| Debian | 11 (Bullseye), 12 (Bookworm) | x86_64 |

---

## 支持的国产化平台

### 国产操作系统（信创适配）

| 操作系统 | 版本 | 说明 |
|----------|------|------|
| **麒麟 Kylin** | V10 (SP1/SP2) | 基于 openEuler，支持 x86_64 和 ARM64 (鲲鹏/飞腾) |
| **统信 UOS** | V20 (1050+) | 基于 Deepin，支持 x86_64 和 ARM64 |
| **openEuler** | 22.03 LTS+ | 华为开源操作系统，支持鲲鹏处理器 |

### 国产数据库

SetJoin 默认使用 PostgreSQL 作为主数据库。国产化环境中可选用：

| 数据库 | 版本 | 说明 |
|--------|------|------|
| **PolarDB for PostgreSQL** | PG 15+ | 基于 PostgreSQL，100% 原生兼容 |
| **GaussDB** | 3.x (openGauss) | 华为 cloud-native 数据库，PostgreSQL 协议兼容 |

**连接配置示例（PolarDB for PostgreSQL）：**

```bash
# PolarDB for PostgreSQL 使用标准 PostgreSQL 连接
DB_DSN="postgres://mail:password@polardb-host:5432/mailserver?sslmode=disable"
DB_DIRECT_DSN="postgres://mail:password@polardb-host:5432/mailserver?sslmode=disable"
```

**连接配置示例（PolarDB for PostgreSQL）：**

```bash
DB_DSN="postgres://mail:password@polardb-host:54321/mailserver"
DB_DIRECT_DSN="postgres://mail:password@polardb-host:54321/mailserver"
```

### 国产密码算法（国密）

SetJoin 支持 SM2/SM3/SM4 国密算法（详见 Stage 3.2）：

- **SM2**：用于 TLS 证书加密和数字签名（替代 RSA/ECC）
- **SM3**：用于数据完整性校验和密码哈希（替代 SHA-256）
- **SM4**：用于数据库字段级加密（替代 AES-256）

---

## 快速安装

### 使用安装脚本

```bash
# 克隆代码仓库
git clone https://github.com/your-org/setjoin.git /opt/setjoin

# 运行安装脚本
cd /opt/setjoin
sudo bash scripts/install.sh

# 按提示完成：
# 1. 选择安装类型（单机/集群）
# 2. 输入数据库连接信息
# 3. 配置域名和 TLS 证书
# 4. 设置管理员账户
```

### 手动安装步骤

1. **安装 PostgreSQL**（或/金仓数据库）

```bash
# CentOS/RHEL/Kylin
sudo dnf install -y postgresql16-server
sudo postgresql-16-setup initdb
sudo systemctl enable --now postgresql-16
```

2. **初始化数据库**

```bash
psql -U postgres -c "CREATE USER mail WITH PASSWORD 'your-password';"
psql -U postgres -c "CREATE DATABASE mailserver OWNER mail;"
cd /opt/setjoin/mailserver/sql/dbschema
psql -U mail -d mailserver -f V001__baseline.sql
# 然后应用前向迁移（V002+）：mailctl schema apply  （或 deploy/scripts/install.sh 一并完成）
```

3. **配置环境变量**

```bash
# /etc/setjoin/env.conf
LISTEN_ADDR=":80"
HOSTNAME="mail.example.com"
DB_DSN="postgres://mail:password@127.0.0.1:6432/mailserver"
DB_DIRECT_DSN="postgres://mail:password@127.0.0.1:5432/mailserver"
JWT_SECRET="your-jwt-secret-at-least-32-chars"
DB_ENCRYPTION_KEY="your-32-char-aes-encryption-key"
```

4. **启动服务**

```bash
bash scripts/dev.sh
# 或使用 systemd：
sudo systemctl start setjoin-gateway setjoin-authserver
```

---

## 数据库配置

### PostgreSQL 调优

针对中国市场的典型邮件负载（300-10,000 用户），建议以下 PostgreSQL 参数：

```ini
# postgresql.conf
shared_buffers = 4GB
effective_cache_size = 12GB
maintenance_work_mem = 1GB
wal_buffers = 64MB
work_mem = 64MB
random_page_cost = 1.1
effective_io_concurrency = 200
max_connections = 200
```

### PgBouncer 连接池

SetJoin 使用 PgBouncer 管理数据库连接池。在中国电信/联通/移动网络环境下，建议适当增加连接超时时间：

```ini
# pgbouncer.ini
pool_mode = transaction
default_pool_size = 25
max_client_conn = 200
server_idle_timeout = 600
query_timeout = 30
```

---

## TLS 证书配置

### 使用 Let's Encrypt（国际通用）

```bash
certbot certonly --standalone -d mail.example.com
# 证书路径：
# /etc/letsencrypt/live/mail.example.com/fullchain.pem
# /etc/letsencrypt/live/mail.example.com/privkey.pem
```

### 使用中国金融认证中心 (CFCA) 证书

```bash
# 向 CFCA（中国金融认证中心）或国内 CA 申请 SSL 证书
# 下载证书文件后配置：
TLS_CERT="/etc/setjoin/certs/cfca-cert.pem"
TLS_KEY="/etc/setjoin/certs/cfca-key.pem"
```

### 使用 SM2 国密证书（Stage 3.2）

```bash
# SM2 双证书模式：签名证书 + 加密证书
TLS_SIGN_CERT="/etc/setjoin/certs/sm2_sign.pem"
TLS_SIGN_KEY="/etc/setjoin/certs/sm2_sign_key.pem"
TLS_ENC_CERT="/etc/setjoin/certs/sm2_enc.pem"
TLS_ENC_KEY="/etc/setjoin/certs/sm2_enc_key.pem"
```

---

## DNS 配置

### 必备 DNS 记录

| 记录类型 | 名称 | 值 | 说明 |
|----------|------|-----|------|
| A | mail.example.com | `<服务器公网 IP>` | 邮件服务器地址 |
| MX | example.com | `mail.example.com` 优先级 10 | 邮件交换记录 |
| TXT | example.com | `v=spf1 mx -all` | SPF 记录 |
| TXT | default._domainkey.example.com | `v=DKIM1; k=rsa; p=<公钥>` | DKIM 记录 |
| TXT | _dmarc.example.com | `v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com` | DMARC 记录 |

### 国内 DNS 服务商

| 服务商 | 说明 |
|--------|------|
| DNSPod（腾讯云） | 国内最大的 DNS 托管服务 |
| 阿里云 DNS | 阿里云域名解析服务 |
| 华为云 DNS | 华为云域名解析服务 |
| CloudFlare（中国网络） | 与京东云合作的国内节点 |

### 国内网络注意事项

- 中国电信、联通、移动三网互联可能存在延迟，建议使用多线 BGP IP
- DNSSEC 配置可能受 GFW 影响，建议在国内 DNS 服务商处配置
- 部分地区的运营商可能拦截 SMTP 端口 25（仅企业宽带/专线开放）

---

## 网络要求与 ICP 备案

### ICP 备案

根据《互联网信息服务管理办法》，在中国大陆提供邮件服务需要完成 ICP 备案。

- **ICP 备案号**：向接入服务商（阿里云、腾讯云、华为云等）申请
- **公安备案**：根据《计算机信息网络国际联网安全保护管理办法》完成
- **邮件服务专项备案**：部分地区通信管理局要求邮件服务单独备案

### 端口开放

| 端口 | 协议 | 用途 | 国内可用性 |
|------|------|------|-----------|
| 25 | SMTP | 入站邮件接收 | 仅企业宽带/IDC 开放 |
| 465 | SMTPS | 加密邮件提交 | 通常开放 |
| 587 | SMTP | 邮件提交 (STARTTLS) | 推荐使用 |
| 993 | IMAPS | 加密邮件收取 | 通常开放 |
| 80 | HTTP | 网页邮箱访问 | 需 ICP 备案 |
| 443 | HTTPS | 加密网页访问 | 需 ICP 备案 |

---

## 等保 (MLPS) 合规建议

根据《信息安全技术 网络安全等级保护基本要求》（GB/T 22239-2019）：

### 等保二级要求（适用 300-1,000 用户部署）

- **身份鉴别**：启用密码 + MFA 双重认证
- **访问控制**：基于角色的访问控制 (RBAC)，管理员分权
- **安全审计**：启用审计日志，保存不少于 6 个月
- **通信保密性**：启用 TLS 1.2+ 加密
- **数据完整性**：使用 DKIM 签名确保邮件完整性

### 等保三级要求（适用 1,000+ 用户或政府/金融行业）

除二级要求外，还需满足：

- **双因子认证**：强制 MFA（TOTP 或 SM2 数字证书）
- **国密算法**：使用 SM2/SM3/SM4 国密算法套件
- **三权分立**：系统管理员、安全管理员、审计管理员分设
- **审计日志保存 12 个月以上**
- **数据备份与恢复**：异地备份、灾难恢复演练
- **入侵防范**：启用威胁检测管线（Spamhaus、GeoIP、密码喷洒检测等）
- **可信验证**：基于可信根的计算环境验证

---

## 高可用部署

### 推荐架构（500+ 用户）

```
                      ┌─────────────┐
                      │   负载均衡   │ (Nginx/HAProxy)
                      └──────┬──────┘
              ┌──────────────┼──────────────┐
        ┌─────┴─────┐  ┌─────┴─────┐  ┌─────┴─────┐
        │ Gateway 1 │  │ Gateway 2 │  │ Gateway 3 │
        └─────┬─────┘  └─────┬─────┘  └─────┬─────┘
              └──────────────┼──────────────┘
                      ┌──────┴──────┐
                      │   PgBouncer │
                      └──────┬──────┘
              ┌──────────────┼──────────────┐
        ┌─────┴─────┐  ┌─────┴─────┐  ┌─────┴─────┐
        │  PG 主库  │  │  PG 备库  │  │  PG 备库  │
        │(Pgpool-II)│  │(Pgpool-II)│  │(Pgpool-II)│
        └───────────┘  └───────────┘  └───────────┘
```

### 国内云服务商部署选项

| 云服务商 | 推荐产品 |
|----------|----------|
| **阿里云** | ECS (云服务器) + RDS PostgreSQL + SLB (负载均衡) + OSS (对象存储) |
| **华为云** | ECS + GaussDB + ELB + OBS |
| **腾讯云** | CVM + TencentDB for PostgreSQL + CLB + COS |

---

## 监控与运维

### 内置监控

SetJoin 提供 Prometheus 指标端点 (`/metrics`) 和健康检查端点 (`/health`, `/ready`)。

### 日志管理

- 应用日志：标准输出，支持 journald 或文件
- 审计日志：存储在数据库中，通过管理后台查看
- 日志轮转：建议使用 logrotate 管理日志文件

### 备份策略

- 数据库备份：使用 `pg_dump` 每日全量备份 + WAL 归档
- Blob 存储备份：SetJoin 内置增量备份引擎，支持 S3/OSS 目标

---

> 更多部署问题请参阅 [常见问题 (FAQ)](./faq.md)。
