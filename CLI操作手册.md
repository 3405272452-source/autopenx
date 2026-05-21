# AutoPenX CLI 操作手册

## 快速开始

```bash
# SSH 连入 Kali
ssh kali-vm

# 查看帮助
autopenx --help

# 列出所有工具
autopenx --list-tools

# 查看版本
autopenx --version
```

## 扫描模式

### 1. 被动扫描（默认）
```bash
autopenx -t http://target.com -y
```
只做信息收集，不发攻击性请求。

### 2. 主动扫描
```bash
autopenx -t http://target.com --scan-mode active --allow-external-tools -y
```
包含目录爆破、参数 fuzz、nmap 扫描等。

### 3. 全量扫描 + 漏洞利用
```bash
autopenx -t http://target.com --scan-mode active --allow-external-tools --enable-exploit -y
```
完整渗透测试流程：侦察 → 扫描 → 漏洞检测 → 漏洞利用。

### 4. Mock 模式（离线，不调 LLM）
```bash
autopenx -t http://target.com --mock --allow-external-tools -y
```
纯规则驱动，不需要 DeepSeek API Key。

## 完整参数表

| 参数 | 缩写 | 说明 | 默认值 |
|------|------|------|--------|
| `--target` | `-t` | 目标 URL 或主机名 | 必填 |
| `--scan-mode` | | `passive` 或 `active` | `active` |
| `--allow-external-tools` | | 允许 nmap/sqlmap/ffuf 等外部工具 | 否 |
| `--allow-local-targets` | | 允许扫描本地/内网目标 | 否 |
| `--enable-exploit` | | 启用漏洞利用阶段 | 否 |
| `--mock` | | 离线模式，不调用 LLM | 否 |
| `--out` | `-o` | Markdown 报告输出路径 | `reports/<时间戳>.md` |
| `--html` | | HTML 报告输出路径 | 同名 `.html` |
| `--json` | | JSON 原始数据输出路径 | 无 |
| `--max-iter` | | 每阶段最大迭代次数 | 6 |
| `--quiet` | `-q` | 减少控制台输出 | 否 |
| `--yes` | `-y` | 跳过授权确认（CI 模式） | 否 |
| `--list-tools` | | 列出所有工具后退出 | |
| `--version` | `-V` | 显示版本后退出 | |

## 工具分类（32 个）

### 侦察 (recon) — 6 个
| 工具 | 说明 |
|------|------|
| `port_scan` | TCP 端口快速扫描 |
| `tech_detect` | Web 技术栈识别 |
| `subdomain_find` | 被动子域名枚举 (crt.sh) |
| `nmap_scan` | Nmap 服务与端口识别 |
| `headers_audit` | 安全响应头审计 |
| `gowitness` | 目标页面截图 |

### 扫描 (scan) — 5 个
| 工具 | 说明 |
|------|------|
| `web_scan` | 敏感文件与响应头扫描 |
| `dir_buster` | 内置目录爆破 |
| `crawl` | 页面与参数爬取 |
| `ffuf_scan` | ffuf 高速内容发现 |
| `burp_proxy_scan` | Burp 代理重放 |

### 漏洞检测 (vuln) — 12 个
| 工具 | 说明 |
|------|------|
| `sqli_detect` | SQL 注入检测 |
| `xss_detect` | 反射型 XSS 检测 |
| `ssrf_detect` | SSRF 检测 |
| `cmdi_detect` | 命令注入检测 |
| `sqlmap_scan` | sqlmap 定向确认 |
| `param_fuzzer` | SSTI/LFI/XXE/CRLF/原型污染 fuzz |
| `logic_audit` | 业务逻辑漏洞审计 |
| `js_analyze` | JavaScript 安全分析 |
| `rate_limit_test` | 限速/时序/竞态测试 |
| `idor_test` | IDOR 自动发现 |
| `nuclei_scan` | Nuclei 模板扫描 |
| `session_manager` | 会话管理 |

### 漏洞利用 (exploit) — 8 个
| 工具 | 说明 |
|------|------|
| `sqli_exploit` | SQL 注入利用 |
| `xss_exploit` | XSS 利用 |
| `auth_bypass` | 认证绕过 |
| `file_upload_exploit` | 文件上传利用 |
| `privilege_escalation` | 权限提升 |
| `finding_replay` | 漏洞重放 |
| `hydra_crack` | Hydra 暴力破解 |
| `session_manager` | 会话管理 |

### 浏览器 (browser) — 1 个
| 工具 | 说明 |
|------|------|
| `browser_test` | Playwright SPA/XSS/DOM 测试 |

### Docker (docker) — 1 个
| 工具 | 说明 |
|------|------|
| `docker_exec` | 容器内任意命令执行 |

## 实战示例

### 扫描公开靶场 (授权测试)
```bash
# 完整扫描 testphp.vulnweb.com
autopenx -t http://testphp.vulnweb.com \
  --scan-mode active \
  --allow-external-tools \
  --enable-exploit \
  --allow-local-targets \
  -y

# 报告会生成在 reports/ 目录
ls reports/
```

### 快速侦察
```bash
autopenx -t http://target.com --scan-mode passive -y --quiet
```

### 生成 JSON 数据
```bash
autopenx -t http://target.com -y --json results.json
```

## 输出文件

- `reports/<时间戳>.md` — Markdown 报告
- `reports/<时间戳>.html` — HTML 报告（可直接浏览器打开）
- `results.json` — 原始 JSON 数据（需 `--json` 参数）

## 环境变量（可选）

在 `/opt/autopnex/.env` 中配置：
```bash
DEEPSEEK_API_KEY=sk-xxx        # DeepSeek API Key（--mock 模式可不填）
AUTOPENX_SCAN_MODE=active
AUTOPENX_ALLOW_EXTERNAL_TOOLS=true
AUTOPENX_EXPLOIT_ENABLED=true
```

## Kali VM 信息

```
IP:       192.168.5.133
用户:     root
密码:     qq111111
SSH:      ssh kali-vm
安装路径: /opt/autopnex
启动命令: autopenx
```
