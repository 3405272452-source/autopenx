# AutoPenX — LLM 驱动的全自动渗透测试系统

> AutoPenX (Automated Penetration Testing with AI eXpertise)  
> **LLM 大脑 + 状态机骨架 + 模块化工具集** 的三层架构实现。

本项目是《Web 安全与渗透测试》课程设计的完整 MVP，严格按照 [`ai.md`](../../Desktop/ai.md) 会议纪要确定的最终方案实现：单一 LLM（DeepSeek V3）作为决策引擎、PTES 五阶段有限状态机作为流程骨架、纯 Python 实现的可插拔工具集作为执行手段，并提供 CLI 与 FastAPI Web UI 两种使用方式。

---

## ✨ 亮点

- **LLM 决策 + ReAct 循环**：每个状态内，LLM 基于当前 findings 快照决定下一步调用哪个工具、传什么参数、何时进入下一状态；无 API key 时自动退回确定性规则引擎，课程演示不依赖外网。
- **有限状态机流程控制**：`INIT → RECON → SCAN → VULN_DETECT → EXPLOIT → REPORT → DONE`，每状态有最大迭代次数保护，全局 `StateFindings` 存储贯通全流程。
- **模块化工具集**（11 个纯 Python 工具）：端口扫描、Web 指纹、子域枚举、敏感文件扫描、目录爆破、爬虫、SQLi/XSS/SSRF/CMDi 检测、SQLi 利用；全部继承 `BaseTool`，通过 `ToolRegistry` 注册、自动向 LLM 暴露 OpenAI 兼容 function schema。
- **跨平台运行**：所有扫描基于 `requests` / `asyncio` / `aiohttp` / `BeautifulSoup`，Windows、Linux、macOS 原生运行，无需 Kali 或 WSL。
- **双入口**：
  - `python autopnex.py --target <url>` — CLI，终端实时进度 + Markdown/HTML 报告。
  - `uvicorn autopnex.web.api:app` — FastAPI Web UI，实时 SSE 日志流 + 报告内嵌预览。
- **自动报告**：Jinja2 模板渲染 Markdown，LLM 可选生成执行摘要（离线时用规则模板兜底），markdown 包转 HTML 带样式。

---

## 🗂️ 目录结构

```
AutoPenX/
├── autopnex.py                  # CLI 入口
├── autopnex/
│   ├── orchestrator/            # DeepSeek 客户端、prompts、ReAct 循环、离线 MockBrain
│   ├── state_machine/           # PenTestStateMachine + StateFindings
│   ├── tools/                   # BaseTool + 11 个具体工具
│   │   ├── recon/  scan/  vuln/  exploit/
│   ├── knowledge_base/          # 漏洞指纹/payload 库 + 词表
│   ├── report/                  # Jinja2 模板 + 报告生成器
│   └── web/                     # FastAPI + 前端单页 (SSE 实时进度)
├── config/settings.py           # .env 配置加载
├── tests/                       # pytest 单测 + 集成测试（内置假靶场）
└── requirements.txt
```

---

## 🚀 快速开始

### Windows 推荐方式（一键脚本）

1. 双击 `安装依赖.bat`，初始化 `.venv`、安装依赖并创建 `.env`
2. 双击 `一键启动Web界面.bat`，启动 Web UI；脚本会自动打开浏览器
3. 或双击 `一键扫描.bat`，启动命令行扫描；若 `.env` 中存在有效 `DEEPSEEK_API_KEY`，默认使用 DeepSeek，否则自动回退到 `--mock`

### 手动方式（PowerShell）

```powershell
# Windows PowerShell
cd C:\Users\86181\Desktop\AutoPenX
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
copy .env.example .env   # 填入 DEEPSEEK_API_KEY 后即可启用真实 LLM
```

### 方式 A — CLI

```powershell
# 离线规则模式（不需要 API key，适合演示 / 跑通流程）
python autopnex.py --target http://testphp.vulnweb.com --mock --yes

# LLM 模式（需 .env 中配置有效的 DEEPSEEK_API_KEY，且不要加 --mock）
python autopnex.py --target http://testphp.vulnweb.com
```

输出：
- `reports/<timestamp>.md` — Markdown 报告
- `reports/<timestamp>.html` — 排版好的 HTML 报告
- 可选 `--json <path>` 同时导出原始 findings JSON

常用参数：

| 参数 | 说明 |
|------|------|
| `--target` / `-t` | 目标 URL 或主机 (**必填**) |
| `--mock` | 强制使用离线规则引擎（不调用 LLM） |
| `--max-iter N` | 每个状态的最大迭代次数（默认 6） |
| `--out path.md` | 指定 Markdown 输出路径 |
| `--html path.html` | 指定 HTML 输出路径 |
| `--json path.json` | 额外导出原始 findings JSON |
| `--yes` / `-y` | 跳过授权交互确认（适合脚本化） |

### 方式 B — Web UI

```powershell
.venv\Scripts\python -m uvicorn autopnex.web.api:app --reload --host 127.0.0.1 --port 8000
```

浏览器打开 <http://127.0.0.1:8000/>，输入目标 URL，实时查看：

1. 当前状态高亮（RECON → SCAN → VULN_DETECT → EXPLOIT → REPORT → DONE）
2. SSE 推送的工具调用流水与 LLM 推理摘要
3. 发现的漏洞列表（按严重度排序）
4. 内嵌的 HTML 报告预览

---

## 🧪 运行测试

```powershell
pytest
```

测试覆盖：

- `test_tool_registry.py` — 验证 11 个工具全部注册、schema 合法
- `test_findings.py` — `StateFindings` 去重、排序
- `test_orchestrator_mock.py` — 离线 MockBrain 的 ReAct 决策序列
- `test_state_machine.py` — 在进程内假靶场上端到端跑完整流水线 + 生成报告
- `test_tools_sqli.py` — 对进程内假 SQLi 站点验证 `sqli_detect`

---

## 🧠 系统架构（对应设计方案）

```
┌───────────────────────────────────────────┐
│        LLM Orchestrator (DeepSeek)        │
│     Planner · Reasoner · Analyzer         │
└──────────────────┬────────────────────────┘
                   │  Function Calling
┌──────────────────┴────────────────────────┐
│   PenTestStateMachine (RECON → REPORT)    │
└──────────────────┬────────────────────────┘
                   │
┌──────────────────┴────────────────────────┐
│   Tool Manager (BaseTool / ToolRegistry)  │
│   recon · scan · vuln · exploit · report  │
└──────────────────┬────────────────────────┘
                   │
┌──────────────────┴────────────────────────┐
│       Knowledge Base (patterns + wordlist)│
└───────────────────────────────────────────┘
```

### 工具清单（全部纯 Python）

| 阶段 | 工具名 | 功能 |
|------|--------|------|
| RECON | `port_scan` | asyncio TCP 端口扫描 + banner 抓取 |
| RECON | `tech_detect` | HTTP header + Cookie + HTML 指纹识别 |
| RECON | `subdomain_find` | 通过 crt.sh 被动枚举子域名 |
| SCAN | `web_scan` | Nikto 风格敏感文件 + 安全响应头检查 |
| SCAN | `dir_buster` | aiohttp 异步目录爆破 |
| SCAN | `crawl` | 同源 BFS 爬虫，抽取页面/表单/参数 |
| VULN | `sqli_detect` | 错误/布尔/时延三路 SQL 注入检测 |
| VULN | `xss_detect` | 反射 XSS payload 回显检查 |
| VULN | `ssrf_detect` | 内网 URL 注入 + 响应差异分析 |
| VULN | `cmdi_detect` | 时延型命令注入检测 |
| EXPLOIT | `sqli_exploit` | UNION SELECT PoC 抽取 DB 信息 |

---

## 📊 对应评分标准

| 评分项 | 分值 | 对应实现 |
|--------|------|----------|
| 系统架构 | 10 | 三层分离：Orchestrator / StateMachine / Tools，各自独立可替换 |
| 全智能实现机制 | 15 | LLM 基于 findings 快照 ReAct 决策，状态机内每次迭代向 LLM 暴露工具 schema |
| 关键代码实现 | 15 | 每个模块保持单一职责，工具基类抽象清晰，规则/LLM 双模式支持 |
| 测试效果 | 10 | pytest 内置假靶场做端到端集成测试，运行 `pytest` 即可复现 |
| 运行流程展示 | 10 | Web UI 的 SSE 流实时展示每个状态与每次工具调用 |
| 演示效果 | 15 | 报告生成带 LLM 执行摘要；离线模式也能完整演示 |
| 报告规范性 | 5 | Jinja2 模板 + Markdown + HTML 双输出 |

---

## 👥 团队分工（建议）

- **组长**：`orchestrator/`、`state_machine/`、总集成、Prompt 工程
- **成员 2**：`tools/recon/*` + `tools/scan/*`
- **成员 3**：`tools/vuln/*` + `tools/exploit/*`
- **成员 4**：`knowledge_base/`、`report/`、`web/` 前端、基准集测试

---

## ⚠️ 法律与授权

本工具仅用于教学与授权测试。对未授权系统使用属于违法行为，任何后果由使用者自行承担。CLI 启动时会强制要求确认授权；Web UI 首页会显示警示文字。

## 🛣️ 后续可扩展方向

- 真实 `nmap` / `sqlmap` / `nikto` / `ffuf` 作为可选 backend
- 在 `Orchestrator` 上接入 Anthropic Claude / OpenAI GPT-4o provider
- 持久化 `StateFindings` 至 SQLite，做历史对比与增量扫描
- `asyncio` 并行工具调度（`ToolManager.execute_many`）
- 基于 xbow-validation-benchmarks 的基准集自动化测试与覆盖率统计
