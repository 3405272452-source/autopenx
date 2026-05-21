# AutoPenX — LLM 驱动的全自动 CTF Web 解题 & 渗透测试系统

> **三阶段混合求解架构**：确定性多智能体路线状态机 → 并行 LLM 竞速 → 顺序 ReAct 推理，实现零 API 开销快速解题 + LLM 深度推理兜底。

---

## 系统架构总览

```
┌─────────────────────────────────────────────────────────────┐
│  CTFReActAgent.solve(multi_agent=True)                      │
│                                                             │
│  Phase 1: MultiAgentOrchestrator (确定性, 0 API 开销)       │
│  ┌─────────────────────────────────────────────────────┐    │
│  │ ReconAgent → 指纹识别 → 路线证据收集                  │    │
│  │ CoordinatorAgent → 选择最优路线                       │    │
│  │ ExploitAgent → RouteStateMachine → flag?             │    │
│  │ CriticAgent → 重复检测 + 路线切换                     │    │
│  │ KnowledgeLearner → 匹配已知模式                      │    │
│  └─────────────────────────────────────────────────────┘    │
│                                                             │
│  Phase 2: Parallel LLM Racing (3 workers × 5 turns)         │
│  ┌─────────────────────────────────────────────────────┐    │
│  │ Worker 1 (DeepSeek): SQLi + auth 方向                │    │
│  │ Worker 2 (OpenAI):   LFI + SSTI 方向                 │    │
│  │ Worker 3 (Claude):   CMDi + upload 方向              │    │
│  │ 首个找到 flag 的 worker 胜出 → 取消其他               │    │
│  └─────────────────────────────────────────────────────┘    │
│                                                             │
│  Phase 3: Sequential LLM ReAct (剩余预算)                   │
│  ┌─────────────────────────────────────────────────────┐    │
│  │ 完整工具集: http_request, run_python,                 │    │
│  │ repl_execute, scan_flag, file_analyze 等              │    │
│  │ 多轮推理 + 响应分析                                   │    │
│  └─────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────┘
```

---

## ✨ 核心特性

- **三阶段混合求解**：Phase 1 确定性路线（零 API 开销）→ Phase 2 并行 LLM 竞速 → Phase 3 顺序 ReAct 深度推理
- **15 条路线状态机**：source_leak, lfi, ssti, sqli, cmdi, jwt, upload, php_pop, ssrf, idor, xss, graphql, websocket, xxe, auth_logic
- **多智能体协作**：Coordinator / Recon / Exploit / Critic 四角色，通过 Blackboard 共享状态
- **12 种 LLM 工具**：http_request, run_python, repl_execute, scan_flag, decode_data, file_analyze, recon_scan, ctf_knowledge_search, write_tool_script, run_tool_script, install_python_package, download_tool_url
- **自进化知识库**：成功解题后自动提取模式，下次遇到相似题目直接命中
- **多模型支持**：DeepSeek / OpenAI / Claude 并行竞速，首个出 flag 即停
- **Flag 检测管线**：正则 → 启发式 → AI 验证，三级过滤减少误报
- **Web UI**：FastAPI + SSE 实时流式展示解题过程
- **30 个真实 CTF 靶场**：基于 BUUCTF 经典题目的本地复现
- **12 个严格基准测试**：覆盖所有主要漏洞类型

---

## 🚀 快速开始

### 环境要求

- Python 3.10+
- Windows / Linux / macOS

### 安装

```powershell
# 克隆项目
cd C:\Users\86181\Desktop\AutoPenX

# 创建虚拟环境
python -m venv .venv
.venv\Scripts\Activate.ps1   # Windows PowerShell
# source .venv/bin/activate  # Linux/macOS

# 安装依赖
pip install -r requirements.txt

# 配置环境变量
copy .env.example .env
# 编辑 .env，填入 DEEPSEEK_API_KEY
```

### Windows 一键脚本

- `安装依赖.bat` — 初始化虚拟环境 + 安装依赖
- `一键启动Web界面.bat` — 启动 Web UI 并自动打开浏览器
- `一键扫描.bat` — 命令行模式扫描

### 运行 CTF 解题

```powershell
# 多智能体模式（推荐）
python run_ctf_solve.py

# 或直接指定目标
python -c "
import asyncio
from autopnex.ctf.react_agent import CTFReActAgent
from config.settings import settings

agent = CTFReActAgent(
    target='http://target-url:port',
    challenge_type='web',
    max_iterations=30,
    multi_agent=True,
    runtime_config=settings.snapshot(),
)
result = asyncio.run(agent.solve())
print(f'Flag: {result.get(\"flag\")}')
"
```

### 启动 Web UI

```powershell
.venv\Scripts\python -m uvicorn autopnex.web.api:app --reload --host 127.0.0.1 --port 8000
```

浏览器打开 http://127.0.0.1:8000/

### 传统渗透测试模式

```powershell
# LLM 模式
python autopnex.py --target http://testphp.vulnweb.com

# 离线规则模式（无需 API key）
python autopnex.py --target http://testphp.vulnweb.com --mock --yes
```

---

## 🧪 运行基准测试

```powershell
# 严格 12 目标基准测试（确定性路线，无需 API key）
pytest tests/benchmark/test_web_benchmark.py -v

# 30 目标真实 CTF 基准测试
pytest tests/benchmark/test_real_ctf.py -v

# 探索模式（21 目标，测试路线覆盖广度）
pytest tests/benchmark/test_web_benchmark_explore.py -v

# 全部单元测试
pytest tests/ -v --ignore=tests/benchmark

# 冒烟测试（快速验证核心功能）
pytest tests/benchmark/test_web_benchmark_smoke.py -v
```

---

## 🗂️ 项目结构

```
AutoPenX/
├── autopnex/
│   ├── ctf/                          # CTF 解题核心引擎
│   │   ├── multi_agent.py            # 多智能体编排器 + 4 个 Agent
│   │   ├── route_state_machine.py    # 13 条路线状态机 + 工厂
│   │   ├── routes/                   # 模块化路线包（15 个路线文件）
│   │   │   ├── source_leak.py        # 源码泄露路线
│   │   │   ├── lfi.py                # 本地文件包含
│   │   │   ├── ssti.py               # 模板注入
│   │   │   ├── sqli.py               # SQL 注入
│   │   │   ├── cmdi.py               # 命令注入
│   │   │   ├── jwt.py                # JWT 伪造
│   │   │   ├── upload.py             # 文件上传
│   │   │   ├── php_pop.py            # PHP 反序列化
│   │   │   ├── ssrf.py               # SSRF
│   │   │   ├── idor.py               # 越权访问
│   │   │   ├── xss.py                # XSS
│   │   │   ├── graphql.py            # GraphQL 注入
│   │   │   ├── websocket.py          # WebSocket 绕过
│   │   │   ├── xxe.py                # XXE 注入
│   │   │   └── auth_logic.py         # 认证逻辑绕过
│   │   ├── react_agent.py            # CTFReActAgent（LLM ReAct 循环）
│   │   ├── tool_router.py            # 工具定义 + 执行网关
│   │   ├── web_state_blackboard.py   # 共享状态黑板
│   │   ├── knowledge_learner.py      # 自进化知识学习器
│   │   ├── flag_engine.py            # Flag 检测引擎
│   │   ├── prompt_compiler.py        # Prompt 编译器
│   │   ├── workers.py                # 并行 LLM Worker
│   │   └── ...
│   ├── orchestrator/                 # LLM 客户端层
│   │   ├── llm_client.py             # DeepSeek/OpenAI 兼容客户端
│   │   ├── mock_brain.py             # 离线规则引擎
│   │   └── orchestrator.py           # 传统渗透编排器
│   ├── tools/                        # 工具集
│   │   ├── recon/                    # 侦察工具
│   │   ├── scan/                     # 扫描工具
│   │   ├── vuln/                     # 漏洞检测
│   │   ├── exploit/                  # 利用工具
│   │   ├── ctf_web/                  # CTF Web 专用工具
│   │   └── ctf_crypto/              # CTF Crypto 工具
│   ├── web/                          # Web UI
│   │   ├── api.py                    # FastAPI 后端 + SSE
│   │   └── static/                   # 前端静态文件
│   ├── state_machine/                # PTES 状态机
│   ├── evasion/                      # WAF 绕过引擎
│   └── knowledge_base/               # 漏洞指纹/payload 库
├── tests/
│   ├── benchmark/
│   │   ├── test_web_benchmark.py     # 严格 12 目标基准
│   │   ├── test_real_ctf.py          # 30 目标真实 CTF
│   │   ├── challenges.py             # 靶场实现
│   │   └── real_ctf_targets.py       # 真实 CTF 目标注册
│   └── ctf/                          # CTF 引擎单元测试
├── config/
│   └── settings.py                   # 配置管理
├── run_ctf_solve.py                  # CTF 解题 CLI 入口
├── autopnex.py                       # 传统渗透 CLI 入口
├── ctf_knowledge.json                # 自进化知识库
├── .env                              # 环境变量配置
└── requirements.txt                  # Python 依赖
```

---

## ⚙️ 配置说明

### `.env` 环境变量

```bash
# ---- 必填：主 LLM ----
DEEPSEEK_API_KEY=sk-xxx              # DeepSeek API Key
DEEPSEEK_BASE_URL=https://api.deepseek.com
DEEPSEEK_MODEL=deepseek-chat

# ---- 可选：多模型并行 ----
OPENAI_API_KEY=                       # OpenAI API Key（Worker 2）
OPENAI_BASE_URL=https://api.openai.com/v1
OPENAI_MODEL=gpt-4o
CLAUDE_API_KEY=                       # Claude API Key（Worker 3）
CLAUDE_BASE_URL=https://api.anthropic.com/v1
CLAUDE_MODEL=claude-sonnet-4-20250514

# ---- 运行时配置 ----
AUTOPENX_SCAN_MODE=active             # passive | active
AUTOPENX_MAX_ITER_PER_STATE=6         # 每状态最大迭代
AUTOPENX_HTTP_TIMEOUT=8               # HTTP 超时秒数
AUTOPENX_REQUEST_DELAY=0.0            # 请求间隔（秒）

# ---- WAF 绕过 ----
AUTOPENX_EVASION_ENABLED=false        # 启用绕过引擎
AUTOPENX_WAF_BYPASS_LEVEL=none        # none | light | aggressive

# ---- CTF 工具管理 ----
AUTOPENX_CTF_AUTO_TOOLING_ENABLED=true   # 允许 LLM 写脚本
AUTOPENX_CTF_TOOL_INSTALL_ENABLED=true   # 允许 pip install
AUTOPENX_CTF_WORKSPACE_DIR=ctf_workspace # 工作目录
```

---

## 🔧 如何扩展

### 添加新路线

1. 在 `autopnex/ctf/routes/` 下创建新文件（如 `nosql.py`）
2. 继承 `RouteStateMachine`，实现 `preconditions_met()`, `get_probes()`, `score_evidence()`, `get_exploit_steps()`
3. 在 `autopnex/ctf/routes/registry.py` 中注册
4. 在 `CoordinatorAgent.ROUTE_PRIORITY` 中添加优先级

### 添加新 CTF 靶场

1. 在 `tests/benchmark/real_ctf_targets.py`（或 `_real_ctf_extra.py`）中添加新 Target 类
2. 实现 `start()`, `stop()`, `url`, `flag`, `name`, `category` 属性
3. 在 `REAL_CTF_TARGETS` 字典中注册

### 添加新 LLM 工具

1. 在 `autopnex/ctf/tool_router.py` 的 `TOOL_DEFINITIONS` 列表中添加 OpenAI function schema
2. 在 `ToolRouter.execute()` 方法中添加对应的执行分支
3. 将工具名加入 `CORE_TOOL_NAMES` 集合

---

## 📊 当前能力

| 指标 | 数值 |
|------|------|
| 严格基准通过率 | 12/12 (100%) |
| 真实 CTF 通过率 | 30/30 (100%) |
| 支持路线数 | 15 |
| LLM 工具数 | 12 |
| 平均解题轮次 | ~5 轮 |
| 平均解题时间 | ~1.5s（本地靶场） |

### 覆盖的漏洞类型

SQL 注入、文件包含(LFI)、模板注入(SSTI)、命令注入(CMDi)、JWT 伪造、文件上传、PHP 反序列化、SSRF、IDOR 越权、XSS、GraphQL 注入、WebSocket 绕过、XXE 注入、认证逻辑绕过、源码泄露

---

## 🛠️ 技术栈

| 层级 | 技术 |
|------|------|
| 语言 | Python 3.12 |
| LLM | DeepSeek V3 / GPT-4o / Claude (OpenAI 兼容协议) |
| Web 框架 | FastAPI + Uvicorn |
| HTTP 客户端 | requests + aiohttp |
| 测试框架 | pytest + hypothesis |
| 前端 | 原生 HTML/JS + SSE |
| 配置 | python-dotenv |
| 模板 | Jinja2 |

---

## ⚠️ 法律与授权

本工具仅用于教学、CTF 竞赛和授权渗透测试。对未授权系统使用属于违法行为，任何后果由使用者自行承担。
