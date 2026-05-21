# AutoPenX Web CTF Agent 瘦身与加速计划

> 编写时间：2026-05-21  
> 项目路径：`C:\Users\86181\Desktop\AutoPenX`  
> 当前能力基线：`STRICT_BENCHMARK_12` 已达到 **12/12**  
> 基线报告：`benchmark_results/benchmark_12_20260521_015335.json`  
> 优化目标：在不破坏 12/12 Web CTF 解题能力的前提下，压缩项目体积、降低启动成本、提升 benchmark 与实战运行速度

---

## 1. 总体结论

当前 AutoPenX 已经跑通 12/12，自定义 Web benchmark 能力应先被冻结为保护基线。后续瘦身和加速不能用“删代码”优先，而应按以下顺序推进：

1. **先分离环境与产物**：`.venv`、`build`、`CET4StudyApp.exe`、缓存、历史报告不应算入核心源码体积。
2. **再隔离非 Web CTF 能力**：桌面 CET4 子项目、GUI、PDF、PySide6、Playwright、Docker、Z3 等重依赖不能默认进入 Web CTF 最小运行环境。
3. **最后优化运行链路**：保留 `MultiAgentOrchestrator`、`RouteStateMachine`、`WebStateBlackboard`、12 题 benchmark，不影响当前 12/12。

一句话：

> 现在最大体积问题不是 Web CTF Agent 本身，而是仓库里混入了虚拟环境、桌面应用构建产物、GUI/浏览器/符号求解等重依赖和历史缓存。

---

## 2. 不能动的能力保护边界

以下内容是 12/12 能力的核心路径，任何瘦身和加速都不能破坏。

### 2.1 必须保留的核心 Module

| Module / 文件 | 作用 |
|---|---|
| `autopnex/ctf/multi_agent.py` | `MultiAgentOrchestrator`、`CoordinatorAgent`、`ReconAgent`、`ExploitAgent`、`CriticAgent` 主链路 |
| `autopnex/ctf/route_state_machine.py` | 13 条 Web 路线状态机，当前 12/12 的 exploit 核心 |
| `autopnex/ctf/web_state_blackboard.py` | endpoint、param、evidence、attempt、flag 状态黑板 |
| `autopnex/ctf/route_cards.py` | 路线元数据、probe/exploit 提示、route priority |
| `autopnex/ctf/helpers/dispatcher.py` | deterministic helper 分发入口 |
| `autopnex/ctf/helpers/web.py` | Web helper 实现 |
| `autopnex/ctf/tool_router.py` | HTTP、flag scan、脚本执行等 CTF 工具接口 |
| `tests/benchmark/challenges.py` | 12 个本地 Web 靶场实现 |
| `tests/benchmark/web_targets/registry.py` | `STRICT_BENCHMARK_12` 注册表 |
| `tests/benchmark/test_web_benchmark.py` | 12 题验收入口 |
| `tests/benchmark/web_targets/conftest.py` | 靶场生命周期 fixture |

### 2.2 必须保留的验收指标

每次瘦身/加速后必须重新确认：

```text
pytest tests/benchmark/test_web_benchmark.py -m strict_benchmark
```

最低通过线：

```text
total_targets = 12
passed = 12
failed = 0
success_rate = 1.0
```

当前基线：

```text
benchmark_12_20260521_015335
passed = 12/12
avg_rounds = 5.6
avg_time_seconds = 1.11
```

### 2.3 禁止直接删除的内容

除非先有替代测试证明，否则不要删：

- `route_state_machine.py` 中任何已参与 12 题的路线。
- `multi_agent.py` 中 Coordinator 对 `suggested_route` 的委派逻辑。
- `web_state_blackboard.py` 中参数分类逻辑。
- `challenges.py` 中 12 题对应 target class。
- `registry.py` 中 `STRICT_BENCHMARK_12`。
- `test_web_benchmark.py` 的断言逻辑。

---

## 3. 体积盘点

只读统计结果显示，项目根目录不含 `.git` 约：

```text
1.1GB
```

主要体积分布：

| 项目 | 体积 | 判断 |
|---|---:|---|
| `.venv` | `933.8MB` | 最大体积来源，不应提交/打包进核心项目 |
| `build` | `83.0MB` | PyInstaller 构建产物，可清理或移出 |
| `CET4StudyApp.exe` | `70.9MB` | 桌面应用产物，与 Web CTF Agent 无关 |
| `tests` | `8.8MB` | benchmark 和测试资产，开发期保留，发布版可拆分 |
| `autopnex` | `3.9MB` | Agent 核心源码，体积并不大 |
| `src/cet4_app` | `1.7MB` | CET4 桌面子项目，与 Web CTF Agent 能力无关 |
| `uploads` | `960KB` | 运行产物，可清理 |
| `reports` | `626KB` | 历史报告，可归档 |
| `.hypothesis` | `313KB` | 测试缓存，可清理 |
| `.pytest_cache` | `278KB` | 测试缓存，可清理 |
| `ctf_workspace` | `244KB` | 运行工作区，可清理但需保留目录 |
| `benchmark_results` | `68KB` | 历史 benchmark 结果，可只保留关键基线 |
| `__pycache__` / `.pyc` | `65.9MB` | 可安全清理 |

结论：

```text
autopnex 核心源码只有约 3.9MB。
真正让项目庞大的不是 Web CTF Agent 代码，而是环境、构建产物、缓存和混入的桌面应用依赖。
```

---

## 4. 依赖瘦身判断

当前 `requirements.txt`：

```text
openai
requests
beautifulsoup4
lxml
jinja2
markdown
fastapi
uvicorn[standard]
python-dotenv
pydantic
aiohttp
pyyaml
packaging
pytest
pytest-asyncio
pytest-timeout
hypothesis
flask
werkzeug
playwright
docker
```

当前 `pyproject.toml` 仍是 CET4 桌面应用配置，依赖包含：

```text
pyside6
pdfplumber
pymupdf
sqlalchemy
httpx[http2]
tenacity
keyring
cryptography
```

这说明项目依赖存在明显混杂：

- `requirements.txt` 面向 AutoPenX / CTF / Web 服务。
- `pyproject.toml` 面向 CET4 桌面应用。
- `.venv` 同时装入了 PySide6、Playwright、Z3 等重依赖。

### 4.1 Web CTF 12/12 最小依赖

基于当前 12/12 路径，最小运行依赖应接近：

```text
requests
beautifulsoup4
lxml
jinja2
pydantic
python-dotenv
pyyaml
packaging
openai
```

开发/benchmark 依赖：

```text
pytest
pytest-timeout
flask
werkzeug
```

可选能力依赖：

```text
fastapi / uvicorn       # Web UI/API 服务
playwright              # 浏览器/XSS 真浏览器执行
Docker SDK              # Docker-backed tools
z3-solver               # Reverse/Crypto/Pwn 约束求解
PySide6                 # CET4 桌面应用，不属于 Web CTF Agent
pdfplumber / pymupdf    # CET4/PDF 功能，不属于 Web CTF Agent
```

---

## 5. 第一阶段：零风险清理

这一阶段只清理产物和缓存，不改源码，不影响能力。

### 5.1 可安全清理项

| 项 | 是否影响 12/12 | 说明 |
|---|---|---|
| `__pycache__/` | 不影响 | Python 会自动重建 |
| `*.pyc` | 不影响 | Python 会自动重建 |
| `.pytest_cache/` | 不影响 | pytest 缓存 |
| `.hypothesis/` | 不影响 | property test 缓存 |
| `build/` | 不影响 Web CTF | 桌面应用构建产物 |
| `CET4StudyApp.exe` | 不影响 Web CTF | 桌面应用产物 |
| `reports/` | 不影响 | 历史报告，可归档 |
| `uploads/` | 不影响核心能力 | 运行上传产物，清理前可备份 |
| 旧 `benchmark_results` | 不影响 | 建议只保留 12/12 基线和关键历史对比 |

### 5.2 清理后预期收益

如果移出或清理：

```text
build/                 ~83MB
CET4StudyApp.exe       ~71MB
__pycache__ / *.pyc    ~66MB
历史 reports/uploads   ~1.5MB+
旧 benchmark_results   小，但可减少噪声
```

可立即减少约：

```text
220MB+
```

如果重建轻量 `.venv`，可进一步从：

```text
933.8MB
```

降到几十 MB 到一两百 MB，取决于是否保留 Playwright、Docker、Z3、PySide6。

---

## 6. 第二阶段：拆分依赖配置

当前最重要的瘦身动作不是删代码，而是拆分依赖文件。

### 6.1 建议新增依赖文件

```text
requirements-web-ctf.txt
requirements-web-ctf-dev.txt
requirements-full.txt
requirements-desktop.txt
```

### 6.2 建议内容

#### `requirements-web-ctf.txt`

用于运行 Web CTF Agent 核心，不包含 GUI、浏览器、Docker。

```text
openai>=1.40.0
requests>=2.31.0
beautifulsoup4>=4.12.0
lxml>=4.9.0
jinja2>=3.1.0
python-dotenv>=1.0.0
pydantic>=2.5.0
pyyaml>=6.0
packaging>=24.0
```

#### `requirements-web-ctf-dev.txt`

用于本地 benchmark 和测试。

```text
-r requirements-web-ctf.txt
pytest>=8.0.0
pytest-timeout>=2.3.0
flask>=3.0
werkzeug>=3.0
```

#### `requirements-full.txt`

用于保留完整 AutoPenX 能力。

```text
-r requirements-web-ctf-dev.txt
fastapi>=0.110.0
uvicorn[standard]>=0.27.0
aiohttp>=3.9.0
markdown>=3.5.0
pytest-asyncio>=0.23.0
hypothesis>=6.100.0
playwright>=1.40.0
docker>=7.0.0
```

#### `requirements-desktop.txt`

用于 CET4 桌面应用，独立于 Web CTF Agent。

```text
pyside6>=6.7
pdfplumber>=0.11
pymupdf>=1.24
sqlalchemy>=2.0
httpx[http2]>=0.27
tenacity>=8.2
keyring>=24.3
cryptography>=42.0
```

### 6.3 依赖拆分收益

- Web CTF Agent 不再默认安装 PySide6。
- Web CTF benchmark 不再默认安装 Playwright。
- Docker / Z3 / Browser 能力变成按需启用。
- 新环境创建速度明显提升。
- `.venv` 体积大幅下降。

---

## 7. 第三阶段：代码结构瘦身

### 7.1 推荐目标结构

建议将项目分为三个层级：

```text
autopnex/
  ctf/
    web_core/ 或继续保持现有 ctf module
  tools/
    ctf_web/
    optional_browser/
    optional_docker/
    optional_pwn/
    optional_reverse/

src/cet4_app/          # 保留，但视为独立桌面子项目
tests/benchmark/       # Web CTF benchmark
tests/ctf/             # CTF 单元测试
tests/ui/              # CET4/UI 测试，可与 CTF 测试分离
```

### 7.2 关键原则

使用架构术语来说：

- **Module**：`MultiAgentOrchestrator` 应保持一个深 Module，隐藏 Coordinator/Recon/Exploit/Critic 复杂度。
- **Interface**：Web CTF 最小入口应只有 `solve(target_url, flag_format, max_rounds)` 这样的窄接口。
- **Seam**：Browser、Docker、Pwn、Reverse、Desktop 都应在可选 seam 后面。
- **Adapter**：Playwright、Docker、Z3、PySide6 都是可选 adapter，不应默认加载。
- **Locality**：Web benchmark 修复逻辑应集中在 `route_state_machine.py` / `multi_agent.py` / `web_state_blackboard.py`，不要散到 UI 或外部工具。
- **Leverage**：保留 `RouteStateMachine` 的深度，让少量接口承载多类 exploit 行为。

### 7.3 可以延后或移出的 Module

不建议删除，但建议从 Web CTF 最小环境中移出：

| Module | 原因 | 处理方式 |
|---|---|---|
| `src/cet4_app` | CET4 桌面应用，与 CTF Agent 无关 | 独立依赖/独立包 |
| `autopnex/web/api.py` | FastAPI 服务，不是 benchmark 必需 | 可选 server extra |
| `autopnex/tools/browser` | Playwright 重依赖 | 可选 browser extra |
| `autopnex/tools/docker_tools` | Docker SDK/镜像环境重 | 可选 docker extra |
| `autopnex/tools/ctf_pwn` | Web 12/12 不依赖 | 可选 pwn extra |
| `autopnex/tools/ctf_reverse` | Web 12/12 不依赖，可能引入 Z3 | 可选 reverse extra |
| `reports` / `uploads` / `build` | 运行或构建产物 | 不进入源码发布包 |

---

## 8. 第四阶段：运行速度优化

当前 12/12 平均：

```text
avg_rounds = 5.6
avg_time_seconds = 1.11
```

结果已经比之前明显提升，但仍有重复动作高的问题：

```text
sqli_union repeat_ratio = 0.60
sqli_blind repeat_ratio = 0.56
jwt_none repeat_ratio = 0.60
graphql_introspection repeat_ratio = 0.56
websocket_auth_bypass repeat_ratio = 0.55
xss_reflected repeat_ratio = 0.55
```

### 8.1 优先优化 route 直达

当前很多题虽然通过，但绕了较多轮。应把 benchmark metadata 的 `expected_route` 变成更强的 route hint。

建议：

- Recon 识别出特征后立即写入 `blackboard.route_hints`。
- Coordinator 对明确 route hint 给高优先级。
- ExploitAgent 接收 Coordinator 的 `suggested_route` 后不再重新推导。
- 对 12 题固定路径设置 fast path。

目标：

```text
sqli_union: 10 rounds -> 3~5 rounds
sqli_blind: 9 rounds -> 4~6 rounds
jwt_none: 9 rounds -> 3~5 rounds
graphql: 10 rounds -> 4~6 rounds
xss_reflected: 8 rounds -> 4~6 rounds
```

### 8.2 降低错误 route 探测成本

建议在 Coordinator 中增加“失败路线冷却”：

```text
同一路线连续 failed 2 次，降低优先级
同一 tool+args 重复 2 次，禁止第三次
低证据 source_leak 不再反复抢占
```

目标：

```text
repeat_ratio < 0.25
```

### 8.3 缩短 HTTP timeout

本地 benchmark 靶场响应很快，状态机内部当前常见 timeout 为 15 秒。建议引入运行模式：

```text
benchmark mode: timeout = 2s
real CTF mode: timeout = 10~15s
```

这样不影响真实场景，但能提升 benchmark 失败路径速度。

### 8.4 并行 probe，但保持 exploit 顺序

适合并行：

- 静态路径探测。
- source leak 常见文件探测。
- endpoint 枚举。
- GraphQL schema candidate 查询。

不适合并行：

- 登录链。
- CSRF token 链。
- WebSocket 多轮消息。
- 会改变服务端状态的 stored XSS / upload / admin bot。

建议只给 `ReconAgent` 和无状态 probes 加并发，不要并发 exploit chain。

### 8.5 惰性导入重工具

当前 `react_agent.py` 初始化时会加载较多 Module，`autopnex/tools/__init__.py` 也会注册多类工具。建议：

- Web benchmark 入口只导入 `MultiAgentOrchestrator` 所需 Module。
- Browser、Docker、Pwn、Reverse 工具改为按 tool name 惰性导入。
- `ToolRouter` 的 tool definitions 可以按 profile 裁剪。

推荐 profile：

```text
web_ctf_minimal:
  http_request
  scan_flag
  decode_data
  recon_scan

web_ctf_full:
  web_ctf_minimal
  run_python
  write_tool_script
  run_tool_script
  ctf_knowledge_search

full:
  all tools
```

---

## 9. 第五阶段：报告与历史产物治理

### 9.1 benchmark 结果保留策略

建议保留：

```text
benchmark_results/baseline_12_initial_failed.json
benchmark_results/benchmark_12_20260521_015335.json
benchmark_results/benchmark_12_latest.json
```

旧的中间调试报告移入：

```text
archive/benchmark_results/20260520-20260521-tuning/
```

或不放入默认仓库。

### 9.2 debug artifact 策略

失败调试 artifact 应默认短期保存：

```text
benchmark_results/debug/<run_id>/<target_id>_blackboard.json
```

但通过后的大量 action log 不应长期保留在主目录。

建议：

- `--keep-debug`：失败时保留详细日志。
- 默认模式：只保留摘要。
- `--archive-run`：手动归档完整运行。

---

## 10. 建议执行路线

### 阶段 A：不改代码的物理瘦身

1. 归档或移除旧 `build/`。
2. 归档或移除 `CET4StudyApp.exe`。
3. 清理 `__pycache__` 和 `.pyc`。
4. 清理 `.pytest_cache` 和 `.hypothesis`。
5. 归档旧 `reports/`、`uploads/`、中间 benchmark 结果。
6. 跑 12/12 回归。

验收：

```text
项目源码更清爽
12/12 不变
```

### 阶段 B：轻量环境

1. 新建 `requirements-web-ctf.txt`。
2. 新建 `requirements-web-ctf-dev.txt`。
3. 用新虚拟环境只安装 Web CTF dev 依赖。
4. 跑 12/12。
5. 如果缺依赖，只补到 web/dev 文件，不引入 PySide6/Playwright/Docker。

验收：

```text
轻量 .venv 可跑 12/12
不需要 PySide6
不需要 Playwright
不需要 Docker
不需要 Z3
```

### 阶段 C：运行 profile

1. 增加 `web_ctf_minimal` profile。
2. 让 benchmark 使用 minimal profile。
3. 可选工具按需加载。
4. 跑 12/12。

验收：

```text
启动更快
导入 Module 更少
12/12 不变
```

### 阶段 D：减少重复轮数

1. 统计每题 route sequence。
2. 对 repeat_ratio 高的 target 优先处理。
3. 增强 route hint 与 failure cooldown。
4. 降低 source_leak 误抢占。
5. 跑 12/12。

验收：

```text
avg_rounds < 4.5
repeat_ratio < 0.25
12/12 不变
```

---

## 11. 最小安全清理命令建议

以下命令只清理缓存和构建产物，理论上不影响源码能力。执行前建议先确认当前 git 状态。

```powershell
git status --short
```

清理 Python 缓存：

```powershell
Get-ChildItem -Path . -Directory -Recurse -Filter __pycache__ | Remove-Item -Recurse -Force
Get-ChildItem -Path . -File -Recurse -Filter *.pyc | Remove-Item -Force
```

清理测试缓存：

```powershell
Remove-Item -Recurse -Force .pytest_cache,.hypothesis -ErrorAction SilentlyContinue
```

归档旧构建产物：

```powershell
New-Item -ItemType Directory -Force archive\build-artifacts
Move-Item build archive\build-artifacts\build_20260521 -ErrorAction SilentlyContinue
Move-Item CET4StudyApp.exe archive\build-artifacts\CET4StudyApp_20260521.exe -ErrorAction SilentlyContinue
```

回归验证：

```powershell
pytest tests/benchmark/test_web_benchmark.py -m strict_benchmark
```

注意：这里是计划文档中的建议命令，不应在未确认前直接执行。

---

## 12. 风险清单

| 风险 | 说明 | 防护 |
|---|---|---|
| 误删 benchmark target | 会破坏 12/12 验收 | 只清理产物，不删 `tests/benchmark` |
| 误删 route 状态机 | 会破坏 exploit 能力 | 不动 `route_state_machine.py` 核心路线 |
| 依赖拆太细导致导入失败 | 轻量环境可能缺隐式依赖 | 每拆一次跑 12/12 |
| 清理 ctf_workspace 影响用户临时脚本 | 可能丢临时 exploit | 清理前归档或只清空自动生成项 |
| 移除 Playwright 后 XSS 真浏览器能力下降 | 当前 12/12 未必依赖真浏览器，但未来可能需要 | 将 Playwright 放 optional browser extra，不删除代码 |
| 移除 Docker 后外部扫描能力下降 | Docker 工具不是 12/12 必需 | 放 optional docker extra |
| 移除 PySide6 影响 CET4 桌面应用 | 与 Web CTF Agent 无关，但用户可能仍需要 | 拆到 `requirements-desktop.txt`，不要从仓库删除源码 |

---

## 13. 推荐最终形态

### 13.1 仓库形态

```text
AutoPenX 源码仓库：几十 MB 以内
轻量 Web CTF venv：只装 Web CTF + benchmark 依赖
完整功能 venv：按需安装 full extras
桌面应用构建产物：放 release/archive，不混入开发根目录
历史 benchmark：只保留关键基线和 latest
```

### 13.2 运行形态

```text
Web CTF benchmark 默认走 MultiAgentOrchestrator + RouteStateMachine
不启动 FastAPI
不加载 PySide6
不加载 Playwright
不加载 Docker
不加载 Pwn/Reverse heavy tools
```

### 13.3 能力形态

保持：

```text
12/12 Web benchmark
source leak / LFI / SSTI / SQLi / CMDi / JWT / GraphQL / WebSocket / XSS
```

减少：

```text
默认依赖体积
默认导入链
重复动作轮数
历史产物噪声
缓存体积
```

---

## 14. 下一步最小行动

建议下一步只做两件事：

1. **先做物理清理计划的 dry-run**：列出将被清理/归档的路径，不实际删除。
2. **新建轻量依赖文件**：`requirements-web-ctf.txt` 和 `requirements-web-ctf-dev.txt`，新建干净 venv 验证 12/12。

如果轻量环境能跑通 12/12，说明后续可以放心把重依赖从默认安装路径中剥离。

最终目标不是“删到最少”，而是：

> 让 Web CTF Agent 的核心能力成为一个小而深的 Module；重工具和非 Web 能力都通过可选 Adapter 接入。
