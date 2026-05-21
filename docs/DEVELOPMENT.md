# AutoPenX 开发者指南

本文档面向需要修改、扩展或调试 AutoPenX 的开发者。

---

## 1. 如何添加新路线 (Route)

路线是 AutoPenX CTF 引擎的核心扩展点。每条路线代表一种漏洞利用策略。

### 步骤

#### 1.1 创建路线文件

在 `autopnex/ctf/routes/` 下创建新文件，例如 `nosql.py`：

```python
"""NoSQL 注入路线状态机。"""
from __future__ import annotations
from typing import Any, Callable, Dict, List, Optional, Tuple
import requests
from .base import RouteStateMachine, EvidenceScore, ProbeResult

class NoSQLMachine(RouteStateMachine):
    """NoSQL 注入检测与利用。"""
    route = "nosql"

    def preconditions_met(self, blackboard_state: Dict[str, Any]) -> Tuple[bool, str]:
        """检查前置条件 — 是否值得尝试此路线。"""
        tech_stack = blackboard_state.get("tech_stack", [])
        if any("mongo" in str(t).lower() or "node" in str(t).lower() for t in tech_stack):
            return True, "MongoDB/Node.js detected"
        return True, "NoSQL injection is worth trying on any target"

    def get_probes(self) -> List[Tuple[str, str, Optional[Callable]]]:
        """返回探针列表: (name, payload, response_transform)"""
        return [
            ("nosql_or", '{"$gt":""}', None),
            ("nosql_regex", '{"$regex":".*"}', None),
            ("nosql_ne", '{"$ne":"invalid"}', None),
        ]

    def score_evidence(self, probe_name: str, response: requests.Response) -> EvidenceScore:
        """评估探针响应的证据强度。"""
        if response.status_code == 200 and "admin" in response.text.lower():
            return EvidenceScore(self.route, 0.8, probe_name, "NoSQL injection confirmed")
        if response.status_code == 200 and len(response.text) > 100:
            return EvidenceScore(self.route, 0.4, probe_name, "Possible NoSQL response")
        return EvidenceScore(self.route, 0.0, probe_name, "No evidence")

    def get_exploit_steps(self) -> List[Dict[str, Any]]:
        """返回有序的利用步骤。"""
        return [
            {
                "name": "nosql_login_bypass",
                "description": "NoSQL 登录绕过",
                "method": "POST",
                "path": "/login",
                "json": {"username": {"$gt": ""}, "password": {"$gt": ""}},
            },
            # ... 更多步骤
        ]
```

#### 1.2 注册路线

在 `autopnex/ctf/routes/registry.py` 中导入并注册：

```python
from .nosql import NoSQLMachine

ROUTE_REGISTRY["nosql"] = NoSQLMachine
```

#### 1.3 设置优先级

在 `autopnex/ctf/multi_agent.py` 的 `CoordinatorAgent.ROUTE_PRIORITY` 中添加：

```python
ROUTE_PRIORITY = {
    ...
    "nosql": 7,  # 与 sqli 同级
}
```

#### 1.4 添加到 ALWAYS_EXPLOIT_ROUTES（可选）

如果路线的 exploit steps 是确定性的（不需要先收集证据），添加到：

```python
ALWAYS_EXPLOIT_ROUTES = {
    "lfi", "ssti", "sqli", "cmdi", ..., "nosql",
}
```

#### 1.5 编写测试

在 `tests/ctf/test_route_state_machine.py` 或新建测试文件中添加测试。

---

## 2. 如何添加新的真实 CTF 靶场

### 步骤

#### 2.1 创建 Target 类

在 `tests/benchmark/real_ctf_targets.py` 或 `_real_ctf_extra.py` 中：

```python
class MyNewTarget:
    """描述题目背景和解法。"""
    flag = "flag{my_new_challenge_flag}"
    name = "ctf_name_challenge"
    category = "sqli"  # 对应路线名

    def __init__(self):
        self.port = _find_free_port()
        self._server = None
        self._thread = None

    @property
    def url(self):
        return f"http://127.0.0.1:{self.port}"

    def start(self):
        parent = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a): pass

            def do_GET(self):
                # 实现漏洞逻辑
                ...

        self._server = HTTPServer(("127.0.0.1", self.port), Handler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return self.url

    def stop(self):
        if self._server:
            self._server.shutdown()
```

#### 2.2 注册到 REAL_CTF_TARGETS

```python
REAL_CTF_TARGETS["ctf_name_challenge"] = MyNewTarget
```

#### 2.3 验证

```powershell
pytest tests/benchmark/test_real_ctf.py -k "ctf_name_challenge" -v
```

---

## 3. 如何添加新的 LLM 工具

### 步骤

#### 3.1 定义 Tool Schema

在 `autopnex/ctf/tool_router.py` 的 `TOOL_DEFINITIONS` 列表中添加：

```python
{
    "type": "function",
    "function": {
        "name": "my_new_tool",
        "description": "工具描述 — LLM 会根据这个描述决定何时调用",
        "parameters": {
            "type": "object",
            "properties": {
                "param1": {
                    "type": "string",
                    "description": "参数描述",
                },
            },
            "required": ["param1"],
        },
    },
}
```

#### 3.2 注册工具名

将工具名加入 `CORE_TOOL_NAMES`：

```python
CORE_TOOL_NAMES = {
    ...,
    "my_new_tool",
}
```

#### 3.3 实现执行逻辑

在 `ToolRouter.execute()` 方法中添加分支：

```python
elif name == "my_new_tool":
    param1 = args.get("param1", "")
    # 执行逻辑
    return {"result": "..."}
```

#### 3.4 测试

确保工具在 `ToolRouter.definitions()` 中出现，并且 `execute()` 正确返回。

---

## 4. 如何配置多模型支持

### 4.1 环境变量

在 `.env` 中配置多个 API Key：

```bash
DEEPSEEK_API_KEY=sk-xxx          # 必填：主模型
OPENAI_API_KEY=sk-yyy            # 可选：Worker 2
CLAUDE_API_KEY=sk-zzz            # 可选：Worker 3
```

### 4.2 工作原理

- 只配置 DeepSeek → 所有 Worker 使用 DeepSeek（不同方向偏好）
- 配置 DeepSeek + OpenAI → Worker 1 用 DeepSeek，Worker 2 用 OpenAI
- 三个都配置 → 三个 Worker 分别使用不同模型

### 4.3 自定义 Worker 方向

在 `autopnex/ctf/workers.py` 中修改 Worker 的方向偏好。

---

## 5. 如何运行测试

### 5.1 测试分类

```powershell
# 全部单元测试（快速，不需要 API key）
pytest tests/ -v --ignore=tests/benchmark

# 严格基准测试（12 目标，确定性路线）
pytest tests/benchmark/test_web_benchmark.py -v

# 真实 CTF 基准（30 目标）
pytest tests/benchmark/test_real_ctf.py -v

# 探索模式（21 目标，测试路线覆盖广度）
pytest tests/benchmark/test_web_benchmark_explore.py -v

# 冒烟测试
pytest tests/benchmark/test_web_benchmark_smoke.py -v

# 单个测试
pytest tests/ctf/test_route_state_machine.py -v

# 带覆盖率
pytest tests/ --cov=autopnex --cov-report=html
```

### 5.2 测试标记

```powershell
# 只跑特定类别
pytest -k "sqli" -v
pytest -k "test_real_ctf" -v
```

### 5.3 调试单个目标

```powershell
# 使用 debug_single.py
python debug_single.py
```

---

## 6. 如何调试失败的目标

### 6.1 启用详细日志

```python
import logging
logging.basicConfig(level=logging.DEBUG)
logging.getLogger("autopnex.ctf").setLevel(logging.DEBUG)
```

### 6.2 使用 progress_callback

```python
def progress_callback(event):
    print(json.dumps(event, ensure_ascii=False, indent=2))

agent = CTFReActAgent(
    target=url,
    progress_callback=progress_callback,
    ...
)
```

### 6.3 检查 Blackboard 状态

```python
# 在测试中
blackboard = agent.blackboard
print(blackboard.state_summary())
print(blackboard.evidence)
print(blackboard.candidate_flags)
```

### 6.4 单独运行路线状态机

```python
from autopnex.ctf.routes.sqli import SQLiMachine

machine = SQLiMachine(target_url="http://127.0.0.1:8080")
evidence = machine.run_probes()
print(f"Evidence score: {evidence.score}")

found, flag = machine.run_exploit()
print(f"Flag: {flag}")
```

### 6.5 查看 HTTP 历史

```python
# RouteStateMachine 记录所有 HTTP 请求
for req in machine._http_history:
    print(f"{req['method']} {req['url']} → {req['status']}")
    print(f"  Response: {req['response_excerpt'][:100]}")
```

---

## 7. 代码风格与约定

### 7.1 通用规则

- Python 3.10+ 类型注解
- 使用 `dataclass` 定义数据结构
- 使用 `ABC` + `abstractmethod` 定义接口
- 日志使用 `logging.getLogger("autopnex.ctf.module_name")`
- 所有 Agent 输出为结构化 JSON，不是自然语言

### 7.2 命名约定

- 路线名：小写下划线（`source_leak`, `auth_logic`）
- Agent 类：`XxxAgent`（`CoordinatorAgent`, `ReconAgent`）
- 状态机类：`XxxMachine`（`SQLiMachine`, `LFIMachine`）
- 测试文件：`test_xxx.py`

### 7.3 错误处理

- 工具执行失败返回 `{"error": "描述"}` 而非抛异常
- Agent 决策失败返回低置信度 AgentDecision
- 网络错误被捕获并记录为 `ProbeResult.ERROR`

### 7.4 安全限制

- 每路线最多 30 步 (`MAX_STEPS_PER_ROUTE`)
- 每路线最多 30 秒 (`MAX_TIME_PER_ROUTE`)
- HTTP 超时 8 秒
- Python 脚本执行超时 120 秒
- 工具安装需要 `ctf_tool_install_enabled=True`

---

## 8. 关键文件职责速查

| 文件 | 职责 |
|------|------|
| `autopnex/ctf/react_agent.py` | CTFReActAgent 主类，三阶段求解入口 |
| `autopnex/ctf/multi_agent.py` | 多智能体编排器 + 4 个 Agent 实现 |
| `autopnex/ctf/route_state_machine.py` | RouteStateMachine 基类 + 早期路线实现 |
| `autopnex/ctf/routes/` | 模块化路线包（15 个路线文件） |
| `autopnex/ctf/routes/registry.py` | 路线注册表 |
| `autopnex/ctf/tool_router.py` | 工具定义 + ToolRouter 执行网关 |
| `autopnex/ctf/web_state_blackboard.py` | 共享状态黑板 |
| `autopnex/ctf/knowledge_learner.py` | 自进化知识学习器 |
| `autopnex/ctf/flag_engine.py` | Flag 检测引擎（正则+启发式+AI） |
| `autopnex/ctf/prompt_compiler.py` | LLM Prompt 动态编译 |
| `autopnex/ctf/workers.py` | 并行 LLM Worker |
| `autopnex/ctf/fuse_controller.py` | 熔断器（防无限循环） |
| `autopnex/ctf/critic.py` | Critic 评估器 |
| `autopnex/ctf/session.py` | CTF 会话状态 |
| `autopnex/orchestrator/llm_client.py` | LLM 客户端（OpenAI 兼容） |
| `autopnex/orchestrator/mock_brain.py` | 离线规则引擎 |
| `autopnex/web/api.py` | FastAPI Web UI 后端 |
| `config/settings.py` | 配置管理 + RuntimeConfig |
| `tests/benchmark/challenges.py` | 基准靶场实现 |
| `tests/benchmark/real_ctf_targets.py` | 真实 CTF 靶场注册 |
| `run_ctf_solve.py` | CTF 解题 CLI 入口 |
| `ctf_knowledge.json` | 持久化知识库 |

---

## 9. 开发工作流

### 9.1 添加功能

1. 在对应模块中实现
2. 编写单元测试
3. 运行 `pytest tests/ -v` 确保不破坏现有功能
4. 运行 `pytest tests/benchmark/test_web_benchmark.py -v` 确保基准不退化

### 9.2 修复 Bug

1. 先写一个失败的测试复现 bug
2. 修复代码
3. 确认测试通过
4. 运行全量基准确保无回归

### 9.3 性能优化

1. 使用 `tests/performance/profiler.py` 定位瓶颈
2. 优化后运行基准对比 `Avg Rounds` 和 `Avg Time`
3. 确保通过率不下降
