# AutoPenX 系统架构文档

本文档详细描述 AutoPenX 的系统设计、模块交互和数据流。

---

## 1. 总体设计：三阶段混合求解

AutoPenX 采用 **三阶段递进式** 架构解决 CTF Web 题目：

```
┌─────────────────────────────────────────────────────────────────┐
│                    CTFReActAgent.solve()                         │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Phase 1: 确定性多智能体路线 (0 API 开销)                        │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │  KnowledgeLearner.match_pattern()                         │  │
│  │       ↓ (命中已知模式则直接走对应路线)                      │  │
│  │  ReconAgent.execute()                                     │  │
│  │       ↓ (指纹识别 + 参数发现 + 证据收集)                   │  │
│  │  CoordinatorAgent.decide()                                │  │
│  │       ↓ (基于证据评分选择最优路线)                         │  │
│  │  ExploitAgent → RouteStateMachine.run_exploit()           │  │
│  │       ↓ (执行路线状态机的 exploit steps)                   │  │
│  │  CriticAgent → 重复检测 + 路线切换建议                     │  │
│  │       ↓ (如果当前路线失败，切换到下一个)                   │  │
│  │  循环直到: flag 找到 / 所有路线耗尽 / 预算用完             │  │
│  └───────────────────────────────────────────────────────────┘  │
│       ↓ (Phase 1 未找到 flag)                                   │
│                                                                 │
│  Phase 2: 并行 LLM 竞速 (3 workers × 5 turns)                  │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │  Worker 1 (DeepSeek): SQLi + auth 方向                    │  │
│  │  Worker 2 (OpenAI):   LFI + SSTI 方向                     │  │
│  │  Worker 3 (Claude):   CMDi + upload 方向                  │  │
│  │  首个找到 flag → 取消其他 workers                          │  │
│  └───────────────────────────────────────────────────────────┘  │
│       ↓ (Phase 2 未找到 flag)                                   │
│                                                                 │
│  Phase 3: 顺序 LLM ReAct (剩余预算)                            │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │  完整工具集 + 多轮推理                                     │  │
│  │  LLM 自主决定调用哪个工具、传什么参数                      │  │
│  │  每轮: Thought → Action → Observation → 循环              │  │
│  └───────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

### 设计理念

1. **Phase 1 零开销**：大部分 CTF 题目有固定模式，确定性路线可以在 0 API 调用内解决
2. **Phase 2 多样性**：不同 LLM 有不同的推理偏好，并行竞速提高覆盖率
3. **Phase 3 深度兜底**：对于复杂题目，给 LLM 完整工具集和充足预算进行深度推理

---

## 2. 多智能体协作系统

### 2.1 Agent 角色

| Agent | 职责 | 决策方式 |
|-------|------|----------|
| **CoordinatorAgent** | 路线选择、预算分配、停止决策 | 基于证据评分 + 优先级 + 失败历史 |
| **ReconAgent** | 确定性枚举：路径扫描、指纹识别、参数发现 | 纯确定性，不调用 LLM |
| **ExploitAgent** | 执行 RouteStateMachine，构造 payload | 确定性状态机步骤 |
| **CriticAgent** | 假设反驳、重复检测、路线切换建议 | 基于 attempt 历史分析 |

### 2.2 协作协议

```
CoordinatorAgent
    │
    ├── decide() → AgentDecision {route, action, confidence}
    │
    ├── delegate("recon") → ReconAgent.execute()
    │       └── 更新 Blackboard: endpoints, params, tech_stack, evidence
    │
    ├── delegate("exploit") → ExploitAgent.execute()
    │       └── RouteStateMachine.run_probes() + run_exploit()
    │       └── 返回 RouteResult {status, flag, handoff_target}
    │
    └── process_exploit_result() → {stop, next_route, flag}
            └── 更新 route_failures, budget_remaining
```

### 2.3 AgentDecision 结构

所有 Agent 输出统一为 `AgentDecision` 结构化 JSON：

```python
@dataclass
class AgentDecision:
    agent: str              # 产生决策的 agent 名
    route: str              # 目标路线
    hypothesis: str         # 当前假设
    confidence: float       # 置信度 0.0-1.0
    supporting_evidence: List[str]  # 支撑证据
    next_action: Dict       # 下一步动作
    stop_if: List[str]      # 停止条件
    reasoning: str          # 推理过程
```

---

## 3. 路线状态机系统 (Route State Machine)

### 3.1 概述

每条路线是一个完整的状态机，包含：

```
preconditions → probes → evidence scoring → exploit steps → fallbacks → handoffs
```

### 3.2 15 条路线

| 路线 | 文件 | 描述 |
|------|------|------|
| source_leak | `routes/source_leak.py` | .git/HEAD, .env, www.zip 等源码泄露 |
| lfi | `routes/lfi.py` | 本地文件包含 + 过滤绕过 |
| ssti | `routes/ssti.py` | Jinja2/Twig/Smarty 模板注入 |
| sqli | `routes/sqli.py` | UNION/布尔/时延 SQL 注入 |
| cmdi | `routes/cmdi.py` | 命令注入 + 过滤绕过 |
| jwt | `routes/jwt.py` | alg=none + 弱密钥爆破 |
| upload | `routes/upload.py` | 文件上传绕过（MIME/扩展名/内容） |
| php_pop | `routes/php_pop.py` | PHP 反序列化链 |
| ssrf | `routes/ssrf.py` | file:// + 内网元数据探测 |
| idor | `routes/idor.py` | 路径/ID 枚举越权 |
| xss | `routes/xss.py` | 反射/存储 XSS + admin bot |
| graphql | `routes/graphql.py` | 内省查询 + 隐藏字段 |
| websocket | `routes/websocket.py` | WebSocket 认证绕过 |
| xxe | `routes/xxe.py` | XML 外部实体注入 |
| auth_logic | `routes/auth_logic.py` | Cookie/Header 认证逻辑绕过 |

### 3.3 状态机生命周期

```python
class RouteStateMachine(ABC):
    # 1. 前置条件检查
    def preconditions_met(blackboard_state) -> (bool, reason)

    # 2. 探测阶段 — 发送探针收集证据
    def get_probes() -> List[(name, payload, transform)]
    def run_probes() -> EvidenceScore

    # 3. 证据评分
    def score_evidence(probe_name, response) -> EvidenceScore

    # 4. 利用阶段 — 执行 exploit 步骤链
    def get_exploit_steps() -> List[Dict]
    def run_exploit() -> (found_flag, flag_value)

    # 5. 安全限制
    MAX_STEPS_PER_ROUTE = 30    # 每路线最多 30 步
    MAX_TIME_PER_ROUTE = 30.0   # 每路线最多 30 秒
```

### 3.4 RouteResult 结构

```python
@dataclass
class RouteResult:
    route: str
    status: "success" | "failed" | "inconclusive" | "handoff"
    flag: Optional[str]
    best_evidence_score: float
    steps_executed: int
    stop_reason: str
    handoff_target: Optional[str]  # 切换到哪条路线
```

### 3.5 路线评分算法

CoordinatorAgent 使用多因子评分选择路线：

```
score = base_priority * 0.05
      + max_evidence_score * 0.5
      + param_hint_bonus * 0.2
      + tech_stack_boost (0.1-0.15)
      - failures * 0.35
      - over_attempts * 0.5
```

---

## 4. LLM 集成

### 4.1 LLMClient

位于 `autopnex/orchestrator/llm_client.py`，基于 OpenAI SDK 的薄封装：

- 支持 DeepSeek V3 / GPT-4o / Claude（OpenAI 兼容协议）
- 支持 Function Calling（工具调用）
- 支持 Thinking Mode（DeepSeek 深度推理）
- 超时 180 秒，温度 0.2

### 4.2 并行 Workers

Phase 2 中，3 个 Worker 并行运行：

```python
# workers.py
class BaseCTFWorker:
    """每个 Worker 有独立的 LLM 客户端和方向偏好"""
    pass

class WebExploitWorker(BaseCTFWorker):
    """Web 漏洞利用方向"""
    pass

class ReconWorker(BaseCTFWorker):
    """侦察方向"""
    pass
```

### 4.3 多模型配置

```
Worker 1: DEEPSEEK_API_KEY → deepseek-chat
Worker 2: OPENAI_API_KEY   → gpt-4o
Worker 3: CLAUDE_API_KEY   → claude-sonnet-4-20250514
```

如果只配置了 DeepSeek，所有 Worker 都使用 DeepSeek（不同方向偏好）。

### 4.4 Fallback 链

```
DeepSeek (主) → OpenAI (备) → Claude (备) → 离线规则引擎 (MockBrain)
```

---

## 5. 自进化知识学习器

### 5.1 工作原理

```
成功解题 → KnowledgeLearner.record_success()
    → 提取: route, scenario, fingerprints, payload_family, tech_stack, key_params
    → 存储到 ctf_knowledge.json

下次遇到相似题目 → KnowledgeLearner.match_pattern()
    → 指纹匹配 → 直接返回最优路线 (confidence=0.95)
    → 跳过盲目探索
```

### 5.2 知识结构

```json
{
  "version": 2,
  "patterns": [
    {
      "route": "sqli",
      "scenario": "login_form_sqli",
      "fingerprints": ["check.php", "username", "password"],
      "payload_family": "or_true",
      "tech_stack": ["PHP"],
      "key_params": ["username", "password"]
    }
  ],
  "solve_history": [...]
}
```

---

## 6. 工具系统

### 6.1 ToolRouter 架构

```
CTFReActAgent
    │
    └── ToolRouter.execute(name, args)
            │
            ├── 内置工具 (12 个)
            │   ├── http_request → _exec_http_request()
            │   ├── run_python → script_execute()
            │   ├── repl_execute → PersistentREPL()
            │   ├── scan_flag → FlagEngine.scan()
            │   ├── decode_data → encoding_decode()
            │   ├── file_analyze → SourceAnalysis
            │   ├── recon_scan → ReconModule.scan()
            │   ├── ctf_knowledge_search → KnowledgeBase.search()
            │   ├── write_tool_script → CTFToolWorkspace.write_script()
            │   ├── run_tool_script → CTFToolWorkspace.run_script()
            │   ├── install_python_package → pip --target
            │   └── download_tool_url → CTFToolWorkspace.download_url()
            │
            └── 注册表工具 (ToolRegistry)
                ├── ssti_detect
                ├── lfi_detect
                ├── unserialize_detect
                ├── flag_reader
                └── ...
```

### 6.2 工具定义格式

每个工具以 OpenAI Function Calling schema 定义：

```python
{
    "type": "function",
    "function": {
        "name": "http_request",
        "description": "Make an HTTP request...",
        "parameters": {
            "type": "object",
            "properties": { ... },
            "required": ["url"],
        },
    },
}
```

### 6.3 CTFToolWorkspace

LLM 可以动态写入和执行脚本：

- `write_tool_script` — 写入 Python/Bash/Node 脚本到 `ctf_workspace/`
- `run_tool_script` — 执行已写入的脚本
- `install_python_package` — pip install 到隔离目录
- `download_tool_url` — 下载辅助文件

---

## 7. Blackboard 状态管理

### 7.1 WebStateBlackboard

所有 Agent 通过 Blackboard 共享状态，替代消息历史：

```python
class WebStateBlackboard:
    # 端点记录
    endpoints: List[EndpointRecord]

    # 表单记录
    forms: List[FormRecord]

    # 证据卡片
    evidence: List[EvidenceCard]

    # 参数记录
    params: List[ParamRecord]

    # Flag 候选
    candidate_flags: List[FlagCandidate]

    # 技术栈
    tech_stack: List[str]

    # 阻塞器
    blockers: List[str]

    # 尝试记录
    attempts: List[AttemptRecord]
```

### 7.2 设计原则

- **状态在 Blackboard 上，不在 Prompt 中** — 避免 context window 膨胀
- **结构化记录** — 每个工具结果自动提取摘要写入 Blackboard
- **可查询** — Coordinator 可以按路线、按分数过滤证据
- **持久化** — 跨 Agent 调用存活

---

## 8. Flag 检测管线

### 8.1 三级检测

```
Level 1: 正则匹配
    flag{...}, CTF{...}, HCTF{...}, DASCTF{...} 等已知前缀

Level 2: 启发式过滤
    排除 CSS/JS 误报 (input{...}, function{...})
    排除多行内容、含分号冒号的 CSS 块

Level 3: AI 验证
    对模糊匹配调用 LLM 确认是否为真实 flag
    无 API key 时 fail-open（信任正则）
```

### 8.2 FlagEngine

```python
class FlagEngine:
    def scan(text) -> List[FlagCandidate]       # 正则扫描
    def decode_and_scan(text) -> List[...]       # 解码后扫描
    def validate(candidate) -> bool             # AI 验证
```

---

## 9. Web UI 架构

### 9.1 技术栈

- **后端**: FastAPI + Uvicorn
- **实时通信**: Server-Sent Events (SSE)
- **前端**: 原生 HTML/CSS/JS（无框架）

### 9.2 数据流

```
浏览器
  │
  ├── POST /api/solve {target, options}
  │       → 启动 CTFReActAgent
  │
  ├── GET /api/events (SSE)
  │       ← ctf_iteration_start
  │       ← ctf_tool_start
  │       ← ctf_tool_finish
  │       ← ctf_evidence_card
  │       ← ctf_flag_found
  │       ← ctf_complete
  │
  └── GET /api/status
          ← {phase, iteration, route, flag}
```

### 9.3 事件类型

| 事件 | 描述 |
|------|------|
| `ctf_iteration_start` | 新一轮迭代开始 |
| `ctf_tool_start` | 工具调用开始 |
| `ctf_tool_finish` | 工具调用完成 |
| `ctf_helper_triggered` | 确定性 helper 触发 |
| `ctf_fuse_triggered` | 熔断器触发 |
| `ctf_evidence_card` | 新证据发现 |
| `ctf_flag_found` | Flag 找到 |
| `ctf_complete` | 解题完成 |

---

## 10. 辅助子系统

### 10.1 WAF 绕过引擎 (`autopnex/evasion/`)

- `waf_detector.py` — WAF 指纹检测
- `payload_mutator.py` — Payload 变异（大小写、编码、注释插入）
- `rate_controller.py` — 请求速率控制 + 抖动
- `evasion_middleware.py` — 中间件集成

### 10.2 FuseController

熔断器，防止无限循环：

- 连续失败 N 次 → 强制切换路线
- 总预算耗尽 → 停止
- 重复 payload 检测 → 跳过

### 10.3 PromptCompiler

动态编译 LLM prompt，基于 token 预算裁剪：

- 注入 Blackboard 摘要
- 注入路线卡片（当前路线的 payload 提示）
- 注入历史尝试摘要
- 控制总 token 不超过模型限制
