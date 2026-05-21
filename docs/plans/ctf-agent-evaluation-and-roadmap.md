# AutoPenX Web-first 通用 CTF Agent 能力评估与实现路线图

> 评估时间：2026-05-20  
> 项目路径：`C:\Users\86181\Desktop\AutoPenX`  
> 当前定位：Web-first 架构雏形已开始落地，但仍处于集成验证阶段  
> 下一阶段目标：Web-first 通用 CTF Agent  
> 评估方法：源码审阅 + 测试体系复核 + 架构差距分析 + 实现路线设计

---

## 1. 总体结论

`AutoPenX` 目前还不能称为稳定的“通用 CTF 自主解题 Agent”。

更准确的定位是：

- **当前水平**：CTF 辅助/半自主 Agent + Web-first 架构雏形
- **最强方向**：Web CTF，已有 LFI/SSTI/SQLi/CMDI/SSRF/JWT/PHP POP/Upload/XXE/NoSQLi/IDOR/XSS/DirEnum 等 deterministic helper
- **已新增但待验证**：`PromptCompiler`、`WebStateBlackboard`、`RouteCard`、`RouteStateMachine`、`multi_agent.py`
- **主要短板**：接口一致性、真实 benchmark、专项单测、DeepSeek 契约测试、多 Agent 主链路接入
- **推荐战略**：先不要追求 Web/Pwn/Reverse/Crypto/Forensics 全类型通吃，优先把 Web 做成可量化、可复现、可扩展的通用 CTF Agent

下一阶段建议目标：

> 建设 **Web-first 通用 CTF Agent**：以 Web CTF 为主场景，通过结构化黑板、路线状态机、PromptCompiler、RouteCard、deterministic helper 与少量 specialist LLM Agent 协作，实现真实靶场上的自主侦察、漏洞假设、利用链编排、失败复盘与 flag 验证。

一句话总结：

> AutoPenX 已经从“Web helper 自动化雏形”推进到“Web-first 架构组件初步落地”阶段；`PromptCompiler`、`WebStateBlackboard`、`RouteCard`、`RouteStateMachine` 和最小多 Agent 编排已经出现，但仍需要修复接口一致性、补专项测试、接入真实 benchmark，才能称为稳定可用的 Web-first 通用 CTF Agent。

---

## 2. 当前能力基线

### 2.1 Agent 主循环

当前已有可运行的 ReAct 式 Agent：

| 组件 | 文件 | 当前作用 |
|---|---|---|
| 主 Agent | `autopnex/ctf/react_agent.py` | ReAct 循环、LLM 调用、工具执行、helper 触发 |
| LLM 封装 | `autopnex/orchestrator/llm_client.py` | DeepSeek/OpenAI-compatible 调用 |
| 工具网关 | `autopnex/ctf/tool_router.py` | 注册并执行 CTF 工具 |
| 策略引擎 | `autopnex/ctf/strategy.py` | 路线预算、去重、证据评分 |
| helper 分发 | `autopnex/ctf/helpers/dispatcher.py` | Web deterministic helper 短路执行 |
| 熔断器 | `autopnex/ctf/fuse_controller.py` | 重复动作、无证据、错误模式、空转检测 |
| Critic | `autopnex/ctf/critic.py` | 规则审查 + AICritic 兜底 |
| Worker | `autopnex/ctf/workers.py` | 后台固定任务执行 |
| Consensus | `autopnex/ctf/consensus.py` | Worker 结果聚合 |

这些说明项目不是单纯脚本集合，而是已经有 Agent 框架骨架。

### 2.2 Web helper 自动化

当前 Web 是最强方向，helper 覆盖：

- **源码泄露**：`.git`、备份文件、配置文件、composer 线索
- **LFI/路径穿越**：常见路径、flag 路径、`php://filter`
- **SSTI**：Jinja2/Twig/Smarty 等模板注入
- **SQLi**：报错、Union、基础布尔探测
- **CMDI**：命令分隔符、常见读 flag 命令
- **SSRF**：localhost、file、metadata mock
- **JWT**：none、弱密钥、kid 类思路
- **Upload**：MIME、后缀、WebShell 基础尝试
- **XXE**：本地文件读取、基础实体注入
- **NoSQLi**：Mongo 风格基础绕过
- **IDOR**：对象 ID 替换
- **XSS**：基础反射/存储信号
- **DirEnum**：常见目录枚举

当前模式更像：

```text
LLM 触发探索
  -> 工具返回响应
    -> helper 基于响应模式匹配
      -> 命中后自动补充利用请求
```

这个模式对固定模板题很有效，但对以下场景不足：

- **复杂登录链**
- **CSRF token / session 状态**
- **多阶段上传链**
- **源码泄露后的审计链**
- **GraphQL / WebSocket**
- **XSS admin bot**
- **WAF/过滤器自适应绕过**
- **非标准参数名**
- **需要脚本化盲注或爆破的题**

### 2.3 DeepSeek 适配

当前 DeepSeek 主链路已经接入：

- **OpenAI-compatible SDK**
- **tools / tool_choice**
- **assistant content=None 兼容**
- **tool_calls 后接 tool messages**
- **reasoning_content 提取与回灌**
- **AICritic 独立 LLM 调用**

主要风险：

- **仍缺真实 API 契约测试**
- **`deepseek-chat` 与 `deepseek-reasoner` 能力边界未验证**
- **thinking + tools 的组合兼容性未验证**
- **无模型降级策略**
- **已有启发式 token 预算，但仍非 tokenizer 精确计数**

### 2.4 多 Agent 现状

当前已有 `AgentPool`、`TaskQueue`、`Consensus`、`ReconWorker`、`WebExploitWorker`、`ReverseCryptoWorker`。

此外，项目已新增 `autopnex/ctf/multi_agent.py`，包含：

- **`CoordinatorAgent`**
- **`ReconAgent`**
- **`ExploitAgent`**
- **`CriticAgent`**
- **`MultiAgentOrchestrator`**

因此当前状态应拆开看：

- **旧 worker/consensus**：后台 worker 并发与结果聚合基础设施
- **新 multi_agent.py**：最小多 Agent 协作雏形已经出现
- **主链路接入**：仍未证明已经替代或稳定接入 `CTFReActAgent.solve()`
- **接口一致性**：仍存在明显风险，需要优先修复

仍不能称为：

> 成熟多智能体自主协作解题系统。

关键原因：

- **多 Agent 协作尚无专项测试**
- **`multi_agent.py` 存在与 `WebStateBlackboard` 的接口不一致风险**
- **主 Agent 仍主要走 ReAct + helper 路径**
- **尚无真实多 Agent benchmark 证明**
- **Consensus 仍是启发式结果聚合，不等同于成熟协商裁决**

### 2.5 本次项目完成情况复核

复核时间：2026-05-20。

本次复核重点检查了计划项是否已经以代码形式落地、是否接入主链路、是否有测试证明。

| 模块/目标 | 当前状态 | 证据 | 结论 |
|---|---|---|---|
| `PromptCompiler` | 🟡 部分完成 | `autopnex/ctf/prompt_compiler.py` 已存在，`react_agent.py` 已导入并用于 `_build_initial_messages()` | 架构已接入，但仍会追加知识库/source/skills 上下文，prompt 瘦身未完全完成 |
| `WebStateBlackboard` | 🟡 部分完成 | `autopnex/ctf/web_state_blackboard.py` 已存在，`react_agent._update_blackboard()` 已调用 `ingest_tool_result()` | 状态模型已落地，但专项测试缺失，接口仍需统一 |
| `RouteCard` | ✅ 基本完成 | `autopnex/ctf/route_cards.py` 已定义 13 类 route cards | 作为 prompt route layer 已可用 |
| `RouteStateMachine` | 🟡 部分完成 | `autopnex/ctf/route_state_machine.py` 已定义 13 类机器及 `run_route()` | 文件完整度高，但未确认主 Agent 稳定调用，专项测试缺失 |
| ReAct 主链路接入黑板 | 🟡 部分完成 | `react_agent.py` 已调用 `_update_blackboard()` | 接入点存在，但诊断函数引用 `self._blackboard.evidence_cards`，而黑板实际字段为 `evidence`，存在潜在运行错误 |
| Prompt token 预算 | 🟡 部分完成 | `TokenBudget` 与 `check_budget()` 已实现 | 是启发式估算，不是精确 tokenizer；超预算只粗略移除 skills |
| Web benchmark 靶场目录 | 🟡 部分完成 | `tests/benchmark/web_targets/` 已存在 | 目录为空，30 题 benchmark 未建立 |
| 本地 E2E baseline | ✅ 已有基础 | `tests/benchmark/web_e2e_targets.py` 提供 6 个 Flask endpoint；`test_web_e2e_baseline.py` 覆盖 LFI/SSTI/SQLi/CMDI/SSRF/JWT | 证明 helper + HTTP 闭环，不证明真实自主解题 |
| Web autonomy 测试 | 🟡 烟雾级 | `tests/benchmark/test_web_autonomy.py` 使用真实 LLM，但失败也通过结构校验 | 不能作为成功率 benchmark |
| DeepSeek 契约测试 | ❌ 未完成 | 未发现 `tests/llm/test_deepseek_contract.py` 或 `requires_deepseek` 专项矩阵测试 | 仍需补齐 |
| 多 Agent 最小闭环 | 🟡 原型完成 | `multi_agent.py` 定义 Coordinator/Recon/Exploit/Critic/Orchestrator | 可导入，最小空跑不崩，但存在接口不一致与缺测试问题 |
| 多 Agent 接口一致性 | ⚠️ 有风险 | `multi_agent.py` 使用 `add_endpoint`、`add_candidate_flag`、`EvidenceCard(...)` 对象式传参、`attempt.tool_name`；黑板实际为 `record_endpoint`、`add_flag_candidate`、`add_evidence(route,...)`、`attempt.tool` | 一旦命中相关代码路径可能报错，应优先修复 |
| GraphQL/WebSocket/XSS admin bot | 🟡 设计/卡片/状态机层 | `route_cards.py` 与 `route_state_machine.py` 已包含对应路线 | 还未见 benchmark 与真实工具闭环证明 |

当前综合判断：

> 项目已经完成 M1/M2/M4 的“代码骨架初步落地”，但还没有完成“测试证明、接口收敛、真实 benchmark、成功率评估”。下一步不应继续扩展新功能，而应优先做接口修复、专项测试和真实 benchmark。

---

## 3. 目标重定义：Web-first 通用 CTF Agent

### 3.1 不建议的目标

短期不建议把目标写成：

> 通用 CTF 全自动解题 Agent。

原因：

- **Pwn 自动利用闭环缺口很大**
- **Reverse 需要静态/动态分析与约束求解**
- **Crypto/Forensics/Misc capability 仍是 stub**
- **全类型 benchmark 成本高**
- **过早扩展会稀释 Web 主线**

### 3.2 推荐目标

推荐目标：

> Web-first 通用 CTF Agent。

含义：

- **Web-first**：优先覆盖 Web CTF 主流题型
- **通用**：不是只靠固定 payload，而是能侦察、建模、推理、验证和切线
- **Agent**：不是单次扫描器，而是多轮状态驱动解题系统
- **可评估**：用真实 benchmark 成功率证明，而不是只靠 mock 测试

### 3.3 能力边界

第一阶段应覆盖：

- **源码泄露 / 备份文件 / `.git`**
- **LFI / 路径穿越 / `php://filter`**
- **SSTI**
- **SQLi**
- **CMDI**
- **SSRF**
- **JWT**
- **Upload**
- **PHP POP / Phar**
- **XXE**
- **NoSQLi**
- **IDOR**
- **XSS admin bot 基线**
- **GraphQL 基线**
- **WebSocket 基线**
- **JS bundle / source map / API 枚举**

暂不作为第一阶段主目标：

- **复杂内网横向移动**
- **真实浏览器 bot 全自动利用全部场景**
- **深度 Java 反序列化 gadget 自动生成**
- **全自动 0day CVE 发现**
- **通用二进制利用**

---

## 4. 推荐总体架构

### 4.1 架构图

```text
CTFWebAgent
  ├── Coordinator
  │   ├── 读取黑板状态
  │   ├── 选择攻击路线
  │   ├── 分配预算
  │   ├── 调用 PromptCompiler
  │   └── 裁决继续/切线/停止
  │
  ├── WebStateBlackboard
  │   ├── TargetProfile
  │   ├── EndpointMap
  │   ├── FormMap
  │   ├── ParameterMap
  │   ├── AuthState
  │   ├── EvidenceCards
  │   ├── Hypotheses
  │   ├── Attempts
  │   ├── Blockers
  │   └── CandidateFlags
  │
  ├── RouteStateMachines
  │   ├── source_leak
  │   ├── lfi
  │   ├── ssti
  │   ├── sqli
  │   ├── cmdi
  │   ├── ssrf
  │   ├── jwt
  │   ├── upload
  │   ├── php_pop
  │   ├── xxe
  │   ├── nosqli
  │   ├── idor
  │   ├── xss
  │   ├── graphql
  │   └── websocket
  │
  ├── Specialist Agents
  │   ├── ReconAgent
  │   ├── SourceAuditAgent
  │   ├── ExploitAgent
  │   ├── ChainAgent
  │   ├── ToolsmithAgent
  │   └── CriticAgent
  │
  ├── PromptCompiler
  │   ├── Core Prompt
  │   ├── State Summary
  │   ├── RouteCard 检索
  │   ├── Token Budget
  │   └── History Compression
  │
  └── BenchmarkHarness
      ├── 真实 LLM
      ├── 真实工具执行
      ├── 成功率统计
      ├── 平均轮数统计
      ├── helper/LLM 归因
      └── 失败原因分类
```

### 4.2 核心设计原则

- **状态优先**：不要依赖 LLM 记忆完整对话，状态必须写入黑板
- **证据优先**：每个假设必须绑定 evidence
- **路线优先**：当前只执行最有信息增益的一条路线
- **预算优先**：每条路线有独立 attempt/token/time 预算
- **deterministic 优先**：标准探测和固定利用先用程序，非标准绕过再用 LLM
- **低频 Critic**：Critic 在卡住、路线冲突、熔断时调用，不要每轮浪费 token
- **可复现优先**：每次动作、输入、输出、原因都要可回放

---

## 5. Prompt 弊端与解决方案

### 5.1 当前 Prompt 问题

当前 `_build_initial_messages()` 将大量内容一次性塞入初始 prompt：

- **CTF_REACT_PLAN_PROMPT**
- **CTF_TYPE_PROMPTS**
- **45+ 条用户指令**
- **静态源码分析结果**
- **知识库检索结果**
- **CTF skills**
- **历史经验**

主要问题：

- **提示词过长**：DeepSeek 可能忽略后半段
- **技巧互相干扰**：当前是 LFI，却同时塞 SQLi/JWT/XSS/POP
- **强引导降低探索能力**：模型容易机械套 payload
- **每轮携带全量初始内容**：上下文成本高
- **无 token 计数保护**：可能静默截断
- **无动态摘要**：工具历史越长，模型越难判断当前状态

### 5.2 推荐方案：PromptCompiler

新增 `PromptCompiler`，替代巨型 `_build_initial_messages()`。

职责：

- **构建最小可用 prompt**
- **按当前路线选择 RouteCard**
- **压缩历史为 State Summary**
- **按 token budget 裁剪**
- **避免重复注入无关知识**
- **在工具失败后注入针对性纠错提示**

推荐接口：

```python
class PromptCompiler:
    def build_messages(
        self,
        challenge: ChallengeContext,
        state: WebStateBlackboard,
        route: str,
        budget: TokenBudget,
    ) -> list[dict]:
        ...
```

### 5.3 Prompt 四层结构

#### 第一层：Core Prompt

只放永远不变的规则：

```text
你是 Web CTF Agent。
你必须基于证据行动。
每轮只选择一个最高信息增益动作。
不要重复已经失败的动作。
所有假设必须绑定 evidence。
发现 flag 后必须验证并停止。
```

建议控制在 **300-500 中文字**。

#### 第二层：Task Context

只放题目上下文：

- **目标 URL**
- **flag 格式**
- **挑战类型**
- **工具清单**
- **轮数预算**
- **时间预算**
- **当前路线**

#### 第三层：State Summary

由黑板自动生成：

```json
{
  "tech_stack": ["PHP", "nginx"],
  "endpoints": ["/", "/login", "/upload"],
  "forms": [
    {"path": "/login", "fields": ["username", "password"]}
  ],
  "cookies": ["PHPSESSID"],
  "interesting_params": ["file", "page", "url"],
  "top_evidence": [
    {
      "route": "lfi",
      "score": 0.72,
      "detail": "page 参数触发 include warning"
    }
  ],
  "failed_attempts": [
    {
      "route": "sqli",
      "reason": "单引号无报错且响应无差异"
    }
  ]
}
```

#### 第四层：RouteCards

只注入当前路线相关技巧。

例如当前路线是 LFI，只注入：

- **LFI 基础探测**
- **编码绕过**
- **`php://filter`**
- **常见 flag 路径**
- **源码泄露后切到 source_audit**

不要同时注入 SQLi、JWT、POP、XSS。

### 5.4 RouteCard 设计

推荐数据结构：

```json
{
  "id": "lfi_php_filter",
  "route": "lfi",
  "triggers": [
    "参数名包含 file/page/path/template/include",
    "响应出现 failed to open stream",
    "响应出现 include() warning"
  ],
  "probes": [
    "../../../etc/passwd",
    "..%2f..%2f..%2fetc/passwd",
    "php://filter/convert.base64-encode/resource=index.php"
  ],
  "handoffs": [
    {
      "condition": "成功读取 PHP 源码",
      "next_route": "source_audit"
    }
  ],
  "stop_conditions": [
    "读到 flag",
    "参数不可控",
    "所有编码绕过无响应差异"
  ],
  "common_mistakes": [
    "不要只试 /etc/passwd，CTF flag 通常在 /flag、/flag.txt、/app/flag.txt",
    "php://filter 读到的是 base64，需要解码后再扫描 flag 和源码 sink",
    "URL 编码要区分客户端编码和服务端二次解码"
  ]
}
```

### 5.5 History Compression

不要把所有历史消息塞回 LLM。

建议每轮只保留：

- **最近 2-4 次关键动作**
- **当前路线最高分 evidence**
- **失败路线摘要**
- **候选 flag**
- **当前 blocker**

历史压缩原则：

- **工具原始长响应不要进入 prompt**
- **HTML 页面只保留 title、forms、links、scripts、interesting snippets**
- **错误栈只保留关键行**
- **JS bundle 只保留 endpoint、secret、route、API schema**

---

## 6. WebStateBlackboard 设计

### 6.1 为什么需要黑板

当前系统主要依赖消息历史和 helper 输出。成熟 Web Agent 必须有结构化状态，否则会出现：

- **重复请求同一路径**
- **忘记已失败 payload**
- **丢失 cookie/CSRF**
- **不能比较响应差异**
- **无法判断哪条路线证据最强**
- **无法复现解题过程**

### 6.2 推荐数据模型

```text
WebStateBlackboard
  ├── TargetProfile
  │   ├── base_url
  │   ├── status
  │   ├── headers
  │   ├── tech_stack
  │   └── fingerprints
  │
  ├── EndpointMap
  │   ├── path
  │   ├── method
  │   ├── status_code
  │   ├── content_type
  │   ├── discovered_from
  │   └── last_seen
  │
  ├── FormMap
  │   ├── action
  │   ├── method
  │   ├── fields
  │   ├── csrf_field
  │   └── auth_related
  │
  ├── ParameterMap
  │   ├── name
  │   ├── locations
  │   ├── suspected_routes
  │   ├── reflection
  │   └── mutation_history
  │
  ├── AuthState
  │   ├── cookies
  │   ├── csrf_tokens
  │   ├── roles
  │   ├── users
  │   └── session_validity
  │
  ├── EvidenceCards
  │   ├── route
  │   ├── score
  │   ├── source
  │   ├── observation
  │   ├── request_id
  │   └── next_hint
  │
  ├── Hypotheses
  │   ├── route
  │   ├── confidence
  │   ├── supporting_evidence
  │   ├── disconfirming_evidence
  │   └── next_action
  │
  ├── Attempts
  │   ├── route
  │   ├── tool
  │   ├── args_hash
  │   ├── result_summary
  │   ├── success
  │   └── failure_reason
  │
  └── CandidateFlags
      ├── value
      ├── source
      ├── confidence
      └── verified
```

### 6.3 黑板更新规则

每次工具执行后必须更新：

- **新 endpoint**
- **新表单**
- **新参数**
- **新 cookie**
- **状态码变化**
- **响应长度变化**
- **错误栈**
- **技术栈指纹**
- **漏洞信号**
- **flag 候选**
- **失败原因**

技术提醒：

- **不要只存 raw response**：必须提取结构化摘要
- **不要只按 URL 去重**：同一 URL 不同 method/body/cookie 是不同尝试
- **不要丢 Set-Cookie**：很多 Web CTF 需要保持 session
- **不要忽略 302**：登录、跳转、open redirect、OAuth 类题都依赖跳转链
- **不要忽略 403/405**：方法绕过、Host 绕过、TRACE/PUT/PATCH 可能有价值

---

## 7. RouteStateMachine 设计

### 7.1 为什么 helper 要升级

当前 helper 是短路式 pattern matching：

```text
响应命中特征 -> helper 尝试固定 payload -> 成功则返回
```

缺点：

- **不能处理多步骤链**
- **不能记录路线内部进度**
- **不能根据失败原因切换 payload**
- **不能把源码泄露结果交给审计器**
- **不能区分“路线无效”和“payload 不够”**

建议升级为路线状态机：

```text
RouteStateMachine
  ├── preconditions
  ├── probes
  ├── evidence scoring
  ├── exploit steps
  ├── fallbacks
  ├── handoffs
  └── stop conditions
```

### 7.2 推荐优先实现路线

| 优先级 | 路线 | 原因 |
|---:|---|---|
| 1 | `source_leak` | Web CTF 高 ROI，可引出审计链 |
| 2 | `lfi` | payload 成本低，flag 命中率高 |
| 3 | `ssti` | 标准探测明确，利用链短 |
| 4 | `sqli` | 常见且需要脚本化盲注 |
| 5 | `cmdi` | 成功后读 flag 直接 |
| 6 | `jwt` | 状态清晰，可 deterministic |
| 7 | `upload` | 多阶段链，适合状态机 |
| 8 | `php_pop` | 与源码泄露强相关 |
| 9 | `ssrf` | 需要内网目标字典和方法约束 |
| 10 | `idor` | 需要对象 ID 与用户状态 |
| 11 | `xss` | 需要 admin bot/browser 支持 |
| 12 | `graphql` | 现代 Web CTF 覆盖补强 |
| 13 | `websocket` | 覆盖实时 API 题 |

### 7.3 LFI 状态机示例

```text
lfi:
  preconditions:
    - 参数名像 file/page/path/template/include
    - 响应出现文件错误、include warning、路径回显

  probes:
    - ../../../etc/passwd
    - ..%2f..%2f..%2fetc/passwd
    - ....//....//....//etc/passwd
    - php://filter/convert.base64-encode/resource=index.php

  evidence:
    - passwd 内容命中 -> score 0.9
    - PHP 源码 base64 命中 -> score 0.8
    - include warning -> score 0.5

  exploit:
    - 尝试 /flag、/flag.txt、/app/flag.txt
    - 尝试 /proc/self/environ
    - 尝试读取源码并交给 source_audit

  fallbacks:
    - 编码绕过
    - 双重编码
    - wrapper 绕过

  handoff:
    - 读到源码 -> source_audit
    - 读到日志路径 -> log_poisoning

  stop:
    - flag verified
    - 参数不可控
    - 所有 payload 无差异
```

### 7.4 Upload 状态机示例

```text
upload:
  preconditions:
    - 存在 multipart/form-data 表单
    - 存在文件名、Content-Type、扩展名过滤

  probes:
    - 上传 txt 探测存储路径
    - 上传图片 polyglot
    - 双后缀 .php.jpg
    - 大小写 .pHp
    - .htaccess + 自定义后缀

  evidence:
    - 响应返回上传路径
    - 文件可访问
    - 服务器解析脚本

  exploit:
    - 上传 webshell
    - 猜测上传目录
    - 验证命令执行
    - 读 flag

  common failures:
    - 只上传成功但不知道路径
    - 路径可访问但不解析 PHP
    - MIME 被检查
    - 内容被重编码
```

技术提醒：

- **上传成功不等于 RCE**
- **能访问文件不等于脚本被解析**
- **图片处理库可能重写内容**
- **路径可能来自响应、JS、源码、目录枚举或时间戳规律**
- **`.htaccess` 只在 Apache 且 AllowOverride 生效时有用**

---

## 8. 多智能体协作设计

### 8.1 实用性判断

成熟多 Agent 对 Web CTF 有实用价值，但前提是职责明确、证据结构化、调用受预算控制。

不推荐：

```text
多个 LLM Agent 互相聊天，各自猜一个漏洞。
```

推荐：

```text
Coordinator 统一调度
  deterministic worker 负责低成本枚举
  specialist LLM agent 负责复杂判断
  Critic agent 负责反证和切线
  黑板保存全部状态和证据
```

### 8.2 推荐 Agent 分工

| Agent | 职责 | 是否频繁调用 LLM |
|---|---|---:|
| Coordinator | 路线选择、预算分配、停止条件裁决 | 是 |
| ReconAgent | 路由、表单、参数、JS、headers、目录枚举 | 否，必要时少量 |
| StateAgent | cookie、CSRF、登录态、角色、对象 ID | 否 |
| SourceAuditAgent | 源码泄露后审计 source/sink | 是 |
| ExploitAgent | 构造 payload、执行路线状态机 | 部分 |
| ChainAgent | 多阶段链编排 | 是 |
| ToolsmithAgent | 写盲注/爆破/解析脚本 | 是 |
| CriticAgent | 反驳假设、检查重复、建议切线 | 低频 |

### 8.3 协作协议

每个 Agent 输出必须是结构化对象，不要输出散文。

推荐格式：

```json
{
  "agent": "ExploitAgent",
  "route": "ssti",
  "hypothesis": "name 参数可能进入 Jinja2 模板渲染",
  "confidence": 0.72,
  "supporting_evidence": ["payload {{7*7}} 返回 49"],
  "next_action": {
    "tool": "http_request",
    "args": {
      "path": "/hello",
      "params": {"name": "{{config}}"}
    }
  },
  "stop_if": ["响应无模板行为", "WAF 拦截所有花括号"]
}
```

### 8.4 多 Agent 容易犯错点

- **不要让每个 Agent 都拿全量上下文**：只给其职责相关黑板切片
- **不要让多个 Agent 同时打同一 payload**：所有动作先过去重器
- **不要让 Critic 只做观点审查**：Critic 必须引用 evidence 和 attempts
- **不要让 Coordinator 只相信 LLM 建议**：必须结合 route score、budget、fuse 状态
- **不要把 Consensus 当多 Agent 协商**：Consensus 只是结果聚合，协作需要假设、反证和裁决协议
- **不要并发破坏状态**：登录态、CSRF、购物车、一次性 token 相关动作必须串行

---

## 9. Benchmark 与验收标准

### 9.1 当前测试问题

当前测试体系中：

- **部分测试 mock LLM**
- **部分失败分支也算结构通过**
- **helper 闭环测试不能证明自主解题**
- **能力评估测试偏静态**

需要明确区分：

| 测试类型 | 是否允许 mock LLM | 目标 |
|---|---:|---|
| smoke | 允许 | 验证结构不崩 |
| unit | 允许 | 验证组件逻辑 |
| helper baseline | 允许 | 验证 deterministic helper |
| autonomy | 不允许 | 验证真实 LLM 决策 |
| benchmark | 不允许 | 统计真实成功率 |

### 9.2 Web Benchmark 题型矩阵

建议至少 30 道本地 Web CTF：

| 类型 | 数量 | 覆盖点 |
|---|---:|---|
| source_leak | 3 | 备份文件、`.git`、配置泄露 |
| LFI | 3 | 直读、编码绕过、`php://filter` |
| SSTI | 3 | Jinja2、Twig、过滤绕过 |
| SQLi | 4 | 报错、Union、布尔盲注、时间盲注 |
| CMDI | 3 | 分隔符、过滤绕过、无回显 |
| SSRF | 3 | localhost、file、metadata mock |
| JWT | 3 | none、弱密钥、kid |
| Upload | 3 | MIME、双后缀、`.htaccess` |
| PHP POP | 2 | 源码泄露、POP 链触发 |
| IDOR | 2 | 数字 ID、UUID/对象引用 |
| XSS admin bot | 2 | cookie theft、same-origin 行为 |
| GraphQL/WebSocket | 2 | introspection、消息鉴权 |

### 9.3 Web-first 阶段验收

达到以下标准后，可称为 Web-first 通用 CTF Agent 初版：

- **30 道本地 Web benchmark 成功率 ≥ 70%**
- **固定模板题成功率 ≥ 85%**
- **多阶段链题成功率 ≥ 50%**
- **真实 DeepSeek，不 mock `_call_llm`**
- **真实工具执行，不 mock `_execute_tool`**
- **平均轮数 ≤ 12**
- **重复动作率 ≤ 10%**
- **失败原因 100% 结构化**
- **每轮 prompt token 有上限**
- **能区分 helper 完成、LLM 决策完成、脚本完成**

### 9.4 报告字段

每次 benchmark 输出：

```json
{
  "challenge": "lfi_php_filter_01",
  "success": true,
  "flag": "flag{...}",
  "rounds": 6,
  "elapsed_seconds": 24.5,
  "token_estimate": 8200,
  "routes_tried": ["recon", "lfi", "source_audit"],
  "winning_route": "lfi",
  "completion_type": "route_state_machine",
  "llm_key_decisions": 2,
  "helper_key_decisions": 4,
  "failure_reason": null,
  "replay_log": "..."
}
```

---

## 10. 实现路线图

### 10.1 第一阶段：Prompt 与状态治理（当前：🟡 部分完成）

目标：

> 解决长 prompt、上下文污染、无 token 预算、历史不可控问题。

当前完成情况：

- ✅ **已新增 `WebStateBlackboard`**
   - 文件：`autopnex/ctf/web_state_blackboard.py`
   - endpoints/forms/params/cookies/evidence/attempts/candidate_flags
   - 工具结果自动抽取摘要
   - 已提供 `state_summary()`、`ingest_tool_result()`、flag candidate、attempt/evidence 记录等基础能力

- ✅ **已新增 `PromptCompiler`**
   - 文件：`autopnex/ctf/prompt_compiler.py`
   - core prompt
   - task context
   - state summary
   - route card 注入
   - token budget 裁剪

- 🟡 **`_build_initial_messages()` 已切到 PromptCompiler，但瘦身未彻底**
   - `react_agent.py` 已使用 `self._compiler.build_messages(...)`
   - 仍会追加知识库、源码分析、skills context
   - 当前 skills context 已压到前 5 条，但仍不是完全 RouteCard 驱动

- 🟡 **已新增 token 预算雏形**
   - 输入 token 估算
   - `check_budget()` 已存在
   - 超预算时主要移除 skills context
   - 仍缺精确 tokenizer 与分层压缩策略

下一步修复项：

1. **统一黑板字段名**
   - `react_agent._get_current_route_card_info()` 中 `self._blackboard.evidence_cards` 应改为实际字段 `self._blackboard.evidence`
   - 所有新增模块统一使用 `record_endpoint()` / `add_flag_candidate()` / `add_evidence(...)`

2. **补专项测试**
   - `tests/ctf/test_prompt_compiler.py`
   - `tests/ctf/test_web_state_blackboard.py`
   - 覆盖 prompt 分层、token budget、history compression、tool result ingest

3. **进一步减少 prompt 污染**
   - skills context 默认不追加，改为只在 route/card 检索命中时注入
   - knowledge context 限制为当前 route 相关结果
   - 大响应一律只进黑板摘要，不进入 LLM 原始消息

### 10.2 第二阶段：RouteCard 与路线状态机（当前：🟡 代码骨架完成，测试不足）

目标：

> 将 helper 从“响应模式触发”升级为“路线状态机”。

当前完成情况：

- ✅ **`RouteCard` 已覆盖 13 类路线**
  - `source_leak`
  - `lfi`
  - `ssti`
  - `sqli`
  - `cmdi`
  - `jwt`
  - `upload`
  - `php_pop`
  - `ssrf`
  - `idor`
  - `xss`
  - `graphql`
  - `websocket`

- ✅ **`RouteStateMachine` 已覆盖 13 类路线**
  - 文件：`autopnex/ctf/route_state_machine.py`
  - 已有 `MACHINE_REGISTRY`
  - 已有 `create_machine()` 与 `run_route()`
  - 已有 source_leak/LFI/SSTI/SQLi/CMDI/JWT/Upload/PHP POP/SSRF/IDOR/XSS/GraphQL/WebSocket 机器

- 🟡 **主链路接入仍不充分**
  - `react_agent.py` 仍主要依赖 ReAct 工具调用 + deterministic helper
  - `RouteStateMachine` 更多由 `multi_agent.py` 的 `ExploitAgent` 使用
  - 尚未证明 `CTFReActAgent.solve()` 已稳定通过状态机完成路线推进

下一步修复项：

1. **为每条核心路线写单元测试**
   - `tests/ctf/test_route_state_machine_lfi.py`
   - `tests/ctf/test_route_state_machine_ssti.py`
   - `tests/ctf/test_route_state_machine_sqli.py`
   - `tests/ctf/test_route_state_machine_cmdi.py`

2. **定义状态机与 helper 的关系**
   - 短期：保留 helper 作为兜底
   - 中期：helper 内部调用 RouteStateMachine
   - 长期：RouteStateMachine 成为主路径，helper 只做快速命中优化

3. **补接口契约**
   - `run_route()` 返回结构固定化
   - `best_evidence_score`、`stop_reason`、`handoff_target` 必须稳定存在
   - 所有机器都必须支持无参数安全退出

### 10.3 第三阶段：真实 Web benchmark（当前：🔴 未完成，只有 baseline）

目标：

> 证明真实 DeepSeek + 真实工具链能解题。

当前完成情况：

- 🟡 **目录已存在但为空**
  - `tests/benchmark/web_targets/`

- ✅ **已有 6 个 baseline endpoint**
  - 文件：`tests/benchmark/web_e2e_targets.py`
  - 覆盖 LFI/SSTI/SQLi/CMDI/SSRF/JWT

- ✅ **已有 helper + HTTP 闭环测试**
  - 文件：`tests/benchmark/test_web_e2e_baseline.py`
  - 明确 mock LLM，只证明 deterministic helper 与真实 HTTP 工具链可用

- 🟡 **已有 autonomy 烟雾测试**
  - 文件：`tests/benchmark/test_web_autonomy.py`
  - 使用真实 LLM，但失败也通过结构校验
  - 不能作为自主成功率 benchmark

下一步修复项：

1. **建立真正 benchmark 靶场**
   - `tests/benchmark/web_targets/lfi_basic/`
   - `tests/benchmark/web_targets/ssti_jinja/`
   - `tests/benchmark/web_targets/sqli_union/`
   - `tests/benchmark/web_targets/cmdi_filter/`
   - 每题独立启动、固定 flag、固定端口或随机端口注册

2. **新增严格 autonomy benchmark**
   - 不允许 mock `_call_llm`
   - 不允许 mock `_execute_tool`
   - 失败不能通过
   - 必须断言：
     ```python
     assert result["success"] is True
     assert result["flag"] == expected_flag
     ```

3. **输出报告**
   - JSON 报告：机器可读
   - Markdown 报告：人工复盘
   - 字段包括成功率、平均轮数、平均耗时、失败原因、winning route、helper/LLM/状态机归因

### 10.4 第四阶段：实用多 Agent（当前：🟡 原型完成，⚠️ 接口风险）

目标：

> 从 worker 并发升级为假设协作。

当前完成情况：

- ✅ **最小闭环类已出现**
  - `CoordinatorAgent`
  - `ReconAgent`
  - `ExploitAgent`
  - `CriticAgent`
  - `MultiAgentOrchestrator`

- ✅ **最小导入与空跑可通过**
  - 关键模块可导入
  - `MultiAgentOrchestrator(...).run_loop(max_rounds=1)` 最小场景不崩

- ⚠️ **存在接口不一致风险**
  - `multi_agent.py` 使用 `self.blackboard.add_endpoint(...)`
  - 但 `WebStateBlackboard` 实际是 `record_endpoint(...)`
  - `multi_agent.py` 使用 `add_candidate_flag(...)`
  - 但 `WebStateBlackboard` 实际是 `add_flag_candidate(...)`
  - `multi_agent.py` 使用 `attempt.tool_name`
  - 但 `AttemptRecord` 实际字段是 `tool`
  - `multi_agent.py` 用 `EvidenceCard(...)` 对象传给 `add_evidence(...)`
  - 但 `add_evidence()` 实际签名是 `add_evidence(route, score, source, observation, next_hint="")`

当前可认为已完成：

```text
Coordinator
  + ReconAgent
  + ExploitAgent
  + CriticAgent
  + WebStateBlackboard
```

但它仍是：

> 多 Agent 原型，而不是可依赖的成熟协作解题主链路。

下一步修复项：

1. **先修接口一致性**
   - 替换 `add_endpoint` → `record_endpoint`
   - 替换 `add_candidate_flag` → `add_flag_candidate`
   - 替换 `attempt.tool_name` → `attempt.tool`
   - 修正 `add_evidence()` 调用方式

2. **补 `tests/ctf/test_multi_agent.py`**
   - Coordinator 路线选择
   - ReconAgent 扫描并写入黑板
   - ExploitAgent 调用 `run_route()`
   - CriticAgent 检测重复尝试
   - Orchestrator 单轮/多轮不崩

3. **再决定是否接入主 Agent**
   - 短期作为实验入口
   - 不要直接替换 `CTFReActAgent.solve()`
   - 等测试稳定后再用 feature flag 启用

后续再加：

- **SourceAuditAgent**
- **ToolsmithAgent**
- **ChainAgent**
- **StateAgent**

### 10.5 第五阶段：现代 Web 能力补强（当前：🟡 设计已有，闭环不足）

当前完成情况：

- 🟡 **GraphQL/WebSocket/XSS 已有 RouteCard 与状态机**
- 🟡 **`route_state_machine.py` 已包含 `GraphQLMachine`、`WebSocketMachine`、`XSSMachine`**
- ❌ **尚无对应 benchmark**
- ❌ **尚无浏览器/admin bot 自动化闭环**
- ❌ **尚未看到 JS bundle/source map 专项 analyzer 与测试**

下一步修复项：

1. **先补 JS/API 枚举能力**
   - 提取 JS 中 `/api/...`、GraphQL endpoint、WebSocket URL
   - source map 下载与还原
   - secret/token/route hint 提取

2. **补现代 Web benchmark**
   - GraphQL introspection 题
   - GraphQL authz 题
   - WebSocket 消息鉴权题
   - XSS admin bot 基础题

3. **接入 Playwright/browser automation**
   - 仅用于 admin bot/XSS/前端状态题
   - 与普通 HTTP agent 分离 session
   - benchmark 后清理浏览器上下文

### 10.6 当前最高优先级修复清单

不要继续先扩展新路线。当前最高优先级是：

1. **修复接口不一致**
   - `react_agent.py`: `evidence_cards` → `evidence`
   - `multi_agent.py`: `add_endpoint` → `record_endpoint`
   - `multi_agent.py`: `add_candidate_flag` → `add_flag_candidate`
   - `multi_agent.py`: `attempt.tool_name` → `attempt.tool`
   - `multi_agent.py`: `add_evidence(EvidenceCard(...))` → `add_evidence(route=..., score=..., source=..., observation=...)`

2. **补新增模块单测**
   - `test_prompt_compiler.py`
   - `test_web_state_blackboard.py`
   - `test_route_cards.py`
   - `test_route_state_machine.py`
   - `test_multi_agent.py`

3. **把 autonomy 测试拆成 smoke 与 benchmark**
   - smoke：允许失败，只测结构
   - benchmark：不允许失败，必须拿到 flag

4. **建立 30 题 Web benchmark 的前 8 题**
   - source_leak 1
   - LFI 2
   - SSTI 1
   - SQLi 2
   - CMDI 1
   - JWT 1

5. **补 DeepSeek 契约测试**
   - `thinking + tools`
   - `tool_calls + reasoning_content`
   - `tool message 回灌`
   - `deepseek-chat/deepseek-reasoner` 差异

### 10.7 技术实现细节要求

以下是各修复项/新增项的精确实现规格，实现时必须满足这些约束。

#### 10.7.1 接口一致性修复：精确变更表

| 文件 | 当前错误写法 | 正确写法 | 位置提示 |
|---|---|---|---|
| `react_agent.py` | `self._blackboard.evidence_cards` | `self._blackboard.evidence` | `_get_current_route_card_info()` 内 |
| `multi_agent.py` | `self.blackboard.add_endpoint(path=..., method=..., status_code=...)` | `self.blackboard.record_endpoint(path=..., method=..., status_code=...)` | `ReconAgent._process_direnum()` |
| `multi_agent.py` | `self.blackboard.add_candidate_flag(flag, source=..., confidence=...)` | `self.blackboard.add_flag_candidate(flag, source=..., confidence=...)` | `ExploitAgent._run_route()` |
| `multi_agent.py` | `attempt.tool_name` | `attempt.tool` | `CriticAgent._detect_repeats()` |
| `multi_agent.py` | `self.blackboard.add_evidence(EvidenceCard(route=..., score=..., source=..., observation=...))` | `self.blackboard.add_evidence(route=..., score=..., source=..., observation=...)` | `ExploitAgent._run_route()` |

修复后验证方式：

```python
# 最小冒烟验证脚本 scripts/verify_interface_consistency.py
from autopnex.ctf.web_state_blackboard import WebStateBlackboard
from autopnex.ctf.multi_agent import MultiAgentOrchestrator

bb = WebStateBlackboard("http://127.0.0.1:9999")
bb.record_endpoint(path="/test", method="GET", status_code=200)
bb.add_flag_candidate("flag{test}", source="verify", confidence=0.9)
bb.add_evidence(route="lfi", score=0.8, source="verify", observation="test")
assert len(bb.evidence) == 1
assert len(bb.candidate_flags) == 1

orch = MultiAgentOrchestrator("http://127.0.0.1:9999", max_rounds=2)
found, flag, log = orch.run_loop(max_rounds=2)
assert isinstance(log, list)
print("PASS: interface consistency verified")
```

#### 10.7.2 `WebStateBlackboard` 接口契约

核心公共 API 签名（实现时不得随意更改）：

```python
class WebStateBlackboard:
    # 属性
    target_url: str
    endpoints: List[EndpointRecord]
    forms: List[FormRecord]
    params: List[ParamRecord]
    evidence: List[EvidenceCard]        # 注意不是 evidence_cards
    attempts: List[AttemptRecord]
    candidate_flags: List[CandidateFlag]
    tech_stack: Dict[str, Any]

    # 写入方法
    def record_endpoint(self, path: str, method: str = "GET",
                        status_code: int = 0, **kwargs) -> EndpointRecord: ...
    def record_form(self, action: str, method: str, fields: List[str],
                    **kwargs) -> FormRecord: ...
    def record_param(self, name: str, location: str, sample: str = "",
                     **kwargs) -> ParamRecord: ...
    def add_evidence(self, route: str, score: float, source: str,
                     observation: str, next_hint: str = "") -> EvidenceCard: ...
    def add_flag_candidate(self, flag: str, source: str,
                           confidence: float = 0.5) -> CandidateFlag: ...
    def record_attempt(self, tool: str, args_hash: str,
                       success: bool, **kwargs) -> AttemptRecord: ...

    # 批量摄入
    def ingest_tool_result(self, tool_name: str, tool_args: Dict[str, Any],
                           result: Dict[str, Any], route_hint: str = "") -> Dict[str, Any]: ...

    # 查询方法
    def state_summary(self, max_chars: int = 2000) -> Dict[str, Any]: ...
    def check_and_record_flag(self, text: str, source: str = "") -> Optional[str]: ...
    def get_top_routes(self, top_k: int = 3) -> List[Tuple[str, float]]: ...
```

`AttemptRecord` 数据类字段：

```python
@dataclass
class AttemptRecord:
    tool: str               # 注意不是 tool_name
    args_hash: str
    success: bool
    route: str = ""
    error: str = ""
    timestamp: float = 0.0
```

`EvidenceCard` 数据类字段：

```python
@dataclass
class EvidenceCard:
    route: str
    score: float            # 0.0 ~ 1.0
    source: str             # 产生该证据的 tool 或 helper 名
    observation: str        # 截断到 500 字符
    request_id: str = ""
    next_hint: str = ""
    timestamp: float = 0.0
```

#### 10.7.3 `PromptCompiler` 实现规格

**4 层结构固定顺序**：

```
messages[0] = system: CorePrompt + TaskContext + StateSummary + RouteCard
messages[1..n] = history (已压缩)
```

**TokenBudget 公式**：

```python
@dataclass
class TokenBudget:
    total: int = 8000           # 单次请求输入上限（字符数估算）
    core_prompt: int = 600      # Layer 1 不可压缩
    task_context: int = 800     # Layer 2 不可压缩
    state_summary: int = 1200   # Layer 3 可截断
    route_card: int = 1000      # Layer 4 可截断
    history: int = 4400         # 剩余给历史消息

    def remaining_for_history(self, used: int) -> int:
        return max(0, self.total - used)
```

**压缩策略优先级**（超预算时按此顺序截断）：

1. 移除 skills context（非当前 route 的知识注入）
2. 截断 state_summary 中已关闭路线的 evidence
3. 移除旧历史消息（保留最近 3 轮 + 含 flag/evidence 的轮次）
4. 截断大 HTML/JSON 响应为摘要
5. 最后才压缩 route_card

**禁止行为**：

- 不得在 `build_messages()` 内追加超过 5 条 skills context
- 不得将完整 HTML（>2000 chars）写入历史消息
- 不得同时注入 >1 个 RouteCard
- 不得在 core_prompt 中包含漏洞特定 payload

#### 10.7.4 `RouteStateMachine` 返回值契约

`run_route()` 返回值必须严格为以下结构：

```python
@dataclass
class RouteResult:
    route: str                      # 路线名
    status: Literal["success", "failed", "inconclusive", "handoff"]
    flag: Optional[str] = None      # 仅 status=success 时非空
    best_evidence_score: float = 0.0
    steps_executed: int = 0
    stop_reason: str = ""           # 必须存在，如 "flag_found", "max_steps", "precondition_fail", "no_evidence"
    handoff_target: Optional[str] = None  # status=handoff 时给出下一条路线
    evidence_cards: List[Dict] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
```

**每个具体状态机必须实现的抽象方法**：

```python
class RouteStateMachine(ABC):
    @abstractmethod
    def preconditions_met(self, blackboard: WebStateBlackboard) -> Tuple[bool, str]: ...

    @abstractmethod
    def get_probes(self) -> List[Dict[str, Any]]: ...
        # 返回 [{"tool": "http_request", "args": {...}, "expect": "regex|status|contains"}]

    @abstractmethod
    def score_evidence(self, probe_results: List[Dict]) -> float: ...
        # 返回 0.0~1.0

    @abstractmethod
    def get_exploit_steps(self, evidence_score: float) -> List[Dict[str, Any]]: ...
        # 返回有序步骤列表

    @abstractmethod
    def get_fallbacks(self) -> List[Dict[str, Any]]: ...
        # exploit 失败时的备选

    @abstractmethod
    def get_handoff(self) -> Optional[str]: ...
        # 返回建议切换的路线名，或 None

    @abstractmethod
    def stop_condition(self, state: MachineState) -> Tuple[bool, str]: ...
        # 返回 (是否停止, 原因)
```

**安全退出要求**：

- 任何参数异常时 `run_route()` 返回 `status="failed"`, `stop_reason="invalid_params"`
- 外部 HTTP 超时时返回 `status="inconclusive"`, `stop_reason="timeout"`
- preconditions 不满足时直接返回 `status="failed"`, `stop_reason="precondition_fail"`
- 步骤执行总数上限 = 10，超过即停

#### 10.7.5 `MultiAgentOrchestrator` 协议规格

**Agent 输出格式**（所有 Agent 输出必须为结构化 JSON）：

```python
@dataclass
class AgentDecision:
    agent: str                  # "coordinator" | "recon" | "exploit" | "critic"
    action: str                 # "select_route" | "run_probe" | "run_exploit" | "switch" | "stop"
    route: Optional[str] = None
    tool: Optional[str] = None
    tool_args: Optional[Dict] = None
    reason: str = ""
    confidence: float = 0.0
    budget_used: int = 0        # 已消耗的轮次
    budget_remaining: int = 0   # 剩余轮次
```

**Orchestrator 主循环伪代码**：

```python
def run_loop(self, max_rounds: int = 15) -> Tuple[bool, Optional[str], List[Dict]]:
    for round_idx in range(max_rounds):
        # 1. Coordinator 决策
        decision = self.coordinator.decide(self.blackboard, round_idx, max_rounds)

        if decision.action == "stop":
            break

        # 2. 执行阶段
        if decision.action in ("run_probe", "select_route"):
            result = self.recon.execute(decision, self.blackboard)
        elif decision.action == "run_exploit":
            result = self.exploit.execute(decision, self.blackboard)
        else:
            result = {}

        # 3. Critic 审查
        critique = self.critic.review(decision, result, self.blackboard)

        # 4. 更新黑板
        self.blackboard.record_attempt(
            tool=decision.tool or decision.action,
            args_hash=hash_args(decision.tool_args),
            success=result.get("success", False),
            route=decision.route or "",
        )

        # 5. Flag 检查
        if self.blackboard.candidate_flags:
            best = max(self.blackboard.candidate_flags, key=lambda f: f.confidence)
            if best.confidence >= 0.9:
                return True, best.flag, self.log

        # 6. Critic 建议路线切换
        if critique.get("switch_route"):
            self.coordinator.force_route(critique["switch_route"])

    return False, None, self.log
```

**Coordinator 路线选择规则**：

```python
ROUTE_PRIORITY = {
    "source_leak": 10,   # 最优先
    "lfi": 8,
    "ssti": 8,
    "sqli": 7,
    "cmdi": 7,
    "jwt": 6,
    "upload": 5,
    "ssrf": 5,
    "php_pop": 4,
    "idor": 4,
    "xss": 3,
    "graphql": 3,
    "websocket": 2,
}

# 路线选择公式
route_score = (
    ROUTE_PRIORITY[route] * 0.3
    + evidence_score * 0.5
    + (1.0 - attempts_ratio) * 0.2
)
```

#### 10.7.6 Benchmark 靶场技术规格

**目录结构**：

```
tests/benchmark/web_targets/
├── __init__.py
├── conftest.py              # pytest fixtures: start_target / stop_target
├── registry.py              # 靶场注册表
├── base_target.py           # 靶场基类
├── lfi_basic/
│   ├── app.py               # Flask app
│   ├── flag.txt             # 固定 flag
│   └── metadata.json        # 靶场元数据
├── lfi_filter/
│   ├── app.py
│   ├── flag.txt
│   └── metadata.json
├── ssti_jinja/
│   └── ...
├── sqli_union/
│   └── ...
├── sqli_blind/
│   └── ...
├── cmdi_filter/
│   └── ...
├── jwt_none/
│   └── ...
└── source_leak_git/
    └── ...
```

**`metadata.json` 规格**：

```json
{
  "id": "lfi_basic",
  "name": "LFI Basic - Direct Path Traversal",
  "category": "lfi",
  "difficulty": 1,
  "flag": "flag{lfi_basic_12345}",
  "expected_route": "lfi",
  "expected_max_rounds": 8,
  "port": 0,
  "description": "Direct path traversal via 'file' parameter, no filter",
  "hints": ["GET /read?file=", "flag at /flag.txt"],
  "tags": ["lfi", "path_traversal", "no_filter"]
}
```

**`base_target.py` 基类**：

```python
class BaseWebTarget(ABC):
    def __init__(self, metadata_path: str):
        with open(metadata_path) as f:
            self.metadata = json.load(f)
        self.port: int = 0
        self._process: Optional[subprocess.Popen] = None

    @abstractmethod
    def create_app(self) -> Flask: ...

    def start(self) -> int:
        """启动靶场，返回实际端口号"""
        ...

    def stop(self) -> None:
        """停止靶场，清理资源"""
        ...

    def verify_flag(self, candidate: str) -> bool:
        return candidate.strip() == self.metadata["flag"]

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}"
```

**Benchmark 测试模板**：

```python
# tests/benchmark/test_web_benchmark.py
import pytest
from tests.benchmark.web_targets.registry import ALL_TARGETS

@pytest.mark.benchmark
@pytest.mark.requires_deepseek
@pytest.mark.parametrize("target_id", [t["id"] for t in ALL_TARGETS])
def test_web_benchmark(target_id, benchmark_target, real_agent):
    """严格 benchmark：必须拿到 flag。"""
    target = benchmark_target(target_id)
    result = real_agent.solve(
        target=target.url,
        flag_format="flag{...}",
        max_iterations=15,
        timeout=120,
    )
    assert result["success"] is True, f"Failed: {result.get('failure_reason')}"
    assert target.verify_flag(result["flag"]), f"Wrong flag: {result['flag']}"
    # 记录指标
    result["rounds"] = result.get("iterations", 0)
    result["route_used"] = result.get("winning_route", "unknown")
```

**Benchmark 报告输出格式**：

```json
{
  "run_id": "20260520_143022",
  "model": "deepseek-chat",
  "total_targets": 8,
  "passed": 6,
  "failed": 2,
  "success_rate": 0.75,
  "avg_rounds": 7.3,
  "avg_time_seconds": 34.2,
  "results": [
    {
      "target_id": "lfi_basic",
      "success": true,
      "flag": "flag{lfi_basic_12345}",
      "rounds": 4,
      "time_seconds": 12.1,
      "winning_route": "lfi",
      "attribution": "helper",
      "repeat_ratio": 0.0
    },
    {
      "target_id": "sqli_blind",
      "success": false,
      "flag": null,
      "rounds": 15,
      "time_seconds": 89.3,
      "winning_route": null,
      "attribution": null,
      "failure_reason": "max_iterations_reached",
      "repeat_ratio": 0.33
    }
  ]
}
```

#### 10.7.7 DeepSeek 契约测试精确规格

**文件位置**：`tests/llm/test_deepseek_contract.py`

**测试矩阵**：

| 测试场景 | 模型 | 输入 | 预期输出 | 超时 |
|---|---|---|---|---|
| ping | `deepseek-chat` | `[{"role":"user","content":"reply OK"}]` | `content` 非空 | 10s |
| function_calling | `deepseek-chat` | 带 `tools` 参数 | `tool_calls` 存在 | 15s |
| tool_message_chain | `deepseek-chat` | assistant(tool_calls) + tool(result) | content 引用结果 | 15s |
| thinking_enabled | `deepseek-chat` | `extra_body={"enable_thinking":true}` | `reasoning_content` 或降级 | 20s |
| thinking_with_tools | `deepseek-chat` | thinking + tools 同时传入 | 不崩溃，按优先级返回 | 20s |
| reasoner_ping | `deepseek-reasoner` | 同 ping | content 含推理 | 30s |
| reasoner_tools | `deepseek-reasoner` | 带 tools | 确认行为 (支持/降级/报错) | 30s |
| rate_limit | `deepseek-chat` | 快速连续 5 次 | 识别 429/retry-after | 60s |
| invalid_tool_schema | `deepseek-chat` | 故意错误 tool JSON | 返回错误而非崩溃 | 10s |
| content_none_handling | `deepseek-chat` | 期望 content=None + tool_calls | 正确解析 | 15s |

**测试断言模板**：

```python
@pytest.mark.integration
@pytest.mark.requires_deepseek
class TestDeepSeekContract:

    def test_function_calling_returns_tool_calls(self, llm_client):
        tools = [{
            "type": "function",
            "function": {
                "name": "http_request",
                "description": "Send HTTP request",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "method": {"type": "string"},
                        "url": {"type": "string"},
                    },
                    "required": ["method", "url"],
                },
            },
        }]
        messages = [{"role": "user", "content": "Send GET to http://example.com"}]
        response = llm_client.chat(messages=messages, tools=tools, max_tokens=200)

        # 核心断言
        assert response.get("tool_calls") is not None, "No tool_calls in response"
        assert len(response["tool_calls"]) >= 1
        call = response["tool_calls"][0]
        assert call["function"]["name"] == "http_request"
        args = json.loads(call["function"]["arguments"])
        assert "url" in args

    def test_tool_message_continuation(self, llm_client):
        messages = [
            {"role": "user", "content": "What is at http://target.com/flag?"},
            {"role": "assistant", "content": None, "tool_calls": [{
                "id": "call_001",
                "type": "function",
                "function": {"name": "http_request", "arguments": '{"method":"GET","url":"http://target.com/flag"}'}
            }]},
            {"role": "tool", "tool_call_id": "call_001", "content": '{"status":200,"body":"flag{test123}"}'}
        ]
        response = llm_client.chat(messages=messages, max_tokens=200)

        assert response.get("content") is not None
        assert "flag" in response["content"].lower()

    def test_thinking_graceful_degradation(self, llm_client):
        """thinking 不可用时必须降级而非崩溃"""
        messages = [{"role": "user", "content": "Explain XSS briefly."}]
        try:
            response = llm_client.chat(
                messages=messages,
                max_tokens=200,
                extra_body={"enable_thinking": True, "thinking_budget": 1024}
            )
            # 成功: reasoning_content 可能存在也可能不存在
            assert response.get("content") is not None
        except Exception as e:
            # 降级: 不应是未处理异常
            assert "thinking" in str(e).lower() or "not supported" in str(e).lower()
```

#### 10.7.8 `test_prompt_compiler.py` 规格

```python
class TestPromptCompiler:
    def test_build_messages_returns_4_layers(self, compiler):
        """system 消息包含 core + task + state + route 四层"""
        msgs = compiler.build_messages(
            target="http://x.com", flag_format="flag{...}",
            challenge_type="web", blackboard=mock_bb, route="lfi"
        )
        system_msg = msgs[0]["content"]
        assert "[CORE]" in system_msg or "你是" in system_msg
        assert "http://x.com" in system_msg      # task context
        assert "endpoint" in system_msg.lower()   # state summary
        assert "lfi" in system_msg.lower()        # route card

    def test_token_budget_respected(self, compiler, large_blackboard):
        """输出不超过 TokenBudget.total"""
        msgs = compiler.build_messages(...)
        total_chars = sum(len(m.get("content", "")) for m in msgs)
        assert total_chars <= compiler.budget.total * 1.1  # 10% 容差

    def test_history_compression_preserves_evidence(self, compiler):
        """压缩历史时保留含 evidence/flag 的消息"""
        history = [make_msg(i, has_flag=(i == 5)) for i in range(20)]
        compressed = compiler.compress_history(history, max_chars=2000)
        flag_msgs = [m for m in compressed if "flag" in m.get("content", "")]
        assert len(flag_msgs) >= 1

    def test_only_one_route_card_injected(self, compiler):
        """不论 route 如何切换，system 中只有 1 张 RouteCard"""
        msgs = compiler.build_messages(..., route="ssti")
        card_mentions = msgs[0]["content"].count("RouteCard:")
        assert card_mentions <= 1

    def test_no_raw_html_in_messages(self, compiler, bb_with_html_response):
        """大 HTML 必须被摘要化，不能原样进 prompt"""
        msgs = compiler.build_messages(...)
        for m in msgs:
            assert len(m.get("content", "")) <= 3000
```

#### 10.7.9 `test_web_state_blackboard.py` 规格

```python
class TestWebStateBlackboard:
    def test_ingest_tool_result_extracts_endpoints(self, bb):
        result = {"status": 200, "body": "<a href='/admin'>Admin</a><a href='/api/v1'>API</a>"}
        bb.ingest_tool_result("http_request", {"url": "http://x.com"}, result)
        assert len(bb.endpoints) >= 1

    def test_ingest_tool_result_detects_flag(self, bb):
        result = {"status": 200, "body": "flag{auto_detect_123}"}
        bb.ingest_tool_result("http_request", {"url": "http://x.com/flag"}, result)
        assert len(bb.candidate_flags) == 1
        assert bb.candidate_flags[0].flag == "flag{auto_detect_123}"

    def test_add_evidence_enforces_score_range(self, bb):
        card = bb.add_evidence(route="lfi", score=1.5, source="test", observation="x")
        assert card.score <= 1.0  # 自动截断

    def test_state_summary_within_char_limit(self, bb_with_many_records):
        summary = bb_with_many_records.state_summary(max_chars=1000)
        assert len(str(summary)) <= 1200  # 允许 JSON key 开销

    def test_record_attempt_dedup_hash(self, bb):
        bb.record_attempt(tool="http_request", args_hash="abc123", success=False)
        bb.record_attempt(tool="http_request", args_hash="abc123", success=False)
        assert len(bb.attempts) == 2  # 不去重，但可以统计重复率

    def test_get_top_routes_ordered_by_score(self, bb):
        bb.add_evidence(route="lfi", score=0.9, source="t", observation="o")
        bb.add_evidence(route="ssti", score=0.5, source="t", observation="o")
        bb.add_evidence(route="lfi", score=0.7, source="t", observation="o2")
        top = bb.get_top_routes(top_k=2)
        assert top[0][0] == "lfi"
        assert top[0][1] >= top[1][1]
```

#### 10.7.10 `test_multi_agent.py` 规格

```python
class TestMultiAgentOrchestrator:
    def test_single_round_no_crash(self, orchestrator):
        found, flag, log = orchestrator.run_loop(max_rounds=1)
        assert isinstance(found, bool)
        assert isinstance(log, list)
        assert len(log) >= 1

    def test_coordinator_selects_highest_priority_route(self, orchestrator):
        orchestrator.blackboard.add_evidence(
            route="source_leak", score=0.3, source="test", observation="found .git"
        )
        decision = orchestrator.coordinator.decide(orchestrator.blackboard, 0, 10)
        assert decision.route == "source_leak"  # 最高优先级

    def test_critic_detects_repeat(self, orchestrator):
        for _ in range(4):
            orchestrator.blackboard.record_attempt(
                tool="http_request", args_hash="same_hash", success=False, route="lfi"
            )
        critique = orchestrator.critic.review({}, {}, orchestrator.blackboard)
        assert critique.get("repeat_detected") is True

    def test_exploit_agent_calls_run_route(self, orchestrator, monkeypatch):
        called = {}
        def mock_run_route(route, bb, **kwargs):
            called["route"] = route
            return {"status": "failed", "stop_reason": "test"}
        monkeypatch.setattr("autopnex.ctf.multi_agent.run_route", mock_run_route)
        decision = AgentDecision(agent="exploit", action="run_exploit", route="lfi")
        orchestrator.exploit.execute(decision, orchestrator.blackboard)
        assert called.get("route") == "lfi"

    def test_flag_found_terminates_loop(self, orchestrator):
        orchestrator.blackboard.add_flag_candidate(
            "flag{found}", source="test", confidence=0.95
        )
        found, flag, log = orchestrator.run_loop(max_rounds=10)
        assert found is True
        assert flag == "flag{found}"
```

#### 10.7.11 `test_route_state_machine.py` 通用规格

```python
class TestRouteStateMachineBase:
    """每条路线状态机都必须通过这些基础测试"""

    @pytest.mark.parametrize("route", list(MACHINE_REGISTRY.keys()))
    def test_create_machine_returns_instance(self, route):
        machine = create_machine(route)
        assert isinstance(machine, RouteStateMachine)

    @pytest.mark.parametrize("route", list(MACHINE_REGISTRY.keys()))
    def test_preconditions_met_returns_tuple(self, route, empty_blackboard):
        machine = create_machine(route)
        result = machine.preconditions_met(empty_blackboard)
        assert isinstance(result, tuple)
        assert len(result) == 2
        assert isinstance(result[0], bool)
        assert isinstance(result[1], str)

    @pytest.mark.parametrize("route", list(MACHINE_REGISTRY.keys()))
    def test_get_probes_returns_list(self, route):
        machine = create_machine(route)
        probes = machine.get_probes()
        assert isinstance(probes, list)
        for probe in probes:
            assert "tool" in probe or "action" in probe

    @pytest.mark.parametrize("route", list(MACHINE_REGISTRY.keys()))
    def test_run_route_safe_exit_on_empty_bb(self, route, empty_blackboard):
        """空黑板时不崩溃"""
        result = run_route(route, empty_blackboard, max_steps=2)
        assert "status" in result
        assert result["status"] in ("success", "failed", "inconclusive", "handoff")
        assert "stop_reason" in result
```

---

## 11. 容易犯错的技术细节提醒

### 11.1 HTTP 与状态管理

- **不要丢 cookie**：`Set-Cookie` 必须进入 `AuthState`
- **不要忽略 CSRF token**：表单提交前要刷新 token
- **不要把 302 当失败**：跳转链可能包含登录成功、open redirect、flag path
- **不要只看状态码**：CTF 里 404 页面也可能包含 flag 或线索
- **不要忽略响应长度差异**：盲注和 IDOR 常靠长度变化
- **不要忽略 headers**：`X-Flag`、`Location`、`Server`、`Set-Cookie` 都可能关键
- **不要默认 GET/POST 等价**：方法绕过常见于 Web CTF
- **不要并发修改同一会话状态**：登录态、一次性 token、购物车类题要串行

### 11.2 去重与重试

- **去重不能只看 tool name**：必须包含 method、URL、params、body、headers、cookie
- **参数顺序要 canonicalize**：否则同一请求会重复执行
- **失败要分类**：timeout、connection、403、WAF、no_diff、parse_error 不应混为一类
- **重试不能盲目重复**：重试前必须改变 timeout、headers、payload 或 route
- **不要把网络失败当漏洞失败**：环境问题和攻击路线失败必须分开

### 11.3 Prompt 与 LLM 调用

- **不要每轮塞全量知识库**
- **不要把完整 HTML/JS bundle 塞进 prompt**
- **不要让 prompt 同时指导 10 条路线**
- **不要让 LLM 自己记住已失败 payload**
- **不要假设 DeepSeek 一定支持 thinking + tools**
- **不要假设 `reasoning_content` 一定存在**
- **不要让 tool_calls 后缺少 tool message**
- **不要在 assistant tool_calls 消息里乱填 content**
- **不要无 token 预算运行长会话**

### 11.4 Helper 与路线状态机

- **helper 命中不代表路线已验证**
- **payload 失败不代表漏洞不存在**
- **短路执行可能误杀后续更优 helper**
- **路线切换要保留证据，不要清空上下文**
- **同一 evidence 可以支持多条路线**
- **源码泄露应优先切 source_audit，而不是继续盲打 payload**

### 11.5 LFI / 文件读取

- **`php://filter` 结果通常需要 base64 解码**
- **`/etc/passwd` 成功不等于能读 flag**
- **flag 可能在 `/flag`、`/flag.txt`、`/app/flag.txt`、环境变量、数据库**
- **URL 编码层级要记录**
- **Windows/Linux 路径不要混用**
- **include warning 是强 evidence，但不是直接成功**

### 11.6 SQLi

- **不要只测单引号**
- **布尔盲注要比较响应长度/关键词/状态码**
- **时间盲注要做基线延迟**
- **Union 列数要自动探测**
- **SQLite/MySQL/PostgreSQL payload 不通用**
- **WAF 绕过应由 RouteCard 提供变体，不要全靠 LLM 即兴**

### 11.7 SSTI

- **`{{7*7}}` 不一定适用于所有模板**
- **返回 49 是强 evidence，但还要识别模板引擎**
- **过滤花括号时要尝试编码、变量拼接、属性访问绕过**
- **无 shell 环境时应尝试文件读取类 payload**
- **不要默认 Jinja2，Twig/Smarty/Go template/ERB 都可能出现**

### 11.8 Upload

- **上传成功不等于路径可访问**
- **路径可访问不等于脚本执行**
- **Content-Type、扩展名、文件头可能分别检查**
- **图片处理会破坏 webshell**
- **`.htaccess` 只对特定 Apache 配置有效**
- **上传目录可能不可列目录，需要路径猜测**

### 11.9 JWT/Auth

- **先 decode，不要先 forge**
- **检查 alg、kid、jku、jwk、x5u**
- **不要只测 none**
- **弱密钥爆破要有字典和时间预算**
- **kid 可能是路径穿越或 SQLi**
- **修改 JWT 后要确认服务器是否真的校验签名**
- **cookie 中不一定是 JWT，也可能是 Flask/Django/session pickle**

### 11.10 XSS/Admin Bot

- **反射 XSS 不等于能打 admin bot**
- **必须确认 bot 访问 URL、cookie 作用域、same-site、CSP**
- **`javascript:`、meta refresh、window.name、postMessage 都可能相关**
- **CSP 下可以考虑 JSONP、CDN allowlist、CSS exfil、XS-Leak**
- **浏览器自动化要隔离 session，避免污染 benchmark**

### 11.11 GraphQL/WebSocket

- **GraphQL 先测 introspection**
- **GET GraphQL 可能绕过 CSRF/CORS 预检**
- **alias/batching 可用于绕过限制**
- **WebSocket 握手阶段也有 cookie/origin/auth**
- **消息级鉴权不能只看连接成功**
- **WebSocket fuzz 要记录消息状态机**

### 11.12 Benchmark

- **benchmark 不能把失败也算通过**
- **autonomy 测试不能 mock LLM 决策**
- **helper 成功和 LLM 自主成功要分开统计**
- **每题要固定 flag 和随机种子**
- **每次运行要保存 replay log**
- **失败原因要可聚合**
- **本地靶场要保证启动/清理幂等**

---

## 12. DeepSeek 专项测试建议

新增 `tests/llm/test_deepseek_contract.py`，使用：

```python
@pytest.mark.integration
@pytest.mark.requires_deepseek
```

必须覆盖：

- **普通 chat ping**
- **function calling 返回 tool_calls**
- **tool message 回灌后继续回答**
- **thinking=True 是否可用**
- **reasoning_content 是否存在**
- **thinking + tools 是否兼容**
- **deepseek-chat / deepseek-reasoner 模型矩阵**
- **不支持 thinking 时是否降级**
- **不支持 tool calling 时是否切 JSON action 模式**
- **API 错误、限流、超时分类**

技术提醒：

- **不要把契约测试放进默认 CI**
- **没有 API key 时必须 skip**
- **真实 API 测试要限制 max_tokens 和调用次数**
- **错误消息要脱敏，不要打印 API key**

---

## 13. 文档口径建议

### 13.1 应避免的表述

- “已实现通用 CTF 自主解题”
- “已验证多 Agent 协商解题”
- “DeepSeek 已完整适配所有 function calling 场景”
- “Web CTF 已通用覆盖”
- “benchmark 已证明自主能力”

### 13.2 推荐表述

- “已具备 Web-first 架构组件雏形”
- “已验证 helper + HTTP 闭环”
- “已具备 ReAct 主循环与工具调用框架”
- “PromptCompiler / WebStateBlackboard / RouteCard / RouteStateMachine 已初步落地”
- “多 Agent 最小闭环原型已出现，但接口一致性和测试仍需补齐”
- “真实自主成功率需要 benchmark 验证”
- “下一阶段目标是接口收敛 + 测试证明 + Web benchmark”

---

## 14. 最终建议

AutoPenX 下一阶段最有价值的方向已经不是继续“从零设计 Web-first 架构”，而是：

> 把已经新增的 Web-first 架构组件修到可运行、可测试、可 benchmark，并用真实成功率证明能力。

当前实现重点不是继续堆 payload，也不是继续增加新的 Agent 角色，而是：

1. **修复 `WebStateBlackboard` 与 `multi_agent.py` / `react_agent.py` 的接口不一致**
2. **给 `PromptCompiler`、`WebStateBlackboard`、`RouteCard`、`RouteStateMachine`、`multi_agent.py` 补专项测试**
3. **把 smoke/autonomy/benchmark 测试语义彻底拆开**
4. **先建立 8 道严格 Web benchmark，再扩到 30 道**
5. **补 DeepSeek function calling / thinking 契约测试**
6. **确认 RouteStateMachine 与 helper 的主从关系**
7. **等多 Agent 原型稳定后，再通过 feature flag 接入主解题路径**

更新后的近期里程碑：

```text
M0: 接口一致性修复
    - evidence_cards/evidence
    - add_endpoint/record_endpoint
    - add_candidate_flag/add_flag_candidate
    - attempt.tool_name/attempt.tool
    - add_evidence 调用签名

M1: 新增模块专项测试
    - PromptCompiler
    - WebStateBlackboard
    - RouteCard
    - RouteStateMachine
    - MultiAgentOrchestrator

M2: 严格 Web benchmark 前 8 题
    - 不 mock LLM 决策
    - 失败不能通过
    - 输出 JSON/Markdown 报告

M3: DeepSeek 契约测试
    - tools
    - thinking
    - reasoning_content
    - tool message 回灌

M4: 多 Agent feature flag 接入
    - 默认关闭
    - benchmark 模式可打开
    - 与 ReAct 主链路可对比

M5: 扩展现代 Web benchmark
    - GraphQL
    - WebSocket
    - XSS admin bot
    - JS/source map
```

达到这些后，项目可以比较有底气地称为：

> 具备可测试、可复现、可量化的 Web-first 通用 CTF 半自主 Agent。

只有当严格 Web benchmark 成功率稳定后，才建议继续扩展 Crypto、Reverse、Pwn、Forensics，避免再次进入“代码骨架很多但能力证明不足”的状态。
