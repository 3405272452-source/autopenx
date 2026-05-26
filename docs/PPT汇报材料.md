# AutoPenX — AI 驱动的自动化 CTF 解题系统

## 一、项目概述

AutoPenX 是一个基于大语言模型（LLM）的自动化 Web CTF 解题系统，采用"确定性状态机 + 并行 AI 推理"的混合架构，实现从目标识别到漏洞利用的全自动化流程。

**核心定位**：将 CTF Web 安全竞赛中的人工解题过程，转化为可复现、可积累、可并行的自动化流水线。

---

## 二、技术架构

### 2.1 四阶段流水线架构

```
┌─────────────────────────────────────────────────────────────┐
│                    CTFSolvePipeline                          │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌─────────────┐   快速通道（源码可见+单一漏洞）              │
│  │ Fast-Track  │──→ 单 Worker 64K token 直接解题            │
│  └─────────────┘                                            │
│         ↓ (不适用时)                                         │
│  ┌─────────────┐                                            │
│  │  Phase 0    │  知识匹配 + 目标指纹识别                    │
│  └─────────────┘                                            │
│         ↓                                                   │
│  ┌─────────────┐                                            │
│  │  Phase 1    │  并行状态机扫描（19条路线 × ThreadPool）     │
│  └─────────────┘                                            │
│         ↓                                                   │
│  ┌─────────────┐                                            │
│  │  Phase 2    │  并行 LLM Worker 竞速（3 Worker × 15轮）   │
│  └─────────────┘                                            │
│         ↓                                                   │
│  ┌─────────────┐                                            │
│  │  Phase 3    │  ReAct 深度推理（兜底）                     │
│  └─────────────┘                                            │
│         ↓                                                   │
│  ┌─────────────┐                                            │
│  │ Experience  │  经验双写（路线权重 + 快速Payload）          │
│  └─────────────┘                                            │
└─────────────────────────────────────────────────────────────┘
```

### 2.2 核心模块

| 模块 | 职责 | 技术实现 |
|------|------|----------|
| ParallelRouteScan | 并行路线探测 | ThreadPoolExecutor, 19条攻击路线并行 |
| Phase2Runner | 并行 LLM 竞速 | 多线程 Worker, cancel_event 协作取消 |
| Phase2Worker | 单个 AI 解题者 | Tool-calling loop, 动态能力加载 |
| DiscoveryBroadcast | Worker 间信息共享 | 线程安全广播通道, 去重+容量控制 |
| ExperienceWriter | 经验沉淀 | 路线权重更新, Payload 模板提取 |
| KnowledgeSchema | 统一知识库 | JSON schema 迁移, 向后兼容 |
| ResultSummarizer | 智能输出摘要 | Flag 永不丢失保证, 上下文压缩 |

---

## 三、技术特色与创新点

### 3.1 创新点一：确定性 + 概率性混合架构

**问题**：纯 LLM 解题成本高、不稳定；纯规则解题覆盖面窄。

**方案**：
- **Phase 1（确定性）**：19 条 RouteStateMachine 用确定性逻辑快速探测，零 API 成本
- **Phase 2（概率性）**：LLM Worker 基于 Phase 1 证据进行创造性推理

**效果**：简单题 Phase 1 直接解决（<10秒），复杂题由 Phase 2 接力。

### 3.2 创新点二：动态能力加载（Dynamic Capability Loading）

**问题**：通用 system prompt 臃肿，浪费 token，降低推理精度。

**方案**：
```python
def _load_route_capabilities(self, route: str) -> str:
    capabilities = {
        "deserialization": "## PHP反序列化...",
        "sqli": "## SQL注入...",
        "ssti": "## 模板注入...",
        "lfi": "## 文件包含...",
    }
    return capabilities.get(route, default_capability)
```

根据 Phase 1 识别的漏洞类型，只加载对应的攻击知识，减少 70% prompt token。

### 3.3 创新点三：并行竞速 + First-Flag-Wins

**问题**：单 Agent 串行尝试效率低，一条路走不通浪费大量时间。

**方案**：
- 3 个 Worker 并行攻击不同路线
- 最高分路线分配 2 个 Worker（不同 payload 变体）
- 任一 Worker 找到 flag → `cancel_event.set()` → 其他 Worker 立即停止

**效果**：相比串行，理论加速 3x，实际加速 2-2.5x。

### 3.4 创新点四：经验沉淀正反馈循环

**问题**：每次解题从零开始，无法积累经验。

**方案**：
```
解题成功 → ExperienceWriter
  ├── 路线权重 +0.1（下次优先尝试）
  ├── 成功 Payload 存入快速通道（下次直接重放）
  └── 目标指纹→路线映射（相似目标跳过扫描）

解题失败 → ExperienceWriter
  └── 路线权重 -0.05~-0.15（下次降低优先级）
```

**效果**：第二次遇到同类题，解题速度提升 50-80%。

### 3.5 创新点五：Worker 间发现广播

**问题**：并行 Worker 各自为战，重复探索。

**方案**：`DiscoveryBroadcast` 线程安全通道
- Worker A 发现源码泄露 → 广播给 B、C
- Worker B 发现数据库结构 → 广播给 A、C
- 每轮 LLM 调用前注入新发现摘要

**效果**：减少重复探索，Worker 间形成协作。

### 3.6 创新点六：快速通道直接解题

**问题**：简单题（源码可见+单一漏洞）不需要复杂流水线。

**方案**：
- 初始 GET 请求检测到 `unserialize($_POST[...])` 等明确漏洞模式
- 跳过 Phase 0-1，直接启动单 Worker（64K token 预算）
- 本地 Python 执行（零延迟 payload 生成）

**效果**：简单题解题时间从 3-5 分钟降至 30-60 秒。

---

## 四、关键技术指标

| 指标 | 数值 |
|------|------|
| 支持攻击路线 | 19 种（SQLi, SSTI, LFI, RCE, 反序列化, JWT, SSRF 等） |
| 并行扫描速度 | 19 路线 / 4 秒（ThreadPoolExecutor） |
| HTTP 请求预算 | 可配置，默认 100 请求/扫描 |
| 并行 Worker 数 | 3 个（可配置） |
| 单 Worker token 预算 | 12K-64K（动态） |
| 经验知识库 | JSON schema v3，自动迁移 |
| Flag 保留保证 | 摘要压缩时 flag 永不丢失 |
| 向后兼容 | PipelineConfig() 无参数即可运行 |

---

## 五、与同类系统对比

| 维度 | AutoPenX | 通用 Agent (Claude Code) | 传统扫描器 (sqlmap) |
|------|----------|------------------------|-------------------|
| 漏洞覆盖面 | 19 种 Web 漏洞 | 无限（但需人工引导） | 单一类型 |
| 自主性 | 全自动，无需人工 | 需要人工对话引导 | 半自动 |
| 经验积累 | ✅ 自动沉淀 | ❌ 每次从零 | ❌ 无 |
| 并行能力 | ✅ 多 Worker 竞速 | ❌ 单线程 | ❌ 单线程 |
| 成本控制 | ✅ Phase 1 零成本 | ❌ 全程消耗 token | ✅ 无 LLM 成本 |
| 复杂题能力 | 中等（受 token 限制） | 强（200K 上下文） | 弱 |

---

## 六、技术栈

- **语言**：Python 3.10+
- **LLM**：DeepSeek V4 Pro（支持 tool calling + reasoning）
- **并发**：ThreadPoolExecutor + threading.Event 协作取消
- **知识库**：JSON schema + 原子写入 + 自动迁移
- **测试**：pytest, 200+ 单元测试
- **CI/CD**：GitHub Actions

---

## 七、项目结构

```
autopnex/
├── ctf/
│   ├── solve_pipeline.py      # 主流水线（Phase 0→1→2→3）
│   ├── parallel_route_scan.py # 并行路线扫描
│   ├── phase2_runner.py       # 并行 LLM Worker 竞速
│   ├── discovery_broadcast.py # Worker 间发现广播
│   ├── experience_writer.py   # 经验双写
│   ├── knowledge_schema.py    # 统一知识库 schema
│   ├── result_summarizer.py   # 智能输出摘要
│   ├── route_state_machine.py # 状态机基类（19条路线）
│   ├── routes/                # 各攻击路线实现
│   │   ├── sqli.py, ssti.py, lfi.py, ...
│   └── ...
├── orchestrator/
│   └── llm_client.py          # LLM 客户端（多模型支持）
└── ...
```

---

## 八、演示场景

**题目**：PHP 反序列化 + 命令执行（正则过滤绕过）

**AutoPenX 解题流程**：
1. Fast-Track 检测到 `unserialize($_POST['payload'])` → 触发快速通道
2. 动态加载 `deserialization` 能力模块
3. LLM Worker 分析源码 → 识别 `__destruct → __toString → exec()` 链
4. 构造嵌套序列化 payload → 绕过正则（用 `sort -o` 代替 `>`）
5. `ls /` 发现 flag 文件名 → 读取 flag

**耗时**：~60 秒（含 LLM 推理时间）
