# AutoPenX Multi-Agent 讨论共识文档

**日期**: 2026-04-24
**参与方**: 5 位独立专家 Agent + 主持 Agent

---

## 第二轮：交叉否决关键发现

| 否决方 | 被否决方 | 否决点 | 原因 |
|--------|---------|--------|------|
| Agent 2 (检测) | Agent 1 (架构) | 在 VULN_DETECT 阶段使用 asyncio.to_thread 并行 | 需先解决笛卡尔积剪枝，否则并行放大无用请求 |
| Agent 3 (利用链) | Agent 2 (检测) | VULN_VALIDATE 作为独立 FSM 阶段 | 验证应集成到检测 Agent 内部，而非增加 FSM 复杂度 |
| Agent 4 (WAF) | Agent 2 (检测) | 多基线 SSRF 检测增加 3 倍请求 | WAF 环境下额外请求会触发封锁，应先检测 WAF 再决定策略 |
| Agent 1 (架构) | Agent 3 (利用链) | ChainPlanner 在 EXPLOIT 阶段启动前调用 LLM | 应移至 Coordinator 层，避免 EXPLOIT Agent 承担规划职责 |
| Agent 5 (知识) | Agent 4 (WAF) | 27 种 payload 变异策略 | 过度膨胀 payload 空间；应按 WAF 厂商只选 top-5 策略 |
| Agent 4 (WAF) | Agent 5 (知识) | fastembed + FAISS 增加 150MB 依赖 | 渗透测试工具应轻量；建议 PoC 知识库用纯 JSON 匹配而非向量检索 |

## 第三轮：共识收敛

### 全组一致通过的实施优先级

**P0 — 立即修复（安全 + 阻塞性问题）**
1. Web API `start_scan` 增加 `ensure_target_allowed` 校验
2. 移除审批令牌 `target="*"` 通配
3. HMAC 签名密钥与 LLM 密钥解耦
4. LLM 降级显式标记

**P1 — 核心架构升级**
5. 多 Agent 基础设施（Blackboard + BaseAgent + Coordinator）
6. 检测优先级排序 + 笛卡尔积剪枝
7. 并行工具执行（asyncio + Semaphore）
8. 攻击图数据结构 + 攻击链规划器

**P2 — 能力扩展**
9. WAF 检测 + payload 变异引擎（精简版：top-5 策略/厂商）
10. 新利用工具（XSS/AuthBypass/FileUpload/PrivEsc）
11. PoC 知识库（纯 JSON 匹配，暂不引入向量检索）
12. 技术栈→CVE 映射（CPE 匹配）
13. 动态 Wordlist 生成

**P3 — 增强功能（下阶段）**
14. RAG 向量检索（待项目成熟后引入 fastembed+FAISS）
15. 扫描历史学习
16. SSTI/IDOR/XXE 新检测器
17. 三层验证 pipeline（集成在 VulnAgent 内部）

### 架构决策共识

1. **通信模式**: Shared-Blackboard（基于现有 StateFindings）+ Event Bus（基于现有 _emit）
2. **并行粒度**: RECON 全并行、SCAN 部分并行、VULN_DETECT 全并行、EXPLOIT 串行
3. **验证层**: 集成在 VulnDetectAgent 内部（非独立 FSM 阶段），suspected→confirmed 需 2/3 信号
4. **攻击链规划**: 由 Coordinator 调度，ChainPlanner 模板匹配优先 + LLM 补充
5. **WAF 绕过**: 精简方案，按检测到的 WAF 厂商选择 top-5 变异策略
6. **知识库**: P2 阶段用纯 JSON PoC 匹配 + CPE 版本映射；P3 引入向量检索
7. **向后兼容**: `multi_agent=False` 为默认值，现有测试套件零回归
