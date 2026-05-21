# AutoPenX BUUCTF 20 与 Web Benchmark 完成情况及后续建议

## 1. 文档目的

本文档记录 AutoPenX 在最近一次更新后的实现效果、benchmark 复测结果、已完成能力、当前发现的问题，以及下一阶段建议。

本次评估重点包括：

- `STRICT_BENCHMARK_12` 是否仍保持全通过。
- BUUCTF/classic `real_ctf_20` 是否达到全通过。
- `gxyctf2019_pingpingping` 的 CMDi 空格绕过修复是否有效。
- 新增 `ScenarioHint`、`XXEMachine`、`AuthLogicMachine` 等结构是否已经落地。
- 当前实现是否只是“能过题”，还是已经具备较好的可解释、可复现、可扩展能力。

## 2. 当前复测结论

当前实现已经达到非常明确的阶段性成果：

```text
STRICT_BENCHMARK_12: 12/12 passed
real_ctf_20:         20/20 passed
```

这说明 AutoPenX 目前已经具备稳定解决一组基础 Web CTF benchmark 的能力，并且本次 BUUCTF 20 题调优没有破坏原有 12 题严格 benchmark。

## 3. 现场复测结果

### 3.1 STRICT_BENCHMARK_12

复测命令：

```powershell
python -m pytest tests/benchmark/test_web_benchmark.py -q
```

复测结果：

```text
12 passed in 9.44s
```

最新报告：

```text
benchmark_results/benchmark_12_20260522_005948.json
```

报告指标：

```text
total_targets = 12
passed = 12
failed = 0
success_rate = 1.0
avg_rounds = 1.9
avg_time_seconds = 0.24
```

结论：

- 原有 12 题严格 benchmark 仍然稳定全通过。
- 平均轮次约 `1.9`，说明大多数题已经被确定性路线快速解决。
- 本次 BUUCTF 方向更新没有造成能力回退。

### 3.2 BUUCTF/classic real_ctf_20

复测命令：

```powershell
python -m pytest tests/benchmark/test_real_ctf.py -m real_ctf -q -s
```

复测结果：

```text
20 passed in 61.40s
```

最新报告：

```text
benchmark_results/real_ctf_20260522_010051.json
```

报告指标：

```text
suite = real_ctf_20
run_mode = full
total = 20
passed = 20
failed = 0
success_rate = 1.0
```

结论：

- BUUCTF/classic 20 题已经从之前的 `19/20` 提升到 `20/20`。
- `gxyctf2019_pingpingping` 已经成功解决。
- 当前实现已经达到阶段性 benchmark 全通过目标。

## 4. 已完成情况

### 4.1 PingPingPing CMDi 修复完成

之前失败的核心题目是：

```text
gxyctf2019_pingpingping
```

当前复测结果：

```text
gxyctf2019_pingpingping: rounds=2 time=0.25s flag=flag{gxyctf2019_p1ng_p1ng_p1ng}
```

该题当前由 `cmdi` 状态机解决，说明 `$IFS` 空格绕过方向有效。

已完成能力：

- CMDi route 已包含 `$IFS` 风格 payload。
- 能处理空格被过滤的命令注入场景。
- 对 PingPingPing 风格题型已经能稳定快速命中。

### 4.2 自定义 benchmark 未回退

`STRICT_BENCHMARK_12` 仍然保持：

```text
12/12 passed
```

这说明本次更新不是针对 BUUCTF 20 题的脆弱补丁，而是在不破坏旧能力的前提下提升了覆盖面。

### 4.3 BUUCTF 20 题全通过

当前 `real_ctf_20` 已经全通过：

```text
20/20 passed
```

这说明 AutoPenX 对基础 Web CTF 常见类型已经形成较完整覆盖，包括：

- SQL 注入绕过
- 文件包含
- PHP filter
- SSTI
- CMDi
- SSRF
- PHP 反序列化
- Cookie/auth 绕过
- Header spoofing
- XXE 风格 payload
- 类型比较与弱类型绕过

### 4.4 ScenarioHint 已落地

`autopnex/ctf/web_state_blackboard.py` 中已经存在：

```python
@dataclass
class ScenarioHint:
    route: str
    scenario: str
    confidence: float
    source: str
    detail: str
    payload_family: str = ""
```

`WebStateBlackboard` 中也已经加入：

```python
self.scenario_hints: List[ScenarioHint] = []
```

这说明项目已经开始从单纯 route 维度，向更细粒度的 scenario 维度演进。

这是一个重要方向，因为 Web CTF 中同一大类漏洞内部差异很大，例如：

- `sqli.login_bypass`
- `sqli.blacklist_bypass`
- `cmdi.space_bypass`
- `lfi.php_filter`
- `auth.header_spoofing`
- `xxe.entity_injection`

后续可以基于 scenario 做更准确的能力统计、route 排序和失败诊断。

### 4.5 XXE/Auth Logic route 文件已实现

当前已经新增：

```text
autopnex/ctf/routes/xxe.py
autopnex/ctf/routes/auth_logic.py
```

其中：

- `XXEMachine` 用于 XML External Entity 注入。
- `AuthLogicMachine` 用于 cookie manipulation、header spoofing、HTTP verb tampering 等认证/授权逻辑绕过。

`routes/__init__.py` 中也已经导入：

```python
from autopnex.ctf.routes.xxe import XXEMachine
from autopnex.ctf.routes.auth_logic import AuthLogicMachine
```

说明模块化 route 拆分工作已经开始。

## 5. 当前高价值成果

### 5.1 AutoPenX 已经不只是普通 payload runner

当前项目已经具备这些特征：

- 有 `CoordinatorAgent` 做 route 选择。
- 有 `ReconAgent` 做信息收集。
- 有 `ExploitAgent` 执行状态机或 fallback。
- 有 `CriticAgent` 做重复尝试和弱证据检查。
- 有 `WebStateBlackboard` 统一记录 endpoint、param、cookie、evidence、attempt、flag。
- 有 benchmark 报告和 scenario coverage。

这使它区别于简单脚本，也区别于完全不可控的通用 agent。

它的价值不在于“比通用 agent 更聪明”，而在于：

- 更可复现。
- 更可测量。
- 更适合做能力矩阵。
- 更适合稳定执行已知 CTF 解题模式。
- 更容易定位失败原因。
- 更容易扩展确定性 exploit route。

### 5.2 当前已经达到阶段性验收线

若以本阶段目标衡量：

```text
基础 Web CTF benchmark 稳定全通过
```

则当前已经达标。

当前可认为已经完成：

- 自定义 12 题能力基线。
- BUUCTF 20 题基础真实题型基线。
- CMDi PingPingPing 修复。
- 初步 scenario 化报告。
- 初步模块化 route 拆分。

## 6. 发现的问题与风险

虽然结果很好，但当前还有几个工程层面的关键问题。

### 6.1 xxe/auth_logic 没有真正接入主 Orchestrator registry

运行时验证结果显示：

```text
direct route_state_machine registry:
['cmdi', 'graphql', 'idor', 'jwt', 'lfi', 'php_pop', 'source_leak', 'sqli', 'ssrf', 'ssti', 'upload', 'websocket', 'xss']

after multi_agent import:
['cmdi', 'graphql', 'idor', 'jwt', 'lfi', 'php_pop', 'source_leak', 'sqli', 'ssrf', 'ssti', 'upload', 'websocket', 'xss']

after routes package import:
['auth_logic', 'cmdi', 'graphql', 'idor', 'jwt', 'lfi', 'php_pop', 'source_leak', 'sqli', 'ssrf', 'ssti', 'upload', 'websocket', 'xss', 'xxe']
```

这说明：

- `xxe` 和 `auth_logic` 只有在显式导入 `autopnex.ctf.routes` 后才注册。
- 主流程 `multi_agent.py` 当前仍然直接依赖 `autopnex.ctf.route_state_machine`。
- 因此主 Orchestrator 默认不一定会使用新的 `XXEMachine` / `AuthLogicMachine`。

这不是 benchmark 失败问题，但会影响架构正确性和后续扩展。

### 6.2 `nctf2019_truexml` 实际不是由 xxe route 命中

抽样运行显示：

```text
nctf2019_truexml found=True
flag=flag{nctf2019_xxe_xml_c00kb00k}
actual route=ssrf
```

也就是说：

- 报告中的 scenario 是 `xxe.entity_injection`。
- 但实际成功 route 是 `ssrf`。
- 这说明当前通过依赖的是旧 route 中的 broad payload 覆盖，而不是新的 `XXEMachine`。

这会造成能力归因不准。

### 6.3 `geek2019_http` 仍然偏慢，可能依赖 fallback

最新报告中：

```text
geek2019_http: rounds=16 time=33.0s scenario=auth.header_spoofing
```

抽样执行中也观察到它最终可能由 `llm_fallback` 找到 flag。

这说明：

- `auth.header_spoofing` 场景还没有被足够早地确定性解决。
- `AuthLogicMachine` 的价值还没有完全进入主路径。
- 对 header/referer 类 BUUCTF 题型的 route selection 仍需优化。

理想状态应该是：

```text
geek2019_http <= 4 rounds
winning_route = auth_logic
attribution = deterministic_route
```

### 6.4 报告中的 `winning_route` 仍为空

最新报告中，多数条目的：

```text
winning_route = ""
```

这说明报告目前更像是在记录：

```text
expected scenario + success/fail
```

而不是记录：

```text
actual winning route + actual winning scenario + attribution
```

这会影响后续分析：

- 无法准确知道每个题到底由哪个 route 解出。
- 无法区分 deterministic route 和 LLM fallback。
- 无法定位哪些 scenario 只是“被 broad payload 顺便覆盖”。

## 7. 建议的下一步工作

### P0：修正 route 注册链

目标：

```text
xxe/auth_logic 必须默认进入主 Orchestrator 可用 route 集合
```

建议方案：

#### 短期方案

在主路径启动时显式导入：

```python
import autopnex.ctf.routes
```

优点：

- 改动小。
- 能快速让 `xxe/auth_logic` 注册进现有 `MACHINE_REGISTRY`。

缺点：

- 仍然依赖 import side effect。
- 架构上不够干净。

#### 中期方案

将主 Orchestrator 的导入从旧文件切到模块化 registry：

```python
from autopnex.ctf.routes import MACHINE_REGISTRY, create_machine, run_route
```

优点：

- 和新 `routes/` 包一致。
- 更符合模块化 route 的长期方向。

#### 长期方案

彻底拆分：

```text
autopnex/ctf/routes/base.py
autopnex/ctf/routes/registry.py
autopnex/ctf/routes/cmdi.py
autopnex/ctf/routes/sqli.py
autopnex/ctf/routes/lfi.py
autopnex/ctf/routes/xxe.py
autopnex/ctf/routes/auth_logic.py
```

让 `route_state_machine.py` 逐步退役或只作为兼容层。

### P1：修复真实 winning_route 归因

目标：

每个 benchmark 结果中都应该包含：

```json
{
  "expected_scenario": "xxe.entity_injection",
  "winning_route": "xxe",
  "winning_scenario": "xxe.entity_injection",
  "attribution": "deterministic_route"
}
```

建议从 `action_log` 中提取真实成功事件：

- 找最后一个 `phase == "execute"`。
- 解析 `result_summary`。
- 判断 `found_flag == True`。
- 提取其中的 `route`。
- 如果成功来自 `llm_fallback`，则 `attribution = "llm_fallback"`。

这样可以区分：

- 确定性 route 成功。
- LLM fallback 成功。
- broad route 误归因。
- scenario map 预期值。

### P2：让 `nctf2019_truexml` 由 xxe route 命中

当前状态：

```text
scenario = xxe.entity_injection
actual route = ssrf
```

目标状态：

```text
winning_route = xxe
rounds <= 4
```

建议：

- 确保 `XXEMachine` 注册进主 registry。
- 在 coordinator route priority 中加入 `xxe`。
- recon 阶段发现 XML parser、XML body、Content-Type 相关线索时增加 `xxe` evidence。
- `nctf2019_truexml` 的场景应该优先走 `xxe`，而不是由 `ssrf` 兜底。

### P3：让 `geek2019_http` deterministic 化

当前状态：

```text
rounds = 16
time = 33.0s
可能依赖 LLM fallback
```

目标状态：

```text
rounds <= 4
winning_route = auth_logic
attribution = deterministic_route
```

建议：

- 确保 `AuthLogicMachine` 注册进主 registry。
- 在 recon 中识别页面提示、header hint、referer hint。
- 对 header spoofing 场景优先尝试：

```text
Referer: https://www.Sycsecret.com
X-Forwarded-For: 127.0.0.1
X-Real-IP: 127.0.0.1
Client-IP: 127.0.0.1
```

- 将 BUUCTF 常见 header hint 抽象为 scenario：

```text
auth.header_spoofing
```

而不是仅作为普通 fallback payload。

### P4：把 scenario coverage 从静态映射升级为真实覆盖

当前 scenario coverage 主要来自：

```text
_TARGET_SCENARIO_MAP
```

这适合表达 expected scenario，但不适合表达 actual capability。

建议拆成两个字段：

```text
expected_scenario
actual_scenario
```

并在 coverage report 中分别统计：

```text
expected coverage: benchmark 设计覆盖了哪些场景
actual coverage: agent 实际通过哪些 route/scenario 解题
```

这样可以回答更关键的问题：

- 这个题期望考 XXE，agent 是否真的用 XXE 解出？
- 这个题期望考 header spoofing，agent 是否真的用 auth_logic 解出？
- 哪些题其实是 LLM fallback 解决？
- 哪些题是 broad route 顺便解决？

## 8. 阶段性评价

### 8.1 结果层面

当前结果可以评价为：

```text
优秀
```

原因：

- `STRICT_BENCHMARK_12` 全通过。
- BUUCTF/classic `real_ctf_20` 全通过。
- 之前失败的 PingPingPing 已修复。
- 测试现场复测通过，而不是只依赖历史报告。

### 8.2 工程层面

当前工程状态可以评价为：

```text
可用，但需要收口
```

主要原因：

- 新 route 已写出，但注册链没有完全闭合。
- benchmark 报告 success 准确，但 attribution 不够准确。
- 部分题仍依赖 broad route 或 LLM fallback。
- route modularization 已开始，但旧 `route_state_machine.py` 仍是核心入口。

### 8.3 研究/项目意义层面

当前 AutoPenX 已经证明它有意义。

它不是为了在开放世界中全面超过通用 agent，而是为了构建一个：

```text
稳定、可复现、可度量、可扩展的 Web CTF 解题执行系统
```

相比通用 agent，它的价值在于：

- benchmark 可重复。
- 每个漏洞类型可以单独量化。
- route/state machine 可以确定性改进。
- 失败可以归因到 route、scenario、payload family。
- 可以逐步形成 Web CTF 能力图谱。

## 9. 建议验收标准

下一阶段可以把验收目标从“是否过题”升级为“是否用正确能力过题”。

建议设定如下标准：

### 9.1 稳定性标准

```text
STRICT_BENCHMARK_12 连续 3 次 12/12
real_ctf_20 连续 3 次 20/20
```

### 9.2 归因标准

```text
每个通过题必须有非空 winning_route
每个通过题必须有 attribution
每个通过题必须区分 deterministic_route / llm_fallback
```

### 9.3 效率标准

```text
PingPingPing <= 3 rounds
nctf2019_truexml <= 4 rounds
geek2019_http <= 4 rounds
real_ctf_20 总耗时 <= 45s
```

### 9.4 架构标准

```text
xxe/auth_logic 默认注册进主 registry
multi_agent 不再直接依赖旧 monolithic registry
ScenarioHint 被 coordinator 实际消费
coverage_report 同时包含 expected_scenario 与 actual_scenario
```

## 10. 总结

当前 AutoPenX 的更新是成功的。

已经完成：

```text
STRICT_BENCHMARK_12: 12/12
real_ctf_20:         20/20
PingPingPing:        fixed
ScenarioHint:        implemented
XXE/Auth route:      files implemented
```

仍需完善：

```text
xxe/auth_logic 注册链
winning_route 真实归因
geek2019_http deterministic 化
nctf2019_truexml 用 xxe route 命中
scenario coverage 从静态映射升级为真实能力统计
```

下一步不建议继续无序堆 payload，而应该进入工程收口阶段：

```text
从“能过题”升级到“能解释为什么过题、用什么能力过题、哪些能力还弱”。
```

这会让 AutoPenX 从一个调优后的 benchmark solver，进一步变成一个真正可评估、可迭代的 Web CTF 专用 agent 系统。
