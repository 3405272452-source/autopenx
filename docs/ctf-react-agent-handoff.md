# AutoPenX CTF ReAct Agent 交接文档

**更新时间**: 2026-05-19
**适用对象**: 后续接手本项目的 AI / 开发者
**范围**: `autopnex/ctf/react_agent.py` 及其相关测试、CTF Web 求解闭环能力

---

## 1. 文档目的

这份文档用于帮助后续 AI 快速理解以下内容：

- **这次已经完成了什么改动**
- **当前 CTF Agent 的关键设计思路是什么**
- **哪些约束和不变量不能破坏**
- **下一阶段最值得补全的目标是什么**
- **如果继续扩展 deterministic helper，应遵循什么实现模式**

这不是面向最终用户的介绍文档，而是面向“继续开发 AutoPenX CTF Agent 的执行者”的交接说明。

---

## 2. 当前核心目标

当前 CTF Agent 的主方向不是单纯依赖大模型自由发挥，而是逐步演进为：

- **LLM 负责广义推理与工具选择**
- **Agent 负责确定性闭环能力**
- **常见漏洞场景下，Agent 能自动完成低成本验证、自动利用、自动提取 flag**

换句话说，目标是把高频 Web CTF 模式逐步沉淀为 **deterministic helpers**，减少模型在显而易见漏洞点上的浪费轮次和随机性。

---

## 3. 关键代码位置

### 3.1 主文件

- `autopnex/ctf/react_agent.py`

这是当前改动最集中的文件，主要包含：

- ReAct 主循环
- 工具调用与消息维护
- flag 扫描逻辑
- 长结果压缩逻辑
- 失败诊断逻辑
- deterministic helper 调度与实现
- static preflight 注入逻辑

### 3.2 测试文件

- `tests/test_ctf_web_pipeline.py`

这个文件是当前闭环能力的主要回归测试入口。后续新增 deterministic helper 时，优先往这里补测试。

### 3.3 运行入口

- `autopnex/web/api.py`
- `ctf_workspace/run_web_target_once.py`

前者是 Web API 调用入口，后者适合做单目标实战验证。

---

## 4. 这次已经完成的主要改动

## 4.1 工具结果先完整扫描，再压缩给 LLM

### 已完成

Agent 对工具结果的处理从“先截断再扫描”改为：

- 先对 **完整 tool result JSON** 扫 flag
- 再用 `_compact_for_llm()` 压缩给 LLM
- 压缩策略保留 **头部 + 尾部**，中间截断

### 原因

以前如果 flag 或关键报错出现在长响应尾部，会被截掉，导致 Agent 实际已经拿到 flag 却没识别。

### 相关点

- `_compact_for_llm()`
- `solve()` 中对 `full_result_str` 的扫描顺序

---

## 4.2 flag 扫描增强为多视图归一化

### 已完成

`_check_flag_in_text()` 不再只扫原文，而是通过 `_normalised_text_variants()` 同时扫描：

- 原文
- HTML 反实体
- 去标签文本
- 去标签后再反实体

### 解决的问题

可识别例如以下变体：

- `flag<span>{...}</span>`
- `flag&#123;...&#125;`
- 被 HTML 标签或实体打散的 flag

---

## 4.3 工具失败后向 LLM 注入中文诊断信息

### 已完成

新增 `_diagnose_tool_result()`，当工具结果表现出以下特征时，会向对话历史中再追加一条 `user` 诊断消息：

- HTTP 404 / 403 / 500 / 302
- 空响应
- stderr / 执行报错
- 仍停留在表单页等

### 目标

避免模型在同一个错误请求上无变化重复。

### 约束

诊断信息必须是 **可操作的下一步提示**，而不是泛泛而谈。

---

## 4.4 ctf_tool_manager 优先复用本地工具

### 已完成

`ctf_tool_manager` 的策略已经调整为：

优先检查：

- PATH
- `ctf_workspace/scripts`
- `downloads`
- `python_packages`
- `local_search_paths`

如果命中本地现有工具，会优先给出：

- `use_existing`
- `next_core_tool=run_tool_script`

### 目标

避免 Agent 每次都重新下载/安装已有工具。

---

## 4.5 建立 deterministic helper 统一调度框架

### 已完成

新增统一入口：

- `_run_deterministic_helpers()`

当前它会在 `http_request` 等工具结果之后尝试调用已注册的 helper；如果 helper 直接拿到 flag，Agent 会立即结束。

### 设计意义

这是后续扩展更多闭环能力的主扩展点。新增 helper 时，应优先沿这个框架继续做，而不是把特判逻辑散落在 `solve()` 主循环里。

---

## 4.6 已落地的 deterministic helpers

### 4.6.1 `deterministic_php_pop`

目标场景：

- 已访问到疑似 NewStarCTF 风格 PHP POP 链源码
- 响应体包含 `Begin/Then/Handle/Super/CTF/WhiteGod` 等结构
- 存在 `unserialize($_POST['pop'])`

行为：

- 自动构造 Python bytes payload
- 自动 POST `pop`
- 自动执行 `cat /flag`
- 自动扫描响应中的 flag

约束：

- 私有/保护属性名必须使用 **真实 NUL 字节**
- 不能偷懒用手写的转义字符串代替真实 bytes

---

### 4.6.2 `deterministic_lfi`

目标场景：

- 访问过的 URL 查询参数中存在以下候选名：
  - `file`
  - `path`
  - `page`
  - `include`
  - `template`
  - `view`
  - `filename`
  - `filepath`

行为：

- 自动尝试常见 flag 路径：
  - `/flag`
  - `/flag.txt`
  - 路径穿越版本
  - `php://filter/convert.base64-encode/resource=/flag`
- 只有实际命中 flag 才返回 helper 成功

原则：

- 低成本
- 只在明显文件读取参数上触发
- 不要无界扩张 payload 数量

---

### 4.6.3 `deterministic_ssti`

目标场景：

- 访问过的 URL 查询参数中存在以下候选名：
  - `name`
  - `template`
  - `message`
  - `content`
  - `text`
  - `q`
  - `query`
  - `search`
  - `input`

行为：

- 先自动打低成本探测 payload：`{{7*7}}`
- 若响应出现 `49`，认为模板表达式反射成立
- 再尝试 Jinja 风格读取 `/flag` payload
- 只有命中 flag 才视为 helper 成功

当前限制：

- 当前只实现了偏 Jinja 的最小闭环版本
- 还没有按模板引擎类型细分 payload（如 Twig / Freemarker / Go template）

---

### 4.6.4 `deterministic_sqli`

目标场景：

- 访问过的 URL 查询参数中存在以下候选名：
  - `id`
  - `uid`
  - `item`
  - `cat`
  - `category`
  - `product`
  - `page`
  - `q`
  - `query`
  - `search`
  - `user`
  - `username`

行为：

- 先自动打单引号探测，例如 `id=1'`
- 识别常见 SQL 报错标记：
  - `SQLSTATE`
  - `syntax error`
  - `mysql`
  - `sqlite`
  - `postgres`
  - `odbc`
  - `PDOException`
- 若命中，再自动尝试一组低成本 `UNION SELECT` flag 读取 payload
- 只有命中 flag 才返回 helper 成功

当前限制：

- 目前是最小可用版
- 尚未做列数自适应、数据库类型自适应、布尔盲注/时间盲注

---

## 5. 当前 prompt 已加入的重要启发

在 `_build_initial_messages()` 中，已经为 LLM 注入了一批高价值启发，尤其是：

- 文件类参数优先怀疑 LFI
- 文本/模板类参数优先怀疑 SSTI
- `id/item/category/q/search/user` 类参数优先怀疑 SQLi
- PHP unserialize / POP payload 必须使用 Python bytes
- strange_php Phar+PDO 链若缺 MySQL，应直接走 `ctf_mysql_helper`
- 若缺隧道暴露能力，应优先走 `ctf_tunnel_helper`
- 发现已有静态源码分析结果时，不要重复解压/重复阅读

这些 prompt 不是闭环本身，但会显著降低模型浪费轮次。

---

## 6. 当前测试状态

当前 `tests/test_ctf_web_pipeline.py` 已覆盖并通过以下方向：

- PHP POP deterministic exploit
- LFI deterministic probing
- SSTI deterministic probing
- SQLi deterministic probing
- tool result 长响应头尾保留
- tool result 完整扫描后提 flag
- 工具失败诊断注入

### 当前状态

- `22 passed, 2 warnings`

说明：

- 现阶段回归是绿的
- 后续继续加 helper 时，必须保持这批测试不回退

---

## 7. 关键实现原则（后续 AI 不应破坏）

## 7.1 永远优先做低成本验证

如果出现明显漏洞点，优先：

- 低成本 probe
- 确认回显/确认报错/确认行为差异
- 再做利用

不要一上来直接走重 payload、长 payload、复杂脚本路线。

---

## 7.2 deterministic helper 必须是“闭环增强”，不是“硬编码答案”

允许：

- 通用参数启发
- 通用 payload 集
- 通用闭环路径

不允许：

- 针对某个具体题目把 flag 路径、表名、业务逻辑写死在主逻辑里
- 绕开框架在 `solve()` 中塞题目特判

新增能力时，优先做成：

- 常量集合
- `_try_xxx_from_tool_result()`
- 注册到 `_run_deterministic_helpers()`
- 配套测试
- 配套 prompt 启发

---

## 7.3 只有真正命中 flag，helper 才算成功

不要因为：

- 响应状态码变化
- 页面结构变化
- 出现 suspicious 字样

就把 helper 视为成功。

必须以 `_check_flag_in_text()` 命中为准，避免虚假收敛。

---

## 7.4 先扫描完整结果，再决定是否压缩

这是已经解决过的真实问题，不要回退。

正确顺序应始终是：

1. 获取完整 tool result
2. 对完整文本做 flag 扫描
3. 需要喂给 LLM 时再压缩

---

## 7.5 新增能力优先走测试驱动

推荐顺序：

1. 在 `tests/test_ctf_web_pipeline.py` 先写行为测试
2. 运行失败，确认是红灯
3. 最小实现让测试通过
4. 跑完整回归
5. 再考虑扩展版本

这套流程在本轮 LFI / SSTI / SQLi helper 中已经验证有效。

---

## 8. 当前已知不足

尽管已经有初步闭环，但距离“像强通用 AI 一样完整”仍有明显差距：

### 8.1 helper 覆盖面还不够

当前只覆盖：

- PHP POP
- LFI
- SSTI
- SQLi

但高频 Web CTF 还缺：

- JWT / Session 篡改
- XXE
- 文件上传到文件读/代码执行
- 命令注入
- SSRF 到本地资源 / 元数据 / Docker API
- 身份绕过 / 越权 / IDOR

### 8.2 现有 helper 仍偏“最小可用”

例如：

- SSTI 还没有模板引擎分类
- SQLi 还没有列数探测、数据库类型探测、盲注路径
- LFI 还没有更丰富的目标路径与 wrapper 变体

### 8.3 缺少统一“漏洞证据评分”机制

当前 helper 主要是单点启发 + 闭环尝试，未来可以考虑引入：

- 候选参数评分
- 证据强度评分
- exploit 尝试预算控制

---

## 9. 未来目标与优先级建议

下面是建议的后续开发优先级。

## P0：继续扩 deterministic helper 库

优先补：

### 9.1 `deterministic_jwt`

建议能力：

- 自动识别 JWT / session token
- 自动尝试 `alg:none`
- 自动尝试无签名验证场景
- 自动尝试常见弱密钥
- 若 payload 生效，则自动访问高权限页面/接口并扫 flag

### 9.2 `deterministic_xxe`

建议能力：

- 自动识别 XML 请求体 / XML 上传点
- 自动尝试基础 `file:///flag`
- 自动尝试 `php://filter` / base64 场景
- 只在明确是 XML 交互时触发

### 9.3 `deterministic_cmdi`

建议能力：

- 自动识别疑似命令参数
- 自动做 2~3 轮低成本命令拼接验证
- 命中后尝试 `cat /flag`
- 兼顾 `;`, `|`, `&&`, 换行等低成本变体

---

## P1：增强现有 helper 的泛化能力

### 9.4 SSTI 引擎分类

将 `deterministic_ssti` 从单一 Jinja payload 升级为：

- Jinja2
- Twig
- Go template
- Freemarker / Thymeleaf（按项目生态再决定）

### 9.5 SQLi 自适应能力

增强 `deterministic_sqli`：

- 列数探测
- 回显列定位
- SQLite / MySQL / PostgreSQL 的差异 payload
- 表名枚举最小闭环
- 有预算的错误型 / 联合查询型自动切换

### 9.6 LFI 丰富化

增强 `deterministic_lfi`：

- 更多常见路径
- `php://filter` 解码辅助
- `/proc/self/environ`
- 应用配置文件路径猜测

---

## P2：从 helper 库进化到“策略层”

未来应该逐步引入：

- **候选漏洞类型评分机制**
- **尝试预算控制**
- **helper 触发记录与去重**
- **失败后自动切换相邻思路**

目标不是无限增加 payload，而是让 Agent 学会：

- 何时值得尝试
- 何时应停止
- 何时切到别的利用方向

---

## 10. 推荐的继续开发方式

如果后续 AI 要继续补 helper，建议采用以下固定模板：

### 第一步：补测试

在 `tests/test_ctf_web_pipeline.py` 增加：

- 一个最小闭环测试
- 明确断言首轮 probe 是什么
- 明确断言 helper 成功后提取到 flag

### 第二步：补常量

在 `react_agent.py` 顶部增加：

- 参数名集合
- probe payload
- exploit payload 集
- 错误标记 / 命中标记

### 第三步：补 helper 实现

新增：

- `_try_xxx_flag_from_tool_result()`

要求：

- 触发条件清晰
- 尝试次数受控
- 命中 flag 才返回成功

### 第四步：注册到 dispatcher

在 `_run_deterministic_helpers()` 中接入。

### 第五步：补 prompt 提示

在 `_build_initial_messages()` 的 instruction 区补一条高价值启发，帮助 LLM 与 deterministic helper 协同。

### 第六步：跑完整回归

至少运行：

```bash
python -m pytest tests/test_ctf_web_pipeline.py -q
```

---

## 11. 一句话总结

当前 AutoPenX CTF ReAct Agent 已经从“纯 LLM 驱动”进化为“LLM + deterministic exploit 闭环”的混合模式，已经落地的闭环能力包括：

- PHP POP
- LFI
- SSTI
- SQLi

后续最重要的工作，不是继续堆 prompt，而是继续把高频漏洞路径沉淀为 **可测试、可复用、可维护的 deterministic helpers**。
