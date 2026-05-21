# AutoPenX 当前状态

最后更新：2026-05-21

---

## 1. 基准测试结果

### 1.1 严格基准 (Strict Benchmark) — 12/12

| 目标 | 类别 | 状态 | 路线 | 轮次 | 时间 |
|------|------|------|------|------|------|
| lfi_basic | LFI | ✅ | lfi | 1 | 0.17s |
| lfi_filter | LFI | ✅ | lfi | 2 | 0.36s |
| ssti_jinja | SSTI | ✅ | ssti | 3 | 0.45s |
| sqli_union | SQLi | ✅ | sqli | 8 | 1.45s |
| sqli_blind | SQLi | ✅ | sqli | 7 | 1.25s |
| cmdi_filter | CMDi | ✅ | cmdi | 4 | 0.56s |
| jwt_none | JWT | ✅ | jwt | 11 | 2.03s |
| source_leak_git | Source Leak | ✅ | source_leak | 1 | 0.16s |
| graphql_introspection | GraphQL | ✅ | graphql | - | - |
| websocket_auth_bypass | WebSocket | ✅ | websocket | - | - |
| xss_reflected | XSS | ✅ | xss | - | - |
| xss_stored | XSS | ✅ | xss | - | - |

**通过率**: 12/12 (100%)
**平均轮次**: ~5 轮
**平均时间**: ~1.0s

### 1.2 真实 CTF 基准 (Real CTF) — 30/30

基于 BUUCTF 经典题目的本地复现：

| # | 目标名 | 类别 | 原题 |
|---|--------|------|------|
| 1 | geek2019_easysql | sqli | [极客大挑战 2019] EasySQL |
| 2 | geek2019_upload | upload | [极客大挑战 2019] Upload |
| 3 | hctf2018_warmup | lfi | [HCTF 2018] WarmUp |
| 4 | geek2019_php | php_pop | [极客大挑战 2019] PHP |
| 5 | suctf2019_easysql | sqli | [SUCTF 2019] EasySQL |
| 6-30 | ... | 多种 | 覆盖所有 15 条路线 |

**通过率**: 30/30 (100%)

### 1.3 探索模式 (Explore) — 21 目标

测试路线覆盖广度，包含更复杂的多步骤题目。

---

## 2. 能力覆盖矩阵

### 2.1 路线覆盖

| 路线 | 状态 | 探针数 | Exploit 步骤数 | 备注 |
|------|------|--------|---------------|------|
| source_leak | ✅ 完成 | 14 | 20+ | .git, .env, www.zip, .bak 等 |
| lfi | ✅ 完成 | 8+ | 15+ | 直接读取 + 过滤绕过 + php://filter |
| ssti | ✅ 完成 | 6+ | 10+ | Jinja2, Twig, Smarty |
| sqli | ✅ 完成 | 10+ | 20+ | UNION, 布尔盲注, 时延, 堆叠 |
| cmdi | ✅ 完成 | 8+ | 15+ | 直接执行 + 过滤绕过 |
| jwt | ✅ 完成 | 4+ | 10+ | alg=none + 弱密钥爆破 |
| upload | ✅ 完成 | 5+ | 15+ | MIME 绕过, 扩展名绕过, 内容检测绕过 |
| php_pop | ✅ 完成 | 6+ | 10+ | 反序列化 + __wakeup 绕过 |
| ssrf | ✅ 完成 | 5+ | 10+ | file://, gopher://, 内网探测 |
| idor | ✅ 完成 | 4+ | 8+ | 路径枚举, ID 遍历 |
| xss | ✅ 完成 | 6+ | 10+ | 反射 + 存储 + admin bot |
| graphql | ✅ 完成 | 3+ | 8+ | 内省 + 隐藏字段查询 |
| websocket | ✅ 完成 | 3+ | 6+ | 认证绕过 + 参数注入 |
| xxe | ✅ 完成 | 4+ | 8+ | XML 外部实体 + 文件读取 |
| auth_logic | ✅ 完成 | 4+ | 8+ | Cookie/Header 操纵 |

### 2.2 工具覆盖

| 工具 | 状态 | 用途 |
|------|------|------|
| http_request | ✅ | HTTP 请求（含文件上传） |
| run_python | ✅ | Python 脚本执行 |
| repl_execute | ✅ | 持久化 REPL（跨调用保持状态） |
| scan_flag | ✅ | Flag 模式扫描 |
| decode_data | ✅ | 编码解码（base64/hex/rot13 等） |
| file_analyze | ✅ | 文件类型检测 + 字符串提取 |
| recon_scan | ✅ | 攻击面扫描 |
| ctf_knowledge_search | ✅ | 知识库搜索 |
| write_tool_script | ✅ | 写入辅助脚本 |
| run_tool_script | ✅ | 执行辅助脚本 |
| install_python_package | ✅ | 安装 Python 包 |
| download_tool_url | ✅ | 下载辅助文件 |

### 2.3 检测能力

| 能力 | 状态 |
|------|------|
| 技术栈指纹识别 | ✅ PHP, Apache, nginx, Laravel, Flask, Django, Express, Spring |
| 参数自动发现 | ✅ 从 HTML 链接和表单提取 |
| Flag 正则检测 | ✅ 10+ 已知前缀 |
| Flag AI 验证 | ✅ 排除 CSS/JS 误报 |
| 知识模式匹配 | ✅ 自进化学习 |
| WAF 检测 | ✅ 指纹 + 自动绕过 |

---

## 3. 已知限制

### 3.1 架构限制

- **Phase 2 并行竞速** 需要多个 API Key 才能发挥最大效果；只有 DeepSeek 时退化为单模型多方向
- **知识学习器** 依赖成功解题积累，冷启动时无已知模式
- **路线状态机** 是确定性的，对于需要创造性推理的题目依赖 Phase 3 LLM

### 3.2 功能限制

- 不支持需要浏览器交互的复杂 XSS（如 CSP 绕过 + DOM XSS）
- 不支持二进制 PWN 题目的自动化利用（仅有基础框架）
- 不支持需要外网回连的 SSRF（本地测试环境限制）
- GraphQL 路线不支持 mutation 类型的利用
- WebSocket 路线不支持长连接状态维护

### 3.3 性能限制

- 每路线 30 步上限可能不够复杂多步骤题目
- 每路线 30 秒超时对慢速目标可能不足
- 并行 Worker 的 5 轮限制可能不够深度推理

### 3.4 环境限制

- 需要 Python 3.10+
- 部分工具（如 `install_python_package`）需要网络访问
- Windows 环境下某些 shell 命令可能不兼容

---

## 4. 剩余工作项

### 4.1 高优先级

- [ ] 提升 Phase 2 并行竞速的方向分配策略
- [ ] 增加更多真实 CTF 靶场（目标 50+）
- [ ] 完善 XSS 路线的 admin bot 模拟
- [ ] 添加 NoSQL 注入路线

### 4.2 中优先级

- [ ] 集成真实 `nmap` / `sqlmap` 作为可选后端
- [ ] 持久化 Blackboard 到 SQLite（支持断点续扫）
- [ ] 添加 CORS 误配置检测路线
- [ ] 添加 HTTP 请求走私路线
- [ ] 完善 Docker 隔离执行环境

### 4.3 低优先级

- [ ] Web UI 增加历史记录和对比功能
- [ ] 添加 Burp Suite 集成（通过代理）
- [ ] 支持团队协作模式
- [ ] 添加自动报告生成（PDF 格式）
- [ ] 国际化支持（英文界面）

---

## 5. 性能指标

### 5.1 Phase 1 确定性路线

| 指标 | 数值 |
|------|------|
| 平均解题轮次 | 4.5 轮 |
| 平均解题时间 | 0.8s |
| API 调用次数 | 0 |
| 路线切换次数 | 1.2 次/题 |

### 5.2 整体（含 LLM）

| 指标 | 数值 |
|------|------|
| Phase 1 解决率 | ~85% |
| Phase 2 解决率 | ~10% |
| Phase 3 解决率 | ~5% |
| 总解决率 | 100%（基准集） |
| 平均 API 调用 | 2-3 次/题（仅 Phase 2/3 触发时） |

### 5.3 资源消耗

| 指标 | 数值 |
|------|------|
| 内存占用 | ~100MB（基础） |
| 并行 Worker 内存 | +50MB/Worker |
| 磁盘占用 | ~5MB（知识库 + 工作区） |
| 网络请求 | 10-50 次/题（含探针） |

---

## 6. 版本历史

### v2.0 (当前)
- 三阶段混合求解架构
- 15 条路线状态机
- 多智能体协作
- 自进化知识学习器
- 30 个真实 CTF 靶场
- 12 个严格基准测试 100% 通过

### v1.0 (初始)
- PTES 五阶段状态机
- 11 个纯 Python 工具
- 单一 LLM ReAct 循环
- CLI + Web UI 双入口
- 离线规则引擎兜底
