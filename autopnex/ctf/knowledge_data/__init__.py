"""
CTF 经验知识库数据包。

包含五大题型的解题经验、常见模式、Payload模板和工具参考：
- web_patterns.json: Web题型解题模式（SQLi, SSTI, LFI, 命令注入, 反序列化, SSRF, XXE等）
- crypto_patterns.json: Crypto题型解题模式（RSA攻击, AES攻击, XOR, 古典密码等）
- pwn_patterns.json: Pwn题型解题模式（栈溢出, 格式化字符串, 堆利用等）
- misc_patterns.json: Misc题型解题模式（文件分析, 隐写术, 流量分析, 内存取证等）
- reverse_patterns.json: Reverse题型解题模式（静态分析, 动态调试, Z3求解, angr等）
- tool_reference.json: 工具速查表（按题型分类的推荐工具和使用方法）

使用方式：
    from autopnex.ctf.knowledge_data import load_patterns, load_tool_reference

    web_patterns = load_patterns("web")
    tools = load_tool_reference()
"""

import json
from pathlib import Path
from typing import Dict, List, Optional

_DATA_DIR = Path(__file__).parent


def load_patterns(category: str) -> Dict:
    """加载指定题型的解题模式数据。

    Args:
        category: 题型类别 (web/crypto/pwn/misc/reverse)

    Returns:
        包含该题型所有解题模式的字典
    """
    file_path = _DATA_DIR / f"{category}_patterns.json"
    if not file_path.exists():
        return {"category": category, "patterns": []}
    with open(file_path, "r", encoding="utf-8") as f:
        return json.load(f)


def load_tool_reference() -> Dict:
    """加载工具速查表。"""
    file_path = _DATA_DIR / "tool_reference.json"
    if not file_path.exists():
        return {"tool_categories": {}}
    with open(file_path, "r", encoding="utf-8") as f:
        return json.load(f)


def load_all_patterns() -> Dict[str, Dict]:
    """加载所有题型的解题模式。"""
    categories = ["web", "crypto", "pwn", "misc", "reverse"]
    return {cat: load_patterns(cat) for cat in categories}


def get_patterns_for_challenge(
    category: str,
    indicators: Optional[List[str]] = None,
) -> List[Dict]:
    """根据题目特征匹配最相关的解题模式。

    Args:
        category: 题型类别
        indicators: 题目中发现的特征/指标列表

    Returns:
        匹配的解题模式列表，按相关度排序
    """
    data = load_patterns(category)
    patterns = data.get("patterns", [])

    if not indicators:
        return patterns

    # 按指标匹配度排序
    scored_patterns = []
    for pattern in patterns:
        pattern_indicators = set(
            ind.lower() for ind in pattern.get("indicators", [])
        )
        input_indicators = set(ind.lower() for ind in indicators)
        overlap = len(pattern_indicators & input_indicators)
        if overlap > 0:
            scored_patterns.append((overlap, pattern))

    scored_patterns.sort(key=lambda x: x[0], reverse=True)
    return [p for _, p in scored_patterns] if scored_patterns else patterns


def get_payloads_for_vuln(vuln_type: str) -> List[str]:
    """获取指定漏洞类型的Payload列表。

    Args:
        vuln_type: 漏洞类型 (sqli, ssti, lfi, cmdi, ssrf, xxe等)

    Returns:
        Payload字符串列表
    """
    # 漏洞类型到题型的映射
    vuln_to_category = {
        "sqli": "web", "sql_injection": "web",
        "ssti": "web", "template_injection": "web",
        "lfi": "web", "rfi": "web", "file_inclusion": "web",
        "cmdi": "web", "command_injection": "web",
        "ssrf": "web", "xxe": "web",
        "deserialization": "web",
        "rsa": "crypto", "aes": "crypto", "xor": "crypto",
    }

    category = vuln_to_category.get(vuln_type.lower(), "web")
    data = load_patterns(category)

    for pattern in data.get("patterns", []):
        pattern_id = pattern.get("id", "")
        if vuln_type.lower() in pattern_id.lower():
            payloads = pattern.get("payloads", [])
            if isinstance(payloads, list):
                return payloads
            elif isinstance(payloads, dict):
                # 展平嵌套的payload字典
                all_payloads = []
                for key, val in payloads.items():
                    if isinstance(val, list):
                        all_payloads.extend(val)
                    else:
                        all_payloads.append(str(val))
                return all_payloads

    return []


def get_first_steps(category: str) -> List[str]:
    """获取指定题型的第一步操作列表。"""
    tools = load_tool_reference()
    steps = tools.get("first_steps_by_challenge_type", {})
    return steps.get(category, [])
