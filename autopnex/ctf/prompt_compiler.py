"""PromptCompiler — 4-layer prompt construction with token budget management.

Replaces the monolithic prompt in react_agent._build_initial_messages() with:

  Layer 1: Core Prompt        — immutable rules (300-500 chars)
  Layer 2: Task Context       — target, flag format, type, tools, budgets
  Layer 3: State Summary      — auto-generated from WebStateBlackboard
  Layer 4: RouteCard          — route-specific techniques (only current route)

Includes token budget estimation, history compression, and route-aware
skill injection to avoid context pollution.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from html.parser import HTMLParser
from typing import Any, Dict, List, Optional, Tuple

from .web_state_blackboard import WebStateBlackboard


# ---------------------------------------------------------------------------
# HTML Summarization (Requirement 6.4)
# ---------------------------------------------------------------------------

# Threshold: HTML responses longer than this are summarized
HTML_SUMMARY_THRESHOLD = 2000


class _HTMLSummaryParser(HTMLParser):
    """Lightweight HTML parser that extracts key elements for summarization."""

    def __init__(self) -> None:
        super().__init__()
        self.title: str = ""
        self.forms: List[Dict[str, str]] = []
        self.links: List[str] = []
        self.scripts: List[str] = []
        self.error_messages: List[str] = []

        self._in_title = False
        self._current_form: Optional[Dict[str, str]] = None
        self._in_error = False
        self._error_text = ""
        self._text_buffer = ""

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]) -> None:
        attr_dict = dict(attrs)
        tag_lower = tag.lower()

        if tag_lower == "title":
            self._in_title = True
            self._text_buffer = ""
        elif tag_lower == "form":
            self._current_form = {
                "action": attr_dict.get("action", ""),
                "method": attr_dict.get("method", "GET").upper(),
                "inputs": "",
            }
        elif tag_lower == "input" and self._current_form is not None:
            name = attr_dict.get("name", "")
            input_type = attr_dict.get("type", "text")
            if name:
                existing = self._current_form.get("inputs", "")
                sep = ", " if existing else ""
                self._current_form["inputs"] = existing + sep + f"{name}({input_type})"
        elif tag_lower == "a":
            href = attr_dict.get("href", "")
            if href and not href.startswith("#") and not href.startswith("javascript:"):
                self.links.append(href)
        elif tag_lower == "script":
            src = attr_dict.get("src", "")
            if src:
                self.scripts.append(src)
        elif tag_lower in ("div", "span", "p"):
            cls = attr_dict.get("class", "")
            if any(kw in cls.lower() for kw in ("error", "alert", "warning", "danger", "message")):
                self._in_error = True
                self._error_text = ""

    def handle_endtag(self, tag: str) -> None:
        tag_lower = tag.lower()
        if tag_lower == "title":
            self._in_title = False
            self.title = self._text_buffer.strip()
        elif tag_lower == "form" and self._current_form is not None:
            self.forms.append(self._current_form)
            self._current_form = None
        elif tag_lower in ("div", "span", "p") and self._in_error:
            self._in_error = False
            text = self._error_text.strip()
            if text:
                self.error_messages.append(text[:200])

    def handle_data(self, data: str) -> None:
        if self._in_title:
            self._text_buffer += data
        if self._in_error:
            self._error_text += data


def summarize_html(html_content: str) -> str:
    """Summarize HTML content by extracting key elements.

    When HTML > HTML_SUMMARY_THRESHOLD chars, extracts:
    - title
    - forms (action, method, input fields)
    - links (href values)
    - scripts (src values)
    - error messages (elements with error/alert/warning classes)

    Returns a compact text summary suitable for prompt injection.
    """
    if not html_content or len(html_content) <= HTML_SUMMARY_THRESHOLD:
        return html_content

    parser = _HTMLSummaryParser()
    try:
        parser.feed(html_content)
    except Exception:
        # If parsing fails, return a truncated version
        return html_content[:500] + f"\n... (HTML truncated, original {len(html_content)} chars)"

    parts = [f"[HTML Summary, original {len(html_content)} chars]"]

    if parser.title:
        parts.append(f"Title: {parser.title}")

    if parser.forms:
        parts.append("Forms:")
        for form in parser.forms[:5]:  # Limit to 5 forms
            inputs = form.get("inputs", "")
            parts.append(f"  - {form['method']} {form['action']} [{inputs}]")

    if parser.links:
        # Deduplicate and limit
        unique_links = list(dict.fromkeys(parser.links))[:15]
        parts.append(f"Links ({len(unique_links)}):")
        for link in unique_links:
            parts.append(f"  - {link}")

    if parser.scripts:
        unique_scripts = list(dict.fromkeys(parser.scripts))[:10]
        parts.append(f"Scripts ({len(unique_scripts)}):")
        for script in unique_scripts:
            parts.append(f"  - {script}")

    if parser.error_messages:
        parts.append("Errors/Messages:")
        for msg in parser.error_messages[:5]:
            parts.append(f"  - {msg}")

    summary = "\n".join(parts)

    # If summary is still too long (unlikely but safe), truncate
    if len(summary) > HTML_SUMMARY_THRESHOLD:
        summary = summary[:HTML_SUMMARY_THRESHOLD - 50] + "\n... (summary truncated)"

    return summary


def _is_html_content(text: str) -> bool:
    """Heuristic check if text looks like HTML."""
    if not text:
        return False
    stripped = text.strip()[:200].lower()
    return (
        stripped.startswith("<!doctype html")
        or stripped.startswith("<html")
        or ("<head" in stripped and "<body" in stripped)
        or ("<div" in stripped and "</" in stripped)
        or (stripped.count("<") > 3 and stripped.count(">") > 3)
    )


# ---------------------------------------------------------------------------
# Token budget
# ---------------------------------------------------------------------------

@dataclass
class TokenBudget:
    """Token budget for a single LLM call."""
    max_input_tokens: int = 8000
    max_output_tokens: int = 4096
    # Budget allocations for each layer
    core_prompt_budget: int = 600
    task_context_budget: int = 800
    state_summary_budget: int = 2000
    route_card_budget: int = 1500
    history_budget: int = 2500
    tool_definitions_budget: int = 600

    def remaining_for_layer(self, layer: str) -> int:
        return getattr(self, f"{layer}_budget", 500)

    def total_consumed(self, counts: Dict[str, int]) -> int:
        return sum(counts.values())


# ---------------------------------------------------------------------------
# Layer 1: Core Prompt (immutable, ~400 chars)
# ---------------------------------------------------------------------------

CORE_PROMPT = """\
你是 Web CTF Agent。
你必须基于证据行动，不要猜测。
每轮只选择一个最高信息增益动作。
不要重复已经失败的动作。
所有假设必须绑定 evidence。
发现 flag 后必须验证并停止。
用中文输出行动摘要和当前判断。
"""


# ---------------------------------------------------------------------------
# Layer 2: Task Context builder
# ---------------------------------------------------------------------------

def build_task_context(
    target: str,
    flag_format: str,
    challenge_type: Optional[str] = None,
    max_iterations: int = 15,
    timeout: int = 300,
    current_route: str = "recon",
    route_progress: str = "not_started",
) -> str:
    """Build the task context layer with challenge metadata and budgets."""
    parts = [
        "## 任务上下文",
        "",
        f"- **目标**: {target}",
        f"- **Flag 格式**: `{flag_format}`",
    ]
    if challenge_type:
        parts.append(f"- **题目类型**: {challenge_type}")
    parts.extend([
        f"- **轮数预算**: 最多 {max_iterations} 轮",
        f"- **时间预算**: {timeout}s",
        f"- **当前路线**: {current_route}",
        f"- **路线进度**: {route_progress}",
        "",
        "## 可用工具",
        "",
        "- `http_request` — 发送 HTTP 请求（支持 GET/POST/PUT，自定义 headers/body/form）",
        "- `run_python` — 执行 Python 脚本",
        "- `decode_data` — 解码 Base64/Hex/JWT 等",
        "- `scan_flag` — 扫描文本中的 flag 模式",
        "- `dir_scan` — 目录/文件扫描",
        "- `source_leak_scan` — 源码泄露检测",
        "- `sql_inject` — SQL 注入检测与利用",
        "- `ssti_detect` — 模板注入检测",
        "- `lfi_detect` — 文件包含检测",
        "- `cmd_inject` — 命令注入检测",
        "- `jwt_attack` — JWT 攻击",
        "- `upload_exploit` — 文件上传利用",
        "- `phar_pdo_chain` — PHP Phar 反序列化",
        "- `pop_chain_generate` — POP 链生成",
        "- `ctf_tool_manager` — 工具管理",
        "- `ctf_knowledge_search` — 知识库搜索",
    ])
    return "\n".join(parts)


# ---------------------------------------------------------------------------
# Layer 3: State Summary (from WebStateBlackboard)
# ---------------------------------------------------------------------------

def build_state_summary(blackboard: Optional[WebStateBlackboard] = None) -> str:
    """Generate compact state summary from the blackboard."""
    if blackboard is None:
        return "## 当前状态\n\n尚无信息收集数据。请先探索目标。\n"

    summary = blackboard.state_summary()

    parts = ["## 当前状态"]
    parts.append("")
    parts.append("```json")
    parts.append(json.dumps(summary, ensure_ascii=False, indent=2))
    parts.append("```")
    return "\n".join(parts)


# ---------------------------------------------------------------------------
# History compression
# ---------------------------------------------------------------------------

def estimate_tokens_heuristic(text: str) -> int:
    """Heuristic token count: ~3 chars/token for English, ~1.5 for Chinese.

    Conservative estimate suitable for budget checking without tiktoken.
    """
    if not text:
        return 0
    # Count CJK characters (roughly 1 token each)
    cjk = len(re.findall(r'[一-鿿　-〿]', text))
    # Count other characters (roughly 3 per token)
    other = len(text) - cjk
    return cjk + (other // 3) + 1


def compress_history(
    messages: List[Dict[str, Any]],
    max_tokens: int = 2500,
    encoding_name: str = "",
) -> List[Dict[str, Any]]:
    """Compress message history to fit within a token budget.

    Strategy:
    - Always keep system message
    - Keep last 3 turns intact
    - Summarize older turns by extracting: tool calls made, key findings
    - Truncate long tool outputs to first 500 chars
    """
    if not messages:
        return []

    def _count(msg: Dict[str, Any]) -> int:
        content = msg.get("content", "") or ""
        if isinstance(content, list):
            content = json.dumps(content)
        return estimate_tokens_heuristic(str(content))

    # Always keep system message first
    result: List[Dict[str, Any]] = []
    system_msgs = [m for m in messages if m.get("role") == "system"]
    non_system = [m for m in messages if m.get("role") != "system"]

    result.extend(system_msgs)
    used = sum(_count(m) for m in result)

    if not non_system:
        return result

    # Separate into turns (user/assistant/tool groups)
    # Keep last N turns intact, compress earlier ones
    turns: List[List[Dict[str, Any]]] = []
    current_turn: List[Dict[str, Any]] = []

    for msg in non_system:
        if msg.get("role") in ("user",):
            if current_turn:
                turns.append(current_turn)
            current_turn = [msg]
        else:
            current_turn.append(msg)
    if current_turn:
        turns.append(current_turn)

    # Keep last 3 turns intact
    keep_turns = min(3, len(turns))
    recent = turns[-keep_turns:] if keep_turns > 0 else []
    older = turns[:-keep_turns] if keep_turns > 0 else turns

    # Compress older turns into a summary
    if older:
        compressed_lines = ["## 历史摘要", ""]
        for turn in older:
            for msg in turn:
                role = msg.get("role", "?")
                content = msg.get("content", "")
                if isinstance(content, str) and len(content) > 200:
                    content = content[:200] + "..."
                if role == "user" and content:
                    compressed_lines.append(f"- 任务: {content[:150]}")
                elif role == "assistant":
                    tc = msg.get("tool_calls", [])
                    if tc:
                        tool_names = [t.get("function", {}).get("name", "?") for t in tc]
                        compressed_lines.append(f"- 调用: {', '.join(tool_names)}")
                elif role == "tool":
                    c = str(content)[:200] if content else "(空)"
                    compressed_lines.append(f"- 结果: {c}")
        compressed_msg = {
            "role": "user",
            "content": "\n".join(compressed_lines),
        }
        result.append(compressed_msg)

    # Add recent turns
    for turn in recent:
        for msg in turn:
            # Summarize HTML or truncate long tool outputs
            if msg.get("role") == "tool":
                content = msg.get("content", "")
                if isinstance(content, str) and len(content) > HTML_SUMMARY_THRESHOLD and _is_html_content(content):
                    msg = {**msg, "content": summarize_html(content)}
                elif isinstance(content, str) and len(content) > 500:
                    msg = {**msg, "content": content[:500] + f"\n... (truncated, original {len(content)} chars)"}
            result.append(msg)

    # Trim if still over budget
    total = sum(_count(m) for m in result)
    while total > max_tokens and len(result) > 2:
        # Remove oldest non-system, non-compressed message
        for i, m in enumerate(result):
            if m.get("role") not in ("system",) and "历史摘要" not in str(m.get("content", "")):
                total -= _count(m)
                result.pop(i)
                break
        else:
            break

    return result


# ---------------------------------------------------------------------------
# PromptCompiler
# ---------------------------------------------------------------------------

@dataclass
class PromptCompiler:
    """Compiles 4-layer prompts with token budget management.

    Usage:
        compiler = PromptCompiler()
        messages = compiler.build_messages(
            target="http://chall.ctf:8080",
            flag_format="flag{...}",
            challenge_type="web",
            blackboard=blackboard,
            route="lfi",
            previous_messages=history,
        )
    """

    budget: TokenBudget = field(default_factory=TokenBudget)
    _last_token_stats: Dict[str, int] = field(default_factory=dict, repr=False)

    # -----------------------------------------------------------------------
    # Strict token budget enforcement helpers
    # -----------------------------------------------------------------------

    def _truncate_text(self, text: str, max_tokens: int) -> str:
        """Truncate text to fit within max_tokens (heuristic)."""
        if not text:
            return text
        current = estimate_tokens_heuristic(text)
        if current <= max_tokens:
            return text
        # Approximate char limit: use 2 chars/token as conservative estimate
        char_limit = max(50, max_tokens * 2)
        return text[:char_limit] + "\n... (truncated to fit budget)"

    def _compress_state_summary(self, summary_text: str, max_tokens: int) -> str:
        """Compress state summary by removing closed-route evidence and details."""
        current = estimate_tokens_heuristic(summary_text)
        if current <= max_tokens:
            return summary_text
        # Try to parse and reduce the JSON content
        try:
            json_match = summary_text.split("```json\n")
            if len(json_match) >= 2:
                json_str = json_match[1].split("\n```")[0]
                data = json.loads(json_str)
                # Remove lower-priority fields progressively
                for field_to_remove in [
                    "recent_failures", "interesting_params", "forms",
                    "cookies", "key_endpoints",
                ]:
                    if field_to_remove in data:
                        del data[field_to_remove]
                    reduced = "## 当前状态\n\n```json\n" + json.dumps(data, ensure_ascii=False, indent=2) + "\n```"
                    if estimate_tokens_heuristic(reduced) <= max_tokens:
                        return reduced
                # Still too large — minimal summary
                minimal = {
                    "endpoint_count": data.get("endpoint_count", 0),
                    "top_evidence": data.get("top_evidence", [])[:3],
                    "total_attempts": data.get("total_attempts", 0),
                    "round": data.get("round", 0),
                }
                return "## 当前状态\n\n```json\n" + json.dumps(minimal, ensure_ascii=False, indent=2) + "\n```"
        except (json.JSONDecodeError, IndexError, KeyError):
            pass
        # Fallback: raw truncation
        return self._truncate_text(summary_text, max_tokens)

    def _apply_budget_compression(
        self,
        messages: List[Dict[str, Any]],
        *,
        route_card_text: str,
        state_summary_text: str,
        core_text: str,
        task_ctx_text: str,
        history_messages: List[Dict[str, Any]],
        files: Optional[List[str]],
    ) -> List[Dict[str, Any]]:
        """Apply compression in priority order until output fits within budget.

        Compression priority (lowest priority removed first):
        1. Remove skills/knowledge context (non-current route)
        2. Truncate closed-route evidence in state summary
        3. Remove old history (reduce to last 2, then 1 turn)
        4. Truncate large responses in history
        5. Truncate RouteCard (last resort)
        """
        max_tokens = self.budget.max_input_tokens

        # --- Priority 1: Skills context is already excluded by design ---
        # (We never inject non-current-route skills)

        # --- Priority 2: Compress state summary (closed evidence) ---
        remaining_for_summary = max(200, max_tokens // 4)
        compressed_summary = self._compress_state_summary(state_summary_text, remaining_for_summary)

        # --- Priority 3: Reduce history aggressively ---
        compressed_history = history_messages
        # Try progressively smaller history budgets
        for history_budget_fraction in [1.0, 0.6, 0.3, 0.0]:
            adjusted_budget = int(self.budget.history_budget * history_budget_fraction)
            if history_messages and adjusted_budget > 0:
                compressed_history = compress_history(
                    [{"role": "system", "content": ""}] + history_messages,
                    max_tokens=adjusted_budget,
                )
                compressed_history = [m for m in compressed_history if m.get("role") != "system"]
            elif adjusted_budget == 0:
                compressed_history = []

            # Build candidate and check
            candidate = self._assemble_messages(
                core_text, route_card_text, task_ctx_text,
                compressed_summary, compressed_history, files,
            )
            if self.estimate_tokens(candidate) <= max_tokens:
                return candidate

        # --- Priority 4: Truncate large responses in remaining history ---
        for msg in compressed_history:
            if msg.get("role") == "tool":
                content = msg.get("content", "")
                if isinstance(content, str) and len(content) > HTML_SUMMARY_THRESHOLD and _is_html_content(content):
                    msg["content"] = summarize_html(content)
                elif isinstance(content, str) and len(content) > 300:
                    msg["content"] = content[:300] + "\n...(truncated)"

        candidate = self._assemble_messages(
            core_text, route_card_text, task_ctx_text,
            compressed_summary, compressed_history, files,
        )
        if self.estimate_tokens(candidate) <= max_tokens:
            return candidate

        # --- Priority 5: Truncate RouteCard ---
        current_route_card = route_card_text
        for card_fraction in [0.5, 0.25, 0.0]:
            if current_route_card:
                if card_fraction == 0.0:
                    current_route_card = ""
                else:
                    char_limit = int(len(route_card_text) * card_fraction)
                    current_route_card = route_card_text[:char_limit] + "\n...(route card truncated)"

            candidate = self._assemble_messages(
                core_text, current_route_card, task_ctx_text,
                compressed_summary, compressed_history, files,
            )
            if self.estimate_tokens(candidate) <= max_tokens:
                return candidate

        # --- Final fallback: truncate task context and state summary further ---
        compressed_summary = self._truncate_text(compressed_summary, max_tokens // 6)
        task_ctx_truncated = self._truncate_text(task_ctx_text, max_tokens // 4)
        candidate = self._assemble_messages(
            core_text, "", task_ctx_truncated,
            compressed_summary, [], files,
        )
        # If still over, hard-truncate the user message content
        if self.estimate_tokens(candidate) > max_tokens:
            for msg in candidate:
                if msg.get("role") == "user":
                    msg["content"] = self._truncate_text(
                        msg["content"], max_tokens - estimate_tokens_heuristic(core_text) - 50
                    )
                    break

        return candidate

    def _assemble_messages(
        self,
        core_text: str,
        route_card_text: str,
        task_ctx_text: str,
        state_summary_text: str,
        history_messages: List[Dict[str, Any]],
        files: Optional[List[str]],
    ) -> List[Dict[str, Any]]:
        """Assemble the final message list from components."""
        # System message = core + route card
        system_content = core_text
        if route_card_text:
            system_content += "\n\n" + route_card_text
        system_msg = {"role": "system", "content": system_content}

        # User message = task context + state summary + instructions
        user_parts = [task_ctx_text, "", state_summary_text]
        if files:
            user_parts.append("")
            user_parts.append("## 附件文件")
            user_parts.append(", ".join(files))
        user_parts.append("")
        user_parts.append("## 指令")
        user_parts.append("")
        user_parts.append(
            "使用 Thought → Action → Observation 格式。"
            "每轮只做一个动作。优先高信息增益操作。"
            "发现 flag 后输出 FLAG_FOUND: <flag值>"
        )
        user_msg = {"role": "user", "content": "\n".join(user_parts)}

        # Assemble: system + history + user
        if history_messages:
            return [system_msg] + history_messages + [user_msg]
        return [system_msg, user_msg]

    # -----------------------------------------------------------------------
    # Main build method
    # -----------------------------------------------------------------------

    def build_messages(
        self,
        target: str,
        flag_format: str,
        challenge_type: Optional[str] = None,
        max_iterations: int = 15,
        timeout: int = 300,
        blackboard: Optional[WebStateBlackboard] = None,
        route: str = "recon",
        route_progress: str = "not_started",
        previous_messages: Optional[List[Dict[str, Any]]] = None,
        files: Optional[List[str]] = None,
    ) -> List[Dict[str, Any]]:
        """Build the full message list for an LLM call.

        Enforces strict token budget: after building each layer, checks
        cumulative tokens. If over budget, applies compression in priority
        order until output fits within TokenBudget.max_input_tokens.

        Returns [system_msg, user_msg] for initial call, or merges with
        compressed history for subsequent calls.
        """
        max_tokens = self.budget.max_input_tokens

        # Layer 1: Core prompt (immutable, always included)
        core = CORE_PROMPT.strip()
        core_tokens = estimate_tokens_heuristic(core)

        # Layer 4: RouteCard (injected into system prompt if route known)
        route_card_text = ""
        if route and route != "recon":
            from .route_cards import ROUTE_CARDS
            card = ROUTE_CARDS.get(route)
            if card:
                route_card_text = card.to_prompt_text()
        route_card_tokens = estimate_tokens_heuristic(route_card_text)

        # Layer 2: Task context
        task_ctx = build_task_context(
            target=target,
            flag_format=flag_format,
            challenge_type=challenge_type,
            max_iterations=max_iterations,
            timeout=timeout,
            current_route=route,
            route_progress=route_progress,
        )
        task_ctx_tokens = estimate_tokens_heuristic(task_ctx)

        # Layer 3: State summary
        state_summary = build_state_summary(blackboard)
        state_summary_tokens = estimate_tokens_heuristic(state_summary)

        # Prepare history
        history_messages: List[Dict[str, Any]] = []
        if previous_messages:
            compressed = compress_history(
                previous_messages,
                max_tokens=self.budget.history_budget,
            )
            history_messages = [m for m in compressed if m.get("role") != "system"]
        history_tokens = sum(
            estimate_tokens_heuristic(str(m.get("content", "") or "")) + 4
            for m in history_messages
        )

        # Track token stats per layer
        self._last_token_stats = {
            "core_prompt": core_tokens,
            "task_context": task_ctx_tokens,
            "state_summary": state_summary_tokens,
            "route_card": route_card_tokens,
            "history": history_tokens,
            "total": core_tokens + task_ctx_tokens + state_summary_tokens + route_card_tokens + history_tokens,
        }

        # --- Assemble initial candidate ---
        result = self._assemble_messages(
            core, route_card_text, task_ctx, state_summary, history_messages, files,
        )

        # --- Check budget and apply compression if needed ---
        estimated = self.estimate_tokens(result)
        if estimated <= max_tokens:
            return result

        # Over budget — apply priority-based compression
        result = self._apply_budget_compression(
            result,
            route_card_text=route_card_text,
            state_summary_text=state_summary,
            core_text=core,
            task_ctx_text=task_ctx,
            history_messages=previous_messages or [],
            files=files,
        )

        return result

    def estimate_tokens(self, messages: List[Dict[str, Any]]) -> int:
        """Estimate total token count for a list of messages using heuristic."""
        total = 0
        for msg in messages:
            content = msg.get("content", "") or ""
            if isinstance(content, list):
                content = json.dumps(content)
            total += estimate_tokens_heuristic(str(content))
            total += 4  # message overhead
        return total

    def check_budget(self, messages: List[Dict[str, Any]]) -> Tuple[bool, int, int]:
        """Check if messages fit within the input token budget.

        Returns (within_budget, estimated_tokens, budget_limit).
        """
        est = self.estimate_tokens(messages)
        return est <= self.budget.max_input_tokens, est, self.budget.max_input_tokens

    def get_token_stats(self) -> Dict[str, int]:
        """Return estimated token usage per prompt layer.

        Fields:
        - core_prompt: tokens used by the core system prompt
        - task_context: tokens used by task context (target, tools, etc.)
        - state_summary: tokens used by blackboard state summary
        - route_card: tokens used by the injected RouteCard
        - history: tokens used by conversation history
        - total: sum of all layers

        Call this after build_messages() to get stats for the last build.

        **Validates: Requirements 6.6**
        """
        return dict(self._last_token_stats) if self._last_token_stats else {
            "core_prompt": 0,
            "task_context": 0,
            "state_summary": 0,
            "route_card": 0,
            "history": 0,
            "total": 0,
        }
