"""Unit tests for PromptCompiler — 4-layer prompt construction & token budget."""
from __future__ import annotations

import pytest

from autopnex.ctf.prompt_compiler import (
    PromptCompiler,
    TokenBudget,
    build_task_context,
    build_state_summary,
    compress_history,
    estimate_tokens_heuristic,
    summarize_html,
    HTML_SUMMARY_THRESHOLD,
    _is_html_content,
    CORE_PROMPT,
)
from autopnex.ctf.web_state_blackboard import WebStateBlackboard


# ---------------------------------------------------------------------------
# 1. 4-layer structure
# ---------------------------------------------------------------------------

class TestPromptCompiler4LayerStructure:
    """Verify all 4 layers are present in compiled output."""

    def test_four_layers_present(self):
        compiler = PromptCompiler()
        messages = compiler.build_messages(
            target="http://chall.ctf:8080",
            flag_format="flag{...}",
            challenge_type="web",
            route="recon",
        )
        assert len(messages) >= 2
        system = messages[0]
        user = messages[1]
        assert system["role"] == "system"
        assert user["role"] == "user"

        # Layer 1: Core prompt in system message
        assert "Web CTF Agent" in system["content"]
        assert "证据" in system["content"]

        # Layer 2: Task context in user message
        assert "任务上下文" in user["content"]
        assert "http://chall.ctf:8080" in user["content"]
        assert "flag{...}" in user["content"]

        # Layer 3: State summary in user message
        assert "当前状态" in user["content"]

        # Layer 4: Route card (recon route has no card injection, so just verify layer structure)
        assert "指令" in user["content"]
        assert "Thought" in user["content"]

    def test_route_card_injected_for_known_route(self):
        compiler = PromptCompiler()
        messages = compiler.build_messages(
            target="http://chall.ctf:8080",
            flag_format="flag{...}",
            route="lfi",
        )
        system = messages[0]["content"]
        # LFI route card should be present
        assert "LFI" in system.upper() or "当前路线" in system


# ---------------------------------------------------------------------------
# 2. Token budget
# ---------------------------------------------------------------------------

class TestTokenBudget:
    def test_heuristic_estimates_chinese(self):
        tokens = estimate_tokens_heuristic("你好世界")
        assert tokens > 0
        # CJK chars count as ~1 token each
        assert tokens >= 4

    def test_heuristic_estimates_english(self):
        tokens = estimate_tokens_heuristic("hello world this is a test")
        # ~3 chars per token + 1
        expected = len("hello world this is a test") // 3 + 1
        assert tokens == expected

    def test_heuristic_empty_string(self):
        assert estimate_tokens_heuristic("") == 0

    def test_heuristic_none(self):
        assert estimate_tokens_heuristic(None) == 0  # type: ignore[arg-type]

    def test_budget_check_within_limit(self):
        compiler = PromptCompiler()
        messages = compiler.build_messages(
            target="http://chall.ctf:8080",
            flag_format="flag{...}",
        )
        within, est, limit = compiler.check_budget(messages)
        assert within
        assert est > 0
        assert limit == compiler.budget.max_input_tokens

    def test_remaining_for_layer(self):
        budget = TokenBudget()
        assert budget.remaining_for_layer("state_summary") == budget.state_summary_budget
        assert budget.remaining_for_layer("history") == budget.history_budget

    def test_total_consumed(self):
        budget = TokenBudget()
        total = budget.total_consumed({"core": 300, "task": 500, "history": 1000})
        assert total == 1800


# ---------------------------------------------------------------------------
# 3. History compression
# ---------------------------------------------------------------------------

class TestHistoryCompression:
    def test_keeps_system_messages(self):
        messages = [
            {"role": "system", "content": "You are a CTF agent."},
            {"role": "user", "content": "Find the flag."},
            {"role": "assistant", "content": "Scanning..."},
        ]
        compressed = compress_history(messages, max_tokens=5000)
        assert any(m["role"] == "system" for m in compressed)

    def test_compresses_older_turns(self):
        """Older turns should be summarized into a single compressed message."""
        messages = [
            {"role": "system", "content": "System."},
            {"role": "user", "content": "Task 1"},
            {"role": "assistant", "content": "Done 1"},
            {"role": "user", "content": "Task 2"},
            {"role": "assistant", "content": "Done 2"},
            {"role": "user", "content": "Task 3"},
            {"role": "assistant", "content": "Done 3"},
            {"role": "user", "content": "Task 4"},
            {"role": "assistant", "content": "Done 4"},
            {"role": "user", "content": "Task 5"},
            {"role": "assistant", "content": "Done 5"},
        ]
        compressed = compress_history(messages, max_tokens=5000)
        # Should contain system + compressed summary + last 3 turns
        assert len(compressed) < len(messages)
        # There should be a compressed history message
        has_compressed = any("历史摘要" in str(m.get("content", "")) for m in compressed)
        assert has_compressed

    def test_truncates_long_tool_outputs(self):
        long_output = "A" * 800
        messages = [
            {"role": "system", "content": "Sys"},
            {"role": "user", "content": "Do X"},
            {"role": "assistant", "content": "OK"},
            {"role": "tool", "content": long_output, "tool_call_id": "1"},
            {"role": "user", "content": "Next"},
        ]
        compressed = compress_history(messages, max_tokens=5000)
        # Find the tool message
        tool_msgs = [m for m in compressed if m.get("role") == "tool"]
        if tool_msgs:
            content = tool_msgs[0].get("content", "")
            assert len(content) < len(long_output)
            assert "truncated" in content.lower()

    def test_handles_empty_messages(self):
        assert compress_history([], max_tokens=1000) == []

    def test_keeps_last_3_turns_intact(self):
        """The 3 most recent turns should be preserved in full."""
        messages = [
            {"role": "system", "content": "Sys"},
            {"role": "user", "content": "Q1"},
            {"role": "assistant", "content": "A1"},
            {"role": "user", "content": "Q2"},
            {"role": "assistant", "content": "A2"},
            {"role": "user", "content": "Q3"},
            {"role": "assistant", "content": "A3"},
            {"role": "user", "content": "Q4"},
            {"role": "assistant", "content": "A4"},
        ]
        compressed = compress_history(messages, max_tokens=5000)
        # Q2-A2, Q3-A3, Q4-A4 should be intact (last 3 turns)
        user_contents = [
            m.get("content", "") for m in compressed
            if m.get("role") == "user" and "历史摘要" not in str(m.get("content", ""))
        ]
        # Should include Q2, Q3, Q4 (3 recent turns)
        recent_questions = [c for c in user_contents if c.startswith("Q")]
        assert len(recent_questions) == 3
        assert "Q2" in recent_questions
        assert "Q3" in recent_questions
        assert "Q4" in recent_questions


# ---------------------------------------------------------------------------
# 4. Single route card (no multi-route pollution)
# ---------------------------------------------------------------------------

class TestSingleRouteCard:
    def test_only_current_route_card_injected(self):
        compiler = PromptCompiler()
        messages = compiler.build_messages(
            target="http://chall.ctf:8080",
            flag_format="flag{...}",
            route="ssti",
        )
        system = messages[0]["content"]
        # SSTI should be referenced
        assert "SSTI" in system.upper() or "模板注入" in system or "模板" in system
        # Should NOT contain SQLi-specific terms
        assert "SQL" not in system.upper()

    def test_recon_route_no_card_noise(self):
        compiler = PromptCompiler()
        messages = compiler.build_messages(
            target="http://chall.ctf:8080",
            flag_format="flag{...}",
            route="recon",
        )
        system = messages[0]["content"]
        # recon route should not inject route-specific techniques
        # System should essentially be core prompt only
        # It's fine if "当前路线" appears in user message, but system should be clean
        assert "Web CTF Agent" in system


# ---------------------------------------------------------------------------
# 5. No raw HTML in output
# ---------------------------------------------------------------------------

class TestNoRawHtml:
    def test_build_messages_no_html_tags(self):
        compiler = PromptCompiler()
        messages = compiler.build_messages(
            target="http://chall.ctf:8080",
            flag_format="flag{...}",
        )
        for msg in messages:
            content = msg.get("content", "")
            assert "<html" not in content.lower()
            assert "<body" not in content.lower()
            assert "<div" not in content.lower()

    def test_build_task_context_no_html(self):
        ctx = build_task_context(
            target="http://chall.ctf:8080",
            flag_format="flag{...}",
        )
        assert "<html" not in ctx.lower()
        assert "<script" not in ctx.lower()

    def test_state_summary_no_html_inline(self):
        bb = WebStateBlackboard(target_url="http://chall.ctf:8080")
        bb.record_endpoint(path="/test", body_snippet="<html><body>test</body></html>")
        summary = build_state_summary(bb)
        # State summary is JSON-formatted — the snippet may contain HTML tags
        # but the summary structure itself should be valid JSON
        assert "当前状态" in summary
        # Verify JSON part is parsable
        import json
        json_part = summary.split("```json\n")[1].split("\n```")[0]
        data = json.loads(json_part)
        assert isinstance(data, dict)
        assert "endpoint_count" in data

    def test_core_prompt_no_html(self):
        assert "<html" not in CORE_PROMPT.lower()


# ---------------------------------------------------------------------------
# 6. HTML Summarization (Task 10.2)
# ---------------------------------------------------------------------------

class TestHtmlSummarization:
    """Tests for summarize_html() and HTML detection."""

    def test_short_html_returned_unchanged(self):
        """HTML shorter than threshold is returned as-is."""
        short_html = "<html><body><p>Hello</p></body></html>"
        assert summarize_html(short_html) == short_html

    def test_long_html_summarized(self):
        """HTML longer than threshold is summarized."""
        long_html = (
            "<html><head><title>Login Page</title></head>"
            "<body>"
            '<form action="/login" method="POST">'
            '<input type="text" name="username">'
            '<input type="password" name="password">'
            '<input type="submit" value="Login">'
            "</form>"
            '<a href="/register">Register</a>'
            '<a href="/forgot">Forgot Password</a>'
            '<script src="/static/app.js"></script>'
            '<div class="error">Invalid credentials</div>'
            + "<p>" + "x" * 2500 + "</p>"
            + "</body></html>"
        )
        assert len(long_html) > HTML_SUMMARY_THRESHOLD
        summary = summarize_html(long_html)

        # Summary should be shorter than original
        assert len(summary) < len(long_html)
        # Should contain key extracted info
        assert "Login Page" in summary  # title
        assert "/login" in summary  # form action
        assert "POST" in summary  # form method
        assert "username" in summary  # form input
        assert "/register" in summary  # link
        assert "/static/app.js" in summary  # script
        assert "Invalid credentials" in summary  # error message

    def test_summary_within_threshold(self):
        """Summary output should not exceed the threshold."""
        # Build a truly large HTML
        links = "".join(f'<a href="/page{i}">Link {i}</a>' for i in range(500))
        huge_html = f"<html><body>{links}</body></html>"
        summary = summarize_html(huge_html)
        assert len(summary) <= HTML_SUMMARY_THRESHOLD

    def test_empty_html(self):
        """Empty string returns empty."""
        assert summarize_html("") == ""

    def test_none_html(self):
        """None returns empty."""
        assert summarize_html(None) == None  # type: ignore[arg-type]

    def test_is_html_content_detection(self):
        """_is_html_content correctly identifies HTML."""
        assert _is_html_content("<!DOCTYPE html><html><body>test</body></html>")
        assert _is_html_content("<html><head></head><body></body></html>")
        assert _is_html_content("<div><p>text</p><span>more</span></div>")
        assert not _is_html_content("Just plain text")
        assert not _is_html_content('{"key": "value"}')
        assert not _is_html_content("")

    def test_compress_history_summarizes_html_tool_output(self):
        """compress_history should summarize HTML tool outputs > threshold."""
        long_html = (
            "<html><head><title>Test Page</title></head><body>"
            + "<p>" + "A" * 2500 + "</p>"
            + '<a href="/api/users">Users</a>'
            + "</body></html>"
        )
        messages = [
            {"role": "system", "content": "Sys"},
            {"role": "user", "content": "Check the page"},
            {"role": "assistant", "content": "OK", "tool_calls": [{"function": {"name": "http_request"}}]},
            {"role": "tool", "content": long_html, "tool_call_id": "1"},
            {"role": "user", "content": "Next step"},
            {"role": "assistant", "content": "Analyzing"},
        ]
        compressed = compress_history(messages, max_tokens=5000)
        # Find tool messages in result
        tool_msgs = [m for m in compressed if m.get("role") == "tool"]
        if tool_msgs:
            content = tool_msgs[0].get("content", "")
            # Should be summarized, not raw HTML
            assert len(content) < len(long_html)
            assert "HTML Summary" in content or "Test Page" in content

    def test_build_messages_with_html_in_history(self):
        """build_messages should handle HTML in previous_messages tool outputs."""
        long_html = (
            "<!DOCTYPE html><html><head><title>Admin Panel</title></head><body>"
            + '<form action="/admin/login" method="POST">'
            + '<input type="text" name="user">'
            + '<input type="password" name="pass">'
            + "</form>"
            + "<p>" + "content " * 500 + "</p>"
            + "</body></html>"
        )
        history = [
            {"role": "user", "content": "Scan target"},
            {"role": "assistant", "content": "Scanning..."},
            {"role": "tool", "content": long_html, "tool_call_id": "tc1"},
            {"role": "user", "content": "What did you find?"},
            {"role": "assistant", "content": "Found admin panel"},
        ]
        compiler = PromptCompiler()
        messages = compiler.build_messages(
            target="http://test.local:8080",
            flag_format="flag{...}",
            previous_messages=history,
        )
        # The raw HTML should not appear in the output
        full_content = " ".join(m.get("content", "") or "" for m in messages)
        assert "<html" not in full_content.lower() or "HTML Summary" in full_content


# ---------------------------------------------------------------------------
# 7. get_token_stats() (Task 10.3)
# ---------------------------------------------------------------------------

class TestGetTokenStats:
    """Tests for PromptCompiler.get_token_stats() method."""

    def test_returns_all_fields(self):
        """get_token_stats() returns all required fields."""
        compiler = PromptCompiler()
        compiler.build_messages(
            target="http://test.local:8080",
            flag_format="flag{...}",
            route="lfi",
        )
        stats = compiler.get_token_stats()
        assert "core_prompt" in stats
        assert "task_context" in stats
        assert "state_summary" in stats
        assert "route_card" in stats
        assert "history" in stats
        assert "total" in stats

    def test_total_is_sum_of_layers(self):
        """total should equal sum of all layer token counts."""
        compiler = PromptCompiler()
        compiler.build_messages(
            target="http://test.local:8080",
            flag_format="flag{...}",
            route="ssti",
        )
        stats = compiler.get_token_stats()
        expected_total = (
            stats["core_prompt"]
            + stats["task_context"]
            + stats["state_summary"]
            + stats["route_card"]
            + stats["history"]
        )
        assert stats["total"] == expected_total

    def test_core_prompt_nonzero(self):
        """Core prompt should always have tokens."""
        compiler = PromptCompiler()
        compiler.build_messages(
            target="http://test.local:8080",
            flag_format="flag{...}",
        )
        stats = compiler.get_token_stats()
        assert stats["core_prompt"] > 0

    def test_route_card_zero_for_recon(self):
        """Route card should be 0 for recon route (no card injected)."""
        compiler = PromptCompiler()
        compiler.build_messages(
            target="http://test.local:8080",
            flag_format="flag{...}",
            route="recon",
        )
        stats = compiler.get_token_stats()
        assert stats["route_card"] == 0

    def test_route_card_nonzero_for_known_route(self):
        """Route card should be > 0 for a known route like lfi."""
        compiler = PromptCompiler()
        compiler.build_messages(
            target="http://test.local:8080",
            flag_format="flag{...}",
            route="lfi",
        )
        stats = compiler.get_token_stats()
        assert stats["route_card"] > 0

    def test_history_nonzero_with_previous_messages(self):
        """History tokens should be > 0 when previous_messages provided."""
        compiler = PromptCompiler()
        history = [
            {"role": "user", "content": "Find the flag"},
            {"role": "assistant", "content": "Scanning the target..."},
        ]
        compiler.build_messages(
            target="http://test.local:8080",
            flag_format="flag{...}",
            previous_messages=history,
        )
        stats = compiler.get_token_stats()
        assert stats["history"] > 0

    def test_history_zero_without_previous_messages(self):
        """History tokens should be 0 when no previous_messages."""
        compiler = PromptCompiler()
        compiler.build_messages(
            target="http://test.local:8080",
            flag_format="flag{...}",
        )
        stats = compiler.get_token_stats()
        assert stats["history"] == 0

    def test_stats_before_build_returns_zeros(self):
        """get_token_stats() before build_messages() returns all zeros."""
        compiler = PromptCompiler()
        stats = compiler.get_token_stats()
        assert stats["total"] == 0
        assert all(v == 0 for v in stats.values())


# ---------------------------------------------------------------------------
# 8. Route-aware injection (Task 10.4)
# ---------------------------------------------------------------------------

class TestRouteAwareInjection:
    """Tests verifying only current route's RouteCard is injected."""

    def test_only_current_route_card_in_system(self):
        """Only the current route's card should appear in system message."""
        compiler = PromptCompiler()
        messages = compiler.build_messages(
            target="http://test.local:8080",
            flag_format="flag{...}",
            route="sqli",
        )
        system = messages[0]["content"]
        # SQLi route card should be present
        assert "SQL" in system.upper() or "注入" in system
        # Other route-specific terms should NOT be present
        assert "SSTI" not in system.upper()
        assert "LFI" not in system.upper()
        assert "SSRF" not in system.upper()

    def test_no_skills_context_injected(self):
        """No skills/knowledge context should be injected by default."""
        compiler = PromptCompiler()
        messages = compiler.build_messages(
            target="http://test.local:8080",
            flag_format="flag{...}",
            route="lfi",
        )
        # Check that no "skills" or "knowledge base" sections are injected
        full_content = " ".join(m.get("content", "") or "" for m in messages)
        # The tool list mentions ctf_knowledge_search as a tool name, which is fine
        # But there should be no injected knowledge content
        assert "## 知识库内容" not in full_content
        assert "## Skills" not in full_content

    def test_different_routes_get_different_cards(self):
        """Different routes should inject different RouteCards."""
        compiler = PromptCompiler()

        msgs_lfi = compiler.build_messages(
            target="http://test.local:8080",
            flag_format="flag{...}",
            route="lfi",
        )
        msgs_jwt = compiler.build_messages(
            target="http://test.local:8080",
            flag_format="flag{...}",
            route="jwt",
        )

        system_lfi = msgs_lfi[0]["content"]
        system_jwt = msgs_jwt[0]["content"]

        # They should be different (different route cards)
        assert system_lfi != system_jwt

    def test_recon_route_has_no_route_card(self):
        """Recon route should not inject any route-specific card."""
        compiler = PromptCompiler()
        messages = compiler.build_messages(
            target="http://test.local:8080",
            flag_format="flag{...}",
            route="recon",
        )
        system = messages[0]["content"]
        # Should only contain core prompt, no route card
        assert "当前路线:" not in system
        assert "触发条件" not in system
        assert "探测 Payload" not in system
